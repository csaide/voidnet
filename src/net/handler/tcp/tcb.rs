use std::collections::BTreeMap;
use std::fmt;

use coarsetime::Instant;

use crate::net::{
    socket::LocalQueue,
    wire::ip::IpAddress,
};

use super::ring_buffer::RingBuffer;
use super::state::TcpState;

/// Identifies a TCP connection by its 4-tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId {
    pub local_addr: IpAddress,
    pub local_port: u16,
    pub remote_addr: IpAddress,
    pub remote_port: u16,
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{}",
            self.local_addr, self.local_port, self.remote_addr, self.remote_port
        )
    }
}

/// Events delivered to user-facing TCP sockets.
#[derive(Debug, PartialEq, Eq)]
pub enum TcpEvent {
    Connected,
    ConnectionRefused,
    Reset,
    Timeout,
    RemoteClose,
}

/// Errors returned by TCP operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum TcpError {
    ConnectionRefused,
    Timeout,
    Reset,
    NotConnected,
}

impl fmt::Display for TcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TcpError::ConnectionRefused => write!(f, "connection refused"),
            TcpError::Timeout => write!(f, "connection timed out"),
            TcpError::Reset => write!(f, "connection reset"),
            TcpError::NotConnected => write!(f, "not connected"),
        }
    }
}

/// Default receive MSS advertised by this implementation.
pub const DEFAULT_RCV_MSS: u16 = 1460;

/// Default receive window size.
pub const DEFAULT_RCV_WND: u16 = 65535;

/// Default receive window scale shift count.
pub const DEFAULT_RCV_WSCALE: u8 = 7;

/// Default delayed ACK timeout in milliseconds (RFC 9293 §4.2: < 500ms).
pub const DEFAULT_DELAYED_ACK_MS: u64 = 40;

/// Maximum consecutive unACKed segments before flushing (RFC 5681 §4.2).
pub const MAX_DELAYED_ACK_COUNT: u8 = 2;

/// Configuration for TCP connections.
pub struct TcpConfig {
    /// Send buffer size in bytes. Must be a power of two. Default: 256KB.
    pub send_buffer_size: usize,
    /// Receive buffer size in bytes. Must be a power of two. Default: 256KB.
    pub recv_buffer_size: usize,
    /// Listener backlog. Default: 128.
    pub backlog: usize,
    /// Duration to remain in TIME-WAIT state in milliseconds. Default: 60000 (60s).
    pub time_wait_duration_ms: u64,
    /// If true, disable Nagle algorithm (send small segments immediately). Default: false.
    pub tcp_no_delay: bool,
    /// Maximum delay for ACKs in milliseconds. Default: 40.
    pub delayed_ack_ms: u64,
    /// Enable TCP keep-alive probes. Default: false.
    pub keep_alive: bool,
    /// Idle time before first keep-alive probe in milliseconds. Default: 7200000 (2 hours).
    pub keep_alive_idle_ms: u64,
    /// Interval between keep-alive probes in milliseconds. Default: 75000 (75 seconds).
    pub keep_alive_interval_ms: u64,
    /// Max probes before aborting connection. Default: 9.
    pub keep_alive_count: u8,
    /// SO_LINGER setting. None = off (default), Some(0) = RST, Some(ms) = timeout.
    pub linger: Option<u64>,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            send_buffer_size: 256 * 1024,
            recv_buffer_size: 256 * 1024,
            backlog: 128,
            time_wait_duration_ms: 60_000,
            tcp_no_delay: false,
            delayed_ack_ms: DEFAULT_DELAYED_ACK_MS,
            keep_alive: false,
            keep_alive_idle_ms: 7_200_000,
            keep_alive_interval_ms: 75_000,
            keep_alive_count: 9,
            linger: None,
        }
    }
}

/// Transmission Control Block — per-connection state.
pub struct Tcb {
    pub id: ConnectionId,
    pub state: TcpState,
    /// True if this connection originated from a passive open (LISTEN).
    pub from_passive_open: bool,

    // --- Send sequence space ---
    /// Initial send sequence number.
    pub iss: u32,
    /// Oldest unacknowledged sequence number.
    pub snd_una: u32,
    /// Next sequence number to send.
    pub snd_nxt: u32,
    /// Send window.
    pub snd_wnd: u32,
    /// Segment sequence number used for last window update.
    pub snd_wl1: u32,
    /// Segment acknowledgment number used for last window update.
    pub snd_wl2: u32,

    // --- Receive sequence space ---
    /// Initial receive sequence number.
    pub irs: u32,
    /// Next sequence number expected on incoming segments.
    pub rcv_nxt: u32,
    /// Receive window.
    pub rcv_wnd: u32,

    // --- MSS negotiation ---
    /// MSS advertised by the remote peer.
    pub snd_mss: u16,
    /// MSS we advertise to the remote peer.
    pub rcv_mss: u16,
    /// Effective send MSS (min of snd_mss and path MTU constraints).
    pub eff_snd_mss: u16,

    // --- Window scale ---
    /// Send window scale factor (shift count from remote).
    pub snd_wscale: u8,
    /// Receive window scale factor (our shift count).
    pub rcv_wscale: u8,
    /// Whether window scaling is enabled for this connection.
    pub wscale_enabled: bool,

    // --- Retransmission ---
    /// Deadline for retransmitting unacknowledged SYN or SYN-ACK.
    pub retransmit_deadline: Option<Instant>,
    /// Exponential backoff counter for retransmissions.
    pub rto_backoff: u8,

    // --- Event notification ---
    /// Queue for delivering events to user-facing socket.
    pub event_queue: LocalQueue<TcpEvent>,

    // --- Data transfer buffers ---
    /// Send ring buffer — user data is copied in, segments built from here.
    pub send_buffer: RingBuffer,
    /// Receive ring buffer — incoming payload copied here, user reads from here.
    pub recv_buffer: RingBuffer,
    /// Out-of-order receive ranges: seq -> byte_length (metadata only).
    pub ooo_ranges: BTreeMap<u32, u32>,

    // --- Congestion control ---
    /// Congestion window in bytes.
    pub cwnd: u32,
    /// Slow start threshold.
    pub ssthresh: u32,
    /// Duplicate ACK counter for fast retransmit.
    pub dup_ack_count: u8,

    // --- RTT estimation (RFC 6298) ---
    /// Smoothed RTT in microseconds.
    pub srtt: Option<u64>,
    /// RTT variance in microseconds.
    pub rttvar: u64,
    /// Retransmission timeout in milliseconds (computed from srtt/rttvar).
    pub rto: u64,
    /// Timestamp of last data segment sent (for RTT measurement).
    pub last_send_time: Option<Instant>,

    // --- Connection teardown ---
    /// True when a FIN needs to be sent.
    pub pending_fin: bool,
    /// Sequence number of our FIN (set when FIN is sent).
    pub fin_seq: Option<u32>,
    /// Deadline for exiting TIME-WAIT state.
    pub time_wait_deadline: Option<Instant>,
    /// Duration to remain in TIME-WAIT state in milliseconds.
    pub time_wait_duration: u64,

    // --- Delayed ACK ---
    /// True when an ACK is owed but deferred.
    pub ack_pending: bool,
    /// Deadline for sending the deferred ACK.
    pub delayed_ack_deadline: Option<Instant>,
    /// Count of consecutive unACKed segments (flush at MAX_DELAYED_ACK_COUNT).
    pub ack_delay_count: u8,
    /// Delayed ACK timeout in milliseconds.
    pub delayed_ack_ms: u64,

    // --- Nagle algorithm ---
    /// When true, the Nagle algorithm gates small sends. Disabled by TCP_NODELAY.
    pub nagle_enabled: bool,

    // --- Keep-alive ---
    pub keep_alive_enabled: bool,
    pub keep_alive_idle_ms: u64,
    pub keep_alive_interval_ms: u64,
    pub keep_alive_count: u8,
    pub last_activity: Instant,
    pub keep_alive_probes_sent: u8,

    // --- Linger ---
    pub linger: Option<u64>,
    pub linger_deadline: Option<Instant>,
}

impl Tcb {
    /// Compute SEG.LEN for a segment: data octets + SYN/FIN contribution.
    #[inline]
    pub fn seg_len(data_len: usize, flags: u8) -> u32 {
        let mut len = data_len as u32;
        if flags & crate::net::wire::tcp::flags::SYN != 0 {
            len += 1;
        }
        if flags & crate::net::wire::tcp::flags::FIN != 0 {
            len += 1;
        }
        len
    }
}
