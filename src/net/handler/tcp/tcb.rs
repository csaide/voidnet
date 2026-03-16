use std::collections::BTreeMap;
use std::fmt;

use coarsetime::Instant;

use crate::net::{socket::LocalQueue, wire::ip::IpAddress};

use super::congestion::CubicState;
use super::recovery::{FRtoState, PrrState, SackRecovery};
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

/// TCP timestamp option overhead: NOP + NOP + Timestamp (10 bytes) = 12 bytes.
/// When timestamps are negotiated, eff_snd_mss must be reduced by this amount
/// to avoid exceeding MTU (RFC 7323 §5.1).
pub const TS_OPTION_LEN: u16 = 12;

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
    /// Enable TCP timestamps (RFC 7323). Default: true.
    pub timestamps: bool,
    /// Enable SACK (RFC 2018). Default: true.
    pub sack: bool,
    /// Enable ECN (RFC 3168). Default: true.
    pub ecn: bool,
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
            timestamps: true,
            sack: true,
            ecn: true,
        }
    }
}

/// Transmission Control Block — per-connection state.
///
/// Fields are ordered by access frequency to maximize L1d cache locality.
/// Hot fields (accessed every packet) are packed into the first 1-2 cache lines.
pub struct Tcb {
    // === HOT: accessed every packet ===
    /// Next sequence number expected on incoming segments.
    pub rcv_nxt: u32,
    /// Next sequence number to send.
    pub snd_nxt: u32,
    /// Oldest unacknowledged sequence number.
    pub snd_una: u32,
    /// Send window.
    pub snd_wnd: u32,
    pub state: TcpState,
    /// True when an ACK is owed but deferred.
    pub ack_pending: bool,
    /// Count of consecutive unACKed segments (flush at MAX_DELAYED_ACK_COUNT).
    pub ack_delay_count: u8,
    /// Whether timestamps were negotiated.
    pub ts_enabled: bool,
    /// Whether SACK was negotiated.
    pub sack_enabled: bool,
    /// Whether ECN was negotiated for this connection.
    pub ecn_enabled: bool,
    /// True when a CE-marked segment has been received and needs to be echoed.
    pub ecn_ce_received: bool,
    /// Whether window scaling is enabled for this connection.
    pub wscale_enabled: bool,
    /// Effective send MSS (min of snd_mss and path MTU constraints).
    pub eff_snd_mss: u16,
    /// Send window scale factor (shift count from remote).
    pub snd_wscale: u8,
    /// Receive window scale factor (our shift count).
    pub rcv_wscale: u8,
    /// MSS we advertise to the remote peer.
    pub rcv_mss: u16,
    /// When true, the Nagle algorithm gates small sends. Disabled by TCP_NODELAY.
    pub nagle_enabled: bool,
    /// True if this connection originated from a passive open (LISTEN).
    pub from_passive_open: bool,

    // === WARM: accessed most packets (data transfer) ===
    pub id: ConnectionId,
    /// Send ring buffer — user data is copied in, segments built from here.
    pub send_buffer: RingBuffer,
    /// Receive ring buffer — incoming payload copied here, user reads from here.
    pub recv_buffer: RingBuffer,
    /// Most recent TSval received from peer.
    pub ts_recent: u32,
    /// Deadline for sending the deferred ACK.
    pub delayed_ack_deadline: Option<Instant>,
    /// Delayed ACK timeout in milliseconds.
    pub delayed_ack_ms: u64,

    // === ACK processing ===
    /// Segment sequence number used for last window update.
    pub snd_wl1: u32,
    /// Segment acknowledgment number used for last window update.
    pub snd_wl2: u32,
    /// Largest send window ever advertised by peer (for sender SWS).
    pub max_snd_wnd: u32,
    /// Right edge of last advertised receive window (rcv_nxt + wnd at ACK time).
    pub last_advertised_right_edge: u32,
    /// Initial send sequence number.
    pub iss: u32,
    /// Initial receive sequence number.
    pub irs: u32,
    /// Receive window.
    pub rcv_wnd: u32,
    /// MSS advertised by the remote peer.
    pub snd_mss: u16,

    // === Congestion/recovery ===
    pub cubic: CubicState,
    pub recovery: SackRecovery,
    pub prr: PrrState,
    pub frto: FRtoState,

    // === RTT estimation (RFC 6298) ===
    /// Smoothed RTT in milliseconds.
    pub srtt: Option<u64>,
    /// RTT variance in milliseconds.
    pub rttvar: u64,
    /// Retransmission timeout in milliseconds (computed from srtt/rttvar).
    pub rto: u64,
    /// Timestamp of last data segment sent (for RTT measurement).
    pub last_send_time: Option<Instant>,
    /// When ts_recent was last updated.
    pub ts_recent_age: Instant,
    /// Base instant for deriving our monotonic timestamp clock.
    pub ts_offset: Instant,

    // === COLD: rarely accessed ===
    /// Deadline for retransmitting unacknowledged SYN or SYN-ACK.
    pub retransmit_deadline: Option<Instant>,
    /// Exponential backoff counter for retransmissions.
    pub rto_backoff: u8,
    /// Queue for delivering events to user-facing socket.
    pub event_queue: LocalQueue<TcpEvent>,
    /// Out-of-order receive ranges: seq -> byte_length (metadata only).
    pub ooo_ranges: BTreeMap<u32, u32>,
    /// Scoreboard: byte ranges the peer has confirmed receiving (left_edge -> right_edge).
    pub sack_scoreboard: BTreeMap<u32, u32>,
    /// True when CWR has been sent and is awaiting acknowledgment.
    pub ecn_cwr_sent: bool,
    /// True when a FIN needs to be sent.
    pub pending_fin: bool,
    /// Sequence number of our FIN (set when FIN is sent).
    pub fin_seq: Option<u32>,
    /// Deadline for exiting TIME-WAIT state.
    pub time_wait_deadline: Option<Instant>,
    /// Duration to remain in TIME-WAIT state in milliseconds.
    pub time_wait_duration: u64,
    /// Deadline for next zero-window probe.
    pub persist_deadline: Option<Instant>,
    /// Exponential backoff counter for persist probes (cap at 6).
    pub persist_backoff: u8,
    pub keep_alive_enabled: bool,
    pub keep_alive_idle_ms: u64,
    pub keep_alive_interval_ms: u64,
    pub keep_alive_count: u8,
    pub last_activity: Instant,
    pub keep_alive_probes_sent: u8,
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

    /// Compute the window value to advertise in outgoing segments.
    /// Downscales by `rcv_wscale` if window scaling is enabled.
    /// Applies receiver SWS avoidance (MUST-39): don't open the window
    /// until we can advertise at least min(MSS, buffer/2) of new space.
    #[inline]
    pub fn advertised_window(&self) -> u16 {
        let free = self.recv_buffer.free_space();
        let threshold = (self.rcv_mss as usize).min(self.recv_buffer.capacity() / 2);

        // SWS avoidance (MUST-39): don't open the window until we can
        // advertise at least min(MSS, buffer/2) of new space.
        let right_edge = self.rcv_nxt.wrapping_add(free as u32);
        let prev_right_edge = self.last_advertised_right_edge;

        let effective_free = if prev_right_edge != 0 {
            let new_space = right_edge.wrapping_sub(prev_right_edge) as i32;
            if new_space > 0 && (new_space as usize) < threshold {
                // Not enough new space — clamp to previous right edge.
                let clamped = prev_right_edge.wrapping_sub(self.rcv_nxt);
                (clamped as usize).min(free)
            } else {
                free
            }
        } else {
            free
        };

        if self.wscale_enabled {
            (effective_free >> self.rcv_wscale as usize).min(u16::MAX as usize) as u16
        } else {
            effective_free.min(u16::MAX as usize) as u16
        }
    }

    /// Update the last advertised right edge after sending an ACK.
    /// Call this after any path that sends an ACK with our advertised window.
    #[inline]
    pub fn update_advertised_edge(&mut self) {
        self.last_advertised_right_edge = self
            .rcv_nxt
            .wrapping_add(self.recv_buffer.free_space() as u32);
    }

    /// Build the timestamp option tuple using a pre-computed tsval.
    /// `ts_recent` is read at call time since it may change during segment processing.
    #[inline(always)]
    pub(super) fn ts_option(&self, tsval: u32) -> Option<(u32, u32)> {
        if self.ts_enabled {
            Some((tsval, self.ts_recent))
        } else {
            None
        }
    }

    /// Scale an incoming window value by `snd_wscale`.
    /// Only call after SYN exchange (Established onward).
    #[inline]
    pub fn scale_incoming_window(&self, raw_wnd: u32) -> u32 {
        if self.wscale_enabled {
            raw_wnd << self.snd_wscale as u32
        } else {
            raw_wnd
        }
    }

    /// Mark this connection as having a pending ACK.
    #[inline]
    pub fn mark_ack_pending(&mut self) {
        self.ack_pending = true;
    }

    /// Set the pending FIN flag.
    #[inline]
    pub fn set_pending_fin(&mut self) {
        self.pending_fin = true;
    }

    /// Update the send window. Returns `true` when the window
    /// transitions from zero to non-zero (peer un-stalls the sender).
    #[inline]
    pub fn update_send_window(&mut self, wnd: u32) -> bool {
        let old = self.snd_wnd;
        self.snd_wnd = wnd;
        old == 0 && wnd > 0
    }
}

#[cfg(test)]
mod tests {
    use super::super::ring_buffer::RingBuffer;
    use super::*;

    fn make_tcb(wscale_enabled: bool, snd_wscale: u8, rcv_wscale: u8, recv_buf_size: usize) -> Tcb {
        Tcb {
            id: ConnectionId {
                local_addr: IpAddress::V4(crate::net::wire::ip::Ipv4Address {
                    octets: [127, 0, 0, 1],
                }),
                local_port: 1234,
                remote_addr: IpAddress::V4(crate::net::wire::ip::Ipv4Address {
                    octets: [127, 0, 0, 1],
                }),
                remote_port: 5678,
            },
            state: TcpState::Established,
            from_passive_open: false,
            iss: 0,
            snd_una: 0,
            snd_nxt: 0,
            snd_wnd: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            irs: 0,
            rcv_nxt: 0,
            rcv_wnd: 0,
            snd_mss: DEFAULT_RCV_MSS,
            rcv_mss: DEFAULT_RCV_MSS,
            eff_snd_mss: DEFAULT_RCV_MSS,
            snd_wscale,
            rcv_wscale,
            wscale_enabled,
            retransmit_deadline: None,
            rto_backoff: 0,
            event_queue: LocalQueue::new(16),
            send_buffer: RingBuffer::new(1024),
            recv_buffer: RingBuffer::new(recv_buf_size),
            ooo_ranges: BTreeMap::new(),
            cubic: CubicState::new(DEFAULT_RCV_MSS),
            recovery: SackRecovery::new(),
            prr: PrrState::new(),
            frto: FRtoState::new(),
            srtt: None,
            rttvar: 0,
            rto: 1000,
            last_send_time: None,
            pending_fin: false,
            fin_seq: None,
            time_wait_deadline: None,
            time_wait_duration: 60_000,
            ack_pending: false,
            delayed_ack_deadline: None,
            ack_delay_count: 0,
            delayed_ack_ms: DEFAULT_DELAYED_ACK_MS,
            nagle_enabled: true,
            keep_alive_enabled: false,
            keep_alive_idle_ms: 7_200_000,
            keep_alive_interval_ms: 75_000,
            keep_alive_count: 9,
            last_activity: Instant::now(),
            keep_alive_probes_sent: 0,
            linger: None,
            linger_deadline: None,
            ts_enabled: false,
            ts_recent: 0,
            ts_recent_age: Instant::now(),
            ts_offset: Instant::now(),
            sack_enabled: false,
            sack_scoreboard: BTreeMap::new(),
            ecn_enabled: false,
            ecn_ce_received: false,
            ecn_cwr_sent: false,
            persist_deadline: None,
            persist_backoff: 0,
            max_snd_wnd: 0,
            last_advertised_right_edge: 0,
        }
    }

    #[test]
    fn advertised_window_no_scaling() {
        // recv_buffer capacity 1024, all free → capped at 1024 (fits in u16)
        let tcb = make_tcb(false, 0, 0, 1024);
        assert_eq!(tcb.advertised_window(), 1024);
    }

    #[test]
    fn advertised_window_with_scaling() {
        // recv_buffer capacity 1024, rcv_wscale = 2 → 1024 >> 2 = 256
        let tcb = make_tcb(true, 0, 2, 1024);
        assert_eq!(tcb.advertised_window(), 256);
    }

    #[test]
    fn scale_incoming_window_no_scaling() {
        let tcb = make_tcb(false, 0, 0, 1024);
        assert_eq!(tcb.scale_incoming_window(500), 500);
    }

    #[test]
    fn scale_incoming_window_with_scaling() {
        // snd_wscale = 3 → 500 << 3 = 4000
        let tcb = make_tcb(true, 3, 0, 1024);
        assert_eq!(tcb.scale_incoming_window(500), 4000);
    }

    #[test]
    fn receiver_sws_avoidance_holds_small_window_opens() {
        // Buffer capacity = 64, rcv_mss = 1460.
        // threshold = min(1460, 64/2) = 32.
        let mut tcb = make_tcb(false, 0, 0, 64);
        tcb.rcv_nxt = 1000;

        // Initially, no previous right edge — full window advertised.
        assert_eq!(tcb.advertised_window(), 64);

        // Simulate: buffer was full, we advertised right edge at rcv_nxt + 64.
        tcb.last_advertised_right_edge = 1000u32.wrapping_add(64);

        // Fill 48 bytes of the buffer, leaving 16 bytes free.
        tcb.recv_buffer.write(&[0u8; 48]);

        // Free space = 16, new_space = (1000+16) - (1000+64) = -48 (negative, no new space).
        // Since new_space is not positive, effective_free = free = 16.
        assert_eq!(tcb.advertised_window(), 16);

        // Now simulate the app reads 48 bytes → buffer is fully free (64 bytes).
        let mut drain = [0u8; 48];
        tcb.recv_buffer.read(&mut drain);

        // Free space = 64, right_edge = 1000+64, prev = 1064.
        // new_space = 1064 - 1064 = 0, not > 0 → effective_free = 64.
        assert_eq!(tcb.advertised_window(), 64);

        // Now advance rcv_nxt by 48 (data was received and consumed).
        tcb.rcv_nxt = 1048;
        // Fill 54 bytes leaving 10 free.
        tcb.recv_buffer.write(&[0u8; 54]);
        // Free space = 10, right_edge = 1048+10 = 1058, prev = 1064.
        // new_space = 1058 - 1064 = -6 (negative) → effective_free = 10.
        assert_eq!(tcb.advertised_window(), 10);

        // App reads 10 bytes → 20 free.
        let mut drain2 = [0u8; 10];
        tcb.recv_buffer.read(&mut drain2);
        // Free = 20, right_edge = 1048+20 = 1068, prev = 1064.
        // new_space = 1068 - 1064 = 4 < threshold(32) → clamped.
        // clamped = 1064 - 1048 = 16. min(16, 20) = 16.
        assert_eq!(
            tcb.advertised_window(),
            16,
            "SWS holds: only 4 bytes of new space < threshold 32"
        );

        // App reads 34 more bytes → 54 free.
        let mut drain3 = [0u8; 34];
        tcb.recv_buffer.read(&mut drain3);
        // Free = 54, right_edge = 1048+54 = 1102, prev = 1064.
        // new_space = 1102 - 1064 = 38 >= threshold(32) → opens.
        assert_eq!(
            tcb.advertised_window(),
            54,
            "SWS opens: 38 bytes of new space >= threshold 32"
        );
    }

    #[test]
    fn update_advertised_edge_sets_right_edge() {
        let mut tcb = make_tcb(false, 0, 0, 128);
        tcb.rcv_nxt = 5000;
        assert_eq!(tcb.last_advertised_right_edge, 0);

        tcb.update_advertised_edge();
        // free_space = 128 (empty buffer).
        assert_eq!(tcb.last_advertised_right_edge, 5000u32.wrapping_add(128));
    }

    #[test]
    fn update_send_window_zero_to_nonzero_returns_true() {
        let mut tcb = make_tcb(false, 0, 0, 1024);
        assert_eq!(tcb.snd_wnd, 0);
        assert!(tcb.update_send_window(1000));
    }

    #[test]
    fn update_send_window_nonzero_to_nonzero_returns_false() {
        let mut tcb = make_tcb(false, 0, 0, 1024);
        tcb.snd_wnd = 500;
        assert!(!tcb.update_send_window(1000));
    }

    #[test]
    fn update_send_window_nonzero_to_zero_returns_false() {
        let mut tcb = make_tcb(false, 0, 0, 1024);
        tcb.snd_wnd = 500;
        assert!(!tcb.update_send_window(0));
    }

    #[test]
    fn update_send_window_zero_to_zero_returns_false() {
        let mut tcb = make_tcb(false, 0, 0, 1024);
        assert!(!tcb.update_send_window(0));
    }
}
