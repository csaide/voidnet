use coarsetime::{Duration, Instant};

use super::connection_id::{CidSet, ConnectionId};
use super::crypto::key_update::KeyUpdateState;
use super::crypto::keys::PacketKeys;
use super::crypto::tls::CryptoState;
use super::error::TransportError;
use super::packet_parser::{CryptoRecvBuffer, PnBitset};
use super::path::PathState;
use super::stream::map::StreamMap;
use super::stream::pool::StreamPool;
use super::timer_kinds::QuicTimerHandles;
use super::transport::ack::AckState;
use super::transport::congestion::QuicCubic;
use super::transport::ecn::EcnState;
use super::transport::flow_control::FlowControl;
use super::transport::frame::StreamId;
use super::transport::frame_log::FrameLog;
use super::transport::loss::LossDetector;
use super::transport::pacing::Pacer;
use super::transport::params::TransportParams;
use super::transport::retransmit::RetransmitQueue;
use crate::net::handler::quic::event::QuicEvent;
use crate::net::socket::LocalQueue;
use crate::net::wire::ethernet::MacAddress;
use crate::net::wire::ip::{IpAddress, Ipv4Address};

/// High-level connection state (RFC 9000 §17.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Handshaking,
    HandshakeComplete,
    Established,
    Draining,
    Closing,
    Closed,
}

/// Which side of the connection this endpoint is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Client,
    Server,
}

/// Complete state for a single QUIC connection.
pub struct QuicConnectionState {
    // Identity
    pub dcid: ConnectionId,
    pub scid_set: CidSet,
    pub state: ConnectionState,
    pub side: Side,

    // Crypto
    pub keys: PacketKeys,
    pub crypto: Option<CryptoState>,

    // Transport — one LossDetector covers all three packet number spaces
    pub loss: LossDetector,
    pub congestion: QuicCubic,
    pub flow: FlowControl,
    pub ecn: EcnState,
    /// Per packet-number-space ACK state: [Initial, Handshake, 1-RTT].
    pub ack: [AckState; 3],

    // Streams
    pub streams: StreamMap,
    pub stream_pool: StreamPool,

    // Path
    pub path: PathState,

    // Parameters
    pub local_params: TransportParams,
    pub peer_params: Option<TransportParams>,

    // Timers
    pub timers: QuicTimerHandles,

    // AEAD limits (RFC 9001 §6.6)
    pub packets_encrypted: u64,
    pub failed_decryptions: u64,

    // Config
    pub idle_timeout: Duration,
    pub max_udp_payload: u16,

    // Created time
    pub created_at: Instant,
    /// Last activity time (for idle timeout tracking)
    pub last_activity: Instant,

    // Handshake CRYPTO buffering
    pub crypto_recv: [CryptoRecvBuffer; 3],
    pub pending_crypto: [Vec<u8>; 3],
    pub crypto_offset: [u64; 3],
    pub crypto_acked: [u64; 3],

    // Transport
    pub pacing: Pacer,
    pub retransmit: RetransmitQueue,

    // Control frames
    pub pending_path_response: Option<[u8; 8]>,
    pub send_handshake_done: bool,
    pub needs_probe: bool,
    /// Set when the connection transitions to Established; cleared after accept_queue push.
    pub notify_established: bool,

    // Frame log
    pub frame_log: FrameLog,

    // Duplicate PN detection
    pub recv_pn_seen: [PnBitset; 3],

    // Primary SCID (used in outgoing packet headers)
    pub scid: ConnectionId,

    // Network addressing
    pub local_addr: IpAddress,
    pub remote_addr: IpAddress,
    pub local_port: u16,
    pub remote_port: u16,
    pub local_mac: MacAddress,
    pub remote_mac: MacAddress,

    // Socket API queues
    /// Accept queue from the listener — pushed when handshake completes (server side).
    pub accept_queue: Option<LocalQueue<usize>>,
    /// Per-stream accept queue — new peer-initiated stream IDs are pushed here.
    pub stream_accept_queue: LocalQueue<StreamId>,
    /// Per-connection event queue for waking socket futures.
    pub event_queue: LocalQueue<QuicEvent>,

    /// Key update state tracking (RFC 9001 §6)
    pub key_update: KeyUpdateState,

    /// Key update secrets from rustls (for key update support)
    pub key_update_secrets: Option<rustls::quic::Secrets>,

    /// QUIC version in use for this connection
    pub version: u32,

    /// Transport error to send in CONNECTION_CLOSE when entering Closing state
    pub close_error: Option<TransportError>,
}

impl QuicConnectionState {
    pub fn new(
        dcid: ConnectionId,
        side: Side,
        local_params: TransportParams,
        max_datagram_size: usize,
        now: Instant,
    ) -> Self {
        let is_client = side == Side::Client;
        let congestion = QuicCubic::new(max_datagram_size);
        let initial_window = congestion.cwnd;
        let mut streams = StreamMap::new(is_client);
        streams.local_max_bidi = local_params.initial_max_streams_bidi;
        streams.local_max_uni = local_params.initial_max_streams_uni;
        let idle_timeout = if local_params.max_idle_timeout_ms > 0 {
            Duration::from_millis(local_params.max_idle_timeout_ms)
        } else {
            Duration::from_millis(0)
        };
        Self {
            dcid,
            scid_set: CidSet::new(),
            state: ConnectionState::Handshaking,
            side,
            keys: PacketKeys::new(),
            crypto: None,
            loss: LossDetector::new(),
            congestion,
            flow: FlowControl::new(0, local_params.initial_max_data),
            ecn: EcnState::new(),
            ack: [AckState::new(), AckState::new(), AckState::new()],
            streams,
            stream_pool: StreamPool::new(64),
            path: PathState::new(),
            local_params,
            peer_params: None,
            timers: QuicTimerHandles::new(),
            packets_encrypted: 0,
            failed_decryptions: 0,
            idle_timeout,
            max_udp_payload: 1200,
            created_at: now,
            last_activity: now,
            crypto_recv: [
                CryptoRecvBuffer::new(),
                CryptoRecvBuffer::new(),
                CryptoRecvBuffer::new(),
            ],
            pending_crypto: [Vec::new(), Vec::new(), Vec::new()],
            crypto_offset: [0; 3],
            crypto_acked: [0; 3],
            pacing: Pacer::new(initial_window),
            retransmit: RetransmitQueue::new(),
            pending_path_response: None,
            send_handshake_done: false,
            needs_probe: false,
            notify_established: false,
            frame_log: FrameLog::new(1024),
            recv_pn_seen: [PnBitset::new(), PnBitset::new(), PnBitset::new()],
            scid: ConnectionId::empty(),
            local_addr: IpAddress::V4(Ipv4Address::new([0, 0, 0, 0])),
            remote_addr: IpAddress::V4(Ipv4Address::new([0, 0, 0, 0])),
            local_port: 0,
            remote_port: 0,
            local_mac: MacAddress::zero(),
            remote_mac: MacAddress::zero(),
            accept_queue: None,
            stream_accept_queue: LocalQueue::new(64),
            event_queue: LocalQueue::new(64),
            key_update: KeyUpdateState::new(),
            key_update_secrets: None,
            version: 0x00000001, // QUIC v1 default
            close_error: None,
        }
    }
}
