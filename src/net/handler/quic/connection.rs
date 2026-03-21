use coarsetime::{Duration, Instant};

use super::connection_id::{CidSet, ConnectionId};
use super::crypto::keys::PacketKeys;
use super::crypto::tls::CryptoState;
use super::path::PathState;
use super::stream::map::StreamMap;
use super::stream::pool::StreamPool;
use super::timer_kinds::QuicTimerHandles;
use super::transport::ack::AckState;
use super::transport::congestion::QuicCubic;
use super::transport::flow_control::FlowControl;
use super::transport::loss::LossDetector;
use super::transport::params::TransportParams;

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
        Self {
            dcid,
            scid_set: CidSet::new(),
            state: ConnectionState::Handshaking,
            side,
            keys: PacketKeys::new(),
            crypto: None,
            loss: LossDetector::new(),
            congestion: QuicCubic::new(max_datagram_size),
            flow: FlowControl::new(0, local_params.initial_max_data),
            ack: [AckState::new(), AckState::new(), AckState::new()],
            streams: StreamMap::new(is_client),
            stream_pool: StreamPool::new(64),
            path: PathState::new(),
            local_params,
            peer_params: None,
            timers: QuicTimerHandles::new(),
            packets_encrypted: 0,
            failed_decryptions: 0,
            idle_timeout: Duration::from_secs(30),
            max_udp_payload: 1200,
            created_at: now,
        }
    }
}
