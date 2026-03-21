use std::net::SocketAddr;
use std::time::Instant;

/// Anti-amplification limit (RFC 9000 §8.1).
///
/// Before address validation, a server MUST NOT send more than three times
/// as many bytes as have been received.
pub struct AmplificationLimit {
    pub bytes_received: usize,
    pub bytes_sent: usize,
    pub validated: bool,
}

impl AmplificationLimit {
    pub fn new() -> Self {
        Self {
            bytes_received: 0,
            bytes_sent: 0,
            validated: false,
        }
    }

    /// Returns `true` if we are allowed to send `bytes` more bytes.
    pub fn can_send(&self, bytes: usize) -> bool {
        self.validated || self.bytes_sent + bytes <= 3 * self.bytes_received
    }

    pub fn on_bytes_received(&mut self, bytes: usize) {
        self.bytes_received += bytes;
    }

    pub fn on_bytes_sent(&mut self, bytes: usize) {
        self.bytes_sent += bytes;
    }

    pub fn set_validated(&mut self) {
        self.validated = true;
    }
}

/// State for a network path (RFC 9000 §9).
pub struct PathState {
    pub remote_addr: Option<SocketAddr>,
    pub local_addr: Option<SocketAddr>,
    pub validated: bool,
    pub mtu_validated: bool,
    pub challenge_pending: Option<[u8; 8]>,
    pub challenge_sent_at: Option<Instant>,
    pub amplification: AmplificationLimit,
}

impl PathState {
    pub fn new() -> Self {
        Self {
            remote_addr: None,
            local_addr: None,
            validated: false,
            mtu_validated: false,
            challenge_pending: None,
            challenge_sent_at: None,
            amplification: AmplificationLimit::new(),
        }
    }
}
