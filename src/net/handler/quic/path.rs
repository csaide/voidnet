use std::net::SocketAddr;

use coarsetime::{Duration, Instant};

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

/// Generate random PATH_CHALLENGE data
pub fn generate_challenge() -> [u8; 8] {
    use ring::rand::SecureRandom;
    let mut data = [0u8; 8];
    // Use ring's random for cryptographic randomness
    ring::rand::SystemRandom::new().fill(&mut data).unwrap();
    data
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

    /// Initiate path validation by sending PATH_CHALLENGE
    pub fn initiate_validation(&mut self, now: Instant) -> [u8; 8] {
        let challenge = generate_challenge();
        self.challenge_pending = Some(challenge);
        self.challenge_sent_at = Some(now);
        challenge
    }

    /// Process a PATH_RESPONSE and check if it matches our challenge
    pub fn on_path_response(&mut self, data: &[u8; 8]) -> bool {
        if let Some(pending) = &self.challenge_pending {
            if pending == data {
                self.validated = true;
                self.challenge_pending = None;
                self.challenge_sent_at = None;
                self.amplification.set_validated();
                return true;
            }
        }
        false
    }

    /// Check if path validation has timed out
    pub fn validation_timed_out(&self, now: Instant, timeout: Duration) -> bool {
        if let Some(sent_at) = self.challenge_sent_at {
            now.duration_since(sent_at) > timeout
        } else {
            false
        }
    }

    /// Handle detecting a new peer address (potential migration)
    pub fn on_peer_address_change(&mut self, new_addr: std::net::SocketAddr) {
        if self.remote_addr.as_ref() != Some(&new_addr) {
            self.remote_addr = Some(new_addr);
            self.validated = false;
            self.mtu_validated = false;
            // Anti-amplification re-applied
            self.amplification = AmplificationLimit::new();
        }
    }

    /// Whether this path needs a CID rotation (linkability prevention)
    pub fn needs_cid_rotation(&self) -> bool {
        // On migration to a new path, must use different CID
        !self.validated && self.remote_addr.is_some()
    }
}
