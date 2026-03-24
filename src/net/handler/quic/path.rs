use coarsetime::{Duration, Instant};

use crate::net::wire::ip::IpAddress;

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
    #[inline]
    pub fn can_send(&self, bytes: usize) -> bool {
        self.validated || self.bytes_sent + bytes <= 3 * self.bytes_received
    }

    pub fn on_bytes_received(&mut self, bytes: usize) {
        self.bytes_received += bytes;
    }

    #[inline]
    pub fn on_bytes_sent(&mut self, bytes: usize) {
        self.bytes_sent += bytes;
    }

    pub fn set_validated(&mut self) {
        self.validated = true;
    }
}

/// State for a network path (RFC 9000 §9).
pub struct PathState {
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
        if let Some(pending) = &self.challenge_pending
            && pending == data
        {
            self.validated = true;
            self.challenge_pending = None;
            self.challenge_sent_at = None;
            self.amplification.set_validated();
            return true;
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

    /// Handle detecting a new peer address (potential migration).
    /// Compares new_remote/new_port against current_remote/current_port.
    pub fn on_peer_address_change(
        &mut self,
        new_remote: &IpAddress,
        new_port: u16,
        current_remote: &IpAddress,
        current_port: u16,
    ) {
        if new_remote != current_remote || new_port != current_port {
            self.validated = false;
            self.mtu_validated = false;
            // Anti-amplification re-applied
            self.amplification = AmplificationLimit::new();
        }
    }

    /// Whether this path needs a CID rotation (linkability prevention)
    pub fn needs_cid_rotation(&self) -> bool {
        // On migration to a new path, must use different CID
        !self.validated
    }
}

/// PMTU discovery phase (DPLPMTUD, RFC 8899).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmtuPhase {
    Disabled,
    Searching,
    SearchComplete,
}

/// Result from a PMTU probe event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmtuProbeResult {
    Searching,
    Complete,
}

impl PmtuProbeResult {
    pub fn is_searching(self) -> bool {
        self == PmtuProbeResult::Searching
    }
    pub fn is_complete(self) -> bool {
        self == PmtuProbeResult::Complete
    }
}

const BASE_PLPMTU: u16 = 1200;
const MAX_PROBE_ATTEMPTS: u8 = 3;

/// DPLPMTUD state for a single connection path.
pub struct PmtuState {
    phase: PmtuPhase,
    floor: u16,
    ceiling: u16,
    probe_pn: Option<u64>,
    probe_count: u8,
}

impl PmtuState {
    pub fn new(ceiling: u16) -> Self {
        Self {
            phase: PmtuPhase::Disabled,
            floor: BASE_PLPMTU,
            ceiling,
            probe_pn: None,
            probe_count: 0,
        }
    }

    pub fn phase(&self) -> PmtuPhase {
        self.phase
    }
    pub fn floor(&self) -> u16 {
        self.floor
    }
    pub fn ceiling(&self) -> u16 {
        self.ceiling
    }
    pub fn current_mtu(&self) -> u16 {
        self.floor
    }

    pub fn next_probe_size(&self) -> u16 {
        (self.floor + self.ceiling) / 2
    }

    pub fn set_probe_pn(&mut self, pn: u64) {
        self.probe_pn = Some(pn);
        self.probe_count = 0;
    }

    pub fn start_searching(&mut self) {
        self.phase = PmtuPhase::Searching;
        self.probe_count = 0;
        self.probe_pn = None;
    }

    pub fn on_probe_acked(&mut self, pn: u64, step_threshold: u16) -> PmtuProbeResult {
        if self.probe_pn != Some(pn) {
            return if self.phase == PmtuPhase::SearchComplete {
                PmtuProbeResult::Complete
            } else {
                PmtuProbeResult::Searching
            };
        }
        self.floor = self.next_probe_size();
        self.probe_pn = None;
        self.probe_count = 0;
        if self.ceiling - self.floor < step_threshold {
            self.phase = PmtuPhase::SearchComplete;
            PmtuProbeResult::Complete
        } else {
            PmtuProbeResult::Searching
        }
    }

    pub fn on_probe_lost(&mut self, step_threshold: u16) -> PmtuProbeResult {
        self.probe_count += 1;
        if self.probe_count >= MAX_PROBE_ATTEMPTS {
            self.ceiling = self.next_probe_size();
            self.probe_count = 0;
            self.probe_pn = None;
            if self.ceiling - self.floor < step_threshold {
                self.phase = PmtuPhase::SearchComplete;
                return PmtuProbeResult::Complete;
            }
        }
        PmtuProbeResult::Searching
    }

    pub fn on_icmp_reduction(&mut self, new_mtu: u16) {
        let clamped = new_mtu.max(BASE_PLPMTU);
        if clamped < self.floor {
            self.floor = clamped;
            self.phase = PmtuPhase::Searching;
        } else if clamped < self.ceiling {
            self.ceiling = clamped;
            if self.phase == PmtuPhase::SearchComplete {
                self.phase = PmtuPhase::Searching;
            }
        }
        self.probe_pn = None;
        self.probe_count = 0;
    }

    pub fn reset(&mut self, ceiling: u16) {
        *self = Self::new(ceiling);
    }

    pub fn start_reprobing(&mut self, ceiling: u16) {
        self.ceiling = ceiling;
        self.phase = PmtuPhase::Searching;
        self.probe_pn = None;
        self.probe_count = 0;
    }

    pub fn has_outstanding_probe(&self) -> bool {
        self.probe_pn.is_some()
    }

    pub fn outstanding_probe_pn(&self) -> Option<u64> {
        self.probe_pn
    }
}
