use super::keys::DirectionalKey;

/// Tracks key update state for a connection (RFC 9001 §6)
pub struct KeyUpdateState {
    /// Current key phase bit (flipped on each update)
    pub key_phase: bool,
    /// Lowest PN sent with current key phase (for double-update detection)
    pub lowest_pn_current_phase: Option<u64>,
    /// Whether we've received an ACK for current phase
    pub acked_current_phase: bool,
    /// Previous receive key (kept for 3×PTO to handle reordering)
    pub prev_remote_key: Option<DirectionalKey>,
}

impl KeyUpdateState {
    pub fn new() -> Self {
        Self {
            key_phase: false,
            lowest_pn_current_phase: None,
            acked_current_phase: false,
            prev_remote_key: None,
        }
    }

    /// Check if initiating a key update is allowed.
    /// MUST NOT initiate before handshake confirmed.
    /// MUST NOT initiate without ACK for current phase.
    pub fn can_initiate_update(&self) -> bool {
        self.acked_current_phase
    }

    /// Record that a key update was initiated.
    pub fn on_update_initiated(&mut self) {
        self.key_phase = !self.key_phase;
        self.lowest_pn_current_phase = None;
        self.acked_current_phase = false;
    }

    /// Record that a packet was sent with the current key phase.
    pub fn on_packet_sent(&mut self, pn: u64) {
        if self.lowest_pn_current_phase.is_none() {
            self.lowest_pn_current_phase = Some(pn);
        }
    }

    /// Record that an ACK was received for a packet in the current key phase.
    pub fn on_ack_for_current_phase(&mut self) {
        self.acked_current_phase = true;
    }

    /// Check if a received key phase indicates a peer-initiated update.
    pub fn is_peer_update(&self, received_key_phase: bool) -> bool {
        received_key_phase != self.key_phase
    }
}
