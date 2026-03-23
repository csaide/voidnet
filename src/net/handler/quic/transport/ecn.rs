/// ECN validation state per path (RFC 9000 §13.4, RFC 9002 §8)
#[derive(Debug)]
pub struct EcnState {
    /// Whether ECN has been validated for this path
    pub capable: bool,
    /// Whether validation is in progress
    pub validation_pending: bool,
    /// Packets sent with ECT(0) mark during validation
    pub ect0_sent: u64,
    /// Last known CE count from peer's ACK
    pub ce_counter: u64,
    /// Whether ECN was disabled (validation failed)
    pub disabled: bool,
    /// Previous ECT(0) count from peer's ACK
    pub prev_ect0: u64,
    /// Previous ECT(1) count from peer's ACK
    pub prev_ect1: u64,
}

impl EcnState {
    pub fn new() -> Self {
        Self {
            capable: false,
            validation_pending: false,
            ect0_sent: 0,
            ce_counter: 0,
            disabled: false,
            prev_ect0: 0,
            prev_ect1: 0,
        }
    }

    /// Start ECN validation by marking packets with ECT(0)
    pub fn begin_validation(&mut self) {
        if !self.disabled {
            self.validation_pending = true;
        }
    }

    /// Record that a packet was sent with ECT(0) mark
    pub fn on_ect0_sent(&mut self) {
        self.ect0_sent += 1;
    }

    /// Process ECN counts from an ACK frame.
    /// Returns true if congestion was signaled (CE count increased).
    pub fn on_ack_ecn(&mut self, ect0: u64, ect1: u64, ecn_ce: u64) -> bool {
        if self.disabled {
            return false;
        }

        // RFC 9000 §13.4.2.1: ECN counts MUST NOT decrease
        if ect0 < self.prev_ect0 || ect1 < self.prev_ect1 || ecn_ce < self.ce_counter {
            self.disabled = true;
            self.capable = false;
            self.validation_pending = false;
            return false;
        }

        // RFC 9000 §13.4.2.1: If ECT counts don't account for sent packets, disable ECN.
        // The increase in ECT(0)+ECT(1)+CE must be >= newly acknowledged ECT-marked packets.
        let new_ect0 = ect0 - self.prev_ect0;
        let new_ect1 = ect1 - self.prev_ect1;
        let new_ce = ecn_ce - self.ce_counter;
        let total_new_marks = new_ect0 + new_ect1 + new_ce;

        // Validation: if we sent ECT(0) but none reflected, disable ECN
        if self.validation_pending && self.ect0_sent > 0 && total_new_marks == 0 {
            // No ECN marks at all — path strips ECN
            self.disabled = true;
            self.capable = false;
            self.validation_pending = false;
            return false;
        }

        if ect0 > 0 {
            self.capable = true;
            self.validation_pending = false;
        }

        let ce_increased = ecn_ce > self.ce_counter;
        self.prev_ect0 = ect0;
        self.prev_ect1 = ect1;
        self.ce_counter = ecn_ce;
        ce_increased
    }

    /// Reset for path migration (must re-validate)
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}
