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
}

impl EcnState {
    pub fn new() -> Self {
        Self {
            capable: false,
            validation_pending: false,
            ect0_sent: 0,
            ce_counter: 0,
            disabled: false,
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
    pub fn on_ack_ecn(&mut self, ect0: u64, _ect1: u64, ecn_ce: u64) -> bool {
        if self.disabled {
            return false;
        }

        // Validation: if we sent ECT(0) but none reflected, disable ECN
        if self.validation_pending && ect0 == 0 && self.ect0_sent > 0 {
            self.disabled = true;
            self.capable = false;
            self.validation_pending = false;
            return false;
        }

        if ect0 > 0 {
            self.capable = true;
            self.validation_pending = false;
        }

        // Check for congestion signal
        let ce_increased = ecn_ce > self.ce_counter;
        self.ce_counter = ecn_ce;
        ce_increased
    }

    /// Reset for path migration (must re-validate)
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}
