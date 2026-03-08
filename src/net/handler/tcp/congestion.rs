use coarsetime::Instant;

/// CUBIC constants (RFC 9438 S5).
const CUBIC_C: f64 = 0.4;
const CUBIC_BETA: f64 = 0.7;

pub struct CubicState {
    pub cwnd: u32,
    pub ssthresh: u32,
    w_max: u32,
    w_max_prev: u32,
    epoch_start: Option<Instant>,
    k: f64,
    origin_point: u32,
    tcp_cwnd: u32,
    ack_count: u32,
    eff_mss: u16,
    cwnd_before_rto: Option<u32>,
    ssthresh_before_rto: Option<u32>,
}

impl CubicState {
    pub fn new(eff_mss: u16) -> Self {
        Self {
            cwnd: 10 * eff_mss as u32,
            ssthresh: u32::MAX,
            w_max: 0,
            w_max_prev: 0,
            epoch_start: None,
            k: 0.0,
            origin_point: 0,
            tcp_cwnd: 0,
            ack_count: 0,
            eff_mss,
            cwnd_before_rto: None,
            ssthresh_before_rto: None,
        }
    }

    pub fn set_mss(&mut self, eff_mss: u16) {
        self.eff_mss = eff_mss;
    }

    /// Called on each new ACK (that advances snd_una). NOT called during recovery.
    pub fn on_ack(&mut self, bytes_acked: u32, now: Instant, rtt_ms: u64) {
        let mss = self.eff_mss as u32;
        if self.cwnd < self.ssthresh {
            // Slow start.
            self.cwnd += mss;
        } else {
            // Congestion avoidance — stub for now (Task 2 replaces this).
            self.cubic_update(bytes_acked, now, rtt_ms);
        }
    }

    /// Called on packet loss (3 dup ACKs / SACK recovery entry).
    pub fn on_loss(&mut self) {
        self.epoch_start = None;
        let mss = self.eff_mss as u32;

        // Fast convergence (RFC 9438 S5.8).
        if self.cwnd < self.w_max_prev {
            self.w_max_prev = self.cwnd;
            self.w_max = (self.cwnd as f64 * (1.0 + CUBIC_BETA) / 2.0) as u32;
        } else {
            self.w_max_prev = self.cwnd;
            self.w_max = self.cwnd;
        }

        self.ssthresh = (self.cwnd as f64 * CUBIC_BETA) as u32;
        self.ssthresh = self.ssthresh.max(2 * mss);
        self.cwnd = self.ssthresh;
    }

    /// Called on ECN congestion signal. Same as loss per RFC 9438.
    pub fn on_ecn(&mut self) {
        self.on_loss();
    }

    /// Called on RTO expiry.
    pub fn on_rto(&mut self) {
        let mss = self.eff_mss as u32;
        self.cwnd_before_rto = Some(self.cwnd);
        self.ssthresh_before_rto = Some(self.ssthresh);
        self.epoch_start = None;

        self.w_max_prev = self.w_max;
        self.w_max = self.cwnd;
        self.ssthresh = (self.cwnd as f64 * CUBIC_BETA) as u32;
        self.ssthresh = self.ssthresh.max(2 * mss);
        self.cwnd = mss;
    }

    /// Restore cwnd/ssthresh after F-RTO determines RTO was spurious.
    pub fn restore_after_spurious_rto(&mut self) {
        if let (Some(cwnd), Some(ssthresh)) = (self.cwnd_before_rto, self.ssthresh_before_rto) {
            self.cwnd = cwnd;
            self.ssthresh = ssthresh;
            self.cwnd_before_rto = None;
            self.ssthresh_before_rto = None;
        }
    }

    // Placeholder for Task 2.
    fn cubic_update(&mut self, bytes_acked: u32, _now: Instant, _rtt_ms: u64) {
        let mss = self.eff_mss as u32;
        self.ack_count += bytes_acked;
        if self.ack_count >= self.cwnd {
            self.cwnd += mss;
            self.ack_count -= self.cwnd - mss;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slow_start_increases_cwnd_by_mss_per_ack() {
        let mut cubic = CubicState::new(1460);
        // IW = 10 * MSS = 14600, ssthresh = MAX => slow start.
        let now = Instant::now();
        cubic.on_ack(1460, now, 100);
        assert_eq!(cubic.cwnd, 14600 + 1460);
        cubic.on_ack(1460, now, 100);
        assert_eq!(cubic.cwnd, 14600 + 2 * 1460);
    }

    #[test]
    fn on_loss_sets_ssthresh_to_cwnd_times_beta() {
        let mut cubic = CubicState::new(1460);
        cubic.cwnd = 100_000;
        cubic.on_loss();
        assert_eq!(cubic.ssthresh, 70_000); // 100_000 * 0.7
        assert_eq!(cubic.cwnd, 70_000);
        assert_eq!(cubic.w_max, 100_000);
    }

    #[test]
    fn on_rto_resets_cwnd_to_one_mss() {
        let mut cubic = CubicState::new(1460);
        cubic.cwnd = 100_000;
        cubic.ssthresh = 50_000;
        cubic.on_rto();
        assert_eq!(cubic.cwnd, 1460);
        assert_eq!(cubic.ssthresh, 70_000); // 100_000 * 0.7
        assert_eq!(cubic.cwnd_before_rto, Some(100_000));
        assert_eq!(cubic.ssthresh_before_rto, Some(50_000));
    }

    #[test]
    fn beta_is_07_not_05() {
        let mut cubic = CubicState::new(1460);
        cubic.cwnd = 10_000;
        cubic.on_loss();
        // Reno would be 5000, CUBIC should be 7000.
        assert_eq!(cubic.ssthresh, 7000);
    }

    #[test]
    fn fast_convergence_reduces_w_max() {
        let mut cubic = CubicState::new(1460);
        // First loss at cwnd=100_000.
        cubic.cwnd = 100_000;
        cubic.on_loss();
        // w_max_prev = 100_000.
        // Second loss at cwnd=80_000 (below w_max_prev).
        cubic.cwnd = 80_000;
        cubic.on_loss();
        // Fast convergence: w_max = 80_000 * (1 + 0.7) / 2 = 68_000.
        assert_eq!(cubic.w_max, 68_000);
    }
}
