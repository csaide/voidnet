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
    ///
    /// `receiver_window` is the largest window advertised by the peer
    /// (`max_snd_wnd`). `cwnd` is clamped to this value after growth to
    /// prevent unbounded increase on lossless links.
    pub fn on_ack(&mut self, bytes_acked: u32, now: Instant, rtt_ms: u64, receiver_window: u32) {
        let mss = self.eff_mss as u32;
        if self.cwnd < self.ssthresh {
            // Slow start.
            self.cwnd = self.cwnd.saturating_add(mss);
        } else {
            // Congestion avoidance — stub for now (Task 2 replaces this).
            self.cubic_update(bytes_acked, now, rtt_ms);
        }
        // Cap cwnd at receiver window — growing beyond the peer's buffer is
        // pointless since the effective send window is min(cwnd, snd_wnd).
        if receiver_window > 0 {
            self.cwnd = self.cwnd.min(receiver_window);
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

    /// CUBIC window function (RFC 9438 §5).
    fn cubic_update(&mut self, _bytes_acked: u32, now: Instant, rtt_ms: u64) {
        let mss = self.eff_mss as u32;

        // Initialize epoch on first ACK in congestion avoidance.
        if self.epoch_start.is_none() {
            self.epoch_start = Some(now);
            if self.cwnd < self.w_max {
                self.k = ((self.w_max - self.cwnd) as f64 / CUBIC_C).cbrt();
                self.origin_point = self.w_max;
            } else {
                self.k = 0.0;
                self.origin_point = self.cwnd;
            }
            self.ack_count = 0;
            self.tcp_cwnd = self.cwnd;
        }

        let epoch_start = self.epoch_start.unwrap();
        let t = now.duration_since(epoch_start).as_millis() as f64 / 1000.0;

        // W_cubic(t) = C * (t - K)^3 + origin_point.
        let t_minus_k = t - self.k;
        let w_cubic =
            (CUBIC_C * t_minus_k * t_minus_k * t_minus_k) as i64 + self.origin_point as i64;
        let w_cubic = (w_cubic.max(mss as i64)) as u32;

        // TCP-friendly estimate.
        if rtt_ms > 0 {
            let rtt_sec = rtt_ms as f64 / 1000.0;
            let acks_since_epoch = t / rtt_sec;
            let reno_inc = (3.0 * (1.0 - CUBIC_BETA) / (1.0 + CUBIC_BETA)) * acks_since_epoch;
            self.tcp_cwnd =
                ((self.origin_point as f64 * CUBIC_BETA) + reno_inc * mss as f64) as u32;
        }

        let target = w_cubic.max(self.tcp_cwnd);

        if target > self.cwnd {
            let delta = target - self.cwnd;
            let inc = ((delta as u64 * mss as u64) / self.cwnd as u64) as u32;
            self.cwnd = self.cwnd.saturating_add(inc.max(1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Large receiver window used in tests so the cap doesn't interfere
    /// with the property being tested.
    const TEST_RWND: u32 = u32::MAX;

    #[test]
    fn slow_start_increases_cwnd_by_mss_per_ack() {
        let mut cubic = CubicState::new(1460);
        // IW = 10 * MSS = 14600, ssthresh = MAX => slow start.
        let now = Instant::now();
        cubic.on_ack(1460, now, 100, TEST_RWND);
        assert_eq!(cubic.cwnd, 14600 + 1460);
        cubic.on_ack(1460, now, 100, TEST_RWND);
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

    #[test]
    fn congestion_avoidance_grows_past_w_max() {
        let mut cubic = CubicState::new(1460);
        // Simulate loss at cwnd=100_000 to set w_max.
        cubic.cwnd = 100_000;
        cubic.on_loss();
        // Now cwnd = 70_000, ssthresh = 70_000, w_max = 100_000.

        let start = Instant::now();
        let rtt_ms = 50;
        // Simulate ~400 ACKs over several seconds.
        for i in 0..400 {
            let elapsed_ms = (i as u64) * rtt_ms;
            let now = start + coarsetime::Duration::from_millis(elapsed_ms);
            cubic.on_ack(1460, now, rtt_ms, TEST_RWND);
        }
        // After enough time, cwnd should exceed w_max.
        assert!(
            cubic.cwnd > 100_000,
            "cwnd {} should exceed w_max 100_000",
            cubic.cwnd
        );
    }

    #[test]
    fn tcp_friendliness_cwnd_at_least_reno() {
        let mut cubic = CubicState::new(1460);
        // Loss at 50_000.
        cubic.cwnd = 50_000;
        cubic.on_loss();
        // cwnd = 35_000, w_max = 50_000.

        let start = Instant::now();
        let rtt_ms = 100;
        let mut reno_cwnd = 35_000u32;
        let mss = 1460u32;
        for i in 0..200 {
            let now = start + coarsetime::Duration::from_millis(i * rtt_ms);
            cubic.on_ack(1460, now, rtt_ms, TEST_RWND);
            // Reno: cwnd += MSS^2 / cwnd per ACK.
            reno_cwnd += (mss * mss) / reno_cwnd;
        }
        assert!(
            cubic.cwnd >= reno_cwnd - mss,
            "CUBIC cwnd {} should be >= Reno cwnd {} (within 1 MSS)",
            cubic.cwnd,
            reno_cwnd
        );
    }

    #[test]
    fn cwnd_capped_at_receiver_window() {
        let mut cubic = CubicState::new(1460);
        // IW = 14600, ssthresh = MAX => slow start.
        let now = Instant::now();
        let receiver_window = 20_000u32;
        // Grow past receiver window.
        for _ in 0..100 {
            cubic.on_ack(1460, now, 100, receiver_window);
        }
        assert_eq!(
            cubic.cwnd, receiver_window,
            "cwnd should be capped at receiver window"
        );
    }

    #[test]
    fn cwnd_does_not_overflow_in_slow_start() {
        let mut cubic = CubicState::new(1460);
        // Manually set cwnd near u32::MAX to verify saturating_add.
        cubic.cwnd = u32::MAX - 500;
        let now = Instant::now();
        // Without saturating_add this would panic.
        cubic.on_ack(1460, now, 100, u32::MAX);
        assert_eq!(cubic.cwnd, u32::MAX);
    }
}
