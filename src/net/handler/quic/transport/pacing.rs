use coarsetime::{Duration, Instant};

/// Timer-driven pacing (RFC 9002 §7.7)
pub struct Pacer {
    /// Current pacing rate in bytes per second
    rate: u64,
    /// When the next packet can be sent
    next_send_time: Option<Instant>,
    /// Burst allowance (bytes that can be sent immediately)
    burst_allowance: usize,
    /// Maximum burst (initial window size)
    max_burst: usize,
}

impl Pacer {
    pub fn new(initial_window: usize) -> Self {
        Self {
            rate: 0,
            next_send_time: None,
            burst_allowance: initial_window,
            max_burst: initial_window,
        }
    }

    /// Update pacing rate from congestion window and RTT.
    /// rate = N * cwnd / srtt (N = 1.25 recommended)
    pub fn update_rate(&mut self, cwnd: usize, smoothed_rtt: Duration) {
        let rtt_ms = smoothed_rtt.as_millis();
        if rtt_ms == 0 {
            self.rate = 0;
            return;
        }
        // rate = 1.25 * cwnd / (rtt_ms / 1000) = 1250 * cwnd / rtt_ms
        self.rate = (1250 * cwnd as u64) / rtt_ms;
    }

    /// Check if a packet of given size can be sent now.
    pub fn can_send(&self, now: Instant, _size: usize) -> bool {
        if self.rate == 0 {
            return true; // no pacing before first RTT
        }
        match self.next_send_time {
            Some(t) if now < t => self.burst_allowance > 0,
            _ => true,
        }
    }

    /// Record that a packet was sent.
    pub fn on_packet_sent(&mut self, size: usize, now: Instant) {
        if self.rate == 0 {
            return;
        }

        if self.burst_allowance >= size {
            self.burst_allowance -= size;
            return;
        }
        self.burst_allowance = 0;

        // Calculate inter-packet interval in nanoseconds, then convert to Duration.
        let interval_ns = (size as u128 * 1_000_000_000) / self.rate as u128;
        let interval_secs = (interval_ns / 1_000_000_000) as u64;
        let interval_nanos = (interval_ns % 1_000_000_000) as u32;
        let interval = Duration::new(interval_secs, interval_nanos);

        self.next_send_time = Some(
            self.next_send_time
                .map(|t| t + interval)
                .filter(|&t| t > now)
                .unwrap_or(now + interval),
        );
    }

    /// Get the next time we're allowed to send (for timer scheduling).
    /// Returns None if we can send immediately.
    pub fn next_send_time(&self) -> Option<Instant> {
        self.next_send_time
    }

    /// Reset burst allowance (e.g., after idle period)
    pub fn reset_burst(&mut self) {
        self.burst_allowance = self.max_burst;
    }

    /// ACK-only packets bypass pacing
    pub fn is_ack_only_exempt() -> bool {
        true
    }

    pub fn rate(&self) -> u64 {
        self.rate
    }
}
