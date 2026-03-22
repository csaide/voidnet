use coarsetime::{Duration, Instant};

use crate::net::congestion::CongestionController;

// RFC 9002 §7.2 constants
const K_MINIMUM_WINDOW_PACKETS: usize = 2;
const K_LOSS_REDUCTION_FACTOR: f64 = 0.5;
const K_PERSISTENT_CONGESTION_THRESHOLD: u32 = 3;

pub struct QuicCubic {
    // Window state
    pub(crate) cwnd: usize,
    pub(crate) ssthresh: usize,
    bytes_in_flight: usize,
    max_datagram_size: usize,

    // CUBIC state
    w_max: f64, // window size at last congestion event
    #[allow(dead_code)]
    k: f64, // time period for CUBIC to reach w_max
    epoch_start: Option<Instant>, // start of current congestion epoch

    // Recovery
    congestion_recovery_start_time: Option<Instant>,

    // App-limited
    app_limited: bool,
}

impl QuicCubic {
    pub fn new(max_datagram_size: usize) -> Self {
        let initial_window = initial_window(max_datagram_size);
        Self {
            cwnd: initial_window,
            ssthresh: usize::MAX,
            bytes_in_flight: 0,
            max_datagram_size,
            w_max: 0.0,
            k: 0.0,
            epoch_start: None,
            congestion_recovery_start_time: None,
            app_limited: false,
        }
    }

    pub fn set_app_limited(&mut self, limited: bool) {
        self.app_limited = limited;
    }

    pub fn in_persistent_congestion(&self, duration: Duration, pto: Duration) -> bool {
        duration > pto * K_PERSISTENT_CONGESTION_THRESHOLD
    }

    pub fn on_persistent_congestion(&mut self) {
        self.cwnd = self.minimum_window();
        self.congestion_recovery_start_time = None;
        self.ssthresh = self.cwnd;
    }

    /// RFC 9002 §7.6.1: persistent congestion duration always includes max_ack_delay
    pub fn persistent_congestion_threshold(
        smoothed_rtt: coarsetime::Duration,
        rttvar: coarsetime::Duration,
        max_ack_delay: coarsetime::Duration,
    ) -> coarsetime::Duration {
        let granularity = coarsetime::Duration::from_millis(1);
        let var4 = rttvar * 4;
        let var_component = if var4 > granularity {
            var4
        } else {
            granularity
        };
        (smoothed_rtt + var_component + max_ack_delay) * K_PERSISTENT_CONGESTION_THRESHOLD
    }

    fn minimum_window(&self) -> usize {
        K_MINIMUM_WINDOW_PACKETS * self.max_datagram_size
    }

    #[allow(dead_code)]
    fn in_recovery(&self, sent_time: Instant) -> bool {
        self.congestion_recovery_start_time
            .map(|start| sent_time <= start)
            .unwrap_or(false)
    }
}

/// RFC 9002 §7.2: min(10 * mds, max(14720, 2 * mds))
fn initial_window(max_datagram_size: usize) -> usize {
    (10 * max_datagram_size).min((14720_usize).max(2 * max_datagram_size))
}

impl CongestionController for QuicCubic {
    #[inline]
    fn on_packets_sent(&mut self, bytes: usize, _now: Instant) {
        self.bytes_in_flight += bytes;
    }

    #[inline]
    fn on_ack(
        &mut self,
        acked_bytes: usize,
        _rtt: Duration,
        _min_rtt: Duration,
        _now: Instant,
        in_flight: bool,
        sent_time: Instant,
    ) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(acked_bytes);

        // Only grow window for in-flight packets (RFC 9002 §7.3.2)
        if !in_flight {
            return;
        }

        // During recovery, only grow window for packets sent after recovery started
        // (Fix 16: Don't clear congestion_recovery_start_time; it naturally becomes
        // irrelevant as all packets are sent after it.)
        if let Some(start) = self.congestion_recovery_start_time {
            if sent_time <= start {
                return; // still in recovery for this packet
            }
        }

        if self.app_limited {
            return; // Don't grow window when app-limited (RFC 9002 §7.8)
        }

        if self.cwnd < self.ssthresh {
            // Slow start: cwnd += acked_bytes
            self.cwnd += acked_bytes;
        } else {
            // Congestion avoidance: cwnd += mds * acked_bytes / cwnd
            self.cwnd += self.max_datagram_size * acked_bytes / self.cwnd;
        }
    }

    #[inline]
    fn on_congestion_event(&mut self, lost_bytes: usize, now: Instant, sent_time: Instant) {
        // Only one congestion response per recovery period (RFC 9002 §7.3.2)
        if let Some(start) = self.congestion_recovery_start_time {
            if sent_time <= start {
                self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);
                return;
            }
        }

        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);
        self.congestion_recovery_start_time = Some(now);
        self.w_max = self.cwnd as f64;
        self.ssthresh =
            ((self.cwnd as f64 * K_LOSS_REDUCTION_FACTOR) as usize).max(self.minimum_window());
        self.cwnd = self.ssthresh;
        self.epoch_start = None; // reset CUBIC epoch
    }

    fn on_ecn_ce(&mut self, sent_time: Instant, now: Instant) {
        // ECN CE: trigger congestion event using the sent_time of the largest acked packet
        self.on_congestion_event(0, now, sent_time);
    }

    #[inline]
    fn window(&self) -> usize {
        self.cwnd
    }

    fn bytes_in_flight(&self) -> usize {
        self.bytes_in_flight
    }

    #[inline]
    fn can_send(&self) -> bool {
        self.bytes_in_flight < self.cwnd
    }

    fn on_mtu_update(&mut self, new_mtu: usize) {
        self.max_datagram_size = new_mtu;
    }

    fn reset(&mut self) {
        *self = Self::new(self.max_datagram_size);
    }
}
