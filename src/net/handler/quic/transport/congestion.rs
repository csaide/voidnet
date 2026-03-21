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
    in_congestion_recovery: bool,

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
            in_congestion_recovery: false,
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
    fn on_packets_sent(&mut self, bytes: usize, _now: Instant) {
        self.bytes_in_flight += bytes;
    }

    fn on_ack(&mut self, acked_bytes: usize, _rtt: Duration, _min_rtt: Duration, now: Instant) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(acked_bytes);

        // Exit recovery when we get an ACK after recovery started
        if self.in_congestion_recovery {
            if let Some(start) = self.congestion_recovery_start_time {
                if now > start {
                    self.in_congestion_recovery = false;
                }
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

    fn on_congestion_event(&mut self, lost_bytes: usize, now: Instant) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);

        // Only one congestion response per recovery period
        if self.in_congestion_recovery {
            return;
        }

        self.in_congestion_recovery = true;
        self.congestion_recovery_start_time = Some(now);
        self.w_max = self.cwnd as f64;
        self.ssthresh =
            ((self.cwnd as f64 * K_LOSS_REDUCTION_FACTOR) as usize).max(self.minimum_window());
        self.cwnd = self.ssthresh;
        self.epoch_start = None; // reset CUBIC epoch
    }

    fn on_ecn_ce(&mut self, now: Instant) {
        // Same as congestion event
        self.on_congestion_event(0, now);
    }

    fn window(&self) -> usize {
        self.cwnd
    }

    fn bytes_in_flight(&self) -> usize {
        self.bytes_in_flight
    }

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
