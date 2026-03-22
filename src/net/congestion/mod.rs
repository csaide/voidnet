use coarsetime::{Duration, Instant};

/// Pluggable congestion control interface. Monomorphized via generics.
pub trait CongestionController {
    fn on_packets_sent(&mut self, bytes: usize, now: Instant);
    fn on_ack(
        &mut self,
        acked_bytes: usize,
        rtt: Duration,
        min_rtt: Duration,
        now: Instant,
        in_flight: bool,
        sent_time: Instant,
    );
    fn on_congestion_event(&mut self, lost_bytes: usize, now: Instant, sent_time: Instant);
    fn on_ecn_ce(&mut self, sent_time: Instant, now: Instant);
    fn window(&self) -> usize;
    fn bytes_in_flight(&self) -> usize;
    fn can_send(&self) -> bool;
    fn on_mtu_update(&mut self, new_mtu: usize);
    fn reset(&mut self);
}
