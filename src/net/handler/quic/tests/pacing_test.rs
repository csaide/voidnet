use std::time::{Duration, Instant};

use crate::net::handler::quic::transport::pacing::Pacer;

#[test]
fn pacer_initial_can_send() {
    // Before any rate update, rate=0, can always send
    let pacer = Pacer::new(12000);
    let now = Instant::now();
    assert!(pacer.can_send(now, 1200));
    assert!(pacer.can_send(now, 12000));
}

#[test]
fn pacer_update_rate() {
    let mut pacer = Pacer::new(12000);
    // cwnd=12000, rtt=100ms → rate = 1.25 * 12000 / 0.1 = 150000 bytes/sec
    pacer.update_rate(12000, Duration::from_millis(100));
    assert_eq!(pacer.rate(), 150_000);
}

#[test]
fn pacer_burst_allowance() {
    let mut pacer = Pacer::new(12000);
    pacer.update_rate(12000, Duration::from_millis(100));
    let now = Instant::now();
    // First burst of packets should send immediately
    assert!(pacer.can_send(now, 1200));
    pacer.on_packet_sent(1200, now);
    assert!(pacer.can_send(now, 1200));
    pacer.on_packet_sent(1200, now);
    assert!(pacer.can_send(now, 1200));
}

#[test]
fn pacer_throttles_after_burst() {
    let mut pacer = Pacer::new(1200);
    pacer.update_rate(12000, Duration::from_millis(100));
    let now = Instant::now();
    // Exhaust the burst allowance
    pacer.on_packet_sent(1200, now);
    // Burst exhausted; next_send_time is in the future
    // can_send with burst_allowance=0 and now < next_send_time should return false
    let slightly_later = now; // same instant: next_send_time > now
    let next = pacer.next_send_time();
    assert!(next.is_some(), "should have a scheduled send time");
    // At 'now', we cannot send (burst_allowance=0, next_send_time in future)
    assert!(!pacer.can_send(slightly_later, 1200));
    // After the scheduled time, we can send again
    let after = next.unwrap() + Duration::from_nanos(1);
    assert!(pacer.can_send(after, 1200));
}

#[test]
fn pacer_next_send_time() {
    let mut pacer = Pacer::new(1200);
    pacer.update_rate(12000, Duration::from_millis(100));
    assert!(pacer.next_send_time().is_none());
    let now = Instant::now();
    pacer.on_packet_sent(1200, now);
    // After exhausting burst, next_send_time should be set
    let nst = pacer.next_send_time();
    assert!(nst.is_some());
    assert!(nst.unwrap() > now);
}

#[test]
fn pacer_reset_burst() {
    let mut pacer = Pacer::new(1200);
    pacer.update_rate(12000, Duration::from_millis(100));
    let now = Instant::now();
    // Exhaust burst
    pacer.on_packet_sent(1200, now);
    assert!(!pacer.can_send(now, 1200));
    // Reset burst re-enables immediate send
    pacer.reset_burst();
    assert!(pacer.can_send(now, 1200));
}
