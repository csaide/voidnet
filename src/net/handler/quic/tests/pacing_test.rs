use coarsetime::{Duration, Instant};

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
    // cwnd=12000, rtt=100ms → rate ≈ 1.25 * 12000 / 0.1 = 150000 bytes/sec
    // coarsetime has ~3% precision for sub-second durations, so allow tolerance.
    pacer.update_rate(12000, Duration::from_millis(100));
    let rate = pacer.rate();
    assert!(
        rate >= 145_000 && rate <= 160_000,
        "expected rate near 150000, got {}",
        rate
    );
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
    // burst=0 so any sent packet goes through the pacing path
    let mut pacer = Pacer::new(0);
    pacer.update_rate(12000, Duration::from_millis(100));
    let now = Instant::now();
    // Send a packet — with no burst, this sets next_send_time
    pacer.on_packet_sent(1200, now);
    let next = pacer.next_send_time();
    assert!(next.is_some(), "should have a scheduled send time");
    // At 'now', next_send_time is in the future, burst_allowance=0 → cannot send
    assert!(!pacer.can_send(now, 1200));
    // After the scheduled time, we can send again
    let after = next.unwrap() + Duration::new(0, 1);
    assert!(pacer.can_send(after, 1200));
}

#[test]
fn pacer_next_send_time() {
    // burst=0 so the pacing path is taken immediately
    let mut pacer = Pacer::new(0);
    pacer.update_rate(12000, Duration::from_millis(100));
    assert!(pacer.next_send_time().is_none());
    let now = Instant::now();
    pacer.on_packet_sent(1200, now);
    // After sending with no burst, next_send_time should be set in the future
    let nst = pacer.next_send_time();
    assert!(nst.is_some());
    assert!(nst.unwrap() > now);
}

#[test]
fn pacer_reset_burst() {
    // burst=1200 so we can send one packet immediately; second is paced
    let mut pacer = Pacer::new(1200);
    pacer.update_rate(12000, Duration::from_millis(100));
    let now = Instant::now();
    // Exhaust burst (burst_allowance = 1200 - 1200 = 0, returns early, no next_send_time)
    pacer.on_packet_sent(1200, now);
    // Send a second packet — no burst left, goes through pacing path
    pacer.on_packet_sent(1200, now);
    // next_send_time is now set in the future; cannot send
    assert!(!pacer.can_send(now, 1200));
    // Reset burst re-enables immediate sends
    pacer.reset_burst();
    assert!(pacer.can_send(now, 1200));
}
