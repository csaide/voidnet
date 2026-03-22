use coarsetime::{Duration, Instant};

use crate::net::congestion::CongestionController;
use crate::net::handler::quic::transport::congestion::QuicCubic;

#[test]
fn initial_window_calculation() {
    // mds = 1200: min(12000, max(14720, 2400)) = min(12000, 14720) = 12000
    let cc = QuicCubic::new(1200);
    assert_eq!(cc.window(), 12000);
}

#[test]
fn initial_window_large_mds() {
    // mds = 1500: min(15000, max(14720, 3000)) = min(15000, 14720) = 14720
    let cc = QuicCubic::new(1500);
    assert_eq!(cc.window(), 14720);
}

#[test]
fn slow_start_growth() {
    let mut cc = QuicCubic::new(1200);
    let now = Instant::now();
    cc.on_packets_sent(1200, now);
    cc.on_ack(
        1200,
        Duration::from_millis(50),
        Duration::from_millis(50),
        now,
        true,
        now,
    );
    assert_eq!(cc.window(), 12000 + 1200); // slow start adds acked_bytes
}

#[test]
fn congestion_avoidance_growth() {
    let mut cc = QuicCubic::new(1200);
    cc.ssthresh = 10000; // force into CA
    cc.cwnd = 12000;
    let now = Instant::now();
    cc.on_packets_sent(1200, now);
    // CA: cwnd += mds * acked / cwnd = 1200 * 1200 / 12000 = 120
    cc.on_ack(
        1200,
        Duration::from_millis(50),
        Duration::from_millis(50),
        now,
        true,
        now,
    );
    assert_eq!(cc.window(), 12120);
}

#[test]
fn loss_reduces_window() {
    let mut cc = QuicCubic::new(1200);
    cc.cwnd = 24000;
    let now = Instant::now();
    cc.on_congestion_event(1200, now, now);
    // ssthresh = cwnd * 0.5 = 12000, cwnd = ssthresh = 12000
    assert_eq!(cc.window(), 12000);
}

#[test]
fn minimum_window_enforced() {
    let mut cc = QuicCubic::new(1200);
    cc.cwnd = 2400; // minimum_window = 2 * 1200 = 2400
    let now = Instant::now();
    cc.on_congestion_event(1200, now, now);
    // 0.5 * 2400 = 1200, but minimum is 2400
    assert_eq!(cc.window(), 2400);
}

#[test]
fn persistent_congestion_resets_to_minimum() {
    let mut cc = QuicCubic::new(1200);
    cc.cwnd = 24000;
    cc.on_persistent_congestion();
    assert_eq!(cc.window(), 2400); // 2 * mds
}

#[test]
fn app_limited_prevents_growth() {
    let mut cc = QuicCubic::new(1200);
    cc.set_app_limited(true);
    let now = Instant::now();
    let initial = cc.window();
    cc.on_packets_sent(1200, now);
    cc.on_ack(
        1200,
        Duration::from_millis(50),
        Duration::from_millis(50),
        now,
        true,
        now,
    );
    assert_eq!(cc.window(), initial); // no growth
}

#[test]
fn can_send_checks_flight() {
    let mut cc = QuicCubic::new(1200);
    assert!(cc.can_send());
    let now = Instant::now();
    // Fill the window
    cc.on_packets_sent(cc.window(), now);
    assert!(!cc.can_send());
}

#[test]
fn reset_restores_initial_state() {
    let mut cc = QuicCubic::new(1200);
    cc.cwnd = 50000;
    cc.ssthresh = 10000;
    cc.reset();
    assert_eq!(cc.window(), 12000); // initial window
    assert_eq!(cc.bytes_in_flight(), 0);
}

/// RFC 9002 §7.3.2: a congestion event for a packet sent before the recovery
/// period start time must not trigger a second window reduction.
#[test]
fn test_recovery_ignores_old_losses() {
    let mut cc = QuicCubic::new(1200);
    cc.cwnd = 24000;
    let t0 = Instant::now();
    // Trigger recovery now with a packet sent at t0
    cc.on_congestion_event(0, t0, t0);
    let window_after_first = cc.window();
    assert_eq!(window_after_first, 12000);

    // A second congestion event for a packet sent at or before t0 must be ignored
    cc.on_congestion_event(0, t0, t0);
    assert_eq!(cc.window(), window_after_first); // no further reduction
}

/// RFC 9002 §7.3.2: an ACK for a packet sent after the recovery start allows
/// the window to grow again.
#[test]
fn test_recovery_exits_on_new_ack() {
    let mut cc = QuicCubic::new(1200);
    cc.cwnd = 24000;
    let t0 = Instant::now();

    // Enter recovery
    cc.on_congestion_event(0, t0, t0);
    let window_in_recovery = cc.window();

    // Simulate a packet sent after recovery start being acknowledged
    let t1 = t0 + Duration::from_millis(100);
    cc.on_ack(
        1200,
        Duration::from_millis(50),
        Duration::from_millis(50),
        t1,
        true,
        t1, // sent_time after recovery start
    );
    // Window should grow (recovery is over for this packet)
    assert!(cc.window() > window_in_recovery);
}

/// RFC 8312: CUBIC congestion avoidance grows the window beyond w_max after loss.
#[test]
fn cubic_growth_after_loss() {
    use crate::net::congestion::CongestionController;
    use crate::net::handler::quic::transport::congestion::QuicCubic;
    use coarsetime::{Duration, Instant};

    let mds = 1200;
    let mut cubic = QuicCubic::new(mds);
    let now = Instant::now();

    // Grow in slow start
    for _ in 0..20 {
        cubic.on_packets_sent(mds, now);
        cubic.on_ack(
            mds,
            Duration::from_millis(50),
            Duration::from_millis(50),
            now,
            true,
            now,
        );
    }
    let pre_loss = cubic.window();
    assert!(pre_loss > 20000);

    // Loss event
    let loss_time = now + Duration::from_millis(100);
    cubic.on_congestion_event(mds, loss_time, loss_time);
    let post_loss = cubic.window();
    assert!(post_loss < pre_loss);
    assert_eq!(post_loss, (pre_loss as f64 * 0.5) as usize);

    // Congestion avoidance — CUBIC should grow
    for i in 0..200u64 {
        let t = loss_time + Duration::from_millis(200 + i * 50);
        cubic.on_packets_sent(mds, t);
        cubic.on_ack(
            mds,
            Duration::from_millis(50),
            Duration::from_millis(50),
            t,
            true,
            t,
        );
    }
    let final_cwnd = cubic.window();
    assert!(
        final_cwnd > post_loss,
        "CUBIC should grow: final={}, post_loss={}",
        final_cwnd,
        post_loss
    );
}

/// RFC 9002 §7.3.2: on_ack for a packet that was not in-flight must not
/// cause window growth.
#[test]
fn test_non_in_flight_no_growth() {
    let mut cc = QuicCubic::new(1200);
    let now = Instant::now();
    let initial = cc.window();
    cc.on_packets_sent(1200, now);
    cc.on_ack(
        1200,
        Duration::from_millis(50),
        Duration::from_millis(50),
        now,
        false, // not in-flight
        now,
    );
    assert_eq!(cc.window(), initial); // no growth
}
