use std::time::{Duration, Instant};

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
    );
    assert_eq!(cc.window(), 12120);
}

#[test]
fn loss_reduces_window() {
    let mut cc = QuicCubic::new(1200);
    cc.cwnd = 24000;
    let now = Instant::now();
    cc.on_congestion_event(1200, now);
    // ssthresh = cwnd * 0.5 = 12000, cwnd = ssthresh = 12000
    assert_eq!(cc.window(), 12000);
}

#[test]
fn minimum_window_enforced() {
    let mut cc = QuicCubic::new(1200);
    cc.cwnd = 2400; // minimum_window = 2 * 1200 = 2400
    let now = Instant::now();
    cc.on_congestion_event(1200, now);
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
