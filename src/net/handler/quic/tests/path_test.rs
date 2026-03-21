use coarsetime::{Duration, Instant};

use crate::net::handler::quic::path::{AmplificationLimit, PathState};
use crate::net::wire::ip::{IpAddress, Ipv4Address};

fn make_ip(last_octet: u8) -> IpAddress {
    IpAddress::V4(Ipv4Address::new([127, 0, 0, last_octet]))
}

#[test]
fn path_validation_roundtrip() {
    let mut path = PathState::new();
    let now = Instant::now();
    let challenge = path.initiate_validation(now);
    assert!(path.challenge_pending.is_some());
    assert!(!path.validated);
    let ok = path.on_path_response(&challenge);
    assert!(ok);
    assert!(path.validated);
    assert!(path.challenge_pending.is_none());
    assert!(path.challenge_sent_at.is_none());
    assert!(path.amplification.validated);
}

#[test]
fn path_validation_wrong_response() {
    let mut path = PathState::new();
    let now = Instant::now();
    let _challenge = path.initiate_validation(now);
    let wrong = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04];
    let ok = path.on_path_response(&wrong);
    assert!(!ok);
    assert!(!path.validated);
    assert!(path.challenge_pending.is_some());
}

#[test]
fn path_validation_timeout() {
    let mut path = PathState::new();
    let now = Instant::now();
    let _challenge = path.initiate_validation(now);
    let timeout = Duration::from_secs(5);
    // Not timed out yet (sent at 'now', checking at 'now')
    assert!(!path.validation_timed_out(now, timeout));
    // Timed out after 6 seconds
    let later = now + Duration::from_secs(6);
    assert!(path.validation_timed_out(later, timeout));
}

#[test]
fn peer_address_change_resets_validation() {
    let mut path = PathState::new();
    let now = Instant::now();
    let challenge = path.initiate_validation(now);
    path.on_path_response(&challenge);
    assert!(path.validated);

    let current_addr = make_ip(1);
    let current_port = 4433u16;

    // New address triggers reset of validation state
    let new_addr = make_ip(2);
    let new_port = 4434u16;
    path.on_peer_address_change(&new_addr, new_port, &current_addr, current_port);
    assert!(!path.validated);
    assert!(!path.mtu_validated);
    assert!(!path.amplification.validated);
}

#[test]
fn peer_address_same_no_reset() {
    let mut path = PathState::new();
    let now = Instant::now();
    let challenge = path.initiate_validation(now);
    path.on_path_response(&challenge);
    assert!(path.validated);

    let addr = make_ip(1);
    let port = 4433u16;

    // Same address does NOT reset validation
    path.on_peer_address_change(&addr, port, &addr, port);
    assert!(path.validated);
}

#[test]
fn amplification_limit_enforced() {
    let mut amp = AmplificationLimit::new();
    amp.on_bytes_received(100);
    // Can send up to 3x received = 300
    assert!(amp.can_send(300));
    assert!(!amp.can_send(301));
    amp.on_bytes_sent(200);
    assert!(amp.can_send(100));
    assert!(!amp.can_send(101));
}

#[test]
fn amplification_validated_removes_limit() {
    let mut amp = AmplificationLimit::new();
    // No bytes received, cannot send anything before validation
    assert!(!amp.can_send(1));
    amp.set_validated();
    // After validation, unlimited
    assert!(amp.can_send(1_000_000));
}
