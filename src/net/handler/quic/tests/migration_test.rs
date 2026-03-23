use coarsetime::Instant;

use crate::net::handler::quic::connection::{
    ConnectionState, PreviousPath, QuicConnectionState, Side,
};
use crate::net::handler::quic::connection_id::ConnectionId;
use crate::net::handler::quic::error::TransportError;
use crate::net::handler::quic::path::PathState;
use crate::net::handler::quic::processor::{TimerResult, handle_timeout};
use crate::net::handler::quic::timer_kinds::QuicTimerKind;
use crate::net::handler::quic::transport::params::TransportParams;
use crate::net::wire::ethernet::MacAddress;
use crate::net::wire::ip::{IpAddress, Ipv4Address};

fn make_conn() -> QuicConnectionState {
    let dcid = ConnectionId::from_slice(&[0x01, 0x02, 0x03, 0x04]);
    let params = TransportParams::default();
    let now = Instant::now();
    QuicConnectionState::new(dcid, Side::Server, params, 1200, now)
}

// ---------- CidSet::pick_unused tests ----------

#[test]
fn pick_unused_returns_non_active_cid() {
    use crate::net::handler::quic::connection_id::CidSet;

    let mut set = CidSet::new();
    let active = ConnectionId::from_slice(&[0x01]);
    let spare = ConnectionId::from_slice(&[0x02]);
    set.push_with_seq(active, 0);
    set.push_with_seq(spare, 1);

    let result = set.pick_unused(&active);
    assert!(result.is_some());
    let (cid, seq) = result.unwrap();
    assert_eq!(cid, spare);
    assert_eq!(seq, 1);
}

#[test]
fn pick_unused_returns_none_when_only_active() {
    use crate::net::handler::quic::connection_id::CidSet;

    let mut set = CidSet::new();
    let active = ConnectionId::from_slice(&[0x01]);
    set.push_with_seq(active, 0);

    let result = set.pick_unused(&active);
    assert!(result.is_none());
}

#[test]
fn pick_unused_returns_none_on_empty_set() {
    use crate::net::handler::quic::connection_id::CidSet;

    let set = CidSet::new();
    let active = ConnectionId::from_slice(&[0x01]);
    let result = set.pick_unused(&active);
    assert!(result.is_none());
}

// ---------- PathValidation timeout tests ----------

#[test]
fn path_validation_timeout_reverts_to_prev_path() {
    let mut conn = make_conn();
    let now = Instant::now();

    // Set up current path as unvalidated (migration in progress)
    conn.path = PathState::new();
    conn.path.validated = false;
    conn.remote_addr = IpAddress::V4(Ipv4Address::new([10, 0, 0, 2]));
    conn.remote_port = 5000;
    conn.remote_mac = MacAddress::new([0xaa; 6]);

    // Provide a previous path to revert to
    let prev_addr = IpAddress::V4(Ipv4Address::new([10, 0, 0, 1]));
    let prev_port = 4433u16;
    let prev_mac = MacAddress::new([0xbb; 6]);
    let mut prev_path = PathState::new();
    prev_path.validated = true;
    conn.prev_path = Some(PreviousPath {
        remote_addr: prev_addr,
        remote_port: prev_port,
        remote_mac: prev_mac,
        path: prev_path,
    });

    let result = handle_timeout(&mut conn, QuicTimerKind::PathValidation, now);
    assert!(matches!(result, TimerResult::Ok));

    // Should have reverted to previous path
    assert_eq!(conn.remote_addr, prev_addr);
    assert_eq!(conn.remote_port, prev_port);
    assert_eq!(conn.remote_mac, prev_mac);
    assert!(conn.path.validated);
    assert!(conn.prev_path.is_none());
}

#[test]
fn path_validation_timeout_closes_when_no_prev_path() {
    let mut conn = make_conn();
    let now = Instant::now();

    // Unvalidated path with no previous path to revert to
    conn.path = PathState::new();
    conn.path.validated = false;
    conn.prev_path = None;

    let result = handle_timeout(&mut conn, QuicTimerKind::PathValidation, now);
    assert!(matches!(result, TimerResult::Ok));

    // Should be closing with INTERNAL_ERROR
    assert_eq!(conn.state, ConnectionState::Closing);
    assert_eq!(conn.close_error, Some(TransportError::INTERNAL_ERROR));
    assert!(conn.needs_draining_timer);
}

#[test]
fn path_validation_timeout_noop_when_validated() {
    let mut conn = make_conn();
    let now = Instant::now();

    // Path is already validated — timeout should be a no-op
    conn.path.validated = true;
    let orig_addr = conn.remote_addr;

    let result = handle_timeout(&mut conn, QuicTimerKind::PathValidation, now);
    assert!(matches!(result, TimerResult::Ok));

    // Nothing should have changed
    assert_eq!(conn.state, ConnectionState::Handshaking);
    assert_eq!(conn.remote_addr, orig_addr);
}
