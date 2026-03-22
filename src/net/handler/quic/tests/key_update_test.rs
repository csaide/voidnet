use crate::net::handler::quic::crypto::key_update::KeyUpdateState;

#[test]
fn cannot_initiate_before_ack() {
    let state = KeyUpdateState::new();
    assert!(!state.can_initiate_update());
}

#[test]
fn cannot_initiate_before_handshake_confirmed() {
    let mut state = KeyUpdateState::new();
    state.acked_current_phase = true;
    // handshake_confirmed is false — must not allow key update (RFC 9001 §6)
    assert!(!state.can_initiate_update());
}

#[test]
fn can_initiate_after_ack() {
    let mut state = KeyUpdateState::new();
    state.handshake_confirmed = true;
    state.acked_current_phase = true;
    assert!(state.can_initiate_update());
}

#[test]
fn update_flips_key_phase() {
    let mut state = KeyUpdateState::new();
    state.acked_current_phase = true;
    assert!(!state.key_phase);
    state.on_update_initiated();
    assert!(state.key_phase);
}

#[test]
fn update_resets_ack_tracking() {
    let mut state = KeyUpdateState::new();
    state.handshake_confirmed = true;
    state.acked_current_phase = true;
    state.on_update_initiated();
    assert!(!state.acked_current_phase);
    assert!(!state.can_initiate_update());
}

#[test]
fn tracks_lowest_pn() {
    let mut state = KeyUpdateState::new();
    state.on_packet_sent(10);
    state.on_packet_sent(11);
    assert_eq!(state.lowest_pn_current_phase, Some(10));
}

#[test]
fn detects_peer_update() {
    let state = KeyUpdateState::new();
    assert!(!state.is_peer_update(false)); // same phase
    assert!(state.is_peer_update(true)); // different phase
}
