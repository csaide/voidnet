use crate::net::handler::quic::transport::ecn::EcnState;

// Use Application Data space (2) for tests, as it's the most common.
const APP: usize = 2;

#[test]
fn ecn_initial_state() {
    let ecn = EcnState::new();
    assert!(!ecn.capable);
    assert!(!ecn.disabled);
    assert!(!ecn.validation_pending);
    assert_eq!(ecn.ect0_sent, 0);
}

#[test]
fn ecn_validation_success() {
    let mut ecn = EcnState::new();
    ecn.begin_validation();
    ecn.on_ect0_sent();
    ecn.on_ect0_sent();
    // Peer reflects ect0 count > 0 → validation succeeds
    let ce_signal = ecn.on_ack_ecn(APP, 2, 0, 0);
    assert!(ecn.capable);
    assert!(!ecn.validation_pending);
    assert!(!ecn.disabled);
    assert!(!ce_signal);
}

#[test]
fn ecn_validation_failure() {
    let mut ecn = EcnState::new();
    ecn.begin_validation();
    ecn.on_ect0_sent();
    // Peer reflects ect0=0 despite us sending ECT(0) → disabled
    let ce_signal = ecn.on_ack_ecn(APP, 0, 0, 0);
    assert!(!ecn.capable);
    assert!(ecn.disabled);
    assert!(!ecn.validation_pending);
    assert!(!ce_signal);
}

#[test]
fn ecn_ce_signals_congestion() {
    let mut ecn = EcnState::new();
    ecn.begin_validation();
    ecn.on_ect0_sent();
    // First ACK: validate ECN
    ecn.on_ack_ecn(APP, 1, 0, 0);
    assert!(ecn.capable);
    // Second ACK: CE count increases → congestion signal
    let ce_signal = ecn.on_ack_ecn(APP, 1, 0, 1);
    assert!(ce_signal);
    // Third ACK: CE count same → no signal
    let ce_signal2 = ecn.on_ack_ecn(APP, 1, 0, 1);
    assert!(!ce_signal2);
}

#[test]
fn ecn_disabled_ignores_counts() {
    let mut ecn = EcnState::new();
    ecn.begin_validation();
    ecn.on_ect0_sent();
    // Force disabled via failed validation
    ecn.on_ack_ecn(APP, 0, 0, 0);
    assert!(ecn.disabled);
    // Even with CE increase, disabled state returns false
    let ce_signal = ecn.on_ack_ecn(APP, 5, 0, 10);
    assert!(!ce_signal);
}

#[test]
fn ecn_reset_for_migration() {
    let mut ecn = EcnState::new();
    ecn.begin_validation();
    ecn.on_ect0_sent();
    ecn.on_ack_ecn(APP, 1, 0, 3);
    assert!(ecn.capable);
    // Reset clears all state
    ecn.reset();
    assert!(!ecn.capable);
    assert!(!ecn.disabled);
    assert!(!ecn.validation_pending);
    assert_eq!(ecn.ect0_sent, 0);
}

#[test]
fn ecn_per_space_ce_counters() {
    let mut ecn = EcnState::new();
    ecn.begin_validation();
    ecn.on_ect0_sent();
    // Validate via Initial space
    ecn.on_ack_ecn(0, 1, 0, 0);
    assert!(ecn.capable);
    // CE in Initial space
    let ce = ecn.on_ack_ecn(0, 1, 0, 2);
    assert!(ce);
    // No CE in Handshake space (counter starts at 0)
    let ce = ecn.on_ack_ecn(1, 1, 0, 0);
    assert!(!ce);
    // CE in Handshake space
    let ce = ecn.on_ack_ecn(1, 1, 0, 1);
    assert!(ce);
    // AppData space is independent — CE=0 is not a signal
    let ce = ecn.on_ack_ecn(2, 1, 0, 0);
    assert!(!ce);
}
