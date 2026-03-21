use crate::net::handler::quic::transport::ecn::EcnState;

#[test]
fn ecn_initial_state() {
    let ecn = EcnState::new();
    assert!(!ecn.capable);
    assert!(!ecn.disabled);
    assert!(!ecn.validation_pending);
    assert_eq!(ecn.ect0_sent, 0);
    assert_eq!(ecn.ce_counter, 0);
}

#[test]
fn ecn_validation_success() {
    let mut ecn = EcnState::new();
    ecn.begin_validation();
    ecn.on_ect0_sent();
    ecn.on_ect0_sent();
    // Peer reflects ect0 count > 0 → validation succeeds
    let ce_signal = ecn.on_ack_ecn(2, 0, 0);
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
    let ce_signal = ecn.on_ack_ecn(0, 0, 0);
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
    ecn.on_ack_ecn(1, 0, 0);
    assert!(ecn.capable);
    // Second ACK: CE count increases → congestion signal
    let ce_signal = ecn.on_ack_ecn(1, 0, 1);
    assert!(ce_signal);
    assert_eq!(ecn.ce_counter, 1);
    // Third ACK: CE count same → no signal
    let ce_signal2 = ecn.on_ack_ecn(1, 0, 1);
    assert!(!ce_signal2);
}

#[test]
fn ecn_disabled_ignores_counts() {
    let mut ecn = EcnState::new();
    ecn.begin_validation();
    ecn.on_ect0_sent();
    // Force disabled via failed validation
    ecn.on_ack_ecn(0, 0, 0);
    assert!(ecn.disabled);
    // Even with CE increase, disabled state returns false
    let ce_signal = ecn.on_ack_ecn(5, 0, 10);
    assert!(!ce_signal);
}

#[test]
fn ecn_reset_for_migration() {
    let mut ecn = EcnState::new();
    ecn.begin_validation();
    ecn.on_ect0_sent();
    ecn.on_ack_ecn(1, 0, 3);
    assert!(ecn.capable);
    assert_eq!(ecn.ce_counter, 3);
    // Reset clears all state
    ecn.reset();
    assert!(!ecn.capable);
    assert!(!ecn.disabled);
    assert!(!ecn.validation_pending);
    assert_eq!(ecn.ect0_sent, 0);
    assert_eq!(ecn.ce_counter, 0);
}
