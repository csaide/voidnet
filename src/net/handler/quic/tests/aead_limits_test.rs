use crate::net::handler::quic::crypto::aead_limits::AeadLimits;

#[test]
fn aes_gcm_confidentiality_limit() {
    let limits = AeadLimits::AES_GCM;
    assert!(!limits.needs_key_update(0));
    assert!(!limits.needs_key_update((1 << 23) - 2));
    assert!(limits.needs_key_update((1 << 23) - 1));
}

#[test]
fn aes_gcm_integrity_limit() {
    let limits = AeadLimits::AES_GCM;
    assert!(!limits.must_close(0));
    assert!(!limits.must_close((1 << 52) - 1));
    assert!(limits.must_close(1 << 52));
}

#[test]
fn chacha20_no_confidentiality_limit() {
    let limits = AeadLimits::CHACHA20;
    assert!(!limits.needs_key_update(1 << 62));
}

#[test]
fn chacha20_integrity_limit() {
    let limits = AeadLimits::CHACHA20;
    assert!(limits.must_close(1 << 36));
}
