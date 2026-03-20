use crate::net::handler::quic::error::TransportError;

#[test]
fn transport_error_codes_match_rfc() {
    assert_eq!(TransportError::NO_ERROR.code(), 0x00);
    assert_eq!(TransportError::INTERNAL_ERROR.code(), 0x01);
    assert_eq!(TransportError::CONNECTION_REFUSED.code(), 0x02);
    assert_eq!(TransportError::FLOW_CONTROL_ERROR.code(), 0x03);
    assert_eq!(TransportError::STREAM_LIMIT_ERROR.code(), 0x04);
    assert_eq!(TransportError::STREAM_STATE_ERROR.code(), 0x05);
    assert_eq!(TransportError::FINAL_SIZE_ERROR.code(), 0x06);
    assert_eq!(TransportError::FRAME_ENCODING_ERROR.code(), 0x07);
    assert_eq!(TransportError::TRANSPORT_PARAMETER_ERROR.code(), 0x08);
    assert_eq!(TransportError::CONNECTION_ID_LIMIT_ERROR.code(), 0x09);
    assert_eq!(TransportError::PROTOCOL_VIOLATION.code(), 0x0a);
    assert_eq!(TransportError::INVALID_TOKEN.code(), 0x0b);
    assert_eq!(TransportError::APPLICATION_ERROR.code(), 0x0c);
    assert_eq!(TransportError::CRYPTO_BUFFER_EXCEEDED.code(), 0x0d);
    assert_eq!(TransportError::KEY_UPDATE_ERROR.code(), 0x0e);
    assert_eq!(TransportError::AEAD_LIMIT_REACHED.code(), 0x0f);
    assert_eq!(TransportError::NO_VIABLE_PATH.code(), 0x10);
}

#[test]
fn tls_alert_mapping() {
    let err = TransportError::from_tls_alert(42);
    assert_eq!(err.code(), 0x012a);
}

#[test]
fn is_crypto_error() {
    // Standard errors are not crypto errors
    assert!(!TransportError::NO_ERROR.is_crypto_error());
    assert!(!TransportError::INTERNAL_ERROR.is_crypto_error());
    assert!(!TransportError::NO_VIABLE_PATH.is_crypto_error());

    // TLS alert range (0x0100-0x01ff) are crypto errors
    assert!(TransportError::from_tls_alert(0).is_crypto_error());
    assert!(TransportError::from_tls_alert(42).is_crypto_error());
    assert!(TransportError::from_tls_alert(255).is_crypto_error());

    // Boundary: 0x0100 and 0x01ff are included
    assert!(TransportError(0x0100).is_crypto_error());
    assert!(TransportError(0x01ff).is_crypto_error());

    // Outside range
    assert!(!TransportError(0x00ff).is_crypto_error());
    assert!(!TransportError(0x0200).is_crypto_error());
}

#[test]
fn display_formatting() {
    // Named errors should produce readable output
    let s = format!("{}", TransportError::NO_ERROR);
    assert!(!s.is_empty());
    assert!(s.contains("NO_ERROR") || s.to_lowercase().contains("no error") || s.contains("0x0"));

    let s = format!("{}", TransportError::INTERNAL_ERROR);
    assert!(!s.is_empty());

    // Crypto error should show TLS alert info
    let s = format!("{}", TransportError::from_tls_alert(42));
    assert!(!s.is_empty());
    // Should mention it's a crypto/TLS error or show the code
    assert!(
        s.contains("TLS")
            || s.contains("tls")
            || s.contains("CRYPTO")
            || s.contains("crypto")
            || s.contains("0x12a")
            || s.contains("0x012a")
    );
}
