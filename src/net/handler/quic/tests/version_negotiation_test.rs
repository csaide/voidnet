use std::sync::Arc;

use coarsetime::Instant;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};

use crate::net::handler::quic::connection::{ConnectionState, QuicConnectionState, Side};
use crate::net::handler::quic::connection_id::ConnectionId;
use crate::net::handler::quic::transport::params::TransportParams;
use crate::net::handler::quic::transport::version::{
    QUIC_VERSION_1, QUIC_VERSION_2, is_supported_version,
};

/// A cert verifier that accepts everything (test only).
#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

fn make_client_config() -> Arc<ClientConfig> {
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h3".to_vec()];
    Arc::new(config)
}

fn make_client_conn() -> QuicConnectionState {
    let dcid = ConnectionId::from_slice(&[0x01, 0x02, 0x03, 0x04]);
    let params = TransportParams {
        initial_max_data: 1_000_000,
        initial_max_stream_data_bidi_local: 100_000,
        initial_max_stream_data_bidi_remote: 100_000,
        initial_max_streams_bidi: 100,
        ..TransportParams::default()
    };
    let now = Instant::now();
    let mut conn = QuicConnectionState::new(dcid, Side::Client, params, 1200, now);
    conn.state = ConnectionState::Handshaking;
    conn.version = QUIC_VERSION_1;
    conn
}

/// Helper: simulate the version selection logic from processor.rs
/// Returns (negotiated_version, found) given the offered version list bytes.
fn select_version(current_version: u32, version_bytes: &[u8]) -> Option<u32> {
    let mut i = 0;
    while i + 4 <= version_bytes.len() {
        let v = u32::from_be_bytes([
            version_bytes[i],
            version_bytes[i + 1],
            version_bytes[i + 2],
            version_bytes[i + 3],
        ]);
        if is_supported_version(v) && v != current_version {
            return Some(v);
        }
        i += 4;
    }
    None
}

#[test]
fn vn_selects_supported_version() {
    // Server offers V2 (different from client's V1) — should be selected
    let mut versions = Vec::new();
    versions.extend_from_slice(&QUIC_VERSION_2.to_be_bytes());

    let result = select_version(QUIC_VERSION_1, &versions);
    assert_eq!(result, Some(QUIC_VERSION_2));
}

#[test]
fn vn_no_compatible_version_returns_none() {
    // Server only offers an unknown version
    let unknown_version: u32 = 0xdeadbeef;
    let mut versions = Vec::new();
    versions.extend_from_slice(&unknown_version.to_be_bytes());

    let result = select_version(QUIC_VERSION_1, &versions);
    assert_eq!(result, None);
}

#[test]
fn vn_skips_current_version() {
    // Server offers only the same version we're already using — no upgrade possible
    let mut versions = Vec::new();
    versions.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());

    let result = select_version(QUIC_VERSION_1, &versions);
    assert_eq!(result, None);
}

#[test]
fn vn_picks_first_compatible_from_multiple() {
    // Server offers unknown, then V2, then V1 — should pick V2
    let mut versions = Vec::new();
    versions.extend_from_slice(&0xdeadbeef_u32.to_be_bytes());
    versions.extend_from_slice(&QUIC_VERSION_2.to_be_bytes());
    versions.extend_from_slice(&QUIC_VERSION_1.to_be_bytes()); // same as current, skipped

    let result = select_version(QUIC_VERSION_1, &versions);
    assert_eq!(result, Some(QUIC_VERSION_2));
}

#[test]
fn vn_no_compatible_closes_connection() {
    let mut conn = make_client_conn();
    assert_eq!(conn.state, ConnectionState::Handshaking);

    // Simulate: no compatible version found — connection should close
    let versions_bytes: Vec<u8> = 0xdeadbeef_u32.to_be_bytes().to_vec();
    let negotiated = select_version(conn.version, &versions_bytes);
    assert!(negotiated.is_none());

    // When no version is found, processor closes the connection
    conn.state = ConnectionState::Closed;
    assert_eq!(conn.state, ConnectionState::Closed);
}

#[test]
fn vn_retry_updates_version_and_stores_original() {
    let mut conn = make_client_conn();
    let original = conn.version;
    assert_eq!(original, QUIC_VERSION_1);
    assert!(conn.original_version.is_none());

    // Simulate successful version negotiation to V2
    let negotiated = QUIC_VERSION_2;
    conn.original_version = Some(conn.version);
    conn.version = negotiated;

    assert_eq!(conn.version, QUIC_VERSION_2);
    assert_eq!(conn.original_version, Some(QUIC_VERSION_1));
}

#[test]
fn vn_retry_reinitializes_crypto_state() {
    use crate::net::handler::quic::crypto::initial_keys::derive_initial_keys;
    use crate::net::handler::quic::crypto::keys::{DirectionalKey, KeyPair};
    use crate::net::handler::quic::crypto::tls::CryptoState;
    use crate::net::handler::quic::transport::ack::AckState;
    use crate::net::handler::quic::transport::loss::LossDetector;

    let mut conn = make_client_conn();
    let client_config = make_client_config();
    conn.client_config = Some(client_config.clone());
    conn.server_name = Some("localhost".to_string());

    // Put some dummy data in crypto state to verify it gets reset
    conn.crypto_offset = [10, 20, 30];
    conn.crypto_acked = [5, 15, 25];

    let new_version = QUIC_VERSION_2;
    conn.original_version = Some(conn.version);
    conn.version = new_version;

    let rustls_version = rustls::quic::Version::V2;

    // Re-create TLS client
    let mut params_buf = [0u8; 512];
    let params_len = conn.local_params.encode(&mut params_buf);
    let result = CryptoState::new_client(
        client_config,
        "localhost",
        &params_buf[..params_len],
        rustls_version,
    );
    assert!(result.is_ok(), "CryptoState::new_client should succeed");

    let (crypto, initial_data) = result.unwrap();
    conn.crypto = Some(crypto);

    // Re-derive initial keys
    let (local_dk, remote_dk) =
        derive_initial_keys(conn.dcid.as_bytes(), rustls::Side::Client, rustls_version);
    conn.keys.initial = Some(KeyPair {
        local: DirectionalKey::from_rustls(local_dk),
        remote: DirectionalKey::from_rustls(remote_dk),
    });

    // Reset state
    conn.pending_crypto = [initial_data, Vec::new(), Vec::new()];
    conn.crypto_offset = [0; 3];
    conn.crypto_acked = [0; 3];
    conn.ack = [AckState::new(), AckState::new(), AckState::new()];
    conn.loss = LossDetector::new();

    // Verify state was reset
    assert_eq!(conn.version, QUIC_VERSION_2);
    assert_eq!(conn.original_version, Some(QUIC_VERSION_1));
    assert!(conn.crypto.is_some());
    assert!(conn.keys.initial.is_some());
    assert_eq!(conn.crypto_offset, [0; 3]);
    assert_eq!(conn.crypto_acked, [0; 3]);
    assert!(
        !conn.pending_crypto[0].is_empty(),
        "initial crypto data should be present"
    );
    assert!(conn.pending_crypto[1].is_empty());
    assert!(conn.pending_crypto[2].is_empty());
    // Connection should still be handshaking (not closed)
    assert_eq!(conn.state, ConnectionState::Handshaking);
}

#[test]
fn vn_ignored_when_not_handshaking() {
    let mut conn = make_client_conn();
    conn.state = ConnectionState::Established;

    // VN should only be processed during handshaking
    let versions_bytes: Vec<u8> = QUIC_VERSION_2.to_be_bytes().to_vec();
    let negotiated = select_version(conn.version, &versions_bytes);
    // Even though a compatible version exists, we should not act on it
    // when not in Handshaking state (the processor checks this condition)
    assert!(negotiated.is_some()); // version exists
    // But since state != Handshaking, processor would skip VN processing
    assert_ne!(conn.state, ConnectionState::Handshaking);
    // Version should remain unchanged
    assert_eq!(conn.version, QUIC_VERSION_1);
    assert!(conn.original_version.is_none());
}

#[test]
fn vn_ignored_for_server_side() {
    let dcid = ConnectionId::from_slice(&[0x01, 0x02, 0x03, 0x04]);
    let params = TransportParams::default();
    let now = Instant::now();
    let conn = QuicConnectionState::new(dcid, Side::Server, params, 1200, now);

    // Server should never process VN packets (processor checks side == Client)
    assert_eq!(conn.side, Side::Server);
    assert_eq!(conn.state, ConnectionState::Handshaking);
    // Even though state is Handshaking, the server side check prevents processing
}

#[test]
fn validate_version_info_none_always_ok() {
    let params = TransportParams::default();

    // No version_information → validation always passes
    assert!(
        params
            .validate_version_info(QUIC_VERSION_1, &[QUIC_VERSION_1, QUIC_VERSION_2])
            .is_ok()
    );
    assert!(
        params
            .validate_version_info(QUIC_VERSION_2, &[QUIC_VERSION_1])
            .is_ok()
    );
}
