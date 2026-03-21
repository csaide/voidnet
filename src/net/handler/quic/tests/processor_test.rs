use std::sync::Arc;

use coarsetime::Instant;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, ServerConfig, SignatureScheme};

use crate::net::handler::quic::connection::{QuicConnectionState, Side};
use crate::net::handler::quic::connection_id::ConnectionId;
use crate::net::handler::quic::crypto::initial_keys::derive_initial_keys;
use crate::net::handler::quic::crypto::keys::{DirectionalKey, KeyPair};
use crate::net::handler::quic::crypto::packet_protection::protect_packet;
use crate::net::handler::quic::crypto::tls::CryptoState;
use crate::net::handler::quic::processor::process_packet;
use crate::net::handler::quic::transport::params::TransportParams;
use crate::net::handler::quic::transport::varint::encode_varint;
use crate::net::handler::quic::transport::version::QUIC_VERSION_1;

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

fn make_test_cert() -> (
    Vec<CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    (
        vec![cert_der],
        rustls::pki_types::PrivateKeyDer::Pkcs8(key_der),
    )
}

fn make_client_config() -> Arc<ClientConfig> {
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h3".to_vec()];
    Arc::new(config)
}

fn make_server_config() -> Arc<ServerConfig> {
    let (certs, key) = make_test_cert();
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    config.alpn_protocols = vec![b"h3".to_vec()];
    config.max_early_data_size = 0;
    Arc::new(config)
}

fn encode_test_transport_params() -> Vec<u8> {
    let params = TransportParams {
        initial_max_data: 1_000_000,
        initial_max_stream_data_bidi_local: 100_000,
        initial_max_stream_data_bidi_remote: 100_000,
        initial_max_streams_bidi: 100,
        ..Default::default()
    };
    let mut buf = [0u8; 256];
    let len = params.encode(&mut buf);
    buf[..len].to_vec()
}

/// Build a QUIC Initial packet with the given CRYPTO data.
///
/// Layout:
/// - Long header: first_byte | version(4) | dcid_len | dcid | scid_len | scid
/// - Token length (varint) = 0
/// - Length (varint) = pn_len + crypto_frame_len + padding + tag_len
/// - PN = 0 (1 byte)
/// - CRYPTO frame containing data
/// - PADDING to reach ~1200 bytes
/// - (tag space appended for AEAD)
///
/// Returns the mutable buffer and the total length before encryption.
fn build_initial_packet(
    client_dcid: &[u8],
    client_scid: &[u8],
    crypto_data: &[u8],
    client_key: &DirectionalKey,
) -> Vec<u8> {
    let tag_len = client_key.packet_key.tag_len();

    // Build header
    // first_byte: 1100_0000 = 0xC0 (long header, Initial, pn_length=0 means 1 byte PN encoded as 00)
    let first_byte = 0xC0u8; // PN length bits will be set to 00 (1 byte)

    let mut header = Vec::with_capacity(64);
    header.push(first_byte);
    header.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
    header.push(client_dcid.len() as u8);
    header.extend_from_slice(client_dcid);
    header.push(client_scid.len() as u8);
    header.extend_from_slice(client_scid);

    // Token length = 0 (varint)
    let mut varint_buf = [0u8; 8];
    let n = encode_varint(0, &mut varint_buf);
    header.extend_from_slice(&varint_buf[..n]);

    // Build CRYPTO frame: type(0x06) | offset(varint) | length(varint) | data
    let mut crypto_frame = Vec::new();
    crypto_frame.push(0x06); // CRYPTO frame type
    let n = encode_varint(0, &mut varint_buf); // offset = 0
    crypto_frame.extend_from_slice(&varint_buf[..n]);
    let n = encode_varint(crypto_data.len() as u64, &mut varint_buf); // length
    crypto_frame.extend_from_slice(&varint_buf[..n]);
    crypto_frame.extend_from_slice(crypto_data);

    // We want the total packet to be at least 1200 bytes (QUIC minimum for Initial).
    // Total = header_len + Length_field_size + pn_len(1) + crypto_frame_len + padding + tag_len
    let pn_len = 1usize;
    let min_payload_before_tag = 1200 - header.len() - 2 - pn_len - tag_len;
    // 2 bytes for the Length varint (will be a 2-byte encoding)
    let padding_needed = if crypto_frame.len() < min_payload_before_tag {
        min_payload_before_tag - crypto_frame.len()
    } else {
        0
    };

    // The Length field covers: pn_len + crypto_frame + padding + tag_len
    let length_value = pn_len + crypto_frame.len() + padding_needed + tag_len;

    // Encode Length as 2-byte varint (values up to 16383)
    let n = encode_varint(length_value as u64, &mut varint_buf);
    header.extend_from_slice(&varint_buf[..n]);

    let pn_offset = header.len();

    // Build full packet: header | PN | crypto_frame | padding | tag_space
    let total_len = header.len() + pn_len + crypto_frame.len() + padding_needed + tag_len;
    let mut packet = vec![0u8; total_len];
    packet[..header.len()].copy_from_slice(&header);
    // PN = 0 (1 byte)
    packet[pn_offset] = 0x00;
    let payload_start = pn_offset + pn_len;
    packet[payload_start..payload_start + crypto_frame.len()].copy_from_slice(&crypto_frame);
    // padding is already zero
    // tag space is already zero

    // Encrypt with client Initial keys
    protect_packet(client_key, &mut packet, pn_offset, pn_len, 0).unwrap();

    packet
}

#[test]
fn process_initial_packet_extracts_crypto() {
    let now = Instant::now();

    // Use a fixed DCID that both sides agree on
    let dcid_bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let scid_bytes = [0xAA, 0xBB, 0xCC, 0xDD];

    // 1. Create client-side TLS to generate ClientHello CRYPTO data
    let client_config = make_client_config();
    let client_params = encode_test_transport_params();
    let (_client_crypto, client_hello) =
        CryptoState::new_client(client_config, "localhost", &client_params).unwrap();
    assert!(!client_hello.is_empty(), "ClientHello should not be empty");

    // 2. Derive Initial keys from the client's DCID
    // Client encrypts with client keys, server decrypts with server keys.
    // derive_initial_keys(dcid, Side::Client) => (local=client_encrypt, remote=client_decrypt)
    let (client_local, _client_remote) = derive_initial_keys(&dcid_bytes, rustls::Side::Client);
    let client_encrypt_key = DirectionalKey::from_rustls(client_local);

    // Server needs keys from client perspective: derive_initial_keys for Server side
    // gives (local=server_encrypt, remote=server_decrypt_of_client)
    let (server_local, server_remote) = derive_initial_keys(&dcid_bytes, rustls::Side::Server);
    let server_initial_keys = KeyPair {
        local: DirectionalKey::from_rustls(server_local),
        remote: DirectionalKey::from_rustls(server_remote),
    };

    // 3. Build an encrypted Initial packet containing the ClientHello
    let packet = build_initial_packet(&dcid_bytes, &scid_bytes, &client_hello, &client_encrypt_key);
    assert!(
        packet.len() >= 1200,
        "Initial packet should be at least 1200 bytes, got {}",
        packet.len()
    );

    // 4. Create server connection state
    let server_config = make_server_config();
    let server_params_bytes = encode_test_transport_params();
    let server_crypto = CryptoState::new_server(server_config, &server_params_bytes).unwrap();

    let server_params = TransportParams {
        initial_max_data: 1_000_000,
        initial_max_stream_data_bidi_local: 100_000,
        initial_max_stream_data_bidi_remote: 100_000,
        initial_max_streams_bidi: 100,
        ..Default::default()
    };

    let dcid = ConnectionId::from_slice(&dcid_bytes);
    let mut conn = QuicConnectionState::new(dcid, Side::Server, server_params, 1200, now);
    conn.crypto = Some(server_crypto);
    conn.keys.initial = Some(server_initial_keys);

    // 5. Process the packet
    let datagram_len = packet.len();
    let mut packet_buf = packet;
    let _result = process_packet(&mut conn, &mut packet_buf, datagram_len, now);

    // 6. Verify results
    // The server should have processed the CRYPTO frame and produced response data
    let has_pending_crypto = conn.pending_crypto.iter().any(|v| !v.is_empty());
    assert!(
        has_pending_crypto,
        "Server should have pending CRYPTO data (ServerHello response)"
    );

    // After processing ClientHello, TLS 1.3 server derives both handshake and 1-RTT keys
    // in one shot. The processor discards handshake keys once 1-RTT keys are installed (per
    // RFC 9001), so we check 1-RTT keys.
    assert!(
        conn.keys.one_rtt.is_some(),
        "Server should have installed 1-RTT keys after processing ClientHello"
    );
    // Handshake keys are discarded after 1-RTT key installation (server side)
    assert!(
        conn.keys.handshake.is_none(),
        "Server should have discarded handshake keys after 1-RTT key installation"
    );

    // ACK state should reflect receiving PN 0
    assert_eq!(
        conn.ack[0].largest_received(),
        Some(0),
        "ACK state should show PN 0 as largest received"
    );

    // PN 0 should be marked as seen
    assert!(
        conn.recv_pn_seen[0].is_duplicate(0),
        "PN 0 should be marked as seen"
    );
}
