use crate::net::handler::quic::connection_id::ConnectionId;
use crate::net::handler::quic::crypto::retry::{
    compute_retry_integrity_tag, verify_retry_integrity_tag,
};
use crate::net::handler::quic::token::RetryToken;
use crate::net::handler::quic::transport::packet_builder::build_retry_packet;
use crate::net::handler::quic::transport::version::QUIC_VERSION_1;
use crate::net::wire::quic::{self as wire_quic, PacketHeader, PacketType};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use coarsetime::{Duration, Instant};

fn make_server_config() -> std::sync::Arc<rustls::ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert);
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert_der],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key_der),
        )
        .unwrap();
    config.alpn_protocols = vec![b"h3".to_vec()];
    config.max_early_data_size = 0;
    std::sync::Arc::new(config)
}

#[test]
fn retry_tag_deterministic() {
    let odcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let packet = [0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08]; // fake retry header
    let tag1 = compute_retry_integrity_tag(&odcid, &packet, 0x00000001);
    let tag2 = compute_retry_integrity_tag(&odcid, &packet, 0x00000001);
    assert_eq!(tag1, tag2);
}

#[test]
fn retry_tag_verify_roundtrip() {
    let odcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let packet = [0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08];
    let tag = compute_retry_integrity_tag(&odcid, &packet, 0x00000001);

    let mut packet_with_tag = packet.to_vec();
    packet_with_tag.extend_from_slice(&tag);

    assert!(verify_retry_integrity_tag(
        &odcid,
        &packet_with_tag,
        0x00000001
    ));
}

#[test]
fn retry_tag_tampered_fails() {
    let odcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let packet = [0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08];
    let tag = compute_retry_integrity_tag(&odcid, &packet, 0x00000001);

    let mut packet_with_tag = packet.to_vec();
    packet_with_tag.extend_from_slice(&tag);
    packet_with_tag[0] ^= 0x01; // tamper

    assert!(!verify_retry_integrity_tag(
        &odcid,
        &packet_with_tag,
        0x00000001
    ));
}

#[test]
fn retry_tag_wrong_odcid_fails() {
    let odcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let packet = [0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08];
    let tag = compute_retry_integrity_tag(&odcid, &packet, 0x00000001);

    let mut packet_with_tag = packet.to_vec();
    packet_with_tag.extend_from_slice(&tag);

    let wrong_odcid = [0x00; 8];
    assert!(!verify_retry_integrity_tag(
        &wrong_odcid,
        &packet_with_tag,
        0x00000001
    ));
}

#[test]
fn retry_token_expiry() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 4433);
    let cid = ConnectionId::from_slice(&[1, 2, 3, 4]);
    let now = Instant::now();
    let token = RetryToken::new(cid, addr, now);
    assert!(!token.is_expired(now, Duration::from_secs(30)));
    // Can't easily test expiry without sleeping, so just verify the logic
    let future = now + Duration::from_secs(31);
    assert!(token.is_expired(future, Duration::from_secs(30)));
}

#[test]
fn token_encrypt_unique_nonces() {
    let secret = [0xABu8; 32];
    let ip = &[127u8, 0, 0, 1];
    let ts = 1000u64;
    let dcid = &[1u8, 2, 3, 4];
    let version = 0x00000001u32;

    let t1 = crate::net::handler::quic::token_crypto::encrypt_token(
        &secret,
        crate::net::handler::quic::token_crypto::TokenType::Retry,
        ip,
        ts,
        dcid,
        version,
    )
    .unwrap();
    let t2 = crate::net::handler::quic::token_crypto::encrypt_token(
        &secret,
        crate::net::handler::quic::token_crypto::TokenType::Retry,
        ip,
        ts,
        dcid,
        version,
    )
    .unwrap();

    // Random portion of nonce (bytes 4..12) must differ across calls
    assert_ne!(
        &t1[4..12],
        &t2[4..12],
        "random nonce bytes must differ across calls"
    );
    assert_ne!(t1, t2);
}

#[test]
fn build_retry_packet_roundtrip_v1() {
    let version = QUIC_VERSION_1;
    let dcid = &[0x01, 0x02, 0x03, 0x04];
    let scid = &[0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11];
    let odcid = &[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let token = &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];

    let packet = build_retry_packet(version, dcid, scid, odcid, token);

    let (header, _consumed) = wire_quic::parse_header(&packet, 0).unwrap();
    match header {
        PacketHeader::Long(long) => {
            assert_eq!(long.packet_type, PacketType::Retry);
            assert_eq!(long.version, version);
            assert_eq!(long.dcid.as_bytes(), dcid);
            assert_eq!(long.scid.as_bytes(), scid);
        }
        _ => panic!("expected long header"),
    }

    assert!(verify_retry_integrity_tag(odcid, &packet, version));
}

#[test]
fn build_retry_packet_roundtrip_v2() {
    use crate::net::handler::quic::transport::version::QUIC_VERSION_2;

    let version = QUIC_VERSION_2;
    let dcid = &[0x01, 0x02, 0x03, 0x04];
    let scid = &[0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11];
    let odcid = &[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let token = &[0xDE, 0xAD, 0xBE, 0xEF];

    let packet = build_retry_packet(version, dcid, scid, odcid, token);

    let (header, _) = wire_quic::parse_header(&packet, 0).unwrap();
    match header {
        PacketHeader::Long(long) => {
            assert_eq!(long.packet_type, PacketType::Retry);
            assert_eq!(long.version, version);
        }
        _ => panic!("expected long header"),
    }
    assert!(verify_retry_integrity_tag(odcid, &packet, version));
}

#[test]
fn build_retry_packet_tampered_tag_fails() {
    let version = QUIC_VERSION_1;
    let dcid = &[0x01, 0x02];
    let scid = &[0x0A, 0x0B, 0x0C, 0x0D];
    let odcid = &[0x83, 0x94, 0xc8, 0xf0];
    let token = &[0xCA, 0xFE];

    let mut packet = build_retry_packet(version, dcid, scid, odcid, token);
    let len = packet.len();
    packet[len - 1] ^= 0xFF;

    assert!(!verify_retry_integrity_tag(odcid, &packet, version));
}

#[test]
fn extract_initial_token_empty() {
    use crate::net::handler::quic::handler::QuicHandler;

    // Build a minimal Initial packet header with token_length = 0
    // Format: first_byte(1) + version(4) + dcid_len(1) + dcid(4) + scid_len(1) + scid(4) + token_len(1=varint 0)
    let mut pkt = Vec::new();
    pkt.push(0xC0); // long header, Initial type
    pkt.extend_from_slice(&0x00000001u32.to_be_bytes()); // version
    pkt.push(4); // DCID length
    pkt.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // DCID
    pkt.push(4); // SCID length
    pkt.extend_from_slice(&[0x0A, 0x0B, 0x0C, 0x0D]); // SCID
    pkt.push(0x00); // token length = 0

    let token = QuicHandler::extract_initial_token(&pkt);
    assert_eq!(token, Some(Vec::new()));
}

#[test]
fn extract_initial_token_with_data() {
    use crate::net::handler::quic::handler::QuicHandler;

    let mut pkt = Vec::new();
    pkt.push(0xC0);
    pkt.extend_from_slice(&0x00000001u32.to_be_bytes());
    pkt.push(4); // DCID length
    pkt.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
    pkt.push(4); // SCID length
    pkt.extend_from_slice(&[0x0A, 0x0B, 0x0C, 0x0D]);
    // Token length = 6 (varint: single byte since < 64)
    pkt.push(0x06);
    pkt.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]);

    let token = QuicHandler::extract_initial_token(&pkt);
    assert_eq!(token, Some(vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]));
}

#[test]
fn extract_initial_token_truncated() {
    use crate::net::handler::quic::handler::QuicHandler;

    // Token length says 10 but only 3 bytes follow
    let mut pkt = Vec::new();
    pkt.push(0xC0);
    pkt.extend_from_slice(&0x00000001u32.to_be_bytes());
    pkt.push(4);
    pkt.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
    pkt.push(4);
    pkt.extend_from_slice(&[0x0A, 0x0B, 0x0C, 0x0D]);
    pkt.push(0x0A); // token length = 10
    pkt.extend_from_slice(&[0x01, 0x02, 0x03]); // only 3 bytes

    let token = QuicHandler::extract_initial_token(&pkt);
    assert_eq!(token, None);
}

#[test]
fn validate_retry_token_roundtrip() {
    use crate::net::handler::quic::handler::QuicHandler;
    use crate::net::handler::quic::token_crypto::{TokenType, encrypt_token};
    use crate::net::wire::ip::{IpAddress, Ipv4Address};

    let mut handler = QuicHandler::new(false, false);
    // Register a listener to get a token_secret
    let tls_config = make_server_config();
    let params = crate::net::handler::quic::transport::params::TransportParams::default();
    handler.listen(4433, tls_config, params);

    let client_ip_bytes = [127u8, 0, 0, 1];
    let client_addr = IpAddress::V4(Ipv4Address {
        octets: client_ip_bytes,
    });
    let odcid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let version = 0x00000001u32;

    // Encrypt a token using the listener's secret
    let secret = handler.listeners.get(&4433).unwrap().token_secret;
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token = encrypt_token(
        &secret,
        TokenType::Retry,
        &client_ip_bytes,
        now_secs,
        &odcid,
        version,
    )
    .unwrap();

    // Validate should succeed and return the original DCID
    let result = handler.validate_retry_token(&token, &client_addr, 4433, version);
    assert!(result.is_some());
    assert_eq!(result.unwrap().as_bytes(), &odcid);
}

#[test]
fn validate_retry_token_wrong_ip() {
    use crate::net::handler::quic::handler::QuicHandler;
    use crate::net::handler::quic::token_crypto::{TokenType, encrypt_token};
    use crate::net::wire::ip::{IpAddress, Ipv4Address};

    let mut handler = QuicHandler::new(false, false);
    let tls_config = make_server_config();
    let params = crate::net::handler::quic::transport::params::TransportParams::default();
    handler.listen(4433, tls_config, params);

    let secret = handler.listeners.get(&4433).unwrap().token_secret;
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let odcid = [0x01, 0x02, 0x03, 0x04];
    let version = 0x00000001u32;

    // Encrypt with IP 127.0.0.1
    let token = encrypt_token(
        &secret,
        TokenType::Retry,
        &[127, 0, 0, 1],
        now_secs,
        &odcid,
        version,
    )
    .unwrap();

    // Validate with different IP — should fail
    let wrong_addr = IpAddress::V4(Ipv4Address {
        octets: [10, 0, 0, 1],
    });
    let result = handler.validate_retry_token(&token, &wrong_addr, 4433, version);
    assert!(result.is_none());
}

#[test]
fn validate_retry_token_wrong_version() {
    use crate::net::handler::quic::handler::QuicHandler;
    use crate::net::handler::quic::token_crypto::{TokenType, encrypt_token};
    use crate::net::wire::ip::{IpAddress, Ipv4Address};

    let mut handler = QuicHandler::new(false, false);
    let tls_config = make_server_config();
    let params = crate::net::handler::quic::transport::params::TransportParams::default();
    handler.listen(4433, tls_config, params);

    let secret = handler.listeners.get(&4433).unwrap().token_secret;
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let odcid = [0x01, 0x02, 0x03, 0x04];
    let client_ip = [127u8, 0, 0, 1];

    // Encrypt with version 1
    let token = encrypt_token(
        &secret,
        TokenType::Retry,
        &client_ip,
        now_secs,
        &odcid,
        0x00000001,
    )
    .unwrap();

    // Validate with version 2 — should fail
    let addr = IpAddress::V4(Ipv4Address { octets: client_ip });
    let result = handler.validate_retry_token(&token, &addr, 4433, 0x6b3343cf);
    assert!(result.is_none());
}

#[test]
fn generate_retry_packet_produces_valid_retry() {
    use crate::net::handler::quic::handler::QuicHandler;
    use crate::net::wire::quic::{self as wire_quic, PacketHeader, PacketType};

    let mut handler = QuicHandler::new(false, false);
    let tls_config = make_server_config();
    let params = crate::net::handler::quic::transport::params::TransportParams::default();
    handler.listen(4433, tls_config, params);

    let odcid = &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let client_scid = &[0x0A, 0x0B, 0x0C, 0x0D];
    let client_ip = &[127u8, 0, 0, 1];
    let version = 0x00000001u32;

    let retry_pkt = handler
        .generate_retry_packet(odcid, client_scid, client_ip, 4433, version)
        .expect("should generate retry packet");

    // Parse the Retry packet and verify structure
    let (header, _) = wire_quic::parse_header(&retry_pkt, 0).unwrap();
    match header {
        PacketHeader::Long(long) => {
            assert_eq!(long.packet_type, PacketType::Retry);
            assert_eq!(long.version, version);
            // DCID in the Retry should be the client's SCID
            assert_eq!(long.dcid.as_bytes(), client_scid);
        }
        _ => panic!("expected long header"),
    }

    // Verify integrity tag
    assert!(
        crate::net::handler::quic::crypto::retry::verify_retry_integrity_tag(
            odcid, &retry_pkt, version,
        )
    );
}

#[test]
fn client_handles_retry_packet() {
    use crate::net::handler::quic::connection::{QuicConnectionState, Side};
    use crate::net::handler::quic::transport::packet_builder::build_retry_packet;
    use crate::net::handler::quic::transport::params::TransportParams;
    use crate::net::handler::quic::transport::version::QUIC_VERSION_1;
    use coarsetime::Instant;

    let now = Instant::now();
    let dcid = ConnectionId::from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    let scid = ConnectionId::from_slice(&[0x0A, 0x0B, 0x0C, 0x0D]);
    let mut conn =
        QuicConnectionState::new(dcid, Side::Client, TransportParams::default(), 1200, now);
    conn.scid = scid;
    conn.version = QUIC_VERSION_1;

    // Build a Retry packet
    let server_scid = &[0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7];
    let token = &[0xDE, 0xAD, 0xBE, 0xEF];
    let retry_packet = build_retry_packet(
        QUIC_VERSION_1,
        scid.as_bytes(),
        server_scid,
        dcid.as_bytes(),
        token,
    );

    let handled = crate::net::handler::quic::processor::handle_retry_packet(
        &mut conn,
        &retry_packet,
        QUIC_VERSION_1,
    );
    assert!(handled);
    assert!(conn.retry_received);
    assert_eq!(conn.dcid, ConnectionId::from_slice(server_scid));
    assert_eq!(conn.retry_token.as_deref(), Some(token.as_slice()));
    assert_eq!(conn.original_dcid, Some(dcid));
}

#[test]
fn client_rejects_second_retry() {
    use crate::net::handler::quic::connection::{QuicConnectionState, Side};
    use crate::net::handler::quic::transport::packet_builder::build_retry_packet;
    use crate::net::handler::quic::transport::params::TransportParams;
    use crate::net::handler::quic::transport::version::QUIC_VERSION_1;
    use coarsetime::Instant;

    let now = Instant::now();
    let dcid = ConnectionId::from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    let mut conn =
        QuicConnectionState::new(dcid, Side::Client, TransportParams::default(), 1200, now);
    conn.retry_received = true;

    let retry_packet = build_retry_packet(
        QUIC_VERSION_1,
        &[0x0A],
        &[0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7],
        dcid.as_bytes(),
        &[0xCA, 0xFE],
    );

    let handled = crate::net::handler::quic::processor::handle_retry_packet(
        &mut conn,
        &retry_packet,
        QUIC_VERSION_1,
    );
    assert!(!handled);
}

#[test]
fn client_rejects_retry_with_bad_tag() {
    use crate::net::handler::quic::connection::{QuicConnectionState, Side};
    use crate::net::handler::quic::transport::packet_builder::build_retry_packet;
    use crate::net::handler::quic::transport::params::TransportParams;
    use crate::net::handler::quic::transport::version::QUIC_VERSION_1;
    use coarsetime::Instant;

    let now = Instant::now();
    let dcid = ConnectionId::from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    let mut conn =
        QuicConnectionState::new(dcid, Side::Client, TransportParams::default(), 1200, now);

    let mut retry_packet = build_retry_packet(
        QUIC_VERSION_1,
        &[0x0A],
        &[0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7],
        dcid.as_bytes(),
        &[0xCA, 0xFE],
    );
    let len = retry_packet.len();
    retry_packet[len - 1] ^= 0xFF; // tamper tag

    let handled = crate::net::handler::quic::processor::handle_retry_packet(
        &mut conn,
        &retry_packet,
        QUIC_VERSION_1,
    );
    assert!(!handled);
    assert!(!conn.retry_received); // should not be set
}
