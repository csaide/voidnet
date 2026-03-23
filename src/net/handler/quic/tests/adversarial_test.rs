//! Adversarial / edge-case tests for QUIC packet and frame handling.
//!
//! Every test constructs a malformed or out-of-spec packet/frame and feeds it
//! to the handler or processor. The key requirement is **no crash** — the
//! implementation must silently drop or return an appropriate error.

use std::sync::Arc;

use coarsetime::{Duration, Instant};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, ServerConfig, SignatureScheme};

use crate::net::handler::quic::QuicHandler;
use crate::net::handler::quic::connection::{ConnectionState, QuicConnectionState, Side};
use crate::net::handler::quic::connection_id::ConnectionId;
use crate::net::handler::quic::crypto::initial_keys::derive_initial_keys;
use crate::net::handler::quic::crypto::keys::{DirectionalKey, KeyPair};
use crate::net::handler::quic::crypto::packet_protection::protect_packet;
use crate::net::handler::quic::crypto::tls::CryptoState;
use crate::net::handler::quic::processor;
use crate::net::handler::quic::transport::frame::StreamId;
use crate::net::handler::quic::transport::params::TransportParams;
use crate::net::handler::quic::transport::varint::encode_varint;
use crate::net::handler::quic::transport::version::QUIC_VERSION_1;
use crate::net::neighbor::NeighborHandler;
use crate::net::timer_wheel::TimerWheel;
use crate::net::wire::ethernet::EthernetFrame;
use crate::net::wire::ip::{IPV4_MIN_HEADER_LEN, IpAddress, Ipv4Address};
use crate::net::wire::udp::UDP_HEADER_LEN;
use crate::xdp::frame::{BasicFrameBuffer, Frame, FrameBuffer};

const QUIC_PORT: u16 = 4433;

// ── TLS helpers ──────────────────────────────────────────────────────

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

fn test_transport_params() -> TransportParams {
    TransportParams {
        initial_max_data: 1_000_000,
        initial_max_stream_data_bidi_local: 100_000,
        initial_max_stream_data_bidi_remote: 100_000,
        initial_max_stream_data_uni: 100_000,
        initial_max_streams_bidi: 100,
        initial_max_streams_uni: 100,
        ..Default::default()
    }
}

fn encode_test_transport_params() -> Vec<u8> {
    let params = test_transport_params();
    let mut buf = [0u8; 256];
    let len = params.encode(&mut buf);
    buf[..len].to_vec()
}

// ── Packet construction helpers ──────────────────────────────────────

/// Build a valid QUIC Initial packet.
fn build_initial_packet(
    client_dcid: &[u8],
    client_scid: &[u8],
    crypto_data: &[u8],
    client_key: &DirectionalKey,
) -> Vec<u8> {
    let tag_len = client_key.packet_key.tag_len();

    let first_byte = 0xC0u8;

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
    crypto_frame.push(0x06);
    let n = encode_varint(0, &mut varint_buf);
    crypto_frame.extend_from_slice(&varint_buf[..n]);
    let n = encode_varint(crypto_data.len() as u64, &mut varint_buf);
    crypto_frame.extend_from_slice(&varint_buf[..n]);
    crypto_frame.extend_from_slice(crypto_data);

    let pn_len = 1usize;
    let min_payload_before_tag = 1200 - header.len() - 2 - pn_len - tag_len;
    let padding_needed = if crypto_frame.len() < min_payload_before_tag {
        min_payload_before_tag - crypto_frame.len()
    } else {
        0
    };

    let length_value = pn_len + crypto_frame.len() + padding_needed + tag_len;

    let n = encode_varint(length_value as u64, &mut varint_buf);
    header.extend_from_slice(&varint_buf[..n]);

    let pn_offset = header.len();

    let total_len = header.len() + pn_len + crypto_frame.len() + padding_needed + tag_len;
    let mut packet = vec![0u8; total_len];
    packet[..header.len()].copy_from_slice(&header);
    packet[pn_offset] = 0x00;
    let payload_start = pn_offset + pn_len;
    packet[payload_start..payload_start + crypto_frame.len()].copy_from_slice(&crypto_frame);

    protect_packet(client_key, &mut packet, pn_offset, pn_len, 0).unwrap();

    packet
}

/// Build a complete Ethernet + IPv4 + UDP frame wrapping raw QUIC data.
fn wrap_in_eth_ipv4_udp(quic_packet: &[u8], frame_buf: &mut [u8]) -> usize {
    use crate::net::checksum::compute_ipv4_checksum;

    let eth_len = std::mem::size_of::<EthernetFrame>();
    let ip_len = IPV4_MIN_HEADER_LEN;
    let udp_offset = eth_len + ip_len;
    let quic_offset = udp_offset + UDP_HEADER_LEN;

    let quic_len = quic_packet.len();
    let total_frame_len = quic_offset + quic_len;
    assert!(
        frame_buf.len() >= total_frame_len,
        "frame_buf too small: {} < {}",
        frame_buf.len(),
        total_frame_len
    );

    // Ethernet header
    frame_buf[0..6].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    frame_buf[6..12].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    frame_buf[12] = 0x08;
    frame_buf[13] = 0x00;

    // IPv4 header
    let ip_total = (ip_len + UDP_HEADER_LEN + quic_len) as u16;
    let ip_buf = &mut frame_buf[eth_len..];
    ip_buf[0] = 0x45;
    ip_buf[1] = 0x00;
    ip_buf[2..4].copy_from_slice(&ip_total.to_be_bytes());
    ip_buf[4..6].copy_from_slice(&[0x00, 0x00]);
    ip_buf[6] = 0x40;
    ip_buf[7] = 0x00;
    ip_buf[8] = 64;
    ip_buf[9] = 17;
    ip_buf[10] = 0;
    ip_buf[11] = 0;
    ip_buf[12..16].copy_from_slice(&[10, 0, 0, 2]);
    ip_buf[16..20].copy_from_slice(&[192, 168, 1, 1]);
    let cksum = compute_ipv4_checksum(&ip_buf[..ip_len]);
    ip_buf[10] = cksum[0];
    ip_buf[11] = cksum[1];

    // UDP header
    let udp_buf = &mut frame_buf[udp_offset..];
    let udp_total = (UDP_HEADER_LEN + quic_len) as u16;
    udp_buf[0..2].copy_from_slice(&12345u16.to_be_bytes());
    udp_buf[2..4].copy_from_slice(&QUIC_PORT.to_be_bytes());
    udp_buf[4..6].copy_from_slice(&udp_total.to_be_bytes());
    udp_buf[6] = 0;
    udp_buf[7] = 0;

    // QUIC payload
    frame_buf[quic_offset..quic_offset + quic_len].copy_from_slice(quic_packet);

    total_frame_len
}

/// Create a server handler with a listener on QUIC_PORT.
fn setup_server_handler() -> QuicHandler {
    let mut handler = QuicHandler::new(false, false);
    let server_config = make_server_config();
    let params = test_transport_params();
    handler
        .listen(QUIC_PORT, server_config, params)
        .expect("listen should succeed");
    handler
}

/// Feed a raw QUIC packet (wrapped in Eth/IP/UDP) to the handler.
/// Returns (connections_before, connections_after).
fn feed_quic_packet_to_handler(handler: &mut QuicHandler, quic_packet: &[u8]) -> (usize, usize) {
    let now = Instant::now();

    let mut frame_data = vec![0u8; 4096];
    let frame_len = wrap_in_eth_ipv4_udp(quic_packet, &mut frame_data);

    let frame = Frame::new(0, &mut frame_data, frame_len, false);
    let mut wheel = TimerWheel::new(now);
    let nh = NeighborHandler::new("lo", Duration::from_secs(60)).unwrap();

    let mut free_bufs: Vec<Vec<u8>> = (0..8).map(|_| vec![0u8; 4096]).collect();
    let mut free = BasicFrameBuffer::new(8);
    for (i, buf) in free_bufs.iter_mut().enumerate() {
        let f = Frame::new((i as u64 + 1) * 4096, buf.as_mut_slice(), 1, false);
        free.push(f);
    }
    let mut rx = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(8);

    let conns_before = handler.connections.len();
    handler.process_ipv4(frame, now, &mut wheel, &nh, &mut free, &mut rx, &mut tx);
    handler.poll_send(now, &mut wheel, &mut free, &mut tx);
    let conns_after = handler.connections.len();

    (conns_before, conns_after)
}

/// Build a valid Initial packet using real TLS ClientHello.
fn build_valid_initial() -> (Vec<u8>, [u8; 8], [u8; 4]) {
    let dcid_bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let scid_bytes = [0xAA, 0xBB, 0xCC, 0xDD];

    let client_config = make_client_config();
    let client_params = encode_test_transport_params();
    let (_client_crypto, client_hello) = CryptoState::new_client(
        client_config,
        "localhost",
        &client_params,
        rustls::quic::Version::V1,
    )
    .unwrap();

    let (client_local, _) =
        derive_initial_keys(&dcid_bytes, rustls::Side::Client, rustls::quic::Version::V1);
    let client_encrypt_key = DirectionalKey::from_rustls(client_local);
    let quic_packet =
        build_initial_packet(&dcid_bytes, &scid_bytes, &client_hello, &client_encrypt_key);

    (quic_packet, dcid_bytes, scid_bytes)
}

// ═══════════════════════════════════════════════════════════════════════
// Task 19: Adversarial Packet-Level Tests
// ═══════════════════════════════════════════════════════════════════════

/// Test 1: Truncated Initial packet should not crash.
#[test]
fn truncated_packet() {
    let mut handler = setup_server_handler();
    let (valid_packet, _, _) = build_valid_initial();

    // Truncate to half length
    let truncated = &valid_packet[..valid_packet.len() / 2];
    let (before, after) = feed_quic_packet_to_handler(&mut handler, truncated);

    // Should not have created a connection
    assert_eq!(
        before, after,
        "truncated packet should not create a connection"
    );
}

/// Test 2: DCID length byte exceeding 20 should be dropped.
#[test]
fn dcid_length_exceeds_20() {
    let mut handler = setup_server_handler();

    // Construct a long header with DCID length = 25 (exceeds max of 20)
    let mut packet = Vec::with_capacity(128);
    // First byte: long header form bit + fixed bit + Initial type
    packet.push(0xC0);
    // Version
    packet.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
    // DCID length = 25 (invalid, max is 20 per RFC 9000)
    packet.push(25);
    // Fill with 25 bytes of DCID data
    packet.extend_from_slice(&[0xAA; 25]);
    // SCID length = 4
    packet.push(4);
    packet.extend_from_slice(&[0xBB; 4]);
    // Token length = 0
    packet.push(0);
    // Length = some value (doesn't matter, will be rejected earlier)
    packet.push(0x40);
    packet.push(0x10);
    // Padding to fill to some size
    packet.extend_from_slice(&[0x00; 64]);

    let (before, after) = feed_quic_packet_to_handler(&mut handler, &packet);
    assert_eq!(
        before, after,
        "oversized DCID should not create a connection"
    );
}

/// Test 3: Short header (1-RTT) packet before handshake should be dropped.
#[test]
fn short_header_before_handshake() {
    let mut handler = setup_server_handler();

    // Build a short header packet — form bit = 0, fixed bit = 1
    let mut packet = Vec::with_capacity(128);
    // First byte: 0x40 (form=0, fixed=1) — short header
    packet.push(0x40);
    // DCID (8 bytes — arbitrary, no connection exists for this)
    packet.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    // PN + payload (garbage)
    packet.extend_from_slice(&[0x00; 64]);

    let (before, after) = feed_quic_packet_to_handler(&mut handler, &packet);
    assert_eq!(
        before, after,
        "short header before handshake should not create a connection"
    );
}

/// Test 4: Duplicate packet number should be silently dropped on the second delivery.
#[test]
fn duplicate_packet_number() {
    let now = Instant::now();

    // Build a valid Initial packet
    let (quic_packet, dcid_bytes, _) = build_valid_initial();
    assert!(quic_packet.len() >= 1200);

    // Set up handler
    let mut handler = setup_server_handler();
    let mut wheel = TimerWheel::new(now);
    let nh = NeighborHandler::new("lo", Duration::from_secs(60)).unwrap();

    // First delivery
    {
        let mut frame_data = vec![0u8; 4096];
        let frame_len = wrap_in_eth_ipv4_udp(&quic_packet, &mut frame_data);
        let frame = Frame::new(0, &mut frame_data, frame_len, false);

        let mut free_bufs: Vec<Vec<u8>> = (0..8).map(|_| vec![0u8; 4096]).collect();
        let mut free = BasicFrameBuffer::new(8);
        for (i, buf) in free_bufs.iter_mut().enumerate() {
            let f = Frame::new((i as u64 + 1) * 4096, buf.as_mut_slice(), 1, false);
            free.push(f);
        }
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(8);

        handler.process_ipv4(frame, now, &mut wheel, &nh, &mut free, &mut rx, &mut tx);
        handler.poll_send(now, &mut wheel, &mut free, &mut tx);
    }

    // Should have created exactly one connection
    assert_eq!(
        handler.connections.len(),
        1,
        "first delivery should create a connection"
    );

    // Second delivery (same packet, same PN)
    {
        let mut frame_data = vec![0u8; 4096];
        let frame_len = wrap_in_eth_ipv4_udp(&quic_packet, &mut frame_data);
        let frame = Frame::new(0, &mut frame_data, frame_len, false);

        let mut free_bufs: Vec<Vec<u8>> = (0..8).map(|_| vec![0u8; 4096]).collect();
        let mut free = BasicFrameBuffer::new(8);
        for (i, buf) in free_bufs.iter_mut().enumerate() {
            let f = Frame::new((i as u64 + 1) * 4096, buf.as_mut_slice(), 1, false);
            free.push(f);
        }
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(8);

        handler.process_ipv4(frame, now, &mut wheel, &nh, &mut free, &mut rx, &mut tx);
        handler.poll_send(now, &mut wheel, &mut free, &mut tx);
    }

    // Should still have exactly one connection (duplicate silently dropped)
    assert_eq!(
        handler.connections.len(),
        1,
        "duplicate packet should not create a second connection"
    );
}

/// Test 5: Client Initial below 1200 bytes should be dropped by the server.
#[test]
fn client_initial_below_1200() {
    let mut handler = setup_server_handler();

    let dcid_bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let scid_bytes = [0xAA, 0xBB, 0xCC, 0xDD];

    let client_config = make_client_config();
    let client_params = encode_test_transport_params();
    let (_client_crypto, client_hello) = CryptoState::new_client(
        client_config,
        "localhost",
        &client_params,
        rustls::quic::Version::V1,
    )
    .unwrap();

    let (client_local, _) =
        derive_initial_keys(&dcid_bytes, rustls::Side::Client, rustls::quic::Version::V1);
    let client_encrypt_key = DirectionalKey::from_rustls(client_local);

    // Build an Initial packet WITHOUT padding to 1200 bytes
    let tag_len = client_encrypt_key.packet_key.tag_len();
    let first_byte = 0xC0u8;

    let mut header = Vec::with_capacity(64);
    header.push(first_byte);
    header.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
    header.push(dcid_bytes.len() as u8);
    header.extend_from_slice(&dcid_bytes);
    header.push(scid_bytes.len() as u8);
    header.extend_from_slice(&scid_bytes);

    let mut varint_buf = [0u8; 8];
    let n = encode_varint(0, &mut varint_buf);
    header.extend_from_slice(&varint_buf[..n]);

    // Build CRYPTO frame with minimal data (just 10 bytes instead of full ClientHello)
    let mut crypto_frame = Vec::new();
    crypto_frame.push(0x06);
    let n = encode_varint(0, &mut varint_buf);
    crypto_frame.extend_from_slice(&varint_buf[..n]);
    let small_data = &client_hello[..10.min(client_hello.len())];
    let n = encode_varint(small_data.len() as u64, &mut varint_buf);
    crypto_frame.extend_from_slice(&varint_buf[..n]);
    crypto_frame.extend_from_slice(small_data);

    // NO padding — intentionally small
    let pn_len = 1usize;
    let length_value = pn_len + crypto_frame.len() + tag_len;

    let n = encode_varint(length_value as u64, &mut varint_buf);
    header.extend_from_slice(&varint_buf[..n]);

    let pn_offset = header.len();
    let total_len = header.len() + pn_len + crypto_frame.len() + tag_len;
    let mut packet = vec![0u8; total_len];
    packet[..header.len()].copy_from_slice(&header);
    packet[pn_offset] = 0x00;
    let payload_start = pn_offset + pn_len;
    packet[payload_start..payload_start + crypto_frame.len()].copy_from_slice(&crypto_frame);

    protect_packet(&client_encrypt_key, &mut packet, pn_offset, pn_len, 0).unwrap();

    // Verify it's actually under 1200 bytes
    assert!(
        packet.len() < 1200,
        "test packet should be under 1200 bytes, got {}",
        packet.len()
    );

    let (before, after) = feed_quic_packet_to_handler(&mut handler, &packet);
    assert_eq!(
        before, after,
        "Initial packet under 1200 bytes should not create a connection"
    );
}
