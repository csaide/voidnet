//! Socket API integration tests.
//!
//! These tests validate that the QUIC socket API (QuicListener, QuicConnection,
//! QuicStream) integrates correctly with the handler layer. They drive the
//! handler directly (same pattern as handshake_integration_test) and verify that
//! the accept_queue, stream_accept_queue, and event_queue are populated
//! correctly when packets are processed.

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
use crate::net::handler::quic::transport::frame::StreamId;
use crate::net::handler::quic::transport::params::TransportParams;
use crate::net::handler::quic::transport::varint::encode_varint;
use crate::net::handler::quic::transport::version::QUIC_VERSION_1;
use crate::net::neighbor::NeighborHandler;
use crate::net::socket::LocalQueue;
use crate::net::timer_wheel::TimerWheel;
use crate::net::wire::ethernet::EthernetFrame;
use crate::net::wire::ip::IPV4_MIN_HEADER_LEN;
use crate::net::wire::udp::UDP_HEADER_LEN;
use crate::xdp::frame::{BasicFrameBuffer, Frame, FrameBuffer};

const QUIC_PORT: u16 = 4433;

// ---------------------------------------------------------------------------
// Shared helpers (same as handshake_integration_test)
// ---------------------------------------------------------------------------

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

    let mut varint_buf = [0u8; 8];
    let n = encode_varint(0, &mut varint_buf);
    header.extend_from_slice(&varint_buf[..n]);

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

fn wrap_in_eth_ipv4_udp(quic_packet: &[u8], frame_buf: &mut [u8]) -> usize {
    use crate::net::checksum::compute_ipv4_checksum;

    let eth_len = std::mem::size_of::<EthernetFrame>();
    let ip_len = IPV4_MIN_HEADER_LEN;
    let udp_offset = eth_len + ip_len;
    let quic_offset = udp_offset + UDP_HEADER_LEN;

    let quic_len = quic_packet.len();
    let total_frame_len = quic_offset + quic_len;
    assert!(frame_buf.len() >= total_frame_len);

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

    frame_buf[quic_offset..quic_offset + quic_len].copy_from_slice(quic_packet);
    total_frame_len
}

/// Helper macro: create frame buffers for handler testing.
/// Defines variables in the caller's scope so frame lifetimes work out.
macro_rules! make_frame_buffers {
    ($free_bufs:ident, $free:ident, $rx:ident, $tx:ident) => {
        let mut $free_bufs: Vec<Vec<u8>> = (0..8).map(|_| vec![0u8; 4096]).collect();
        let mut $free = BasicFrameBuffer::new(8);
        for (i, buf) in $free_bufs.iter_mut().enumerate() {
            let f = Frame::new((i as u64 + 1) * 4096, buf.as_mut_slice(), 1, false);
            $free.push(f);
        }
        let mut $rx = BasicFrameBuffer::new(4);
        let mut $tx = BasicFrameBuffer::new(8);
    };
}

/// Helper: complete a TLS handshake and produce both sides' 1-RTT keys.
fn complete_tls_handshake() -> (KeyPair, KeyPair) {
    let client_config = make_client_config();
    let server_config = make_server_config();
    let client_params_bytes = encode_test_transport_params();
    let server_params_bytes = encode_test_transport_params();

    let (mut client_crypto, client_hello) = CryptoState::new_client(
        client_config,
        "localhost",
        &client_params_bytes,
        rustls::quic::Version::V1,
    )
    .unwrap();
    let mut server_crypto = CryptoState::new_server(
        server_config,
        &server_params_bytes,
        rustls::quic::Version::V1,
    )
    .unwrap();

    let server_out = server_crypto.process_crypto_data(&client_hello).unwrap();
    let mut server_one_rtt = server_out.one_rtt_keys;
    let _server_hs_keys = server_out.handshake_keys;

    let client_out = client_crypto
        .process_crypto_data(&server_out.crypto_data)
        .unwrap();
    let client_one_rtt = client_out.one_rtt_keys;

    if !client_out.crypto_data.is_empty() {
        let server_out2 = server_crypto
            .process_crypto_data(&client_out.crypto_data)
            .unwrap();
        if server_one_rtt.is_none() {
            server_one_rtt = server_out2.one_rtt_keys;
        }
    }

    let client_keys = client_one_rtt.expect("client must have 1-RTT keys");
    let server_keys = server_one_rtt.expect("server must have 1-RTT keys");
    (client_keys, server_keys)
}

/// Helper: set up a QuicConnectionState with 1-RTT keys for stream tests.
fn make_established_conn(server_keys: KeyPair, now: Instant) -> (QuicConnectionState, [u8; 8]) {
    let dcid_bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let dcid = ConnectionId::from_slice(&dcid_bytes);

    let params = TransportParams {
        initial_max_data: 1_000_000,
        initial_max_stream_data_bidi_local: 100_000,
        initial_max_stream_data_bidi_remote: 100_000,
        initial_max_streams_bidi: 100,
        ..Default::default()
    };

    let mut conn = QuicConnectionState::new(dcid, Side::Server, params, 1200, now);
    conn.keys.one_rtt = Some(server_keys);
    conn.state = ConnectionState::Established;
    // Set SCID to match the DCID used in incoming short header packets
    conn.scid = ConnectionId::from_slice(&dcid_bytes);
    conn.streams.local_max_bidi = 100;
    conn.streams.local_max_uni = 100;
    conn.streams.peer_max_bidi = 100;
    conn.streams.peer_max_uni = 100;
    conn.flow =
        crate::net::handler::quic::transport::flow_control::FlowControl::new(1_000_000, 1_000_000);

    (conn, dcid_bytes)
}

/// Build a 1-RTT short-header packet with a STREAM frame.
fn build_stream_packet(
    dcid_bytes: &[u8],
    stream_id: StreamId,
    data: &[u8],
    pn: u64,
    client_keys: &KeyPair,
) -> Vec<u8> {
    let first_byte = 0x40u8;
    let tag_len = client_keys.local.packet_key.tag_len();

    let mut header = Vec::new();
    header.push(first_byte);
    header.extend_from_slice(dcid_bytes);
    let pn_offset = header.len();
    header.push(pn as u8);
    let payload_start = header.len();

    // STREAM frame: type=0x0a (LEN=1, OFF=0, FIN=0)
    let mut stream_frame = Vec::new();
    stream_frame.push(0x0a);
    let mut varint_buf = [0u8; 8];
    let n = encode_varint(stream_id.0, &mut varint_buf);
    stream_frame.extend_from_slice(&varint_buf[..n]);
    let n = encode_varint(data.len() as u64, &mut varint_buf);
    stream_frame.extend_from_slice(&varint_buf[..n]);
    stream_frame.extend_from_slice(data);

    let total_len = payload_start + stream_frame.len() + tag_len;
    let mut packet = vec![0u8; total_len];
    packet[..header.len()].copy_from_slice(&header);
    packet[payload_start..payload_start + stream_frame.len()].copy_from_slice(&stream_frame);

    protect_packet(&client_keys.local, &mut packet, pn_offset, 1, pn)
        .expect("protect_packet should succeed");

    packet
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// After a full handshake through the handler, the accept_queue (registered
/// via listen_with_queue) should contain the connection's slab key.
#[test]
fn accept_queue_populated_after_handshake() {
    let now = Instant::now();

    let dcid_bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let scid_bytes = [0xAA, 0xBB, 0xCC, 0xDD];

    // Generate ClientHello
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

    let mut frame_data = vec![0u8; 2048];
    let frame_len = wrap_in_eth_ipv4_udp(&quic_packet, &mut frame_data);

    // Set up handler with accept_queue via listen_with_queue
    let mut handler = QuicHandler::new(false, false);
    let server_config = make_server_config();
    let params = TransportParams {
        initial_max_data: 1_000_000,
        initial_max_stream_data_bidi_local: 100_000,
        initial_max_stream_data_bidi_remote: 100_000,
        initial_max_streams_bidi: 100,
        ..Default::default()
    };
    let accept_queue: LocalQueue<usize> = LocalQueue::new(128);
    handler.listen_with_queue(QUIC_PORT, server_config, params, accept_queue.clone());

    // Process the ClientHello
    let frame = Frame::new(0, &mut frame_data, frame_len, false);
    let mut wheel = TimerWheel::new(now);
    let nh = NeighborHandler::new("lo", Duration::from_secs(60)).unwrap();

    make_frame_buffers!(_free_bufs, free, rx, tx);
    handler.process_ipv4(frame, now, &mut wheel, &nh, &mut free, &mut rx, &mut tx);

    // Verify connection was created
    assert_eq!(handler.connections.len(), 1, "one connection should exist");

    // The accept_queue should contain the connection key
    let conn_key = accept_queue.pop();
    assert!(
        conn_key.is_some(),
        "accept_queue should have the connection key after handshake"
    );

    // Verify the key points to a valid connection
    let key = conn_key.unwrap();
    assert!(
        handler.connections.contains(key),
        "accept_queue key should reference a valid connection"
    );

    // Queue should be empty after one pop
    assert!(
        accept_queue.pop().is_none(),
        "accept_queue should have exactly one entry"
    );
}

/// When a STREAM frame arrives on a new stream, the stream_accept_queue on the
/// connection should be populated with the stream ID.
#[test]
fn stream_accept_queue_populated_on_stream_frame() {
    use crate::net::handler::quic::processor;

    let now = Instant::now();
    let (client_keys, server_keys) = complete_tls_handshake();
    let (mut conn, dcid_bytes) = make_established_conn(server_keys, now);

    let stream_id = StreamId(0x00); // client-initiated bidi stream 0
    let stream_data = b"hello quic";

    let mut packet = build_stream_packet(&dcid_bytes, stream_id, stream_data, 0, &client_keys);
    let datagram_len = packet.len();

    let result = processor::process_packet(&mut conn, &mut packet, datagram_len, now);
    assert!(
        matches!(result, processor::ProcessResult::Ok),
        "process_packet should return Ok"
    );

    // stream_accept_queue should have the new stream
    let accepted = conn.stream_accept_queue.pop();
    assert!(
        accepted.is_some(),
        "stream_accept_queue should contain the new stream ID"
    );
    assert_eq!(
        accepted.unwrap(),
        stream_id,
        "accepted stream ID should match"
    );

    // Queue should be empty after one pop
    assert!(
        conn.stream_accept_queue.pop().is_none(),
        "stream_accept_queue should have exactly one entry"
    );
}

/// Data arriving on a stream should be readable from the RecvHalf.
#[test]
fn stream_read_returns_data() {
    use crate::net::handler::quic::processor;

    let now = Instant::now();
    let (client_keys, server_keys) = complete_tls_handshake();
    let (mut conn, dcid_bytes) = make_established_conn(server_keys, now);

    let stream_id = StreamId(0x00);
    let stream_data = b"hello quic";

    let mut packet = build_stream_packet(&dcid_bytes, stream_id, stream_data, 0, &client_keys);
    let datagram_len = packet.len();

    let result = processor::process_packet(&mut conn, &mut packet, datagram_len, now);
    assert!(matches!(result, processor::ProcessResult::Ok));

    // Read data from the RecvHalf directly
    let entry = conn
        .streams
        .get_mut(stream_id)
        .expect("stream should exist");
    let recv = entry.recv.as_mut().expect("stream should have RecvHalf");

    let mut read_buf = [0u8; 64];
    let n = recv.read(&mut read_buf);
    assert_eq!(n, stream_data.len(), "should read all stream data");
    assert_eq!(
        &read_buf[..n],
        stream_data,
        "read data should match 'hello quic'"
    );
}

/// Writing to a SendHalf should queue data that the packet builder can emit.
#[test]
fn stream_write_queues_data() {
    let now = Instant::now();
    let (_client_keys, server_keys) = complete_tls_handshake();
    let (mut conn, _dcid_bytes) = make_established_conn(server_keys, now);

    // Create a server-initiated bidi stream (stream ID = 1: type bits = 0x01)
    let stream_id = StreamId(0x01);
    let entry = conn
        .streams
        .get_or_create(stream_id)
        .expect("should be able to create stream");

    // Write data to the SendHalf
    let write_data = b"response data";
    let send = entry
        .send
        .as_mut()
        .expect("bidi stream should have SendHalf");
    let written = send.write(write_data);
    assert_eq!(
        written,
        write_data.len(),
        "all data should be written to SendHalf"
    );

    // Verify the buffer has pending data
    assert!(
        send.buffer.len() > 0,
        "SendHalf buffer should have pending data"
    );
    assert!(send.can_send(), "SendHalf should report can_send() == true");
}

/// The event_queue should contain a StreamReadable event after receiving
/// a STREAM frame.
#[test]
fn event_queue_notified_on_stream_data() {
    use crate::net::handler::quic::event::QuicEvent;
    use crate::net::handler::quic::processor;

    let now = Instant::now();
    let (client_keys, server_keys) = complete_tls_handshake();
    let (mut conn, dcid_bytes) = make_established_conn(server_keys, now);

    let stream_id = StreamId(0x00);
    let stream_data = b"event test";

    let mut packet = build_stream_packet(&dcid_bytes, stream_id, stream_data, 0, &client_keys);
    let datagram_len = packet.len();

    let result = processor::process_packet(&mut conn, &mut packet, datagram_len, now);
    assert!(matches!(result, processor::ProcessResult::Ok));

    // event_queue should have a StreamReadable event
    let event = conn.event_queue.pop();
    assert!(
        event.is_some(),
        "event_queue should contain an event after STREAM frame"
    );

    match event.unwrap() {
        QuicEvent::StreamReadable(sid) => {
            assert_eq!(sid, stream_id, "event stream ID should match");
        }
        other => panic!(
            "expected StreamReadable event, got {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

/// Multiple STREAM frames on different stream IDs should each produce an
/// entry in stream_accept_queue and events in event_queue.
#[test]
fn multiple_streams_accepted() {
    use crate::net::handler::quic::processor;

    let now = Instant::now();
    let (client_keys, server_keys) = complete_tls_handshake();
    let (mut conn, dcid_bytes) = make_established_conn(server_keys, now);

    // Send data on stream 0 (client-initiated bidi)
    let stream0 = StreamId(0x00);
    let mut pkt0 = build_stream_packet(&dcid_bytes, stream0, b"stream zero", 0, &client_keys);
    let len0 = pkt0.len();
    let r0 = processor::process_packet(&mut conn, &mut pkt0, len0, now);
    assert!(matches!(r0, processor::ProcessResult::Ok));

    // Send data on stream 4 (client-initiated bidi, next one)
    let stream4 = StreamId(0x04);
    let mut pkt4 = build_stream_packet(&dcid_bytes, stream4, b"stream four", 1, &client_keys);
    let len4 = pkt4.len();
    let r4 = processor::process_packet(&mut conn, &mut pkt4, len4, now);
    assert!(matches!(r4, processor::ProcessResult::Ok));

    // Both streams should be in the accept queue
    let accepted: Vec<StreamId> = std::iter::from_fn(|| conn.stream_accept_queue.pop()).collect();
    assert_eq!(accepted.len(), 2, "should have 2 streams accepted");
    assert!(accepted.contains(&stream0), "stream 0 should be accepted");
    assert!(accepted.contains(&stream4), "stream 4 should be accepted");

    // Both should have readable data
    for sid in &[stream0, stream4] {
        let entry = conn.streams.get_mut(*sid).expect("stream should exist");
        let recv = entry.recv.as_mut().expect("should have RecvHalf");
        let mut buf = [0u8; 64];
        let n = recv.read(&mut buf);
        assert!(n > 0, "stream {:?} should have data", sid);
    }
}

/// The handler should correctly populate cid_map when using listen_with_queue,
/// ensuring the socket API can look up connections by connection ID.
#[test]
fn cid_map_populated_with_listen_with_queue() {
    let now = Instant::now();

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

    let mut frame_data = vec![0u8; 2048];
    let frame_len = wrap_in_eth_ipv4_udp(&quic_packet, &mut frame_data);

    let mut handler = QuicHandler::new(false, false);
    let server_config = make_server_config();
    let params = TransportParams {
        initial_max_data: 1_000_000,
        initial_max_stream_data_bidi_local: 100_000,
        initial_max_stream_data_bidi_remote: 100_000,
        initial_max_streams_bidi: 100,
        ..Default::default()
    };
    let accept_queue: LocalQueue<usize> = LocalQueue::new(128);
    handler.listen_with_queue(QUIC_PORT, server_config, params, accept_queue.clone());

    let frame = Frame::new(0, &mut frame_data, frame_len, false);
    let mut wheel = TimerWheel::new(now);
    let nh = NeighborHandler::new("lo", Duration::from_secs(60)).unwrap();
    make_frame_buffers!(_free_bufs, free, rx, tx);

    handler.process_ipv4(frame, now, &mut wheel, &nh, &mut free, &mut rx, &mut tx);

    // cid_map should have entries
    assert!(
        !handler.cid_map.is_empty(),
        "cid_map should have entries for the new connection"
    );

    // All CID map entries should point to valid connections
    for (_, &conn_key) in handler.cid_map.iter() {
        assert!(
            handler.connections.contains(conn_key),
            "cid_map entry should reference a valid connection"
        );
    }

    // accept_queue key should match cid_map connection key
    let accepted_key = accept_queue.pop().unwrap();
    let cid_keys: Vec<usize> = handler.cid_map.values().copied().collect();
    assert!(
        cid_keys.contains(&accepted_key),
        "accept_queue key should be in cid_map"
    );
}
