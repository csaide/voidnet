use std::sync::Arc;

use coarsetime::{Duration, Instant};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, ServerConfig, SignatureScheme};

use crate::net::handler::quic::QuicHandler;
use crate::net::handler::quic::connection::ConnectionState;
use crate::net::handler::quic::connection_id::ConnectionId;
use crate::net::handler::quic::crypto::initial_keys::derive_initial_keys;
use crate::net::handler::quic::crypto::keys::DirectionalKey;
use crate::net::handler::quic::crypto::packet_protection::protect_packet;
use crate::net::handler::quic::crypto::tls::CryptoState;
use crate::net::handler::quic::transport::params::TransportParams;
use crate::net::handler::quic::transport::varint::encode_varint;
use crate::net::handler::quic::transport::version::QUIC_VERSION_1;
use crate::net::neighbor::NeighborHandler;
use crate::net::timer_wheel::TimerWheel;
use crate::net::wire::ethernet::EthernetFrame;
use crate::net::wire::ip::IPV4_MIN_HEADER_LEN;
use crate::net::wire::udp::UDP_HEADER_LEN;
use crate::xdp::frame::{BasicFrameBuffer, Frame, FrameBuffer};

const QUIC_PORT: u16 = 4433;

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

/// Build a QUIC Initial packet (same logic as processor_test).
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
    // dst MAC
    frame_buf[0..6].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    // src MAC (remote)
    frame_buf[6..12].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    // EtherType = IPv4
    frame_buf[12] = 0x08;
    frame_buf[13] = 0x00;

    // IPv4 header
    let ip_total = (ip_len + UDP_HEADER_LEN + quic_len) as u16;
    let ip_buf = &mut frame_buf[eth_len..];
    ip_buf[0] = 0x45; // version=4, IHL=5
    ip_buf[1] = 0x00; // DSCP/ECN
    ip_buf[2..4].copy_from_slice(&ip_total.to_be_bytes());
    ip_buf[4..6].copy_from_slice(&[0x00, 0x00]); // identification
    ip_buf[6] = 0x40; // DF
    ip_buf[7] = 0x00;
    ip_buf[8] = 64; // TTL
    ip_buf[9] = 17; // protocol = UDP
    ip_buf[10] = 0; // checksum (zero before calculation)
    ip_buf[11] = 0;
    // src addr = 10.0.0.2
    ip_buf[12..16].copy_from_slice(&[10, 0, 0, 2]);
    // dst addr = 192.168.1.1
    ip_buf[16..20].copy_from_slice(&[192, 168, 1, 1]);
    let cksum = compute_ipv4_checksum(&ip_buf[..ip_len]);
    ip_buf[10] = cksum[0];
    ip_buf[11] = cksum[1];

    // UDP header
    let udp_buf = &mut frame_buf[udp_offset..];
    let udp_total = (UDP_HEADER_LEN + quic_len) as u16;
    udp_buf[0..2].copy_from_slice(&12345u16.to_be_bytes()); // src port
    udp_buf[2..4].copy_from_slice(&QUIC_PORT.to_be_bytes()); // dst port
    udp_buf[4..6].copy_from_slice(&udp_total.to_be_bytes());
    udp_buf[6] = 0;
    udp_buf[7] = 0; // checksum = 0 (valid for IPv4 UDP)

    // QUIC payload
    frame_buf[quic_offset..quic_offset + quic_len].copy_from_slice(quic_packet);

    total_frame_len
}

#[test]
fn full_handshake_through_handler() {
    let now = Instant::now();

    // Fixed CIDs
    let dcid_bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let scid_bytes = [0xAA, 0xBB, 0xCC, 0xDD];

    // 1. Generate ClientHello
    let client_config = make_client_config();
    let client_params = encode_test_transport_params();
    let (_client_crypto, client_hello) = CryptoState::new_client(
        client_config,
        "localhost",
        &client_params,
        rustls::quic::Version::V1,
    )
    .unwrap();
    assert!(!client_hello.is_empty());

    // 2. Derive client Initial keys and build encrypted QUIC packet
    let (client_local, _) =
        derive_initial_keys(&dcid_bytes, rustls::Side::Client, rustls::quic::Version::V1);
    let client_encrypt_key = DirectionalKey::from_rustls(client_local);
    let quic_packet =
        build_initial_packet(&dcid_bytes, &scid_bytes, &client_hello, &client_encrypt_key);
    assert!(quic_packet.len() >= 1200);

    // 3. Wrap in Ethernet + IPv4 + UDP
    let mut frame_data = vec![0u8; 2048];
    let frame_len = wrap_in_eth_ipv4_udp(&quic_packet, &mut frame_data);

    // 4. Set up handler with a listener
    let mut handler = QuicHandler::new(false, false);
    let server_config = make_server_config();
    let params = TransportParams {
        initial_max_data: 1_000_000,
        initial_max_stream_data_bidi_local: 100_000,
        initial_max_stream_data_bidi_remote: 100_000,
        initial_max_streams_bidi: 100,
        ..Default::default()
    };
    handler.listen(QUIC_PORT, server_config, params);

    // 5. Create frame and buffers
    let frame = Frame::new(0, &mut frame_data, frame_len, false);
    let mut wheel = TimerWheel::new(now);
    let nh = NeighborHandler::new("lo", Duration::from_secs(60)).unwrap();

    // Free frames for generate_packets to use for responses
    let mut free_bufs: Vec<Vec<u8>> = (0..8).map(|_| vec![0u8; 4096]).collect();
    let mut free = BasicFrameBuffer::new(8);
    for (i, buf) in free_bufs.iter_mut().enumerate() {
        let f = Frame::new((i as u64 + 1) * 4096, buf.as_mut_slice(), 1, false);
        free.push(f);
    }
    let mut rx = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(8);

    // 6. Process!
    handler.process_ipv4(frame, now, &mut wheel, &nh, &mut free, &mut rx, &mut tx);

    // 7. Verify: rx_return should have the consumed frame
    assert!(rx.num_frames() > 0, "frame should be returned to rx_return");

    // 8. Verify: tx should have response frame(s)
    assert!(
        tx.num_frames() > 0,
        "server should produce response packets, got 0"
    );

    // 9. Verify: a connection was created
    assert_eq!(
        handler.connections.len(),
        1,
        "exactly one connection should exist"
    );

    // 10. Verify connection state
    let (_, conn) = handler.connections.iter().next().unwrap();

    // After processing ClientHello, TLS 1.3 server derives 1-RTT keys in one shot.
    assert!(
        conn.keys.one_rtt.is_some(),
        "server should have installed 1-RTT keys after processing ClientHello"
    );

    // Connection should be Established or HandshakeComplete
    assert!(
        conn.state == ConnectionState::Established
            || conn.state == ConnectionState::HandshakeComplete
            || conn.state == ConnectionState::Handshaking,
        "connection should be in a handshake-progressed state, got {:?}",
        conn.state
    );

    // 11. Verify the output frames look like valid QUIC packets
    let eth_len = std::mem::size_of::<EthernetFrame>();
    for frame in tx.iter_frames() {
        let flen = frame.len();
        let min_expected = eth_len + IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN + 20;
        assert!(
            flen >= min_expected,
            "Response frame too short: {} < {}",
            flen,
            min_expected
        );

        // EtherType should be IPv4
        assert_eq!(frame[12], 0x08, "EtherType high byte should be 0x08");
        assert_eq!(frame[13], 0x00, "EtherType low byte should be 0x00");

        // IP version = 4, protocol = UDP (17)
        assert_eq!(frame[eth_len] >> 4, 4, "IP version should be 4");
        assert_eq!(frame[eth_len + 9], 17, "IP protocol should be UDP (17)");

        // UDP src port should be QUIC_PORT, dst should be 12345 (client's port)
        let udp_offset = eth_len + IPV4_MIN_HEADER_LEN;
        let src_port = u16::from_be_bytes([frame[udp_offset], frame[udp_offset + 1]]);
        let dst_port = u16::from_be_bytes([frame[udp_offset + 2], frame[udp_offset + 3]]);
        assert_eq!(src_port, QUIC_PORT, "UDP src port should be QUIC port");
        assert_eq!(dst_port, 12345, "UDP dst port should be client's port");

        // QUIC fixed bit (bit 6) should be set
        let quic_offset = udp_offset + UDP_HEADER_LEN;
        assert!(
            frame[quic_offset] & 0x40 != 0,
            "QUIC packet first byte should have fixed bit set, got {:#04x}",
            frame[quic_offset]
        );
    }

    // 12. Verify the connection has been registered in cid_map
    assert!(
        !handler.cid_map.is_empty(),
        "cid_map should have entries for the new connection"
    );
}

#[test]
fn stream_data_after_handshake() {
    use crate::net::handler::quic::connection::{ConnectionState, QuicConnectionState, Side};
    use crate::net::handler::quic::crypto::keys::KeyPair;
    use crate::net::handler::quic::crypto::packet_protection::protect_packet;
    use crate::net::handler::quic::processor;
    use crate::net::handler::quic::transport::frame::StreamId;

    let now = Instant::now();

    // ── Step 1: Complete the TLS handshake at CryptoState level ──────
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

    // Round 1: ClientHello → Server
    let server_out = server_crypto.process_crypto_data(&client_hello).unwrap();
    let mut server_one_rtt: Option<KeyPair> = server_out.one_rtt_keys;
    let server_hs_keys = server_out.handshake_keys;

    // Round 2: Server response → Client
    let client_out = client_crypto
        .process_crypto_data(&server_out.crypto_data)
        .unwrap();
    let client_one_rtt: Option<KeyPair> = client_out.one_rtt_keys;

    // If client has more data (Finished), feed it to server
    if !client_out.crypto_data.is_empty() {
        let server_out2 = server_crypto
            .process_crypto_data(&client_out.crypto_data)
            .unwrap();
        if server_one_rtt.is_none() {
            server_one_rtt = server_out2.one_rtt_keys;
        }
    }

    // Both sides must have 1-RTT keys
    let client_keys = client_one_rtt.expect("client must have 1-RTT keys");
    let server_keys = server_one_rtt.expect("server must have 1-RTT keys");

    // ── Step 2: Set up a QuicConnectionState with server-side keys ───
    let server_dcid_bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let server_dcid = ConnectionId::from_slice(&server_dcid_bytes);

    let params = TransportParams {
        initial_max_data: 1_000_000,
        initial_max_stream_data_bidi_local: 100_000,
        initial_max_stream_data_bidi_remote: 100_000,
        initial_max_streams_bidi: 100,
        ..Default::default()
    };

    let mut conn = QuicConnectionState::new(server_dcid.clone(), Side::Server, params, 1200, now);
    // Set SCID to match the DCID used in incoming short header packets
    conn.scid = ConnectionId::from_slice(&server_dcid_bytes);

    // Install server-side 1-RTT keys.
    // Server's "local" encrypts outgoing, server's "remote" decrypts incoming.
    // The client's "local" key encrypts what the server's "remote" decrypts.
    conn.keys.one_rtt = Some(server_keys);
    if let Some(hs) = server_hs_keys {
        conn.keys.handshake = Some(hs);
    }
    conn.state = ConnectionState::Established;

    // Set stream limits so the server accepts client-initiated bidi streams
    conn.streams.local_max_bidi = 100;
    conn.streams.local_max_uni = 100;

    // Set flow control to allow data
    conn.flow = crate::net::handler::quic::transport::flow_control::FlowControl::new(
        1_000_000, // send
        1_000_000, // recv
    );

    // ── Step 3: Build a 1-RTT (short header) packet with STREAM frame ─
    let stream_data = b"hello quic";
    let stream_id = StreamId(0x00); // client-initiated bidi stream 0

    // Short header format:
    // first_byte: 0b0100_0000 = 0x40 (form=0, fixed=1, spin=0, reserved=00, key_phase=0, pn_len=00 → 1-byte PN)
    let first_byte = 0x40u8;
    let pn: u64 = 0;

    let tag_len = client_keys.local.packet_key.tag_len();

    // Build header: first_byte + DCID + PN(1 byte)
    let mut header = Vec::new();
    header.push(first_byte);
    header.extend_from_slice(&server_dcid_bytes); // DCID = server's DCID
    let pn_offset = header.len();
    header.push(0x00); // PN = 0 (1 byte)
    let payload_start = header.len();

    // Build STREAM frame: type=0x0a (OFF=0, LEN=1, FIN=0)
    // Bit layout: 0x08 base | 0x02 (LEN) = 0x0a. OFF bit (0x04) not set since offset=0.
    let mut stream_frame = Vec::new();
    stream_frame.push(0x0a); // STREAM type: LEN=1, OFF=0, FIN=0
    let mut varint_buf = [0u8; 8];
    // stream_id = 0
    let n = encode_varint(stream_id.0, &mut varint_buf);
    stream_frame.extend_from_slice(&varint_buf[..n]);
    // length = stream_data.len() (no offset field since OFF=0)
    let n = encode_varint(stream_data.len() as u64, &mut varint_buf);
    stream_frame.extend_from_slice(&varint_buf[..n]);
    // data
    stream_frame.extend_from_slice(stream_data);

    // Assemble the full packet: header + stream_frame + tag space
    let total_len = payload_start + stream_frame.len() + tag_len;
    let mut packet = vec![0u8; total_len];
    packet[..header.len()].copy_from_slice(&header);
    packet[payload_start..payload_start + stream_frame.len()].copy_from_slice(&stream_frame);

    // Encrypt with client's 1-RTT local key (what server decrypts with its remote key)
    protect_packet(&client_keys.local, &mut packet, pn_offset, 1, pn)
        .expect("protect_packet should succeed");

    // ── Step 4: Feed to processor::process_packet ────────────────────
    let datagram_len = packet.len();
    let result = processor::process_packet(&mut conn, &mut packet, datagram_len, now);
    assert!(
        matches!(result, processor::ProcessResult::Ok),
        "process_packet should return Ok"
    );

    // ── Step 5: Verify ──────────────────────────────────────────────

    // 5a. Stream 0 should exist and have data
    let entry = conn
        .streams
        .get(stream_id)
        .expect("stream 0 should exist in StreamMap");
    let recv = entry.recv.as_ref().expect("stream 0 should have RecvHalf");
    assert_eq!(
        recv.received,
        stream_data.len() as u64,
        "RecvHalf.received should equal stream data length"
    );

    // Read the data out and verify
    let entry_mut = conn.streams.get_mut(stream_id).unwrap();
    let recv_mut = entry_mut.recv.as_mut().unwrap();
    let mut read_buf = [0u8; 64];
    let n = recv_mut.read(&mut read_buf);
    assert_eq!(n, stream_data.len());
    assert_eq!(
        &read_buf[..n],
        stream_data,
        "stream data should be 'hello quic'"
    );

    // 5b. ACK should be pending in 1-RTT space (space index 2)
    assert!(
        conn.ack[2].needs_ack(),
        "1-RTT ACK space should need to send an ACK after receiving STREAM frame"
    );

    // 5c. Connection should still be Established
    assert_eq!(
        conn.state,
        ConnectionState::Established,
        "connection should remain in Established state"
    );
}
