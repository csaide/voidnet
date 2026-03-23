use std::sync::Arc;

use coarsetime::{Duration, Instant};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, ServerConfig, SignatureScheme};

use crate::net::handler::quic::QuicHandler;
use crate::net::handler::quic::connection::ConnectionState;
use crate::net::handler::quic::transport::frame::StreamId;
use crate::net::handler::quic::transport::params::TransportParams;
use crate::net::neighbor::NeighborHandler;
use crate::net::timer_wheel::TimerWheel;
use crate::net::wire::ethernet::MacAddress;
use crate::net::wire::ip::{IpAddress, Ipv4Address};
use crate::xdp::frame::{BasicFrameBuffer, Frame, FrameBuffer};

const QUIC_PORT: u16 = 4433;

// Client addresses
const CLIENT_IP: [u8; 4] = [10, 0, 0, 2];
const CLIENT_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
const CLIENT_PORT: u16 = 12345;

// Server addresses
const SERVER_IP: [u8; 4] = [192, 168, 1, 1];
const SERVER_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

// ── TLS helpers (same as handshake_integration_test.rs) ──────────────

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

// ── E2E test helpers ─────────────────────────────────────────────────

/// Pump all pending TX frames from `src_handler` to `dst_handler`.
///
/// 1. Calls poll_send on src to generate outbound packets.
/// 2. Drains src's tx buffer, copies each frame's raw bytes into a frame
///    from dst's free pool, and feeds it to dst's process_ipv4.
/// 3. Recycles consumed frames.
///
/// Returns the number of frames pumped.
fn pump_packets<'a>(
    src_handler: &mut QuicHandler,
    src_wheel: &mut TimerWheel,
    src_free: &mut BasicFrameBuffer<'a>,
    src_tx: &mut BasicFrameBuffer<'a>,
    dst_handler: &mut QuicHandler,
    dst_wheel: &mut TimerWheel,
    dst_nh: &NeighborHandler,
    dst_free: &mut BasicFrameBuffer<'a>,
    dst_rx: &mut BasicFrameBuffer<'a>,
    dst_tx: &mut BasicFrameBuffer<'a>,
    now: Instant,
) -> usize {
    // Generate pending outbound packets
    src_handler.poll_send(now, src_wheel, src_free, src_tx);

    // Collect raw bytes from src tx
    let mut raw_frames: Vec<Vec<u8>> = Vec::new();
    while let Some(frame) = src_tx.pop() {
        raw_frames.push(frame[..frame.len()].to_vec());
        src_free.push(frame);
    }

    let count = raw_frames.len();

    for frame_data in raw_frames {
        if let Some(mut free_frame) = dst_free.pop() {
            let len = frame_data.len().min(free_frame.capacity());
            // SAFETY: expand to capacity so we can write, then shrink to actual data length.
            unsafe { free_frame.set_len(free_frame.capacity()) };
            free_frame[..len].copy_from_slice(&frame_data[..len]);
            unsafe { free_frame.set_len(len) };

            dst_handler.process_ipv4(free_frame, now, dst_wheel, dst_nh, dst_free, dst_rx, dst_tx);
            // Recycle consumed frames from rx back to free
            while let Some(rx_frame) = dst_rx.pop() {
                dst_free.push(rx_frame);
            }
        }
    }

    count
}

/// Drive the handshake to completion, returning the server connection key.
///
/// Calls pump_packets back and forth between client and server until both
/// sides reach Established state (or panics after max_rounds).
fn drive_handshake<'a>(
    client_handler: &mut QuicHandler,
    client_wheel: &mut TimerWheel,
    client_free: &mut BasicFrameBuffer<'a>,
    client_tx: &mut BasicFrameBuffer<'a>,
    client_rx: &mut BasicFrameBuffer<'a>,
    client_nh: &NeighborHandler,
    client_conn_key: usize,
    server_handler: &mut QuicHandler,
    server_wheel: &mut TimerWheel,
    server_free: &mut BasicFrameBuffer<'a>,
    server_tx: &mut BasicFrameBuffer<'a>,
    server_rx: &mut BasicFrameBuffer<'a>,
    server_nh: &NeighborHandler,
    now: Instant,
    max_rounds: usize,
) -> usize {
    for round in 0..max_rounds {
        // Client → Server
        let sent_c2s = pump_packets(
            client_handler,
            client_wheel,
            client_free,
            client_tx,
            server_handler,
            server_wheel,
            server_nh,
            server_free,
            server_rx,
            server_tx,
            now,
        );

        // Server → Client
        let sent_s2c = pump_packets(
            server_handler,
            server_wheel,
            server_free,
            server_tx,
            client_handler,
            client_wheel,
            client_nh,
            client_free,
            client_rx,
            client_tx,
            now,
        );

        // Check if both sides are Established
        let client_state = client_handler.connections[client_conn_key].state;
        let client_established = client_state == ConnectionState::Established;

        let server_established = server_handler
            .connections
            .iter()
            .any(|(_, conn)| conn.state == ConnectionState::Established);

        if client_established && server_established {
            return server_handler
                .connections
                .iter()
                .find(|(_, conn)| conn.state == ConnectionState::Established)
                .map(|(key, _)| key)
                .expect("server should have an established connection");
        }

        if sent_c2s == 0 && sent_s2c == 0 && round > 1 {
            panic!(
                "handshake stalled at round {}: client={:?}, server_conns={}",
                round,
                client_state,
                server_handler.connections.len(),
            );
        }
    }
    panic!("handshake did not complete within {} rounds", max_rounds);
}

// ── Tests ────────────────────────────────────────────────────────────

#[test]
fn e2e_full_lifecycle() {
    let now = Instant::now();

    // ── Set up client ────────────────────────────────────────────────
    let mut client_handler = QuicHandler::new(false, false);
    let mut client_wheel = TimerWheel::new(now);
    let client_nh = NeighborHandler::new("lo", Duration::from_secs(60)).unwrap();
    let mut client_free_backing: Vec<Vec<u8>> = (0..32).map(|_| vec![0u8; 4096]).collect();
    let mut client_free = BasicFrameBuffer::new(32);
    for (i, buf) in client_free_backing.iter_mut().enumerate() {
        let f = Frame::new((i as u64 + 1) * 4096, buf.as_mut_slice(), 1, false);
        client_free.push(f);
    }
    let mut client_rx = BasicFrameBuffer::new(16);
    let mut client_tx = BasicFrameBuffer::new(32);

    let client_conn_key = client_handler
        .initiate_connection(
            IpAddress::V4(Ipv4Address::new(SERVER_IP)),
            QUIC_PORT,
            IpAddress::V4(Ipv4Address::new(CLIENT_IP)),
            CLIENT_PORT,
            MacAddress::new(CLIENT_MAC),
            MacAddress::new(SERVER_MAC),
            "localhost",
            make_client_config(),
            test_transport_params(),
            now,
        )
        .expect("initiate_connection should succeed");

    // ── Set up server ────────────────────────────────────────────────
    let mut server_handler = QuicHandler::new(false, false);
    let mut server_wheel = TimerWheel::new(now);
    let server_nh = NeighborHandler::new("lo", Duration::from_secs(60)).unwrap();
    let mut server_free_backing: Vec<Vec<u8>> = (0..32).map(|_| vec![0u8; 4096]).collect();
    let mut server_free = BasicFrameBuffer::new(32);
    for (i, buf) in server_free_backing.iter_mut().enumerate() {
        let f = Frame::new((i as u64 + 100) * 4096, buf.as_mut_slice(), 1, false);
        server_free.push(f);
    }
    let mut server_rx = BasicFrameBuffer::new(16);
    let mut server_tx = BasicFrameBuffer::new(32);

    server_handler
        .listen(QUIC_PORT, make_server_config(), test_transport_params())
        .expect("listen should succeed");

    // ── Drive handshake to completion ────────────────────────────────
    let server_conn_key = drive_handshake(
        &mut client_handler,
        &mut client_wheel,
        &mut client_free,
        &mut client_tx,
        &mut client_rx,
        &client_nh,
        client_conn_key,
        &mut server_handler,
        &mut server_wheel,
        &mut server_free,
        &mut server_tx,
        &mut server_rx,
        &server_nh,
        now,
        10,
    );

    // Verify both sides are Established
    assert_eq!(
        client_handler.connections[client_conn_key].state,
        ConnectionState::Established,
        "client should be Established"
    );
    assert_eq!(
        server_handler.connections[server_conn_key].state,
        ConnectionState::Established,
        "server should be Established"
    );

    // ── Client: open bidi stream 0 and write "hello" ─────────────────
    let stream_id = StreamId(0x00); // client-initiated bidi stream 0
    {
        let conn = &mut client_handler.connections[client_conn_key];
        let entry = conn
            .streams
            .get_or_create(stream_id)
            .expect("should be able to open stream 0");
        let send = entry
            .send
            .as_mut()
            .expect("bidi stream should have SendHalf");
        let written = send.write(b"hello");
        assert_eq!(written, 5, "should write all 5 bytes");
        conn.streams.pending_send_count += 1;
    }

    // ── Pump client → server ─────────────────────────────────────────
    pump_packets(
        &mut client_handler,
        &mut client_wheel,
        &mut client_free,
        &mut client_tx,
        &mut server_handler,
        &mut server_wheel,
        &server_nh,
        &mut server_free,
        &mut server_rx,
        &mut server_tx,
        now,
    );

    // ── Server: read from stream and verify "hello" ──────────────────
    {
        let conn = &mut server_handler.connections[server_conn_key];
        let entry = conn
            .streams
            .get_mut(stream_id)
            .expect("server should have stream 0 after receiving data");
        let recv = entry
            .recv
            .as_mut()
            .expect("stream 0 should have RecvHalf on server");
        let mut buf = [0u8; 64];
        let n = recv.read(&mut buf);
        assert_eq!(n, 5, "server should read 5 bytes");
        assert_eq!(&buf[..n], b"hello", "server should read 'hello'");
    }

    // ── Server: write "world" back on stream 0 ──────────────────────
    {
        let conn = &mut server_handler.connections[server_conn_key];
        let entry = conn
            .streams
            .get_mut(stream_id)
            .expect("server should have stream 0");
        let send = entry
            .send
            .as_mut()
            .expect("bidi stream should have SendHalf on server");
        let written = send.write(b"world");
        assert_eq!(written, 5, "should write all 5 bytes");
        conn.streams.pending_send_count += 1;
    }

    // ── Pump server → client ─────────────────────────────────────────
    pump_packets(
        &mut server_handler,
        &mut server_wheel,
        &mut server_free,
        &mut server_tx,
        &mut client_handler,
        &mut client_wheel,
        &client_nh,
        &mut client_free,
        &mut client_rx,
        &mut client_tx,
        now,
    );

    // ── Client: read from stream and verify "world" ──────────────────
    {
        let conn = &mut client_handler.connections[client_conn_key];
        let entry = conn
            .streams
            .get_mut(stream_id)
            .expect("client should have stream 0");
        let recv = entry
            .recv
            .as_mut()
            .expect("stream 0 should have RecvHalf on client");
        let mut buf = [0u8; 64];
        let n = recv.read(&mut buf);
        assert_eq!(n, 5, "client should read 5 bytes");
        assert_eq!(&buf[..n], b"world", "client should read 'world'");
    }
}

#[test]
fn e2e_unidirectional_streams() {
    let now = Instant::now();

    // ── Set up client ────────────────────────────────────────────────
    let mut client_handler = QuicHandler::new(false, false);
    let mut client_wheel = TimerWheel::new(now);
    let client_nh = NeighborHandler::new("lo", Duration::from_secs(60)).unwrap();
    let mut client_free_backing: Vec<Vec<u8>> = (0..32).map(|_| vec![0u8; 4096]).collect();
    let mut client_free = BasicFrameBuffer::new(32);
    for (i, buf) in client_free_backing.iter_mut().enumerate() {
        let f = Frame::new((i as u64 + 1) * 4096, buf.as_mut_slice(), 1, false);
        client_free.push(f);
    }
    let mut client_rx = BasicFrameBuffer::new(16);
    let mut client_tx = BasicFrameBuffer::new(32);

    let client_conn_key = client_handler
        .initiate_connection(
            IpAddress::V4(Ipv4Address::new(SERVER_IP)),
            QUIC_PORT,
            IpAddress::V4(Ipv4Address::new(CLIENT_IP)),
            CLIENT_PORT,
            MacAddress::new(CLIENT_MAC),
            MacAddress::new(SERVER_MAC),
            "localhost",
            make_client_config(),
            test_transport_params(),
            now,
        )
        .expect("initiate_connection should succeed");

    // ── Set up server ────────────────────────────────────────────────
    let mut server_handler = QuicHandler::new(false, false);
    let mut server_wheel = TimerWheel::new(now);
    let server_nh = NeighborHandler::new("lo", Duration::from_secs(60)).unwrap();
    let mut server_free_backing: Vec<Vec<u8>> = (0..32).map(|_| vec![0u8; 4096]).collect();
    let mut server_free = BasicFrameBuffer::new(32);
    for (i, buf) in server_free_backing.iter_mut().enumerate() {
        let f = Frame::new((i as u64 + 100) * 4096, buf.as_mut_slice(), 1, false);
        server_free.push(f);
    }
    let mut server_rx = BasicFrameBuffer::new(16);
    let mut server_tx = BasicFrameBuffer::new(32);

    server_handler
        .listen(QUIC_PORT, make_server_config(), test_transport_params())
        .expect("listen should succeed");

    // ── Drive handshake to completion ────────────────────────────────
    let server_conn_key = drive_handshake(
        &mut client_handler,
        &mut client_wheel,
        &mut client_free,
        &mut client_tx,
        &mut client_rx,
        &client_nh,
        client_conn_key,
        &mut server_handler,
        &mut server_wheel,
        &mut server_free,
        &mut server_tx,
        &mut server_rx,
        &server_nh,
        now,
        10,
    );

    // ── Client: open uni stream 0x02 and write data ──────────────────
    let client_uni_id = StreamId(0x02); // first client-initiated uni stream
    {
        let conn = &mut client_handler.connections[client_conn_key];
        let entry = conn
            .streams
            .get_or_create(client_uni_id)
            .expect("should be able to open client uni stream 0x02");
        assert!(
            entry.send.is_some(),
            "initiator of uni stream should have SendHalf"
        );
        assert!(
            entry.recv.is_none(),
            "initiator of uni stream should NOT have RecvHalf"
        );
        let send = entry.send.as_mut().unwrap();
        let written = send.write(b"client-uni-data");
        assert_eq!(written, 15, "should write all 15 bytes");
        conn.streams.pending_send_count += 1;
    }

    // Pump client → server (data), then server → client (ACKs)
    pump_packets(
        &mut client_handler,
        &mut client_wheel,
        &mut client_free,
        &mut client_tx,
        &mut server_handler,
        &mut server_wheel,
        &server_nh,
        &mut server_free,
        &mut server_rx,
        &mut server_tx,
        now,
    );
    pump_packets(
        &mut server_handler,
        &mut server_wheel,
        &mut server_free,
        &mut server_tx,
        &mut client_handler,
        &mut client_wheel,
        &client_nh,
        &mut client_free,
        &mut client_rx,
        &mut client_tx,
        now,
    );

    // ── Server: read from client's uni stream ────────────────────────
    {
        let conn = &mut server_handler.connections[server_conn_key];
        let entry = conn
            .streams
            .get_mut(client_uni_id)
            .expect("server should have client uni stream 0x02 after receiving data");
        assert!(
            entry.send.is_none(),
            "receiver of uni stream should NOT have SendHalf"
        );
        assert!(
            entry.recv.is_some(),
            "receiver of uni stream should have RecvHalf"
        );
        let recv = entry.recv.as_mut().unwrap();
        let mut buf = [0u8; 64];
        let n = recv.read(&mut buf);
        assert_eq!(n, 15, "server should read 15 bytes from client uni stream");
        assert_eq!(
            &buf[..n],
            b"client-uni-data",
            "server should read 'client-uni-data'"
        );
    }

    // ── Server: open uni stream 0x03 and write data ──────────────────
    let server_uni_id = StreamId(0x03); // first server-initiated uni stream
    {
        let conn = &mut server_handler.connections[server_conn_key];
        let entry = conn
            .streams
            .get_or_create(server_uni_id)
            .expect("should be able to open server uni stream 0x03");
        assert!(
            entry.send.is_some(),
            "initiator of uni stream should have SendHalf"
        );
        assert!(
            entry.recv.is_none(),
            "initiator of uni stream should NOT have RecvHalf"
        );
        let send = entry.send.as_mut().unwrap();
        let written = send.write(b"server-uni-data");
        assert_eq!(written, 15, "should write all 15 bytes");
        conn.streams.pending_send_count += 1;
    }

    // Pump server → client (data), then client → server (ACKs)
    pump_packets(
        &mut server_handler,
        &mut server_wheel,
        &mut server_free,
        &mut server_tx,
        &mut client_handler,
        &mut client_wheel,
        &client_nh,
        &mut client_free,
        &mut client_rx,
        &mut client_tx,
        now,
    );
    pump_packets(
        &mut client_handler,
        &mut client_wheel,
        &mut client_free,
        &mut client_tx,
        &mut server_handler,
        &mut server_wheel,
        &server_nh,
        &mut server_free,
        &mut server_rx,
        &mut server_tx,
        now,
    );

    // ── Client: read from server's uni stream ────────────────────────
    {
        let conn = &mut client_handler.connections[client_conn_key];
        let entry = conn
            .streams
            .get_mut(server_uni_id)
            .expect("client should have server uni stream 0x03 after receiving data");
        assert!(
            entry.send.is_none(),
            "receiver of uni stream should NOT have SendHalf"
        );
        assert!(
            entry.recv.is_some(),
            "receiver of uni stream should have RecvHalf"
        );
        let recv = entry.recv.as_mut().unwrap();
        let mut buf = [0u8; 64];
        let n = recv.read(&mut buf);
        assert_eq!(n, 15, "client should read 15 bytes from server uni stream");
        assert_eq!(
            &buf[..n],
            b"server-uni-data",
            "client should read 'server-uni-data'"
        );
    }
}

#[test]
fn e2e_concurrent_streams() {
    let now = Instant::now();

    // ── Set up client ────────────────────────────────────────────────
    let mut client_handler = QuicHandler::new(false, false);
    let mut client_wheel = TimerWheel::new(now);
    let client_nh = NeighborHandler::new("lo", Duration::from_secs(60)).unwrap();
    let mut client_free_backing: Vec<Vec<u8>> = (0..64).map(|_| vec![0u8; 4096]).collect();
    let mut client_free = BasicFrameBuffer::new(64);
    for (i, buf) in client_free_backing.iter_mut().enumerate() {
        let f = Frame::new((i as u64 + 1) * 4096, buf.as_mut_slice(), 1, false);
        client_free.push(f);
    }
    let mut client_rx = BasicFrameBuffer::new(16);
    let mut client_tx = BasicFrameBuffer::new(64);

    let client_conn_key = client_handler
        .initiate_connection(
            IpAddress::V4(Ipv4Address::new(SERVER_IP)),
            QUIC_PORT,
            IpAddress::V4(Ipv4Address::new(CLIENT_IP)),
            CLIENT_PORT,
            MacAddress::new(CLIENT_MAC),
            MacAddress::new(SERVER_MAC),
            "localhost",
            make_client_config(),
            test_transport_params(),
            now,
        )
        .expect("initiate_connection should succeed");

    // ── Set up server ────────────────────────────────────────────────
    let mut server_handler = QuicHandler::new(false, false);
    let mut server_wheel = TimerWheel::new(now);
    let server_nh = NeighborHandler::new("lo", Duration::from_secs(60)).unwrap();
    let mut server_free_backing: Vec<Vec<u8>> = (0..64).map(|_| vec![0u8; 4096]).collect();
    let mut server_free = BasicFrameBuffer::new(64);
    for (i, buf) in server_free_backing.iter_mut().enumerate() {
        let f = Frame::new((i as u64 + 100) * 4096, buf.as_mut_slice(), 1, false);
        server_free.push(f);
    }
    let mut server_rx = BasicFrameBuffer::new(16);
    let mut server_tx = BasicFrameBuffer::new(64);

    server_handler
        .listen(QUIC_PORT, make_server_config(), test_transport_params())
        .expect("listen should succeed");

    // ── Drive handshake to completion ────────────────────────────────
    let server_conn_key = drive_handshake(
        &mut client_handler,
        &mut client_wheel,
        &mut client_free,
        &mut client_tx,
        &mut client_rx,
        &client_nh,
        client_conn_key,
        &mut server_handler,
        &mut server_wheel,
        &mut server_free,
        &mut server_tx,
        &mut server_rx,
        &server_nh,
        now,
        10,
    );

    // ── Client: open 8 bidi streams and write distinct data ──────────
    let num_streams = 8;
    let stream_ids: Vec<StreamId> = (0..num_streams)
        .map(|n| StreamId(4 * n as u64)) // 0x00, 0x04, 0x08, ...
        .collect();

    for (i, &sid) in stream_ids.iter().enumerate() {
        let conn = &mut client_handler.connections[client_conn_key];
        let entry = conn
            .streams
            .get_or_create(sid)
            .unwrap_or_else(|_| panic!("should be able to open stream {:?}", sid));
        let send = entry
            .send
            .as_mut()
            .expect("bidi stream should have SendHalf");
        let data = format!("stream-{}", i);
        let written = send.write(data.as_bytes());
        assert_eq!(
            written,
            data.len(),
            "should write all bytes for stream {}",
            i
        );
        conn.streams.pending_send_count += 1;
    }

    // ── Pump packets back and forth several times ────────────────────
    // Multiple rounds to handle flow control, ACKs, and potential
    // packet size limits with 8 concurrent streams.
    for _ in 0..4 {
        pump_packets(
            &mut client_handler,
            &mut client_wheel,
            &mut client_free,
            &mut client_tx,
            &mut server_handler,
            &mut server_wheel,
            &server_nh,
            &mut server_free,
            &mut server_rx,
            &mut server_tx,
            now,
        );
        pump_packets(
            &mut server_handler,
            &mut server_wheel,
            &mut server_free,
            &mut server_tx,
            &mut client_handler,
            &mut client_wheel,
            &client_nh,
            &mut client_free,
            &mut client_rx,
            &mut client_tx,
            now,
        );
    }

    // ── Server: read from each stream and verify ─────────────────────
    for (i, &sid) in stream_ids.iter().enumerate() {
        let conn = &mut server_handler.connections[server_conn_key];
        let entry = conn
            .streams
            .get_mut(sid)
            .unwrap_or_else(|| panic!("server should have stream {:?}", sid));
        let recv = entry
            .recv
            .as_mut()
            .expect("bidi stream should have RecvHalf on server");
        let mut buf = [0u8; 64];
        let n = recv.read(&mut buf);
        let expected = format!("stream-{}", i);
        assert_eq!(
            n,
            expected.len(),
            "server should read {} bytes from stream {}",
            expected.len(),
            i
        );
        assert_eq!(
            &buf[..n],
            expected.as_bytes(),
            "server should read '{}' from stream {}",
            expected,
            i
        );
    }

    // ── Server: respond on each stream with distinct data ────────────
    for (i, &sid) in stream_ids.iter().enumerate() {
        let conn = &mut server_handler.connections[server_conn_key];
        let entry = conn
            .streams
            .get_mut(sid)
            .unwrap_or_else(|| panic!("server should have stream {:?}", sid));
        let send = entry
            .send
            .as_mut()
            .expect("bidi stream should have SendHalf on server");
        let data = format!("reply-{}", i);
        let written = send.write(data.as_bytes());
        assert_eq!(
            written,
            data.len(),
            "should write all bytes for reply {}",
            i
        );
        conn.streams.pending_send_count += 1;
    }

    // ── Pump packets back and forth to deliver responses ─────────────
    for _ in 0..4 {
        pump_packets(
            &mut server_handler,
            &mut server_wheel,
            &mut server_free,
            &mut server_tx,
            &mut client_handler,
            &mut client_wheel,
            &client_nh,
            &mut client_free,
            &mut client_rx,
            &mut client_tx,
            now,
        );
        pump_packets(
            &mut client_handler,
            &mut client_wheel,
            &mut client_free,
            &mut client_tx,
            &mut server_handler,
            &mut server_wheel,
            &server_nh,
            &mut server_free,
            &mut server_rx,
            &mut server_tx,
            now,
        );
    }

    // ── Client: read all responses and verify ────────────────────────
    for (i, &sid) in stream_ids.iter().enumerate() {
        let conn = &mut client_handler.connections[client_conn_key];
        let entry = conn
            .streams
            .get_mut(sid)
            .unwrap_or_else(|| panic!("client should have stream {:?}", sid));
        let recv = entry
            .recv
            .as_mut()
            .expect("bidi stream should have RecvHalf on client");
        let mut buf = [0u8; 64];
        let n = recv.read(&mut buf);
        let expected = format!("reply-{}", i);
        assert_eq!(
            n,
            expected.len(),
            "client should read {} bytes from stream {} reply",
            expected.len(),
            i
        );
        assert_eq!(
            &buf[..n],
            expected.as_bytes(),
            "client should read '{}' from stream {} reply",
            expected,
            i
        );
    }
}
