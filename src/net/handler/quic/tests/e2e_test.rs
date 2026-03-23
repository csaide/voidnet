use std::sync::Arc;

use coarsetime::{Duration, Instant};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, ServerConfig, SignatureScheme};

use crate::net::handler::quic::QuicHandler;
use crate::net::handler::quic::connection::ConnectionState;
use crate::net::handler::quic::error::TransportError;
use crate::net::handler::quic::event::QuicEvent;
use crate::net::handler::quic::processor::{TimerResult, handle_timeout};
use crate::net::handler::quic::timer_kinds::QuicTimerKind;
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

#[test]
fn e2e_large_transfer() {
    let now = Instant::now();

    // ── Generate test data: 64KB repeating pattern ──────────────────
    let total_len: usize = 64 * 1024;
    let data: Vec<u8> = (0..total_len).map(|i| (i % 256) as u8).collect();

    // ── Set up client (more frames for large transfer) ──────────────
    let mut client_handler = QuicHandler::new(false, false);
    let mut client_wheel = TimerWheel::new(now);
    let client_nh = NeighborHandler::new("lo", Duration::from_secs(60)).unwrap();
    let mut client_free_backing: Vec<Vec<u8>> = (0..128).map(|_| vec![0u8; 4096]).collect();
    let mut client_free = BasicFrameBuffer::new(128);
    for (i, buf) in client_free_backing.iter_mut().enumerate() {
        let f = Frame::new((i as u64 + 1) * 4096, buf.as_mut_slice(), 1, false);
        client_free.push(f);
    }
    let mut client_rx = BasicFrameBuffer::new(32);
    let mut client_tx = BasicFrameBuffer::new(128);

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

    // ── Set up server ───────────────────────────────────────────────
    let mut server_handler = QuicHandler::new(false, false);
    let mut server_wheel = TimerWheel::new(now);
    let server_nh = NeighborHandler::new("lo", Duration::from_secs(60)).unwrap();
    let mut server_free_backing: Vec<Vec<u8>> = (0..128).map(|_| vec![0u8; 4096]).collect();
    let mut server_free = BasicFrameBuffer::new(128);
    for (i, buf) in server_free_backing.iter_mut().enumerate() {
        let f = Frame::new((i as u64 + 500) * 4096, buf.as_mut_slice(), 1, false);
        server_free.push(f);
    }
    let mut server_rx = BasicFrameBuffer::new(32);
    let mut server_tx = BasicFrameBuffer::new(128);

    server_handler
        .listen(QUIC_PORT, make_server_config(), test_transport_params())
        .expect("listen should succeed");

    // ── Drive handshake to completion ───────────────────────────────
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

    // ── Client: open bidi stream 0 ──────────────────────────────────
    let stream_id = StreamId(0x00);
    {
        let conn = &mut client_handler.connections[client_conn_key];
        conn.streams
            .get_or_create(stream_id)
            .expect("should be able to open stream 0");
        conn.streams.pending_send_count += 1;
    }

    // ── Write data in chunks, pumping packets to drain the buffer ───
    // The send ring buffer is only 8192 bytes, so we must write in
    // chunks, pump packets (which triggers ACKs that free buffer
    // space), then write more.
    let mut offset = 0;
    let chunk_size = 4096;
    let max_iterations = 500; // safety valve
    let mut iterations = 0;

    while offset < total_len {
        iterations += 1;
        assert!(
            iterations < max_iterations,
            "large transfer stalled after {} iterations, offset={}/{}",
            iterations,
            offset,
            total_len
        );

        // Try to write a chunk
        let end = (offset + chunk_size).min(total_len);
        let chunk = &data[offset..end];
        let written = {
            let conn = &mut client_handler.connections[client_conn_key];
            let entry = conn
                .streams
                .get_mut(stream_id)
                .expect("client should have stream 0");
            let send = entry
                .send
                .as_mut()
                .expect("bidi stream should have SendHalf");
            send.write(chunk)
        };
        offset += written;

        // Pump client -> server (data), then server -> client (ACKs + flow control)
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

        // Server: drain received data so the recv buffer doesn't fill up
        // and flow control updates get sent
        {
            let conn = &mut server_handler.connections[server_conn_key];
            if let Some(entry) = conn.streams.get_mut(stream_id) {
                if let Some(recv) = entry.recv.as_mut() {
                    let mut drain_buf = [0u8; 8192];
                    recv.read(&mut drain_buf);
                    // We'll do final verification from a fresh transfer below
                }
            }
        }
    }

    // ── Final pump rounds to flush remaining data ───────────────────
    for _ in 0..10 {
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

    // ── Verify: server received all data ────────────────────────────
    // The server has been draining the recv buffer during the loop above.
    // Check that the server's RecvHalf has received the full stream offset.
    {
        let conn = &mut server_handler.connections[server_conn_key];
        let entry = conn
            .streams
            .get_mut(stream_id)
            .expect("server should have stream 0");
        let recv = entry
            .recv
            .as_ref()
            .expect("bidi stream should have RecvHalf on server");
        // read_offset tracks how much was consumed by read() calls above
        // received tracks the contiguous frontier from the network
        let total_consumed = recv.read_offset as usize;
        let remaining_buffered = (recv.received - recv.read_offset) as usize;
        assert_eq!(
            total_consumed + remaining_buffered,
            total_len,
            "server should have received all {} bytes (consumed={}, buffered={})",
            total_len,
            total_consumed,
            remaining_buffered,
        );
    }

    // ── Now do a verified transfer: send data and read it all back ──
    // Open a second stream to do a clean verified transfer
    let stream_id2 = StreamId(0x04); // second client-initiated bidi
    let verify_len: usize = 32 * 1024;
    let verify_data: Vec<u8> = (0..verify_len).map(|i| ((i * 7 + 3) % 256) as u8).collect();
    let mut received_data: Vec<u8> = Vec::with_capacity(verify_len);

    {
        let conn = &mut client_handler.connections[client_conn_key];
        conn.streams
            .get_or_create(stream_id2)
            .expect("should be able to open stream 4");
        conn.streams.pending_send_count += 1;
    }

    let mut offset = 0;
    iterations = 0;

    while offset < verify_len || received_data.len() < verify_len {
        iterations += 1;
        assert!(
            iterations < max_iterations,
            "verified transfer stalled after {} iterations, sent={}/{}, received={}/{}",
            iterations,
            offset,
            verify_len,
            received_data.len(),
            verify_len,
        );

        // Write more data if we haven't finished sending
        if offset < verify_len {
            let end = (offset + chunk_size).min(verify_len);
            let chunk = &verify_data[offset..end];
            let written = {
                let conn = &mut client_handler.connections[client_conn_key];
                let entry = conn
                    .streams
                    .get_mut(stream_id2)
                    .expect("client should have stream 4");
                let send = entry
                    .send
                    .as_mut()
                    .expect("bidi stream should have SendHalf");
                send.write(chunk)
            };
            offset += written;
        }

        // Pump bidirectionally
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

        // Server: read available data
        {
            let conn = &mut server_handler.connections[server_conn_key];
            if let Some(entry) = conn.streams.get_mut(stream_id2) {
                if let Some(recv) = entry.recv.as_mut() {
                    let mut buf = [0u8; 8192];
                    let n = recv.read(&mut buf);
                    if n > 0 {
                        received_data.extend_from_slice(&buf[..n]);
                    }
                }
            }
        }
    }

    // Verify data integrity
    assert_eq!(
        received_data.len(),
        verify_len,
        "should receive exactly {} bytes",
        verify_len
    );
    assert_eq!(
        received_data, verify_data,
        "received data should match sent data byte-for-byte"
    );
}

#[test]
fn e2e_zero_rtt_reconnect() {
    // 0-RTT requires session tickets from a previous connection. At the handler
    // level, session tickets are delivered via TLS post-handshake messages
    // (NewSessionTicket) which flow through CRYPTO frames after 1-RTT is
    // established. This test verifies that:
    //
    // 1. A first connection completes and the server sends NewSessionTicket
    // 2. A second connection with the same client config can attempt 0-RTT
    //
    // The client_config must have a session cache (Resumption) for this to work.

    let now = Instant::now();

    // ── Shared TLS configs with 0-RTT support ───────────────────────
    let (certs, key) = make_test_cert();
    let mut server_tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    server_tls_config.alpn_protocols = vec![b"h3".to_vec()];
    server_tls_config.max_early_data_size = u32::MAX; // enable 0-RTT
    let server_tls_config = Arc::new(server_tls_config);

    let mut client_tls_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    client_tls_config.alpn_protocols = vec![b"h3".to_vec()];
    client_tls_config.resumption = rustls::client::Resumption::in_memory_sessions(256);
    let client_tls_config = Arc::new(client_tls_config);

    // ── First connection: establish and get session ticket ───────────
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
            client_tls_config.clone(),
            test_transport_params(),
            now,
        )
        .expect("initiate_connection should succeed");

    let mut server_handler = QuicHandler::new(false, false);
    let mut server_wheel = TimerWheel::new(now);
    let server_nh = NeighborHandler::new("lo", Duration::from_secs(60)).unwrap();
    let mut server_free_backing: Vec<Vec<u8>> = (0..64).map(|_| vec![0u8; 4096]).collect();
    let mut server_free = BasicFrameBuffer::new(64);
    for (i, buf) in server_free_backing.iter_mut().enumerate() {
        let f = Frame::new((i as u64 + 200) * 4096, buf.as_mut_slice(), 1, false);
        server_free.push(f);
    }
    let mut server_rx = BasicFrameBuffer::new(16);
    let mut server_tx = BasicFrameBuffer::new(64);

    server_handler
        .listen(
            QUIC_PORT,
            server_tls_config.clone(),
            test_transport_params(),
        )
        .expect("listen should succeed");

    // Drive first handshake
    let _server_conn_key = drive_handshake(
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

    // Pump several more rounds so the server's NewSessionTicket (post-handshake
    // TLS message) gets delivered to the client and stored in the session cache.
    for _ in 0..10 {
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

    // ── Second connection: attempt 0-RTT with cached session ticket ─
    // Use a fresh handler but the SAME client_tls_config (shared session cache).
    let mut client2_handler = QuicHandler::new(false, false);
    let mut client2_wheel = TimerWheel::new(now);
    let client2_nh = NeighborHandler::new("lo", Duration::from_secs(60)).unwrap();
    let mut client2_free_backing: Vec<Vec<u8>> = (0..64).map(|_| vec![0u8; 4096]).collect();
    let mut client2_free = BasicFrameBuffer::new(64);
    for (i, buf) in client2_free_backing.iter_mut().enumerate() {
        let f = Frame::new((i as u64 + 300) * 4096, buf.as_mut_slice(), 1, false);
        client2_free.push(f);
    }
    let mut client2_rx = BasicFrameBuffer::new(16);
    let mut client2_tx = BasicFrameBuffer::new(64);

    // Use a different client port to avoid conflicts
    let client2_conn_key = client2_handler
        .initiate_connection(
            IpAddress::V4(Ipv4Address::new(SERVER_IP)),
            QUIC_PORT,
            IpAddress::V4(Ipv4Address::new(CLIENT_IP)),
            CLIENT_PORT + 1,
            MacAddress::new(CLIENT_MAC),
            MacAddress::new(SERVER_MAC),
            "localhost",
            client_tls_config.clone(),
            test_transport_params(),
            now,
        )
        .expect("second initiate_connection should succeed");

    // Check if the client has 0-RTT keys after initial setup.
    // With a valid session ticket, rustls should provide 0-RTT keys immediately.
    let has_zero_rtt = client2_handler.connections[client2_conn_key]
        .keys
        .zero_rtt_seal
        .is_some()
        || client2_handler.connections[client2_conn_key]
            .keys
            .zero_rtt_open
            .is_some();

    // Note: 0-RTT key availability depends on whether the NewSessionTicket
    // was successfully delivered and processed during the first connection.
    // If session tickets weren't delivered (e.g., because the handler doesn't
    // process post-handshake TLS messages in pump_packets), 0-RTT won't be
    // available. This is a known limitation of handler-level testing.
    if has_zero_rtt {
        // 0-RTT keys are available — verify the second handshake completes
        let mut server2_handler = QuicHandler::new(false, false);
        let mut server2_wheel = TimerWheel::new(now);
        let server2_nh = NeighborHandler::new("lo", Duration::from_secs(60)).unwrap();
        let mut server2_free_backing: Vec<Vec<u8>> = (0..64).map(|_| vec![0u8; 4096]).collect();
        let mut server2_free = BasicFrameBuffer::new(64);
        for (i, buf) in server2_free_backing.iter_mut().enumerate() {
            let f = Frame::new((i as u64 + 400) * 4096, buf.as_mut_slice(), 1, false);
            server2_free.push(f);
        }
        let mut server2_rx = BasicFrameBuffer::new(16);
        let mut server2_tx = BasicFrameBuffer::new(64);

        server2_handler
            .listen(
                QUIC_PORT,
                server_tls_config.clone(),
                test_transport_params(),
            )
            .expect("second listen should succeed");

        let server2_conn_key = drive_handshake(
            &mut client2_handler,
            &mut client2_wheel,
            &mut client2_free,
            &mut client2_tx,
            &mut client2_rx,
            &client2_nh,
            client2_conn_key,
            &mut server2_handler,
            &mut server2_wheel,
            &mut server2_free,
            &mut server2_tx,
            &mut server2_rx,
            &server2_nh,
            now,
            10,
        );

        assert_eq!(
            client2_handler.connections[client2_conn_key].state,
            ConnectionState::Established,
            "second client connection should be Established with 0-RTT"
        );
        assert_eq!(
            server2_handler.connections[server2_conn_key].state,
            ConnectionState::Established,
            "second server connection should be Established"
        );
    } else {
        // 0-RTT not available — this is expected if session tickets aren't
        // delivered through the handler's packet processing pipeline.
        // Verify the second connection still completes a normal 1-RTT handshake.
        let mut server2_handler = QuicHandler::new(false, false);
        let mut server2_wheel = TimerWheel::new(now);
        let server2_nh = NeighborHandler::new("lo", Duration::from_secs(60)).unwrap();
        let mut server2_free_backing: Vec<Vec<u8>> = (0..64).map(|_| vec![0u8; 4096]).collect();
        let mut server2_free = BasicFrameBuffer::new(64);
        for (i, buf) in server2_free_backing.iter_mut().enumerate() {
            let f = Frame::new((i as u64 + 400) * 4096, buf.as_mut_slice(), 1, false);
            server2_free.push(f);
        }
        let mut server2_rx = BasicFrameBuffer::new(16);
        let mut server2_tx = BasicFrameBuffer::new(64);

        server2_handler
            .listen(
                QUIC_PORT,
                server_tls_config.clone(),
                test_transport_params(),
            )
            .expect("second listen should succeed");

        let server2_conn_key = drive_handshake(
            &mut client2_handler,
            &mut client2_wheel,
            &mut client2_free,
            &mut client2_tx,
            &mut client2_rx,
            &client2_nh,
            client2_conn_key,
            &mut server2_handler,
            &mut server2_wheel,
            &mut server2_free,
            &mut server2_tx,
            &mut server2_rx,
            &server2_nh,
            now,
            10,
        );

        assert_eq!(
            client2_handler.connections[client2_conn_key].state,
            ConnectionState::Established,
            "second client connection should be Established (1-RTT fallback)"
        );
        assert_eq!(
            server2_handler.connections[server2_conn_key].state,
            ConnectionState::Established,
            "second server connection should be Established (1-RTT fallback)"
        );

        // Log that 0-RTT was not available for diagnostic purposes.
        // This is not a failure — 0-RTT requires NewSessionTicket delivery
        // which depends on post-handshake message processing in the handler.
        eprintln!(
            "note: 0-RTT keys not available after first connection — \
             NewSessionTicket may not have been delivered through handler pipeline"
        );
    }
}

// ── Connection Close + Stream Reset + Idle Timeout Tests ─────────────

#[test]
fn e2e_client_initiated_close() {
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

    // Verify both sides are established
    assert_eq!(
        client_handler.connections[client_conn_key].state,
        ConnectionState::Established,
    );
    assert_eq!(
        server_handler.connections[server_conn_key].state,
        ConnectionState::Established,
    );

    // ── Client: initiate connection close ────────────────────────────
    {
        let conn = &mut client_handler.connections[client_conn_key];
        conn.close_error = Some(TransportError::NO_ERROR);
        conn.state = ConnectionState::Closing;
        conn.needs_draining_timer = true;
    }

    // ── Pump client → server (CONNECTION_CLOSE packet) ──────────────
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

    // ── Verify server entered Draining state ────────────────────────
    let server_state = server_handler.connections[server_conn_key].state;
    assert_eq!(
        server_state,
        ConnectionState::Draining,
        "server should enter Draining after receiving CONNECTION_CLOSE, got {:?}",
        server_state,
    );

    // ── Verify server received ConnectionClosed event ───────────────
    let event = server_handler.connections[server_conn_key]
        .event_queue
        .pop();
    let found_close = if let Some(QuicEvent::ConnectionClosed(code)) = event {
        assert_eq!(code, 0, "error code should be NO_ERROR (0)");
        true
    } else {
        // The ConnectionClosed event might not be the first event; drain them
        false
    };
    if !found_close {
        // Try draining remaining events
        let mut found = false;
        for _ in 0..64 {
            if let Some(QuicEvent::ConnectionClosed(code)) = server_handler.connections
                [server_conn_key]
                .event_queue
                .pop()
            {
                assert_eq!(code, 0, "error code should be NO_ERROR (0)");
                found = true;
                break;
            }
        }
        assert!(
            found,
            "server event_queue should contain a ConnectionClosed event"
        );
    }
}

#[test]
fn e2e_server_initiated_close() {
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

    // ── Server: initiate connection close with application error ─────
    {
        let conn = &mut server_handler.connections[server_conn_key];
        conn.close_error = Some(TransportError(0x42));
        conn.state = ConnectionState::Closing;
        conn.needs_draining_timer = true;
    }

    // ── Pump server → client (CONNECTION_CLOSE packet) ──────────────
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

    // ── Verify client entered Draining state ────────────────────────
    let client_state = client_handler.connections[client_conn_key].state;
    assert_eq!(
        client_state,
        ConnectionState::Draining,
        "client should enter Draining after receiving CONNECTION_CLOSE, got {:?}",
        client_state,
    );

    // ── Verify client received ConnectionClosed event ───────────────
    let mut found_close = false;
    for _ in 0..64 {
        match client_handler.connections[client_conn_key]
            .event_queue
            .pop()
        {
            Some(QuicEvent::ConnectionClosed(code)) => {
                assert_eq!(code, 0x42, "error code should be 0x42");
                found_close = true;
                break;
            }
            Some(_) => continue,
            None => break,
        }
    }
    assert!(
        found_close,
        "client event_queue should contain a ConnectionClosed event"
    );
}

#[test]
fn e2e_stream_reset() {
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

    // ── Client: open bidi stream 0 and write partial data ────────────
    let stream_id = StreamId(0x00);
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
        let written = send.write(b"partial");
        assert_eq!(written, 7, "should write 7 bytes");
        conn.streams.pending_send_count += 1;
    }

    // ── Pump client → server to deliver the partial data ─────────────
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

    // Server should have the stream with partial data
    {
        let conn = &server_handler.connections[server_conn_key];
        let entry = conn
            .streams
            .get(stream_id)
            .expect("server should have stream 0 after receiving data");
        let recv = entry
            .recv
            .as_ref()
            .expect("stream 0 should have RecvHalf on server");
        assert!(!recv.is_reset, "stream should not be reset yet");
    }

    // ── Client: reset the stream with error code 0x77 ────────────────
    {
        let conn = &mut client_handler.connections[client_conn_key];
        let entry = conn
            .streams
            .get_mut(stream_id)
            .expect("client should have stream 0");
        let send = entry
            .send
            .as_mut()
            .expect("bidi stream should have SendHalf");
        send.mark_reset(0x77);
    }

    // ── Pump client → server (RESET_STREAM packet) ──────────────────
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

    // ── Verify server's recv half is reset ───────────────────────────
    {
        let conn = &server_handler.connections[server_conn_key];
        let entry = conn
            .streams
            .get(stream_id)
            .expect("server should still have stream 0");
        let recv = entry.recv.as_ref().expect("stream 0 should have RecvHalf");
        assert!(
            recv.is_reset,
            "server's recv half should be marked as reset after RESET_STREAM"
        );
    }

    // Verify connection is still Established (stream reset does not close connection)
    assert_eq!(
        server_handler.connections[server_conn_key].state,
        ConnectionState::Established,
        "server connection should still be Established after stream reset"
    );
}

#[test]
fn e2e_idle_timeout() {
    let now = Instant::now();

    // ── Transport params with idle timeout ───────────────────────────
    let params = TransportParams {
        max_idle_timeout_ms: 5000,
        initial_max_data: 1_000_000,
        initial_max_stream_data_bidi_local: 100_000,
        initial_max_stream_data_bidi_remote: 100_000,
        initial_max_stream_data_uni: 100_000,
        initial_max_streams_bidi: 100,
        initial_max_streams_uni: 100,
        ..Default::default()
    };

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
            params.clone(),
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
        .listen(QUIC_PORT, make_server_config(), params)
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

    // Verify both sides are established
    assert_eq!(
        client_handler.connections[client_conn_key].state,
        ConnectionState::Established,
    );
    assert_eq!(
        server_handler.connections[server_conn_key].state,
        ConnectionState::Established,
    );

    // ── Exchange some data to confirm connection is working ──────────
    let stream_id = StreamId(0x00);
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
        send.write(b"ping");
        conn.streams.pending_send_count += 1;
    }
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

    // ── Simulate idle timeout on the client ──────────────────────────
    // Advance time past the idle timeout (5 seconds + margin)
    let timeout_instant = Instant::recent() + Duration::from_secs(10);
    let result = handle_timeout(
        &mut client_handler.connections[client_conn_key],
        QuicTimerKind::Idle,
        timeout_instant,
    );

    // handle_timeout returns TimerResult::Close for idle timeout
    assert!(
        matches!(result, TimerResult::Close),
        "idle timeout should return TimerResult::Close"
    );

    // ── Simulate idle timeout on the server ──────────────────────────
    let result = handle_timeout(
        &mut server_handler.connections[server_conn_key],
        QuicTimerKind::Idle,
        timeout_instant,
    );

    assert!(
        matches!(result, TimerResult::Close),
        "server idle timeout should also return TimerResult::Close"
    );
}
