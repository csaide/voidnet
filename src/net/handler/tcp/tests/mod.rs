use crate::{
    net::{
        NeighborHandler,
        checksum::{compute_ipv4_checksum, compute_tcp_checksum},
        wire::{
            ethernet::MacAddress,
            ip::{IPV4_MIN_HEADER_LEN, IpAddress, IpProtocols, Ipv4Address},
            tcp::{TCP_HEADER_LEN, TcpHeader, flags},
        },
    },
    xdp::frame::{BasicFrameBuffer, Frame},
};

use super::*;
use super::inbound::is_segment_acceptable;
use super::state::TcpState;
use super::tcb::{ConnectionId, DEFAULT_RCV_WSCALE, TcpConfig, TcpEvent};

use crate::xdp::frame::FrameBuffer;

pub(super) const LOCAL_IP: Ipv4Address = Ipv4Address::new([10, 0, 0, 1]);
pub(super) const REMOTE_IP: Ipv4Address = Ipv4Address::new([10, 0, 0, 2]);
pub(super) const ETH_HEADER_LEN: usize = 14;

pub(super) fn new_handler() -> TcpHandler {
    TcpHandler::new(false, false)
}

pub(super) fn new_neighbor_handler() -> NeighborHandler {
    NeighborHandler::new("test0", coarsetime::Duration::from_secs(60)).unwrap()
}

/// Build a valid Ethernet + IPv4 + TCP frame.
pub(super) fn build_tcp_frame(
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    tcp_flags: u8,
    window: u16,
    tcp_options: &[u8],
) -> Vec<u8> {
    let opt_padded_len = (tcp_options.len() + 3) & !3;
    let tcp_header_len = TCP_HEADER_LEN + opt_padded_len;
    let data_offset = (tcp_header_len / 4) as u8;
    let total_ip_len = (IPV4_MIN_HEADER_LEN + tcp_header_len) as u16;
    let mut buf = vec![0u8; ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + tcp_header_len];

    // Ethernet header.
    buf[0..6].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // dst mac
    buf[6..12].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // src mac
    buf[12] = 0x08;
    buf[13] = 0x00;

    // IPv4 header.
    let ip = &mut buf[ETH_HEADER_LEN..];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&total_ip_len.to_be_bytes());
    ip[6] = 0x40;
    ip[8] = 64;
    ip[9] = IpProtocols::Tcp;
    let src_bytes: [u8; 4] = src_ip.into();
    ip[12..16].copy_from_slice(&src_bytes);
    let dst_bytes: [u8; 4] = dst_ip.into();
    ip[16..20].copy_from_slice(&dst_bytes);
    let cksum = compute_ipv4_checksum(&ip[..20]);
    ip[10] = cksum[0];
    ip[11] = cksum[1];

    // TCP header.
    let tcp_off = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
    let hdr = TcpHeader::new(
        src_port,
        dst_port,
        seq,
        ack,
        data_offset,
        tcp_flags,
        window,
        [0, 0],
        0,
    );
    let hdr_bytes = unsafe {
        std::slice::from_raw_parts(&hdr as *const TcpHeader as *const u8, TCP_HEADER_LEN)
    };
    buf[tcp_off..tcp_off + TCP_HEADER_LEN].copy_from_slice(hdr_bytes);

    // Options.
    if !tcp_options.is_empty() {
        buf[tcp_off + TCP_HEADER_LEN..tcp_off + TCP_HEADER_LEN + tcp_options.len()]
            .copy_from_slice(tcp_options);
    }

    // TCP checksum.
    let tcp_segment = &mut buf[tcp_off..];
    let cksum = compute_tcp_checksum(&src_ip, &dst_ip, tcp_segment);
    buf[tcp_off + 16] = cksum[0];
    buf[tcp_off + 17] = cksum[1];

    buf
}

/// Build a valid Ethernet + IPv4 + TCP frame with payload data.
pub(super) fn build_tcp_frame_with_payload(
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    tcp_flags: u8,
    window: u16,
    tcp_options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let opt_padded_len = (tcp_options.len() + 3) & !3;
    let tcp_header_len = TCP_HEADER_LEN + opt_padded_len;
    let data_offset = (tcp_header_len / 4) as u8;
    let total_ip_len = (IPV4_MIN_HEADER_LEN + tcp_header_len + payload.len()) as u16;
    let mut buf =
        vec![0u8; ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + tcp_header_len + payload.len()];

    // Ethernet header.
    buf[0..6].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // dst mac
    buf[6..12].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // src mac
    buf[12] = 0x08;
    buf[13] = 0x00;

    // IPv4 header.
    let ip = &mut buf[ETH_HEADER_LEN..];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&total_ip_len.to_be_bytes());
    ip[6] = 0x40;
    ip[8] = 64;
    ip[9] = IpProtocols::Tcp;
    let src_bytes: [u8; 4] = src_ip.into();
    ip[12..16].copy_from_slice(&src_bytes);
    let dst_bytes: [u8; 4] = dst_ip.into();
    ip[16..20].copy_from_slice(&dst_bytes);
    let cksum = compute_ipv4_checksum(&ip[..20]);
    ip[10] = cksum[0];
    ip[11] = cksum[1];

    // TCP header.
    let tcp_off = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
    let hdr = TcpHeader::new(
        src_port,
        dst_port,
        seq,
        ack,
        data_offset,
        tcp_flags,
        window,
        [0, 0],
        0,
    );
    let hdr_bytes = unsafe {
        std::slice::from_raw_parts(&hdr as *const TcpHeader as *const u8, TCP_HEADER_LEN)
    };
    buf[tcp_off..tcp_off + TCP_HEADER_LEN].copy_from_slice(hdr_bytes);

    // Options.
    if !tcp_options.is_empty() {
        buf[tcp_off + TCP_HEADER_LEN..tcp_off + TCP_HEADER_LEN + tcp_options.len()]
            .copy_from_slice(tcp_options);
    }

    // Payload.
    if !payload.is_empty() {
        buf[tcp_off + tcp_header_len..tcp_off + tcp_header_len + payload.len()]
            .copy_from_slice(payload);
    }

    // TCP checksum (covers header + payload).
    let tcp_segment = &mut buf[tcp_off..];
    let cksum = compute_tcp_checksum(&src_ip, &dst_ip, tcp_segment);
    buf[tcp_off + 16] = cksum[0];
    buf[tcp_off + 17] = cksum[1];

    buf
}

/// Leak data for test frames — avoids lifetime issues with frame buffers.
pub(super) fn leak(data: Vec<u8>) -> &'static mut [u8] {
    Box::leak(data.into_boxed_slice())
}

pub(super) fn alloc_free_frame(addr: u64) -> Frame<'static> {
    Frame::new(addr, leak(vec![0u8; 256]), 256, false)
}

/// Build a 12-byte TCP timestamp option (NOP NOP TSopt) for use in test frames.
pub(super) fn build_ts_option(tsval: u32, tsecr: u32) -> Vec<u8> {
    let mut opt = vec![1u8, 1]; // NOP, NOP (alignment)
    opt.push(8); // kind = TIMESTAMP
    opt.push(10); // length = 10
    opt.extend_from_slice(&tsval.to_be_bytes());
    opt.extend_from_slice(&tsecr.to_be_bytes());
    opt
}

/// Helper: complete a 3-way handshake and return server_iss.
/// Drains tx after handshake so callers start with an empty tx buffer.
pub(super) fn establish_connection(
    handler: &mut TcpHandler,
    nh: &NeighborHandler,
    free: &mut BasicFrameBuffer<'static>,
    rx: &mut BasicFrameBuffer<'static>,
    tx: &mut BasicFrameBuffer<'static>,
) -> u32 {
    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
    let syn_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1000,
        0,
        flags::SYN,
        65535,
        &[],
    );
    let syn_len = syn_data.len();
    handler.process_ipv4(
        Frame::new(0, leak(syn_data), syn_len, false),
        coarsetime::Instant::now(),
        nh,
        free,
        rx,
        tx,
    );
    let server_iss = handler.connections[0].iss;
    let ack_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        server_iss.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
    );
    let ack_len = ack_data.len();
    handler.process_ipv4(
        Frame::new(1, leak(ack_data), ack_len, false),
        coarsetime::Instant::now(),
        nh,
        free,
        rx,
        tx,
    );
    while tx.pop().is_some() {}
    server_iss
}

/// Helper: establish a connection with SACK enabled, returning server_iss.
pub(super) fn establish_connection_with_sack(
    handler: &mut TcpHandler,
    nh: &NeighborHandler,
    free: &mut BasicFrameBuffer<'static>,
    rx: &mut BasicFrameBuffer<'static>,
    tx: &mut BasicFrameBuffer<'static>,
) -> u32 {
    use crate::net::wire::tcp::options as tcp_options;
    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
    let sack_perm_opts = [tcp_options::SACK_PERMITTED, 2];
    let syn_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1000,
        0,
        flags::SYN,
        65535,
        &sack_perm_opts,
    );
    let syn_len = syn_data.len();
    handler.process_ipv4(
        Frame::new(0, leak(syn_data), syn_len, false),
        coarsetime::Instant::now(),
        nh,
        free,
        rx,
        tx,
    );
    assert!(handler.connections[0].sack_enabled);
    let server_iss = handler.connections[0].iss;
    while tx.pop().is_some() {}

    let ack_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        server_iss.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
    );
    let ack_len = ack_data.len();
    handler.process_ipv4(
        Frame::new(1, leak(ack_data), ack_len, false),
        coarsetime::Instant::now(),
        nh,
        free,
        rx,
        tx,
    );
    while tx.pop().is_some() {}
    assert_eq!(handler.connections[0].state, TcpState::Established);
    server_iss
}

/// Helper: perform active open handshake via connect + SYN-ACK processing.
/// Returns the client ISS (so the caller knows snd_una/snd_nxt base).
pub(super) fn active_open_handshake(
    handler: &mut TcpHandler,
    nh: &NeighborHandler,
    free: &mut BasicFrameBuffer<'static>,
    rx: &mut BasicFrameBuffer<'static>,
    tx: &mut BasicFrameBuffer<'static>,
) -> u32 {
    let src_mac =
        crate::net::wire::ethernet::MacAddress::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    let dst_mac =
        crate::net::wire::ethernet::MacAddress::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

    // connect sends SYN.
    let _event_queue = handler
        .connect(
            IpAddress::V4(LOCAL_IP),
            5000,
            IpAddress::V4(REMOTE_IP),
            80,
            src_mac,
            dst_mac,
            coarsetime::Instant::now(),
            free,
            tx,
        )
        .unwrap();
    while tx.pop().is_some() {} // consume SYN frame

    let client_iss = handler.connections[0].iss;

    // Feed SYN-ACK from the remote.
    let syn_ack = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        80,
        5000,
        2000,
        client_iss.wrapping_add(1),
        flags::SYN | flags::ACK,
        65535,
        &[],
    );
    let syn_ack_len = syn_ack.len();
    handler.process_ipv4(
        Frame::new(50, leak(syn_ack), syn_ack_len, false),
        coarsetime::Instant::now(),
        nh,
        free,
        rx,
        tx,
    );
    while tx.pop().is_some() {} // consume ACK frame

    assert_eq!(handler.connections[0].state, TcpState::Established);
    handler.connections[0].snd_wnd = 65535;

    client_iss
}

/// Helper: perform active open handshake with custom TcpConfig.
pub(super) fn active_open_handshake_with_config(
    handler: &mut TcpHandler,
    nh: &NeighborHandler,
    config: TcpConfig,
    free: &mut BasicFrameBuffer<'static>,
    rx: &mut BasicFrameBuffer<'static>,
    tx: &mut BasicFrameBuffer<'static>,
) -> u32 {
    let src_mac =
        crate::net::wire::ethernet::MacAddress::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    let dst_mac =
        crate::net::wire::ethernet::MacAddress::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

    let _event_queue = handler
        .connect_with_config(
            IpAddress::V4(LOCAL_IP),
            5000,
            IpAddress::V4(REMOTE_IP),
            80,
            src_mac,
            dst_mac,
            coarsetime::Instant::now(),
            config,
            free,
            tx,
        )
        .unwrap();
    while tx.pop().is_some() {}

    let client_iss = handler.connections[0].iss;

    let syn_ack = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        80,
        5000,
        2000,
        client_iss.wrapping_add(1),
        flags::SYN | flags::ACK,
        65535,
        &[],
    );
    let syn_ack_len = syn_ack.len();
    handler.process_ipv4(
        Frame::new(50, leak(syn_ack), syn_ack_len, false),
        coarsetime::Instant::now(),
        nh,
        free,
        rx,
        tx,
    );
    while tx.pop().is_some() {}

    assert_eq!(handler.connections[0].state, TcpState::Established);
    handler.connections[0].snd_wnd = 65535;

    client_iss
}

#[test]
fn segment_acceptability_zero_len_zero_wnd() {
    assert!(is_segment_acceptable(100, 0, 100, 0));
    assert!(!is_segment_acceptable(101, 0, 100, 0));
}

#[test]
fn segment_acceptability_zero_len_nonzero_wnd() {
    assert!(is_segment_acceptable(100, 0, 100, 1000));
    assert!(is_segment_acceptable(1099, 0, 100, 1000));
    assert!(!is_segment_acceptable(1100, 0, 100, 1000));
    assert!(!is_segment_acceptable(99, 0, 100, 1000));
}

#[test]
fn segment_acceptability_nonzero_len_zero_wnd() {
    assert!(!is_segment_acceptable(100, 10, 100, 0));
}

#[test]
fn segment_acceptability_nonzero_len_nonzero_wnd() {
    // Start in window
    assert!(is_segment_acceptable(100, 10, 100, 1000));
    // End in window (start slightly before)
    assert!(is_segment_acceptable(95, 10, 100, 1000));
    // Completely outside
    assert!(!is_segment_acceptable(1200, 10, 100, 1000));
    // Completely before
    assert!(!is_segment_acceptable(80, 10, 100, 1000));
}

mod congestion_tests;
mod data_transfer;
mod delayed_ack;
mod ecn;
mod edge_cases;
mod handshake;
mod keepalive;
mod nagle;
mod persist;
mod retransmission;
mod sack;
mod teardown;
mod timestamps;
