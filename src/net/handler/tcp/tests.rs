use super::TcpHandler;
use super::segment::ETH_HEADER_LEN;
use super::types::*;
use crate::net::wire::ethernet::MacAddress;
use crate::net::wire::ip::{
    IPV4_MIN_HEADER_LEN, IPV6_HEADER_LEN, IpAddress, IpProtocols, Ipv4Address, Ipv6Address,
    compute_ipv4_checksum,
};
use crate::net::wire::tcp::{
    TCP_HEADER_LEN, compute_tcp_checksum, compute_tcp_checksum_v6, flags, verify_tcp_checksum,
    verify_tcp_checksum_v6, write_mss_option,
};
use crate::xdp::frame::{BasicFrameBuffer, Frame, FrameBuffer};

const LOCAL_IPV4: Ipv4Address = Ipv4Address::new([192, 168, 1, 1]);
const REMOTE_IPV4: Ipv4Address = Ipv4Address::new([10, 0, 0, 2]);
const LOCAL_IPV6: Ipv6Address =
    Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
const REMOTE_IPV6: Ipv6Address =
    Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

const LOCAL_MAC: MacAddress = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
const REMOTE_MAC: MacAddress = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);

fn build_ipv4_tcp_frame(
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    seg_flags: u8,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    build_ipv4_tcp_frame_with_options(
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        seq,
        ack,
        seg_flags,
        window,
        &[],
        payload,
    )
}

fn build_ipv4_tcp_frame_with_options(
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    seg_flags: u8,
    window: u16,
    options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let tcp_header_len = TCP_HEADER_LEN + options.len();
    assert!(tcp_header_len % 4 == 0);
    let ip_total_len = (IPV4_MIN_HEADER_LEN + tcp_header_len + payload.len()) as u16;
    let mut buf = vec![0u8; ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + tcp_header_len + payload.len()];

    // Ethernet: dst=LOCAL_MAC (it's the frame arriving at our local NIC)
    buf[0..6].copy_from_slice(&<[u8; 6]>::from(LOCAL_MAC));
    buf[6..12].copy_from_slice(&<[u8; 6]>::from(REMOTE_MAC));
    buf[12] = 0x08;
    buf[13] = 0x00;

    let ip = &mut buf[ETH_HEADER_LEN..];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&ip_total_len.to_be_bytes());
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

    let tcp_off = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
    let data_offset = (tcp_header_len / 4) as u8;
    buf[tcp_off..tcp_off + 2].copy_from_slice(&src_port.to_be_bytes());
    buf[tcp_off + 2..tcp_off + 4].copy_from_slice(&dst_port.to_be_bytes());
    buf[tcp_off + 4..tcp_off + 8].copy_from_slice(&seq.to_be_bytes());
    buf[tcp_off + 8..tcp_off + 12].copy_from_slice(&ack.to_be_bytes());
    buf[tcp_off + 12] = data_offset << 4;
    buf[tcp_off + 13] = seg_flags;
    buf[tcp_off + 14..tcp_off + 16].copy_from_slice(&window.to_be_bytes());
    buf[tcp_off + 16..tcp_off + 18].copy_from_slice(&[0, 0]);
    buf[tcp_off + 18..tcp_off + 20].copy_from_slice(&[0, 0]);

    buf[tcp_off + TCP_HEADER_LEN..tcp_off + tcp_header_len].copy_from_slice(options);

    let payload_off = tcp_off + tcp_header_len;
    buf[payload_off..payload_off + payload.len()].copy_from_slice(payload);

    let cksum = compute_tcp_checksum(&src_ip, &dst_ip, &buf[tcp_off..]);
    buf[tcp_off + 16] = cksum[0];
    buf[tcp_off + 17] = cksum[1];

    buf
}

fn build_ipv6_tcp_frame(
    src_ip: Ipv6Address,
    dst_ip: Ipv6Address,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    seg_flags: u8,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let payload_len = (TCP_HEADER_LEN + payload.len()) as u16;
    let mut buf = vec![0u8; ETH_HEADER_LEN + IPV6_HEADER_LEN + TCP_HEADER_LEN + payload.len()];

    buf[0..6].copy_from_slice(&<[u8; 6]>::from(LOCAL_MAC));
    buf[6..12].copy_from_slice(&<[u8; 6]>::from(REMOTE_MAC));
    buf[12] = 0x86;
    buf[13] = 0xDD;

    let ip = &mut buf[ETH_HEADER_LEN..];
    ip[0] = 0x60;
    ip[4..6].copy_from_slice(&payload_len.to_be_bytes());
    ip[6] = IpProtocols::Tcp;
    ip[7] = 64;
    let src_bytes: [u8; 16] = src_ip.into();
    ip[8..24].copy_from_slice(&src_bytes);
    let dst_bytes: [u8; 16] = dst_ip.into();
    ip[24..40].copy_from_slice(&dst_bytes);

    let tcp_off = ETH_HEADER_LEN + IPV6_HEADER_LEN;
    buf[tcp_off..tcp_off + 2].copy_from_slice(&src_port.to_be_bytes());
    buf[tcp_off + 2..tcp_off + 4].copy_from_slice(&dst_port.to_be_bytes());
    buf[tcp_off + 4..tcp_off + 8].copy_from_slice(&seq.to_be_bytes());
    buf[tcp_off + 8..tcp_off + 12].copy_from_slice(&ack.to_be_bytes());
    buf[tcp_off + 12] = 0x50;
    buf[tcp_off + 13] = seg_flags;
    buf[tcp_off + 14..tcp_off + 16].copy_from_slice(&window.to_be_bytes());
    buf[tcp_off + 16..tcp_off + 18].copy_from_slice(&[0, 0]);
    buf[tcp_off + 18..tcp_off + 20].copy_from_slice(&[0, 0]);

    let payload_off = tcp_off + TCP_HEADER_LEN;
    buf[payload_off..payload_off + payload.len()].copy_from_slice(payload);

    let cksum = compute_tcp_checksum_v6(&src_ip, &dst_ip, &buf[tcp_off..]);
    buf[tcp_off + 16] = cksum[0];
    buf[tcp_off + 17] = cksum[1];

    buf
}

/// Helper: create a frame from a buffer, ensuring the buffer outlives the frame.
/// Returns frame capacity size so tests can allocate enough.
const FRAME_CAP: usize = 256;

#[test]
fn syn_to_listening_port_creates_syn_received() {
    let raw = build_ipv4_tcp_frame(
        REMOTE_IPV4,
        LOCAL_IPV4,
        12345,
        80,
        1000,
        0,
        flags::SYN,
        65535,
        &[],
    );
    let mut buf = [0u8; FRAME_CAP];
    buf[..raw.len()].copy_from_slice(&raw);
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);
    let mut handler = TcpHandler::new(256);
    let _accept_q = handler.listen(IpAddress::V4(LOCAL_IPV4), 80, 16);

    let frame = Frame::new(0, &mut buf, raw.len(), false);

    handler.process_ipv4(frame, &mut free, &mut rx, &mut tx);

    assert_eq!(handler.num_connections(), 1);
}

#[test]
fn syn_to_closed_port_generates_rst() {
    let raw = build_ipv4_tcp_frame(
        REMOTE_IPV4,
        LOCAL_IPV4,
        12345,
        80,
        1000,
        0,
        flags::SYN,
        65535,
        &[],
    );
    let mut buf = [0u8; FRAME_CAP];
    buf[..raw.len()].copy_from_slice(&raw);
    let mut free = BasicFrameBuffer::new(16);
    // Seed free buffer with a frame so the RST can be built.
    let mut free_buf = [0u8; FRAME_CAP];
    free.push(Frame::new(99, &mut free_buf, FRAME_CAP, false));
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);
    let mut handler = TcpHandler::new(256);

    let frame = Frame::new(0, &mut buf, raw.len(), false);

    handler.process_ipv4(frame, &mut free, &mut rx, &mut tx);

    assert_eq!(handler.num_connections(), 0);
    assert!(tx.num_frames() > 0);
}

#[test]
fn bad_checksum_drops_frame() {
    let raw = build_ipv4_tcp_frame(
        REMOTE_IPV4,
        LOCAL_IPV4,
        12345,
        80,
        1000,
        0,
        flags::SYN,
        65535,
        &[],
    );
    let mut buf = [0u8; FRAME_CAP];
    buf[..raw.len()].copy_from_slice(&raw);
    // Corrupt checksum
    let tcp_off = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
    buf[tcp_off + 16] ^= 0xFF;
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);
    let mut handler = TcpHandler::new(256);
    let _accept_q = handler.listen(IpAddress::V4(LOCAL_IPV4), 80, 16);

    let frame = Frame::new(0, &mut buf, raw.len(), false);

    handler.process_ipv4(frame, &mut free, &mut rx, &mut tx);

    assert_eq!(handler.num_connections(), 0);
    assert_eq!(rx.num_frames(), 1);
    assert_eq!(tx.num_frames(), 0);
}

#[test]
fn ipv6_syn_to_listening_port() {
    let raw = build_ipv6_tcp_frame(
        REMOTE_IPV6,
        LOCAL_IPV6,
        12345,
        80,
        1000,
        0,
        flags::SYN,
        65535,
        &[],
    );
    let mut buf = [0u8; FRAME_CAP];
    buf[..raw.len()].copy_from_slice(&raw);
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);
    let mut handler = TcpHandler::new(256);
    let _accept_q = handler.listen(IpAddress::V6(LOCAL_IPV6), 80, 16);

    let frame = Frame::new(0, &mut buf, raw.len(), false);
    let tcp_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
    handler.process_ipv6(frame, tcp_offset, &mut free, &mut rx, &mut tx);

    assert_eq!(handler.num_connections(), 1);
}

#[test]
fn passive_three_way_handshake() {
    // Step 1: Client sends SYN
    let raw = build_ipv4_tcp_frame(
        REMOTE_IPV4,
        LOCAL_IPV4,
        12345,
        80,
        1000,
        0,
        flags::SYN,
        65535,
        &[],
    );
    let mut buf = [0u8; FRAME_CAP];
    buf[..raw.len()].copy_from_slice(&raw);
    let mut buf2 = [0u8; FRAME_CAP];
    let mut free = BasicFrameBuffer::new(64);
    let mut rx = BasicFrameBuffer::new(64);
    let mut tx = BasicFrameBuffer::new(64);
    let mut handler = TcpHandler::new(256);
    let accept_q = handler.listen(IpAddress::V4(LOCAL_IPV4), 80, 16);

    let frame = Frame::new(0, &mut buf, raw.len(), false);
    handler.process_ipv4(frame, &mut free, &mut rx, &mut tx);

    let conn_id = ConnectionId {
        local_addr: IpAddress::V4(LOCAL_IPV4),
        local_port: 80,
        remote_addr: IpAddress::V4(REMOTE_IPV4),
        remote_port: 12345,
    };
    assert_eq!(
        handler.connections.get(&conn_id).unwrap().state,
        TcpState::SynReceived,
    );

    // Step 2: Client sends ACK
    let server_iss = handler.connections.get(&conn_id).unwrap().iss;
    let raw2 = build_ipv4_tcp_frame(
        REMOTE_IPV4,
        LOCAL_IPV4,
        12345,
        80,
        1001,
        server_iss.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
    );
    buf2[..raw2.len()].copy_from_slice(&raw2);
    let frame2 = Frame::new(1, &mut buf2, raw2.len(), false);
    handler.process_ipv4(frame2, &mut free, &mut rx, &mut tx);

    assert_eq!(
        handler.connections.get(&conn_id).unwrap().state,
        TcpState::Established,
    );
    assert_eq!(accept_q.len(), 1);
}

#[test]
fn rst_handling_in_listen() {
    let raw = build_ipv4_tcp_frame(
        REMOTE_IPV4,
        LOCAL_IPV4,
        12345,
        80,
        1000,
        0,
        flags::RST,
        0,
        &[],
    );
    let mut buf = [0u8; FRAME_CAP];
    buf[..raw.len()].copy_from_slice(&raw);
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);
    let mut handler = TcpHandler::new(256);
    let _accept_q = handler.listen(IpAddress::V4(LOCAL_IPV4), 80, 16);

    let frame = Frame::new(0, &mut buf, raw.len(), false);

    handler.process_ipv4(frame, &mut free, &mut rx, &mut tx);

    assert_eq!(handler.num_connections(), 0);
    assert_eq!(tx.num_frames(), 0);
}

#[test]
fn mss_parsed_from_syn() {
    let mut mss_opt = [0u8; 4];
    write_mss_option(&mut mss_opt, 1200);

    let raw = build_ipv4_tcp_frame_with_options(
        REMOTE_IPV4,
        LOCAL_IPV4,
        12345,
        80,
        1000,
        0,
        flags::SYN,
        65535,
        &mss_opt,
        &[],
    );
    let mut buf = [0u8; FRAME_CAP];
    buf[..raw.len()].copy_from_slice(&raw);
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);
    let mut handler = TcpHandler::new(256);
    let _accept_q = handler.listen(IpAddress::V4(LOCAL_IPV4), 80, 16);

    let frame = Frame::new(0, &mut buf, raw.len(), false);

    handler.process_ipv4(frame, &mut free, &mut rx, &mut tx);

    let conn_id = ConnectionId {
        local_addr: IpAddress::V4(LOCAL_IPV4),
        local_port: 80,
        remote_addr: IpAddress::V4(REMOTE_IPV4),
        remote_port: 12345,
    };
    assert_eq!(handler.connections.get(&conn_id).unwrap().snd_mss, 1200);
}

// ============================================================
// pnet cross-validation tests
//
// These use the pnet crate as an independent reference implementation
// for TCP checksum computation to verify our checksums match.
// ============================================================

/// Build an IPv4 TCP frame using pnet for independent checksum computation.
fn build_pnet_ipv4_tcp_frame(
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    tcp_flags: u8,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    use pnet::packet::ipv4::MutableIpv4Packet;
    use pnet::packet::tcp::MutableTcpPacket;
    use std::net::Ipv4Addr;

    let tcp_len = TCP_HEADER_LEN + payload.len();
    let ip_len = IPV4_MIN_HEADER_LEN + tcp_len;
    let frame_len = ETH_HEADER_LEN + ip_len;
    let mut buf = vec![0u8; frame_len];

    // Ethernet
    buf[0..6].copy_from_slice(&<[u8; 6]>::from(LOCAL_MAC));
    buf[6..12].copy_from_slice(&<[u8; 6]>::from(REMOTE_MAC));
    buf[12] = 0x08;
    buf[13] = 0x00;

    let src_bytes: [u8; 4] = src_ip.into();
    let dst_bytes: [u8; 4] = dst_ip.into();
    let pnet_src = Ipv4Addr::from(src_bytes);
    let pnet_dst = Ipv4Addr::from(dst_bytes);

    // TCP (pnet checksum)
    let tcp_off = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
    {
        let mut tcp = MutableTcpPacket::new(&mut buf[tcp_off..tcp_off + tcp_len]).unwrap();
        tcp.set_source(src_port);
        tcp.set_destination(dst_port);
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(ack);
        tcp.set_data_offset(5);
        tcp.set_flags(tcp_flags);
        tcp.set_window(window);
        tcp.set_urgent_ptr(0);
        if !payload.is_empty() {
            tcp.set_payload(payload);
        }
        let cksum = pnet::packet::tcp::ipv4_checksum(&tcp.to_immutable(), &pnet_src, &pnet_dst);
        tcp.set_checksum(cksum);
    }

    // IPv4 header (pnet checksum)
    {
        let mut ip =
            MutableIpv4Packet::new(&mut buf[ETH_HEADER_LEN..ETH_HEADER_LEN + ip_len]).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(ip_len as u16);
        ip.set_ttl(64);
        ip.set_flags(2); // DF
        ip.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Tcp);
        ip.set_source(pnet_src);
        ip.set_destination(pnet_dst);
        let cksum = pnet::packet::ipv4::checksum(&ip.to_immutable());
        ip.set_checksum(cksum);
    }

    buf
}

/// Build an IPv6 TCP frame using pnet for independent checksum computation.
fn build_pnet_ipv6_tcp_frame(
    src_ip: Ipv6Address,
    dst_ip: Ipv6Address,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    tcp_flags: u8,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    use pnet::packet::ipv6::MutableIpv6Packet;
    use pnet::packet::tcp::MutableTcpPacket;
    use std::net::Ipv6Addr;

    let tcp_len = TCP_HEADER_LEN + payload.len();
    let frame_len = ETH_HEADER_LEN + IPV6_HEADER_LEN + tcp_len;
    let mut buf = vec![0u8; frame_len];

    // Ethernet
    buf[0..6].copy_from_slice(&<[u8; 6]>::from(LOCAL_MAC));
    buf[6..12].copy_from_slice(&<[u8; 6]>::from(REMOTE_MAC));
    buf[12] = 0x86;
    buf[13] = 0xDD;

    let src_bytes: [u8; 16] = src_ip.into();
    let dst_bytes: [u8; 16] = dst_ip.into();
    let pnet_src = Ipv6Addr::from(src_bytes);
    let pnet_dst = Ipv6Addr::from(dst_bytes);

    // TCP (pnet checksum)
    let tcp_off = ETH_HEADER_LEN + IPV6_HEADER_LEN;
    {
        let mut tcp = MutableTcpPacket::new(&mut buf[tcp_off..tcp_off + tcp_len]).unwrap();
        tcp.set_source(src_port);
        tcp.set_destination(dst_port);
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(ack);
        tcp.set_data_offset(5);
        tcp.set_flags(tcp_flags);
        tcp.set_window(window);
        tcp.set_urgent_ptr(0);
        if !payload.is_empty() {
            tcp.set_payload(payload);
        }
        let cksum = pnet::packet::tcp::ipv6_checksum(&tcp.to_immutable(), &pnet_src, &pnet_dst);
        tcp.set_checksum(cksum);
    }

    // IPv6 header (pnet sets header fields only, TCP bytes preserved)
    {
        let mut ip = MutableIpv6Packet::new(
            &mut buf[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV6_HEADER_LEN + tcp_len],
        )
        .unwrap();
        ip.set_version(6);
        ip.set_payload_length(tcp_len as u16);
        ip.set_next_header(pnet::packet::ip::IpNextHeaderProtocols::Tcp);
        ip.set_hop_limit(64);
        ip.set_source(pnet_src);
        ip.set_destination(pnet_dst);
    }

    buf
}

// -- Direct checksum cross-verification --

#[test]
fn pnet_ipv4_checksum_cross_verify() {
    use pnet::packet::tcp::{MutableTcpPacket, TcpPacket};
    use std::net::Ipv4Addr;

    let payload = b"Hello from netcat!";
    let tcp_len = TCP_HEADER_LEN + payload.len();
    let mut tcp_buf = vec![0u8; tcp_len];

    let src_bytes: [u8; 4] = REMOTE_IPV4.into();
    let dst_bytes: [u8; 4] = LOCAL_IPV4.into();
    let pnet_src = Ipv4Addr::from(src_bytes);
    let pnet_dst = Ipv4Addr::from(dst_bytes);

    {
        let mut tcp = MutableTcpPacket::new(&mut tcp_buf).unwrap();
        tcp.set_source(12345);
        tcp.set_destination(80);
        tcp.set_sequence(1000);
        tcp.set_acknowledgement(500);
        tcp.set_data_offset(5);
        tcp.set_flags(0x18); // PSH+ACK
        tcp.set_window(65535);
        tcp.set_urgent_ptr(0);
        tcp.set_payload(payload);
        let cksum = pnet::packet::tcp::ipv4_checksum(&tcp.to_immutable(), &pnet_src, &pnet_dst);
        tcp.set_checksum(cksum);
    }

    // Our verify must accept pnet-generated checksum
    assert!(
        verify_tcp_checksum(&REMOTE_IPV4, &LOCAL_IPV4, &mut tcp_buf),
        "pnet-generated IPv4 TCP checksum must verify"
    );

    // Our compute must match pnet's value
    let pnet_cksum = {
        let mut zero_buf = tcp_buf.clone();
        zero_buf[16] = 0;
        zero_buf[17] = 0;
        let tcp = TcpPacket::new(&zero_buf).unwrap();
        pnet::packet::tcp::ipv4_checksum(&tcp, &pnet_src, &pnet_dst)
    };
    let mut zero_buf = tcp_buf.clone();
    zero_buf[16] = 0;
    zero_buf[17] = 0;
    let our_cksum = compute_tcp_checksum(&REMOTE_IPV4, &LOCAL_IPV4, &zero_buf);

    assert_eq!(
        our_cksum,
        pnet_cksum.to_be_bytes(),
        "IPv4 TCP checksum mismatch: pnet={:#06X}, ours=[{:#04X}, {:#04X}]",
        pnet_cksum,
        our_cksum[0],
        our_cksum[1]
    );
}

#[test]
fn pnet_ipv6_checksum_cross_verify() {
    use pnet::packet::tcp::{MutableTcpPacket, TcpPacket};
    use std::net::Ipv6Addr;

    let payload = b"Hello from netcat!";
    let tcp_len = TCP_HEADER_LEN + payload.len();
    let mut tcp_buf = vec![0u8; tcp_len];

    let src_bytes: [u8; 16] = REMOTE_IPV6.into();
    let dst_bytes: [u8; 16] = LOCAL_IPV6.into();
    let pnet_src = Ipv6Addr::from(src_bytes);
    let pnet_dst = Ipv6Addr::from(dst_bytes);

    {
        let mut tcp = MutableTcpPacket::new(&mut tcp_buf).unwrap();
        tcp.set_source(12345);
        tcp.set_destination(80);
        tcp.set_sequence(1000);
        tcp.set_acknowledgement(500);
        tcp.set_data_offset(5);
        tcp.set_flags(0x18); // PSH+ACK
        tcp.set_window(65535);
        tcp.set_urgent_ptr(0);
        tcp.set_payload(payload);
        let cksum = pnet::packet::tcp::ipv6_checksum(&tcp.to_immutable(), &pnet_src, &pnet_dst);
        tcp.set_checksum(cksum);
    }

    assert!(
        verify_tcp_checksum_v6(&REMOTE_IPV6, &LOCAL_IPV6, &mut tcp_buf),
        "pnet-generated IPv6 TCP checksum must verify"
    );

    let pnet_cksum = {
        let mut zero_buf = tcp_buf.clone();
        zero_buf[16] = 0;
        zero_buf[17] = 0;
        let tcp = TcpPacket::new(&zero_buf).unwrap();
        pnet::packet::tcp::ipv6_checksum(&tcp, &pnet_src, &pnet_dst)
    };
    let mut zero_buf = tcp_buf.clone();
    zero_buf[16] = 0;
    zero_buf[17] = 0;
    let our_cksum = compute_tcp_checksum_v6(&REMOTE_IPV6, &LOCAL_IPV6, &zero_buf);

    assert_eq!(
        our_cksum,
        pnet_cksum.to_be_bytes(),
        "IPv6 TCP checksum mismatch: pnet={:#06X}, ours=[{:#04X}, {:#04X}]",
        pnet_cksum,
        our_cksum[0],
        our_cksum[1]
    );
}

#[test]
fn pnet_ipv4_odd_payload_checksum_cross_verify() {
    use pnet::packet::tcp::MutableTcpPacket;
    use std::net::Ipv4Addr;

    let payload = b"Hello"; // 5 bytes (odd)
    let tcp_len = TCP_HEADER_LEN + payload.len();
    let mut tcp_buf = vec![0u8; tcp_len];

    let src_bytes: [u8; 4] = REMOTE_IPV4.into();
    let dst_bytes: [u8; 4] = LOCAL_IPV4.into();
    let pnet_src = Ipv4Addr::from(src_bytes);
    let pnet_dst = Ipv4Addr::from(dst_bytes);

    {
        let mut tcp = MutableTcpPacket::new(&mut tcp_buf).unwrap();
        tcp.set_source(12345);
        tcp.set_destination(80);
        tcp.set_sequence(1000);
        tcp.set_acknowledgement(500);
        tcp.set_data_offset(5);
        tcp.set_flags(0x18);
        tcp.set_window(65535);
        tcp.set_urgent_ptr(0);
        tcp.set_payload(payload);
        let cksum = pnet::packet::tcp::ipv4_checksum(&tcp.to_immutable(), &pnet_src, &pnet_dst);
        tcp.set_checksum(cksum);
    }

    assert!(
        verify_tcp_checksum(&REMOTE_IPV4, &LOCAL_IPV4, &mut tcp_buf),
        "pnet IPv4 TCP checksum with odd payload must verify"
    );
}

#[test]
fn pnet_ipv6_odd_payload_checksum_cross_verify() {
    use pnet::packet::tcp::MutableTcpPacket;
    use std::net::Ipv6Addr;

    let payload = b"Hello"; // 5 bytes (odd)
    let tcp_len = TCP_HEADER_LEN + payload.len();
    let mut tcp_buf = vec![0u8; tcp_len];

    let src_bytes: [u8; 16] = REMOTE_IPV6.into();
    let dst_bytes: [u8; 16] = LOCAL_IPV6.into();
    let pnet_src = Ipv6Addr::from(src_bytes);
    let pnet_dst = Ipv6Addr::from(dst_bytes);

    {
        let mut tcp = MutableTcpPacket::new(&mut tcp_buf).unwrap();
        tcp.set_source(12345);
        tcp.set_destination(80);
        tcp.set_sequence(1000);
        tcp.set_acknowledgement(500);
        tcp.set_data_offset(5);
        tcp.set_flags(0x18);
        tcp.set_window(65535);
        tcp.set_urgent_ptr(0);
        tcp.set_payload(payload);
        let cksum = pnet::packet::tcp::ipv6_checksum(&tcp.to_immutable(), &pnet_src, &pnet_dst);
        tcp.set_checksum(cksum);
    }

    assert!(
        verify_tcp_checksum_v6(&REMOTE_IPV6, &LOCAL_IPV6, &mut tcp_buf),
        "pnet IPv6 TCP checksum with odd payload must verify"
    );
}

// -- process_ipv4 / process_ipv6 with pnet-generated frames --

#[test]
fn pnet_ipv4_syn_accepted() {
    let raw = build_pnet_ipv4_tcp_frame(
        REMOTE_IPV4,
        LOCAL_IPV4,
        12345,
        80,
        1000,
        0,
        0x02,
        65535,
        &[],
    );
    let mut buf = [0u8; FRAME_CAP];
    buf[..raw.len()].copy_from_slice(&raw);
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);
    let mut handler = TcpHandler::new(256);
    let _accept_q = handler.listen(IpAddress::V4(LOCAL_IPV4), 80, 16);

    let frame = Frame::new(0, &mut buf, raw.len(), false);
    handler.process_ipv4(frame, &mut free, &mut rx, &mut tx);

    assert_eq!(
        handler.num_connections(),
        1,
        "pnet IPv4 SYN must be accepted"
    );
}

#[test]
fn pnet_ipv6_syn_accepted() {
    let raw = build_pnet_ipv6_tcp_frame(
        REMOTE_IPV6,
        LOCAL_IPV6,
        12345,
        80,
        1000,
        0,
        0x02,
        65535,
        &[],
    );
    let mut buf = [0u8; FRAME_CAP];
    buf[..raw.len()].copy_from_slice(&raw);
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);
    let mut handler = TcpHandler::new(256);
    let _accept_q = handler.listen(IpAddress::V6(LOCAL_IPV6), 80, 16);

    let frame = Frame::new(0, &mut buf, raw.len(), false);
    let tcp_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
    handler.process_ipv6(frame, tcp_offset, &mut free, &mut rx, &mut tx);

    assert_eq!(
        handler.num_connections(),
        1,
        "pnet IPv6 SYN must be accepted"
    );
}

#[test]
fn pnet_ipv4_padded_frame_accepted() {
    let raw = build_pnet_ipv4_tcp_frame(
        REMOTE_IPV4,
        LOCAL_IPV4,
        12345,
        80,
        1000,
        0,
        0x02,
        65535,
        &[],
    );
    // Pad to 64-byte Ethernet minimum with non-zero garbage
    let padded_len = 64.max(raw.len());
    let mut buf = [0xABu8; FRAME_CAP];
    buf[..raw.len()].copy_from_slice(&raw);

    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);
    let mut handler = TcpHandler::new(256);
    let _accept_q = handler.listen(IpAddress::V4(LOCAL_IPV4), 80, 16);

    let frame = Frame::new(0, &mut buf, padded_len, false);
    handler.process_ipv4(frame, &mut free, &mut rx, &mut tx);

    assert_eq!(
        handler.num_connections(),
        1,
        "padded IPv4 frame must pass checksum and be accepted"
    );
}

#[test]
fn pnet_ipv6_padded_frame_accepted() {
    let raw = build_pnet_ipv6_tcp_frame(
        REMOTE_IPV6,
        LOCAL_IPV6,
        12345,
        80,
        1000,
        0,
        0x02,
        65535,
        &[],
    );
    let padded_len = 64.max(raw.len());
    let mut buf = [0xABu8; FRAME_CAP];
    buf[..raw.len()].copy_from_slice(&raw);

    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);
    let mut handler = TcpHandler::new(256);
    let _accept_q = handler.listen(IpAddress::V6(LOCAL_IPV6), 80, 16);

    let frame = Frame::new(0, &mut buf, padded_len, false);
    let tcp_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
    handler.process_ipv6(frame, tcp_offset, &mut free, &mut rx, &mut tx);

    assert_eq!(
        handler.num_connections(),
        1,
        "padded IPv6 frame must pass checksum and be accepted"
    );
}

// ============================================================
// Data payload delivery tests
//
// These test the full pipeline: pnet-generated TCP data segments
// flow through process_ipv4/process_ipv6 and verify that payload
// data is correctly delivered to the rx_queue after a 3-way handshake.
// ============================================================

/// Complete an IPv4 3-way handshake (passive open), returning the connection ID.
fn setup_ipv4_established<'a>(
    handler: &mut TcpHandler<'a>,
    syn_buf: &'a mut [u8],
    ack_buf: &'a mut [u8],
    free: &mut BasicFrameBuffer<'a>,
    rx: &mut BasicFrameBuffer<'a>,
    tx: &mut BasicFrameBuffer<'a>,
) -> ConnectionId {
    let raw = build_pnet_ipv4_tcp_frame(
        REMOTE_IPV4,
        LOCAL_IPV4,
        12345,
        80,
        1000,
        0,
        flags::SYN,
        65535,
        &[],
    );
    syn_buf[..raw.len()].copy_from_slice(&raw);
    let frame = Frame::new(0, syn_buf, raw.len(), false);
    handler.process_ipv4(frame, free, rx, tx);

    let conn_id = ConnectionId {
        local_addr: IpAddress::V4(LOCAL_IPV4),
        local_port: 80,
        remote_addr: IpAddress::V4(REMOTE_IPV4),
        remote_port: 12345,
    };
    let server_iss = handler.connections.get(&conn_id).unwrap().iss;

    let raw = build_pnet_ipv4_tcp_frame(
        REMOTE_IPV4,
        LOCAL_IPV4,
        12345,
        80,
        1001,
        server_iss.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
    );
    ack_buf[..raw.len()].copy_from_slice(&raw);
    let frame = Frame::new(1, ack_buf, raw.len(), false);
    handler.process_ipv4(frame, free, rx, tx);

    assert_eq!(
        handler.connections.get(&conn_id).unwrap().state,
        TcpState::Established,
    );
    conn_id
}

/// Complete an IPv6 3-way handshake (passive open), returning the connection ID.
fn setup_ipv6_established<'a>(
    handler: &mut TcpHandler<'a>,
    syn_buf: &'a mut [u8],
    ack_buf: &'a mut [u8],
    free: &mut BasicFrameBuffer<'a>,
    rx: &mut BasicFrameBuffer<'a>,
    tx: &mut BasicFrameBuffer<'a>,
) -> ConnectionId {
    let tcp_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
    let raw = build_pnet_ipv6_tcp_frame(
        REMOTE_IPV6,
        LOCAL_IPV6,
        12345,
        80,
        1000,
        0,
        flags::SYN,
        65535,
        &[],
    );
    syn_buf[..raw.len()].copy_from_slice(&raw);
    let frame = Frame::new(0, syn_buf, raw.len(), false);
    handler.process_ipv6(frame, tcp_offset, free, rx, tx);

    let conn_id = ConnectionId {
        local_addr: IpAddress::V6(LOCAL_IPV6),
        local_port: 80,
        remote_addr: IpAddress::V6(REMOTE_IPV6),
        remote_port: 12345,
    };
    let server_iss = handler.connections.get(&conn_id).unwrap().iss;

    let raw = build_pnet_ipv6_tcp_frame(
        REMOTE_IPV6,
        LOCAL_IPV6,
        12345,
        80,
        1001,
        server_iss.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
    );
    ack_buf[..raw.len()].copy_from_slice(&raw);
    let frame = Frame::new(1, ack_buf, raw.len(), false);
    handler.process_ipv6(frame, tcp_offset, free, rx, tx);

    assert_eq!(
        handler.connections.get(&conn_id).unwrap().state,
        TcpState::Established,
    );
    conn_id
}

#[test]
fn pnet_ipv4_data_accepted() {
    let payload = b"Hello, TCP world!"; // 17 bytes (odd)
    let mut syn_buf = [0u8; FRAME_CAP];
    let mut ack_buf = [0u8; FRAME_CAP];
    let mut data_buf = [0u8; FRAME_CAP];
    let mut free = BasicFrameBuffer::new(64);
    let mut rx = BasicFrameBuffer::new(64);
    let mut tx = BasicFrameBuffer::new(64);
    let mut handler = TcpHandler::new(256);
    let _accept_q = handler.listen(IpAddress::V4(LOCAL_IPV4), 80, 16);

    let conn_id =
        setup_ipv4_established(&mut handler, &mut syn_buf, &mut ack_buf, &mut free, &mut rx, &mut tx);
    let server_iss = handler.connections.get(&conn_id).unwrap().iss;
    let rx_queue = handler.connections.get(&conn_id).unwrap().rx_queue.clone();
    assert!(matches!(rx_queue.pop(), Some(TcpEvent::Connected)));

    let raw = build_pnet_ipv4_tcp_frame(
        REMOTE_IPV4,
        LOCAL_IPV4,
        12345,
        80,
        1001,
        server_iss.wrapping_add(1),
        flags::PSH | flags::ACK,
        65535,
        payload,
    );
    data_buf[..raw.len()].copy_from_slice(&raw);
    let frame = Frame::new(2, &mut data_buf, raw.len(), false);
    handler.process_ipv4(frame, &mut free, &mut rx, &mut tx);

    let tcb = handler.connections.get(&conn_id).unwrap();
    assert_eq!(tcb.rcv_nxt, 1001 + payload.len() as u32);

    match rx_queue.pop() {
        Some(TcpEvent::Data {
            frame,
            payload_offset,
            payload_len,
        }) => {
            assert_eq!(payload_len, payload.len());
            assert_eq!(
                &frame[payload_offset..payload_offset + payload_len],
                payload.as_slice()
            );
        }
        _ => panic!("expected TcpEvent::Data"),
    }
}

#[test]
fn pnet_ipv6_data_accepted() {
    let payload = b"Hello, TCP world!"; // 17 bytes (odd)
    let mut syn_buf = [0u8; FRAME_CAP];
    let mut ack_buf = [0u8; FRAME_CAP];
    let mut data_buf = [0u8; FRAME_CAP];
    let mut free = BasicFrameBuffer::new(64);
    let mut rx = BasicFrameBuffer::new(64);
    let mut tx = BasicFrameBuffer::new(64);
    let mut handler = TcpHandler::new(256);
    let _accept_q = handler.listen(IpAddress::V6(LOCAL_IPV6), 80, 16);

    let conn_id =
        setup_ipv6_established(&mut handler, &mut syn_buf, &mut ack_buf, &mut free, &mut rx, &mut tx);
    let server_iss = handler.connections.get(&conn_id).unwrap().iss;
    let rx_queue = handler.connections.get(&conn_id).unwrap().rx_queue.clone();
    assert!(matches!(rx_queue.pop(), Some(TcpEvent::Connected)));

    let tcp_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
    let raw = build_pnet_ipv6_tcp_frame(
        REMOTE_IPV6,
        LOCAL_IPV6,
        12345,
        80,
        1001,
        server_iss.wrapping_add(1),
        flags::PSH | flags::ACK,
        65535,
        payload,
    );
    data_buf[..raw.len()].copy_from_slice(&raw);
    let frame = Frame::new(2, &mut data_buf, raw.len(), false);
    handler.process_ipv6(frame, tcp_offset, &mut free, &mut rx, &mut tx);

    let tcb = handler.connections.get(&conn_id).unwrap();
    assert_eq!(tcb.rcv_nxt, 1001 + payload.len() as u32);

    match rx_queue.pop() {
        Some(TcpEvent::Data {
            frame,
            payload_offset,
            payload_len,
        }) => {
            assert_eq!(payload_len, payload.len());
            assert_eq!(
                &frame[payload_offset..payload_offset + payload_len],
                payload.as_slice()
            );
        }
        _ => panic!("expected TcpEvent::Data"),
    }
}

#[test]
fn pnet_ipv4_even_payload_data_accepted() {
    let payload = b"Even payload!!"; // 14 bytes (even)
    let mut syn_buf = [0u8; FRAME_CAP];
    let mut ack_buf = [0u8; FRAME_CAP];
    let mut data_buf = [0u8; FRAME_CAP];
    let mut free = BasicFrameBuffer::new(64);
    let mut rx = BasicFrameBuffer::new(64);
    let mut tx = BasicFrameBuffer::new(64);
    let mut handler = TcpHandler::new(256);
    let _accept_q = handler.listen(IpAddress::V4(LOCAL_IPV4), 80, 16);

    let conn_id =
        setup_ipv4_established(&mut handler, &mut syn_buf, &mut ack_buf, &mut free, &mut rx, &mut tx);
    let server_iss = handler.connections.get(&conn_id).unwrap().iss;
    let rx_queue = handler.connections.get(&conn_id).unwrap().rx_queue.clone();
    assert!(matches!(rx_queue.pop(), Some(TcpEvent::Connected)));

    let raw = build_pnet_ipv4_tcp_frame(
        REMOTE_IPV4,
        LOCAL_IPV4,
        12345,
        80,
        1001,
        server_iss.wrapping_add(1),
        flags::PSH | flags::ACK,
        65535,
        payload,
    );
    data_buf[..raw.len()].copy_from_slice(&raw);
    let frame = Frame::new(2, &mut data_buf, raw.len(), false);
    handler.process_ipv4(frame, &mut free, &mut rx, &mut tx);

    let tcb = handler.connections.get(&conn_id).unwrap();
    assert_eq!(tcb.rcv_nxt, 1001 + payload.len() as u32);

    match rx_queue.pop() {
        Some(TcpEvent::Data {
            frame,
            payload_offset,
            payload_len,
        }) => {
            assert_eq!(payload_len, payload.len());
            assert_eq!(
                &frame[payload_offset..payload_offset + payload_len],
                payload.as_slice()
            );
        }
        _ => panic!("expected TcpEvent::Data"),
    }
}

#[test]
fn pnet_ipv6_even_payload_data_accepted() {
    let payload = b"Even payload!!"; // 14 bytes (even)
    let mut syn_buf = [0u8; FRAME_CAP];
    let mut ack_buf = [0u8; FRAME_CAP];
    let mut data_buf = [0u8; FRAME_CAP];
    let mut free = BasicFrameBuffer::new(64);
    let mut rx = BasicFrameBuffer::new(64);
    let mut tx = BasicFrameBuffer::new(64);
    let mut handler = TcpHandler::new(256);
    let _accept_q = handler.listen(IpAddress::V6(LOCAL_IPV6), 80, 16);

    let conn_id =
        setup_ipv6_established(&mut handler, &mut syn_buf, &mut ack_buf, &mut free, &mut rx, &mut tx);
    let server_iss = handler.connections.get(&conn_id).unwrap().iss;
    let rx_queue = handler.connections.get(&conn_id).unwrap().rx_queue.clone();
    assert!(matches!(rx_queue.pop(), Some(TcpEvent::Connected)));

    let tcp_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
    let raw = build_pnet_ipv6_tcp_frame(
        REMOTE_IPV6,
        LOCAL_IPV6,
        12345,
        80,
        1001,
        server_iss.wrapping_add(1),
        flags::PSH | flags::ACK,
        65535,
        payload,
    );
    data_buf[..raw.len()].copy_from_slice(&raw);
    let frame = Frame::new(2, &mut data_buf, raw.len(), false);
    handler.process_ipv6(frame, tcp_offset, &mut free, &mut rx, &mut tx);

    let tcb = handler.connections.get(&conn_id).unwrap();
    assert_eq!(tcb.rcv_nxt, 1001 + payload.len() as u32);

    match rx_queue.pop() {
        Some(TcpEvent::Data {
            frame,
            payload_offset,
            payload_len,
        }) => {
            assert_eq!(payload_len, payload.len());
            assert_eq!(
                &frame[payload_offset..payload_offset + payload_len],
                payload.as_slice()
            );
        }
        _ => panic!("expected TcpEvent::Data"),
    }
}

#[test]
fn pnet_ipv4_padded_data_frame_accepted() {
    let payload = b"Padded data test";
    let mut syn_buf = [0u8; FRAME_CAP];
    let mut ack_buf = [0u8; FRAME_CAP];
    let mut data_buf = [0xABu8; FRAME_CAP]; // garbage fill
    let mut free = BasicFrameBuffer::new(64);
    let mut rx = BasicFrameBuffer::new(64);
    let mut tx = BasicFrameBuffer::new(64);
    let mut handler = TcpHandler::new(256);
    let _accept_q = handler.listen(IpAddress::V4(LOCAL_IPV4), 80, 16);

    let conn_id =
        setup_ipv4_established(&mut handler, &mut syn_buf, &mut ack_buf, &mut free, &mut rx, &mut tx);
    let server_iss = handler.connections.get(&conn_id).unwrap().iss;
    let rx_queue = handler.connections.get(&conn_id).unwrap().rx_queue.clone();
    assert!(matches!(rx_queue.pop(), Some(TcpEvent::Connected)));

    let raw = build_pnet_ipv4_tcp_frame(
        REMOTE_IPV4,
        LOCAL_IPV4,
        12345,
        80,
        1001,
        server_iss.wrapping_add(1),
        flags::PSH | flags::ACK,
        65535,
        payload,
    );
    // Copy real packet, leaving 0xAB garbage bytes trailing
    data_buf[..raw.len()].copy_from_slice(&raw);
    let padded_len = 128.max(raw.len());
    let frame = Frame::new(2, &mut data_buf, padded_len, false);
    handler.process_ipv4(frame, &mut free, &mut rx, &mut tx);

    let tcb = handler.connections.get(&conn_id).unwrap();
    assert_eq!(
        tcb.rcv_nxt,
        1001 + payload.len() as u32,
        "rcv_nxt must advance by payload length, not padded frame length"
    );

    match rx_queue.pop() {
        Some(TcpEvent::Data {
            frame,
            payload_offset,
            payload_len,
        }) => {
            assert_eq!(
                payload_len,
                payload.len(),
                "payload_len must reflect actual data, not padding"
            );
            assert_eq!(
                &frame[payload_offset..payload_offset + payload_len],
                payload.as_slice()
            );
        }
        _ => panic!("expected TcpEvent::Data"),
    }
}

#[test]
fn pnet_ipv6_padded_data_frame_accepted() {
    let payload = b"Padded data test";
    let mut syn_buf = [0u8; FRAME_CAP];
    let mut ack_buf = [0u8; FRAME_CAP];
    let mut data_buf = [0xABu8; FRAME_CAP]; // garbage fill
    let mut free = BasicFrameBuffer::new(64);
    let mut rx = BasicFrameBuffer::new(64);
    let mut tx = BasicFrameBuffer::new(64);
    let mut handler = TcpHandler::new(256);
    let _accept_q = handler.listen(IpAddress::V6(LOCAL_IPV6), 80, 16);

    let conn_id =
        setup_ipv6_established(&mut handler, &mut syn_buf, &mut ack_buf, &mut free, &mut rx, &mut tx);
    let server_iss = handler.connections.get(&conn_id).unwrap().iss;
    let rx_queue = handler.connections.get(&conn_id).unwrap().rx_queue.clone();
    assert!(matches!(rx_queue.pop(), Some(TcpEvent::Connected)));

    let tcp_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
    let raw = build_pnet_ipv6_tcp_frame(
        REMOTE_IPV6,
        LOCAL_IPV6,
        12345,
        80,
        1001,
        server_iss.wrapping_add(1),
        flags::PSH | flags::ACK,
        65535,
        payload,
    );
    data_buf[..raw.len()].copy_from_slice(&raw);
    let padded_len = 128.max(raw.len());
    let frame = Frame::new(2, &mut data_buf, padded_len, false);
    handler.process_ipv6(frame, tcp_offset, &mut free, &mut rx, &mut tx);

    let tcb = handler.connections.get(&conn_id).unwrap();
    assert_eq!(
        tcb.rcv_nxt,
        1001 + payload.len() as u32,
        "rcv_nxt must advance by payload length, not padded frame length"
    );

    match rx_queue.pop() {
        Some(TcpEvent::Data {
            frame,
            payload_offset,
            payload_len,
        }) => {
            assert_eq!(
                payload_len,
                payload.len(),
                "payload_len must reflect actual data, not padding"
            );
            assert_eq!(
                &frame[payload_offset..payload_offset + payload_len],
                payload.as_slice()
            );
        }
        _ => panic!("expected TcpEvent::Data"),
    }
}

#[test]
fn pnet_ipv4_single_byte_payload_accepted() {
    let payload = b"X"; // 1 byte -- minimal odd payload
    let mut syn_buf = [0u8; FRAME_CAP];
    let mut ack_buf = [0u8; FRAME_CAP];
    let mut data_buf = [0u8; FRAME_CAP];
    let mut free = BasicFrameBuffer::new(64);
    let mut rx = BasicFrameBuffer::new(64);
    let mut tx = BasicFrameBuffer::new(64);
    let mut handler = TcpHandler::new(256);
    let _accept_q = handler.listen(IpAddress::V4(LOCAL_IPV4), 80, 16);

    let conn_id =
        setup_ipv4_established(&mut handler, &mut syn_buf, &mut ack_buf, &mut free, &mut rx, &mut tx);
    let server_iss = handler.connections.get(&conn_id).unwrap().iss;
    let rx_queue = handler.connections.get(&conn_id).unwrap().rx_queue.clone();
    assert!(matches!(rx_queue.pop(), Some(TcpEvent::Connected)));

    let raw = build_pnet_ipv4_tcp_frame(
        REMOTE_IPV4,
        LOCAL_IPV4,
        12345,
        80,
        1001,
        server_iss.wrapping_add(1),
        flags::PSH | flags::ACK,
        65535,
        payload,
    );
    data_buf[..raw.len()].copy_from_slice(&raw);
    let frame = Frame::new(2, &mut data_buf, raw.len(), false);
    handler.process_ipv4(frame, &mut free, &mut rx, &mut tx);

    let tcb = handler.connections.get(&conn_id).unwrap();
    assert_eq!(tcb.rcv_nxt, 1002);

    match rx_queue.pop() {
        Some(TcpEvent::Data {
            frame,
            payload_offset,
            payload_len,
        }) => {
            assert_eq!(payload_len, 1);
            assert_eq!(frame[payload_offset], b'X');
        }
        _ => panic!("expected TcpEvent::Data"),
    }
}

#[test]
fn pnet_ipv4_large_payload_accepted() {
    let payload: Vec<u8> = (0..100).collect(); // 100 bytes
    let mut syn_buf = [0u8; FRAME_CAP];
    let mut ack_buf = [0u8; FRAME_CAP];
    let mut data_buf = [0u8; FRAME_CAP];
    let mut free = BasicFrameBuffer::new(64);
    let mut rx = BasicFrameBuffer::new(64);
    let mut tx = BasicFrameBuffer::new(64);
    let mut handler = TcpHandler::new(256);
    let _accept_q = handler.listen(IpAddress::V4(LOCAL_IPV4), 80, 16);

    let conn_id =
        setup_ipv4_established(&mut handler, &mut syn_buf, &mut ack_buf, &mut free, &mut rx, &mut tx);
    let server_iss = handler.connections.get(&conn_id).unwrap().iss;
    let rx_queue = handler.connections.get(&conn_id).unwrap().rx_queue.clone();
    assert!(matches!(rx_queue.pop(), Some(TcpEvent::Connected)));

    let raw = build_pnet_ipv4_tcp_frame(
        REMOTE_IPV4,
        LOCAL_IPV4,
        12345,
        80,
        1001,
        server_iss.wrapping_add(1),
        flags::PSH | flags::ACK,
        65535,
        &payload,
    );
    data_buf[..raw.len()].copy_from_slice(&raw);
    let frame = Frame::new(2, &mut data_buf, raw.len(), false);
    handler.process_ipv4(frame, &mut free, &mut rx, &mut tx);

    let tcb = handler.connections.get(&conn_id).unwrap();
    assert_eq!(tcb.rcv_nxt, 1001 + 100);

    match rx_queue.pop() {
        Some(TcpEvent::Data {
            frame,
            payload_offset,
            payload_len,
        }) => {
            assert_eq!(payload_len, 100);
            assert_eq!(
                &frame[payload_offset..payload_offset + payload_len],
                payload.as_slice()
            );
        }
        _ => panic!("expected TcpEvent::Data"),
    }
}
