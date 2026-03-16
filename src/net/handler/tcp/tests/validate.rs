use coarsetime::Instant;

use crate::net::{
    checksum::compute_tcp_checksum_ip,
    wire::ip::{Ipv6, Ipv6Address},
};

use super::*;

// ── IPv4 helpers ─────────────────────────────────────────────────────

const ETH_LEN: usize = 14;
const IPV4_LEN: usize = IPV4_MIN_HEADER_LEN;
const IPV6_LEN: usize = 40;

/// Build a minimal Ethernet + IPv4 + TCP SYN frame (raw bytes, no checksum fixup).
fn build_raw_ipv4_tcp_syn(
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    src_port: u16,
    dst_port: u16,
) -> Vec<u8> {
    build_tcp_frame(
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        1000,
        0,
        flags::SYN,
        65535,
        &[],
    )
}

/// Build an Ethernet + IPv6 + TCP frame with correct checksums.
fn build_ipv6_tcp_frame(
    src_ip: Ipv6Address,
    dst_ip: Ipv6Address,
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
    let payload_length = tcp_header_len as u16;
    let total = ETH_LEN + IPV6_LEN + tcp_header_len;
    let mut buf = vec![0u8; total];

    // Ethernet header.
    buf[0..6].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // dst mac
    buf[6..12].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // src mac
    buf[12] = 0x86;
    buf[13] = 0xDD; // EtherType IPv6

    // IPv6 header (40 bytes).
    let ip = &mut buf[ETH_LEN..ETH_LEN + IPV6_LEN];
    ip[0] = 0x60; // version 6
    ip[4..6].copy_from_slice(&payload_length.to_be_bytes());
    ip[6] = IpProtocols::Tcp; // next header
    ip[7] = 64; // hop limit
    let src_bytes: [u8; 16] = src_ip.into();
    ip[8..24].copy_from_slice(&src_bytes);
    let dst_bytes: [u8; 16] = dst_ip.into();
    ip[24..40].copy_from_slice(&dst_bytes);

    // TCP header.
    let tcp_off = ETH_LEN + IPV6_LEN;
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

    // TCP checksum over IPv6 pseudo-header.
    let tcp_segment = &mut buf[tcp_off..];
    let cksum = compute_tcp_checksum_ip::<Ipv6>(&src_ip, &dst_ip, tcp_segment, &[]);
    buf[tcp_off + 16] = cksum[0];
    buf[tcp_off + 17] = cksum[1];

    buf
}

// ── Tests ────────────────────────────────────────────────────────────

/// Frame too short to contain a TCP header should be returned to rx_return.
#[test]
fn frame_too_short_for_tcp_header_returned_to_rx() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(4);
    let mut rx = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(4);

    // Build a valid frame then truncate it so len < tcp_offset + TCP_HEADER_LEN.
    let full = build_raw_ipv4_tcp_syn(REMOTE_IP, LOCAL_IP, 12345, 80);
    let tcp_offset = ETH_LEN + IPV4_LEN;
    // Truncate to just before the end of the TCP header.
    let short = &full[..tcp_offset + TCP_HEADER_LEN - 1];
    let data = leak(short.to_vec());
    let len = data.len();
    let frame = Frame::new(100, data, len, false);

    handler.process_ipv4(frame, Instant::now(), &nh, &mut free, &mut rx, &mut tx);

    // Frame should be returned to rx_return (free pool), not consumed.
    assert!(
        rx.pop().is_some(),
        "short frame should be returned to rx_return"
    );
    assert!(
        tx.pop().is_none(),
        "no response should be sent for short frame"
    );
}

/// Data offset < 5 (invalid) should cause the frame to be returned.
#[test]
fn invalid_data_offset_too_small_returned() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(4);
    let mut rx = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(4);

    let mut data = build_raw_ipv4_tcp_syn(REMOTE_IP, LOCAL_IP, 12345, 80);
    let tcp_off = ETH_LEN + IPV4_LEN;

    // Corrupt data offset to 4 (minimum valid is 5). Data offset is in the
    // upper 4 bits of byte 12 of the TCP header.
    let doff_byte = &mut data[tcp_off + 12];
    *doff_byte = (*doff_byte & 0x0F) | (4 << 4); // data_offset = 4

    let len = data.len();
    let frame = Frame::new(200, leak(data), len, false);

    handler.process_ipv4(frame, Instant::now(), &nh, &mut free, &mut rx, &mut tx);

    assert!(
        rx.pop().is_some(),
        "invalid data_offset frame should be returned"
    );
    assert!(tx.pop().is_none());
}

/// Data offset claims more bytes than available in the frame → returned.
#[test]
fn data_offset_exceeds_frame_length_returned() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(4);
    let mut rx = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(4);

    // Build a minimal 20-byte TCP header frame (data_offset = 5).
    let mut data = build_raw_ipv4_tcp_syn(REMOTE_IP, LOCAL_IP, 12345, 80);
    let tcp_off = ETH_LEN + IPV4_LEN;

    // Set data_offset to 15 (60 bytes header), but the frame only has 20 bytes of TCP.
    let doff_byte = &mut data[tcp_off + 12];
    *doff_byte = (*doff_byte & 0x0F) | (15 << 4);

    let len = data.len();
    let frame = Frame::new(300, leak(data), len, false);

    handler.process_ipv4(frame, Instant::now(), &nh, &mut free, &mut rx, &mut tx);

    assert!(
        rx.pop().is_some(),
        "oversized data_offset frame should be returned"
    );
    assert!(tx.pop().is_none());
}

/// When rx_offload is disabled, a bad checksum should cause the frame to be returned.
#[test]
fn bad_checksum_returned_when_rx_offload_disabled() {
    // new_handler() already creates with rx_offload=false.
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(4);
    let mut rx = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(4);

    let _accept = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();

    let mut data = build_raw_ipv4_tcp_syn(REMOTE_IP, LOCAL_IP, 12345, 80);
    let tcp_off = ETH_LEN + IPV4_LEN;

    // Corrupt the TCP checksum.
    data[tcp_off + 16] ^= 0xFF;
    data[tcp_off + 17] ^= 0xFF;

    let len = data.len();
    let frame = Frame::new(400, leak(data), len, false);

    handler.process_ipv4(frame, Instant::now(), &nh, &mut free, &mut rx, &mut tx);

    assert!(rx.pop().is_some(), "bad checksum frame should be returned");
    assert!(tx.pop().is_none(), "no response for bad checksum");
}

/// When rx_offload is enabled, a bad checksum should NOT cause the frame to be
/// rejected (the NIC already verified it).
#[test]
fn bad_checksum_accepted_when_rx_offload_enabled() {
    let mut handler = TcpHandler::new(true, false); // rx_offload = true
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(4);
    let mut rx = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(4);

    let _accept = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
    free.push(alloc_free_frame(900));

    let mut data = build_raw_ipv4_tcp_syn(REMOTE_IP, LOCAL_IP, 12345, 80);
    let tcp_off = ETH_LEN + IPV4_LEN;

    // Corrupt the TCP checksum — with offload enabled, this should still be processed.
    data[tcp_off + 16] ^= 0xFF;
    data[tcp_off + 17] ^= 0xFF;

    let len = data.len();
    let frame = Frame::new(500, leak(data), len, false);

    handler.process_ipv4(frame, Instant::now(), &nh, &mut free, &mut rx, &mut tx);

    // Should produce a SYN-ACK response (frame was not rejected).
    assert!(
        tx.pop().is_some(),
        "offloaded checksum frame should be accepted"
    );
}

/// IPv6 path: a valid SYN over IPv6 should be processed (covers process_ipv6).
#[test]
fn ipv6_valid_syn_processed() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(4);
    let mut rx = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(4);

    let src_v6 = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let dst_v6 = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    let _accept = handler.listen(IpAddress::V6(dst_v6), 80, 128).unwrap();
    free.push(alloc_free_frame(901));
    nh.seed_cache(
        Instant::now(),
        IpAddress::V6(src_v6),
        MacAddress::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
    );

    let data = build_ipv6_tcp_frame(src_v6, dst_v6, 12345, 80, 1000, 0, flags::SYN, 65535, &[]);
    let tcp_offset = ETH_LEN + IPV6_LEN;
    let len = data.len();
    let frame = Frame::new(600, leak(data), len, false);

    handler.process_ipv6(
        frame,
        tcp_offset,
        Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Should produce a SYN-ACK response.
    assert!(tx.pop().is_some(), "valid IPv6 SYN should produce SYN-ACK");
}

/// IPv6 path: frame too short for TCP header should be returned.
#[test]
fn ipv6_frame_too_short_returned() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(4);
    let mut rx = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(4);

    let src_v6 = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let dst_v6 = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    let full = build_ipv6_tcp_frame(src_v6, dst_v6, 12345, 80, 1000, 0, flags::SYN, 65535, &[]);
    let tcp_offset = ETH_LEN + IPV6_LEN;
    // Truncate to just before the end of the TCP header.
    let short = &full[..tcp_offset + TCP_HEADER_LEN - 1];
    let data = leak(short.to_vec());
    let len = data.len();
    let frame = Frame::new(700, data, len, false);

    handler.process_ipv6(
        frame,
        tcp_offset,
        Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert!(rx.pop().is_some(), "short IPv6 frame should be returned");
    assert!(tx.pop().is_none());
}

/// IPv6 path: bad checksum with rx_offload disabled should be returned.
#[test]
fn ipv6_bad_checksum_returned() {
    let mut handler = new_handler(); // rx_offload = false
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(4);
    let mut rx = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(4);

    let src_v6 = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let dst_v6 = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    let _accept = handler.listen(IpAddress::V6(dst_v6), 80, 128).unwrap();

    let mut data = build_ipv6_tcp_frame(src_v6, dst_v6, 12345, 80, 1000, 0, flags::SYN, 65535, &[]);
    let tcp_off = ETH_LEN + IPV6_LEN;

    // Corrupt checksum.
    data[tcp_off + 16] ^= 0xFF;
    data[tcp_off + 17] ^= 0xFF;

    let len = data.len();
    let frame = Frame::new(800, leak(data), len, false);

    handler.process_ipv6(
        frame,
        tcp_off,
        Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert!(rx.pop().is_some(), "bad IPv6 checksum should be returned");
    assert!(tx.pop().is_none());
}
