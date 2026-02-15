use std::mem::size_of;

use crate::{
    net::NeighborHandler,
    xdp::frame::{Frame, FrameBuffer},
};

use super::{
    ethernet::EthernetFrame,
    ip::{IpProtocols, Ipv6Address},
    ipv6::{IPV6_HEADER_LEN, Ipv6Header},
    pmtu::PmtuCache,
};

/// ICMPv6 header length in bytes (type + code + checksum + body).
pub const ICMPV6_HEADER_LEN: usize = 8;

const _: () = assert!(size_of::<Icmpv6Header>() == ICMPV6_HEADER_LEN);

/// Minimum IPv6 MTU per RFC 2460.
const IPV6_MIN_MTU: usize = 1280;

/// Maximum bytes of the original packet that can be included in an
/// ICMPv6 error payload without exceeding the minimum IPv6 MTU.
/// 1280 (min MTU) - 40 (IPv6 header) - 8 (ICMPv6 header) = 1232.
const MAX_ERROR_PAYLOAD: usize = IPV6_MIN_MTU - IPV6_HEADER_LEN - ICMPV6_HEADER_LEN;

/// ICMPv6 header wire format (8 bytes).
///
/// The `body` field is type-dependent:
/// * Echo Request/Reply: identifier (2 bytes) + sequence number (2 bytes)
/// * Destination Unreachable: unused (4 bytes)
/// * Packet Too Big: MTU (4 bytes, network byte order)
/// * Time Exceeded: unused (4 bytes)
/// * Parameter Problem: pointer (4 bytes, network byte order)
#[repr(C, packed)]
pub struct Icmpv6Header {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: [u8; 2],
    pub body: [u8; 4],
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod Icmpv6Types {
    pub const DestinationUnreachable: u8 = 1;
    pub const PacketTooBig: u8 = 2;
    pub const TimeExceeded: u8 = 3;
    pub const ParameterProblem: u8 = 4;
    pub const EchoRequest: u8 = 128;
    pub const EchoReply: u8 = 129;
    pub const RouterSolicitation: u8 = 133;
    pub const RouterAdvertisement: u8 = 134;
    pub const NeighborSolicitation: u8 = 135;
    pub const NeighborAdvertisement: u8 = 136;
    pub const Redirect: u8 = 137;
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod Icmpv6Codes {
    pub const NoRouteToDestination: u8 = 0;
    pub const AdminProhibited: u8 = 1;
    pub const BeyondScope: u8 = 2;
    pub const AddressUnreachable: u8 = 3;
    pub const PortUnreachable: u8 = 4;
    pub const ErroneousHeaderField: u8 = 0;
    pub const UnrecognizedNextHeader: u8 = 1;
    pub const UnrecognizedOption: u8 = 2;
}

/// Returns `true` if the ICMPv6 type is an error message.
///
/// Per RFC 4443 §2.4, ICMPv6 error messages have types in the range
/// 0--127. Informational messages occupy 128--255.
#[inline]
fn is_icmpv6_error(icmpv6_type: u8) -> bool {
    icmpv6_type < 128
}

/// Computes the ICMPv6 checksum per RFC 4443 §2.3.
///
/// The checksum covers an IPv6 pseudo-header (source address,
/// destination address, upper-layer packet length, next header = 58)
/// followed by the ICMPv6 message data.
///
/// When computing a fresh checksum, zero the checksum field in
/// `icmpv6_data` first. When verifying, pass the data as-is and
/// check for a `[0x00, 0x00]` result.
pub(super) fn compute_icmpv6_checksum(
    src_addr: &Ipv6Address,
    dst_addr: &Ipv6Address,
    icmpv6_data: &[u8],
) -> [u8; 2] {
    let mut sum: u32 = 0;

    let src: [u8; 16] = (*src_addr).into();
    let mut i = 0;
    while i < 16 {
        sum += ((src[i] as u32) << 8) | (src[i + 1] as u32);
        i += 2;
    }

    let dst: [u8; 16] = (*dst_addr).into();
    i = 0;
    while i < 16 {
        sum += ((dst[i] as u32) << 8) | (dst[i + 1] as u32);
        i += 2;
    }

    let len = icmpv6_data.len() as u32;
    sum += (len >> 16) & 0xFFFF;
    sum += len & 0xFFFF;

    sum += IpProtocols::IcmpV6 as u32;

    i = 0;
    while i + 1 < icmpv6_data.len() {
        sum += ((icmpv6_data[i] as u32) << 8) | (icmpv6_data[i + 1] as u32);
        i += 2;
    }
    if i < icmpv6_data.len() {
        sum += (icmpv6_data[i] as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let checksum = !(sum as u16);
    checksum.to_be_bytes()
}

/// Processes an incoming ICMPv6 packet.
///
/// The frame must already be validated as a proper IPv6 packet with
/// an upper-layer protocol of ICMPv6 by the [`Ipv6Handler`].
///
/// `icmpv6_offset` is the byte offset from the start of the frame
/// to the ICMPv6 header (accounting for any extension headers).
/// `icmpv6_len` is the number of bytes in the ICMPv6 message.
///
/// Currently handles:
/// * Echo Request (type 128) -> Echo Reply (type 129), pushed to
///   `tx_return`.
/// * All other types (including NDP 133--137) pass to `rx_return`.
pub fn handle_icmpv6<'umem>(
    mut frame: Frame<'umem>,
    icmpv6_offset: usize,
    icmpv6_len: usize,
    neighbor_handler: &mut NeighborHandler,
    pmtu: &mut PmtuCache,
    rx_return: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) {
    if icmpv6_len < ICMPV6_HEADER_LEN {
        eprintln!("icmpv6: payload too short ({} bytes)", icmpv6_len);
        rx_return.push(frame);
        return;
    }

    let ip = Ipv6Header::from_frame(&frame);
    let src_addr = ip.src_addr;
    let dst_addr = ip.dst_addr;

    let icmpv6_end = icmpv6_offset + icmpv6_len;

    if compute_icmpv6_checksum(&src_addr, &dst_addr, &frame[icmpv6_offset..icmpv6_end])
        != [0x00, 0x00]
    {
        eprintln!("icmpv6: invalid checksum");
        rx_return.push(frame);
        return;
    }

    let icmpv6_type = frame[icmpv6_offset];

    match icmpv6_type {
        Icmpv6Types::EchoRequest => {
            // Silently discard echo requests to multicast destinations.
            // We cannot form a correct reply (source must be unicast, and
            // we do not track our own unicast address here).
            if dst_addr.is_multicast() {
                rx_return.push(frame);
                return;
            }

            // Swap Ethernet MACs.
            let eth = EthernetFrame::from_frame_mut(&mut frame);
            let tmp_mac = eth.dst_mac;
            eth.dst_mac = eth.src_mac;
            eth.src_mac = tmp_mac;

            // Swap IPv6 addresses and reset hop limit.
            let ip = Ipv6Header::from_frame_mut(&mut frame);
            let tmp_addr = ip.src_addr;
            ip.src_addr = ip.dst_addr;
            ip.dst_addr = tmp_addr;
            ip.hop_limit = 64;

            // Set ICMPv6 type to Echo Reply and recompute checksum.
            frame[icmpv6_offset] = Icmpv6Types::EchoReply;
            frame[icmpv6_offset + 2] = 0;
            frame[icmpv6_offset + 3] = 0;
            let cksum = compute_icmpv6_checksum(
                &dst_addr, // new src = old dst
                &src_addr, // new dst = old src
                &frame[icmpv6_offset..icmpv6_end],
            );
            frame[icmpv6_offset + 2] = cksum[0];
            frame[icmpv6_offset + 3] = cksum[1];

            tx_return.push(frame);
        }
        Icmpv6Types::PacketTooBig => {
            // Extract MTU from ICMPv6 header body bytes (u32 big-endian at offset+4).
            let mtu = u32::from_be_bytes([
                frame[icmpv6_offset + 4],
                frame[icmpv6_offset + 5],
                frame[icmpv6_offset + 6],
                frame[icmpv6_offset + 7],
            ]);

            // Extract original destination IP from embedded IPv6 header.
            // The embedded IPv6 header starts at icmpv6_offset + ICMPV6_HEADER_LEN.
            // The destination address is at offset 24 within the IPv6 header.
            let dst_offset = icmpv6_offset + ICMPV6_HEADER_LEN + 24;
            if dst_offset + 16 <= frame.len() {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&frame[dst_offset..dst_offset + 16]);
                let dst_ip = Ipv6Address::new(octets);
                pmtu.update(dst_ip.into(), mtu);
            }

            rx_return.push(frame);
        }
        Icmpv6Types::RouterSolicitation
        | Icmpv6Types::RouterAdvertisement
        | Icmpv6Types::NeighborSolicitation => {
            neighbor_handler.handle_ndp(frame, icmpv6_offset, icmpv6_len, rx_return, tx_return);
        }
        _ => rx_return.push(frame),
    }
}

/// Builds and sends an ICMPv6 error message by transforming the
/// incoming frame in-place.
///
/// Per RFC 4443, the error payload contains as much of the original
/// IPv6 packet as possible without exceeding the minimum IPv6 MTU
/// (1280 bytes).
///
/// RFC 4443 §2.4 restrictions:
/// * MUST NOT send in response to an ICMPv6 error message.
/// * MUST NOT send in response to a packet destined to a multicast
///   address (exceptions: Packet Too Big and Parameter Problem code 2
///   are allowed).
/// * MUST NOT send if the source address does not uniquely identify
///   a single node (multicast, unspecified).
///
/// `orig_upper_protocol` and `orig_upper_offset` identify the
/// upper-layer protocol and its byte offset from the frame start,
/// used to detect ICMPv6-error-in-response-to-error.
///
/// If the response cannot be generated the frame goes to `rx_return`.
pub fn send_icmpv6_error<'umem>(
    mut frame: Frame<'umem>,
    icmpv6_type: u8,
    code: u8,
    body: [u8; 4],
    orig_upper_protocol: u8,
    orig_upper_offset: usize,
    rx_return: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) {
    let eth_len = size_of::<EthernetFrame>();

    let ip = Ipv6Header::from_frame(&frame);
    let src_addr = ip.src_addr;
    let dst_addr = ip.dst_addr;
    let payload_length = ip.payload_length() as usize;

    // RFC 4443 §2.4(e): MUST NOT send if source is not unicast.
    if src_addr.is_multicast() || src_addr.is_unspecified() {
        rx_return.push(frame);
        return;
    }

    // RFC 4443 §2.4(e): MUST NOT send for multicast dst, with
    // exceptions for Packet Too Big and Parameter Problem code 2.
    if dst_addr.is_multicast() {
        let allowed = icmpv6_type == Icmpv6Types::PacketTooBig
            || (icmpv6_type == Icmpv6Types::ParameterProblem && code == Icmpv6Codes::BeyondScope);
        if !allowed {
            rx_return.push(frame);
            return;
        }
    }

    // RFC 4443 §2.4(e): MUST NOT send in response to an ICMPv6 error.
    if orig_upper_protocol == IpProtocols::IcmpV6
        && frame.len() > orig_upper_offset
        && is_icmpv6_error(frame[orig_upper_offset])
    {
        rx_return.push(frame);
        return;
    }

    // Compute how much of the original IPv6 packet to include.
    let orig_ipv6_len = IPV6_HEADER_LEN + payload_length;
    let save_len = orig_ipv6_len.min(MAX_ERROR_PAYLOAD);

    // New frame dimensions.
    let icmpv6_msg_len = ICMPV6_HEADER_LEN + save_len;
    let new_ipv6_payload_len = icmpv6_msg_len;
    let new_frame_len = eth_len + IPV6_HEADER_LEN + new_ipv6_payload_len;

    if new_frame_len > frame.capacity() {
        rx_return.push(frame);
        return;
    }

    // Set frame length to accommodate both the read (source data) and
    // the write (destination). The source data lives at eth_len..eth_len+save_len,
    // the destination starts at eth_len+IPV6_HEADER_LEN+ICMPV6_HEADER_LEN.
    let working_len = frame.len().max(new_frame_len);
    unsafe {
        frame.set_len(working_len);
    }

    // Shift the original IPv6 packet data into the ICMP payload area.
    let icmp_payload_start = eth_len + IPV6_HEADER_LEN + ICMPV6_HEADER_LEN;
    frame.copy_within(eth_len..eth_len + save_len, icmp_payload_start);

    // Swap Ethernet MACs.
    let eth = EthernetFrame::from_frame_mut(&mut frame);
    let tmp_mac = eth.dst_mac;
    eth.dst_mac = eth.src_mac;
    eth.src_mac = tmp_mac;

    // Build the new IPv6 header.
    let ip = Ipv6Header::from_frame_mut(&mut frame);
    ip.version_tc_fl = [0x60, 0x00, 0x00, 0x00];
    ip.payload_length = (new_ipv6_payload_len as u16).to_be_bytes();
    ip.next_header = IpProtocols::IcmpV6;
    ip.hop_limit = 64;
    ip.src_addr = dst_addr; // our address
    ip.dst_addr = src_addr; // original sender

    // Build the ICMPv6 header.
    let icmp_start = eth_len + IPV6_HEADER_LEN;
    frame[icmp_start] = icmpv6_type;
    frame[icmp_start + 1] = code;
    frame[icmp_start + 2] = 0; // checksum (zero for computation)
    frame[icmp_start + 3] = 0;
    frame[icmp_start + 4] = body[0];
    frame[icmp_start + 5] = body[1];
    frame[icmp_start + 6] = body[2];
    frame[icmp_start + 7] = body[3];

    // Truncate to the correct length before computing checksum.
    unsafe {
        frame.set_len(new_frame_len);
    }

    // Compute and write ICMPv6 checksum (over pseudo-header + message).
    let icmp_end = icmp_start + icmpv6_msg_len;
    let cksum = compute_icmpv6_checksum(
        &dst_addr, // new src
        &src_addr, // new dst
        &frame[icmp_start..icmp_end],
    );
    frame[icmp_start + 2] = cksum[0];
    frame[icmp_start + 3] = cksum[1];

    tx_return.push(frame);
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::super::ethernet::MacAddress;
    use super::*;
    use crate::net::pmtu::PmtuCache;
    use crate::xdp::frame::BasicFrameBuffer;

    const SRC_MAC: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01];
    const DST_MAC: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x02];
    const REMOTE_IP: Ipv6Address =
        Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    const LOCAL_IP: Ipv6Address =
        Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    /// Builds a complete Ethernet + IPv6 + ICMPv6 Echo Request frame.
    fn build_echo_request(
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        id: u16,
        seq: u16,
        data: &[u8],
    ) -> Vec<u8> {
        let eth_len = size_of::<EthernetFrame>();
        let icmpv6_len = ICMPV6_HEADER_LEN + data.len();
        let frame_len = eth_len + IPV6_HEADER_LEN + icmpv6_len;
        let mut buf = vec![0u8; frame_len];

        // Ethernet
        buf[0..6].copy_from_slice(&dst_mac);
        buf[6..12].copy_from_slice(&src_mac);
        buf[12] = 0x86;
        buf[13] = 0xDD;

        // IPv6
        buf[14] = 0x60;
        buf[18..20].copy_from_slice(&(icmpv6_len as u16).to_be_bytes());
        buf[20] = IpProtocols::IcmpV6;
        buf[21] = 64;
        let src_bytes: [u8; 16] = src_ip.into();
        buf[22..38].copy_from_slice(&src_bytes);
        let dst_bytes: [u8; 16] = dst_ip.into();
        buf[38..54].copy_from_slice(&dst_bytes);

        // ICMPv6 Echo Request
        let icmp_off = eth_len + IPV6_HEADER_LEN;
        buf[icmp_off] = Icmpv6Types::EchoRequest;
        buf[icmp_off + 1] = 0;
        buf[icmp_off + 4] = (id >> 8) as u8;
        buf[icmp_off + 5] = id as u8;
        buf[icmp_off + 6] = (seq >> 8) as u8;
        buf[icmp_off + 7] = seq as u8;
        buf[icmp_off + 8..].copy_from_slice(data);

        // ICMPv6 checksum
        buf[icmp_off + 2] = 0;
        buf[icmp_off + 3] = 0;
        let cksum = compute_icmpv6_checksum(&src_ip, &dst_ip, &buf[icmp_off..]);
        buf[icmp_off + 2] = cksum[0];
        buf[icmp_off + 3] = cksum[1];

        buf
    }

    /// Builds a generic Ethernet + IPv6 frame (for error-response tests).
    fn build_ipv6_frame(
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        next_header: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let eth_len = size_of::<EthernetFrame>();
        let frame_len = eth_len + IPV6_HEADER_LEN + payload.len();
        let mut buf = vec![0u8; frame_len];

        buf[0..6].copy_from_slice(&dst_mac);
        buf[6..12].copy_from_slice(&src_mac);
        buf[12] = 0x86;
        buf[13] = 0xDD;

        buf[14] = 0x60;
        buf[18..20].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        buf[20] = next_header;
        buf[21] = 64;
        let src_bytes: [u8; 16] = src_ip.into();
        buf[22..38].copy_from_slice(&src_bytes);
        let dst_bytes: [u8; 16] = dst_ip.into();
        buf[38..54].copy_from_slice(&dst_bytes);

        buf[eth_len + IPV6_HEADER_LEN..].copy_from_slice(payload);
        buf
    }

    #[test]
    fn echo_reply_goes_to_tx() {
        let echo = build_echo_request(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 1, 1, &[0xAB; 32]);
        let mut buf = vec![0u8; 512];
        buf[..echo.len()].copy_from_slice(&echo);
        let frame = Frame::new(0, &mut buf, echo.len(), false);

        let icmpv6_offset = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;
        let icmpv6_len = echo.len() - icmpv6_offset;

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        let mut neighbor_handler =
            NeighborHandler::new("test", MacAddress::from(SRC_MAC), Duration::from_secs(60))
                .unwrap();
        handle_icmpv6(
            frame,
            icmpv6_offset,
            icmpv6_len,
            &mut neighbor_handler,
            &mut PmtuCache::new(),
            &mut rx,
            &mut tx,
        );

        assert_eq!(rx.num_frames(), 0);
        assert_eq!(tx.num_frames(), 1);
    }

    #[test]
    fn echo_reply_has_correct_type() {
        let echo = build_echo_request(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 1, 1, &[0; 8]);
        let mut buf = vec![0u8; 512];
        buf[..echo.len()].copy_from_slice(&echo);
        let frame = Frame::new(0, &mut buf, echo.len(), false);

        let icmpv6_offset = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;
        let icmpv6_len = echo.len() - icmpv6_offset;

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        let mut neighbor_handler =
            NeighborHandler::new("test", MacAddress::from(SRC_MAC), Duration::from_secs(60))
                .unwrap();
        handle_icmpv6(
            frame,
            icmpv6_offset,
            icmpv6_len,
            &mut neighbor_handler,
            &mut PmtuCache::new(),
            &mut rx,
            &mut tx,
        );

        let reply = tx.pop().unwrap();
        assert_eq!(reply[icmpv6_offset], Icmpv6Types::EchoReply);
        assert_eq!(reply[icmpv6_offset + 1], 0);
    }

    #[test]
    fn echo_reply_swaps_addresses() {
        let echo = build_echo_request(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 1, 1, &[0; 8]);
        let mut buf = vec![0u8; 512];
        buf[..echo.len()].copy_from_slice(&echo);
        let frame = Frame::new(0, &mut buf, echo.len(), false);

        let icmpv6_offset = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;
        let icmpv6_len = echo.len() - icmpv6_offset;

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        let mut neighbor_handler =
            NeighborHandler::new("test", MacAddress::from(SRC_MAC), Duration::from_secs(60))
                .unwrap();
        handle_icmpv6(
            frame,
            icmpv6_offset,
            icmpv6_len,
            &mut neighbor_handler,
            &mut PmtuCache::new(),
            &mut rx,
            &mut tx,
        );

        let reply = tx.pop().unwrap();
        let eth = EthernetFrame::from_frame(&reply);
        assert_eq!(eth.src_mac, MacAddress::from(DST_MAC));
        assert_eq!(eth.dst_mac, MacAddress::from(SRC_MAC));

        let ip = Ipv6Header::from_frame(&reply);
        assert_eq!(ip.src_addr, LOCAL_IP);
        assert_eq!(ip.dst_addr, REMOTE_IP);
    }

    #[test]
    fn echo_reply_preserves_id_seq_data() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let echo = build_echo_request(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 0x1234, 0x0005, &data);
        let mut buf = vec![0u8; 512];
        buf[..echo.len()].copy_from_slice(&echo);
        let frame = Frame::new(0, &mut buf, echo.len(), false);

        let icmpv6_offset = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;
        let icmpv6_len = echo.len() - icmpv6_offset;

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        let mut neighbor_handler =
            NeighborHandler::new("test", MacAddress::from(SRC_MAC), Duration::from_secs(60))
                .unwrap();
        handle_icmpv6(
            frame,
            icmpv6_offset,
            icmpv6_len,
            &mut neighbor_handler,
            &mut PmtuCache::new(),
            &mut rx,
            &mut tx,
        );

        let reply = tx.pop().unwrap();
        assert_eq!(reply[icmpv6_offset + 4], 0x12);
        assert_eq!(reply[icmpv6_offset + 5], 0x34);
        assert_eq!(reply[icmpv6_offset + 6], 0x00);
        assert_eq!(reply[icmpv6_offset + 7], 0x05);
        assert_eq!(&reply[icmpv6_offset + 8..icmpv6_offset + 16], &data);
    }

    #[test]
    fn echo_reply_has_valid_checksum() {
        let echo = build_echo_request(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 1, 1, &[0xFF; 56]);
        let mut buf = vec![0u8; 512];
        buf[..echo.len()].copy_from_slice(&echo);
        let frame = Frame::new(0, &mut buf, echo.len(), false);

        let icmpv6_offset = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;
        let icmpv6_len = echo.len() - icmpv6_offset;

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        let mut neighbor_handler =
            NeighborHandler::new("test", MacAddress::from(SRC_MAC), Duration::from_secs(60))
                .unwrap();
        handle_icmpv6(
            frame,
            icmpv6_offset,
            icmpv6_len,
            &mut neighbor_handler,
            &mut PmtuCache::new(),
            &mut rx,
            &mut tx,
        );

        let reply = tx.pop().unwrap();
        let ip = Ipv6Header::from_frame(&reply);
        let cksum = compute_icmpv6_checksum(
            &ip.src_addr,
            &ip.dst_addr,
            &reply[icmpv6_offset..icmpv6_offset + icmpv6_len],
        );
        assert_eq!(cksum, [0x00, 0x00]);
    }

    #[test]
    fn echo_reply_sets_hop_limit_64() {
        let echo = build_echo_request(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 1, 1, &[0; 8]);
        let mut buf = vec![0u8; 512];
        buf[..echo.len()].copy_from_slice(&echo);
        let frame = Frame::new(0, &mut buf, echo.len(), false);

        let icmpv6_offset = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;
        let icmpv6_len = echo.len() - icmpv6_offset;

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        let mut neighbor_handler =
            NeighborHandler::new("test", MacAddress::from(SRC_MAC), Duration::from_secs(60))
                .unwrap();
        handle_icmpv6(
            frame,
            icmpv6_offset,
            icmpv6_len,
            &mut neighbor_handler,
            &mut PmtuCache::new(),
            &mut rx,
            &mut tx,
        );

        let reply = tx.pop().unwrap();
        let ip = Ipv6Header::from_frame(&reply);
        assert_eq!(ip.hop_limit, 64);
    }

    #[test]
    fn echo_request_bad_checksum_goes_to_rx() {
        let mut echo = build_echo_request(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 1, 1, &[0; 8]);
        let icmpv6_offset = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;
        echo[icmpv6_offset + 2] ^= 0xFF;
        let mut buf = vec![0u8; 512];
        buf[..echo.len()].copy_from_slice(&echo);
        let frame = Frame::new(0, &mut buf, echo.len(), false);

        let icmpv6_len = echo.len() - icmpv6_offset;

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        let mut neighbor_handler =
            NeighborHandler::new("test", MacAddress::from(SRC_MAC), Duration::from_secs(60))
                .unwrap();
        handle_icmpv6(
            frame,
            icmpv6_offset,
            icmpv6_len,
            &mut neighbor_handler,
            &mut PmtuCache::new(),
            &mut rx,
            &mut tx,
        );

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn echo_request_too_short_goes_to_rx() {
        let data = build_ipv6_frame(
            SRC_MAC,
            DST_MAC,
            REMOTE_IP,
            LOCAL_IP,
            IpProtocols::IcmpV6,
            &[0; 4],
        );
        let mut buf = vec![0u8; 512];
        buf[..data.len()].copy_from_slice(&data);
        let frame = Frame::new(0, &mut buf, data.len(), false);

        let icmpv6_offset = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        let mut neighbor_handler =
            NeighborHandler::new("test", MacAddress::from(SRC_MAC), Duration::from_secs(60))
                .unwrap();
        handle_icmpv6(
            frame,
            icmpv6_offset,
            4,
            &mut neighbor_handler,
            &mut PmtuCache::new(),
            &mut rx,
            &mut tx,
        );

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn echo_request_to_multicast_goes_to_rx() {
        let mcast = Ipv6Address::new([0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let echo = build_echo_request(SRC_MAC, DST_MAC, REMOTE_IP, mcast, 1, 1, &[0; 8]);
        let mut buf = vec![0u8; 512];
        buf[..echo.len()].copy_from_slice(&echo);
        let frame = Frame::new(0, &mut buf, echo.len(), false);

        let icmpv6_offset = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;
        let icmpv6_len = echo.len() - icmpv6_offset;

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        let mut neighbor_handler =
            NeighborHandler::new("test", MacAddress::from(SRC_MAC), Duration::from_secs(60))
                .unwrap();
        handle_icmpv6(
            frame,
            icmpv6_offset,
            icmpv6_len,
            &mut neighbor_handler,
            &mut PmtuCache::new(),
            &mut rx,
            &mut tx,
        );

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn non_echo_request_goes_to_rx() {
        // Build an ICMPv6 Destination Unreachable (type 1).
        let mut icmpv6_payload = [0u8; 48]; // 8 hdr + 40 orig ipv6 hdr
        icmpv6_payload[0] = Icmpv6Types::DestinationUnreachable;
        // Compute checksum.
        let cksum = compute_icmpv6_checksum(&REMOTE_IP, &LOCAL_IP, &icmpv6_payload);
        icmpv6_payload[2] = cksum[0];
        icmpv6_payload[3] = cksum[1];

        let data = build_ipv6_frame(
            SRC_MAC,
            DST_MAC,
            REMOTE_IP,
            LOCAL_IP,
            IpProtocols::IcmpV6,
            &icmpv6_payload,
        );
        let mut buf = vec![0u8; 512];
        buf[..data.len()].copy_from_slice(&data);
        let frame = Frame::new(0, &mut buf, data.len(), false);

        let icmpv6_offset = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;
        let icmpv6_len = icmpv6_payload.len();

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        let mut neighbor_handler =
            NeighborHandler::new("test", MacAddress::from(SRC_MAC), Duration::from_secs(60))
                .unwrap();
        handle_icmpv6(
            frame,
            icmpv6_offset,
            icmpv6_len,
            &mut neighbor_handler,
            &mut PmtuCache::new(),
            &mut rx,
            &mut tx,
        );

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    // -- send_icmpv6_error tests ---------------------------------------------

    #[test]
    fn error_goes_to_tx() {
        let data = build_ipv6_frame(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 99, &[0xAA; 32]);
        let mut buf = vec![0u8; 2048];
        buf[..data.len()].copy_from_slice(&data);
        let frame = Frame::new(0, &mut buf, data.len(), false);

        let upper_offset = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        send_icmpv6_error(
            frame,
            Icmpv6Types::ParameterProblem,
            Icmpv6Codes::UnrecognizedNextHeader,
            6u32.to_be_bytes(),
            99,
            upper_offset,
            &mut rx,
            &mut tx,
        );

        assert_eq!(rx.num_frames(), 0);
        assert_eq!(tx.num_frames(), 1);
    }

    #[test]
    fn error_has_correct_type_and_code() {
        let data = build_ipv6_frame(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 99, &[0; 32]);
        let mut buf = vec![0u8; 2048];
        buf[..data.len()].copy_from_slice(&data);
        let frame = Frame::new(0, &mut buf, data.len(), false);

        let upper_offset = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        send_icmpv6_error(
            frame,
            Icmpv6Types::DestinationUnreachable,
            Icmpv6Codes::PortUnreachable,
            [0; 4],
            99,
            upper_offset,
            &mut rx,
            &mut tx,
        );

        let reply = tx.pop().unwrap();
        let icmp_start = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;
        assert_eq!(reply[icmp_start], Icmpv6Types::DestinationUnreachable);
        assert_eq!(reply[icmp_start + 1], Icmpv6Codes::PortUnreachable);
    }

    #[test]
    fn error_swaps_addresses() {
        let data = build_ipv6_frame(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 99, &[0; 32]);
        let mut buf = vec![0u8; 2048];
        buf[..data.len()].copy_from_slice(&data);
        let frame = Frame::new(0, &mut buf, data.len(), false);

        let upper_offset = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        send_icmpv6_error(
            frame,
            Icmpv6Types::DestinationUnreachable,
            Icmpv6Codes::NoRouteToDestination,
            [0; 4],
            99,
            upper_offset,
            &mut rx,
            &mut tx,
        );

        let reply = tx.pop().unwrap();
        let eth = EthernetFrame::from_frame(&reply);
        assert_eq!(eth.src_mac, MacAddress::from(DST_MAC));
        assert_eq!(eth.dst_mac, MacAddress::from(SRC_MAC));

        let ip = Ipv6Header::from_frame(&reply);
        assert_eq!(ip.src_addr, LOCAL_IP);
        assert_eq!(ip.dst_addr, REMOTE_IP);
        assert_eq!(ip.next_header, IpProtocols::IcmpV6);
    }

    #[test]
    fn error_contains_original_ipv6_header() {
        let payload = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let data = build_ipv6_frame(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 99, &payload);
        let mut buf = vec![0u8; 2048];
        buf[..data.len()].copy_from_slice(&data);

        let eth_len = size_of::<EthernetFrame>();
        // Save the original IPv6 header + payload for comparison.
        let orig_ipv6_packet: Vec<u8> = data[eth_len..].to_vec();

        let frame = Frame::new(0, &mut buf, data.len(), false);
        let upper_offset = eth_len + IPV6_HEADER_LEN;

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        send_icmpv6_error(
            frame,
            Icmpv6Types::DestinationUnreachable,
            Icmpv6Codes::NoRouteToDestination,
            [0; 4],
            99,
            upper_offset,
            &mut rx,
            &mut tx,
        );

        let reply = tx.pop().unwrap();
        let icmp_payload_start = eth_len + IPV6_HEADER_LEN + ICMPV6_HEADER_LEN;
        let icmp_payload_end = icmp_payload_start + orig_ipv6_packet.len();
        assert_eq!(
            &reply[icmp_payload_start..icmp_payload_end],
            &orig_ipv6_packet[..]
        );
    }

    #[test]
    fn error_has_valid_checksum() {
        let data = build_ipv6_frame(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 99, &[0; 32]);
        let mut buf = vec![0u8; 2048];
        buf[..data.len()].copy_from_slice(&data);
        let frame = Frame::new(0, &mut buf, data.len(), false);
        let upper_offset = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        send_icmpv6_error(
            frame,
            Icmpv6Types::DestinationUnreachable,
            Icmpv6Codes::PortUnreachable,
            [0; 4],
            99,
            upper_offset,
            &mut rx,
            &mut tx,
        );

        let reply = tx.pop().unwrap();
        let ip = Ipv6Header::from_frame(&reply);
        let icmp_start = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;
        let icmp_end = icmp_start + ip.payload_length() as usize;
        let cksum =
            compute_icmpv6_checksum(&ip.src_addr, &ip.dst_addr, &reply[icmp_start..icmp_end]);
        assert_eq!(cksum, [0x00, 0x00]);
    }

    #[test]
    fn error_packet_too_big_includes_mtu() {
        let data = build_ipv6_frame(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 17, &[0; 32]);
        let mut buf = vec![0u8; 2048];
        buf[..data.len()].copy_from_slice(&data);
        let frame = Frame::new(0, &mut buf, data.len(), false);
        let upper_offset = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;

        let mtu: u32 = 1280;
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        send_icmpv6_error(
            frame,
            Icmpv6Types::PacketTooBig,
            0,
            mtu.to_be_bytes(),
            17,
            upper_offset,
            &mut rx,
            &mut tx,
        );

        let reply = tx.pop().unwrap();
        let icmp_start = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;
        let body_mtu = u32::from_be_bytes([
            reply[icmp_start + 4],
            reply[icmp_start + 5],
            reply[icmp_start + 6],
            reply[icmp_start + 7],
        ]);
        assert_eq!(body_mtu, 1280);
    }

    #[test]
    fn error_parameter_problem_includes_pointer() {
        let data = build_ipv6_frame(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 99, &[0; 32]);
        let mut buf = vec![0u8; 2048];
        buf[..data.len()].copy_from_slice(&data);
        let frame = Frame::new(0, &mut buf, data.len(), false);
        let upper_offset = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;

        let pointer: u32 = 6;
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        send_icmpv6_error(
            frame,
            Icmpv6Types::ParameterProblem,
            Icmpv6Codes::UnrecognizedNextHeader,
            pointer.to_be_bytes(),
            99,
            upper_offset,
            &mut rx,
            &mut tx,
        );

        let reply = tx.pop().unwrap();
        let icmp_start = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;
        let body_ptr = u32::from_be_bytes([
            reply[icmp_start + 4],
            reply[icmp_start + 5],
            reply[icmp_start + 6],
            reply[icmp_start + 7],
        ]);
        assert_eq!(body_ptr, 6);
    }

    #[test]
    fn error_not_sent_for_multicast_dst() {
        let mcast = Ipv6Address::new([0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let data = build_ipv6_frame(SRC_MAC, DST_MAC, REMOTE_IP, mcast, 99, &[0; 32]);
        let mut buf = vec![0u8; 2048];
        buf[..data.len()].copy_from_slice(&data);
        let frame = Frame::new(0, &mut buf, data.len(), false);
        let upper_offset = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        send_icmpv6_error(
            frame,
            Icmpv6Types::DestinationUnreachable,
            Icmpv6Codes::NoRouteToDestination,
            [0; 4],
            99,
            upper_offset,
            &mut rx,
            &mut tx,
        );

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn error_packet_too_big_allowed_for_multicast_dst() {
        let mcast = Ipv6Address::new([0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let data = build_ipv6_frame(SRC_MAC, DST_MAC, REMOTE_IP, mcast, 17, &[0; 32]);
        let mut buf = vec![0u8; 2048];
        buf[..data.len()].copy_from_slice(&data);
        let frame = Frame::new(0, &mut buf, data.len(), false);
        let upper_offset = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        send_icmpv6_error(
            frame,
            Icmpv6Types::PacketTooBig,
            0,
            1280u32.to_be_bytes(),
            17,
            upper_offset,
            &mut rx,
            &mut tx,
        );

        assert_eq!(rx.num_frames(), 0);
        assert_eq!(tx.num_frames(), 1);
    }

    #[test]
    fn error_not_sent_for_multicast_src() {
        let mcast_src = Ipv6Address::new([0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let data = build_ipv6_frame(SRC_MAC, DST_MAC, mcast_src, LOCAL_IP, 99, &[0; 32]);
        let mut buf = vec![0u8; 2048];
        buf[..data.len()].copy_from_slice(&data);
        let frame = Frame::new(0, &mut buf, data.len(), false);
        let upper_offset = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        send_icmpv6_error(
            frame,
            Icmpv6Types::DestinationUnreachable,
            Icmpv6Codes::NoRouteToDestination,
            [0; 4],
            99,
            upper_offset,
            &mut rx,
            &mut tx,
        );

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn error_not_sent_for_unspecified_src() {
        let unspec = Ipv6Address::unspecified();
        let data = build_ipv6_frame(SRC_MAC, DST_MAC, unspec, LOCAL_IP, 99, &[0; 32]);
        let mut buf = vec![0u8; 2048];
        buf[..data.len()].copy_from_slice(&data);
        let frame = Frame::new(0, &mut buf, data.len(), false);
        let upper_offset = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        send_icmpv6_error(
            frame,
            Icmpv6Types::DestinationUnreachable,
            Icmpv6Codes::NoRouteToDestination,
            [0; 4],
            99,
            upper_offset,
            &mut rx,
            &mut tx,
        );

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn error_not_sent_for_icmpv6_error() {
        // Build a frame carrying an ICMPv6 Destination Unreachable (type 1).
        let mut icmpv6_payload = [0u8; 48];
        icmpv6_payload[0] = Icmpv6Types::DestinationUnreachable;
        let cksum = compute_icmpv6_checksum(&REMOTE_IP, &LOCAL_IP, &icmpv6_payload);
        icmpv6_payload[2] = cksum[0];
        icmpv6_payload[3] = cksum[1];

        let data = build_ipv6_frame(
            SRC_MAC,
            DST_MAC,
            REMOTE_IP,
            LOCAL_IP,
            IpProtocols::IcmpV6,
            &icmpv6_payload,
        );
        let mut buf = vec![0u8; 2048];
        buf[..data.len()].copy_from_slice(&data);
        let frame = Frame::new(0, &mut buf, data.len(), false);
        let upper_offset = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        send_icmpv6_error(
            frame,
            Icmpv6Types::DestinationUnreachable,
            Icmpv6Codes::PortUnreachable,
            [0; 4],
            IpProtocols::IcmpV6,
            upper_offset,
            &mut rx,
            &mut tx,
        );

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn error_allowed_for_icmpv6_echo() {
        // An ICMPv6 Echo Request (type 128) is NOT an error.
        let echo = build_echo_request(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 1, 1, &[0; 8]);
        let mut buf = vec![0u8; 2048];
        buf[..echo.len()].copy_from_slice(&echo);
        let frame = Frame::new(0, &mut buf, echo.len(), false);
        let upper_offset = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        send_icmpv6_error(
            frame,
            Icmpv6Types::DestinationUnreachable,
            Icmpv6Codes::PortUnreachable,
            [0; 4],
            IpProtocols::IcmpV6,
            upper_offset,
            &mut rx,
            &mut tx,
        );

        assert_eq!(rx.num_frames(), 0);
        assert_eq!(tx.num_frames(), 1);
    }

    #[test]
    fn checksum_roundtrip() {
        let src = Ipv6Address::new([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = Ipv6Address::new([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let mut msg = [0u8; 16];
        msg[0] = Icmpv6Types::EchoRequest;
        msg[4] = 0x00;
        msg[5] = 0x01;
        msg[6] = 0x00;
        msg[7] = 0x01;

        let cksum = compute_icmpv6_checksum(&src, &dst, &msg);
        msg[2] = cksum[0];
        msg[3] = cksum[1];

        let verify = compute_icmpv6_checksum(&src, &dst, &msg);
        assert_eq!(verify, [0x00, 0x00]);
    }
}
