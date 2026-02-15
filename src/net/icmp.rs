use std::mem::size_of;

use crate::xdp::frame::{Frame, FrameBuffer};

use super::{
    ethernet::EthernetFrame,
    ip::{IpProtocols, Ipv4Address},
    ipv4::{IPV4_MIN_HEADER_LEN, Ipv4Header, compute_ipv4_checksum},
    pmtu::PmtuCache,
};

/// ICMPv4 header length in bytes (type + code + checksum + rest-of-header).
pub const ICMPV4_HEADER_LEN: usize = 8;

const _: () = assert!(size_of::<Icmpv4Header>() == ICMPV4_HEADER_LEN);

/// ICMPv4 header wire format (8 bytes).
///
/// The `rest_of_header` field is type-dependent:
/// * Echo Request/Reply: identifier (2 bytes) + sequence number (2 bytes)
/// * Destination Unreachable: unused (2 bytes) + next-hop MTU (2 bytes, code 4 only)
/// * Time Exceeded / Parameter Problem: unused (4 bytes)
#[repr(C, packed)]
pub struct Icmpv4Header {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: [u8; 2],
    pub rest_of_header: [u8; 4],
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod Icmpv4Types {
    pub const EchoReply: u8 = 0;
    pub const DestinationUnreachable: u8 = 3;
    pub const SourceQuench: u8 = 4;
    pub const Redirect: u8 = 5;
    pub const EchoRequest: u8 = 8;
    pub const TimeExceeded: u8 = 11;
    pub const ParameterProblem: u8 = 12;
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod Icmpv4Codes {
    pub const ProtocolUnreachable: u8 = 2;
    pub const PortUnreachable: u8 = 3;
    pub const FragmentationNeeded: u8 = 4;
}

/// Returns `true` if the given ICMPv4 type is an error message.
///
/// Per RFC 1122, ICMP error messages MUST NOT be sent in response to
/// other ICMP error messages.
#[inline]
fn is_icmp_error(icmp_type: u8) -> bool {
    matches!(
        icmp_type,
        Icmpv4Types::DestinationUnreachable
            | Icmpv4Types::SourceQuench
            | Icmpv4Types::Redirect
            | Icmpv4Types::TimeExceeded
            | Icmpv4Types::ParameterProblem
    )
}

/// Processes an incoming ICMPv4 packet.
///
/// The frame must already be validated as a proper IPv4 packet with
/// `protocol = ICMP` by the [`Ipv4Handler`].
///
/// Currently handles:
/// * Echo Request (type 8) -> Echo Reply (type 0), pushed to `tx_return`.
/// * All other types are passed to `rx_return`.
pub fn handle_icmpv4<'umem>(
    mut frame: Frame<'umem>,
    pmtu: &mut PmtuCache,
    rx_return: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) {
    let ip = Ipv4Header::from_frame(&frame);
    let payload_offset = ip.payload_offset();
    let payload_len = ip.payload_len();
    let dst_addr = ip.dst_addr;

    if payload_len < ICMPV4_HEADER_LEN {
        eprintln!("icmpv4: payload too short ({} bytes)", payload_len);
        rx_return.push(frame);
        return;
    }

    let icmp_end = payload_offset + payload_len;

    if compute_ipv4_checksum(&frame[payload_offset..icmp_end]) != [0x00, 0x00] {
        eprintln!("icmpv4: invalid checksum");
        rx_return.push(frame);
        return;
    }

    let icmp_type = frame[payload_offset];

    match icmp_type {
        Icmpv4Types::EchoRequest => {
            // RFC 1122 §3.2.2.6: silently discard echo requests to
            // broadcast/multicast (prevents amplification attacks).
            if dst_addr.is_broadcast() || dst_addr.is_multicast() {
                rx_return.push(frame);
                return;
            }

            // Swap Ethernet MACs.
            let eth = EthernetFrame::from_frame_mut(&mut frame);
            let tmp_mac = eth.dst_mac;
            eth.dst_mac = eth.src_mac;
            eth.src_mac = tmp_mac;

            // Swap IPv4 addresses and reset TTL.
            let ip = Ipv4Header::from_frame_mut(&mut frame);
            let tmp_addr = ip.src_addr;
            ip.src_addr = ip.dst_addr;
            ip.dst_addr = tmp_addr;
            ip.ttl = 64;
            ip.fill_checksum();

            // Set ICMP type to Echo Reply and recompute checksum.
            frame[payload_offset] = Icmpv4Types::EchoReply;
            frame[payload_offset + 2] = 0;
            frame[payload_offset + 3] = 0;
            let cksum = compute_ipv4_checksum(&frame[payload_offset..icmp_end]);
            frame[payload_offset + 2] = cksum[0];
            frame[payload_offset + 3] = cksum[1];

            tx_return.push(frame);
        }
        Icmpv4Types::DestinationUnreachable
            if frame[payload_offset + 1] == Icmpv4Codes::FragmentationNeeded =>
        {
            // Extract next-hop MTU from rest-of-header bytes 6-7 (u16 big-endian).
            let mtu = u16::from_be_bytes([
                frame[payload_offset + 6],
                frame[payload_offset + 7],
            ]) as u32;

            // Extract original destination IP from embedded IP header.
            // The embedded IP header starts at payload_offset + ICMPV4_HEADER_LEN.
            // The destination address is at offset 16 within the IP header.
            let dst_offset = payload_offset + ICMPV4_HEADER_LEN + 16;
            if dst_offset + 4 <= frame.len() {
                let dst_ip = Ipv4Address::new([
                    frame[dst_offset],
                    frame[dst_offset + 1],
                    frame[dst_offset + 2],
                    frame[dst_offset + 3],
                ]);
                pmtu.update(dst_ip.into(), mtu);
            }

            rx_return.push(frame);
        }
        _ => rx_return.push(frame),
    }
}

/// Transforms a frame into an ICMPv4 Destination Unreachable response.
///
/// Per RFC 792, the ICMP error payload contains the original IPv4
/// header plus the first 8 bytes of the original datagram's data.
///
/// Per RFC 1122:
/// * MUST NOT send in response to a broadcast/multicast packet.
/// * MUST NOT send in response to an ICMP error message.
/// * MUST NOT send if the source address is not unicast.
/// * Source address of the response is the original packet's
///   destination (our address on the receiving interface).
///
/// If the response cannot be generated the frame goes to `rx_return`.
pub fn send_destination_unreachable<'umem>(
    mut frame: Frame<'umem>,
    code: u8,
    next_hop_mtu: u16,
    rx_return: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) {
    let eth_len = size_of::<EthernetFrame>();

    let ip = Ipv4Header::from_frame(&frame);
    let src_addr = ip.src_addr;
    let dst_addr = ip.dst_addr;
    let orig_header_len = ip.header_len();
    let orig_protocol = ip.protocol;
    let orig_payload_offset = ip.payload_offset();

    // RFC 1122: MUST NOT send ICMP error for broadcast/multicast.
    if dst_addr.is_broadcast() || dst_addr.is_multicast() {
        rx_return.push(frame);
        return;
    }

    // RFC 1122: MUST NOT send if source is not unicast.
    if src_addr.is_broadcast() || src_addr.is_multicast() || src_addr.is_unspecified() {
        rx_return.push(frame);
        return;
    }

    // RFC 792: MUST NOT send ICMP error in response to an ICMP error.
    if orig_protocol == IpProtocols::Icmp && frame.len() > orig_payload_offset {
        if is_icmp_error(frame[orig_payload_offset]) {
            rx_return.push(frame);
            return;
        }
    }

    // Save the original IP header + first 8 bytes of payload.
    // Max IP header is 60 bytes (IHL=15) plus 8 data bytes = 68 bytes.
    let orig_data_avail = frame.len().saturating_sub(eth_len + orig_header_len);
    let orig_data_bytes = orig_data_avail.min(8);
    let save_len = orig_header_len + orig_data_bytes;
    let mut saved = [0u8; 68];
    saved[..save_len].copy_from_slice(&frame[eth_len..eth_len + save_len]);

    // Compute new frame dimensions.
    let icmp_total_len = ICMPV4_HEADER_LEN + save_len;
    let new_ip_total_len = IPV4_MIN_HEADER_LEN + icmp_total_len;
    let new_frame_len = eth_len + new_ip_total_len;

    if new_frame_len > frame.capacity() {
        rx_return.push(frame);
        return;
    }

    // Extend frame to the new length so we can write into it.
    unsafe {
        frame.set_len(new_frame_len);
    }

    // Swap Ethernet MACs.
    let eth = EthernetFrame::from_frame_mut(&mut frame);
    let tmp_mac = eth.dst_mac;
    eth.dst_mac = eth.src_mac;
    eth.src_mac = tmp_mac;

    // Build the new IPv4 header (always 20 bytes, no options).
    let ip = Ipv4Header::from_frame_mut(&mut frame);
    ip.version_ihl = 0x45;
    ip.dscp_ecn = 0;
    ip.total_length = (new_ip_total_len as u16).to_be_bytes();
    ip.identification = [0, 0];
    ip.flags_fragment_offset = [0x40, 0x00]; // DF=1
    ip.ttl = 64;
    ip.protocol = IpProtocols::Icmp;
    ip.header_checksum = [0, 0];
    ip.src_addr = dst_addr; // our address
    ip.dst_addr = src_addr; // original sender
    ip.fill_checksum();

    // Build the ICMP header.
    let icmp_start = eth_len + IPV4_MIN_HEADER_LEN;
    frame[icmp_start] = Icmpv4Types::DestinationUnreachable;
    frame[icmp_start + 1] = code;
    frame[icmp_start + 2] = 0; // checksum (zero for computation)
    frame[icmp_start + 3] = 0;
    if code == Icmpv4Codes::FragmentationNeeded {
        frame[icmp_start + 4] = 0;
        frame[icmp_start + 5] = 0;
        frame[icmp_start + 6] = (next_hop_mtu >> 8) as u8;
        frame[icmp_start + 7] = next_hop_mtu as u8;
    } else {
        frame[icmp_start + 4] = 0;
        frame[icmp_start + 5] = 0;
        frame[icmp_start + 6] = 0;
        frame[icmp_start + 7] = 0;
    }

    // Copy the saved original data into the ICMP payload.
    let payload_start = icmp_start + ICMPV4_HEADER_LEN;
    frame[payload_start..payload_start + save_len].copy_from_slice(&saved[..save_len]);

    // Compute and write ICMP checksum.
    let icmp_end = icmp_start + icmp_total_len;
    let cksum = compute_ipv4_checksum(&frame[icmp_start..icmp_end]);
    frame[icmp_start + 2] = cksum[0];
    frame[icmp_start + 3] = cksum[1];

    tx_return.push(frame);
}

#[cfg(test)]
mod tests {
    use super::super::ethernet::MacAddress;
    use super::super::ip::Ipv4Address;
    use super::*;
    use crate::net::pmtu::PmtuCache;
    use crate::xdp::frame::BasicFrameBuffer;

    const SRC_MAC: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01];
    const DST_MAC: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x02];
    const REMOTE_IP: Ipv4Address = Ipv4Address::new([10, 0, 0, 2]);
    const LOCAL_IP: Ipv4Address = Ipv4Address::new([192, 168, 1, 1]);

    /// Builds a complete Ethernet + IPv4 + ICMP Echo Request frame.
    fn build_echo_request(
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        id: u16,
        seq: u16,
        data: &[u8],
    ) -> Vec<u8> {
        let eth_len = size_of::<EthernetFrame>();
        let icmp_len = ICMPV4_HEADER_LEN + data.len();
        let ip_total_len = (IPV4_MIN_HEADER_LEN + icmp_len) as u16;
        let frame_len = eth_len + IPV4_MIN_HEADER_LEN + icmp_len;
        let mut buf = vec![0u8; frame_len];

        // Ethernet header
        buf[0..6].copy_from_slice(&dst_mac);
        buf[6..12].copy_from_slice(&src_mac);
        buf[12] = 0x08;
        buf[13] = 0x00;

        // IPv4 header
        let ip = &mut buf[14..];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&ip_total_len.to_be_bytes());
        ip[6] = 0x40; // DF
        ip[8] = 64;
        ip[9] = IpProtocols::Icmp;
        let src_bytes: [u8; 4] = src_ip.into();
        ip[12..16].copy_from_slice(&src_bytes);
        let dst_bytes: [u8; 4] = dst_ip.into();
        ip[16..20].copy_from_slice(&dst_bytes);
        let cksum = compute_ipv4_checksum(&ip[..20]);
        ip[10] = cksum[0];
        ip[11] = cksum[1];

        // ICMP Echo Request
        let icmp_start = eth_len + IPV4_MIN_HEADER_LEN;
        buf[icmp_start] = Icmpv4Types::EchoRequest;
        buf[icmp_start + 1] = 0;
        buf[icmp_start + 4] = (id >> 8) as u8;
        buf[icmp_start + 5] = id as u8;
        buf[icmp_start + 6] = (seq >> 8) as u8;
        buf[icmp_start + 7] = seq as u8;
        buf[icmp_start + 8..].copy_from_slice(data);

        // ICMP checksum
        let icmp_end = icmp_start + icmp_len;
        let cksum = compute_ipv4_checksum(&buf[icmp_start..icmp_end]);
        buf[icmp_start + 2] = cksum[0];
        buf[icmp_start + 3] = cksum[1];

        buf
    }

    /// Builds a generic Ethernet + IPv4 frame (for destination unreachable tests).
    fn build_ipv4_frame(
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        protocol: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let eth_len = size_of::<EthernetFrame>();
        let ip_total_len = (IPV4_MIN_HEADER_LEN + payload.len()) as u16;
        let frame_len = eth_len + IPV4_MIN_HEADER_LEN + payload.len();
        let mut buf = vec![0u8; frame_len];

        buf[0..6].copy_from_slice(&dst_mac);
        buf[6..12].copy_from_slice(&src_mac);
        buf[12] = 0x08;
        buf[13] = 0x00;

        let ip = &mut buf[14..];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&ip_total_len.to_be_bytes());
        ip[6] = 0x40;
        ip[8] = 64;
        ip[9] = protocol;
        let src_bytes: [u8; 4] = src_ip.into();
        ip[12..16].copy_from_slice(&src_bytes);
        let dst_bytes: [u8; 4] = dst_ip.into();
        ip[16..20].copy_from_slice(&dst_bytes);
        let cksum = compute_ipv4_checksum(&ip[..20]);
        ip[10] = cksum[0];
        ip[11] = cksum[1];

        buf[eth_len + IPV4_MIN_HEADER_LEN..].copy_from_slice(payload);
        buf
    }

    #[test]
    fn echo_reply_goes_to_tx() {
        let echo = build_echo_request(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 1, 1, &[0xAB; 32]);
        // Allocate extra capacity so frame buffer can handle potential resizing.
        let mut buf = vec![0u8; 256];
        buf[..echo.len()].copy_from_slice(&echo);
        let frame = Frame::new(0, &mut buf, echo.len(), false);

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        handle_icmpv4(frame, &mut PmtuCache::new(), &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 0);
        assert_eq!(tx.num_frames(), 1);
    }

    #[test]
    fn echo_reply_has_correct_type() {
        let echo = build_echo_request(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 1, 1, &[0xAB; 8]);
        let mut buf = vec![0u8; 256];
        buf[..echo.len()].copy_from_slice(&echo);
        let frame = Frame::new(0, &mut buf, echo.len(), false);

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        handle_icmpv4(frame, &mut PmtuCache::new(), &mut rx, &mut tx);

        let reply = tx.pop().unwrap();
        let eth_len = size_of::<EthernetFrame>();
        let icmp_offset = eth_len + IPV4_MIN_HEADER_LEN;
        assert_eq!(reply[icmp_offset], Icmpv4Types::EchoReply);
        assert_eq!(reply[icmp_offset + 1], 0); // code
    }

    #[test]
    fn echo_reply_swaps_addresses() {
        let echo = build_echo_request(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 1, 1, &[0; 8]);
        let mut buf = vec![0u8; 256];
        buf[..echo.len()].copy_from_slice(&echo);
        let frame = Frame::new(0, &mut buf, echo.len(), false);

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        handle_icmpv4(frame, &mut PmtuCache::new(), &mut rx, &mut tx);

        let reply = tx.pop().unwrap();
        let eth = EthernetFrame::from_frame(&reply);

        // Ethernet MACs swapped
        assert_eq!(eth.src_mac, MacAddress::from(DST_MAC));
        assert_eq!(eth.dst_mac, MacAddress::from(SRC_MAC));

        // IPv4 addresses swapped
        let ip = Ipv4Header::from_frame(&reply);
        assert_eq!(ip.src_addr, LOCAL_IP);
        assert_eq!(ip.dst_addr, REMOTE_IP);
    }

    #[test]
    fn echo_reply_preserves_id_seq_data() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let echo = build_echo_request(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 0x1234, 0x0005, &data);
        let mut buf = vec![0u8; 256];
        buf[..echo.len()].copy_from_slice(&echo);
        let frame = Frame::new(0, &mut buf, echo.len(), false);

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        handle_icmpv4(frame, &mut PmtuCache::new(), &mut rx, &mut tx);

        let reply = tx.pop().unwrap();
        let icmp_offset = size_of::<EthernetFrame>() + IPV4_MIN_HEADER_LEN;

        // Identifier
        assert_eq!(reply[icmp_offset + 4], 0x12);
        assert_eq!(reply[icmp_offset + 5], 0x34);
        // Sequence
        assert_eq!(reply[icmp_offset + 6], 0x00);
        assert_eq!(reply[icmp_offset + 7], 0x05);
        // Data
        assert_eq!(&reply[icmp_offset + 8..icmp_offset + 16], &data);
    }

    #[test]
    fn echo_reply_has_valid_checksums() {
        let echo = build_echo_request(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 1, 1, &[0xFF; 56]);
        let mut buf = vec![0u8; 256];
        buf[..echo.len()].copy_from_slice(&echo);
        let frame = Frame::new(0, &mut buf, echo.len(), false);

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        handle_icmpv4(frame, &mut PmtuCache::new(), &mut rx, &mut tx);

        let reply = tx.pop().unwrap();
        let eth_len = size_of::<EthernetFrame>();

        // Verify IPv4 header checksum
        assert_eq!(
            compute_ipv4_checksum(&reply[eth_len..eth_len + IPV4_MIN_HEADER_LEN]),
            [0, 0]
        );

        // Verify ICMP checksum
        let ip = Ipv4Header::from_frame(&reply);
        let icmp_start = ip.payload_offset();
        let icmp_end = icmp_start + ip.payload_len();
        assert_eq!(compute_ipv4_checksum(&reply[icmp_start..icmp_end]), [0, 0]);
    }

    #[test]
    fn echo_reply_sets_ttl_64() {
        let echo = build_echo_request(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 1, 1, &[0; 8]);
        let mut buf = vec![0u8; 256];
        buf[..echo.len()].copy_from_slice(&echo);
        let frame = Frame::new(0, &mut buf, echo.len(), false);

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        handle_icmpv4(frame, &mut PmtuCache::new(), &mut rx, &mut tx);

        let reply = tx.pop().unwrap();
        let ip = Ipv4Header::from_frame(&reply);
        assert_eq!(ip.ttl, 64);
    }

    #[test]
    fn echo_request_bad_checksum_goes_to_rx() {
        let mut echo = build_echo_request(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 1, 1, &[0; 8]);
        let icmp_start = size_of::<EthernetFrame>() + IPV4_MIN_HEADER_LEN;
        echo[icmp_start + 2] ^= 0xFF; // corrupt checksum
        let mut buf = vec![0u8; 256];
        buf[..echo.len()].copy_from_slice(&echo);
        let frame = Frame::new(0, &mut buf, echo.len(), false);

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        handle_icmpv4(frame, &mut PmtuCache::new(), &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn echo_request_too_short_goes_to_rx() {
        // Build a frame with ICMP payload shorter than 8 bytes.
        let data = build_ipv4_frame(
            SRC_MAC,
            DST_MAC,
            REMOTE_IP,
            LOCAL_IP,
            IpProtocols::Icmp,
            &[0; 4],
        );
        let mut buf = vec![0u8; 256];
        buf[..data.len()].copy_from_slice(&data);
        let frame = Frame::new(0, &mut buf, data.len(), false);

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        handle_icmpv4(frame, &mut PmtuCache::new(), &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn echo_request_to_broadcast_goes_to_rx() {
        let bcast = Ipv4Address::broadcast();
        let echo = build_echo_request(SRC_MAC, DST_MAC, REMOTE_IP, bcast, 1, 1, &[0; 8]);
        let mut buf = vec![0u8; 256];
        buf[..echo.len()].copy_from_slice(&echo);
        let frame = Frame::new(0, &mut buf, echo.len(), false);

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        handle_icmpv4(frame, &mut PmtuCache::new(), &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn echo_request_to_multicast_goes_to_rx() {
        let mcast = Ipv4Address::new([224, 0, 0, 1]);
        let echo = build_echo_request(SRC_MAC, DST_MAC, REMOTE_IP, mcast, 1, 1, &[0; 8]);
        let mut buf = vec![0u8; 256];
        buf[..echo.len()].copy_from_slice(&echo);
        let frame = Frame::new(0, &mut buf, echo.len(), false);

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        handle_icmpv4(frame, &mut PmtuCache::new(), &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn non_echo_request_goes_to_rx() {
        // Build an ICMP Destination Unreachable (type 3) - should go to rx.
        let mut icmp_payload = [0u8; 36]; // 8 icmp hdr + 20 orig ip + 8 orig data
        icmp_payload[0] = Icmpv4Types::DestinationUnreachable;
        icmp_payload[1] = 0; // code
        // Leave checksum as 0 for now, recompute below
        let cksum = compute_ipv4_checksum(&icmp_payload);
        icmp_payload[2] = cksum[0];
        icmp_payload[3] = cksum[1];

        let data = build_ipv4_frame(
            SRC_MAC,
            DST_MAC,
            REMOTE_IP,
            LOCAL_IP,
            IpProtocols::Icmp,
            &icmp_payload,
        );
        let mut buf = vec![0u8; 256];
        buf[..data.len()].copy_from_slice(&data);
        let frame = Frame::new(0, &mut buf, data.len(), false);

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        handle_icmpv4(frame, &mut PmtuCache::new(), &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn dest_unreachable_goes_to_tx() {
        let data = build_ipv4_frame(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 99, &[0xAA; 32]);
        let mut buf = vec![0u8; 256];
        buf[..data.len()].copy_from_slice(&data);
        let frame = Frame::new(0, &mut buf, data.len(), false);

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        send_destination_unreachable(frame, Icmpv4Codes::ProtocolUnreachable, 0, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 0);
        assert_eq!(tx.num_frames(), 1);
    }

    #[test]
    fn dest_unreachable_has_correct_type_and_code() {
        let data = build_ipv4_frame(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 99, &[0; 32]);
        let mut buf = vec![0u8; 256];
        buf[..data.len()].copy_from_slice(&data);
        let frame = Frame::new(0, &mut buf, data.len(), false);

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        send_destination_unreachable(frame, Icmpv4Codes::ProtocolUnreachable, 0, &mut rx, &mut tx);

        let reply = tx.pop().unwrap();
        let icmp_start = size_of::<EthernetFrame>() + IPV4_MIN_HEADER_LEN;
        assert_eq!(reply[icmp_start], Icmpv4Types::DestinationUnreachable);
        assert_eq!(reply[icmp_start + 1], Icmpv4Codes::ProtocolUnreachable);
    }

    #[test]
    fn dest_unreachable_swaps_addresses() {
        let data = build_ipv4_frame(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 99, &[0; 32]);
        let mut buf = vec![0u8; 256];
        buf[..data.len()].copy_from_slice(&data);
        let frame = Frame::new(0, &mut buf, data.len(), false);

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        send_destination_unreachable(frame, Icmpv4Codes::ProtocolUnreachable, 0, &mut rx, &mut tx);

        let reply = tx.pop().unwrap();
        let eth = EthernetFrame::from_frame(&reply);
        assert_eq!(eth.src_mac, MacAddress::from(DST_MAC));
        assert_eq!(eth.dst_mac, MacAddress::from(SRC_MAC));

        let ip = Ipv4Header::from_frame(&reply);
        assert_eq!(ip.src_addr, LOCAL_IP);
        assert_eq!(ip.dst_addr, REMOTE_IP);
        assert_eq!(ip.protocol, IpProtocols::Icmp);
    }

    #[test]
    fn dest_unreachable_contains_original_header() {
        let payload = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA];
        let data = build_ipv4_frame(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 99, &payload);
        let mut buf = vec![0u8; 256];
        buf[..data.len()].copy_from_slice(&data);

        // Save the original IPv4 header bytes for comparison.
        let eth_len = size_of::<EthernetFrame>();
        let orig_ip_hdr: Vec<u8> = data[eth_len..eth_len + IPV4_MIN_HEADER_LEN].to_vec();
        let orig_first8: Vec<u8> = payload[..8].to_vec();

        let frame = Frame::new(0, &mut buf, data.len(), false);
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        send_destination_unreachable(frame, Icmpv4Codes::ProtocolUnreachable, 0, &mut rx, &mut tx);

        let reply = tx.pop().unwrap();
        let icmp_payload_start = eth_len + IPV4_MIN_HEADER_LEN + ICMPV4_HEADER_LEN;

        // Original IPv4 header preserved in ICMP payload
        assert_eq!(
            &reply[icmp_payload_start..icmp_payload_start + IPV4_MIN_HEADER_LEN],
            &orig_ip_hdr[..]
        );
        // First 8 bytes of original data preserved
        let data_start = icmp_payload_start + IPV4_MIN_HEADER_LEN;
        assert_eq!(&reply[data_start..data_start + 8], &orig_first8[..]);
    }

    #[test]
    fn dest_unreachable_has_valid_checksums() {
        let data = build_ipv4_frame(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 99, &[0; 32]);
        let mut buf = vec![0u8; 256];
        buf[..data.len()].copy_from_slice(&data);
        let frame = Frame::new(0, &mut buf, data.len(), false);

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        send_destination_unreachable(frame, Icmpv4Codes::ProtocolUnreachable, 0, &mut rx, &mut tx);

        let reply = tx.pop().unwrap();
        let eth_len = size_of::<EthernetFrame>();

        // Verify IPv4 header checksum
        assert_eq!(
            compute_ipv4_checksum(&reply[eth_len..eth_len + IPV4_MIN_HEADER_LEN]),
            [0, 0]
        );

        // Verify ICMP checksum
        let ip = Ipv4Header::from_frame(&reply);
        let icmp_start = ip.payload_offset();
        let icmp_end = icmp_start + ip.payload_len();
        assert_eq!(compute_ipv4_checksum(&reply[icmp_start..icmp_end]), [0, 0]);
    }

    #[test]
    fn dest_unreachable_fragmentation_needed_includes_mtu() {
        let data = build_ipv4_frame(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 17, &[0; 32]);
        let mut buf = vec![0u8; 256];
        buf[..data.len()].copy_from_slice(&data);
        let frame = Frame::new(0, &mut buf, data.len(), false);

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        send_destination_unreachable(
            frame,
            Icmpv4Codes::FragmentationNeeded,
            1280,
            &mut rx,
            &mut tx,
        );

        let reply = tx.pop().unwrap();
        let icmp_start = size_of::<EthernetFrame>() + IPV4_MIN_HEADER_LEN;
        // rest_of_header bytes 2-3 should contain the next-hop MTU (1280 = 0x0500)
        let mtu = u16::from_be_bytes([reply[icmp_start + 6], reply[icmp_start + 7]]);
        assert_eq!(mtu, 1280);
    }

    #[test]
    fn dest_unreachable_not_sent_for_broadcast_dst() {
        let bcast = Ipv4Address::broadcast();
        let data = build_ipv4_frame(SRC_MAC, DST_MAC, REMOTE_IP, bcast, 99, &[0; 32]);
        let mut buf = vec![0u8; 256];
        buf[..data.len()].copy_from_slice(&data);
        let frame = Frame::new(0, &mut buf, data.len(), false);

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        send_destination_unreachable(frame, Icmpv4Codes::ProtocolUnreachable, 0, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn dest_unreachable_not_sent_for_multicast_dst() {
        let mcast = Ipv4Address::new([224, 0, 0, 1]);
        let data = build_ipv4_frame(SRC_MAC, DST_MAC, REMOTE_IP, mcast, 99, &[0; 32]);
        let mut buf = vec![0u8; 256];
        buf[..data.len()].copy_from_slice(&data);
        let frame = Frame::new(0, &mut buf, data.len(), false);

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        send_destination_unreachable(frame, Icmpv4Codes::ProtocolUnreachable, 0, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn dest_unreachable_not_sent_for_broadcast_src() {
        let bcast_src = Ipv4Address::broadcast();
        let data = build_ipv4_frame(SRC_MAC, DST_MAC, bcast_src, LOCAL_IP, 99, &[0; 32]);
        let mut buf = vec![0u8; 256];
        buf[..data.len()].copy_from_slice(&data);
        let frame = Frame::new(0, &mut buf, data.len(), false);

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        send_destination_unreachable(frame, Icmpv4Codes::ProtocolUnreachable, 0, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn dest_unreachable_not_sent_for_unspecified_src() {
        let zero_src = Ipv4Address::unspecified();
        let data = build_ipv4_frame(SRC_MAC, DST_MAC, zero_src, LOCAL_IP, 99, &[0; 32]);
        let mut buf = vec![0u8; 256];
        buf[..data.len()].copy_from_slice(&data);
        let frame = Frame::new(0, &mut buf, data.len(), false);

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        send_destination_unreachable(frame, Icmpv4Codes::ProtocolUnreachable, 0, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn dest_unreachable_not_sent_for_icmp_error() {
        // Build a frame carrying an ICMP Destination Unreachable (type 3).
        let mut icmp_payload = [0u8; 36];
        icmp_payload[0] = Icmpv4Types::DestinationUnreachable;
        icmp_payload[1] = 0;
        let cksum = compute_ipv4_checksum(&icmp_payload);
        icmp_payload[2] = cksum[0];
        icmp_payload[3] = cksum[1];

        let data = build_ipv4_frame(
            SRC_MAC,
            DST_MAC,
            REMOTE_IP,
            LOCAL_IP,
            IpProtocols::Icmp,
            &icmp_payload,
        );
        let mut buf = vec![0u8; 256];
        buf[..data.len()].copy_from_slice(&data);
        let frame = Frame::new(0, &mut buf, data.len(), false);

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        send_destination_unreachable(frame, Icmpv4Codes::ProtocolUnreachable, 0, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn dest_unreachable_allowed_for_icmp_echo() {
        // An ICMP Echo Request is NOT an error, so we CAN send an error in
        // response to it (though unusual, it's not prohibited).
        let echo = build_echo_request(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 1, 1, &[0; 8]);
        let mut buf = vec![0u8; 256];
        buf[..echo.len()].copy_from_slice(&echo);
        let frame = Frame::new(0, &mut buf, echo.len(), false);

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        send_destination_unreachable(frame, Icmpv4Codes::ProtocolUnreachable, 0, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 0);
        assert_eq!(tx.num_frames(), 1);
    }
}
