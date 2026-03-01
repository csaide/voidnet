use std::time::Instant;

use crate::{
    net::PmtuCache,
    xdp::frame::{Frame, FrameBuffer},
};

use super::wire::{
    ethernet::EthernetFrame,
    icmpv4::{
        ICMPV4_HEADER_LEN, Icmpv4Codes, Icmpv4Frame, Icmpv4Header, Icmpv4Types, is_icmp_error,
    },
    ip::{IPV4_MIN_HEADER_LEN, IpProtocols, Ipv4Address, Ipv4Header, compute_ipv4_checksum},
};

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
    pmtu: &PmtuCache,
    now: Instant,
    rx_return: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) {
    let ip = Ipv4Header::from_bytes(&frame);
    let payload_offset = ip.payload_offset();
    let payload_len = ip.payload_len();
    let dst_addr = ip.dst_addr;

    if payload_len < ICMPV4_HEADER_LEN {
        rx_return.push(frame);
        return;
    }

    let icmp_end = payload_offset + payload_len;

    if compute_ipv4_checksum(&frame[payload_offset..icmp_end]) != [0x00, 0x00] {
        rx_return.push(frame);
        return;
    }

    let icmp = Icmpv4Header::from_bytes_at(&frame, payload_offset);
    let icmp_type = icmp.icmp_type;
    let icmp_code = icmp.code;

    match icmp_type {
        Icmpv4Types::EchoRequest => {
            // RFC 1122 §3.2.2.6: silently discard echo requests to
            // broadcast/multicast (prevents amplification attacks).
            if dst_addr.is_broadcast() || dst_addr.is_multicast() {
                rx_return.push(frame);
                return;
            }

            // Swap Ethernet MACs.
            let eth = EthernetFrame::from_bytes_mut(&mut frame);
            let tmp_mac = eth.dst_mac;
            eth.dst_mac = eth.src_mac;
            eth.src_mac = tmp_mac;

            // Swap IPv4 addresses and reset TTL.
            let ip = Ipv4Header::from_bytes_mut(&mut frame);
            let tmp_addr = ip.src_addr;
            ip.src_addr = ip.dst_addr;
            ip.dst_addr = tmp_addr;
            ip.ttl = 64;
            ip.fill_checksum();

            // Set ICMP type to Echo Reply and recompute checksum.
            let icmp = Icmpv4Header::from_bytes_at_mut(&mut frame, payload_offset);
            icmp.icmp_type = Icmpv4Types::EchoReply;
            icmp.checksum = [0, 0];
            let cksum = compute_ipv4_checksum(&frame[payload_offset..icmp_end]);
            Icmpv4Header::from_bytes_at_mut(&mut frame, payload_offset).checksum = cksum;

            tx_return.push(frame);
        }
        Icmpv4Types::DestinationUnreachable if icmp_code == Icmpv4Codes::FragmentationNeeded => {
            // Extract next-hop MTU from the ICMP header.
            let icmp = Icmpv4Header::from_bytes_at(&frame, payload_offset);
            let mtu = icmp.next_hop_mtu() as u32;

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
                pmtu.update(now, dst_ip.into(), mtu);
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

    let ip = Ipv4Header::from_bytes(&frame);
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

    // Build Ethernet + IPv4 + ICMP headers via struct overlay.
    let icmp_start = eth_len + IPV4_MIN_HEADER_LEN;
    {
        let pkt = Icmpv4Frame::from_bytes_mut(&mut frame);

        // Swap Ethernet MACs.
        let tmp_mac = pkt.ethernet.dst_mac;
        pkt.ethernet.dst_mac = pkt.ethernet.src_mac;
        pkt.ethernet.src_mac = tmp_mac;

        // Build the new IPv4 header (always 20 bytes, no options).
        pkt.ipv4.version_ihl = 0x45;
        pkt.ipv4.dscp_ecn = 0;
        pkt.ipv4.total_length = (new_ip_total_len as u16).to_be_bytes();
        pkt.ipv4.identification = [0, 0];
        pkt.ipv4.flags_fragment_offset = [0x40, 0x00]; // DF=1
        pkt.ipv4.ttl = 64;
        pkt.ipv4.protocol = IpProtocols::Icmp;
        pkt.ipv4.header_checksum = [0, 0];
        pkt.ipv4.src_addr = dst_addr; // our address
        pkt.ipv4.dst_addr = src_addr; // original sender
        pkt.ipv4.fill_checksum();

        // Build the ICMP header.
        pkt.icmpv4.icmp_type = Icmpv4Types::DestinationUnreachable;
        pkt.icmpv4.code = code;
        pkt.icmpv4.checksum = [0, 0];
        if code == Icmpv4Codes::FragmentationNeeded {
            pkt.icmpv4.rest_of_header = [0, 0, (next_hop_mtu >> 8) as u8, next_hop_mtu as u8];
        } else {
            pkt.icmpv4.rest_of_header = [0, 0, 0, 0];
        }
    }

    // Copy the saved original data into the ICMP payload.
    let payload_start = icmp_start + ICMPV4_HEADER_LEN;
    frame[payload_start..payload_start + save_len].copy_from_slice(&saved[..save_len]);

    // Compute and write ICMP checksum.
    let icmp_end = icmp_start + icmp_total_len;
    let cksum = compute_ipv4_checksum(&frame[icmp_start..icmp_end]);
    Icmpv4Header::from_bytes_at_mut(&mut frame, icmp_start).checksum = cksum;

    tx_return.push(frame);
}

#[cfg(test)]
mod tests {
    use super::super::wire::ethernet::MacAddress;
    use super::super::wire::ip::{IpAddress, Ipv4Address};
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

        buf[0..6].copy_from_slice(&dst_mac);
        buf[6..12].copy_from_slice(&src_mac);
        buf[12] = 0x08;
        buf[13] = 0x00;

        let ip = &mut buf[14..];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&ip_total_len.to_be_bytes());
        ip[6] = 0x40;
        ip[8] = 64;
        ip[9] = IpProtocols::Icmp;
        let src_bytes: [u8; 4] = src_ip.into();
        ip[12..16].copy_from_slice(&src_bytes);
        let dst_bytes: [u8; 4] = dst_ip.into();
        ip[16..20].copy_from_slice(&dst_bytes);
        let cksum = compute_ipv4_checksum(&ip[..20]);
        ip[10] = cksum[0];
        ip[11] = cksum[1];

        let icmp_start = eth_len + IPV4_MIN_HEADER_LEN;
        buf[icmp_start] = Icmpv4Types::EchoRequest;
        buf[icmp_start + 4] = (id >> 8) as u8;
        buf[icmp_start + 5] = id as u8;
        buf[icmp_start + 6] = (seq >> 8) as u8;
        buf[icmp_start + 7] = seq as u8;
        buf[icmp_start + 8..].copy_from_slice(data);

        let icmp_end = icmp_start + icmp_len;
        let cksum = compute_ipv4_checksum(&buf[icmp_start..icmp_end]);
        buf[icmp_start + 2] = cksum[0];
        buf[icmp_start + 3] = cksum[1];

        buf
    }

    /// Builds a generic Ethernet + IPv4 frame.
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

    /// Helper: asserts frame was rejected (goes to rx, not tx).
    fn assert_rejected(rx: &BasicFrameBuffer, tx: &BasicFrameBuffer) {
        assert_eq!(rx.num_frames(), 1, "expected frame in rx_return");
        assert_eq!(tx.num_frames(), 0, "expected nothing in tx_return");
    }

    // -- Echo Reply tests --

    #[test]
    fn echo_reply_complete_response() {
        let now = Instant::now();
        let data = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let echo = build_echo_request(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 0x1234, 0x0005, &data);
        let mut buf = vec![0u8; 256];
        buf[..echo.len()].copy_from_slice(&echo);
        let frame = Frame::new(0, &mut buf, echo.len(), false);

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        handle_icmpv4(frame, &mut PmtuCache::new(), now, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 0);
        assert_eq!(tx.num_frames(), 1);

        let reply = tx.pop().unwrap();
        let eth_len = size_of::<EthernetFrame>();
        let icmp_offset = eth_len + IPV4_MIN_HEADER_LEN;

        // Type and code
        assert_eq!(reply[icmp_offset], Icmpv4Types::EchoReply);
        assert_eq!(reply[icmp_offset + 1], 0);

        // Ethernet MACs swapped
        let eth = EthernetFrame::from_bytes(&reply);
        assert_eq!(eth.src_mac, MacAddress::from(DST_MAC));
        assert_eq!(eth.dst_mac, MacAddress::from(SRC_MAC));

        // IPv4 addresses swapped, TTL reset
        let ip = Ipv4Header::from_bytes(&reply);
        assert_eq!(ip.src_addr, LOCAL_IP);
        assert_eq!(ip.dst_addr, REMOTE_IP);
        assert_eq!(ip.ttl, 64);

        // Identifier and sequence preserved
        assert_eq!(reply[icmp_offset + 4], 0x12);
        assert_eq!(reply[icmp_offset + 5], 0x34);
        assert_eq!(reply[icmp_offset + 6], 0x00);
        assert_eq!(reply[icmp_offset + 7], 0x05);
        assert_eq!(&reply[icmp_offset + 8..icmp_offset + 16], &data);

        // Valid IPv4 header checksum
        assert_eq!(
            compute_ipv4_checksum(&reply[eth_len..eth_len + IPV4_MIN_HEADER_LEN]),
            [0, 0]
        );

        // Valid ICMP checksum
        let icmp_start = ip.payload_offset();
        let icmp_end = icmp_start + ip.payload_len();
        assert_eq!(compute_ipv4_checksum(&reply[icmp_start..icmp_end]), [0, 0]);
    }

    #[test]
    fn echo_request_bad_checksum_rejected() {
        let now = Instant::now();
        let mut echo = build_echo_request(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 1, 1, &[0; 8]);
        let icmp_start = size_of::<EthernetFrame>() + IPV4_MIN_HEADER_LEN;
        echo[icmp_start + 2] ^= 0xFF;
        let mut buf = vec![0u8; 256];
        buf[..echo.len()].copy_from_slice(&echo);
        let frame = Frame::new(0, &mut buf, echo.len(), false);

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        handle_icmpv4(frame, &mut PmtuCache::new(), now, &mut rx, &mut tx);
        assert_rejected(&rx, &tx);
    }

    #[test]
    fn echo_request_too_short_rejected() {
        let now = Instant::now();
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
        handle_icmpv4(frame, &mut PmtuCache::new(), now, &mut rx, &mut tx);
        assert_rejected(&rx, &tx);
    }

    #[test]
    fn echo_request_broadcast_multicast_rejected() {
        let now = Instant::now();
        // Broadcast destination
        let echo = build_echo_request(
            SRC_MAC,
            DST_MAC,
            REMOTE_IP,
            Ipv4Address::broadcast(),
            1,
            1,
            &[0; 8],
        );
        let mut buf = vec![0u8; 256];
        buf[..echo.len()].copy_from_slice(&echo);
        let frame = Frame::new(0, &mut buf, echo.len(), false);
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        handle_icmpv4(frame, &mut PmtuCache::new(), now, &mut rx, &mut tx);
        assert_rejected(&rx, &tx);

        // Multicast destination
        let echo = build_echo_request(
            SRC_MAC,
            DST_MAC,
            REMOTE_IP,
            Ipv4Address::new([224, 0, 0, 1]),
            1,
            1,
            &[0; 8],
        );
        let mut buf = vec![0u8; 256];
        buf[..echo.len()].copy_from_slice(&echo);
        let frame = Frame::new(0, &mut buf, echo.len(), false);
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        handle_icmpv4(frame, &mut PmtuCache::new(), now, &mut rx, &mut tx);
        assert_rejected(&rx, &tx);
    }

    #[test]
    fn non_echo_goes_to_rx() {
        let now = Instant::now();
        let mut icmp_payload = [0u8; 36];
        icmp_payload[0] = Icmpv4Types::DestinationUnreachable;
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
        handle_icmpv4(frame, &mut PmtuCache::new(), now, &mut rx, &mut tx);
        assert_rejected(&rx, &tx);
    }

    // -- Destination Unreachable tests --

    #[test]
    fn dest_unreachable_complete_response() {
        let payload = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA];
        let data = build_ipv4_frame(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 99, &payload);
        let mut buf = vec![0u8; 256];
        buf[..data.len()].copy_from_slice(&data);

        let eth_len = size_of::<EthernetFrame>();
        let orig_ip_hdr: Vec<u8> = data[eth_len..eth_len + IPV4_MIN_HEADER_LEN].to_vec();
        let orig_first8: Vec<u8> = payload[..8].to_vec();

        let frame = Frame::new(0, &mut buf, data.len(), false);
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        send_destination_unreachable(frame, Icmpv4Codes::ProtocolUnreachable, 0, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 0);
        assert_eq!(tx.num_frames(), 1);

        let reply = tx.pop().unwrap();
        let icmp_start = eth_len + IPV4_MIN_HEADER_LEN;

        // Type and code
        assert_eq!(reply[icmp_start], Icmpv4Types::DestinationUnreachable);
        assert_eq!(reply[icmp_start + 1], Icmpv4Codes::ProtocolUnreachable);

        // Addresses swapped
        let eth = EthernetFrame::from_bytes(&reply);
        assert_eq!(eth.src_mac, MacAddress::from(DST_MAC));
        assert_eq!(eth.dst_mac, MacAddress::from(SRC_MAC));
        let ip = Ipv4Header::from_bytes(&reply);
        assert_eq!(ip.src_addr, LOCAL_IP);
        assert_eq!(ip.dst_addr, REMOTE_IP);
        assert_eq!(ip.protocol, IpProtocols::Icmp);

        // Original header + first 8 bytes preserved
        let icmp_payload_start = icmp_start + ICMPV4_HEADER_LEN;
        assert_eq!(
            &reply[icmp_payload_start..icmp_payload_start + IPV4_MIN_HEADER_LEN],
            &orig_ip_hdr[..]
        );
        let data_start = icmp_payload_start + IPV4_MIN_HEADER_LEN;
        assert_eq!(&reply[data_start..data_start + 8], &orig_first8[..]);

        // Valid IPv4 header checksum
        assert_eq!(
            compute_ipv4_checksum(&reply[eth_len..eth_len + IPV4_MIN_HEADER_LEN]),
            [0, 0]
        );

        // Valid ICMP checksum
        let icmp_end = ip.payload_offset() + ip.payload_len();
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
        let mtu = u16::from_be_bytes([reply[icmp_start + 6], reply[icmp_start + 7]]);
        assert_eq!(mtu, 1280);
    }

    #[test]
    fn dest_unreachable_rfc1122_restrictions() {
        // Helper to test that send_destination_unreachable rejects a frame.
        let assert_not_sent = |data: Vec<u8>| {
            let mut buf = vec![0u8; 256];
            buf[..data.len()].copy_from_slice(&data);
            let frame = Frame::new(0, &mut buf, data.len(), false);
            let mut rx = BasicFrameBuffer::new(4);
            let mut tx = BasicFrameBuffer::new(4);
            send_destination_unreachable(
                frame,
                Icmpv4Codes::ProtocolUnreachable,
                0,
                &mut rx,
                &mut tx,
            );
            assert_eq!(rx.num_frames(), 1, "expected rejection");
            assert_eq!(tx.num_frames(), 0, "expected no response");
        };

        // Broadcast destination
        assert_not_sent(build_ipv4_frame(
            SRC_MAC,
            DST_MAC,
            REMOTE_IP,
            Ipv4Address::broadcast(),
            99,
            &[0; 32],
        ));
        // Multicast destination
        assert_not_sent(build_ipv4_frame(
            SRC_MAC,
            DST_MAC,
            REMOTE_IP,
            Ipv4Address::new([224, 0, 0, 1]),
            99,
            &[0; 32],
        ));
        // Broadcast source
        assert_not_sent(build_ipv4_frame(
            SRC_MAC,
            DST_MAC,
            Ipv4Address::broadcast(),
            LOCAL_IP,
            99,
            &[0; 32],
        ));
        // Multicast source
        assert_not_sent(build_ipv4_frame(
            SRC_MAC,
            DST_MAC,
            Ipv4Address::new([224, 0, 0, 1]),
            LOCAL_IP,
            99,
            &[0; 32],
        ));
        // Unspecified source
        assert_not_sent(build_ipv4_frame(
            SRC_MAC,
            DST_MAC,
            Ipv4Address::unspecified(),
            LOCAL_IP,
            99,
            &[0; 32],
        ));
        // ICMP error as trigger
        let mut icmp_err = [0u8; 36];
        icmp_err[0] = Icmpv4Types::DestinationUnreachable;
        let cksum = compute_ipv4_checksum(&icmp_err);
        icmp_err[2] = cksum[0];
        icmp_err[3] = cksum[1];
        assert_not_sent(build_ipv4_frame(
            SRC_MAC,
            DST_MAC,
            REMOTE_IP,
            LOCAL_IP,
            IpProtocols::Icmp,
            &icmp_err,
        ));
    }

    #[test]
    fn dest_unreachable_allowed_for_non_error() {
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

    // -- PMTU update test --

    #[test]
    fn fragmentation_needed_updates_pmtu() {
        let now = Instant::now();
        // Build a Fragmentation Needed ICMP message carrying an embedded IPv4 header.
        let dest_ip = Ipv4Address::new([172, 16, 0, 1]);

        // Build embedded original IPv4 header (20 bytes) + 8 bytes data.
        let mut embedded = [0u8; 28];
        embedded[0] = 0x45;
        embedded[9] = IpProtocols::Udp;
        let src_bytes: [u8; 4] = REMOTE_IP.into();
        embedded[12..16].copy_from_slice(&src_bytes);
        let dst_bytes: [u8; 4] = dest_ip.into();
        embedded[16..20].copy_from_slice(&dst_bytes);

        // Build ICMP Dest Unreachable / Fragmentation Needed with MTU=1280.
        let mut icmp_payload = vec![0u8; ICMPV4_HEADER_LEN + embedded.len()];
        icmp_payload[0] = Icmpv4Types::DestinationUnreachable;
        icmp_payload[1] = Icmpv4Codes::FragmentationNeeded;
        icmp_payload[6] = (1280u16 >> 8) as u8;
        icmp_payload[7] = 1280u16 as u8;
        icmp_payload[ICMPV4_HEADER_LEN..].copy_from_slice(&embedded);
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

        let mut pmtu = PmtuCache::new();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        handle_icmpv4(frame, &mut pmtu, now, &mut rx, &mut tx);

        // Frame goes to rx (not an echo request)
        assert_eq!(rx.num_frames(), 1);
        // PMTU cache should be updated for the embedded destination IP
        assert_eq!(pmtu.get(now, &IpAddress::V4(dest_ip)), 1280);
    }
}
