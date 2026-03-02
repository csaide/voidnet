use std::mem::size_of;

use coarsetime::Instant;

use crate::{
    net::{
        NeighborHandler, PmtuCache,
        checksum::compute_icmpv6_checksum,
        wire::{
            ethernet::EthernetFrame,
            icmpv6::{
                ICMPV6_HEADER_LEN, Icmpv6Codes, Icmpv6Frame, Icmpv6Header, Icmpv6Types,
                MAX_ERROR_PAYLOAD, is_icmpv6_error,
            },
            ip::{IPV6_HEADER_LEN, IpProtocols, Ipv6Address, Ipv6Header},
        },
    },
    xdp::frame::{Frame, FrameBuffer},
};

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
    neighbor_handler: &NeighborHandler,
    pmtu: &PmtuCache,
    now: Instant,
    rx_offload: bool,
    tx_offload: bool,
    rx_return: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) {
    if icmpv6_len < ICMPV6_HEADER_LEN {
        rx_return.push(frame);
        return;
    }

    let ip = Ipv6Header::from_bytes(&frame);
    let src_addr = ip.src_addr;
    let dst_addr = ip.dst_addr;

    let icmpv6_end = icmpv6_offset + icmpv6_len;

    if !rx_offload
        && compute_icmpv6_checksum(&src_addr, &dst_addr, &frame[icmpv6_offset..icmpv6_end])
            != [0x00, 0x00]
    {
        rx_return.push(frame);
        return;
    }

    let icmpv6 = Icmpv6Header::from_bytes_at(&frame, icmpv6_offset);
    let icmpv6_type = icmpv6.icmp_type;

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
            let eth = EthernetFrame::from_bytes_mut(&mut frame);
            let tmp_mac = eth.dst_mac;
            eth.dst_mac = eth.src_mac;
            eth.src_mac = tmp_mac;

            // Swap IPv6 addresses and reset hop limit.
            let ip = Ipv6Header::from_bytes_mut(&mut frame);
            let tmp_addr = ip.src_addr;
            ip.src_addr = ip.dst_addr;
            ip.dst_addr = tmp_addr;
            ip.hop_limit = 64;

            // Set ICMPv6 type to Echo Reply and recompute checksum.
            let icmpv6 = Icmpv6Header::from_bytes_at_mut(&mut frame, icmpv6_offset);
            icmpv6.icmp_type = Icmpv6Types::EchoReply;
            icmpv6.checksum = [0, 0];
            if !tx_offload {
                let cksum = compute_icmpv6_checksum(
                    &dst_addr, // new src = old dst
                    &src_addr, // new dst = old src
                    &frame[icmpv6_offset..icmpv6_end],
                );
                Icmpv6Header::from_bytes_at_mut(&mut frame, icmpv6_offset).checksum = cksum;
            }

            tx_return.push(frame);
        }
        Icmpv6Types::PacketTooBig => {
            // Extract MTU from ICMPv6 header body.
            let icmpv6 = Icmpv6Header::from_bytes_at(&frame, icmpv6_offset);
            let mtu = icmpv6.body_as_u32();

            // Extract original destination IP from embedded IPv6 header.
            // The embedded IPv6 header starts at icmpv6_offset + ICMPV6_HEADER_LEN.
            // The destination address is at offset 24 within the IPv6 header.
            let dst_offset = icmpv6_offset + ICMPV6_HEADER_LEN + 24;
            if dst_offset + 16 <= frame.len() {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&frame[dst_offset..dst_offset + 16]);
                let dst_ip = Ipv6Address::new(octets);
                pmtu.update(now, dst_ip.into(), mtu);
            }

            rx_return.push(frame);
        }
        Icmpv6Types::RouterSolicitation
        | Icmpv6Types::RouterAdvertisement
        | Icmpv6Types::NeighborSolicitation => {
            neighbor_handler.handle_ndp(
                now,
                frame,
                icmpv6_offset,
                icmpv6_len,
                rx_return,
                tx_return,
            );
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
    tx_offload: bool,
    rx_return: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) {
    let eth_len = size_of::<EthernetFrame>();

    let ip = Ipv6Header::from_bytes(&frame);
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

    // Build all headers via struct overlay.
    let icmp_start = eth_len + IPV6_HEADER_LEN;
    {
        let pkt = Icmpv6Frame::from_bytes_mut(&mut frame);

        // Swap Ethernet MACs.
        let tmp_mac = pkt.ethernet.dst_mac;
        pkt.ethernet.dst_mac = pkt.ethernet.src_mac;
        pkt.ethernet.src_mac = tmp_mac;

        // Build the new IPv6 header.
        pkt.ipv6.version_tc_fl = [0x60, 0x00, 0x00, 0x00];
        pkt.ipv6.payload_length = (new_ipv6_payload_len as u16).to_be_bytes();
        pkt.ipv6.next_header = IpProtocols::IcmpV6;
        pkt.ipv6.hop_limit = 64;
        pkt.ipv6.src_addr = dst_addr; // our address
        pkt.ipv6.dst_addr = src_addr; // original sender

        // Build the ICMPv6 header.
        pkt.icmpv6.icmp_type = icmpv6_type;
        pkt.icmpv6.code = code;
        pkt.icmpv6.checksum = [0, 0];
        pkt.icmpv6.body = body;
    }

    // Truncate to the correct length before computing checksum.
    unsafe {
        frame.set_len(new_frame_len);
    }

    // Compute and write ICMPv6 checksum (over pseudo-header + message).
    if !tx_offload {
        let icmp_end = icmp_start + icmpv6_msg_len;
        let cksum = compute_icmpv6_checksum(
            &dst_addr, // new src
            &src_addr, // new dst
            &frame[icmp_start..icmp_end],
        );
        Icmpv6Header::from_bytes_at_mut(&mut frame, icmp_start).checksum = cksum;
    }

    tx_return.push(frame);
}

#[cfg(test)]
mod tests {
    use coarsetime::Duration;

    use crate::{
        net::wire::{ethernet::MacAddress, ip::IpAddress},
        xdp::frame::BasicFrameBuffer,
    };

    use super::*;

    const SRC_MAC: [u8; 6] = MacAddress::zero().octets;
    const DST_MAC: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x02];
    const REMOTE_IP: Ipv6Address =
        Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    const LOCAL_IP: Ipv6Address =
        Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    const MCAST: Ipv6Address =
        Ipv6Address::new([0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

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

        buf[0..6].copy_from_slice(&dst_mac);
        buf[6..12].copy_from_slice(&src_mac);
        buf[12] = 0x86;
        buf[13] = 0xDD;

        buf[14] = 0x60;
        buf[18..20].copy_from_slice(&(icmpv6_len as u16).to_be_bytes());
        buf[20] = IpProtocols::IcmpV6;
        buf[21] = 64;
        let src_bytes: [u8; 16] = src_ip.into();
        buf[22..38].copy_from_slice(&src_bytes);
        let dst_bytes: [u8; 16] = dst_ip.into();
        buf[38..54].copy_from_slice(&dst_bytes);

        let icmp_off = eth_len + IPV6_HEADER_LEN;
        buf[icmp_off] = Icmpv6Types::EchoRequest;
        buf[icmp_off + 1] = 0;
        buf[icmp_off + 4] = (id >> 8) as u8;
        buf[icmp_off + 5] = id as u8;
        buf[icmp_off + 6] = (seq >> 8) as u8;
        buf[icmp_off + 7] = seq as u8;
        buf[icmp_off + 8..].copy_from_slice(data);

        buf[icmp_off + 2] = 0;
        buf[icmp_off + 3] = 0;
        let cksum = compute_icmpv6_checksum(&src_ip, &dst_ip, &buf[icmp_off..]);
        buf[icmp_off + 2] = cksum[0];
        buf[icmp_off + 3] = cksum[1];

        buf
    }

    /// Builds a generic Ethernet + IPv6 frame.
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
        let mut buf = vec![0u8; 512];
        buf[..echo.len()].copy_from_slice(&echo);
        let frame = Frame::new(0, &mut buf, echo.len(), false);

        let icmpv6_offset = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;
        let icmpv6_len = echo.len() - icmpv6_offset;

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        let mut neighbor_handler = NeighborHandler::new("test", Duration::from_secs(60)).unwrap();
        handle_icmpv6(
            frame,
            icmpv6_offset,
            icmpv6_len,
            &mut neighbor_handler,
            &mut PmtuCache::new(),
            now,
            false,
            false,
            &mut rx,
            &mut tx,
        );

        assert_eq!(rx.num_frames(), 0);
        assert_eq!(tx.num_frames(), 1);

        let reply = tx.pop().unwrap();

        // Type and code
        assert_eq!(reply[icmpv6_offset], Icmpv6Types::EchoReply);
        assert_eq!(reply[icmpv6_offset + 1], 0);

        // Ethernet MACs swapped
        let eth = EthernetFrame::from_bytes(&reply);
        assert_eq!(eth.src_mac, MacAddress::from(DST_MAC));
        assert_eq!(eth.dst_mac, MacAddress::from(SRC_MAC));

        // IPv6 addresses swapped, hop limit reset
        let ip = Ipv6Header::from_bytes(&reply);
        assert_eq!(ip.src_addr, LOCAL_IP);
        assert_eq!(ip.dst_addr, REMOTE_IP);
        assert_eq!(ip.hop_limit, 64);

        // Identifier, sequence, and data preserved
        assert_eq!(reply[icmpv6_offset + 4], 0x12);
        assert_eq!(reply[icmpv6_offset + 5], 0x34);
        assert_eq!(reply[icmpv6_offset + 6], 0x00);
        assert_eq!(reply[icmpv6_offset + 7], 0x05);
        assert_eq!(&reply[icmpv6_offset + 8..icmpv6_offset + 16], &data);

        // Valid ICMPv6 checksum
        let cksum = compute_icmpv6_checksum(
            &ip.src_addr,
            &ip.dst_addr,
            &reply[icmpv6_offset..icmpv6_offset + icmpv6_len],
        );
        assert_eq!(cksum, [0x00, 0x00]);
    }

    #[test]
    fn echo_request_bad_checksum_rejected() {
        let now = Instant::now();
        let mut echo = build_echo_request(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 1, 1, &[0; 8]);
        let icmpv6_offset = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;
        echo[icmpv6_offset + 2] ^= 0xFF;
        let mut buf = vec![0u8; 512];
        buf[..echo.len()].copy_from_slice(&echo);
        let frame = Frame::new(0, &mut buf, echo.len(), false);

        let icmpv6_len = echo.len() - icmpv6_offset;

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        let mut neighbor_handler = NeighborHandler::new("test", Duration::from_secs(60)).unwrap();
        handle_icmpv6(
            frame,
            icmpv6_offset,
            icmpv6_len,
            &mut neighbor_handler,
            &mut PmtuCache::new(),
            now,
            false,
            false,
            &mut rx,
            &mut tx,
        );
        assert_rejected(&rx, &tx);
    }

    #[test]
    fn echo_request_too_short_rejected() {
        let now = Instant::now();
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
        let mut neighbor_handler = NeighborHandler::new("test", Duration::from_secs(60)).unwrap();
        handle_icmpv6(
            frame,
            icmpv6_offset,
            4,
            &mut neighbor_handler,
            &mut PmtuCache::new(),
            now,
            false,
            false,
            &mut rx,
            &mut tx,
        );
        assert_rejected(&rx, &tx);
    }

    #[test]
    fn echo_request_to_multicast_rejected() {
        let now = Instant::now();
        let echo = build_echo_request(SRC_MAC, DST_MAC, REMOTE_IP, MCAST, 1, 1, &[0; 8]);
        let mut buf = vec![0u8; 512];
        buf[..echo.len()].copy_from_slice(&echo);
        let frame = Frame::new(0, &mut buf, echo.len(), false);

        let icmpv6_offset = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;
        let icmpv6_len = echo.len() - icmpv6_offset;

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        let mut neighbor_handler = NeighborHandler::new("test", Duration::from_secs(60)).unwrap();
        handle_icmpv6(
            frame,
            icmpv6_offset,
            icmpv6_len,
            &mut neighbor_handler,
            &mut PmtuCache::new(),
            now,
            false,
            false,
            &mut rx,
            &mut tx,
        );
        assert_rejected(&rx, &tx);
    }

    #[test]
    fn non_echo_request_goes_to_rx() {
        let now = Instant::now();
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
        let mut buf = vec![0u8; 512];
        buf[..data.len()].copy_from_slice(&data);
        let frame = Frame::new(0, &mut buf, data.len(), false);

        let icmpv6_offset = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        let mut neighbor_handler = NeighborHandler::new("test", Duration::from_secs(60)).unwrap();
        handle_icmpv6(
            frame,
            icmpv6_offset,
            icmpv6_payload.len(),
            &mut neighbor_handler,
            &mut PmtuCache::new(),
            now,
            false,
            false,
            &mut rx,
            &mut tx,
        );
        assert_rejected(&rx, &tx);
    }

    #[test]
    fn packet_too_big_updates_pmtu() {
        let now = Instant::now();
        let dest_ip = Ipv6Address::new([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99,
        ]);
        let eth_len = size_of::<EthernetFrame>();

        // Build an ICMPv6 Packet Too Big message with embedded IPv6 header.
        // ICMPv6 header (8 bytes): type=2, code=0, checksum=0, MTU=1280
        // Embedded IPv6 header (40 bytes): src=REMOTE_IP, dst=dest_ip
        let mut icmpv6_msg = vec![0u8; ICMPV6_HEADER_LEN + IPV6_HEADER_LEN];
        icmpv6_msg[0] = Icmpv6Types::PacketTooBig;
        icmpv6_msg[1] = 0;
        // MTU = 1280 in body bytes [4..8]
        icmpv6_msg[4..8].copy_from_slice(&1280u32.to_be_bytes());
        // Embedded IPv6 header at offset 8
        icmpv6_msg[8] = 0x60; // version
        icmpv6_msg[8 + 6] = IpProtocols::Udp; // next header
        icmpv6_msg[8 + 7] = 64; // hop limit
        let remote_bytes: [u8; 16] = REMOTE_IP.into();
        icmpv6_msg[8 + 8..8 + 24].copy_from_slice(&remote_bytes); // src
        let dest_bytes: [u8; 16] = dest_ip.into();
        icmpv6_msg[8 + 24..8 + 40].copy_from_slice(&dest_bytes); // dst

        // Compute ICMPv6 checksum over the whole message
        let cksum = compute_icmpv6_checksum(&REMOTE_IP, &LOCAL_IP, &icmpv6_msg);
        icmpv6_msg[2] = cksum[0];
        icmpv6_msg[3] = cksum[1];

        let data = build_ipv6_frame(
            SRC_MAC,
            DST_MAC,
            REMOTE_IP,
            LOCAL_IP,
            IpProtocols::IcmpV6,
            &icmpv6_msg,
        );
        let mut buf = vec![0u8; 512];
        buf[..data.len()].copy_from_slice(&data);
        let frame = Frame::new(0, &mut buf, data.len(), false);

        let icmpv6_offset = eth_len + IPV6_HEADER_LEN;

        let mut pmtu = PmtuCache::new();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        let mut neighbor_handler = NeighborHandler::new("test", Duration::from_secs(60)).unwrap();
        handle_icmpv6(
            frame,
            icmpv6_offset,
            icmpv6_msg.len(),
            &mut neighbor_handler,
            &mut pmtu,
            now,
            false,
            false,
            &mut rx,
            &mut tx,
        );

        // Frame goes to rx (informational, not echo)
        assert_eq!(rx.num_frames(), 1);
        // PMTU cache should be updated for the embedded destination IP
        assert_eq!(pmtu.get(now, &IpAddress::V6(dest_ip)), 1280);
    }

    // -- send_icmpv6_error tests --

    #[test]
    fn error_complete_response() {
        let payload = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let data = build_ipv6_frame(SRC_MAC, DST_MAC, REMOTE_IP, LOCAL_IP, 99, &payload);
        let mut buf = vec![0u8; 2048];
        buf[..data.len()].copy_from_slice(&data);

        let eth_len = size_of::<EthernetFrame>();
        let orig_ipv6_packet: Vec<u8> = data[eth_len..].to_vec();

        let frame = Frame::new(0, &mut buf, data.len(), false);
        let upper_offset = eth_len + IPV6_HEADER_LEN;

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        send_icmpv6_error(
            frame,
            Icmpv6Types::DestinationUnreachable,
            Icmpv6Codes::PortUnreachable,
            [0; 4],
            99,
            upper_offset,
            false,
            &mut rx,
            &mut tx,
        );

        assert_eq!(rx.num_frames(), 0);
        assert_eq!(tx.num_frames(), 1);

        let reply = tx.pop().unwrap();
        let icmp_start = eth_len + IPV6_HEADER_LEN;

        // Type and code
        assert_eq!(reply[icmp_start], Icmpv6Types::DestinationUnreachable);
        assert_eq!(reply[icmp_start + 1], Icmpv6Codes::PortUnreachable);

        // Addresses swapped
        let eth = EthernetFrame::from_bytes(&reply);
        assert_eq!(eth.src_mac, MacAddress::from(DST_MAC));
        assert_eq!(eth.dst_mac, MacAddress::from(SRC_MAC));
        let ip = Ipv6Header::from_bytes(&reply);
        assert_eq!(ip.src_addr, LOCAL_IP);
        assert_eq!(ip.dst_addr, REMOTE_IP);
        assert_eq!(ip.next_header, IpProtocols::IcmpV6);

        // Original IPv6 header + payload preserved in ICMP payload
        let icmp_payload_start = icmp_start + ICMPV6_HEADER_LEN;
        let icmp_payload_end = icmp_payload_start + orig_ipv6_packet.len();
        assert_eq!(
            &reply[icmp_payload_start..icmp_payload_end],
            &orig_ipv6_packet[..]
        );

        // Valid ICMPv6 checksum
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

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        send_icmpv6_error(
            frame,
            Icmpv6Types::PacketTooBig,
            0,
            1280u32.to_be_bytes(),
            17,
            upper_offset,
            false,
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

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        send_icmpv6_error(
            frame,
            Icmpv6Types::ParameterProblem,
            Icmpv6Codes::UnrecognizedNextHeader,
            6u32.to_be_bytes(),
            99,
            upper_offset,
            false,
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
    fn error_rfc4443_restrictions() {
        let upper_offset = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;

        let assert_not_sent = |data: Vec<u8>, proto: u8| {
            let mut buf = vec![0u8; 2048];
            buf[..data.len()].copy_from_slice(&data);
            let frame = Frame::new(0, &mut buf, data.len(), false);
            let mut rx = BasicFrameBuffer::new(4);
            let mut tx = BasicFrameBuffer::new(4);
            send_icmpv6_error(
                frame,
                Icmpv6Types::DestinationUnreachable,
                Icmpv6Codes::NoRouteToDestination,
                [0; 4],
                proto,
                upper_offset,
                false,
                &mut rx,
                &mut tx,
            );
            assert_rejected(&rx, &tx);
        };

        // Multicast destination
        assert_not_sent(
            build_ipv6_frame(SRC_MAC, DST_MAC, REMOTE_IP, MCAST, 99, &[0; 32]),
            99,
        );
        // Multicast source
        assert_not_sent(
            build_ipv6_frame(SRC_MAC, DST_MAC, MCAST, LOCAL_IP, 99, &[0; 32]),
            99,
        );
        // Unspecified source
        assert_not_sent(
            build_ipv6_frame(
                SRC_MAC,
                DST_MAC,
                Ipv6Address::unspecified(),
                LOCAL_IP,
                99,
                &[0; 32],
            ),
            99,
        );
        // ICMPv6 error as trigger
        let mut icmpv6_err = [0u8; 48];
        icmpv6_err[0] = Icmpv6Types::DestinationUnreachable;
        let cksum = compute_icmpv6_checksum(&REMOTE_IP, &LOCAL_IP, &icmpv6_err);
        icmpv6_err[2] = cksum[0];
        icmpv6_err[3] = cksum[1];
        assert_not_sent(
            build_ipv6_frame(
                SRC_MAC,
                DST_MAC,
                REMOTE_IP,
                LOCAL_IP,
                IpProtocols::IcmpV6,
                &icmpv6_err,
            ),
            IpProtocols::IcmpV6,
        );
    }

    #[test]
    fn error_packet_too_big_allowed_for_multicast_dst() {
        let data = build_ipv6_frame(SRC_MAC, DST_MAC, REMOTE_IP, MCAST, 17, &[0; 32]);
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
            false,
            &mut rx,
            &mut tx,
        );

        assert_eq!(rx.num_frames(), 0);
        assert_eq!(tx.num_frames(), 1);
    }

    #[test]
    fn error_parameter_problem_code2_allowed_for_multicast_dst() {
        let data = build_ipv6_frame(SRC_MAC, DST_MAC, REMOTE_IP, MCAST, 99, &[0; 32]);
        let mut buf = vec![0u8; 2048];
        buf[..data.len()].copy_from_slice(&data);
        let frame = Frame::new(0, &mut buf, data.len(), false);
        let upper_offset = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        send_icmpv6_error(
            frame,
            Icmpv6Types::ParameterProblem,
            Icmpv6Codes::BeyondScope,
            6u32.to_be_bytes(),
            99,
            upper_offset,
            false,
            &mut rx,
            &mut tx,
        );

        assert_eq!(rx.num_frames(), 0);
        assert_eq!(tx.num_frames(), 1);
    }

    #[test]
    fn error_allowed_for_icmpv6_non_error() {
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
            false,
            &mut rx,
            &mut tx,
        );

        assert_eq!(rx.num_frames(), 0);
        assert_eq!(tx.num_frames(), 1);
    }
}
