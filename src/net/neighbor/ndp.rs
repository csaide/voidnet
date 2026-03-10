use coarsetime::{Duration, Instant};
use dashmap::DashMap;

use crate::{
    net::checksum::compute_icmpv6_checksum,
    net::wire::{
        ethernet::{EtherTypes, EthernetFrame, MacAddress},
        icmpv6::Icmpv6Types,
        ip::{IpAddress, IpProtocols, Ipv6Address, Ipv6Header},
        ndp::{
            ALL_NODES_MULTICAST, NDP_MIN_NS_NA_LEN, NDP_MIN_RA_LEN, NDP_NA_FRAME_LEN,
            NDP_NS_FRAME_LEN, NdpNaFrame, NdpNaMessage, NdpNsFrame, NdpNsMessage,
        },
    },
    xdp::frame::{Frame, FrameBuffer},
};

use super::NeighborEntry;

pub(super) fn resolve_v6<'umem>(
    local_mac: MacAddress,
    source_ip: Ipv6Address,
    target_ip: Ipv6Address,
    tx_offload: bool,
    mut frame: Frame<'umem>,
    rx_return: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) {
    // This is essentially a no-op since frames really can't be this small, but
    // JUST in case lets check and bail out.
    if frame.capacity() < NDP_NS_FRAME_LEN {
        rx_return.push(frame);
        return;
    }

    let sol_mcast = target_ip.solicited_node_multicast();
    let dst_mac = sol_mcast.multicast_mac();

    // First set the frame length to the full NDP NS frame length.
    //
    // SAFETY: we know for a fact we can store this much data so we are good to go.
    unsafe {
        frame.set_len(NDP_NS_FRAME_LEN);
    }

    // Create our NDP NS frame.
    let pkt = NdpNsFrame::from_bytes_mut(&mut frame);

    // Setup ethernet headers.
    pkt.ethernet.dst_mac = dst_mac;
    pkt.ethernet.src_mac = local_mac;
    pkt.ethernet.ether_type = EtherTypes::IPv6;

    // Setup IPv6 header.
    pkt.ipv6.version_tc_fl = [0x60, 0x00, 0x00, 0x00];
    pkt.ipv6.payload_length = (size_of::<NdpNsMessage>() as u16).to_be_bytes();
    pkt.ipv6.next_header = IpProtocols::IcmpV6;
    pkt.ipv6.hop_limit = 255; // per RFC 4861
    pkt.ipv6.src_addr = source_ip;
    pkt.ipv6.dst_addr = sol_mcast;

    // Setup NDP NS message.
    pkt.ns.icmp_type = Icmpv6Types::NeighborSolicitation;
    pkt.ns.code = 0;
    pkt.ns.checksum = [0, 0];
    pkt.ns.reserved = [0; 4];
    pkt.ns.target = target_ip;
    pkt.ns.opt_type = 1; // Source Link-Layer Address
    pkt.ns.opt_len = 1; // 1 unit of 8 bytes
    pkt.ns.opt_mac = local_mac;

    // Compute checksum.
    if !tx_offload {
        pkt.ns.checksum = compute_icmpv6_checksum(&source_ip, &sol_mcast, pkt.ns.as_bytes());
    }

    // Push the frame to the TX buffer for transmission.
    tx_return.push(frame);
}

pub(super) fn handle_ndp<'umem>(
    now: Instant,
    ttl: Duration,
    table: &DashMap<IpAddress, NeighborEntry>,
    local_ipv6: &[Ipv6Address],
    local_mac: MacAddress,
    rx_offload: bool,
    tx_offload: bool,
    frame: Frame<'umem>,
    icmpv6_offset: usize,
    icmpv6_len: usize,
    rx_return: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) {
    if icmpv6_len < 8 {
        rx_return.push(frame);
        return;
    }

    let icmpv6_end = icmpv6_offset + icmpv6_len;

    // Validate checksum.
    if !rx_offload {
        let ip = Ipv6Header::from_bytes(&frame);
        let src_addr = ip.src_addr;
        let dst_addr = ip.dst_addr;
        if compute_icmpv6_checksum(&src_addr, &dst_addr, &frame[icmpv6_offset..icmpv6_end])
            != [0x00, 0x00]
        {
            rx_return.push(frame);
            return;
        }
    }

    let icmpv6_type = frame[icmpv6_offset];

    match icmpv6_type {
        Icmpv6Types::NeighborSolicitation => {
            handle_neighbor_solicitation(
                now,
                ttl,
                table,
                local_ipv6,
                local_mac,
                tx_offload,
                frame,
                icmpv6_offset,
                icmpv6_len,
                rx_return,
                tx_return,
            );
        }
        Icmpv6Types::NeighborAdvertisement => {
            handle_neighbor_advertisement(
                now,
                ttl,
                table,
                frame,
                icmpv6_offset,
                icmpv6_len,
                rx_return,
            );
        }
        Icmpv6Types::RouterAdvertisement => {
            handle_router_advertisement(
                now,
                ttl,
                table,
                frame,
                icmpv6_offset,
                icmpv6_len,
                rx_return,
            );
        }
        _ => {
            // RS (133), Redirect (137), or unknown NDP type.
            rx_return.push(frame);
        }
    }
}

fn handle_neighbor_solicitation<'umem>(
    now: Instant,
    ttl: Duration,
    table: &DashMap<IpAddress, NeighborEntry>,
    local_ipv6: &[Ipv6Address],
    local_mac: MacAddress,
    tx_offload: bool,
    mut frame: Frame<'umem>,
    icmpv6_offset: usize,
    icmpv6_len: usize,
    rx_return: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) {
    if icmpv6_len < NDP_MIN_NS_NA_LEN {
        rx_return.push(frame);
        return;
    }

    let icmpv6_end = icmpv6_offset + icmpv6_len;

    // Extract target address (bytes 8..24 relative to ICMPv6 header).
    let mut target_bytes = [0u8; 16];
    target_bytes.copy_from_slice(&frame[icmpv6_offset + 8..icmpv6_offset + 24]);
    let target_addr = Ipv6Address::from(target_bytes);

    // Extract IPv6 source address.
    let ip = Ipv6Header::from_bytes(&frame);
    let src_addr = ip.src_addr;

    // Parse Source Link-Layer Address option (type=1) to get sender MAC.
    let options_start = icmpv6_offset + 24;
    let sender_mac = parse_ndp_link_layer_option(&frame, options_start, icmpv6_end, 1);

    // Cache sender's MAC if source is not unspecified (DAD uses ::).
    if !src_addr.is_unspecified()
        && let Some(mac) = sender_mac
    {
        table.insert(IpAddress::V6(src_addr), NeighborEntry::new(mac, now + ttl));
    }

    // Check if the target is one of our addresses.
    if !local_ipv6.contains(&target_addr) {
        rx_return.push(frame);
        return;
    }

    // Build NA reply.
    let (reply_dst_addr, reply_dst_mac, na_flags) = if src_addr.is_unspecified() {
        (
            ALL_NODES_MULTICAST,
            ALL_NODES_MULTICAST.multicast_mac(),
            [0x20, 0x00, 0x00, 0x00],
        )
    } else {
        (
            src_addr,
            sender_mac.unwrap_or_else(|| {
                // Fallback: use the Ethernet source MAC from the frame.
                let eth = EthernetFrame::from_bytes(&frame);
                eth.src_mac
            }),
            [0x60, 0x00, 0x00, 0x00],
        )
    };

    // First set the frame length to the full NDP NA frame length.
    //
    // SAFETY: we know for a fact we can store this much data so we are good to go.
    unsafe {
        frame.set_len(NDP_NA_FRAME_LEN);
    }

    // Create our NDP NA frame.
    let pkt = NdpNaFrame::from_bytes_mut(&mut frame);

    // Setup ethernet headers.
    pkt.ethernet.dst_mac = reply_dst_mac;
    pkt.ethernet.src_mac = local_mac;
    pkt.ethernet.ether_type = EtherTypes::IPv6;

    // Setup IPv6 header.
    pkt.ipv6.version_tc_fl = [0x60, 0x00, 0x00, 0x00];
    pkt.ipv6.payload_length = (size_of::<NdpNaMessage>() as u16).to_be_bytes();
    pkt.ipv6.next_header = IpProtocols::IcmpV6;
    pkt.ipv6.hop_limit = 255; // per RFC 4861
    pkt.ipv6.src_addr = target_addr;
    pkt.ipv6.dst_addr = reply_dst_addr;

    // Setup NDP NA message.
    pkt.na.icmp_type = Icmpv6Types::NeighborAdvertisement;
    pkt.na.code = 0;
    pkt.na.checksum = [0, 0];
    pkt.na.flags = na_flags;
    pkt.na.target = target_addr;
    pkt.na.opt_type = 2; // Target Link-Layer Address
    pkt.na.opt_len = 1; // 1 unit of 8 bytes
    pkt.na.opt_mac = local_mac;
    if !tx_offload {
        pkt.na.checksum = compute_icmpv6_checksum(&target_addr, &reply_dst_addr, pkt.na.as_bytes());
    }

    tx_return.push(frame);
}

fn handle_neighbor_advertisement<'umem>(
    now: Instant,
    ttl: Duration,
    table: &DashMap<IpAddress, NeighborEntry>,
    frame: Frame<'umem>,
    icmpv6_offset: usize,
    icmpv6_len: usize,
    rx_return: &mut impl FrameBuffer<'umem>,
) {
    if icmpv6_len < NDP_MIN_NS_NA_LEN {
        rx_return.push(frame);
        return;
    }

    let icmpv6_end = icmpv6_offset + icmpv6_len;

    // Extract target address.
    let mut target_bytes = [0u8; 16];
    target_bytes.copy_from_slice(&frame[icmpv6_offset + 8..icmpv6_offset + 24]);
    let target_addr = Ipv6Address::from(target_bytes);

    // Parse Target Link-Layer Address option (type=2).
    let options_start = icmpv6_offset + 24;
    if let Some(mac) = parse_ndp_link_layer_option(&frame, options_start, icmpv6_end, 2) {
        table.insert(
            IpAddress::V6(target_addr),
            NeighborEntry::new(mac, now + ttl),
        );
    }

    rx_return.push(frame);
}

fn handle_router_advertisement<'umem>(
    now: Instant,
    ttl: Duration,
    table: &DashMap<IpAddress, NeighborEntry>,
    frame: Frame<'umem>,
    icmpv6_offset: usize,
    icmpv6_len: usize,
    rx_return: &mut impl FrameBuffer<'umem>,
) {
    if icmpv6_len < NDP_MIN_RA_LEN {
        rx_return.push(frame);
        return;
    }

    let icmpv6_end = icmpv6_offset + icmpv6_len;

    // Extract IPv6 source address (router).
    let ip = Ipv6Header::from_bytes(&frame);
    let src_addr = ip.src_addr;

    // Parse Source Link-Layer Address option (type=1).
    let options_start = icmpv6_offset + 16; // RA header is 16 bytes
    if let Some(mac) = parse_ndp_link_layer_option(&frame, options_start, icmpv6_end, 1) {
        table.insert(IpAddress::V6(src_addr), NeighborEntry::new(mac, now + ttl));
    }

    rx_return.push(frame);
}

/// Walks NDP options looking for a Link-Layer Address option of the
/// specified `option_type` (1 = Source, 2 = Target).
///
/// Returns the 6-byte MAC address if found, `None` otherwise.
fn parse_ndp_link_layer_option(
    frame: &[u8],
    mut offset: usize,
    end: usize,
    option_type: u8,
) -> Option<MacAddress> {
    while offset + 2 <= end {
        let opt_type = frame[offset];
        let opt_len = frame[offset + 1] as usize;

        // Option length is in units of 8 bytes; 0 is invalid.
        if opt_len == 0 {
            return None;
        }

        let opt_byte_len = opt_len * 8;
        if offset + opt_byte_len > end {
            return None;
        }

        if opt_type == option_type && opt_byte_len >= 8 {
            let mac = MacAddress::new([
                frame[offset + 2],
                frame[offset + 3],
                frame[offset + 4],
                frame[offset + 5],
                frame[offset + 6],
                frame[offset + 7],
            ]);
            return Some(mac);
        }

        offset += opt_byte_len;
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::{
        net::{
            neighbor::NeighborHandler,
            wire::ip::{IPV6_HEADER_LEN, Ipv4Address},
        },
        xdp::frame::BasicFrameBuffer,
    };

    use super::*;

    const TEST_LOCAL_MAC: MacAddress = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    const TEST_LOCAL_IP: Ipv4Address = Ipv4Address::new([192, 168, 1, 1]);
    const TEST_REMOTE_MAC: MacAddress = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    const TEST_TTL: Duration = Duration::from_secs(60);

    const TEST_LOCAL_IPV6: Ipv6Address =
        Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    const TEST_REMOTE_IPV6: Ipv6Address =
        Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

    fn new_handler() -> NeighborHandler {
        let mut nh = NeighborHandler::new("test0", TEST_TTL).unwrap();
        nh.set_local_mac(TEST_LOCAL_MAC);
        nh.add_local_ipv4(TEST_LOCAL_IP);
        nh.add_local_ipv6(TEST_LOCAL_IPV6);
        nh
    }

    fn build_ndp_frame(
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        icmpv6_payload: &[u8],
    ) -> Vec<u8> {
        use std::mem::size_of;

        let eth_len = size_of::<EthernetFrame>();
        let frame_len = eth_len + IPV6_HEADER_LEN + icmpv6_payload.len();
        let mut buf = vec![0u8; frame_len];

        buf[0..6].copy_from_slice(&dst_mac);
        buf[6..12].copy_from_slice(&src_mac);
        buf[12] = 0x86;
        buf[13] = 0xDD;

        buf[14] = 0x60;
        let payload_len = (icmpv6_payload.len() as u16).to_be_bytes();
        buf[18..20].copy_from_slice(&payload_len);
        buf[20] = IpProtocols::IcmpV6;
        buf[21] = 255;
        let src_bytes: [u8; 16] = src_ip.into();
        buf[22..38].copy_from_slice(&src_bytes);
        let dst_bytes: [u8; 16] = dst_ip.into();
        buf[38..54].copy_from_slice(&dst_bytes);

        buf[eth_len + IPV6_HEADER_LEN..].copy_from_slice(icmpv6_payload);

        let icmp_off = eth_len + IPV6_HEADER_LEN;
        buf[icmp_off + 2] = 0;
        buf[icmp_off + 3] = 0;
        let cksum = compute_icmpv6_checksum(&src_ip, &dst_ip, &buf[icmp_off..]);
        buf[icmp_off + 2] = cksum[0];
        buf[icmp_off + 3] = cksum[1];

        buf
    }

    fn build_ns_payload(target: Ipv6Address, source_mac: Option<[u8; 6]>) -> Vec<u8> {
        let mut payload = vec![0u8; 24];
        payload[0] = 135;
        let target_bytes: [u8; 16] = target.into();
        payload[8..24].copy_from_slice(&target_bytes);

        if let Some(mac) = source_mac {
            payload.push(1);
            payload.push(1);
            payload.extend_from_slice(&mac);
        }

        payload
    }

    fn build_na_payload(target: Ipv6Address, flags: u8, target_mac: Option<[u8; 6]>) -> Vec<u8> {
        let mut payload = vec![0u8; 24];
        payload[0] = 136;
        payload[4] = flags;
        let target_bytes: [u8; 16] = target.into();
        payload[8..24].copy_from_slice(&target_bytes);

        if let Some(mac) = target_mac {
            payload.push(2);
            payload.push(1);
            payload.extend_from_slice(&mac);
        }

        payload
    }

    fn build_ra_payload(source_mac: Option<[u8; 6]>) -> Vec<u8> {
        let mut payload = vec![0u8; 16];
        payload[0] = 134;

        if let Some(mac) = source_mac {
            payload.push(1);
            payload.push(1);
            payload.extend_from_slice(&mac);
        }

        payload
    }

    fn icmpv6_offset() -> usize {
        std::mem::size_of::<EthernetFrame>() + IPV6_HEADER_LEN
    }

    #[test]
    fn ns_targeting_our_ip_produces_na() {
        let now = Instant::now();
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let remote_mac: [u8; 6] = TEST_REMOTE_MAC.into();
        let local_mac: [u8; 6] = TEST_LOCAL_MAC.into();
        let ns = build_ns_payload(TEST_LOCAL_IPV6, Some(remote_mac));
        let sol_mcast = TEST_LOCAL_IPV6.solicited_node_multicast();
        let frame_data = build_ndp_frame(
            remote_mac,
            sol_mcast.multicast_mac().into(),
            TEST_REMOTE_IPV6,
            sol_mcast,
            &ns,
        );

        let mut buf = vec![0u8; 512];
        buf[..frame_data.len()].copy_from_slice(&frame_data);
        let frame = Frame::new(0, &mut buf, frame_data.len(), false);

        let off = icmpv6_offset();
        let icmp_len = frame_data.len() - off;
        handler.handle_ndp(now, frame, off, icmp_len, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 0);
        assert_eq!(tx.num_frames(), 1);

        let reply = tx.pop().unwrap();

        assert_eq!(reply[off], 136);
        assert_eq!(reply[off + 4], 0x60);

        let mut target = [0u8; 16];
        target.copy_from_slice(&reply[off + 8..off + 24]);
        assert_eq!(Ipv6Address::from(target), TEST_LOCAL_IPV6);

        assert_eq!(reply[off + 24], 2);
        assert_eq!(reply[off + 25], 1);
        assert_eq!(&reply[off + 26..off + 32], &local_mac);

        let ip = Ipv6Header::from_bytes(&reply);
        assert_eq!(ip.hop_limit, 255);

        let cksum = compute_icmpv6_checksum(&ip.src_addr, &ip.dst_addr, &reply[off..off + 32]);
        assert_eq!(cksum, [0x00, 0x00]);
    }

    #[test]
    fn ns_targeting_unknown_ip_goes_to_rx() {
        let now = Instant::now();
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let unknown = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99]);
        let remote_mac: [u8; 6] = TEST_REMOTE_MAC.into();
        let ns = build_ns_payload(unknown, Some(remote_mac));
        let frame_data = build_ndp_frame(
            remote_mac,
            [0x33, 0x33, 0x00, 0x00, 0x00, 0x63],
            TEST_REMOTE_IPV6,
            unknown.solicited_node_multicast(),
            &ns,
        );

        let mut buf = vec![0u8; 512];
        buf[..frame_data.len()].copy_from_slice(&frame_data);
        let frame = Frame::new(0, &mut buf, frame_data.len(), false);

        let off = icmpv6_offset();
        let icmp_len = frame_data.len() - off;
        handler.handle_ndp(now, frame, off, icmp_len, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn ns_caches_sender_mac() {
        let now = Instant::now();
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        assert!(handler.lookup_v6(now, &TEST_REMOTE_IPV6).is_none());

        let remote_mac: [u8; 6] = TEST_REMOTE_MAC.into();
        let ns = build_ns_payload(TEST_LOCAL_IPV6, Some(remote_mac));
        let sol_mcast = TEST_LOCAL_IPV6.solicited_node_multicast();
        let frame_data = build_ndp_frame(
            remote_mac,
            sol_mcast.multicast_mac().into(),
            TEST_REMOTE_IPV6,
            sol_mcast,
            &ns,
        );

        let mut buf = vec![0u8; 512];
        buf[..frame_data.len()].copy_from_slice(&frame_data);
        let frame = Frame::new(0, &mut buf, frame_data.len(), false);

        let off = icmpv6_offset();
        let icmp_len = frame_data.len() - off;
        handler.handle_ndp(now, frame, off, icmp_len, &mut rx, &mut tx);

        assert_eq!(
            handler.lookup_v6(now, &TEST_REMOTE_IPV6),
            Some(TEST_REMOTE_MAC)
        );
    }

    #[test]
    fn ns_dad_produces_na_with_correct_flags() {
        let now = Instant::now();
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let ns = build_ns_payload(TEST_LOCAL_IPV6, None);
        let sol_mcast = TEST_LOCAL_IPV6.solicited_node_multicast();
        let all_nodes_mac: [u8; 6] =
            Ipv6Address::new([0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
                .multicast_mac()
                .into();
        let frame_data = build_ndp_frame(
            [0x00; 6],
            sol_mcast.multicast_mac().into(),
            Ipv6Address::unspecified(),
            sol_mcast,
            &ns,
        );

        let mut buf = vec![0u8; 512];
        buf[..frame_data.len()].copy_from_slice(&frame_data);
        let frame = Frame::new(0, &mut buf, frame_data.len(), false);

        let off = icmpv6_offset();
        let icmp_len = frame_data.len() - off;
        handler.handle_ndp(now, frame, off, icmp_len, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 0);
        assert_eq!(tx.num_frames(), 1);

        let reply = tx.pop().unwrap();

        assert_eq!(reply[off + 4], 0x20);

        let eth = EthernetFrame::from_bytes(&reply);
        assert_eq!(<[u8; 6]>::from(eth.dst_mac), all_nodes_mac);

        let ip = Ipv6Header::from_bytes(&reply);
        assert_eq!(
            ip.dst_addr,
            Ipv6Address::new([0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        );
    }

    #[test]
    fn ns_too_short_goes_to_rx() {
        let now = Instant::now();
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let short_ns = vec![135u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let frame_data = build_ndp_frame(
            [0x11; 6],
            [0x33, 0x33, 0x00, 0x00, 0x00, 0x01],
            TEST_REMOTE_IPV6,
            TEST_LOCAL_IPV6.solicited_node_multicast(),
            &short_ns,
        );

        let mut buf = vec![0u8; 512];
        buf[..frame_data.len()].copy_from_slice(&frame_data);
        let frame = Frame::new(0, &mut buf, frame_data.len(), false);

        let off = icmpv6_offset();
        let icmp_len = frame_data.len() - off;
        handler.handle_ndp(now, frame, off, icmp_len, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn ns_bad_checksum_goes_to_rx() {
        let now = Instant::now();
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let remote_mac: [u8; 6] = TEST_REMOTE_MAC.into();
        let ns = build_ns_payload(TEST_LOCAL_IPV6, Some(remote_mac));
        let sol_mcast = TEST_LOCAL_IPV6.solicited_node_multicast();
        let mut frame_data = build_ndp_frame(
            remote_mac,
            sol_mcast.multicast_mac().into(),
            TEST_REMOTE_IPV6,
            sol_mcast,
            &ns,
        );

        let off = icmpv6_offset();
        frame_data[off + 2] ^= 0xFF;

        let mut buf = vec![0u8; 512];
        buf[..frame_data.len()].copy_from_slice(&frame_data);
        let frame = Frame::new(0, &mut buf, frame_data.len(), false);

        let icmp_len = frame_data.len() - off;
        handler.handle_ndp(now, frame, off, icmp_len, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn na_caches_target_mac() {
        let now = Instant::now();
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        assert!(handler.lookup_v6(now, &TEST_REMOTE_IPV6).is_none());

        let remote_mac: [u8; 6] = TEST_REMOTE_MAC.into();
        let na = build_na_payload(TEST_REMOTE_IPV6, 0x60, Some(remote_mac));
        let frame_data = build_ndp_frame(
            remote_mac,
            TEST_LOCAL_MAC.into(),
            TEST_REMOTE_IPV6,
            TEST_LOCAL_IPV6,
            &na,
        );

        let mut buf = vec![0u8; 512];
        buf[..frame_data.len()].copy_from_slice(&frame_data);
        let frame = Frame::new(0, &mut buf, frame_data.len(), false);

        let off = icmpv6_offset();
        let icmp_len = frame_data.len() - off;
        handler.handle_ndp(now, frame, off, icmp_len, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
        assert_eq!(
            handler.lookup_v6(now, &TEST_REMOTE_IPV6),
            Some(TEST_REMOTE_MAC)
        );
    }

    #[test]
    fn na_too_short_goes_to_rx() {
        let now = Instant::now();
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let short_na = vec![136u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let frame_data = build_ndp_frame(
            [0x11; 6],
            TEST_LOCAL_MAC.into(),
            TEST_REMOTE_IPV6,
            TEST_LOCAL_IPV6,
            &short_na,
        );

        let mut buf = vec![0u8; 512];
        buf[..frame_data.len()].copy_from_slice(&frame_data);
        let frame = Frame::new(0, &mut buf, frame_data.len(), false);

        let off = icmpv6_offset();
        let icmp_len = frame_data.len() - off;
        handler.handle_ndp(now, frame, off, icmp_len, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn ra_caches_router_mac() {
        let now = Instant::now();
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let router_ip = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFE]);
        let router_mac: [u8; 6] = [0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01];

        assert!(handler.lookup_v6(now, &router_ip).is_none());

        let ra = build_ra_payload(Some(router_mac));
        let frame_data = build_ndp_frame(
            router_mac,
            [0x33, 0x33, 0x00, 0x00, 0x00, 0x01],
            router_ip,
            Ipv6Address::new([0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            &ra,
        );

        let mut buf = vec![0u8; 512];
        buf[..frame_data.len()].copy_from_slice(&frame_data);
        let frame = Frame::new(0, &mut buf, frame_data.len(), false);

        let off = icmpv6_offset();
        let icmp_len = frame_data.len() - off;
        handler.handle_ndp(now, frame, off, icmp_len, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
        assert_eq!(
            handler.lookup_v6(now, &router_ip),
            Some(MacAddress::from(router_mac))
        );
    }

    #[test]
    fn ra_without_source_lla_does_not_crash() {
        let now = Instant::now();
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let router_ip = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFE]);
        let ra = build_ra_payload(None);
        let frame_data = build_ndp_frame(
            [0xAA; 6],
            [0x33, 0x33, 0x00, 0x00, 0x00, 0x01],
            router_ip,
            Ipv6Address::new([0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            &ra,
        );

        let mut buf = vec![0u8; 512];
        buf[..frame_data.len()].copy_from_slice(&frame_data);
        let frame = Frame::new(0, &mut buf, frame_data.len(), false);

        let off = icmpv6_offset();
        let icmp_len = frame_data.len() - off;
        handler.handle_ndp(now, frame, off, icmp_len, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
        assert!(handler.lookup_v6(now, &router_ip).is_none());
    }

    #[test]
    fn rs_goes_to_rx() {
        let now = Instant::now();
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut rs_payload = vec![0u8; 8];
        rs_payload[0] = 133;
        let frame_data = build_ndp_frame(
            [0x11; 6],
            [0x33, 0x33, 0x00, 0x00, 0x00, 0x02],
            TEST_REMOTE_IPV6,
            Ipv6Address::new([0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
            &rs_payload,
        );

        let mut buf = vec![0u8; 512];
        buf[..frame_data.len()].copy_from_slice(&frame_data);
        let frame = Frame::new(0, &mut buf, frame_data.len(), false);

        let off = icmpv6_offset();
        let icmp_len = frame_data.len() - off;
        handler.handle_ndp(now, frame, off, icmp_len, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn redirect_goes_to_rx() {
        let now = Instant::now();
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut redirect_payload = vec![0u8; 40];
        redirect_payload[0] = 137;
        let frame_data = build_ndp_frame(
            [0x11; 6],
            TEST_LOCAL_MAC.into(),
            TEST_REMOTE_IPV6,
            TEST_LOCAL_IPV6,
            &redirect_payload,
        );

        let mut buf = vec![0u8; 512];
        buf[..frame_data.len()].copy_from_slice(&frame_data);
        let frame = Frame::new(0, &mut buf, frame_data.len(), false);

        let off = icmpv6_offset();
        let icmp_len = frame_data.len() - off;
        handler.handle_ndp(now, frame, off, icmp_len, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn resolve_v6_produces_valid_ns() {
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let target = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42]);

        let mut data = [0u8; 128];
        let frame = Frame::new(0, &mut data, 1, false);

        handler.resolve_v6(TEST_LOCAL_IPV6, target, frame, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 0);
        assert_eq!(tx.num_frames(), 1);

        let req = tx.pop().unwrap();
        assert_eq!(req.len(), NDP_NS_FRAME_LEN);

        let sol_mcast = target.solicited_node_multicast();
        let expected_mac = sol_mcast.multicast_mac();
        let eth = EthernetFrame::from_bytes(&req);
        assert_eq!(eth.dst_mac, expected_mac);
        assert_eq!(eth.src_mac, TEST_LOCAL_MAC);

        let ip = Ipv6Header::from_bytes(&req);
        assert_eq!(ip.dst_addr, sol_mcast);
        assert_eq!(ip.src_addr, TEST_LOCAL_IPV6);
        assert_eq!(ip.hop_limit, 255);

        let off = icmpv6_offset();
        assert_eq!(req[off], 135);

        let mut target_in_pkt = [0u8; 16];
        target_in_pkt.copy_from_slice(&req[off + 8..off + 24]);
        assert_eq!(Ipv6Address::from(target_in_pkt), target);

        assert_eq!(req[off + 24], 1);
        assert_eq!(req[off + 25], 1);
        let local_mac_bytes: [u8; 6] = TEST_LOCAL_MAC.into();
        assert_eq!(&req[off + 26..off + 32], &local_mac_bytes);

        let cksum = compute_icmpv6_checksum(&ip.src_addr, &ip.dst_addr, &req[off..off + 32]);
        assert_eq!(cksum, [0x00, 0x00]);
    }

    #[test]
    fn resolve_v6_frame_too_small_goes_to_rx() {
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = [0u8; 20];
        let frame = Frame::new(0, &mut data, 1, false);

        handler.resolve_v6(TEST_LOCAL_IPV6, TEST_REMOTE_IPV6, frame, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }
}
