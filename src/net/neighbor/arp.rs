use coarsetime::{Duration, Instant};
use dashmap::DashMap;

use crate::{
    net::wire::{
        arp::{ARP_FRAME_LEN, ArpFrame, ArpHardwareTypes, ArpOperations},
        ethernet::{EtherTypes, MacAddress},
        ip::{IpAddress, Ipv4Address},
    },
    xdp::frame::{Frame, FrameBuffer},
};

use super::NeighborEntry;

#[inline(always)]
pub(super) fn resolve_v4<'umem>(
    local_mac: MacAddress,
    source_ip: Ipv4Address,
    target_ip: Ipv4Address,
    mut frame: Frame<'umem>,
    rx_return: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) {
    // This is essentially a no-op since frames really can't be this small, but
    // JUST in case lets check and bail out.
    if frame.capacity() < ARP_FRAME_LEN {
        rx_return.push(frame);
        return;
    }

    // First set the frame length to the full ARP frame length.
    //
    // SAFETY: we know for a fact we can store this much data so we are good to go.
    unsafe {
        frame.set_len(ARP_FRAME_LEN);
    }

    // Create our ARP request frame:
    // - Broadcast ethernet frame, set to ARP protocol.
    // - ARP request packet, for Ethernet/IPv4, sent to the target IP.
    let arp = ArpFrame::from_bytes_mut(&mut frame);

    // First setup ethernet headers.
    arp.ethernet.dst_mac = MacAddress::broadcast();
    arp.ethernet.src_mac = local_mac;
    arp.ethernet.ether_type = EtherTypes::Arp;

    // Fill out all arp fields.
    arp.arp.htype = ArpHardwareTypes::Ethernet;
    arp.arp.ptype = EtherTypes::IPv4;
    arp.arp.hlen = 6;
    arp.arp.plen = 4;
    arp.arp.oper = ArpOperations::Request;
    arp.arp.sha = local_mac;
    arp.arp.spa = source_ip;
    arp.arp.tha = MacAddress::zero();
    arp.arp.tpa = target_ip;

    // Push the frame to the TX buffer for transmission.
    tx_return.push(frame);
}

pub(super) fn handle_arp<'umem>(
    now: Instant,
    table: &DashMap<IpAddress, NeighborEntry>,
    local_mac: MacAddress,
    local_ipv4: &[Ipv4Address],
    ttl: Duration,
    mut frame: Frame<'umem>,
    rx_return: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) {
    // Check frame length here make sure we at least have enough data to parse the ARP packet.
    if frame.len() < ARP_FRAME_LEN {
        rx_return.push(frame);
        return;
    }

    // Parse the ARP packet from the frame.
    let ArpFrame { ethernet, arp } = ArpFrame::from_bytes_mut(&mut frame);

    // Verify that we are dealing with:
    // - Ethernet hardware type.
    // - IPv4 protocol type.
    // - 6-byte hardware address length.
    // - 4-byte protocol address length.
    //
    // If not, return the frame to the RX buffer.
    if arp.htype != ArpHardwareTypes::Ethernet
        || arp.ptype != EtherTypes::IPv4
        || arp.hlen != 6
        || arp.plen != 4
    {
        rx_return.push(frame);
        return;
    }

    // Extract the sender and target addresses from the ARP packet.
    let sha = arp.sha;
    let spa = arp.spa;

    // Insert the sender into the neighbor table.
    table.insert(IpAddress::V4(spa), NeighborEntry::new(sha, now + ttl));

    // If we are not dealing with an ARP request or the target IP is not one of our local IPv4 addresses,
    // return the frame to the RX buffer.
    if arp.oper != ArpOperations::Request || !local_ipv4.contains(&arp.tpa) {
        rx_return.push(frame);
        return;
    }

    // Swap the ethernet frame's source and destination MAC addresses.
    ethernet.dst_mac = sha;
    ethernet.src_mac = local_mac;

    // Swap the ARP packet's sender and target addresses, and set the operation to reply.
    arp.oper = ArpOperations::Reply;
    arp.sha = local_mac;
    arp.spa = arp.tpa;
    arp.tha = sha;
    arp.tpa = spa;

    // Push the frame to the TX buffer.
    tx_return.push(frame);
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        net::{
            neighbor::NeighborHandler,
            wire::{
                arp::{ARP_FRAME_LEN, ArpFrame, ArpHardwareTypes, ArpOperations, ArpPacket},
                ethernet::{EtherTypes, EthernetFrame, MacAddress},
                ip::Ipv4Address,
            },
        },
        xdp::frame::{BasicFrameBuffer, Frame, FrameBuffer},
    };

    const TEST_LOCAL_MAC: MacAddress = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    const TEST_LOCAL_IP: Ipv4Address = Ipv4Address::new([192, 168, 1, 1]);
    const TEST_REMOTE_MAC: MacAddress = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    const TEST_REMOTE_IP: Ipv4Address = Ipv4Address::new([192, 168, 1, 100]);
    const TEST_TTL: Duration = Duration::from_secs(60);

    fn new_handler() -> NeighborHandler {
        let mut nh = NeighborHandler::new("test0", TEST_TTL).unwrap();
        nh.add_local_ipv4(TEST_LOCAL_IP);
        nh.set_local_mac(TEST_LOCAL_MAC);
        nh
    }

    fn build_arp_request_bytes(target_ip: Ipv4Address) -> [u8; ARP_FRAME_LEN] {
        let f = ArpFrame {
            ethernet: EthernetFrame {
                dst_mac: MacAddress::broadcast(),
                src_mac: TEST_REMOTE_MAC,
                ether_type: EtherTypes::Arp,
            },
            arp: ArpPacket {
                htype: ArpHardwareTypes::Ethernet,
                ptype: EtherTypes::IPv4,
                hlen: 6,
                plen: 4,
                oper: ArpOperations::Request,
                sha: TEST_REMOTE_MAC,
                spa: TEST_REMOTE_IP,
                tha: MacAddress::zero(),
                tpa: target_ip,
            },
        };
        let mut bytes = [0u8; ARP_FRAME_LEN];
        bytes.copy_from_slice(f.as_bytes());
        bytes
    }

    fn build_arp_reply_bytes(
        sender_mac: MacAddress,
        sender_ip: Ipv4Address,
    ) -> [u8; ARP_FRAME_LEN] {
        let f = ArpFrame {
            ethernet: EthernetFrame {
                dst_mac: TEST_LOCAL_MAC,
                src_mac: sender_mac,
                ether_type: EtherTypes::Arp,
            },
            arp: ArpPacket {
                htype: ArpHardwareTypes::Ethernet,
                ptype: EtherTypes::IPv4,
                hlen: 6,
                plen: 4,
                oper: ArpOperations::Reply,
                sha: sender_mac,
                spa: sender_ip,
                tha: TEST_LOCAL_MAC,
                tpa: TEST_LOCAL_IP,
            },
        };
        let mut bytes = [0u8; ARP_FRAME_LEN];
        bytes.copy_from_slice(f.as_bytes());
        bytes
    }

    #[test]
    fn valid_request_produces_reply() {
        let now = Instant::now();
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = build_arp_request_bytes(TEST_LOCAL_IP);
        let frame = Frame::new(0, &mut data, ARP_FRAME_LEN, false);

        handler.handle_arp(now, frame, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 0);
        assert_eq!(tx.num_frames(), 1);

        let reply = tx.pop().unwrap();
        let eth = EthernetFrame::from_bytes(&reply);
        let arp = ArpPacket::from_bytes(&reply);

        assert_eq!(eth.dst_mac, TEST_REMOTE_MAC);
        assert_eq!(eth.src_mac, TEST_LOCAL_MAC);
        assert_eq!(arp.oper, ArpOperations::Reply);
        assert_eq!(arp.sha, TEST_LOCAL_MAC);
        assert_eq!(arp.spa, TEST_LOCAL_IP);
        assert_eq!(arp.tha, TEST_REMOTE_MAC);
        assert_eq!(arp.tpa, TEST_REMOTE_IP);
    }

    #[test]
    fn request_for_wrong_ip_goes_to_rx() {
        let now = Instant::now();
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let wrong = Ipv4Address::new([10, 0, 0, 1]);
        let mut data = build_arp_request_bytes(wrong);
        let frame = Frame::new(0, &mut data, ARP_FRAME_LEN, false);

        handler.handle_arp(now, frame, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn reply_goes_to_rx() {
        let now = Instant::now();
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = build_arp_reply_bytes(TEST_REMOTE_MAC, TEST_REMOTE_IP);
        let frame = Frame::new(0, &mut data, ARP_FRAME_LEN, false);

        handler.handle_arp(now, frame, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn frame_too_short_goes_to_rx() {
        let now = Instant::now();
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = [0u8; 30];
        let frame = Frame::new(0, &mut data, 30, false);

        handler.handle_arp(now, frame, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn invalid_htype_goes_to_rx() {
        let now = Instant::now();
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = build_arp_request_bytes(TEST_LOCAL_IP);
        data[14] = 0xFF;
        data[15] = 0xFF;
        let frame = Frame::new(0, &mut data, ARP_FRAME_LEN, false);

        handler.handle_arp(now, frame, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn invalid_ptype_goes_to_rx() {
        let now = Instant::now();
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = build_arp_request_bytes(TEST_LOCAL_IP);
        data[16] = 0x86;
        data[17] = 0xDD;
        let frame = Frame::new(0, &mut data, ARP_FRAME_LEN, false);

        handler.handle_arp(now, frame, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn invalid_address_lengths_goes_to_rx() {
        let now = Instant::now();
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = build_arp_request_bytes(TEST_LOCAL_IP);
        data[18] = 8;
        let frame = Frame::new(0, &mut data, ARP_FRAME_LEN, false);

        handler.handle_arp(now, frame, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn request_caches_sender() {
        let now = Instant::now();
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        assert!(handler.lookup_v4(now, &TEST_REMOTE_IP).is_none());

        let mut data = build_arp_request_bytes(TEST_LOCAL_IP);
        let frame = Frame::new(0, &mut data, ARP_FRAME_LEN, false);
        handler.handle_arp(now, frame, &mut rx, &mut tx);

        assert_eq!(
            handler.lookup_v4(now, &TEST_REMOTE_IP),
            Some(TEST_REMOTE_MAC)
        );
    }

    #[test]
    fn reply_caches_sender() {
        let now = Instant::now();
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        assert!(handler.lookup_v4(now, &TEST_REMOTE_IP).is_none());

        let mut data = build_arp_reply_bytes(TEST_REMOTE_MAC, TEST_REMOTE_IP);
        let frame = Frame::new(0, &mut data, ARP_FRAME_LEN, false);
        handler.handle_arp(now, frame, &mut rx, &mut tx);

        assert_eq!(
            handler.lookup_v4(now, &TEST_REMOTE_IP),
            Some(TEST_REMOTE_MAC)
        );
    }

    #[test]
    fn wrong_target_still_caches_sender() {
        let now = Instant::now();
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let wrong = Ipv4Address::new([10, 0, 0, 1]);
        let mut data = build_arp_request_bytes(wrong);
        let frame = Frame::new(0, &mut data, ARP_FRAME_LEN, false);
        handler.handle_arp(now, frame, &mut rx, &mut tx);

        assert_eq!(
            handler.lookup_v4(now, &TEST_REMOTE_IP),
            Some(TEST_REMOTE_MAC)
        );
    }

    #[test]
    fn cache_updates_on_new_mac() {
        let now = Instant::now();
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = build_arp_reply_bytes(TEST_REMOTE_MAC, TEST_REMOTE_IP);
        let frame = Frame::new(0, &mut data, ARP_FRAME_LEN, false);
        handler.handle_arp(now, frame, &mut rx, &mut tx);
        assert_eq!(
            handler.lookup_v4(now, &TEST_REMOTE_IP),
            Some(TEST_REMOTE_MAC)
        );

        let new_mac = MacAddress::new([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
        let mut data2 = build_arp_reply_bytes(new_mac, TEST_REMOTE_IP);
        let frame2 = Frame::new(0, &mut data2, ARP_FRAME_LEN, false);
        handler.handle_arp(now, frame2, &mut rx, &mut tx);
        assert_eq!(handler.lookup_v4(now, &TEST_REMOTE_IP), Some(new_mac));
    }

    #[test]
    fn expired_entry_returns_none() {
        let now = Instant::now();
        let mut handler = NeighborHandler::new("test0", Duration::from_ticks(0)).unwrap();
        handler.add_local_ipv4(TEST_LOCAL_IP);
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = build_arp_reply_bytes(TEST_REMOTE_MAC, TEST_REMOTE_IP);
        let frame = Frame::new(0, &mut data, ARP_FRAME_LEN, false);
        handler.handle_arp(now, frame, &mut rx, &mut tx);

        assert!(handler.lookup_v4(now, &TEST_REMOTE_IP).is_none());
    }

    #[test]
    fn lookup_unknown_returns_none() {
        let now = Instant::now();
        let handler = new_handler();
        let unknown = Ipv4Address::new([10, 0, 0, 1]);
        assert!(handler.lookup_v4(now, &unknown).is_none());
    }

    #[test]
    fn invalid_packet_does_not_cache() {
        let now = Instant::now();
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = [0u8; 30];
        let frame = Frame::new(0, &mut data, 30, false);
        handler.handle_arp(now, frame, &mut rx, &mut tx);

        assert!(handler.lookup_v4(now, &TEST_REMOTE_IP).is_none());
    }

    #[test]
    fn resolve_produces_valid_request() {
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let target = Ipv4Address::new([192, 168, 1, 200]);

        let mut data = [0u8; 64];
        let frame = Frame::new(0, &mut data, 1, false);

        handler.resolve_v4(TEST_LOCAL_IP, target, frame, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 0);
        assert_eq!(tx.num_frames(), 1);

        let req = tx.pop().unwrap();
        assert_eq!(req.len(), ARP_FRAME_LEN);

        let eth = EthernetFrame::from_bytes(&req);
        let arp = ArpPacket::from_bytes(&req);

        assert_eq!(eth.dst_mac, MacAddress::broadcast());
        assert_eq!(eth.src_mac, TEST_LOCAL_MAC);
        assert_eq!(eth.ether_type, EtherTypes::Arp);

        assert_eq!(arp.htype, ArpHardwareTypes::Ethernet);
        assert_eq!(arp.ptype, EtherTypes::IPv4);
        assert_eq!(arp.hlen, 6);
        assert_eq!(arp.plen, 4);
        assert_eq!(arp.oper, ArpOperations::Request);
        assert_eq!(arp.sha, TEST_LOCAL_MAC);
        assert_eq!(arp.spa, TEST_LOCAL_IP);
        assert_eq!(arp.tha, MacAddress::zero());
        assert_eq!(arp.tpa, target);
    }

    #[test]
    fn resolve_frame_too_small_goes_to_rx() {
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = [0u8; 20];
        let frame = Frame::new(0, &mut data, 1, false);

        handler.resolve_v4(
            TEST_LOCAL_IP,
            Ipv4Address::new([10, 0, 0, 1]),
            frame,
            &mut rx,
            &mut tx,
        );

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }
}
