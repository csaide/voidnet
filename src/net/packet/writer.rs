use std::sync::atomic::Ordering;

use crate::{
    net::{
        NeighborHandler, PmtuCache,
        packet::{ETH_HEADER_LEN, FragmentPlan, Packet},
        wire::{
            ethernet::{self, EtherTypes, MacAddress},
            ip::{
                FRAGMENT_EXT_LEN, IPV4_MIN_HEADER_LEN, IPV6_HEADER_LEN, IpAddress, IpProtocols,
                Ipv4Address, Ipv4Header, Ipv6Address, Ipv6Header,
            },
            udp::{self, UDP_HEADER_LEN},
        },
    },
    xdp::{
        error::{NonBlocking, WouldBlock},
        frame::{BasicFrameBuffer, FrameBuffer},
    },
};

use super::{DEFAULT_MTU, IPV4_ID, IPV6_ID};

pub struct PacketWriter<'parent, 'umem> {
    free_frames: &'parent mut BasicFrameBuffer<'umem>,
    rx_return: &'parent mut BasicFrameBuffer<'umem>,
    tx_return: &'parent mut BasicFrameBuffer<'umem>,
    pmtu: &'parent mut PmtuCache,
    neighbor_handler: &'parent mut NeighborHandler,
}

impl<'parent, 'umem> PacketWriter<'parent, 'umem> {
    pub fn new(
        free_frames: &'parent mut BasicFrameBuffer<'umem>,
        rx_return: &'parent mut BasicFrameBuffer<'umem>,
        tx_return: &'parent mut BasicFrameBuffer<'umem>,
        pmtu: &'parent mut PmtuCache,
        neighbor_handler: &'parent mut NeighborHandler,
    ) -> Self {
        Self {
            free_frames,
            rx_return,
            tx_return,
            pmtu,
            neighbor_handler,
        }
    }
    pub fn udp_packet(
        &mut self,
        src_addr: IpAddress,
        dst_addr: IpAddress,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> NonBlocking<Packet<'umem>> {
        // Step 1: MAC address resolution.
        let dst_mac = match self.neighbor_handler.lookup(&dst_addr) {
            Some(mac) => mac,
            None => {
                let frame = self.free_frames.pop().ok_or(WouldBlock)?;
                match (src_addr, dst_addr) {
                    (IpAddress::V4(src), IpAddress::V4(dst)) => {
                        self.neighbor_handler.resolve_v4(
                            src,
                            dst,
                            frame,
                            self.rx_return,
                            self.tx_return,
                        );
                    }
                    (IpAddress::V6(src), IpAddress::V6(dst)) => {
                        self.neighbor_handler.resolve_v6(
                            src,
                            dst,
                            frame,
                            self.rx_return,
                            self.tx_return,
                        );
                    }
                    _ => {
                        // Mismatched address families — return frame and error.
                        self.rx_return.push(frame);
                    }
                }
                return Err(WouldBlock);
            }
        };
        let src_mac = self.neighbor_handler.local_mac();

        let pmtu = self.pmtu.get(&dst_addr).min(DEFAULT_MTU);

        match (src_addr, dst_addr) {
            (IpAddress::V4(src_ip), IpAddress::V4(dst_ip)) => self.build_udp_v4(
                src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, payload, pmtu,
            ),
            (IpAddress::V6(src_ip), IpAddress::V6(dst_ip)) => self.build_udp_v6(
                src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, payload, pmtu,
            ),
            _ => Err(WouldBlock),
        }
    }

    fn build_udp_v4(
        &mut self,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
        pmtu: u32,
    ) -> NonBlocking<Packet<'umem>> {
        let max_payload = pmtu as usize - IPV4_MIN_HEADER_LEN - UDP_HEADER_LEN;

        if payload.len() <= max_payload {
            self.build_udp_v4_single(
                src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, payload,
            )
        } else {
            self.build_udp_v4_fragmented(
                src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, payload, pmtu,
            )
        }
    }

    fn build_udp_v4_single(
        &mut self,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> NonBlocking<Packet<'umem>> {
        let mut frame = self.free_frames.pop().ok_or(WouldBlock)?;
        let frame_len = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN + payload.len();
        unsafe { frame.set_len(frame_len) };

        // Ethernet header.
        ethernet::write_ethernet_header(&mut frame, dst_mac, src_mac, EtherTypes::IPv4);

        // IPv4 header.
        let ip_total_len = (IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN + payload.len()) as u16;
        let identification = IPV4_ID.fetch_add(1, Ordering::Relaxed);
        {
            let ip = Ipv4Header::from_frame_mut(&mut frame);
            ip.version_ihl = 0x45;
            ip.dscp_ecn = 0;
            ip.total_length = ip_total_len.to_be_bytes();
            ip.identification = identification.to_be_bytes();
            ip.flags_fragment_offset = [0x40, 0x00]; // DF set
            ip.ttl = 64;
            ip.protocol = IpProtocols::Udp;
            ip.header_checksum = [0, 0];
            ip.src_addr = src_ip;
            ip.dst_addr = dst_ip;
            ip.fill_checksum();
        }

        // UDP header + payload.
        let udp_offset = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;
        udp::write_udp_header(&mut frame, udp_offset, src_port, dst_port, udp_len);
        frame[udp_offset + UDP_HEADER_LEN..frame_len].copy_from_slice(payload);

        // UDP checksum.
        let cksum = udp::compute_udp_checksum(&src_ip, &dst_ip, &frame[udp_offset..frame_len]);
        frame[udp_offset + 6] = cksum[0];
        frame[udp_offset + 7] = cksum[1];

        Ok(Packet::Single(frame))
    }

    fn build_udp_v4_fragmented(
        &mut self,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
        pmtu: u32,
    ) -> NonBlocking<Packet<'umem>> {
        let plan = FragmentPlan::new(IPV4_MIN_HEADER_LEN, pmtu, payload.len());

        if self.free_frames.num_frames() < plan.num_frames {
            return Err(WouldBlock);
        }

        let identification = IPV4_ID.fetch_add(1, Ordering::Relaxed);
        let mut frames = Vec::with_capacity(plan.num_frames);
        let mut payload_offset = 0usize;
        // frag_byte_offset tracks the offset in the original IP payload (for fragment offset field).
        let mut frag_byte_offset = 0usize;

        // Pre-compute UDP checksum over the full (unfragmented) UDP segment.
        let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;
        let mut udp_segment = Vec::with_capacity(UDP_HEADER_LEN + payload.len());
        udp_segment.extend_from_slice(&src_port.to_be_bytes());
        udp_segment.extend_from_slice(&dst_port.to_be_bytes());
        udp_segment.extend_from_slice(&udp_len.to_be_bytes());
        udp_segment.extend_from_slice(&[0u8; 2]); // checksum placeholder
        udp_segment.extend_from_slice(payload);
        let udp_cksum = udp::compute_udp_checksum(&src_ip, &dst_ip, &udp_segment);

        for i in 0..plan.num_frames {
            let mut frame = self.free_frames.pop().ok_or(WouldBlock)?;
            let is_first = i == 0;
            let is_last = i == plan.num_frames - 1;

            let (ip_payload_len, data_to_copy) =
                plan.fragment_sizes(i, payload_offset, payload.len());

            let frame_len = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + ip_payload_len;
            unsafe { frame.set_len(frame_len) };

            // Ethernet header.
            ethernet::write_ethernet_header(&mut frame, dst_mac, src_mac, EtherTypes::IPv4);

            // IPv4 header.
            let ip_total_len = (IPV4_MIN_HEADER_LEN + ip_payload_len) as u16;
            let frag_offset_units = (frag_byte_offset / 8) as u16;
            let mf: u8 = if is_last { 0 } else { 0x20 };
            let flags_frag_hi = mf | ((frag_offset_units >> 8) as u8 & 0x1F);
            let flags_frag_lo = frag_offset_units as u8;

            {
                let ip = Ipv4Header::from_frame_mut(&mut frame);
                ip.version_ihl = 0x45;
                ip.dscp_ecn = 0;
                ip.total_length = ip_total_len.to_be_bytes();
                ip.identification = identification.to_be_bytes();
                ip.flags_fragment_offset = [flags_frag_hi, flags_frag_lo];
                ip.ttl = 64;
                ip.protocol = IpProtocols::Udp;
                ip.header_checksum = [0, 0];
                ip.src_addr = src_ip;
                ip.dst_addr = dst_ip;
                ip.fill_checksum();
            }

            let data_start = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;

            if is_first {
                // Write UDP header in first fragment.
                udp::write_udp_header(&mut frame, data_start, src_port, dst_port, udp_len);
                frame[data_start + 6] = udp_cksum[0];
                frame[data_start + 7] = udp_cksum[1];

                // Copy first payload chunk.
                let chunk = plan.first_chunk.min(payload.len());
                frame[data_start + UDP_HEADER_LEN..data_start + UDP_HEADER_LEN + chunk]
                    .copy_from_slice(&payload[..chunk]);
                payload_offset = chunk;
                frag_byte_offset = UDP_HEADER_LEN + chunk;
            } else {
                // Subsequent fragments: payload only.
                frame[data_start..data_start + data_to_copy]
                    .copy_from_slice(&payload[payload_offset..payload_offset + data_to_copy]);
                payload_offset += data_to_copy;
                frag_byte_offset += data_to_copy;
            }

            frames.push(frame);
        }

        Ok(Packet::Multi(frames))
    }

    fn build_udp_v6(
        &mut self,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
        pmtu: u32,
    ) -> NonBlocking<Packet<'umem>> {
        let max_payload = pmtu as usize - IPV6_HEADER_LEN - UDP_HEADER_LEN;

        if payload.len() <= max_payload {
            self.build_udp_v6_single(
                src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, payload,
            )
        } else {
            self.build_udp_v6_fragmented(
                src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, payload, pmtu,
            )
        }
    }

    fn build_udp_v6_single(
        &mut self,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> NonBlocking<Packet<'umem>> {
        let mut frame = self.free_frames.pop().ok_or(WouldBlock)?;
        let frame_len = ETH_HEADER_LEN + IPV6_HEADER_LEN + UDP_HEADER_LEN + payload.len();
        unsafe { frame.set_len(frame_len) };

        // Ethernet header.
        ethernet::write_ethernet_header(&mut frame, dst_mac, src_mac, EtherTypes::IPv6);

        // IPv6 header.
        let ipv6_payload_len = (UDP_HEADER_LEN + payload.len()) as u16;
        {
            let ip = Ipv6Header::from_frame_mut(&mut frame);
            ip.version_tc_fl = [0x60, 0x00, 0x00, 0x00];
            ip.payload_length = ipv6_payload_len.to_be_bytes();
            ip.next_header = IpProtocols::Udp;
            ip.hop_limit = 64;
            ip.src_addr = src_ip;
            ip.dst_addr = dst_ip;
        }

        // UDP header + payload.
        let udp_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;
        udp::write_udp_header(&mut frame, udp_offset, src_port, dst_port, udp_len);
        frame[udp_offset + UDP_HEADER_LEN..frame_len].copy_from_slice(payload);

        // UDP checksum (mandatory for IPv6).
        let cksum = udp::compute_udp_checksum_v6(&src_ip, &dst_ip, &frame[udp_offset..frame_len]);
        frame[udp_offset + 6] = cksum[0];
        frame[udp_offset + 7] = cksum[1];

        Ok(Packet::Single(frame))
    }

    fn build_udp_v6_fragmented(
        &mut self,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
        pmtu: u32,
    ) -> NonBlocking<Packet<'umem>> {
        let plan = FragmentPlan::new(IPV6_HEADER_LEN + FRAGMENT_EXT_LEN, pmtu, payload.len());

        if self.free_frames.num_frames() < plan.num_frames {
            return Err(WouldBlock);
        }

        let identification = IPV6_ID.fetch_add(1, Ordering::Relaxed);
        let mut frames = Vec::with_capacity(plan.num_frames);
        let mut payload_offset = 0usize;
        // frag_byte_offset tracks the offset in the "unfragmentable part" payload.
        let mut frag_byte_offset = 0usize;

        // Pre-compute UDP checksum over the full (unfragmented) UDP segment.
        let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;
        let mut udp_segment = Vec::with_capacity(UDP_HEADER_LEN + payload.len());
        udp_segment.extend_from_slice(&src_port.to_be_bytes());
        udp_segment.extend_from_slice(&dst_port.to_be_bytes());
        udp_segment.extend_from_slice(&udp_len.to_be_bytes());
        udp_segment.extend_from_slice(&[0u8; 2]); // checksum placeholder
        udp_segment.extend_from_slice(payload);
        let udp_cksum = udp::compute_udp_checksum_v6(&src_ip, &dst_ip, &udp_segment);

        for i in 0..plan.num_frames {
            let mut frame = self.free_frames.pop().ok_or(WouldBlock)?;
            let is_first = i == 0;
            let is_last = i == plan.num_frames - 1;

            let (frag_data_len, data_to_copy) =
                plan.fragment_sizes(i, payload_offset, payload.len());

            let frame_len = ETH_HEADER_LEN + IPV6_HEADER_LEN + FRAGMENT_EXT_LEN + frag_data_len;
            unsafe { frame.set_len(frame_len) };

            // Ethernet header.
            ethernet::write_ethernet_header(&mut frame, dst_mac, src_mac, EtherTypes::IPv6);

            // IPv6 header.
            let ipv6_payload_len = (FRAGMENT_EXT_LEN + frag_data_len) as u16;
            {
                let ip = Ipv6Header::from_frame_mut(&mut frame);
                ip.version_tc_fl = [0x60, 0x00, 0x00, 0x00];
                ip.payload_length = ipv6_payload_len.to_be_bytes();
                ip.next_header = 44; // Fragment extension header
                ip.hop_limit = 64;
                ip.src_addr = src_ip;
                ip.dst_addr = dst_ip;
            }

            // Fragment extension header (8 bytes).
            let frag_ext_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
            let frag_offset_units = (frag_byte_offset / 8) as u16;
            let mf: u16 = if is_last { 0 } else { 1 };
            let frag_offset_mf = (frag_offset_units << 3) | mf;

            frame[frag_ext_offset] = IpProtocols::Udp; // next header
            frame[frag_ext_offset + 1] = 0; // reserved
            frame[frag_ext_offset + 2..frag_ext_offset + 4]
                .copy_from_slice(&frag_offset_mf.to_be_bytes());
            frame[frag_ext_offset + 4..frag_ext_offset + 8]
                .copy_from_slice(&identification.to_be_bytes());

            let data_start = frag_ext_offset + FRAGMENT_EXT_LEN;

            if is_first {
                // Write UDP header in first fragment.
                udp::write_udp_header(&mut frame, data_start, src_port, dst_port, udp_len);
                frame[data_start + 6] = udp_cksum[0];
                frame[data_start + 7] = udp_cksum[1];

                let chunk = plan.first_chunk.min(payload.len());
                frame[data_start + UDP_HEADER_LEN..data_start + UDP_HEADER_LEN + chunk]
                    .copy_from_slice(&payload[..chunk]);
                payload_offset = chunk;
                frag_byte_offset = UDP_HEADER_LEN + chunk;
            } else {
                frame[data_start..data_start + data_to_copy]
                    .copy_from_slice(&payload[payload_offset..payload_offset + data_to_copy]);
                payload_offset += data_to_copy;
                frag_byte_offset += data_to_copy;
            }

            frames.push(frame);
        }

        Ok(Packet::Multi(frames))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::wire::ethernet::EthernetFrame;
    use crate::net::wire::ip::compute_ipv4_checksum;
    use crate::net::wire::udp::{verify_udp_checksum, verify_udp_checksum_v6};
    use crate::xdp::frame::Frame;
    use std::time::Duration;

    const TEST_LOCAL_MAC: MacAddress = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    const TEST_REMOTE_MAC: MacAddress = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    const TEST_LOCAL_IPV4: Ipv4Address = Ipv4Address::new([192, 168, 1, 1]);
    const TEST_REMOTE_IPV4: Ipv4Address = Ipv4Address::new([192, 168, 1, 100]);
    const TEST_LOCAL_IPV6: Ipv6Address =
        Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    const TEST_REMOTE_IPV6: Ipv6Address =
        Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

    fn new_handler_with_cache() -> NeighborHandler {
        let mut nh =
            NeighborHandler::new("test0", TEST_LOCAL_MAC, Duration::from_secs(60)).unwrap();
        nh.add_local_ipv4(TEST_LOCAL_IPV4);
        nh.add_local_ipv6(TEST_LOCAL_IPV6);
        nh
    }

    /// Inserts a neighbor entry by constructing and handling a fake ARP reply.
    fn seed_neighbor_v4(nh: &mut NeighborHandler) {
        use crate::net::wire::arp::{ARP_FRAME_LEN, ArpHardwareTypes, ArpOperations, ArpPacket};

        #[repr(C, packed)]
        struct ArpEthernetFrame {
            ethernet: EthernetFrame,
            arp: ArpPacket,
        }

        let f = ArpEthernetFrame {
            ethernet: EthernetFrame {
                dst_mac: TEST_LOCAL_MAC,
                src_mac: TEST_REMOTE_MAC,
                ether_type: EtherTypes::Arp,
            },
            arp: ArpPacket {
                htype: ArpHardwareTypes::Ethernet,
                ptype: EtherTypes::IPv4,
                hlen: 6,
                plen: 4,
                oper: ArpOperations::Reply,
                sha: TEST_REMOTE_MAC,
                spa: TEST_REMOTE_IPV4,
                tha: TEST_LOCAL_MAC,
                tpa: TEST_LOCAL_IPV4,
            },
        };

        let bytes = unsafe {
            std::slice::from_raw_parts(
                &f as *const _ as *const u8,
                std::mem::size_of::<ArpEthernetFrame>(),
            )
        };
        let mut buf = [0u8; 64];
        buf[..bytes.len()].copy_from_slice(bytes);
        let frame = Frame::new(0, &mut buf, ARP_FRAME_LEN, false);
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        nh.handle_arp(frame, &mut rx, &mut tx);
    }

    /// Seeds a neighbor entry for IPv6 by handling a fake NA.
    fn seed_neighbor_v6(nh: &mut NeighborHandler) {
        use crate::net::wire::icmpv6::compute_icmpv6_checksum;

        let eth_len = size_of::<EthernetFrame>();
        let icmpv6_len = 32; // NA: 8 header + 16 target + 8 target LLA option
        let frame_len = eth_len + IPV6_HEADER_LEN + icmpv6_len;
        let mut buf = vec![0u8; 512];

        // Ethernet
        let remote_mac_bytes: [u8; 6] = TEST_REMOTE_MAC.into();
        let local_mac_bytes: [u8; 6] = TEST_LOCAL_MAC.into();
        buf[0..6].copy_from_slice(&local_mac_bytes);
        buf[6..12].copy_from_slice(&remote_mac_bytes);
        buf[12] = 0x86;
        buf[13] = 0xDD;

        // IPv6
        buf[14] = 0x60;
        let payload_len = (icmpv6_len as u16).to_be_bytes();
        buf[18..20].copy_from_slice(&payload_len);
        buf[20] = IpProtocols::IcmpV6;
        buf[21] = 255;
        let src_bytes: [u8; 16] = TEST_REMOTE_IPV6.into();
        buf[22..38].copy_from_slice(&src_bytes);
        let dst_bytes: [u8; 16] = TEST_LOCAL_IPV6.into();
        buf[38..54].copy_from_slice(&dst_bytes);

        // ICMPv6 NA
        let icmp_off = eth_len + IPV6_HEADER_LEN;
        buf[icmp_off] = 136; // NA type
        buf[icmp_off + 1] = 0;
        buf[icmp_off + 4] = 0x60; // S+O flags

        // Target address = remote
        let target_bytes: [u8; 16] = TEST_REMOTE_IPV6.into();
        buf[icmp_off + 8..icmp_off + 24].copy_from_slice(&target_bytes);

        // Target LLA option
        buf[icmp_off + 24] = 2; // type
        buf[icmp_off + 25] = 1; // length
        buf[icmp_off + 26..icmp_off + 32].copy_from_slice(&remote_mac_bytes);

        // Checksum
        buf[icmp_off + 2] = 0;
        buf[icmp_off + 3] = 0;
        let cksum = compute_icmpv6_checksum(
            &TEST_REMOTE_IPV6,
            &TEST_LOCAL_IPV6,
            &buf[icmp_off..icmp_off + icmpv6_len],
        );
        buf[icmp_off + 2] = cksum[0];
        buf[icmp_off + 3] = cksum[1];

        let frame = Frame::new(0, &mut buf, frame_len, false);
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        nh.handle_ndp(frame, icmp_off, icmpv6_len, &mut rx, &mut tx);
    }

    macro_rules! setup_writer {
        ($nh:ident, $free:ident, $bufs:ident, $rx:ident, $tx:ident, $pmtu:ident, $seed:ident, $n:expr) => {
            let mut $nh = new_handler_with_cache();
            $seed(&mut $nh);
            let mut $free = BasicFrameBuffer::new($n * 2);
            let mut $bufs: Vec<Vec<u8>> = (0..$n).map(|_| vec![0u8; 2048]).collect();
            for (i, buf) in $bufs.iter_mut().enumerate() {
                $free.push(Frame::new(i as u64, buf.as_mut_slice(), 1, false));
            }
            let mut $rx = BasicFrameBuffer::new(16);
            let mut $tx = BasicFrameBuffer::new(16);
            let mut $pmtu = PmtuCache::new();
        };
    }

    fn assert_ethernet_header(frame: &Frame, dst_mac: MacAddress, src_mac: MacAddress, ether_type: crate::net::wire::ethernet::EtherType) {
        let eth = EthernetFrame::from_frame(frame);
        assert_eq!(eth.dst_mac, dst_mac);
        assert_eq!(eth.src_mac, src_mac);
        assert_eq!(eth.ether_type, ether_type);
    }

    fn assert_payload_eq(frame: &Frame, payload_offset: usize, expected: &[u8]) {
        assert_eq!(&frame[payload_offset..frame.len()], expected);
    }

    #[test]
    fn single_ipv4_packet() {
        setup_writer!(nh, free, bufs, rx, tx, pmtu, seed_neighbor_v4, 8);
        let mut writer = PacketWriter::new(&mut free, &mut rx, &mut tx, &mut pmtu, &mut nh);

        let payload = b"Hello, World!";
        let result = writer.udp_packet(
            IpAddress::V4(TEST_LOCAL_IPV4),
            IpAddress::V4(TEST_REMOTE_IPV4),
            12345,
            53,
            payload,
        );

        let packet = result.expect("should succeed");
        match packet {
            Packet::Single(frame) => {
                let expected_len =
                    ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN + payload.len();
                assert_eq!(frame.len(), expected_len);

                assert_ethernet_header(&frame, TEST_REMOTE_MAC, TEST_LOCAL_MAC, EtherTypes::IPv4);

                let ip = Ipv4Header::from_frame(&frame);
                assert_eq!(ip.version(), 4);
                assert_eq!(ip.ihl(), 5);
                assert_eq!(ip.ttl, 64);
                assert_eq!(ip.protocol, IpProtocols::Udp);
                assert_eq!(ip.src_addr, TEST_LOCAL_IPV4);
                assert_eq!(ip.dst_addr, TEST_REMOTE_IPV4);
                assert!(ip.dont_fragment());
                let ip_bytes = &frame[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN];
                assert_eq!(compute_ipv4_checksum(ip_bytes), [0x00, 0x00]);

                let udp_offset = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
                assert!(verify_udp_checksum(
                    &TEST_LOCAL_IPV4,
                    &TEST_REMOTE_IPV4,
                    &frame[udp_offset..frame.len()],
                ));

                assert_payload_eq(&frame, udp_offset + UDP_HEADER_LEN, payload);
            }
            Packet::Multi(_) => panic!("expected Single packet"),
        }
    }

    #[test]
    fn single_ipv6_packet() {
        setup_writer!(nh, free, bufs, rx, tx, pmtu, seed_neighbor_v6, 8);
        let mut builder = PacketWriter::new(&mut free, &mut rx, &mut tx, &mut pmtu, &mut nh);

        let payload = b"Hello, IPv6!";
        let result = builder.udp_packet(
            IpAddress::V6(TEST_LOCAL_IPV6),
            IpAddress::V6(TEST_REMOTE_IPV6),
            12345,
            53,
            payload,
        );

        let packet = result.expect("should succeed");
        match packet {
            Packet::Single(frame) => {
                let expected_len =
                    ETH_HEADER_LEN + IPV6_HEADER_LEN + UDP_HEADER_LEN + payload.len();
                assert_eq!(frame.len(), expected_len);

                assert_ethernet_header(&frame, TEST_REMOTE_MAC, TEST_LOCAL_MAC, EtherTypes::IPv6);

                let ip = Ipv6Header::from_frame(&frame);
                assert_eq!(ip.version(), 6);
                assert_eq!(ip.hop_limit, 64);
                assert_eq!(ip.next_header, IpProtocols::Udp);
                assert_eq!(ip.src_addr, TEST_LOCAL_IPV6);
                assert_eq!(ip.dst_addr, TEST_REMOTE_IPV6);

                let udp_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
                assert!(verify_udp_checksum_v6(
                    &TEST_LOCAL_IPV6,
                    &TEST_REMOTE_IPV6,
                    &frame[udp_offset..frame.len()],
                ));

                assert_payload_eq(&frame, udp_offset + UDP_HEADER_LEN, payload);
            }
            Packet::Multi(_) => panic!("expected Single packet"),
        }
    }

    #[test]
    fn mac_miss_returns_would_block_and_sends_arp() {
        let mut nh = new_handler_with_cache();
        // Don't seed neighbor — MAC is unknown.
        let mut free = BasicFrameBuffer::new(16);
        let mut bufs: Vec<Vec<u8>> = (0..8).map(|_| vec![0u8; 2048]).collect();
        for (i, buf) in bufs.iter_mut().enumerate() {
            free.push(Frame::new(i as u64, buf.as_mut_slice(), 1, false));
        }
        let mut rx = BasicFrameBuffer::new(16);
        let mut tx = BasicFrameBuffer::new(16);
        let mut pmtu = PmtuCache::new();

        let mut builder = PacketWriter::new(&mut free, &mut rx, &mut tx, &mut pmtu, &mut nh);

        let result = builder.udp_packet(
            IpAddress::V4(TEST_LOCAL_IPV4),
            IpAddress::V4(TEST_REMOTE_IPV4),
            1234,
            5678,
            b"test",
        );

        assert_eq!(result.unwrap_err(), WouldBlock);
        assert_eq!(tx.num_frames(), 1);
        assert_eq!(free.num_frames(), 7);
    }

    #[test]
    fn not_enough_frames_returns_would_block() {
        let mut nh = new_handler_with_cache();
        seed_neighbor_v4(&mut nh);

        let mut free = BasicFrameBuffer::new(16);
        let mut rx = BasicFrameBuffer::new(16);
        let mut tx = BasicFrameBuffer::new(16);
        let mut pmtu = PmtuCache::new();

        let mut builder = PacketWriter::new(&mut free, &mut rx, &mut tx, &mut pmtu, &mut nh);

        let result = builder.udp_packet(
            IpAddress::V4(TEST_LOCAL_IPV4),
            IpAddress::V4(TEST_REMOTE_IPV4),
            1234,
            5678,
            b"test",
        );

        assert_eq!(result.unwrap_err(), WouldBlock);
    }

    #[test]
    fn ipv4_fragmented_packet() {
        setup_writer!(nh, free, bufs, rx, tx, pmtu, seed_neighbor_v4, 32);
        let mut builder = PacketWriter::new(&mut free, &mut rx, &mut tx, &mut pmtu, &mut nh);

        // max_payload for single = 1500 - 20 - 8 = 1472
        let payload = vec![0xAB; 3000];
        let result = builder.udp_packet(
            IpAddress::V4(TEST_LOCAL_IPV4),
            IpAddress::V4(TEST_REMOTE_IPV4),
            12345,
            53,
            &payload,
        );

        let packet = result.expect("should succeed");
        match packet {
            Packet::Multi(frames) => {
                assert!(frames.len() >= 2);

                let first_id = Ipv4Header::from_frame(&frames[0]).identification();
                for f in &frames {
                    let ip = Ipv4Header::from_frame(f);
                    assert_eq!(ip.identification(), first_id);
                    assert_eq!(ip.protocol, IpProtocols::Udp);
                    assert_eq!(ip.src_addr, TEST_LOCAL_IPV4);
                    assert_eq!(ip.dst_addr, TEST_REMOTE_IPV4);
                    assert!(!ip.dont_fragment());
                    let ip_bytes = &f[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN];
                    assert_eq!(compute_ipv4_checksum(ip_bytes), [0x00, 0x00]);
                }

                let first_ip = Ipv4Header::from_frame(&frames[0]);
                assert!(first_ip.more_fragments());
                assert_eq!(first_ip.fragment_offset(), 0);

                let last_ip = Ipv4Header::from_frame(frames.last().unwrap());
                assert!(!last_ip.more_fragments());

                for (i, f) in frames.iter().enumerate() {
                    let ip = Ipv4Header::from_frame(f);
                    if i < frames.len() - 1 {
                        assert_eq!(
                            ip.payload_len() % 8,
                            0,
                            "non-last fragment payload not 8-aligned"
                        );
                    }
                }

                // Reassemble and verify payload.
                let mut reassembled = Vec::new();
                for (i, f) in frames.iter().enumerate() {
                    let data_start = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
                    if i == 0 {
                        reassembled.extend_from_slice(&f[data_start + UDP_HEADER_LEN..f.len()]);
                    } else {
                        reassembled.extend_from_slice(&f[data_start..f.len()]);
                    }
                }
                assert_eq!(reassembled, payload);
            }
            Packet::Single(_) => panic!("expected Multi packet for large payload"),
        }
    }

    #[test]
    fn ipv6_fragmented_packet() {
        setup_writer!(nh, free, bufs, rx, tx, pmtu, seed_neighbor_v6, 32);
        let mut builder = PacketWriter::new(&mut free, &mut rx, &mut tx, &mut pmtu, &mut nh);

        // max_payload for single = 1500 - 40 - 8 = 1452
        let payload = vec![0xCD; 3000];
        let result = builder.udp_packet(
            IpAddress::V6(TEST_LOCAL_IPV6),
            IpAddress::V6(TEST_REMOTE_IPV6),
            12345,
            53,
            &payload,
        );

        let packet = result.expect("should succeed");
        match packet {
            Packet::Multi(frames) => {
                assert!(frames.len() >= 2);

                let frag_ext_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
                let first_id = u32::from_be_bytes([
                    frames[0][frag_ext_offset + 4],
                    frames[0][frag_ext_offset + 5],
                    frames[0][frag_ext_offset + 6],
                    frames[0][frag_ext_offset + 7],
                ]);

                for f in &frames {
                    let ip = Ipv6Header::from_frame(f);
                    assert_eq!(ip.next_header, 44);
                    assert_eq!(ip.src_addr, TEST_LOCAL_IPV6);
                    assert_eq!(ip.dst_addr, TEST_REMOTE_IPV6);

                    let id = u32::from_be_bytes([
                        f[frag_ext_offset + 4],
                        f[frag_ext_offset + 5],
                        f[frag_ext_offset + 6],
                        f[frag_ext_offset + 7],
                    ]);
                    assert_eq!(id, first_id);
                    assert_eq!(f[frag_ext_offset], IpProtocols::Udp);
                }

                let first_frag_offset_mf = u16::from_be_bytes([
                    frames[0][frag_ext_offset + 2],
                    frames[0][frag_ext_offset + 3],
                ]);
                assert_eq!(first_frag_offset_mf & 1, 1);
                assert_eq!(first_frag_offset_mf >> 3, 0);

                let last = frames.last().unwrap();
                let last_frag_offset_mf =
                    u16::from_be_bytes([last[frag_ext_offset + 2], last[frag_ext_offset + 3]]);
                assert_eq!(last_frag_offset_mf & 1, 0);

                // Reassemble and verify payload.
                let mut reassembled = Vec::new();
                for (i, f) in frames.iter().enumerate() {
                    let data_start = frag_ext_offset + FRAGMENT_EXT_LEN;
                    if i == 0 {
                        reassembled.extend_from_slice(&f[data_start + UDP_HEADER_LEN..f.len()]);
                    } else {
                        reassembled.extend_from_slice(&f[data_start..f.len()]);
                    }
                }
                assert_eq!(reassembled, payload);
            }
            Packet::Single(_) => panic!("expected Multi packet for large payload"),
        }
    }

    #[test]
    fn empty_payload() {
        // IPv4
        setup_writer!(nh4, free4, bufs4, rx4, tx4, pmtu4, seed_neighbor_v4, 4);
        let mut w4 = PacketWriter::new(&mut free4, &mut rx4, &mut tx4, &mut pmtu4, &mut nh4);
        let r4 = w4.udp_packet(
            IpAddress::V4(TEST_LOCAL_IPV4),
            IpAddress::V4(TEST_REMOTE_IPV4),
            1234,
            5678,
            &[],
        );
        match r4.expect("should succeed") {
            Packet::Single(frame) => {
                assert_eq!(frame.len(), ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN);
            }
            Packet::Multi(_) => panic!("expected Single"),
        }

        // IPv6
        setup_writer!(nh6, free6, bufs6, rx6, tx6, pmtu6, seed_neighbor_v6, 4);
        let mut w6 = PacketWriter::new(&mut free6, &mut rx6, &mut tx6, &mut pmtu6, &mut nh6);
        let r6 = w6.udp_packet(
            IpAddress::V6(TEST_LOCAL_IPV6),
            IpAddress::V6(TEST_REMOTE_IPV6),
            1234,
            5678,
            &[],
        );
        match r6.expect("should succeed") {
            Packet::Single(frame) => {
                assert_eq!(frame.len(), ETH_HEADER_LEN + IPV6_HEADER_LEN + UDP_HEADER_LEN);
            }
            Packet::Multi(_) => panic!("expected Single"),
        }
    }
}
