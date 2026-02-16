use std::collections::HashMap;
use std::mem::size_of;
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use crate::{
    net::{
        EtherTypes, EthernetFrame, IpAddress, MacAddress, NeighborHandler, PmtuCache,
        ip::{IpProtocols, Ipv4Address, Ipv6Address},
        ipv4::{IPV4_MIN_HEADER_LEN, Ipv4Header},
        ipv6::{FRAGMENT_EXT_LEN, IPV6_HEADER_LEN, Ipv6Header},
        udp::{UDP_HEADER_LEN, UdpHeader, compute_udp_checksum, compute_udp_checksum_v6},
    },
    xdp::{
        error::{NonBlocking, WouldBlock},
        frame::{BasicFrameBuffer, Frame, FrameBuffer},
    },
};

const ETH_HEADER_LEN: usize = size_of::<EthernetFrame>();
const DEFAULT_MTU: u32 = 1500;

/// Global atomic counter for IPv4 identification field.
static IPV4_ID: AtomicU16 = AtomicU16::new(1);

/// Global atomic counter for IPv6 fragment header identification field.
static IPV6_ID: AtomicU32 = AtomicU32::new(1);

#[derive(Debug)]
pub enum Packet<'umem> {
    Single(Frame<'umem>),
    Multi(Vec<Frame<'umem>>),
}

impl<'umem> Packet<'umem> {
    /// Returns the number of frames in this packet.
    pub fn num_frames(&self) -> usize {
        match self {
            Packet::Single(_) => 1,
            Packet::Multi(frames) => frames.len(),
        }
    }

    /// Returns a borrowing iterator over the frames in this packet.
    pub fn frames(&self) -> PacketFrameIter<'_, 'umem> {
        match self {
            Packet::Single(frame) => PacketFrameIter::Single(std::iter::once(frame)),
            Packet::Multi(frames) => PacketFrameIter::Multi(frames.iter()),
        }
    }

    /// Returns a consuming iterator over the frames in this packet.
    pub fn into_frames(self) -> PacketIntoIter<'umem> {
        match self {
            Packet::Single(frame) => PacketIntoIter::Single(std::iter::once(frame)),
            Packet::Multi(frames) => PacketIntoIter::Multi(frames.into_iter()),
        }
    }
}

/// Borrowing iterator over frames in a [`Packet`].
pub enum PacketFrameIter<'a, 'umem> {
    Single(std::iter::Once<&'a Frame<'umem>>),
    Multi(std::slice::Iter<'a, Frame<'umem>>),
}

impl<'a, 'umem> Iterator for PacketFrameIter<'a, 'umem> {
    type Item = &'a Frame<'umem>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            PacketFrameIter::Single(iter) => iter.next(),
            PacketFrameIter::Multi(iter) => iter.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            PacketFrameIter::Single(iter) => iter.size_hint(),
            PacketFrameIter::Multi(iter) => iter.size_hint(),
        }
    }
}

impl<'a, 'umem> ExactSizeIterator for PacketFrameIter<'a, 'umem> {}

/// Consuming iterator over frames in a [`Packet`].
pub enum PacketIntoIter<'umem> {
    Single(std::iter::Once<Frame<'umem>>),
    Multi(std::vec::IntoIter<Frame<'umem>>),
}

impl<'umem> Iterator for PacketIntoIter<'umem> {
    type Item = Frame<'umem>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            PacketIntoIter::Single(iter) => iter.next(),
            PacketIntoIter::Multi(iter) => iter.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            PacketIntoIter::Single(iter) => iter.size_hint(),
            PacketIntoIter::Multi(iter) => iter.size_hint(),
        }
    }
}

impl<'umem> ExactSizeIterator for PacketIntoIter<'umem> {}

pub struct PacketBuilder<'parent, 'umem> {
    free_frames: &'parent mut BasicFrameBuffer<'umem>,
    rx_return: &'parent mut BasicFrameBuffer<'umem>,
    tx_return: &'parent mut BasicFrameBuffer<'umem>,
    pmtu: &'parent mut PmtuCache,
    neighbor_handler: &'parent mut NeighborHandler,
}

impl<'parent, 'umem> PacketBuilder<'parent, 'umem> {
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
        if self.free_frames.num_frames() < 1 {
            return Err(WouldBlock);
        }

        let mut frame = self.free_frames.pop().ok_or(WouldBlock)?;
        let frame_len = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN + payload.len();
        unsafe { frame.set_len(frame_len) };

        // Ethernet header.
        write_ethernet_header(&mut frame, dst_mac, src_mac, EtherTypes::IPv4);

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
        write_udp_header(&mut frame, udp_offset, src_port, dst_port, udp_len);
        frame[udp_offset + UDP_HEADER_LEN..frame_len].copy_from_slice(payload);

        // UDP checksum.
        let cksum = compute_udp_checksum(&src_ip, &dst_ip, &frame[udp_offset..frame_len]);
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
        // max_frag_data: max IP payload per fragment, rounded down to multiple of 8.
        let max_frag_data = (pmtu as usize - IPV4_MIN_HEADER_LEN) & !7;
        // First fragment carries UDP header, so less payload data.
        let first_chunk = max_frag_data - UDP_HEADER_LEN;
        let remaining = payload.len() - first_chunk;
        let subsequent_chunks = if remaining == 0 {
            0
        } else {
            (remaining + max_frag_data - 1) / max_frag_data
        };
        let num_frames = 1 + subsequent_chunks;

        if self.free_frames.num_frames() < num_frames {
            return Err(WouldBlock);
        }

        let identification = IPV4_ID.fetch_add(1, Ordering::Relaxed);
        let mut frames = Vec::with_capacity(num_frames);
        let mut payload_offset = 0usize;
        // frag_byte_offset tracks the offset in the original IP payload (for fragment offset field).
        let mut frag_byte_offset = 0usize;

        for i in 0..num_frames {
            let mut frame = self.free_frames.pop().ok_or(WouldBlock)?;
            let is_first = i == 0;
            let is_last = i == num_frames - 1;

            let (ip_payload_len, data_to_copy) = if is_first {
                let chunk = first_chunk.min(payload.len());
                (UDP_HEADER_LEN + chunk, chunk)
            } else if is_last {
                let remaining = payload.len() - payload_offset;
                (remaining, remaining)
            } else {
                (max_frag_data, max_frag_data)
            };

            let frame_len = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + ip_payload_len;
            unsafe { frame.set_len(frame_len) };

            // Ethernet header.
            write_ethernet_header(&mut frame, dst_mac, src_mac, EtherTypes::IPv4);

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
                let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;
                write_udp_header(&mut frame, data_start, src_port, dst_port, udp_len);

                // Build full UDP segment for checksum computation.
                let mut udp_segment = Vec::with_capacity(UDP_HEADER_LEN + payload.len());
                udp_segment.extend_from_slice(&frame[data_start..data_start + UDP_HEADER_LEN]);
                udp_segment.extend_from_slice(payload);
                let cksum = compute_udp_checksum(&src_ip, &dst_ip, &udp_segment);
                frame[data_start + 6] = cksum[0];
                frame[data_start + 7] = cksum[1];

                // Copy first payload chunk.
                let chunk = first_chunk.min(payload.len());
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
        if self.free_frames.num_frames() < 1 {
            return Err(WouldBlock);
        }

        let mut frame = self.free_frames.pop().ok_or(WouldBlock)?;
        let frame_len = ETH_HEADER_LEN + IPV6_HEADER_LEN + UDP_HEADER_LEN + payload.len();
        unsafe { frame.set_len(frame_len) };

        // Ethernet header.
        write_ethernet_header(&mut frame, dst_mac, src_mac, EtherTypes::IPv6);

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
        write_udp_header(&mut frame, udp_offset, src_port, dst_port, udp_len);
        frame[udp_offset + UDP_HEADER_LEN..frame_len].copy_from_slice(payload);

        // UDP checksum (mandatory for IPv6).
        let cksum = compute_udp_checksum_v6(&src_ip, &dst_ip, &frame[udp_offset..frame_len]);
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
        const FRAG_EXT_LEN: usize = 8;

        // max_frag_data: max data after the fragment extension header, rounded down to 8.
        let max_frag_data = (pmtu as usize - IPV6_HEADER_LEN - FRAG_EXT_LEN) & !7;
        let first_chunk = max_frag_data - UDP_HEADER_LEN;
        let remaining = payload.len() - first_chunk;
        let subsequent_chunks = if remaining == 0 {
            0
        } else {
            (remaining + max_frag_data - 1) / max_frag_data
        };
        let num_frames = 1 + subsequent_chunks;

        if self.free_frames.num_frames() < num_frames {
            return Err(WouldBlock);
        }

        let identification = IPV6_ID.fetch_add(1, Ordering::Relaxed);
        let mut frames = Vec::with_capacity(num_frames);
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
        let udp_cksum = compute_udp_checksum_v6(&src_ip, &dst_ip, &udp_segment);

        for i in 0..num_frames {
            let mut frame = self.free_frames.pop().ok_or(WouldBlock)?;
            let is_first = i == 0;
            let is_last = i == num_frames - 1;

            let (frag_data_len, data_to_copy) = if is_first {
                let chunk = first_chunk.min(payload.len());
                (UDP_HEADER_LEN + chunk, chunk)
            } else if is_last {
                let remaining = payload.len() - payload_offset;
                (remaining, remaining)
            } else {
                (max_frag_data, max_frag_data)
            };

            let frame_len = ETH_HEADER_LEN + IPV6_HEADER_LEN + FRAG_EXT_LEN + frag_data_len;
            unsafe { frame.set_len(frame_len) };

            // Ethernet header.
            write_ethernet_header(&mut frame, dst_mac, src_mac, EtherTypes::IPv6);

            // IPv6 header.
            let ipv6_payload_len = (FRAG_EXT_LEN + frag_data_len) as u16;
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

            let data_start = frag_ext_offset + FRAG_EXT_LEN;

            if is_first {
                // Write UDP header in first fragment.
                write_udp_header(&mut frame, data_start, src_port, dst_port, udp_len);
                frame[data_start + 6] = udp_cksum[0];
                frame[data_start + 7] = udp_cksum[1];

                let chunk = first_chunk.min(payload.len());
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

// ---------------------------------------------------------------------------
// Read-side: PacketReader + fragment reassembly
// ---------------------------------------------------------------------------

/// A completed received UDP packet, ready for delivery to user space.
pub struct ReceivedPacket<'umem> {
    pub src_addr: IpAddress,
    pub dst_addr: IpAddress,
    pub src_port: u16,
    pub dst_port: u16,
    pub packet: Packet<'umem>,
}

#[derive(PartialEq, Eq, Hash)]
struct Ipv4FragmentKey {
    src_addr: Ipv4Address,
    dst_addr: Ipv4Address,
    identification: u16,
}

#[derive(PartialEq, Eq, Hash)]
struct Ipv6FragmentKey {
    src_addr: Ipv6Address,
    dst_addr: Ipv6Address,
    identification: u32,
}

struct ReassemblyEntry<'umem> {
    /// (offset_bytes, frame), kept sorted by offset.
    fragments: Vec<(usize, Frame<'umem>)>,
    /// (src_port, dst_port) parsed from the first fragment's UDP header.
    udp_meta: Option<(u16, u16)>,
    /// Known when the final fragment (MF=0) arrives.
    total_len: Option<usize>,
    /// Sum of all received fragment data lengths.
    received_len: usize,
    first_received: Instant,
}

impl<'umem> ReassemblyEntry<'umem> {
    fn new() -> Self {
        Self {
            fragments: Vec::new(),
            udp_meta: None,
            total_len: None,
            received_len: 0,
            first_received: Instant::now(),
        }
    }

    /// Insert a fragment sorted by offset. Returns `None` on success,
    /// `Some(frame)` if a duplicate offset is already present.
    fn insert(
        &mut self,
        offset: usize,
        data_len: usize,
        frame: Frame<'umem>,
    ) -> Option<Frame<'umem>> {
        // Check for duplicate offset.
        for &(existing_offset, _) in &self.fragments {
            if existing_offset == offset {
                return Some(frame);
            }
        }
        // Sorted insertion.
        let pos = self
            .fragments
            .binary_search_by_key(&offset, |&(o, _)| o)
            .unwrap_or_else(|e| e);
        self.fragments.insert(pos, (offset, frame));
        self.received_len += data_len;
        None
    }

    fn is_complete(&self) -> bool {
        match self.total_len {
            Some(total) => self.received_len == total,
            None => false,
        }
    }
}

/// Reads incoming UDP frames (from IPv4/IPv6 handlers), reassembles
/// fragments, and buffers completed packets for the runtime loop.
pub struct PacketReader<'umem> {
    ipv4_reassembly: HashMap<Ipv4FragmentKey, ReassemblyEntry<'umem>>,
    ipv6_reassembly: HashMap<Ipv6FragmentKey, ReassemblyEntry<'umem>>,
    max_entries: usize,
}

impl<'umem> PacketReader<'umem> {
    pub fn new(max_entries: usize) -> Self {
        Self {
            ipv4_reassembly: HashMap::new(),
            ipv6_reassembly: HashMap::new(),
            max_entries,
        }
    }

    /// Called by `UdpHandler` for validated IPv4 UDP frames and fragments.
    ///
    /// Returns `Some(ReceivedPacket)` when a complete packet is available
    /// (either non-fragmented or fully reassembled), `None` otherwise.
    pub fn process_ipv4(
        &mut self,
        frame: Frame<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
    ) -> Option<ReceivedPacket<'umem>> {
        let ip = Ipv4Header::from_frame(&frame);
        let src_addr = ip.src_addr;
        let dst_addr = ip.dst_addr;

        if !ip.is_fragment() {
            // Non-fragmented UDP — hot path.
            let udp_offset = ip.payload_offset();
            if frame.len() < udp_offset + UDP_HEADER_LEN {
                rx_return.push(frame);
                return None;
            }
            let udp = unsafe {
                &*(frame.as_ptr().add(udp_offset) as *const UdpHeader)
            };
            let src_port = udp.src_port();
            let dst_port = udp.dst_port();
            return Some(ReceivedPacket {
                src_addr: IpAddress::V4(src_addr),
                dst_addr: IpAddress::V4(dst_addr),
                src_port,
                dst_port,
                packet: Packet::Single(frame),
            });
        }

        // Fragment reassembly — cold path.
        let identification = ip.identification();
        let frag_offset_units = ip.fragment_offset();
        let frag_offset_bytes = frag_offset_units as usize * 8;
        let more_fragments = ip.more_fragments();
        let payload_len = ip.payload_len();
        let payload_offset = ip.payload_offset();

        let key = Ipv4FragmentKey {
            src_addr,
            dst_addr,
            identification,
        };

        // Check capacity.
        if !self.ipv4_reassembly.contains_key(&key)
            && self.ipv4_reassembly.len() + self.ipv6_reassembly.len() >= self.max_entries
        {
            rx_return.push(frame);
            return None;
        }

        let entry = self.ipv4_reassembly.entry(key).or_insert_with(ReassemblyEntry::new);

        if let Some(dup_frame) = entry.insert(frag_offset_bytes, payload_len, frame) {
            rx_return.push(dup_frame);
            return None;
        }

        // Parse UDP header from first fragment (offset 0).
        if frag_offset_bytes == 0 {
            if let Some(&(_, ref f)) = entry.fragments.iter().find(|&&(o, _)| o == 0) {
                if f.len() >= payload_offset + UDP_HEADER_LEN {
                    let udp = unsafe {
                        &*(f.as_ptr().add(payload_offset) as *const UdpHeader)
                    };
                    entry.udp_meta = Some((udp.src_port(), udp.dst_port()));
                }
            }
        }

        // Last fragment determines total length.
        if !more_fragments {
            entry.total_len = Some(frag_offset_bytes + payload_len);
        }

        // Check completion.
        if entry.is_complete() {
            let entry = self.ipv4_reassembly.remove(&Ipv4FragmentKey {
                src_addr,
                dst_addr,
                identification,
            }).unwrap();
            let (src_port, dst_port) = entry.udp_meta.unwrap_or((0, 0));
            let frames: Vec<Frame<'umem>> = entry.fragments.into_iter().map(|(_, f)| f).collect();
            let packet = if frames.len() == 1 {
                let mut frames = frames;
                Packet::Single(frames.pop().unwrap())
            } else {
                Packet::Multi(frames)
            };
            return Some(ReceivedPacket {
                src_addr: IpAddress::V4(src_addr),
                dst_addr: IpAddress::V4(dst_addr),
                src_port,
                dst_port,
                packet,
            });
        }

        None
    }

    /// Called by `UdpHandler` for validated IPv6 UDP frames and fragments.
    ///
    /// `frag_ext_offset` is `Some(offset)` if a Fragment extension header was
    /// found (from `walk_extension_headers`), `None` for non-fragmented.
    /// `udp_offset` is the byte offset of the UDP header in the frame (for
    /// non-fragmented packets).
    ///
    /// Returns `Some(ReceivedPacket)` when a complete packet is available,
    /// `None` otherwise.
    pub fn process_ipv6(
        &mut self,
        frame: Frame<'umem>,
        frag_ext_offset: Option<usize>,
        udp_offset: usize,
        rx_return: &mut impl FrameBuffer<'umem>,
    ) -> Option<ReceivedPacket<'umem>> {
        let ip = Ipv6Header::from_frame(&frame);
        let src_addr = ip.src_addr;
        let dst_addr = ip.dst_addr;

        match frag_ext_offset {
            None => {
                // Non-fragmented UDP — hot path.
                if frame.len() < udp_offset + UDP_HEADER_LEN {
                    rx_return.push(frame);
                    return None;
                }
                let udp = unsafe {
                    &*(frame.as_ptr().add(udp_offset) as *const UdpHeader)
                };
                let src_port = udp.src_port();
                let dst_port = udp.dst_port();
                Some(ReceivedPacket {
                    src_addr: IpAddress::V6(src_addr),
                    dst_addr: IpAddress::V6(dst_addr),
                    src_port,
                    dst_port,
                    packet: Packet::Single(frame),
                })
            }
            Some(frag_off) => {
                // Fragment reassembly.
                if frame.len() < frag_off + FRAGMENT_EXT_LEN {
                    rx_return.push(frame);
                    return None;
                }

                let next_header = frame[frag_off];
                if next_header != IpProtocols::Udp {
                    rx_return.push(frame);
                    return None;
                }

                let frag_offset_mf = u16::from_be_bytes([
                    frame[frag_off + 2],
                    frame[frag_off + 3],
                ]);
                let frag_offset_units = frag_offset_mf >> 3;
                let frag_offset_bytes = frag_offset_units as usize * 8;
                let more_fragments = (frag_offset_mf & 1) != 0;
                let identification = u32::from_be_bytes([
                    frame[frag_off + 4],
                    frame[frag_off + 5],
                    frame[frag_off + 6],
                    frame[frag_off + 7],
                ]);

                let data_start = frag_off + FRAGMENT_EXT_LEN;
                let data_len = if frame.len() > data_start {
                    frame.len() - data_start
                } else {
                    0
                };

                let key = Ipv6FragmentKey {
                    src_addr,
                    dst_addr,
                    identification,
                };

                // Check capacity.
                if !self.ipv6_reassembly.contains_key(&key)
                    && self.ipv4_reassembly.len() + self.ipv6_reassembly.len() >= self.max_entries
                {
                    rx_return.push(frame);
                    return None;
                }

                let entry = self.ipv6_reassembly.entry(key).or_insert_with(ReassemblyEntry::new);

                if let Some(dup_frame) = entry.insert(frag_offset_bytes, data_len, frame) {
                    rx_return.push(dup_frame);
                    return None;
                }

                // Parse UDP header from first fragment (offset 0).
                if frag_offset_bytes == 0 {
                    if let Some(&(_, ref f)) = entry.fragments.iter().find(|&&(o, _)| o == 0) {
                        if f.len() >= data_start + UDP_HEADER_LEN {
                            let udp = unsafe {
                                &*(f.as_ptr().add(data_start) as *const UdpHeader)
                            };
                            entry.udp_meta = Some((udp.src_port(), udp.dst_port()));
                        }
                    }
                }

                if !more_fragments {
                    entry.total_len = Some(frag_offset_bytes + data_len);
                }

                if entry.is_complete() {
                    let entry = self.ipv6_reassembly.remove(&Ipv6FragmentKey {
                        src_addr,
                        dst_addr,
                        identification,
                    }).unwrap();
                    let (src_port, dst_port) = entry.udp_meta.unwrap_or((0, 0));
                    let frames: Vec<Frame<'umem>> = entry.fragments.into_iter().map(|(_, f)| f).collect();
                    let packet = if frames.len() == 1 {
                        let mut frames = frames;
                        Packet::Single(frames.pop().unwrap())
                    } else {
                        Packet::Multi(frames)
                    };
                    return Some(ReceivedPacket {
                        src_addr: IpAddress::V6(src_addr),
                        dst_addr: IpAddress::V6(dst_addr),
                        src_port,
                        dst_port,
                        packet,
                    });
                }

                None
            }
        }
    }

    /// Evict reassembly entries older than `timeout`, returning held frames.
    pub fn evict_stale(
        &mut self,
        timeout: Duration,
        rx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let now = Instant::now();
        self.ipv4_reassembly.retain(|_, entry| {
            if now.duration_since(entry.first_received) > timeout {
                for (_, frame) in entry.fragments.drain(..) {
                    rx_return.push(frame);
                }
                false
            } else {
                true
            }
        });
        self.ipv6_reassembly.retain(|_, entry| {
            if now.duration_since(entry.first_received) > timeout {
                for (_, frame) in entry.fragments.drain(..) {
                    rx_return.push(frame);
                }
                false
            } else {
                true
            }
        });
    }

    /// Number of in-progress reassembly entries.
    pub fn pending_entries(&self) -> usize {
        self.ipv4_reassembly.len() + self.ipv6_reassembly.len()
    }
}

/// Writes an Ethernet header at the start of a frame.
#[inline]
fn write_ethernet_header(
    frame: &mut Frame<'_>,
    dst_mac: MacAddress,
    src_mac: MacAddress,
    ether_type: crate::net::EtherType,
) {
    let eth = EthernetFrame::from_frame_mut(frame);
    eth.dst_mac = dst_mac;
    eth.src_mac = src_mac;
    eth.ether_type = ether_type;
}

/// Writes a UDP header at the given offset in a frame.
#[inline]
fn write_udp_header(
    frame: &mut Frame<'_>,
    offset: usize,
    src_port: u16,
    dst_port: u16,
    length: u16,
) {
    frame[offset..offset + 2].copy_from_slice(&src_port.to_be_bytes());
    frame[offset + 2..offset + 4].copy_from_slice(&dst_port.to_be_bytes());
    frame[offset + 4..offset + 6].copy_from_slice(&length.to_be_bytes());
    frame[offset + 6] = 0; // checksum placeholder
    frame[offset + 7] = 0;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::ipv4::compute_ipv4_checksum;
    use crate::net::udp::{verify_udp_checksum, verify_udp_checksum_v6};
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
        // Manually insert remote MAC into cache via ARP reply handling.
        nh
    }

    /// Inserts a neighbor entry by constructing and handling a fake ARP reply.
    fn seed_neighbor_v4(nh: &mut NeighborHandler) {
        use crate::net::arp::{ARP_FRAME_LEN, ArpHardwareTypes, ArpOperations, ArpPacket};

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
        use crate::net::icmpv6::compute_icmpv6_checksum;

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

    #[test]
    fn single_ipv4_packet() {
        let mut nh = new_handler_with_cache();
        seed_neighbor_v4(&mut nh);

        let mut free = BasicFrameBuffer::new(16);
        // Push some frames with enough capacity.
        let mut bufs: Vec<Vec<u8>> = (0..8).map(|_| vec![0u8; 2048]).collect();
        for (i, buf) in bufs.iter_mut().enumerate() {
            let frame = Frame::new(i as u64, buf.as_mut_slice(), 1, false);
            free.push(frame);
        }

        let mut rx = BasicFrameBuffer::new(16);
        let mut tx = BasicFrameBuffer::new(16);
        let mut pmtu = PmtuCache::new();

        let mut builder =
            PacketBuilder::new(&mut free, &mut rx, &mut tx, &mut pmtu, &mut nh);

        let payload = b"Hello, World!";
        let result = builder.udp_packet(
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

                // Verify Ethernet header.
                let eth = EthernetFrame::from_frame(&frame);
                assert_eq!(eth.dst_mac, TEST_REMOTE_MAC);
                assert_eq!(eth.src_mac, TEST_LOCAL_MAC);
                assert_eq!(eth.ether_type, EtherTypes::IPv4);

                // Verify IPv4 header.
                let ip = Ipv4Header::from_frame(&frame);
                assert_eq!(ip.version(), 4);
                assert_eq!(ip.ihl(), 5);
                assert_eq!(ip.ttl, 64);
                assert_eq!(ip.protocol, IpProtocols::Udp);
                assert_eq!(ip.src_addr, TEST_LOCAL_IPV4);
                assert_eq!(ip.dst_addr, TEST_REMOTE_IPV4);
                assert!(ip.dont_fragment());
                // Verify checksum.
                let ip_bytes = &frame[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN];
                assert_eq!(compute_ipv4_checksum(ip_bytes), [0x00, 0x00]);

                // Verify UDP header.
                let udp_offset = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
                let udp_end = frame.len();
                assert!(verify_udp_checksum(
                    &TEST_LOCAL_IPV4,
                    &TEST_REMOTE_IPV4,
                    &frame[udp_offset..udp_end],
                ));

                // Verify payload.
                assert_eq!(
                    &frame[udp_offset + UDP_HEADER_LEN..udp_end],
                    payload.as_slice()
                );
            }
            Packet::Multi(_) => panic!("expected Single packet"),
        }
    }

    #[test]
    fn single_ipv6_packet() {
        let mut nh = new_handler_with_cache();
        seed_neighbor_v6(&mut nh);

        let mut free = BasicFrameBuffer::new(16);
        let mut bufs: Vec<Vec<u8>> = (0..8).map(|_| vec![0u8; 2048]).collect();
        for (i, buf) in bufs.iter_mut().enumerate() {
            let frame = Frame::new(i as u64, buf.as_mut_slice(), 1, false);
            free.push(frame);
        }

        let mut rx = BasicFrameBuffer::new(16);
        let mut tx = BasicFrameBuffer::new(16);
        let mut pmtu = PmtuCache::new();

        let mut builder =
            PacketBuilder::new(&mut free, &mut rx, &mut tx, &mut pmtu, &mut nh);

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

                // Verify Ethernet header.
                let eth = EthernetFrame::from_frame(&frame);
                assert_eq!(eth.dst_mac, TEST_REMOTE_MAC);
                assert_eq!(eth.src_mac, TEST_LOCAL_MAC);
                assert_eq!(eth.ether_type, EtherTypes::IPv6);

                // Verify IPv6 header.
                let ip = Ipv6Header::from_frame(&frame);
                assert_eq!(ip.version(), 6);
                assert_eq!(ip.hop_limit, 64);
                assert_eq!(ip.next_header, IpProtocols::Udp);
                assert_eq!(ip.src_addr, TEST_LOCAL_IPV6);
                assert_eq!(ip.dst_addr, TEST_REMOTE_IPV6);

                // Verify UDP.
                let udp_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
                let udp_end = frame.len();
                assert!(verify_udp_checksum_v6(
                    &TEST_LOCAL_IPV6,
                    &TEST_REMOTE_IPV6,
                    &frame[udp_offset..udp_end],
                ));

                // Verify payload.
                assert_eq!(
                    &frame[udp_offset + UDP_HEADER_LEN..udp_end],
                    payload.as_slice()
                );
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
            let frame = Frame::new(i as u64, buf.as_mut_slice(), 1, false);
            free.push(frame);
        }

        let mut rx = BasicFrameBuffer::new(16);
        let mut tx = BasicFrameBuffer::new(16);
        let mut pmtu = PmtuCache::new();

        let mut builder =
            PacketBuilder::new(&mut free, &mut rx, &mut tx, &mut pmtu, &mut nh);

        let result = builder.udp_packet(
            IpAddress::V4(TEST_LOCAL_IPV4),
            IpAddress::V4(TEST_REMOTE_IPV4),
            1234,
            5678,
            b"test",
        );

        assert_eq!(result.unwrap_err(), WouldBlock);
        // ARP request should be queued on tx_return.
        assert_eq!(tx.num_frames(), 1);
        // One frame consumed for ARP.
        assert_eq!(free.num_frames(), 7);
    }

    #[test]
    fn not_enough_frames_returns_would_block() {
        let mut nh = new_handler_with_cache();
        seed_neighbor_v4(&mut nh);

        // Empty frame buffer.
        let mut free = BasicFrameBuffer::new(16);
        let mut rx = BasicFrameBuffer::new(16);
        let mut tx = BasicFrameBuffer::new(16);
        let mut pmtu = PmtuCache::new();

        let mut builder =
            PacketBuilder::new(&mut free, &mut rx, &mut tx, &mut pmtu, &mut nh);

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
        let mut nh = new_handler_with_cache();
        seed_neighbor_v4(&mut nh);

        let mut free = BasicFrameBuffer::new(64);
        let mut bufs: Vec<Vec<u8>> = (0..32).map(|_| vec![0u8; 2048]).collect();
        for (i, buf) in bufs.iter_mut().enumerate() {
            let frame = Frame::new(i as u64, buf.as_mut_slice(), 1, false);
            free.push(frame);
        }

        let mut rx = BasicFrameBuffer::new(16);
        let mut tx = BasicFrameBuffer::new(16);
        let mut pmtu = PmtuCache::new(); // default 1500

        let mut builder =
            PacketBuilder::new(&mut free, &mut rx, &mut tx, &mut pmtu, &mut nh);

        // Payload larger than what fits in a single frame.
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

                // All fragments should have same identification.
                let first_id = Ipv4Header::from_frame(&frames[0]).identification();
                for f in &frames {
                    let ip = Ipv4Header::from_frame(f);
                    assert_eq!(ip.identification(), first_id);
                    assert_eq!(ip.protocol, IpProtocols::Udp);
                    assert_eq!(ip.src_addr, TEST_LOCAL_IPV4);
                    assert_eq!(ip.dst_addr, TEST_REMOTE_IPV4);
                    // No DF flag on fragments.
                    assert!(!ip.dont_fragment());
                    // Verify IP checksum.
                    let ip_bytes = &f[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN];
                    assert_eq!(compute_ipv4_checksum(ip_bytes), [0x00, 0x00]);
                }

                // First fragment should have MF set.
                let first_ip = Ipv4Header::from_frame(&frames[0]);
                assert!(first_ip.more_fragments());
                assert_eq!(first_ip.fragment_offset(), 0);

                // Last fragment should NOT have MF set.
                let last_ip = Ipv4Header::from_frame(frames.last().unwrap());
                assert!(!last_ip.more_fragments());

                // Verify fragment offsets are aligned to 8 bytes (except possibly last).
                for (i, f) in frames.iter().enumerate() {
                    let ip = Ipv4Header::from_frame(f);
                    if i < frames.len() - 1 {
                        // Not last — offset in 8-byte units, payload should be 8-aligned.
                        let ip_payload_len = ip.payload_len();
                        assert_eq!(
                            ip_payload_len % 8,
                            0,
                            "non-last fragment payload not 8-aligned"
                        );
                    }
                }

                // Reassemble and verify payload.
                let mut reassembled = vec![0u8; 0];
                for (i, f) in frames.iter().enumerate() {
                    let data_start = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
                    if i == 0 {
                        // First fragment has UDP header + payload.
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
        let mut nh = new_handler_with_cache();
        seed_neighbor_v6(&mut nh);

        let mut free = BasicFrameBuffer::new(64);
        let mut bufs: Vec<Vec<u8>> = (0..32).map(|_| vec![0u8; 2048]).collect();
        for (i, buf) in bufs.iter_mut().enumerate() {
            let frame = Frame::new(i as u64, buf.as_mut_slice(), 1, false);
            free.push(frame);
        }

        let mut rx = BasicFrameBuffer::new(16);
        let mut tx = BasicFrameBuffer::new(16);
        let mut pmtu = PmtuCache::new(); // default 1500

        let mut builder =
            PacketBuilder::new(&mut free, &mut rx, &mut tx, &mut pmtu, &mut nh);

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

                const FRAG_EXT_LEN: usize = 8;

                // All fragments should have same identification.
                let frag_ext_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
                let first_id = u32::from_be_bytes([
                    frames[0][frag_ext_offset + 4],
                    frames[0][frag_ext_offset + 5],
                    frames[0][frag_ext_offset + 6],
                    frames[0][frag_ext_offset + 7],
                ]);

                for f in &frames {
                    let ip = Ipv6Header::from_frame(f);
                    assert_eq!(ip.next_header, 44); // Fragment ext header
                    assert_eq!(ip.src_addr, TEST_LOCAL_IPV6);
                    assert_eq!(ip.dst_addr, TEST_REMOTE_IPV6);

                    // Check identification.
                    let id = u32::from_be_bytes([
                        f[frag_ext_offset + 4],
                        f[frag_ext_offset + 5],
                        f[frag_ext_offset + 6],
                        f[frag_ext_offset + 7],
                    ]);
                    assert_eq!(id, first_id);

                    // Fragment ext next_header should be UDP.
                    assert_eq!(f[frag_ext_offset], IpProtocols::Udp);
                }

                // First fragment MF should be set.
                let first_frag_offset_mf = u16::from_be_bytes([
                    frames[0][frag_ext_offset + 2],
                    frames[0][frag_ext_offset + 3],
                ]);
                assert_eq!(first_frag_offset_mf & 1, 1); // MF set
                assert_eq!(first_frag_offset_mf >> 3, 0); // offset = 0

                // Last fragment MF should be clear.
                let last = frames.last().unwrap();
                let last_frag_offset_mf =
                    u16::from_be_bytes([last[frag_ext_offset + 2], last[frag_ext_offset + 3]]);
                assert_eq!(last_frag_offset_mf & 1, 0); // MF clear

                // Reassemble and verify payload.
                let mut reassembled = vec![0u8; 0];
                for (i, f) in frames.iter().enumerate() {
                    let data_start = frag_ext_offset + FRAG_EXT_LEN;
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
    fn empty_payload_ipv4() {
        let mut nh = new_handler_with_cache();
        seed_neighbor_v4(&mut nh);

        let mut free = BasicFrameBuffer::new(16);
        let mut bufs: Vec<Vec<u8>> = (0..4).map(|_| vec![0u8; 2048]).collect();
        for (i, buf) in bufs.iter_mut().enumerate() {
            let frame = Frame::new(i as u64, buf.as_mut_slice(), 1, false);
            free.push(frame);
        }

        let mut rx = BasicFrameBuffer::new(16);
        let mut tx = BasicFrameBuffer::new(16);
        let mut pmtu = PmtuCache::new();

        let mut builder =
            PacketBuilder::new(&mut free, &mut rx, &mut tx, &mut pmtu, &mut nh);

        let result = builder.udp_packet(
            IpAddress::V4(TEST_LOCAL_IPV4),
            IpAddress::V4(TEST_REMOTE_IPV4),
            1234,
            5678,
            &[],
        );

        let packet = result.expect("should succeed");
        match packet {
            Packet::Single(frame) => {
                let expected_len = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN;
                assert_eq!(frame.len(), expected_len);
            }
            Packet::Multi(_) => panic!("expected Single"),
        }
    }

    #[test]
    fn empty_payload_ipv6() {
        let mut nh = new_handler_with_cache();
        seed_neighbor_v6(&mut nh);

        let mut free = BasicFrameBuffer::new(16);
        let mut bufs: Vec<Vec<u8>> = (0..4).map(|_| vec![0u8; 2048]).collect();
        for (i, buf) in bufs.iter_mut().enumerate() {
            let frame = Frame::new(i as u64, buf.as_mut_slice(), 1, false);
            free.push(frame);
        }

        let mut rx = BasicFrameBuffer::new(16);
        let mut tx = BasicFrameBuffer::new(16);
        let mut pmtu = PmtuCache::new();

        let mut builder =
            PacketBuilder::new(&mut free, &mut rx, &mut tx, &mut pmtu, &mut nh);

        let result = builder.udp_packet(
            IpAddress::V6(TEST_LOCAL_IPV6),
            IpAddress::V6(TEST_REMOTE_IPV6),
            1234,
            5678,
            &[],
        );

        let packet = result.expect("should succeed");
        match packet {
            Packet::Single(frame) => {
                let expected_len = ETH_HEADER_LEN + IPV6_HEADER_LEN + UDP_HEADER_LEN;
                assert_eq!(frame.len(), expected_len);
            }
            Packet::Multi(_) => panic!("expected Single"),
        }
    }
}
