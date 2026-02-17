use std::{
    collections::HashMap,
    hash::Hash,
    time::{Duration, Instant},
};

use crate::{
    net::{
        Packet,
        wire::{
            ip::{
                FRAGMENT_EXT_LEN, IpAddress, IpProtocols, Ipv4Address, Ipv4Header, Ipv6Address,
                Ipv6Header,
            },
            udp::{UDP_HEADER_LEN, UdpHeader},
        },
    },
    xdp::frame::{Frame, FrameBuffer},
};

/// A completed received UDP packet, ready for delivery to user space.
#[derive(Debug)]
pub struct ReceivedPacket<'umem> {
    pub src_addr: IpAddress,
    pub dst_addr: IpAddress,
    pub src_port: u16,
    pub dst_port: u16,
    pub packet: Packet<'umem>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct Ipv4FragmentKey {
    src_addr: Ipv4Address,
    dst_addr: Ipv4Address,
    identification: u16,
}

#[derive(Clone, PartialEq, Eq, Hash)]
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
        match self.fragments.binary_search_by_key(&offset, |&(o, _)| o) {
            Ok(_) => Some(frame),
            Err(pos) => {
                self.fragments.insert(pos, (offset, frame));
                self.received_len += data_len;
                None
            }
        }
    }

    /// Insert a fragment, parse UDP meta from offset-0, set total_len on last fragment.
    /// Returns `Some(frame)` if the fragment was a duplicate.
    fn accept_fragment(
        &mut self,
        frag_offset_bytes: usize,
        more_fragments: bool,
        data_len: usize,
        udp_header_offset: usize,
        frame: Frame<'umem>,
    ) -> Option<Frame<'umem>> {
        let dup = self.insert(frag_offset_bytes, data_len, frame);
        if dup.is_some() {
            return dup;
        }

        if frag_offset_bytes == 0 {
            let (_, ref f) = self.fragments[0];
            if f.len() >= udp_header_offset + UDP_HEADER_LEN {
                let udp = unsafe { &*(f.as_ptr().add(udp_header_offset) as *const UdpHeader) };
                self.udp_meta = Some((udp.src_port(), udp.dst_port()));
            }
        }

        if !more_fragments {
            self.total_len = Some(frag_offset_bytes + data_len);
        }

        None
    }

    /// Convert a completed entry into its ports and packet.
    fn into_packet(self) -> (u16, u16, Packet<'umem>) {
        let (src_port, dst_port) = self.udp_meta.unwrap_or((0, 0));
        let mut fragments = self.fragments;
        let packet = if fragments.len() == 1 {
            Packet::Single(fragments.pop().unwrap().1)
        } else {
            Packet::Multi(fragments.into_iter().map(|(_, f)| f).collect())
        };
        (src_port, dst_port, packet)
    }

    fn is_complete(&self) -> bool {
        match self.total_len {
            Some(total) => self.received_len == total,
            None => false,
        }
    }
}

/// Evict stale reassembly entries from a map, returning held frames.
fn evict_map<'umem, K: Eq + Hash>(
    map: &mut HashMap<K, ReassemblyEntry<'umem>>,
    now: Instant,
    timeout: Duration,
    rx_return: &mut impl FrameBuffer<'umem>,
) {
    map.retain(|_, entry| {
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

    fn has_capacity_for_new_entry(&self) -> bool {
        self.ipv4_reassembly.len() + self.ipv6_reassembly.len() < self.max_entries
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
            let udp = unsafe { &*(frame.as_ptr().add(udp_offset) as *const UdpHeader) };
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
        let frag_offset_bytes = ip.fragment_offset() as usize * 8;
        let more_fragments = ip.more_fragments();
        let payload_len = ip.payload_len();
        let payload_offset = ip.payload_offset();

        let key = Ipv4FragmentKey {
            src_addr,
            dst_addr,
            identification,
        };

        // Check capacity.
        if !self.ipv4_reassembly.contains_key(&key) && !self.has_capacity_for_new_entry() {
            rx_return.push(frame);
            return None;
        }

        let remove_key = key.clone();
        let entry = self
            .ipv4_reassembly
            .entry(key)
            .or_insert_with(ReassemblyEntry::new);

        if let Some(dup_frame) = entry.accept_fragment(
            frag_offset_bytes,
            more_fragments,
            payload_len,
            payload_offset,
            frame,
        ) {
            rx_return.push(dup_frame);
            return None;
        }

        // Check completion.
        if entry.is_complete() {
            let entry = self.ipv4_reassembly.remove(&remove_key).unwrap();
            let (src_port, dst_port, packet) = entry.into_packet();
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
                let udp = unsafe { &*(frame.as_ptr().add(udp_offset) as *const UdpHeader) };
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

                let frag_offset_mf = u16::from_be_bytes([frame[frag_off + 2], frame[frag_off + 3]]);
                let frag_offset_bytes = (frag_offset_mf >> 3) as usize * 8;
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
                if !self.ipv6_reassembly.contains_key(&key) && !self.has_capacity_for_new_entry() {
                    rx_return.push(frame);
                    return None;
                }

                let remove_key = key.clone();
                let entry = self
                    .ipv6_reassembly
                    .entry(key)
                    .or_insert_with(ReassemblyEntry::new);

                if let Some(dup_frame) = entry.accept_fragment(
                    frag_offset_bytes,
                    more_fragments,
                    data_len,
                    data_start,
                    frame,
                ) {
                    rx_return.push(dup_frame);
                    return None;
                }

                if entry.is_complete() {
                    let entry = self.ipv6_reassembly.remove(&remove_key).unwrap();
                    let (src_port, dst_port, packet) = entry.into_packet();
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
    pub fn evict_stale(&mut self, timeout: Duration, rx_return: &mut impl FrameBuffer<'umem>) {
        let now = Instant::now();
        evict_map(&mut self.ipv4_reassembly, now, timeout, rx_return);
        evict_map(&mut self.ipv6_reassembly, now, timeout, rx_return);
    }

    /// Number of in-progress reassembly entries.
    pub fn pending_entries(&self) -> usize {
        self.ipv4_reassembly.len() + self.ipv6_reassembly.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::wire::{
        ethernet::EthernetFrame,
        ip::{FRAGMENT_EXT_LEN, IPV4_MIN_HEADER_LEN, IPV6_HEADER_LEN, IpProtocols},
    };
    use crate::xdp::frame::{BasicFrameBuffer, Frame};

    const ETH_LEN: usize = size_of::<EthernetFrame>();
    const SRC_V4: [u8; 4] = [192, 168, 1, 1];
    const DST_V4: [u8; 4] = [10, 0, 0, 1];
    const SRC_V6: [u8; 16] = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    const DST_V6: [u8; 16] = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

    /// Build a non-fragmented IPv4 UDP frame, returns the total frame length.
    fn build_ipv4_udp(buf: &mut [u8], src_port: u16, dst_port: u16, payload: &[u8]) -> usize {
        let udp_len = UDP_HEADER_LEN + payload.len();
        let ip_total = IPV4_MIN_HEADER_LEN + udp_len;
        let frame_len = ETH_LEN + ip_total;
        buf[12..14].copy_from_slice(&[0x08, 0x00]); // IPv4 EtherType
        buf[14] = 0x45; // version=4, IHL=5
        buf[16..18].copy_from_slice(&(ip_total as u16).to_be_bytes());
        buf[20..22].copy_from_slice(&[0x40, 0x00]); // DF, no fragments
        buf[23] = IpProtocols::Udp;
        buf[26..30].copy_from_slice(&SRC_V4);
        buf[30..34].copy_from_slice(&DST_V4);
        let u = ETH_LEN + IPV4_MIN_HEADER_LEN;
        buf[u..u + 2].copy_from_slice(&src_port.to_be_bytes());
        buf[u + 2..u + 4].copy_from_slice(&dst_port.to_be_bytes());
        buf[u + 4..u + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        buf[u + UDP_HEADER_LEN..u + UDP_HEADER_LEN + payload.len()].copy_from_slice(payload);
        frame_len
    }

    /// Build an IPv4 fragment. `data` is the IP payload (first fragment includes UDP header).
    fn build_ipv4_fragment(
        buf: &mut [u8],
        id: u16,
        frag_offset_8: u16,
        more: bool,
        data: &[u8],
    ) -> usize {
        let ip_total = IPV4_MIN_HEADER_LEN + data.len();
        let frame_len = ETH_LEN + ip_total;
        buf[12..14].copy_from_slice(&[0x08, 0x00]);
        buf[14] = 0x45;
        buf[16..18].copy_from_slice(&(ip_total as u16).to_be_bytes());
        buf[18..20].copy_from_slice(&id.to_be_bytes());
        let flags = if more {
            0x2000 | frag_offset_8
        } else {
            frag_offset_8
        };
        buf[20..22].copy_from_slice(&flags.to_be_bytes());
        buf[23] = IpProtocols::Udp;
        buf[26..30].copy_from_slice(&SRC_V4);
        buf[30..34].copy_from_slice(&DST_V4);
        let p = ETH_LEN + IPV4_MIN_HEADER_LEN;
        buf[p..p + data.len()].copy_from_slice(data);
        frame_len
    }

    /// Build a non-fragmented IPv6 UDP frame, returns the total frame length.
    fn build_ipv6_udp(buf: &mut [u8], src_port: u16, dst_port: u16, payload: &[u8]) -> usize {
        let udp_len = UDP_HEADER_LEN + payload.len();
        let frame_len = ETH_LEN + IPV6_HEADER_LEN + udp_len;
        buf[12..14].copy_from_slice(&[0x86, 0xDD]); // IPv6 EtherType
        buf[14] = 0x60; // version=6
        buf[18..20].copy_from_slice(&(udp_len as u16).to_be_bytes());
        buf[20] = IpProtocols::Udp;
        buf[22..38].copy_from_slice(&SRC_V6);
        buf[38..54].copy_from_slice(&DST_V6);
        let u = ETH_LEN + IPV6_HEADER_LEN;
        buf[u..u + 2].copy_from_slice(&src_port.to_be_bytes());
        buf[u + 2..u + 4].copy_from_slice(&dst_port.to_be_bytes());
        buf[u + 4..u + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        buf[u + UDP_HEADER_LEN..u + UDP_HEADER_LEN + payload.len()].copy_from_slice(payload);
        frame_len
    }

    /// Build an IPv6 fragment frame. `data` is the payload after the fragment ext header.
    fn build_ipv6_fragment(
        buf: &mut [u8],
        id: u32,
        frag_offset_8: u16,
        more: bool,
        next_header: u8,
        data: &[u8],
    ) -> usize {
        let payload_len = FRAGMENT_EXT_LEN + data.len();
        let frame_len = ETH_LEN + IPV6_HEADER_LEN + payload_len;
        buf[12..14].copy_from_slice(&[0x86, 0xDD]);
        buf[14] = 0x60;
        buf[18..20].copy_from_slice(&(payload_len as u16).to_be_bytes());
        buf[20] = 44; // Fragment extension header
        buf[22..38].copy_from_slice(&SRC_V6);
        buf[38..54].copy_from_slice(&DST_V6);
        let f = ETH_LEN + IPV6_HEADER_LEN;
        buf[f] = next_header;
        let frag_offset_mf = (frag_offset_8 << 3) | if more { 1 } else { 0 };
        buf[f + 2..f + 4].copy_from_slice(&frag_offset_mf.to_be_bytes());
        buf[f + 4..f + 8].copy_from_slice(&id.to_be_bytes());
        let d = f + FRAGMENT_EXT_LEN;
        buf[d..d + data.len()].copy_from_slice(data);
        frame_len
    }

    /// Build a first-fragment UDP payload (UDP header + data).
    fn udp_first_frag(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut data = vec![0u8; UDP_HEADER_LEN + payload.len()];
        data[0..2].copy_from_slice(&src_port.to_be_bytes());
        data[2..4].copy_from_slice(&dst_port.to_be_bytes());
        data[UDP_HEADER_LEN..].copy_from_slice(payload);
        data
    }

    const FRAG_OFF: usize = ETH_LEN + IPV6_HEADER_LEN;

    // --- process_ipv4: non-fragmented ---

    #[test]
    fn ipv4_non_fragmented() {
        let mut reader = PacketReader::new(16);
        let mut rx = BasicFrameBuffer::new(16);
        let mut buf = [0u8; 256];
        let len = build_ipv4_udp(&mut buf, 1234, 5678, b"hello");
        let frame = Frame::new(0, &mut buf, len, false);

        let pkt = reader
            .process_ipv4(frame, &mut rx)
            .expect("should return packet");
        assert_eq!(pkt.src_port, 1234);
        assert_eq!(pkt.dst_port, 5678);
        assert_eq!(pkt.src_addr, IpAddress::V4(Ipv4Address::new(SRC_V4)));
        assert_eq!(pkt.dst_addr, IpAddress::V4(Ipv4Address::new(DST_V4)));
        assert_eq!(pkt.packet.num_frames(), 1);
        assert_eq!(rx.num_frames(), 0);
    }

    #[test]
    fn ipv4_too_short_for_udp() {
        let mut reader = PacketReader::new(16);
        let mut rx = BasicFrameBuffer::new(16);
        let mut buf = [0u8; 256];
        // Valid non-fragment IPv4 header but frame truncated before UDP header
        buf[14] = 0x45;
        buf[16..18].copy_from_slice(&20u16.to_be_bytes());
        buf[20..22].copy_from_slice(&[0x40, 0x00]); // DF
        buf[23] = IpProtocols::Udp;
        buf[26..30].copy_from_slice(&SRC_V4);
        buf[30..34].copy_from_slice(&DST_V4);
        let frame = Frame::new(0, &mut buf, ETH_LEN + IPV4_MIN_HEADER_LEN, false);

        assert!(reader.process_ipv4(frame, &mut rx).is_none());
        assert_eq!(rx.num_frames(), 1); // frame returned
    }

    // --- process_ipv4: fragment reassembly ---

    #[test]
    fn ipv4_fragment_reassembly() {
        let mut reader = PacketReader::new(16);
        let mut rx = BasicFrameBuffer::new(16);

        // First fragment: UDP header + 8 bytes, MF=1, offset=0
        let mut buf1 = [0u8; 256];
        let first = udp_first_frag(1234, 5678, &[1, 2, 3, 4, 5, 6, 7, 8]);
        let len1 = build_ipv4_fragment(&mut buf1, 42, 0, true, &first);
        let f1 = Frame::new(0, &mut buf1, len1, false);
        assert!(reader.process_ipv4(f1, &mut rx).is_none());
        assert_eq!(reader.pending_entries(), 1);

        // Last fragment: 8 bytes, MF=0, offset=2 (2*8=16 bytes in)
        let mut buf2 = [0u8; 256];
        let len2 = build_ipv4_fragment(&mut buf2, 42, 2, false, &[9, 10, 11, 12, 13, 14, 15, 16]);
        let f2 = Frame::new(1, &mut buf2, len2, false);
        let pkt = reader.process_ipv4(f2, &mut rx).expect("should complete");
        assert_eq!(pkt.src_port, 1234);
        assert_eq!(pkt.dst_port, 5678);
        assert_eq!(pkt.packet.num_frames(), 2);
        assert_eq!(reader.pending_entries(), 0);
    }

    #[test]
    fn ipv4_out_of_order_reassembly() {
        let mut reader = PacketReader::new(16);
        let mut rx = BasicFrameBuffer::new(16);

        // Send last fragment first
        let mut buf2 = [0u8; 256];
        let len2 = build_ipv4_fragment(&mut buf2, 77, 2, false, &[0u8; 8]);
        let f2 = Frame::new(1, &mut buf2, len2, false);
        assert!(reader.process_ipv4(f2, &mut rx).is_none());

        // Then send first fragment
        let mut buf1 = [0u8; 256];
        let first = udp_first_frag(1111, 2222, &[0u8; 8]);
        let len1 = build_ipv4_fragment(&mut buf1, 77, 0, true, &first);
        let f1 = Frame::new(0, &mut buf1, len1, false);
        let pkt = reader.process_ipv4(f1, &mut rx).expect("should complete");
        assert_eq!(pkt.src_port, 1111);
        assert_eq!(pkt.dst_port, 2222);
        assert_eq!(pkt.packet.num_frames(), 2);
    }

    #[test]
    fn ipv4_duplicate_fragment_returned() {
        let mut reader = PacketReader::new(16);
        let mut rx = BasicFrameBuffer::new(16);

        let first = udp_first_frag(1000, 2000, &[0u8; 8]);
        let mut buf1 = [0u8; 256];
        let len = build_ipv4_fragment(&mut buf1, 99, 0, true, &first);
        let f1 = Frame::new(0, &mut buf1, len, false);
        reader.process_ipv4(f1, &mut rx);

        // Duplicate of the same offset
        let mut buf2 = [0u8; 256];
        let len = build_ipv4_fragment(&mut buf2, 99, 0, true, &first);
        let f2 = Frame::new(1, &mut buf2, len, false);
        assert!(reader.process_ipv4(f2, &mut rx).is_none());
        assert_eq!(rx.num_frames(), 1); // dup returned
    }

    #[test]
    fn ipv4_capacity_exceeded() {
        let mut reader = PacketReader::new(1);
        let mut rx = BasicFrameBuffer::new(16);

        // Fill the single slot
        let mut buf1 = [0u8; 256];
        let len = build_ipv4_fragment(&mut buf1, 1, 0, true, &[0u8; 16]);
        let f1 = Frame::new(0, &mut buf1, len, false);
        reader.process_ipv4(f1, &mut rx);
        assert_eq!(reader.pending_entries(), 1);

        // Different identification → new entry rejected
        let mut buf2 = [0u8; 256];
        let len = build_ipv4_fragment(&mut buf2, 2, 0, true, &[0u8; 16]);
        let f2 = Frame::new(1, &mut buf2, len, false);
        assert!(reader.process_ipv4(f2, &mut rx).is_none());
        assert_eq!(rx.num_frames(), 1); // rejected
        assert_eq!(reader.pending_entries(), 1);
    }

    // --- process_ipv6: non-fragmented ---

    #[test]
    fn ipv6_non_fragmented() {
        let mut reader = PacketReader::new(16);
        let mut rx = BasicFrameBuffer::new(16);
        let mut buf = [0u8; 256];
        let udp_off = ETH_LEN + IPV6_HEADER_LEN;
        let len = build_ipv6_udp(&mut buf, 4321, 8765, b"world");
        let frame = Frame::new(0, &mut buf, len, false);

        let pkt = reader
            .process_ipv6(frame, None, udp_off, &mut rx)
            .expect("should return packet");
        assert_eq!(pkt.src_port, 4321);
        assert_eq!(pkt.dst_port, 8765);
        assert_eq!(pkt.src_addr, IpAddress::V6(Ipv6Address::new(SRC_V6)));
        assert_eq!(pkt.dst_addr, IpAddress::V6(Ipv6Address::new(DST_V6)));
        assert_eq!(pkt.packet.num_frames(), 1);
    }

    #[test]
    fn ipv6_too_short_for_udp() {
        let mut reader = PacketReader::new(16);
        let mut rx = BasicFrameBuffer::new(16);
        let mut buf = [0u8; 256];
        buf[14] = 0x60;
        buf[20] = IpProtocols::Udp;
        buf[22..38].copy_from_slice(&SRC_V6);
        buf[38..54].copy_from_slice(&DST_V6);
        // Frame only covers the IPv6 header, no room for UDP
        let frame = Frame::new(0, &mut buf, ETH_LEN + IPV6_HEADER_LEN, false);

        assert!(
            reader
                .process_ipv6(frame, None, ETH_LEN + IPV6_HEADER_LEN, &mut rx)
                .is_none()
        );
        assert_eq!(rx.num_frames(), 1);
    }

    // --- process_ipv6: fragment reassembly ---

    #[test]
    fn ipv6_fragment_reassembly() {
        let mut reader = PacketReader::new(16);
        let mut rx = BasicFrameBuffer::new(16);

        // First fragment: UDP header + 8 bytes, MF=1
        let mut buf1 = [0u8; 256];
        let first = udp_first_frag(3000, 4000, &[1, 2, 3, 4, 5, 6, 7, 8]);
        let len1 = build_ipv6_fragment(&mut buf1, 100, 0, true, IpProtocols::Udp, &first);
        let f1 = Frame::new(0, &mut buf1, len1, false);
        assert!(
            reader
                .process_ipv6(f1, Some(FRAG_OFF), FRAG_OFF + FRAGMENT_EXT_LEN, &mut rx)
                .is_none()
        );
        assert_eq!(reader.pending_entries(), 1);

        // Last fragment: 8 bytes, MF=0, offset=2
        let mut buf2 = [0u8; 256];
        let len2 = build_ipv6_fragment(&mut buf2, 100, 2, false, IpProtocols::Udp, &[9; 8]);
        let f2 = Frame::new(1, &mut buf2, len2, false);
        let pkt = reader
            .process_ipv6(f2, Some(FRAG_OFF), FRAG_OFF + FRAGMENT_EXT_LEN, &mut rx)
            .expect("should complete");
        assert_eq!(pkt.src_port, 3000);
        assert_eq!(pkt.dst_port, 4000);
        assert_eq!(pkt.packet.num_frames(), 2);
        assert_eq!(reader.pending_entries(), 0);
    }

    #[test]
    fn ipv6_non_udp_fragment_rejected() {
        let mut reader = PacketReader::new(16);
        let mut rx = BasicFrameBuffer::new(16);
        let mut buf = [0u8; 256];
        let len = build_ipv6_fragment(&mut buf, 1, 0, true, IpProtocols::Tcp, &[0u8; 16]);
        let frame = Frame::new(0, &mut buf, len, false);

        assert!(
            reader
                .process_ipv6(frame, Some(FRAG_OFF), FRAG_OFF + FRAGMENT_EXT_LEN, &mut rx)
                .is_none()
        );
        assert_eq!(rx.num_frames(), 1);
    }

    #[test]
    fn ipv6_fragment_too_short_for_ext() {
        let mut reader = PacketReader::new(16);
        let mut rx = BasicFrameBuffer::new(16);
        let mut buf = [0u8; 256];
        buf[14] = 0x60;
        buf[20] = 44; // Fragment
        buf[22..38].copy_from_slice(&SRC_V6);
        buf[38..54].copy_from_slice(&DST_V6);
        // Frame only 56 bytes — needs 62 (54 + 8) for fragment ext header
        let frame = Frame::new(0, &mut buf, FRAG_OFF + 2, false);

        assert!(
            reader
                .process_ipv6(frame, Some(FRAG_OFF), FRAG_OFF, &mut rx)
                .is_none()
        );
        assert_eq!(rx.num_frames(), 1);
    }

    #[test]
    fn ipv6_capacity_exceeded() {
        let mut reader = PacketReader::new(1);
        let mut rx = BasicFrameBuffer::new(16);

        let mut buf1 = [0u8; 256];
        let len = build_ipv6_fragment(&mut buf1, 1, 0, true, IpProtocols::Udp, &[0u8; 16]);
        let f1 = Frame::new(0, &mut buf1, len, false);
        reader.process_ipv6(f1, Some(FRAG_OFF), FRAG_OFF + FRAGMENT_EXT_LEN, &mut rx);
        assert_eq!(reader.pending_entries(), 1);

        // Different id → rejected
        let mut buf2 = [0u8; 256];
        let len = build_ipv6_fragment(&mut buf2, 2, 0, true, IpProtocols::Udp, &[0u8; 16]);
        let f2 = Frame::new(1, &mut buf2, len, false);
        assert!(
            reader
                .process_ipv6(f2, Some(FRAG_OFF), FRAG_OFF + FRAGMENT_EXT_LEN, &mut rx)
                .is_none()
        );
        assert_eq!(rx.num_frames(), 1);
    }

    // --- pending_entries ---

    #[test]
    fn pending_entries_counts_both_protocols() {
        let mut reader = PacketReader::new(16);
        let mut rx = BasicFrameBuffer::new(16);
        assert_eq!(reader.pending_entries(), 0);

        let mut buf1 = [0u8; 256];
        let len = build_ipv4_fragment(&mut buf1, 1, 0, true, &[0u8; 16]);
        let f1 = Frame::new(0, &mut buf1, len, false);
        reader.process_ipv4(f1, &mut rx);

        let mut buf2 = [0u8; 256];
        let len = build_ipv6_fragment(&mut buf2, 1, 0, true, IpProtocols::Udp, &[0u8; 16]);
        let f2 = Frame::new(1, &mut buf2, len, false);
        reader.process_ipv6(f2, Some(FRAG_OFF), FRAG_OFF + FRAGMENT_EXT_LEN, &mut rx);

        assert_eq!(reader.pending_entries(), 2);
    }

    // --- evict_stale ---

    #[test]
    fn evict_stale_returns_held_frames() {
        let mut reader = PacketReader::new(16);
        let mut rx = BasicFrameBuffer::new(16);

        let mut buf = [0u8; 256];
        let len = build_ipv4_fragment(&mut buf, 1, 0, true, &[0u8; 16]);
        let frame = Frame::new(0, &mut buf, len, false);
        reader.process_ipv4(frame, &mut rx);
        assert_eq!(reader.pending_entries(), 1);

        // Sleep briefly then evict with zero timeout
        std::thread::sleep(Duration::from_millis(5));
        reader.evict_stale(Duration::ZERO, &mut rx);
        assert_eq!(reader.pending_entries(), 0);
        assert_eq!(rx.num_frames(), 1);
    }

    #[test]
    fn evict_stale_keeps_fresh_entries() {
        let mut reader = PacketReader::new(16);
        let mut rx = BasicFrameBuffer::new(16);

        let mut buf = [0u8; 256];
        let len = build_ipv4_fragment(&mut buf, 1, 0, true, &[0u8; 16]);
        let frame = Frame::new(0, &mut buf, len, false);
        reader.process_ipv4(frame, &mut rx);

        // Very long timeout — entry should be kept
        reader.evict_stale(Duration::from_secs(3600), &mut rx);
        assert_eq!(reader.pending_entries(), 1);
        assert_eq!(rx.num_frames(), 0);
    }
}
