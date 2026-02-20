use std::{
    collections::HashMap,
    hash::Hash,
    time::{Duration, Instant},
};

use crate::{
    net::wire::ip::{
        FRAGMENT_EXT_LEN, Ipv4Address, Ipv4Header, Ipv6Address, Ipv6FragmentHeader, Ipv6Header,
    },
    xdp::frame::{Frame, FrameBuffer},
};

use super::pkt::Packet;

/// A fully reassembled IP datagram, protocol-agnostic.
///
/// Does not parse transport-layer metadata — the caller is responsible
/// for interpreting the payload based on `protocol`.
pub struct ReassembledPacket<'umem> {
    /// The reassembled frames (original fragment frames, sorted by offset).
    pub packet: Packet<'umem>,
    /// IP protocol number from the fragment headers (e.g. 17 for UDP, 6 for TCP).
    pub protocol: u8,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct Ipv4FragmentKey {
    src_addr: Ipv4Address,
    dst_addr: Ipv4Address,
    protocol: u8,
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
            total_len: None,
            received_len: 0,
            first_received: Instant::now(),
        }
    }

    /// Insert a fragment sorted by offset. Returns `Some(frame)` if a
    /// duplicate offset is already present.
    fn insert(
        &mut self,
        offset: usize,
        data_len: usize,
        more_fragments: bool,
        frame: Frame<'umem>,
    ) -> Option<Frame<'umem>> {
        match self.fragments.binary_search_by_key(&offset, |&(o, _)| o) {
            Ok(_) => Some(frame), // duplicate
            Err(pos) => {
                self.fragments.insert(pos, (offset, frame));
                self.received_len += data_len;
                if !more_fragments {
                    self.total_len = Some(offset + data_len);
                }
                None
            }
        }
    }

    fn is_complete(&self) -> bool {
        match self.total_len {
            Some(total) => self.received_len == total,
            None => false,
        }
    }

    fn into_packet(self) -> Packet<'umem> {
        Packet::Multi(self.fragments.into_iter().map(|(_, f)| f).collect())
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

/// Protocol-generic IP fragment reassembly engine.
///
/// Does not parse transport-layer headers or extract port numbers. It
/// operates purely at the IP fragmentation level, making it usable for
/// any IP protocol.
pub struct FragmentReader<'umem> {
    ipv4_reassembly: HashMap<Ipv4FragmentKey, ReassemblyEntry<'umem>>,
    ipv6_reassembly: HashMap<Ipv6FragmentKey, ReassemblyEntry<'umem>>,
    max_entries: usize,
}

impl<'umem> FragmentReader<'umem> {
    /// Create a new reader with the given maximum number of concurrent
    /// reassembly entries (across both IPv4 and IPv6).
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

    /// Process an IPv4 fragment.
    ///
    /// The frame must contain a valid Ethernet + IPv4 header with fragment
    /// fields set (MF and/or non-zero offset). Non-fragment frames should
    /// not be passed here.
    ///
    /// Returns `Some(ReassembledPacket)` when all fragments of a datagram
    /// have been received, `None` otherwise. Duplicate fragments are pushed
    /// to `rx_return`.
    pub fn process_ipv4(
        &mut self,
        frame: Frame<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
    ) -> Option<ReassembledPacket<'umem>> {
        let ip = Ipv4Header::from_frame(&frame);
        let src_addr = ip.src_addr;
        let dst_addr = ip.dst_addr;
        let protocol = ip.protocol;
        let identification = ip.identification();
        let frag_offset_bytes = ip.fragment_offset() as usize * 8;
        let more_fragments = ip.more_fragments();
        let payload_len = ip.payload_len();

        // Single-fragment datagram: offset=0 and MF=0 means the entire
        // datagram is in this one frame. Return immediately without
        // touching the reassembly map.
        if frag_offset_bytes == 0 && !more_fragments {
            return Some(ReassembledPacket {
                packet: Packet::Single(frame),
                protocol,
            });
        }

        let key = Ipv4FragmentKey {
            src_addr,
            dst_addr,
            protocol,
            identification,
        };

        if !self.ipv4_reassembly.contains_key(&key) && !self.has_capacity_for_new_entry() {
            rx_return.push(frame);
            return None;
        }

        let remove_key = key.clone();
        let entry = self
            .ipv4_reassembly
            .entry(key)
            .or_insert_with(ReassemblyEntry::new);

        if let Some(dup_frame) =
            entry.insert(frag_offset_bytes, payload_len, more_fragments, frame)
        {
            rx_return.push(dup_frame);
            return None;
        }

        if entry.is_complete() {
            let entry = self.ipv4_reassembly.remove(&remove_key).unwrap();
            let packet = entry.into_packet();
            return Some(ReassembledPacket { packet, protocol });
        }

        None
    }

    /// Process an IPv6 fragment.
    ///
    /// `frag_ext_offset` is the byte offset (from frame start) where the
    /// IPv6 Fragment Extension Header begins. The frame must contain at
    /// least `frag_ext_offset + FRAGMENT_EXT_LEN` bytes.
    ///
    /// Returns `Some(ReassembledPacket)` when all fragments of a datagram
    /// have been received, `None` otherwise.
    pub fn process_ipv6(
        &mut self,
        frame: Frame<'umem>,
        frag_ext_offset: usize,
        rx_return: &mut impl FrameBuffer<'umem>,
    ) -> Option<ReassembledPacket<'umem>> {
        if frame.len() < frag_ext_offset + FRAGMENT_EXT_LEN {
            rx_return.push(frame);
            return None;
        }

        let frag_hdr = Ipv6FragmentHeader::from_bytes(&frame, frag_ext_offset);
        let protocol = frag_hdr.next_header;
        let frag_offset_bytes = frag_hdr.fragment_offset() as usize * 8;
        let more_fragments = frag_hdr.more_fragments();
        let identification = frag_hdr.identification();

        // Single-fragment datagram (atomic fragment): offset=0 and MF=0
        // means the entire datagram is in this one frame. Return
        // immediately without touching the reassembly map.
        if frag_offset_bytes == 0 && !more_fragments {
            return Some(ReassembledPacket {
                packet: Packet::Single(frame),
                protocol,
            });
        }

        let ip = Ipv6Header::from_frame(&frame);
        let src_addr = ip.src_addr;
        let dst_addr = ip.dst_addr;

        let data_start = frag_ext_offset + FRAGMENT_EXT_LEN;
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

        if !self.ipv6_reassembly.contains_key(&key) && !self.has_capacity_for_new_entry() {
            rx_return.push(frame);
            return None;
        }

        let remove_key = key.clone();
        let entry = self
            .ipv6_reassembly
            .entry(key)
            .or_insert_with(ReassemblyEntry::new);

        if let Some(dup_frame) = entry.insert(frag_offset_bytes, data_len, more_fragments, frame) {
            rx_return.push(dup_frame);
            return None;
        }

        if entry.is_complete() {
            let entry = self.ipv6_reassembly.remove(&remove_key).unwrap();
            let packet = entry.into_packet();
            return Some(ReassembledPacket { packet, protocol });
        }

        None
    }

    /// Evict reassembly entries older than `timeout`, returning held frames.
    pub fn evict_stale(&mut self, timeout: Duration, rx_return: &mut impl FrameBuffer<'umem>) {
        let now = Instant::now();
        evict_map(&mut self.ipv4_reassembly, now, timeout, rx_return);
        evict_map(&mut self.ipv6_reassembly, now, timeout, rx_return);
    }

    /// Number of in-progress reassembly entries (IPv4 + IPv6).
    pub fn pending_entries(&self) -> usize {
        self.ipv4_reassembly.len() + self.ipv6_reassembly.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::wire::{
        ethernet::EthernetFrame,
        ip::{IPV4_MIN_HEADER_LEN, IPV6_HEADER_LEN, IpProtocols},
    };
    use crate::xdp::frame::{BasicFrameBuffer, Frame};

    const ETH_LEN: usize = size_of::<EthernetFrame>();
    const SRC_V4: [u8; 4] = [192, 168, 1, 1];
    const DST_V4: [u8; 4] = [10, 0, 0, 1];
    const SRC_V6: [u8; 16] = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    const DST_V6: [u8; 16] = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

    /// Build an IPv4 fragment frame.
    fn build_ipv4_fragment(
        buf: &mut [u8],
        id: u16,
        protocol: u8,
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
        buf[23] = protocol;
        buf[26..30].copy_from_slice(&SRC_V4);
        buf[30..34].copy_from_slice(&DST_V4);
        let p = ETH_LEN + IPV4_MIN_HEADER_LEN;
        buf[p..p + data.len()].copy_from_slice(data);
        frame_len
    }

    /// Build an IPv6 fragment frame.
    fn build_ipv6_fragment(
        buf: &mut [u8],
        id: u32,
        next_header: u8,
        frag_offset_8: u16,
        more: bool,
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

    const FRAG_OFF: usize = ETH_LEN + IPV6_HEADER_LEN;

    // --- IPv4 reassembly ---

    #[test]
    fn ipv4_two_fragment_reassembly() {
        let mut reader = FragmentReader::new(16);
        let mut rx = BasicFrameBuffer::new(16);

        // First fragment: 16 bytes data, MF=1, offset=0
        let mut buf1 = [0u8; 256];
        let len1 = build_ipv4_fragment(&mut buf1, 42, IpProtocols::Udp, 0, true, &[0xAA; 16]);
        let f1 = Frame::new(0, &mut buf1, len1, false);
        assert!(reader.process_ipv4(f1, &mut rx).is_none());
        assert_eq!(reader.pending_entries(), 1);

        // Last fragment: 8 bytes data, MF=0, offset=2 (2*8=16 bytes in)
        let mut buf2 = [0u8; 256];
        let len2 = build_ipv4_fragment(&mut buf2, 42, IpProtocols::Udp, 2, false, &[0xBB; 8]);
        let f2 = Frame::new(1, &mut buf2, len2, false);
        let result = reader.process_ipv4(f2, &mut rx).expect("should complete");
        assert_eq!(result.protocol, IpProtocols::Udp);
        assert_eq!(result.packet.num_frames(), 2);
        assert_eq!(reader.pending_entries(), 0);
    }

    #[test]
    fn ipv4_out_of_order() {
        let mut reader = FragmentReader::new(16);
        let mut rx = BasicFrameBuffer::new(16);

        // Send last fragment first
        let mut buf2 = [0u8; 256];
        let len2 = build_ipv4_fragment(&mut buf2, 77, IpProtocols::Udp, 2, false, &[0u8; 8]);
        let f2 = Frame::new(1, &mut buf2, len2, false);
        assert!(reader.process_ipv4(f2, &mut rx).is_none());

        // Then first fragment
        let mut buf1 = [0u8; 256];
        let len1 = build_ipv4_fragment(&mut buf1, 77, IpProtocols::Udp, 0, true, &[0u8; 16]);
        let f1 = Frame::new(0, &mut buf1, len1, false);
        let result = reader.process_ipv4(f1, &mut rx).expect("should complete");
        assert_eq!(result.protocol, IpProtocols::Udp);
        assert_eq!(result.packet.num_frames(), 2);
    }

    #[test]
    fn ipv4_duplicate_returned() {
        let mut reader = FragmentReader::new(16);
        let mut rx = BasicFrameBuffer::new(16);

        let mut buf1 = [0u8; 256];
        let len = build_ipv4_fragment(&mut buf1, 99, IpProtocols::Udp, 0, true, &[0u8; 16]);
        let f1 = Frame::new(0, &mut buf1, len, false);
        reader.process_ipv4(f1, &mut rx);

        // Duplicate offset
        let mut buf2 = [0u8; 256];
        let len = build_ipv4_fragment(&mut buf2, 99, IpProtocols::Udp, 0, true, &[0u8; 16]);
        let f2 = Frame::new(1, &mut buf2, len, false);
        assert!(reader.process_ipv4(f2, &mut rx).is_none());
        assert_eq!(rx.num_frames(), 1); // dup returned
    }

    #[test]
    fn ipv4_capacity_exceeded() {
        let mut reader = FragmentReader::new(1);
        let mut rx = BasicFrameBuffer::new(16);

        let mut buf1 = [0u8; 256];
        let len = build_ipv4_fragment(&mut buf1, 1, IpProtocols::Udp, 0, true, &[0u8; 16]);
        let f1 = Frame::new(0, &mut buf1, len, false);
        reader.process_ipv4(f1, &mut rx);
        assert_eq!(reader.pending_entries(), 1);

        // Different id → new entry rejected
        let mut buf2 = [0u8; 256];
        let len = build_ipv4_fragment(&mut buf2, 2, IpProtocols::Udp, 0, true, &[0u8; 16]);
        let f2 = Frame::new(1, &mut buf2, len, false);
        assert!(reader.process_ipv4(f2, &mut rx).is_none());
        assert_eq!(rx.num_frames(), 1);
        assert_eq!(reader.pending_entries(), 1);
    }

    #[test]
    fn ipv4_protocol_in_key() {
        // Fragments with same id but different protocols are different datagrams.
        let mut reader = FragmentReader::new(16);
        let mut rx = BasicFrameBuffer::new(16);

        let mut buf1 = [0u8; 256];
        let len = build_ipv4_fragment(&mut buf1, 42, IpProtocols::Udp, 0, true, &[0u8; 16]);
        let f1 = Frame::new(0, &mut buf1, len, false);
        reader.process_ipv4(f1, &mut rx);

        let mut buf2 = [0u8; 256];
        let len = build_ipv4_fragment(&mut buf2, 42, IpProtocols::Tcp, 0, true, &[0u8; 16]);
        let f2 = Frame::new(1, &mut buf2, len, false);
        reader.process_ipv4(f2, &mut rx);

        assert_eq!(reader.pending_entries(), 2); // two separate entries
    }

    // --- IPv6 reassembly ---

    #[test]
    fn ipv6_two_fragment_reassembly() {
        let mut reader = FragmentReader::new(16);
        let mut rx = BasicFrameBuffer::new(16);

        let mut buf1 = [0u8; 256];
        let len1 = build_ipv6_fragment(&mut buf1, 100, IpProtocols::Udp, 0, true, &[0xAA; 16]);
        let f1 = Frame::new(0, &mut buf1, len1, false);
        assert!(reader.process_ipv6(f1, FRAG_OFF, &mut rx).is_none());
        assert_eq!(reader.pending_entries(), 1);

        let mut buf2 = [0u8; 256];
        let len2 = build_ipv6_fragment(&mut buf2, 100, IpProtocols::Udp, 2, false, &[0xBB; 8]);
        let f2 = Frame::new(1, &mut buf2, len2, false);
        let result = reader
            .process_ipv6(f2, FRAG_OFF, &mut rx)
            .expect("should complete");
        assert_eq!(result.protocol, IpProtocols::Udp);
        assert_eq!(result.packet.num_frames(), 2);
        assert_eq!(reader.pending_entries(), 0);
    }

    #[test]
    fn ipv6_out_of_order() {
        let mut reader = FragmentReader::new(16);
        let mut rx = BasicFrameBuffer::new(16);

        // Last fragment first
        let mut buf2 = [0u8; 256];
        let len2 = build_ipv6_fragment(&mut buf2, 200, IpProtocols::Udp, 2, false, &[0u8; 8]);
        let f2 = Frame::new(1, &mut buf2, len2, false);
        assert!(reader.process_ipv6(f2, FRAG_OFF, &mut rx).is_none());

        // Then first
        let mut buf1 = [0u8; 256];
        let len1 = build_ipv6_fragment(&mut buf1, 200, IpProtocols::Udp, 0, true, &[0u8; 16]);
        let f1 = Frame::new(0, &mut buf1, len1, false);
        let result = reader
            .process_ipv6(f1, FRAG_OFF, &mut rx)
            .expect("should complete");
        assert_eq!(result.protocol, IpProtocols::Udp);
        assert_eq!(result.packet.num_frames(), 2);
    }

    #[test]
    fn ipv6_duplicate_returned() {
        let mut reader = FragmentReader::new(16);
        let mut rx = BasicFrameBuffer::new(16);

        let mut buf1 = [0u8; 256];
        let len = build_ipv6_fragment(&mut buf1, 50, IpProtocols::Udp, 0, true, &[0u8; 16]);
        let f1 = Frame::new(0, &mut buf1, len, false);
        reader.process_ipv6(f1, FRAG_OFF, &mut rx);

        let mut buf2 = [0u8; 256];
        let len = build_ipv6_fragment(&mut buf2, 50, IpProtocols::Udp, 0, true, &[0u8; 16]);
        let f2 = Frame::new(1, &mut buf2, len, false);
        assert!(reader.process_ipv6(f2, FRAG_OFF, &mut rx).is_none());
        assert_eq!(rx.num_frames(), 1);
    }

    #[test]
    fn ipv6_capacity_exceeded() {
        let mut reader = FragmentReader::new(1);
        let mut rx = BasicFrameBuffer::new(16);

        let mut buf1 = [0u8; 256];
        let len = build_ipv6_fragment(&mut buf1, 1, IpProtocols::Udp, 0, true, &[0u8; 16]);
        let f1 = Frame::new(0, &mut buf1, len, false);
        reader.process_ipv6(f1, FRAG_OFF, &mut rx);
        assert_eq!(reader.pending_entries(), 1);

        let mut buf2 = [0u8; 256];
        let len = build_ipv6_fragment(&mut buf2, 2, IpProtocols::Udp, 0, true, &[0u8; 16]);
        let f2 = Frame::new(1, &mut buf2, len, false);
        assert!(reader.process_ipv6(f2, FRAG_OFF, &mut rx).is_none());
        assert_eq!(rx.num_frames(), 1);
    }

    #[test]
    fn ipv6_too_short_for_frag_ext() {
        let mut reader = FragmentReader::new(16);
        let mut rx = BasicFrameBuffer::new(16);
        let mut buf = [0u8; 256];
        buf[14] = 0x60;
        buf[20] = 44;
        buf[22..38].copy_from_slice(&SRC_V6);
        buf[38..54].copy_from_slice(&DST_V6);
        // Frame too short for fragment ext
        let frame = Frame::new(0, &mut buf, FRAG_OFF + 2, false);
        assert!(reader.process_ipv6(frame, FRAG_OFF, &mut rx).is_none());
        assert_eq!(rx.num_frames(), 1);
    }

    // --- pending_entries ---

    #[test]
    fn pending_entries_counts_both() {
        let mut reader = FragmentReader::new(16);
        let mut rx = BasicFrameBuffer::new(16);
        assert_eq!(reader.pending_entries(), 0);

        let mut buf1 = [0u8; 256];
        let len = build_ipv4_fragment(&mut buf1, 1, IpProtocols::Udp, 0, true, &[0u8; 16]);
        let f1 = Frame::new(0, &mut buf1, len, false);
        reader.process_ipv4(f1, &mut rx);

        let mut buf2 = [0u8; 256];
        let len = build_ipv6_fragment(&mut buf2, 1, IpProtocols::Udp, 0, true, &[0u8; 16]);
        let f2 = Frame::new(1, &mut buf2, len, false);
        reader.process_ipv6(f2, FRAG_OFF, &mut rx);

        assert_eq!(reader.pending_entries(), 2);
    }

    // --- evict_stale ---

    #[test]
    fn evict_stale_returns_frames() {
        let mut reader = FragmentReader::new(16);
        let mut rx = BasicFrameBuffer::new(16);

        let mut buf = [0u8; 256];
        let len = build_ipv4_fragment(&mut buf, 1, IpProtocols::Udp, 0, true, &[0u8; 16]);
        let frame = Frame::new(0, &mut buf, len, false);
        reader.process_ipv4(frame, &mut rx);
        assert_eq!(reader.pending_entries(), 1);

        std::thread::sleep(Duration::from_millis(5));
        reader.evict_stale(Duration::ZERO, &mut rx);
        assert_eq!(reader.pending_entries(), 0);
        assert_eq!(rx.num_frames(), 1);
    }

    #[test]
    fn evict_stale_keeps_fresh() {
        let mut reader = FragmentReader::new(16);
        let mut rx = BasicFrameBuffer::new(16);

        let mut buf = [0u8; 256];
        let len = build_ipv4_fragment(&mut buf, 1, IpProtocols::Udp, 0, true, &[0u8; 16]);
        let frame = Frame::new(0, &mut buf, len, false);
        reader.process_ipv4(frame, &mut rx);

        reader.evict_stale(Duration::from_secs(3600), &mut rx);
        assert_eq!(reader.pending_entries(), 1);
        assert_eq!(rx.num_frames(), 0);
    }

    // --- Roundtrip: FragmentWriter -> FragmentReader ---

    #[test]
    fn ipv4_roundtrip() {
        use super::super::writer::FragmentWriter;
        use crate::net::wire::{ethernet::MacAddress, udp::UdpHeader};

        let src_mac = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let dst_mac = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let src_ip = Ipv4Address::new(SRC_V4);
        let dst_ip = Ipv4Address::new(DST_V4);

        let payload = vec![0x42u8; 3000];
        let transport = UdpHeader::new(12345, 53, (8 + payload.len()) as u16, [0xAB, 0xCD]);

        let mut bufs: Vec<Vec<u8>> = (0..32).map(|_| vec![0u8; 2048]).collect();
        let mut free = BasicFrameBuffer::new(64);
        for (i, buf) in bufs.iter_mut().enumerate() {
            free.push(Frame::new(i as u64, buf.as_mut_slice(), 1, false));
        }

        let packet = FragmentWriter::fragment_ipv4(
            src_mac, dst_mac, src_ip, dst_ip, 64, &transport, &payload, 1500, &mut free,
        )
        .unwrap();

        // Now reassemble.
        let mut reader = FragmentReader::new(16);
        let mut rx = BasicFrameBuffer::new(16);
        let mut result = None;
        for frame in packet.into_frames() {
            if let Some(r) = reader.process_ipv4(frame, &mut rx) {
                result = Some(r);
            }
        }
        let reassembled = result.expect("should complete reassembly");
        assert_eq!(reassembled.protocol, IpProtocols::Udp);

        // Verify payload from reassembled frames.
        let mut data = Vec::new();
        for (i, frame) in reassembled.packet.frames().enumerate() {
            let ip = Ipv4Header::from_frame(frame);
            let data_start = ip.payload_offset();
            if i == 0 {
                // First fragment includes transport header.
                data.extend_from_slice(&frame[data_start + 8..frame.len()]);
            } else {
                data.extend_from_slice(&frame[data_start..frame.len()]);
            }
        }
        assert_eq!(data, payload);
    }

    #[test]
    fn ipv6_roundtrip() {
        use super::super::writer::FragmentWriter;
        use crate::net::wire::{ethernet::MacAddress, udp::UdpHeader};

        let src_mac = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let dst_mac = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let src_ip = Ipv6Address::new(SRC_V6);
        let dst_ip = Ipv6Address::new(DST_V6);

        let payload = vec![0x77u8; 3000];
        let transport = UdpHeader::new(12345, 53, (8 + payload.len()) as u16, [0xAB, 0xCD]);

        let mut bufs: Vec<Vec<u8>> = (0..32).map(|_| vec![0u8; 2048]).collect();
        let mut free = BasicFrameBuffer::new(64);
        for (i, buf) in bufs.iter_mut().enumerate() {
            free.push(Frame::new(i as u64, buf.as_mut_slice(), 1, false));
        }

        let packet = FragmentWriter::fragment_ipv6(
            src_mac, dst_mac, src_ip, dst_ip, 64, &transport, &payload, 1500, &mut free,
        )
        .unwrap();

        // Now reassemble.
        let frag_ext_offset = ETH_LEN + IPV6_HEADER_LEN;
        let mut reader = FragmentReader::new(16);
        let mut rx = BasicFrameBuffer::new(16);
        let mut result = None;
        for frame in packet.into_frames() {
            if let Some(r) = reader.process_ipv6(frame, frag_ext_offset, &mut rx) {
                result = Some(r);
            }
        }
        let reassembled = result.expect("should complete reassembly");
        assert_eq!(reassembled.protocol, IpProtocols::Udp);

        // Verify payload.
        let mut data = Vec::new();
        for (i, frame) in reassembled.packet.frames().enumerate() {
            let data_start = frag_ext_offset + FRAGMENT_EXT_LEN;
            if i == 0 {
                data.extend_from_slice(&frame[data_start + 8..frame.len()]);
            } else {
                data.extend_from_slice(&frame[data_start..frame.len()]);
            }
        }
        assert_eq!(data, payload);
    }

    #[test]
    fn ipv4_single_frame_roundtrip() {
        use super::super::writer::FragmentWriter;
        use crate::net::wire::{ethernet::MacAddress, udp::UdpHeader};

        let src_mac = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let dst_mac = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let src_ip = Ipv4Address::new(SRC_V4);
        let dst_ip = Ipv4Address::new(DST_V4);

        let payload = b"small";
        let transport = UdpHeader::new(1234, 5678, (8 + payload.len()) as u16, [0x00, 0x00]);

        let mut bufs: Vec<Vec<u8>> = (0..4).map(|_| vec![0u8; 2048]).collect();
        let mut free = BasicFrameBuffer::new(8);
        for (i, buf) in bufs.iter_mut().enumerate() {
            free.push(Frame::new(i as u64, buf.as_mut_slice(), 1, false));
        }

        let packet = FragmentWriter::fragment_ipv4(
            src_mac, dst_mac, src_ip, dst_ip, 64, &transport, payload, 1500, &mut free,
        )
        .unwrap();

        // Single frame → not a fragment, returned directly as Packet::Single.
        // Just verify it's a single frame with correct length.
        assert_eq!(packet.num_frames(), 1);
        match &packet {
            Packet::Single(frame) => {
                let ip = Ipv4Header::from_frame(frame);
                assert!(ip.dont_fragment());
                assert!(!ip.is_fragment());
            }
            _ => panic!("expected Single"),
        }
    }
}
