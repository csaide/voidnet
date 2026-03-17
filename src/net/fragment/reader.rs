use std::{collections::BTreeMap, hash::Hash};

use coarsetime::{Duration, Instant};
use rustc_hash::FxHashMap;

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
    /// IP protocol number from the fragment headers.
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
    /// Fragments keyed by byte offset, kept sorted via BTreeMap.
    fragments: BTreeMap<usize, Frame<'umem>>,
    /// End offset of each fragment, keyed by start offset (parallel to `fragments`).
    fragment_ends: BTreeMap<usize, usize>,
    /// Known when the final fragment (MF=0) arrives.
    total_len: Option<usize>,
    first_received: Instant,
    /// Set when overlapping fragments are detected. The entry will be
    /// discarded on the next eviction pass (or immediately for IPv6 per RFC 5722).
    poisoned: bool,
}

/// Result of attempting to insert a fragment.
enum InsertResult<'umem> {
    /// Fragment accepted.
    Ok,
    /// Duplicate fragment (exact same offset already present).
    Duplicate(Frame<'umem>),
    /// Fragment overlaps with an existing fragment.
    Overlap(Frame<'umem>),
}

impl<'umem> ReassemblyEntry<'umem> {
    fn new() -> Self {
        Self {
            fragments: BTreeMap::new(),
            fragment_ends: BTreeMap::new(),
            total_len: None,
            first_received: Instant::now(),
            poisoned: false,
        }
    }

    /// Insert a fragment by offset. Checks for overlaps with existing fragments.
    fn insert(
        &mut self,
        offset: usize,
        data_len: usize,
        more_fragments: bool,
        frame: Frame<'umem>,
    ) -> InsertResult<'umem> {
        // Exact duplicate check.
        if self.fragments.contains_key(&offset) {
            return InsertResult::Duplicate(frame);
        }

        let end = offset + data_len;

        // Check for overlap with the fragment immediately before this one.
        // If any fragment starts at or before `offset` and extends past it, we overlap.
        if let Some((&prev_start, &prev_end)) = self.fragment_ends.range(..=offset).next_back()
            && prev_start != offset
            && prev_end > offset
        {
            return InsertResult::Overlap(frame);
        }

        // Check for overlap with the fragment immediately after this one.
        // If any fragment starts before `end`, we overlap with it.
        if let Some((&next_start, _)) = self.fragment_ends.range(offset + 1..).next()
            && next_start < end
        {
            return InsertResult::Overlap(frame);
        }

        self.fragments.insert(offset, frame);
        self.fragment_ends.insert(offset, end);
        if !more_fragments {
            self.total_len = Some(end);
        }
        InsertResult::Ok
    }

    /// Check whether all fragments have been received with no gaps.
    ///
    /// Walks the sorted fragment_ends map and verifies that each fragment
    /// starts exactly where the previous one ended, covering [0..total_len).
    fn is_complete(&self) -> bool {
        let total = match self.total_len {
            Some(t) => t,
            None => return false,
        };

        let mut expected = 0;
        for (&start, &end) in &self.fragment_ends {
            if start != expected {
                return false; // gap detected
            }
            expected = end;
        }
        expected == total
    }

    fn into_packet(self) -> Packet<'umem> {
        Packet::Multi(self.fragments.into_values().collect())
    }
}

/// Evict stale reassembly entries from a map, returning held frames.
fn evict_map<'umem, K: Eq + Hash>(
    map: &mut FxHashMap<K, ReassemblyEntry<'umem>>,
    now: Instant,
    timeout: Duration,
    rx_return: &mut impl FrameBuffer<'umem>,
) {
    map.retain(|_, entry| {
        if now.duration_since(entry.first_received) > timeout {
            for (_, frame) in std::mem::take(&mut entry.fragments) {
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
    ipv4_reassembly: FxHashMap<Ipv4FragmentKey, ReassemblyEntry<'umem>>,
    ipv6_reassembly: FxHashMap<Ipv6FragmentKey, ReassemblyEntry<'umem>>,
    max_entries: usize,
}

impl<'umem> FragmentReader<'umem> {
    /// Create a new reader with the given maximum number of concurrent
    /// reassembly entries (across both IPv4 and IPv6).
    pub fn new(max_entries: usize) -> Self {
        Self {
            ipv4_reassembly: FxHashMap::with_capacity_and_hasher(max_entries, Default::default()),
            ipv6_reassembly: FxHashMap::with_capacity_and_hasher(max_entries, Default::default()),
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
        let ip = Ipv4Header::from_bytes(&frame);
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

        match entry.insert(frag_offset_bytes, payload_len, more_fragments, frame) {
            InsertResult::Duplicate(dup_frame) => {
                rx_return.push(dup_frame);
                return None;
            }
            InsertResult::Overlap(frame) => {
                // For IPv4, discard the overlapping fragment and poison the entry.
                entry.poisoned = true;
                rx_return.push(frame);
                return None;
            }
            InsertResult::Ok => {}
        }

        if !entry.poisoned && entry.is_complete() {
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

        let frag_hdr = Ipv6FragmentHeader::from_bytes_at(&frame, frag_ext_offset);
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

        let ip = Ipv6Header::from_bytes(&frame);
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

        match entry.insert(frag_offset_bytes, data_len, more_fragments, frame) {
            InsertResult::Duplicate(dup_frame) => {
                rx_return.push(dup_frame);
                return None;
            }
            InsertResult::Overlap(frame) => {
                // RFC 5722: IPv6 overlapping fragments MUST cause the entire
                // datagram to be silently discarded. Drop all held fragments.
                let entry = self.ipv6_reassembly.remove(&remove_key).unwrap();
                rx_return.push(frame);
                for (_, held_frame) in entry.fragments {
                    rx_return.push(held_frame);
                }
                return None;
            }
            InsertResult::Ok => {}
        }

        if entry.is_complete() {
            let entry = self.ipv6_reassembly.remove(&remove_key).unwrap();
            let packet = entry.into_packet();
            return Some(ReassembledPacket { packet, protocol });
        }

        None
    }

    /// Evict reassembly entries older than `timeout`, returning held frames.
    pub fn evict_stale(
        &mut self,
        now: Instant,
        timeout: Duration,
        rx_return: &mut impl FrameBuffer<'umem>,
    ) {
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
    use crate::{
        net::{
            fragment::FragmentWriter,
            wire::{
                ethernet::{EthernetFrame, MacAddress},
                ip::{IPV4_MIN_HEADER_LEN, IPV6_HEADER_LEN, IpProtocols},
                udp::UdpHeader,
            },
        },
        xdp::frame::{BasicFrameBuffer, Frame},
    };

    use super::*;

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

    #[test]
    fn evict_stale_returns_frames() {
        let mut reader = FragmentReader::new(16);
        let mut rx = BasicFrameBuffer::new(16);

        let mut buf = [0u8; 256];
        let len = build_ipv4_fragment(&mut buf, 1, IpProtocols::Udp, 0, true, &[0u8; 16]);
        let frame = Frame::new(0, &mut buf, len, false);
        reader.process_ipv4(frame, &mut rx);
        assert_eq!(reader.pending_entries(), 1);

        std::thread::sleep(std::time::Duration::from_millis(5));
        reader.evict_stale(Instant::now(), Duration::from_ticks(0), &mut rx);
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

        reader.evict_stale(Instant::now(), Duration::from_secs(3600), &mut rx);
        assert_eq!(reader.pending_entries(), 1);
        assert_eq!(rx.num_frames(), 0);
    }

    #[test]
    fn ipv4_roundtrip() {
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
            src_mac, dst_mac, src_ip, dst_ip, 64, &transport, &payload, 1500, false, &mut free,
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
            let ip = Ipv4Header::from_bytes(frame);
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

    /// Overlapping IPv4 fragments are detected and the overlapping fragment
    /// is rejected. The entry is poisoned so it never completes.
    #[test]
    fn ipv4_overlapping_fragments_rejected() {
        let mut reader = FragmentReader::new(16);
        let mut rx = BasicFrameBuffer::new(16);

        // Fragment 1: offset=0, 16 bytes payload, MF=1.
        let mut buf1 = [0u8; 256];
        let len1 = build_ipv4_fragment(&mut buf1, 55, IpProtocols::Udp, 0, true, &[0xAA; 16]);
        let f1 = Frame::new(0, &mut buf1, len1, false);
        let result1 = reader.process_ipv4(f1, &mut rx);
        assert!(result1.is_none(), "first fragment should not complete");
        assert_eq!(reader.pending_entries(), 1);

        // Fragment 2: offset=8 bytes (frag_offset_8=1), 16 bytes payload, MF=0.
        // Overlaps bytes 8–15 with fragment 1.
        let mut buf2 = [0u8; 256];
        let len2 = build_ipv4_fragment(&mut buf2, 55, IpProtocols::Udp, 1, false, &[0xBB; 16]);
        let f2 = Frame::new(1, &mut buf2, len2, false);
        let result2 = reader.process_ipv4(f2, &mut rx);

        // Overlapping fragment rejected, entry poisoned.
        assert!(result2.is_none(), "overlapping fragment must not complete");
        assert_eq!(reader.pending_entries(), 1, "entry remains but is poisoned");
        // The overlapping frame was returned to rx_return.
        assert_eq!(rx.num_frames(), 1, "overlapping frame returned to caller");
    }

    /// Fragments with a gap are not declared complete even when the sum of
    /// their data lengths equals total_len.
    #[test]
    fn ipv4_gap_fragments_not_declared_complete() {
        let mut reader = FragmentReader::new(16);
        let mut rx = BasicFrameBuffer::new(16);

        // Fragment 1: offset=0, 8 bytes payload, MF=1.
        let mut buf1 = [0u8; 256];
        let len1 = build_ipv4_fragment(&mut buf1, 66, IpProtocols::Udp, 0, true, &[0x11; 8]);
        let f1 = Frame::new(0, &mut buf1, len1, false);
        assert!(reader.process_ipv4(f1, &mut rx).is_none());

        // Fragment 2: offset=24 bytes (frag_offset_8=3), 16 bytes payload,
        // MF=0. Sets total_len = 24+16 = 40.
        let mut buf2 = [0u8; 256];
        let len2 = build_ipv4_fragment(&mut buf2, 66, IpProtocols::Udp, 3, false, &[0x33; 16]);
        let f2 = Frame::new(1, &mut buf2, len2, false);
        assert!(reader.process_ipv4(f2, &mut rx).is_none());

        // Fragment 3: offset=16 bytes (frag_offset_8=2), 16 bytes payload,
        // MF=1. Gap at [8..16) remains unfilled.
        let mut buf3 = [0u8; 256];
        let len3 = build_ipv4_fragment(&mut buf3, 66, IpProtocols::Udp, 2, true, &[0x22; 16]);
        let f3 = Frame::new(2, &mut buf3, len3, false);
        let result = reader.process_ipv4(f3, &mut rx);

        // Contiguity check detects the gap — not declared complete.
        assert!(
            result.is_none(),
            "fragments with gap at [8..16) must not be declared complete"
        );
        assert_eq!(
            reader.pending_entries(),
            1,
            "entry stays pending until gap is filled"
        );
    }

    #[test]
    fn ipv4_single_frame_roundtrip() {
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
            src_mac, dst_mac, src_ip, dst_ip, 64, &transport, payload, 1500, false, &mut free,
        )
        .unwrap();

        // Single frame → not a fragment, returned directly as Packet::Single.
        // Just verify it's a single frame with correct length.
        assert_eq!(packet.num_frames(), 1);
        match &packet {
            Packet::Single(frame) => {
                let ip = Ipv4Header::from_bytes(frame);
                assert!(ip.dont_fragment());
                assert!(!ip.is_fragment());
            }
            _ => panic!("expected Single"),
        }
    }
}
