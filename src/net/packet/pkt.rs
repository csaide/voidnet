use std::sync::atomic::{AtomicU16, AtomicU32};

use crate::{
    net::wire::{ethernet::EthernetFrame, udp::UDP_HEADER_LEN},
    xdp::frame::Frame,
};

pub const ETH_HEADER_LEN: usize = size_of::<EthernetFrame>();
pub const DEFAULT_MTU: u32 = 1500;

/// Global atomic counter for IPv4 identification field.
pub static IPV4_ID: AtomicU16 = AtomicU16::new(1);

/// Global atomic counter for IPv6 fragment header identification field.
pub static IPV6_ID: AtomicU32 = AtomicU32::new(1);

/// A packet is a collection of frames that are part of a single packet.
#[derive(Debug, Default)]
pub enum Packet<'umem> {
    #[default]
    Empty,
    Single(Frame<'umem>),
    Multi(Vec<Frame<'umem>>),
}

impl<'umem> Packet<'umem> {
    /// Returns the number of frames in this packet.
    pub fn num_frames(&self) -> usize {
        match self {
            Packet::Empty => 0,
            Packet::Single(_) => 1,
            Packet::Multi(frames) => frames.len(),
        }
    }

    /// Returns the total length of the packet in bytes.
    ///
    /// Note for fragmented packets this iterates over the entire packet use sparingly.
    pub fn len(&self) -> usize {
        match self {
            Packet::Empty => 0,
            Packet::Single(frame) => frame.len(),
            Packet::Multi(frames) => frames.iter().map(|f| f.len()).sum(),
        }
    }

    /// Returns a borrowing iterator over the frames in this packet.
    pub fn frames(&self) -> PacketFrameIter<'_, 'umem> {
        match self {
            Packet::Empty => PacketFrameIter::Empty,
            Packet::Single(frame) => PacketFrameIter::Single(std::iter::once(frame)),
            Packet::Multi(frames) => PacketFrameIter::Multi(frames.iter()),
        }
    }

    /// Returns a consuming iterator over the frames in this packet.
    pub fn into_frames(self) -> PacketIntoIter<'umem> {
        match self {
            Packet::Empty => PacketIntoIter::Empty,
            Packet::Single(frame) => PacketIntoIter::Single(std::iter::once(frame)),
            Packet::Multi(frames) => PacketIntoIter::Multi(frames.into_iter()),
        }
    }
}

impl<'umem, T: Iterator<Item = Frame<'umem>> + ExactSizeIterator> From<T> for Packet<'umem> {
    fn from(mut iter: T) -> Self {
        if iter.len() == 0 {
            panic!("Cannot create a packet from an empty iterator");
        } else if iter.len() == 1 {
            Packet::Single(iter.next().unwrap())
        } else {
            Packet::Multi(iter.collect())
        }
    }
}

/// Borrowing iterator over frames in a [`Packet`].
pub enum PacketFrameIter<'a, 'umem> {
    Empty,
    Single(std::iter::Once<&'a Frame<'umem>>),
    Multi(std::slice::Iter<'a, Frame<'umem>>),
}

impl<'a, 'umem> Iterator for PacketFrameIter<'a, 'umem> {
    type Item = &'a Frame<'umem>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            PacketFrameIter::Empty => None,
            PacketFrameIter::Single(iter) => iter.next(),
            PacketFrameIter::Multi(iter) => iter.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            PacketFrameIter::Empty => (0, Some(0)),
            PacketFrameIter::Single(iter) => iter.size_hint(),
            PacketFrameIter::Multi(iter) => iter.size_hint(),
        }
    }
}

impl<'a, 'umem> ExactSizeIterator for PacketFrameIter<'a, 'umem> {}

/// Consuming iterator over frames in a [`Packet`].
pub enum PacketIntoIter<'umem> {
    Empty,
    Single(std::iter::Once<Frame<'umem>>),
    Multi(std::vec::IntoIter<Frame<'umem>>),
}

impl<'umem> Iterator for PacketIntoIter<'umem> {
    type Item = Frame<'umem>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            PacketIntoIter::Empty => None,
            PacketIntoIter::Single(iter) => iter.next(),
            PacketIntoIter::Multi(iter) => iter.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            PacketIntoIter::Empty => (0, Some(0)),
            PacketIntoIter::Single(iter) => iter.size_hint(),
            PacketIntoIter::Multi(iter) => iter.size_hint(),
        }
    }
}

impl<'umem> ExactSizeIterator for PacketIntoIter<'umem> {}

/// Pre-computed fragment sizing plan used by both IPv4 and IPv6 fragmentation.
///
/// Computes the maximum fragment data size (8-byte aligned), the first chunk
/// size (accounting for the UDP header), and the total number of frames needed.
pub(crate) struct FragmentPlan {
    pub max_frag_data: usize,
    pub first_chunk: usize,
    pub num_frames: usize,
}

impl FragmentPlan {
    pub fn new(ip_header_overhead: usize, pmtu: u32, payload_len: usize) -> Self {
        let max_frag_data = (pmtu as usize - ip_header_overhead) & !7;
        let first_chunk = max_frag_data - UDP_HEADER_LEN;
        let remaining = payload_len - first_chunk;
        let subsequent_chunks = if remaining == 0 {
            0
        } else {
            (remaining + max_frag_data - 1) / max_frag_data
        };
        FragmentPlan {
            max_frag_data,
            first_chunk,
            num_frames: 1 + subsequent_chunks,
        }
    }

    pub fn fragment_sizes(
        &self,
        i: usize,
        payload_offset: usize,
        payload_len: usize,
    ) -> (usize, usize) {
        if i == 0 {
            let chunk = self.first_chunk.min(payload_len);
            (UDP_HEADER_LEN + chunk, chunk)
        } else if i == self.num_frames - 1 {
            let remaining = payload_len - payload_offset;
            (remaining, remaining)
        } else {
            (self.max_frag_data, self.max_frag_data)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xdp::frame::Frame;

    fn make_frame(buf: &mut [u8], len: usize) -> Frame<'_> {
        Frame::new(0, buf, len, false)
    }

    // --- Packet::num_frames ---

    #[test]
    fn single_num_frames() {
        let mut buf = [0u8; 64];
        let pkt = Packet::Single(make_frame(&mut buf, 10));
        assert_eq!(pkt.num_frames(), 1);
    }

    #[test]
    fn multi_num_frames() {
        let mut bufs = [[0u8; 64]; 3];
        let frames: Vec<_> = bufs.iter_mut().map(|b| make_frame(b, 10)).collect();
        let pkt = Packet::Multi(frames);
        assert_eq!(pkt.num_frames(), 3);
    }

    // --- Packet::frames (borrowing iterator) ---

    #[test]
    fn frames_iter_single() {
        let mut buf = [0u8; 64];
        buf[0] = 0xAA;
        let pkt = Packet::Single(make_frame(&mut buf, 10));
        let collected: Vec<_> = pkt.frames().collect();
        assert_eq!(collected.len(), 1);
        assert_eq!(collected[0][0], 0xAA);
    }

    #[test]
    fn frames_iter_multi() {
        let mut bufs = [[0u8; 64]; 3];
        for (i, b) in bufs.iter_mut().enumerate() {
            b[0] = i as u8;
        }
        let frames: Vec<_> = bufs.iter_mut().map(|b| make_frame(b, 10)).collect();
        let pkt = Packet::Multi(frames);
        let collected: Vec<_> = pkt.frames().collect();
        assert_eq!(collected.len(), 3);
        for (i, f) in collected.iter().enumerate() {
            assert_eq!(f[0], i as u8);
        }
    }

    // --- Packet::into_frames (consuming iterator) ---

    #[test]
    fn into_frames_single() {
        let mut buf = [0u8; 64];
        buf[0] = 0xBB;
        let pkt = Packet::Single(make_frame(&mut buf, 10));
        let collected: Vec<_> = pkt.into_frames().collect();
        assert_eq!(collected.len(), 1);
        assert_eq!(collected[0][0], 0xBB);
    }

    #[test]
    fn into_frames_multi() {
        let mut bufs = [[0u8; 64]; 2];
        bufs[0][0] = 0x01;
        bufs[1][0] = 0x02;
        let frames: Vec<_> = bufs.iter_mut().map(|b| make_frame(b, 10)).collect();
        let pkt = Packet::Multi(frames);
        let collected: Vec<_> = pkt.into_frames().collect();
        assert_eq!(collected.len(), 2);
        assert_eq!(collected[0][0], 0x01);
        assert_eq!(collected[1][0], 0x02);
    }

    // --- ExactSizeIterator (size_hint + len) ---

    #[test]
    fn frames_iter_exact_size() {
        let mut buf = [0u8; 64];
        let pkt = Packet::Single(make_frame(&mut buf, 10));
        let iter = pkt.frames();
        assert_eq!(iter.len(), 1);
        assert_eq!(iter.size_hint(), (1, Some(1)));

        let mut bufs = [[0u8; 64]; 3];
        let frames: Vec<_> = bufs.iter_mut().map(|b| make_frame(b, 10)).collect();
        let pkt = Packet::Multi(frames);
        let iter = pkt.frames();
        assert_eq!(iter.len(), 3);
        assert_eq!(iter.size_hint(), (3, Some(3)));
    }

    #[test]
    fn into_frames_exact_size() {
        let mut buf = [0u8; 64];
        let pkt = Packet::Single(make_frame(&mut buf, 10));
        let iter = pkt.into_frames();
        assert_eq!(iter.len(), 1);

        let mut bufs = [[0u8; 64]; 4];
        let frames: Vec<_> = bufs.iter_mut().map(|b| make_frame(b, 10)).collect();
        let pkt = Packet::Multi(frames);
        let iter = pkt.into_frames();
        assert_eq!(iter.len(), 4);
    }

    // --- FragmentPlan::new ---

    #[test]
    fn fragment_plan_ipv4_typical() {
        // IPv4: overhead=20, MTU=1500, payload=3000
        let plan = FragmentPlan::new(20, 1500, 3000);
        assert_eq!(plan.max_frag_data, 1480); // (1500-20) & !7
        assert_eq!(plan.first_chunk, 1472); // 1480 - UDP_HEADER_LEN
        assert_eq!(plan.num_frames, 3); // 1 + ceil(1528/1480)
    }

    #[test]
    fn fragment_plan_ipv6_typical() {
        // IPv6 + fragment ext: overhead=48, MTU=1500, payload=3000
        let plan = FragmentPlan::new(48, 1500, 3000);
        assert_eq!(plan.max_frag_data, 1448); // (1500-48) & !7 = 1452 & !7
        assert_eq!(plan.first_chunk, 1440);
        assert_eq!(plan.num_frames, 3);
    }

    #[test]
    fn fragment_plan_two_fragments() {
        // Payload barely exceeds single-packet capacity
        let plan = FragmentPlan::new(20, 1500, 1473);
        assert_eq!(plan.first_chunk, 1472);
        assert_eq!(plan.num_frames, 2);
    }

    #[test]
    fn fragment_plan_exact_first_chunk() {
        // payload == first_chunk => remaining=0, single frame suffices
        let plan = FragmentPlan::new(20, 1500, 1472);
        assert_eq!(plan.num_frames, 1);
    }

    #[test]
    fn fragment_plan_8_byte_alignment() {
        // MTU where (mtu - overhead) is not 8-aligned: 1505-20=1485, rounds down to 1480
        let plan = FragmentPlan::new(20, 1505, 3000);
        assert_eq!(plan.max_frag_data % 8, 0);
        assert_eq!(plan.max_frag_data, 1480);
    }

    // --- FragmentPlan::fragment_sizes ---

    #[test]
    fn fragment_sizes_three_fragments() {
        let plan = FragmentPlan::new(20, 1500, 3000);
        // First: UDP header (8) + 1472 payload bytes
        assert_eq!(plan.fragment_sizes(0, 0, 3000), (1480, 1472));
        // Middle: full max_frag_data
        assert_eq!(plan.fragment_sizes(1, 1472, 3000), (1480, 1480));
        // Last: remainder
        assert_eq!(plan.fragment_sizes(2, 2952, 3000), (48, 48));
    }

    #[test]
    fn fragment_sizes_two_fragments() {
        let plan = FragmentPlan::new(20, 1500, 1473);
        assert_eq!(plan.fragment_sizes(0, 0, 1473), (1480, 1472));
        // Last fragment: 1 byte remainder
        assert_eq!(plan.fragment_sizes(1, 1472, 1473), (1, 1));
    }

    #[test]
    fn fragment_plan_large_payload() {
        // Large payload: 64KB over IPv4
        let plan = FragmentPlan::new(20, 1500, 65000);
        assert_eq!(plan.max_frag_data, 1480);
        assert_eq!(plan.first_chunk, 1472);
        // remaining = 65000 - 1472 = 63528, subsequent = ceil(63528/1480) = 43
        assert_eq!(plan.num_frames, 44);
    }
}
