use crate::xdp::frame::{Frame, FrameBuffer};

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

    /// Returns true if the packet is empty.
    ///
    /// Note for fragmented packets this iterates over the entire packet use sparingly.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns a borrowing iterator over the frames in this packet.
    pub fn frames(&self) -> PacketFrameIter<'_, 'umem> {
        match self {
            Packet::Empty => PacketFrameIter::Empty,
            Packet::Single(frame) => PacketFrameIter::Single(std::iter::once(frame)),
            Packet::Multi(frames) => PacketFrameIter::Multi(frames.iter()),
        }
    }

    /// Returns a mutable borrowing iterator over the frames in this packet.
    pub fn frames_mut(&mut self) -> PacketFrameIterMut<'_, 'umem> {
        match self {
            Packet::Empty => PacketFrameIterMut::Empty,
            Packet::Single(frame) => PacketFrameIterMut::Single(std::iter::once(frame)),
            Packet::Multi(frames) => PacketFrameIterMut::Multi(frames.iter_mut()),
        }
    }

    /// Consume this packet, pushing all frames into `buf`.
    pub fn drain_to(self, buf: &mut impl FrameBuffer<'umem>) {
        for frame in self.into_frames() {
            buf.push(frame);
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
            Packet::Empty
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

/// Mutable borrowing iterator over frames in a [`Packet`].
pub enum PacketFrameIterMut<'a, 'umem> {
    Empty,
    Single(std::iter::Once<&'a mut Frame<'umem>>),
    Multi(std::slice::IterMut<'a, Frame<'umem>>),
}

impl<'a, 'umem> Iterator for PacketFrameIterMut<'a, 'umem> {
    type Item = &'a mut Frame<'umem>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            PacketFrameIterMut::Empty => None,
            PacketFrameIterMut::Single(iter) => iter.next(),
            PacketFrameIterMut::Multi(iter) => iter.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            PacketFrameIterMut::Empty => (0, Some(0)),
            PacketFrameIterMut::Single(iter) => iter.size_hint(),
            PacketFrameIterMut::Multi(iter) => iter.size_hint(),
        }
    }
}

impl<'a, 'umem> ExactSizeIterator for PacketFrameIterMut<'a, 'umem> {}

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

#[cfg(test)]
mod tests {
    use crate::xdp::frame::Frame;

    use super::*;

    fn make_frame(buf: &mut [u8], len: usize) -> Frame<'_> {
        Frame::new(0, buf, len, false)
    }

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

    #[test]
    fn frames_mut_single() {
        let mut buf = [0u8; 64];
        buf[0] = 0xAA;
        let mut pkt = Packet::Single(make_frame(&mut buf, 10));
        for frame in pkt.frames_mut() {
            frame[0] = 0xBB;
        }
        let collected: Vec<_> = pkt.frames().collect();
        assert_eq!(collected[0][0], 0xBB);
    }

    #[test]
    fn frames_mut_multi() {
        let mut bufs = [[0u8; 64]; 3];
        for (i, b) in bufs.iter_mut().enumerate() {
            b[0] = i as u8;
        }
        let frames: Vec<_> = bufs.iter_mut().map(|b| make_frame(b, 10)).collect();
        let mut pkt = Packet::Multi(frames);
        for frame in pkt.frames_mut() {
            frame[0] += 10;
        }
        let collected: Vec<_> = pkt.frames().collect();
        for (i, f) in collected.iter().enumerate() {
            assert_eq!(f[0], (i as u8) + 10);
        }
    }

    #[test]
    fn frames_mut_exact_size() {
        let mut buf = [0u8; 64];
        let mut pkt = Packet::Single(make_frame(&mut buf, 10));
        let iter = pkt.frames_mut();
        assert_eq!(iter.len(), 1);
        assert_eq!(iter.size_hint(), (1, Some(1)));

        let mut bufs = [[0u8; 64]; 3];
        let frames: Vec<_> = bufs.iter_mut().map(|b| make_frame(b, 10)).collect();
        let mut pkt = Packet::Multi(frames);
        let iter = pkt.frames_mut();
        assert_eq!(iter.len(), 3);
        assert_eq!(iter.size_hint(), (3, Some(3)));
    }

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
}
