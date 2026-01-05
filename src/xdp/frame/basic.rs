use std::{
    collections::{
        VecDeque,
        vec_deque::{Drain, Iter, IterMut},
    },
    ops::RangeBounds,
};

use super::{Frame, FrameBuffer};

pub struct BasicFrameBuffer<'umem> {
    frames: VecDeque<Frame<'umem>>,
    free_space: usize,
    num_frames: usize,
}

impl<'umem> BasicFrameBuffer<'umem> {
    pub fn new(num_frames: usize) -> Self {
        Self {
            frames: VecDeque::with_capacity(num_frames),
            free_space: num_frames,
            num_frames: 0,
        }
    }

    pub fn drain<R: RangeBounds<usize>>(&mut self, range: R) -> Drain<'_, Frame<'umem>> {
        let drained = self.frames.drain(range);
        self.free_space += drained.len();
        self.num_frames -= drained.len();
        drained
    }
}

impl<'umem> FrameBuffer<'umem> for BasicFrameBuffer<'umem> {
    type Drain<'a>
        = Drain<'a, Frame<'umem>>
    where
        Self: 'a,
        'umem: 'a;

    type IterMut<'a>
        = IterMut<'a, Frame<'umem>>
    where
        Self: 'a,
        'umem: 'a;

    type Iter<'a>
        = Iter<'a, Frame<'umem>>
    where
        Self: 'a,
        'umem: 'a;

    fn free_space(&self) -> usize {
        self.free_space
    }

    fn num_frames(&self) -> usize {
        self.num_frames
    }

    fn push(&mut self, frame: Frame<'umem>) {
        self.free_space -= 1;
        self.num_frames += 1;
        self.frames.push_back(frame);
    }

    fn take_frames(&mut self) -> Self::Drain<'_> {
        self.drain(..)
    }

    fn iter_frames(&self) -> Self::Iter<'_> {
        self.frames.iter()
    }

    fn iter_frames_mut(&mut self) -> Self::IterMut<'_> {
        self.frames.iter_mut()
    }
}

impl<'umem> FromIterator<Frame<'umem>> for BasicFrameBuffer<'umem> {
    fn from_iter<T: IntoIterator<Item = Frame<'umem>>>(iter: T) -> Self {
        let frames: VecDeque<Frame<'umem>> = iter.into_iter().collect();
        let free_space = 0;
        let num_frames = frames.len();
        Self {
            frames,
            free_space,
            num_frames,
        }
    }
}

impl<'umem> Extend<Frame<'umem>> for BasicFrameBuffer<'umem> {
    fn extend<T: IntoIterator<Item = Frame<'umem>>>(&mut self, iter: T) {
        let frames: VecDeque<Frame<'umem>> = iter.into_iter().collect();
        debug_assert!(
            self.free_space >= frames.len(),
            "free space is less than the number of frames to extend"
        );

        self.free_space -= frames.len();
        self.num_frames += frames.len();
        self.frames.extend(frames);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_frame_buffer_new() {
        let buffer = BasicFrameBuffer::new(10);
        assert_eq!(buffer.free_space(), 10);
        assert_eq!(buffer.num_frames(), 0);
        assert_eq!(buffer.iter_frames().count(), 0);
    }

    #[test]
    fn test_basic_frame_buffer_push() {
        let mut buffer = BasicFrameBuffer::new(5);
        let mut data1 = [1u8; 10];
        let mut data2 = [2u8; 10];

        let frame1 = Frame::new(100, &mut data1, 10, false);
        let frame2 = Frame::new(200, &mut data2, 10, true);

        buffer.push(frame1);
        assert_eq!(buffer.num_frames(), 1);
        assert_eq!(buffer.free_space(), 4);

        buffer.push(frame2);
        assert_eq!(buffer.num_frames(), 2);
        assert_eq!(buffer.free_space(), 3);

        let frames: Vec<_> = buffer.iter_frames().collect();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].addr(), 100);
        assert_eq!(frames[1].addr(), 200);
        assert!(frames[1].is_fragment());
    }

    #[test]
    fn test_basic_frame_buffer_drain() {
        let mut buffer = BasicFrameBuffer::new(5);
        let mut data0 = [0u8; 10];
        let mut data1 = [0u8; 10];
        let mut data2 = [0u8; 10];

        buffer.push(Frame::new(0, &mut data0, 10, false));
        buffer.push(Frame::new(1, &mut data1, 10, false));
        buffer.push(Frame::new(2, &mut data2, 10, false));

        assert_eq!(buffer.num_frames(), 3);
        assert_eq!(buffer.free_space(), 2);

        {
            let mut drained = buffer.drain(0..1);
            assert_eq!(drained.len(), 1);
            let frame = drained.next().unwrap();
            assert_eq!(frame.addr(), 0);
        }

        assert_eq!(buffer.num_frames(), 2);
        assert_eq!(buffer.free_space(), 3);

        let remaining_addrs: Vec<_> = buffer.iter_frames().map(|f| f.addr()).collect();
        assert_eq!(remaining_addrs, vec![1, 2]);
    }

    #[test]
    fn test_basic_frame_buffer_take_frames() {
        let mut buffer = BasicFrameBuffer::new(5);
        let mut data0 = [0u8; 10];
        let mut data1 = [0u8; 10];

        buffer.push(Frame::new(0, &mut data0, 10, false));
        buffer.push(Frame::new(1, &mut data1, 10, false));

        let drained: Vec<_> = buffer.take_frames().collect();
        assert_eq!(drained.len(), 2);
        assert_eq!(buffer.num_frames(), 0);
        assert_eq!(buffer.free_space(), 5);
    }

    #[test]
    fn test_basic_frame_buffer_iter_mut() {
        let mut buffer = BasicFrameBuffer::new(5);
        let mut data = [0u8; 10];
        buffer.push(Frame::new(1, &mut data, 10, false));

        for frame in buffer.iter_frames_mut() {
            frame.set_fragment(true);
        }

        assert!(buffer.iter_frames().next().unwrap().is_fragment());
    }

    #[test]
    fn test_basic_frame_buffer_from_iter() {
        let mut data0 = [0u8; 10];
        let mut data1 = [0u8; 10];
        let frames = vec![
            Frame::new(1, &mut data0, 10, false),
            Frame::new(2, &mut data1, 10, false),
        ];

        let buffer = BasicFrameBuffer::from_iter(frames);
        assert_eq!(buffer.num_frames(), 2);
        assert_eq!(buffer.free_space(), 0);
    }

    #[test]
    fn test_basic_frame_buffer_extend() {
        let mut buffer = BasicFrameBuffer::new(10);
        let mut data0 = [0u8; 10];
        let mut data1 = [0u8; 10];
        let frames = vec![
            Frame::new(1, &mut data0, 10, false),
            Frame::new(2, &mut data1, 10, false),
        ];

        buffer.extend(frames);
        assert_eq!(buffer.num_frames(), 2);
        assert_eq!(buffer.free_space(), 8);
    }
}
