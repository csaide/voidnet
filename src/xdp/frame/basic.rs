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
        let free_space = frames.capacity() - frames.len();
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
