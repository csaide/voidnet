use std::{
    collections::{
        VecDeque,
        vec_deque::{Drain, Iter, IterMut},
    },
    ops::RangeBounds,
};

use super::{Frame, FrameBuffer};

pub struct LocalFrameBuffer {
    frames: VecDeque<Frame>,
    free_space: usize,
    num_frames: usize,
}

impl LocalFrameBuffer {
    pub fn new(num_frames: usize) -> Self {
        Self {
            frames: VecDeque::with_capacity(num_frames),
            free_space: num_frames,
            num_frames: 0,
        }
    }

    pub fn drain<R: RangeBounds<usize>>(&mut self, range: R) -> Drain<'_, Frame> {
        let drained = self.frames.drain(range);
        self.free_space += drained.len();
        self.num_frames -= drained.len();
        drained
    }
}

impl FrameBuffer for LocalFrameBuffer {
    type Drain<'a> = Drain<'a, Frame>;
    type IterMut<'a> = IterMut<'a, Frame>;
    type Iter<'a> = Iter<'a, Frame>;

    fn free_space(&self) -> usize {
        self.free_space
    }

    fn num_frames(&self) -> usize {
        self.num_frames
    }

    fn push(&mut self, frame: Frame) {
        self.free_space -= 1;
        self.num_frames += 1;
        self.frames.push_back(frame);
    }

    fn take_frames(&mut self) -> Self::Drain<'_> {
        self.drain(..)
    }

    fn iter_mut(&mut self) -> Self::IterMut<'_> {
        self.frames.iter_mut()
    }

    fn iter(&self) -> Self::Iter<'_> {
        self.frames.iter()
    }
}

impl FromIterator<Frame> for LocalFrameBuffer {
    fn from_iter<T: IntoIterator<Item = Frame>>(iter: T) -> Self {
        let frames: VecDeque<Frame> = iter.into_iter().collect();
        let free_space = frames.capacity() - frames.len();
        let num_frames = frames.len();
        Self {
            frames,
            free_space,
            num_frames,
        }
    }
}

impl Extend<Frame> for LocalFrameBuffer {
    fn extend<T: IntoIterator<Item = Frame>>(&mut self, iter: T) {
        let frames: VecDeque<Frame> = iter.into_iter().collect();
        self.free_space += frames.capacity() - frames.len();
        self.num_frames += frames.len();
        self.frames.extend(frames);
    }
}
