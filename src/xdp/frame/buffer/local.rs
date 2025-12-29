use std::{
    collections::{
        VecDeque,
        vec_deque::{Drain, IterMut},
    },
    ops::{Deref, DerefMut},
};

use super::{Frame, FrameBuffer};

pub struct LocalFrameBuffer {
    frames: VecDeque<Frame>,
    free_space: usize,
}

impl LocalFrameBuffer {
    pub fn new(num_frames: usize) -> Self {
        Self {
            frames: VecDeque::with_capacity(num_frames),
            free_space: num_frames,
        }
    }

    pub fn push(&mut self, frame: Frame) {
        self.frames.push_back(frame);
        self.free_space -= 1;
    }

    pub fn pop(&mut self) -> Option<Frame> {
        self.free_space += 1;
        self.frames.pop_front()
    }
}

impl FrameBuffer for LocalFrameBuffer {
    type Drain<'a> = Drain<'a, Frame>;
    type IterMut<'a> = IterMut<'a, Frame>;

    fn free_space(&self) -> usize {
        self.free_space
    }

    fn num_frames(&self) -> usize {
        self.frames.len()
    }

    fn push(&mut self, frame: Frame) {
        self.frames.push_back(frame);
    }

    fn drain(&mut self) -> Self::Drain<'_> {
        self.free_space = self.frames.capacity();
        self.frames.drain(..)
    }

    fn iter_mut(&mut self) -> Self::IterMut<'_> {
        self.frames.iter_mut()
    }
}

impl FromIterator<Frame> for LocalFrameBuffer {
    fn from_iter<T: IntoIterator<Item = Frame>>(iter: T) -> Self {
        Self {
            frames: iter.into_iter().collect(),
            free_space: 0,
        }
    }
}

impl Deref for LocalFrameBuffer {
    type Target = VecDeque<Frame>;

    fn deref(&self) -> &Self::Target {
        &self.frames
    }
}

impl DerefMut for LocalFrameBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.frames
    }
}
