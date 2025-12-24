use std::{collections::VecDeque, ops::RangeBounds};

use super::Frame;

pub trait FrameBuffer {
    fn capacity(&self) -> usize;
    fn len(&self) -> usize;
    fn push(&mut self, frame: Frame);
    fn drain<R: RangeBounds<usize>>(&mut self, range: R) -> impl Iterator<Item = Frame>;
}

impl<B: FrameBuffer> FrameBuffer for &mut B {
    #[inline(always)]
    fn capacity(&self) -> usize {
        B::capacity(self)
    }

    #[inline(always)]
    fn len(&self) -> usize {
        B::len(self)
    }

    #[inline(always)]
    fn push(&mut self, frame: Frame) {
        B::push(self, frame)
    }

    #[inline(always)]
    fn drain<R: RangeBounds<usize>>(&mut self, range: R) -> impl Iterator<Item = Frame> {
        B::drain(self, range)
    }
}

impl FrameBuffer for VecDeque<Frame> {
    #[inline(always)]
    fn capacity(&self) -> usize {
        VecDeque::capacity(self)
    }

    #[inline(always)]
    fn len(&self) -> usize {
        VecDeque::len(self)
    }

    #[inline(always)]
    fn push(&mut self, frame: Frame) {
        VecDeque::push_back(self, frame)
    }

    #[inline(always)]
    fn drain<R: RangeBounds<usize>>(&mut self, range: R) -> impl Iterator<Item = Frame> {
        VecDeque::drain(self, range)
    }
}

impl FrameBuffer for Vec<Frame> {
    #[inline(always)]
    fn capacity(&self) -> usize {
        Vec::capacity(self)
    }

    #[inline(always)]
    fn len(&self) -> usize {
        Vec::len(self)
    }

    #[inline(always)]
    fn push(&mut self, frame: Frame) {
        Vec::push(self, frame)
    }

    #[inline(always)]
    fn drain<R: RangeBounds<usize>>(&mut self, range: R) -> impl Iterator<Item = Frame> {
        Vec::drain(self, range)
    }
}
