use std::{collections::VecDeque, ops::RangeBounds, sync::MutexGuard};

use super::Frame;

pub trait FrameBuffer {
    type Drain<'a>: Iterator<Item = Frame>
    where
        Self: 'a;

    fn capacity(&self) -> usize;
    fn len(&self) -> usize;
    fn push(&mut self, frame: Frame);
    fn drain<R: RangeBounds<usize>>(&mut self, range: R) -> Self::Drain<'_>;
}

impl<B: FrameBuffer> FrameBuffer for &mut B {
    type Drain<'a>
        = B::Drain<'a>
    where
        Self: 'a;

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
    fn drain<R: RangeBounds<usize>>(&mut self, range: R) -> Self::Drain<'_> {
        B::drain(self, range)
    }
}

impl<B: FrameBuffer> FrameBuffer for MutexGuard<'_, B> {
    type Drain<'a>
        = B::Drain<'a>
    where
        Self: 'a;

    #[inline(always)]
    fn capacity(&self) -> usize {
        B::capacity(&*self)
    }

    #[inline(always)]
    fn len(&self) -> usize {
        B::len(&*self)
    }

    #[inline(always)]
    fn push(&mut self, frame: Frame) {
        B::push(&mut *self, frame)
    }

    #[inline(always)]
    fn drain<R: RangeBounds<usize>>(&mut self, range: R) -> Self::Drain<'_> {
        B::drain(&mut *self, range)
    }
}

impl FrameBuffer for VecDeque<Frame> {
    type Drain<'a>
        = std::collections::vec_deque::Drain<'a, Frame>
    where
        Self: 'a;

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
    fn drain<R: RangeBounds<usize>>(&mut self, range: R) -> Self::Drain<'_> {
        VecDeque::drain(self, range)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[test]
    fn test_mutex_vec() {
        let buffer = Arc::new(Mutex::new(VecDeque::new()));
        let mut guard = buffer.lock().unwrap();

        FrameBuffer::push(&mut guard, unsafe {
            Frame::new(0, std::ptr::null_mut(), 0, 0, false)
        });
        let drain = FrameBuffer::drain(&mut guard, ..1);
        let frames = drain.collect::<VecDeque<_>>();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].addr(), 0);
        assert_eq!(frames[0].len(), 0);
        assert_eq!(frames[0].capacity(), 0);
        assert_eq!(frames[0].is_fragment(), false);
    }
}
