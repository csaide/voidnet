use std::sync::MutexGuard;

use super::Frame;

pub trait FrameBuffer {
    type Drain<'a>: Iterator<Item = Frame>
    where
        Self: 'a;

    type IterMut<'a>: Iterator<Item = &'a mut Frame>
    where
        Self: 'a;

    fn free_space(&self) -> usize;
    fn num_frames(&self) -> usize;
    fn push(&mut self, frame: Frame);
    fn drain(&mut self) -> Self::Drain<'_>;
    fn iter_mut(&mut self) -> Self::IterMut<'_>;
}

impl<B: FrameBuffer> FrameBuffer for &mut B {
    type Drain<'a>
        = B::Drain<'a>
    where
        Self: 'a;

    type IterMut<'a>
        = B::IterMut<'a>
    where
        Self: 'a;

    #[inline(always)]
    fn free_space(&self) -> usize {
        B::free_space(self)
    }

    #[inline(always)]
    fn num_frames(&self) -> usize {
        B::num_frames(self)
    }

    #[inline(always)]
    fn push(&mut self, frame: Frame) {
        B::push(self, frame)
    }

    #[inline(always)]
    fn drain(&mut self) -> Self::Drain<'_> {
        B::drain(self)
    }

    #[inline(always)]
    fn iter_mut(&mut self) -> Self::IterMut<'_> {
        B::iter_mut(self)
    }
}

impl<B: FrameBuffer> FrameBuffer for MutexGuard<'_, B> {
    type Drain<'a>
        = B::Drain<'a>
    where
        Self: 'a;

    type IterMut<'a>
        = B::IterMut<'a>
    where
        Self: 'a;

    #[inline(always)]
    fn free_space(&self) -> usize {
        B::free_space(&*self)
    }

    #[inline(always)]
    fn num_frames(&self) -> usize {
        B::num_frames(&*self)
    }

    #[inline(always)]
    fn push(&mut self, frame: Frame) {
        B::push(&mut *self, frame)
    }

    #[inline(always)]
    fn drain(&mut self) -> Self::Drain<'_> {
        B::drain(&mut *self)
    }

    #[inline(always)]
    fn iter_mut(&mut self) -> Self::IterMut<'_> {
        B::iter_mut(&mut *self)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use crate::xdp::frame::buffer::local::LocalFrameBuffer;

    use super::*;

    #[test]
    fn test_mutex_vec() {
        let buffer = Arc::new(Mutex::new(LocalFrameBuffer::new(1)));
        let mut guard = buffer.lock().unwrap();

        FrameBuffer::push(&mut guard, unsafe {
            Frame::new(0, std::ptr::null_mut(), 0, 0, false)
        });
        let drain = FrameBuffer::drain(&mut guard);
        let frames: LocalFrameBuffer = drain.collect();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].addr(), 0);
        assert_eq!(frames[0].len(), 0);
        assert_eq!(frames[0].capacity(), 0);
        assert_eq!(frames[0].is_fragment(), false);
    }
}
