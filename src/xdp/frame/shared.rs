use std::{
    cell::UnsafeCell,
    collections::vec_deque::{Drain, Iter, IterMut},
    ops::RangeBounds,
    rc::Rc,
};

use crate::xdp::frame::{BasicFrameBuffer, FrameBuffer};

use super::Frame;

#[derive(Debug)]
pub struct SharedFrameBuffer<'umem> {
    inner: Rc<UnsafeCell<BasicFrameBuffer<'umem>>>,
}

impl<'umem> SharedFrameBuffer<'umem> {
    #[inline(always)]
    pub fn drain<R: RangeBounds<usize>>(&self, range: R) -> Drain<'_, Frame<'umem>> {
        unsafe {
            let inner = &mut *self.inner.get();
            inner.drain(range)
        }
    }
}

impl<'umem> From<BasicFrameBuffer<'umem>> for SharedFrameBuffer<'umem> {
    fn from(inner: BasicFrameBuffer<'umem>) -> Self {
        Self {
            inner: Rc::new(UnsafeCell::new(inner)),
        }
    }
}

impl<'umem> Clone for SharedFrameBuffer<'umem> {
    fn clone(&self) -> Self {
        Self {
            inner: Rc::clone(&self.inner),
        }
    }
}

impl<'umem> FrameBuffer<'umem> for SharedFrameBuffer<'umem> {
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

    #[inline(always)]
    fn free_space(&self) -> usize {
        unsafe {
            let inner = &mut *self.inner.get();
            inner.free_space()
        }
    }

    #[inline(always)]
    fn num_frames(&self) -> usize {
        unsafe {
            let inner = &mut *self.inner.get();
            inner.num_frames()
        }
    }

    #[inline(always)]
    fn push(&mut self, frame: Frame<'umem>) {
        unsafe {
            let inner = &mut *self.inner.get();
            inner.push(frame);
        }
    }

    #[inline(always)]
    fn pop(&mut self) -> Option<Frame<'umem>> {
        unsafe {
            let inner = &mut *self.inner.get();
            inner.pop()
        }
    }

    #[inline(always)]
    fn take_frames(&mut self) -> <BasicFrameBuffer<'umem> as FrameBuffer<'umem>>::Drain<'_> {
        unsafe {
            let inner = &mut *self.inner.get();
            inner.take_frames()
        }
    }

    #[inline(always)]
    fn iter_frames(&self) -> <BasicFrameBuffer<'umem> as FrameBuffer<'umem>>::Iter<'_> {
        unsafe {
            let inner = &*self.inner.get();
            inner.iter_frames()
        }
    }

    #[inline(always)]
    fn iter_frames_mut(&mut self) -> <BasicFrameBuffer<'umem> as FrameBuffer<'umem>>::IterMut<'_> {
        unsafe {
            let inner = &mut *self.inner.get();
            inner.iter_frames_mut()
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

    #[test]
    fn from_basic_frame_buffer() {
        let basic = BasicFrameBuffer::new(8);
        let shared = SharedFrameBuffer::from(basic);
        assert_eq!(shared.num_frames(), 0);
        assert_eq!(shared.free_space(), 8);
    }

    #[test]
    fn push_and_pop() {
        let basic = BasicFrameBuffer::new(8);
        let mut shared = SharedFrameBuffer::from(basic);
        let mut buf = [0u8; 64];
        buf[0] = 0xAA;
        shared.push(make_frame(&mut buf, 10));
        assert_eq!(shared.num_frames(), 1);
        let frame = shared.pop().unwrap();
        assert_eq!(frame[0], 0xAA);
        assert_eq!(shared.num_frames(), 0);
    }

    #[test]
    fn pop_empty_returns_none() {
        let basic = BasicFrameBuffer::new(8);
        let mut shared = SharedFrameBuffer::from(basic);
        assert!(shared.pop().is_none());
    }

    #[test]
    fn clone_shares_inner() {
        let basic = BasicFrameBuffer::new(8);
        let mut shared = SharedFrameBuffer::from(basic);
        let cloned = shared.clone();
        let mut buf = [0u8; 64];
        shared.push(make_frame(&mut buf, 10));
        assert_eq!(cloned.num_frames(), 1);
    }

    #[test]
    fn free_space_decreases_on_push() {
        let basic = BasicFrameBuffer::new(4);
        let mut shared = SharedFrameBuffer::from(basic);
        assert_eq!(shared.free_space(), 4);
        let mut buf = [0u8; 64];
        shared.push(make_frame(&mut buf, 10));
        assert_eq!(shared.free_space(), 3);
    }

    #[test]
    fn take_frames_drains_all() {
        let basic = BasicFrameBuffer::new(8);
        let mut shared = SharedFrameBuffer::from(basic);
        let mut bufs = [[0u8; 64]; 3];
        for buf in bufs.iter_mut() {
            shared.push(make_frame(buf, 10));
        }
        assert_eq!(shared.num_frames(), 3);
        let taken: Vec<_> = shared.take_frames().collect();
        assert_eq!(taken.len(), 3);
        assert_eq!(shared.num_frames(), 0);
    }

    #[test]
    fn iter_frames_borrows() {
        let basic = BasicFrameBuffer::new(8);
        let mut shared = SharedFrameBuffer::from(basic);
        let mut bufs = [[0u8; 64]; 2];
        bufs[0][0] = 0x01;
        bufs[1][0] = 0x02;
        for buf in bufs.iter_mut() {
            shared.push(make_frame(buf, 10));
        }
        let collected: Vec<_> = shared.iter_frames().collect();
        assert_eq!(collected.len(), 2);
        assert_eq!(collected[0][0], 0x01);
        assert_eq!(collected[1][0], 0x02);
    }

    #[test]
    fn iter_frames_mut_allows_mutation() {
        let basic = BasicFrameBuffer::new(8);
        let mut shared = SharedFrameBuffer::from(basic);
        let mut buf = [0u8; 64];
        shared.push(make_frame(&mut buf, 10));
        for frame in shared.iter_frames_mut() {
            frame[0] = 0xFF;
        }
        let frame = shared.iter_frames().next().unwrap();
        assert_eq!(frame[0], 0xFF);
    }

    #[test]
    fn drain_range() {
        let basic = BasicFrameBuffer::new(8);
        let mut shared = SharedFrameBuffer::from(basic);
        let mut bufs = [[0u8; 64]; 3];
        for (i, buf) in bufs.iter_mut().enumerate() {
            buf[0] = i as u8;
            shared.push(make_frame(buf, 10));
        }
        let drained: Vec<_> = shared.drain(0..2).collect();
        assert_eq!(drained.len(), 2);
        assert_eq!(shared.num_frames(), 1);
    }
}
