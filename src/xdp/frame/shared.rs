use std::{
    cell::UnsafeCell,
    collections::vec_deque::{Drain, Iter, IterMut},
    ops::RangeBounds,
    rc::Rc,
};

use crate::xdp::frame::{BasicFrameBuffer, FrameBuffer};

use super::Frame;

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
