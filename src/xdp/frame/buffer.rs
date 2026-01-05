use super::Frame;

pub trait FrameBuffer<'umem> {
    /// A consuming iterator that yields frames, it should remove the frames from the buffer and pass ownership of them to the caller.
    type Drain<'a>: Iterator<Item = Frame<'umem>> + ExactSizeIterator
    where
        Self: 'a,
        'umem: 'a;

    /// A non-consuming iterator that yields immutable references to frames, it should not remove the frames from the buffer.
    type Iter<'a>: Iterator<Item = &'a Frame<'umem>> + ExactSizeIterator
    where
        Self: 'a,
        'umem: 'a;

    /// A non-consuming iterator that yields mutable references to frames, it should not remove the frames from the buffer.
    type IterMut<'a>: Iterator<Item = &'a mut Frame<'umem>> + ExactSizeIterator
    where
        Self: 'a,
        'umem: 'a;

    /// Returns the number of free slots in the buffer, while its not a technical requirement to never grow, the entire XDP subsystem will honor this value as a maximum number
    /// of frames that can be pushed into the buffer. It is important for performance that this is accurate and ensure that if the caluclation is expensive to cache the result appropriately.
    fn free_space(&self) -> usize;

    /// Returns the number of frames in the buffer, this is the number of frames that have been pushed into the buffer and are still in it.
    fn num_frames(&self) -> usize;

    /// Pushes a frame into the buffer, note again that the XDP subsystem will use free_space above to determine how many frames to push this should be infalible in every way.
    fn push(&mut self, frame: Frame<'umem>);

    /// Drain all frames from the buffer and pass off ownership to the caller, this is used to take the frames and pass them off to the kernel.
    fn take_frames(&mut self) -> Self::Drain<'_>;

    /// Iterate over all the frames in the buffer mutably.
    fn iter_frames(&self) -> Self::Iter<'_>;

    /// Iterate over all the frames in the buffer immutably.
    fn iter_frames_mut(&mut self) -> Self::IterMut<'_>;
}

impl<'umem, B: FrameBuffer<'umem>> FrameBuffer<'umem> for &mut B {
    type Drain<'a>
        = B::Drain<'a>
    where
        Self: 'a,
        'umem: 'a;

    type Iter<'a>
        = B::Iter<'a>
    where
        Self: 'a,
        'umem: 'a;

    type IterMut<'a>
        = B::IterMut<'a>
    where
        Self: 'a,
        'umem: 'a;

    #[inline(always)]
    fn free_space(&self) -> usize {
        B::free_space(self)
    }

    #[inline(always)]
    fn num_frames(&self) -> usize {
        B::num_frames(self)
    }

    #[inline(always)]
    fn push(&mut self, frame: Frame<'umem>) {
        B::push(self, frame)
    }

    #[inline(always)]
    fn take_frames(&mut self) -> Self::Drain<'_> {
        B::take_frames(self)
    }

    #[inline(always)]
    fn iter_frames(&self) -> Self::Iter<'_> {
        B::iter_frames(self)
    }

    #[inline(always)]
    fn iter_frames_mut(&mut self) -> Self::IterMut<'_> {
        B::iter_frames_mut(self)
    }
}

impl<'umem, B: FrameBuffer<'umem>> FrameBuffer<'umem> for std::sync::MutexGuard<'_, B> {
    type Drain<'a>
        = B::Drain<'a>
    where
        Self: 'a,
        'umem: 'a;

    type Iter<'a>
        = B::Iter<'a>
    where
        Self: 'a,
        'umem: 'a;

    type IterMut<'a>
        = B::IterMut<'a>
    where
        Self: 'a,
        'umem: 'a;

    #[inline(always)]
    fn free_space(&self) -> usize {
        B::free_space(&*self)
    }

    #[inline(always)]
    fn num_frames(&self) -> usize {
        B::num_frames(&*self)
    }

    #[inline(always)]
    fn push(&mut self, frame: Frame<'umem>) {
        B::push(&mut *self, frame)
    }

    #[inline(always)]
    fn take_frames(&mut self) -> Self::Drain<'_> {
        B::take_frames(&mut *self)
    }

    #[inline(always)]
    fn iter_frames(&self) -> Self::Iter<'_> {
        B::iter_frames(&*self)
    }

    #[inline(always)]
    fn iter_frames_mut(&mut self) -> Self::IterMut<'_> {
        B::iter_frames_mut(&mut *self)
    }
}

impl<'umem, B: FrameBuffer<'umem>> FrameBuffer<'umem> for futures::lock::MutexGuard<'_, B> {
    type Drain<'a>
        = B::Drain<'a>
    where
        Self: 'a,
        'umem: 'a;

    type Iter<'a>
        = B::Iter<'a>
    where
        Self: 'a,
        'umem: 'a;

    type IterMut<'a>
        = B::IterMut<'a>
    where
        Self: 'a,
        'umem: 'a;

    #[inline(always)]
    fn free_space(&self) -> usize {
        B::free_space(&*self)
    }

    #[inline(always)]
    fn num_frames(&self) -> usize {
        B::num_frames(&*self)
    }

    #[inline(always)]
    fn push(&mut self, frame: Frame<'umem>) {
        B::push(&mut *self, frame)
    }

    #[inline(always)]
    fn take_frames(&mut self) -> Self::Drain<'_> {
        B::take_frames(&mut *self)
    }

    #[inline(always)]
    fn iter_frames(&self) -> Self::Iter<'_> {
        B::iter_frames(&*self)
    }

    #[inline(always)]
    fn iter_frames_mut(&mut self) -> Self::IterMut<'_> {
        B::iter_frames_mut(&mut *self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::collections::vec_deque::{Drain, Iter, IterMut};

    struct MockFrameBuffer<'umem> {
        frames: VecDeque<Frame<'umem>>,
        capacity: usize,
    }

    impl<'umem> MockFrameBuffer<'umem> {
        fn new(capacity: usize) -> Self {
            Self {
                frames: VecDeque::with_capacity(capacity),
                capacity,
            }
        }
    }

    impl<'umem> FrameBuffer<'umem> for MockFrameBuffer<'umem> {
        type Drain<'a>
            = Drain<'a, Frame<'umem>>
        where
            Self: 'a,
            'umem: 'a;
        type Iter<'a>
            = Iter<'a, Frame<'umem>>
        where
            Self: 'a,
            'umem: 'a;
        type IterMut<'a>
            = IterMut<'a, Frame<'umem>>
        where
            Self: 'a,
            'umem: 'a;

        fn free_space(&self) -> usize {
            self.capacity - self.frames.len()
        }

        fn num_frames(&self) -> usize {
            self.frames.len()
        }

        fn push(&mut self, frame: Frame<'umem>) {
            self.frames.push_back(frame);
        }

        fn take_frames(&mut self) -> Self::Drain<'_> {
            self.frames.drain(..)
        }

        fn iter_frames(&self) -> Self::Iter<'_> {
            self.frames.iter()
        }

        fn iter_frames_mut(&mut self) -> Self::IterMut<'_> {
            self.frames.iter_mut()
        }
    }

    fn test_buffer_logic<'umem, B: FrameBuffer<'umem>>(mut buffer: B, data: &'umem mut [u8]) {
        assert_eq!(buffer.num_frames(), 0);
        assert_eq!(buffer.free_space(), 10);

        let frame = Frame::new(1, data, 10, false);
        buffer.push(frame);

        assert_eq!(buffer.num_frames(), 1);
        assert_eq!(buffer.free_space(), 9);

        for f in buffer.iter_frames() {
            assert_eq!(f.addr(), 1);
        }

        for f in buffer.iter_frames_mut() {
            f.set_fragment(true);
        }

        assert!(buffer.iter_frames().next().unwrap().is_fragment());

        let drained: Vec<_> = buffer.take_frames().collect();
        assert_eq!(drained.len(), 1);
        assert_eq!(buffer.num_frames(), 0);
    }

    #[test]
    fn test_mut_ref_wrapper() {
        let mut mock = MockFrameBuffer::new(10);
        let mut data = vec![0u8; 10];
        test_buffer_logic(&mut mock, &mut data);
    }

    #[test]
    fn test_std_mutex_wrapper() {
        let mock = std::sync::Mutex::new(MockFrameBuffer::new(10));
        let guard = mock.lock().unwrap();
        let mut data = vec![0u8; 10];
        test_buffer_logic(guard, &mut data);
    }

    #[test]
    fn test_futures_mutex_wrapper() {
        let mock = futures::lock::Mutex::new(MockFrameBuffer::new(10));
        let guard = futures::executor::block_on(mock.lock());
        let mut data = vec![0u8; 10];
        test_buffer_logic(guard, &mut data);
    }
}
