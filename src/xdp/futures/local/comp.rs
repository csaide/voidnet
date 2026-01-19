use std::{
    ops::{Deref, DerefMut},
    pin::Pin,
    task::{Context, Poll},
};

use crate::xdp::{error::Result, frame::FrameBuffer, umem::CompletionQueue};

pub struct LocalCompletionQueue<'umem> {
    inner: CompletionQueue<'umem>,
}

impl<'umem> LocalCompletionQueue<'umem> {
    pub fn new(completion_queue: CompletionQueue<'umem>) -> Result<Self> {
        Ok(Self {
            inner: completion_queue,
        })
    }

    #[inline(always)]
    pub fn process_queue<'que, B: FrameBuffer<'umem>>(
        &'que mut self,
        batch: B,
        expected: usize,
    ) -> LocalCompFuture<'que, 'umem, B> {
        LocalCompFuture {
            completion_queue: self,
            batch,
            expected,
        }
    }
}

impl<'umem> Deref for LocalCompletionQueue<'umem> {
    type Target = CompletionQueue<'umem>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'umem> DerefMut for LocalCompletionQueue<'umem> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

pub struct LocalCompFuture<'que, 'umem, B: FrameBuffer<'umem>> {
    pub(crate) completion_queue: &'que mut LocalCompletionQueue<'umem>,
    pub(crate) batch: B,
    pub(crate) expected: usize,
}

impl<'que, 'umem, B: FrameBuffer<'umem>> Future for LocalCompFuture<'que, 'umem, B> {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: We guarantee not to move self, just access its fields.
        // Those accesses are also guaranteed to not move self or the fields themselves.
        let this = unsafe { self.get_unchecked_mut() };

        this.completion_queue.inner.process_queue(&mut this.batch);
        if this.batch.num_frames() >= this.expected {
            return Poll::Ready(Ok(()));
        }

        Poll::Pending
    }
}
