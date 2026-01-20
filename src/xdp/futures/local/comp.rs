use std::{
    ops::{Deref, DerefMut},
    pin::Pin,
    task::{Context, Poll},
};

use crate::xdp::{error::Result, frame::FrameBuffer, umem::CompletionQueue};

/// A completion queue designed to work on the [LocalExecutor] executor.
///
/// [LocalExecutor]: crate::xdp::futures::local::LocalExecutor
pub struct LocalCompletionQueue<'umem> {
    inner: CompletionQueue<'umem>,
}

impl<'umem> LocalCompletionQueue<'umem> {
    pub(crate) fn new(completion_queue: CompletionQueue<'umem>) -> Result<Self> {
        Ok(Self {
            inner: completion_queue,
        })
    }

    /// Asynchronously processes the completion queue, pushing new frames from the frame stack into the completion ring up to the size of the completion ring.
    #[inline(always)]
    pub fn process_queue<'que, B: FrameBuffer<'umem>>(
        &'que mut self,
        batch: B,
    ) -> LocalCompFuture<'que, 'umem, B> {
        LocalCompFuture {
            completion_queue: self,
            batch,
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

/// A future that asynchronously processes the completion queue, pushing new frames from the frame stack into the completion ring up to the size of the completion ring.
pub struct LocalCompFuture<'que, 'umem, B: FrameBuffer<'umem>> {
    pub(crate) completion_queue: &'que mut LocalCompletionQueue<'umem>,
    pub(crate) batch: B,
}

impl<'que, 'umem, B: FrameBuffer<'umem>> Future for LocalCompFuture<'que, 'umem, B> {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: We guarantee not to move self, just access its fields.
        // Those accesses are also guaranteed to not move self or the fields themselves.
        let this = unsafe { self.get_unchecked_mut() };

        if let Ok(_) = this.completion_queue.inner.process_queue(&mut this.batch) {
            return Poll::Ready(Ok(()));
        }

        Poll::Pending
    }
}
