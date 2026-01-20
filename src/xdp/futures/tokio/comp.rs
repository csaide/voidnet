use std::{
    ops::{Deref, DerefMut},
    os::fd::RawFd,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures_core::ready;
use tokio::io::{Ready, unix::AsyncFd};

use crate::xdp::{error::Result, frame::FrameBuffer, umem::CompletionQueue};

/// A completion queue designed to work on the [Tokio] runtime.
///
/// [Tokio]: tokio
pub struct TokioCompletionQueue<'umem> {
    inner: CompletionQueue<'umem>,
    async_fd: Arc<AsyncFd<RawFd>>,
}

impl<'umem> TokioCompletionQueue<'umem> {
    pub(crate) fn new(
        completion_queue: CompletionQueue<'umem>,
        async_fd: Arc<AsyncFd<RawFd>>,
    ) -> Self {
        Self {
            inner: completion_queue,
            async_fd,
        }
    }

    /// Asynchronously processes the completion queue, pushing new frames from the frame stack into the completion ring up to the size of the completion ring.
    #[inline(always)]
    pub fn process_queue<'que, B: FrameBuffer<'umem>>(
        &'que mut self,
        batch: B,
    ) -> TokioCompFuture<'que, 'umem, B> {
        TokioCompFuture {
            completion_queue: self,
            batch,
        }
    }
}

impl<'umem> Deref for TokioCompletionQueue<'umem> {
    type Target = CompletionQueue<'umem>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'umem> DerefMut for TokioCompletionQueue<'umem> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

/// A future that asynchronously processes the completion queue, pushing new frames from the frame stack into the completion ring up to the size of the completion ring.
pub struct TokioCompFuture<'que, 'umem, B: FrameBuffer<'umem>> {
    completion_queue: &'que mut TokioCompletionQueue<'umem>,
    batch: B,
}

impl<'que, 'umem, B: FrameBuffer<'umem>> Future for TokioCompFuture<'que, 'umem, B> {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: We guarantee not to move self, just access its fields.
        // Those accesses are also guaranteed to not move self or the fields themselves.
        let this = unsafe { self.get_unchecked_mut() };

        if let Ok(_) = this.completion_queue.inner.process_queue(&mut this.batch) {
            return Poll::Ready(Ok(()));
        }

        let TokioCompletionQueue { inner, async_fd } = this.completion_queue;
        loop {
            let mut guard = ready!(async_fd.poll_write_ready(cx))?;

            if let Ok(_) = inner.process_queue(&mut this.batch) {
                return Poll::Ready(Ok(()));
            }

            // We aren't actually ready clear our status and loop again.
            guard.clear_ready_matching(Ready::WRITABLE);
        }
    }
}
