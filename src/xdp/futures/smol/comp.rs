use std::{
    ops::{Deref, DerefMut},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use async_io::Async;
use futures_core::ready;

use crate::xdp::{error::Result, frame::FrameBuffer, umem::CompletionQueue};

use super::SmolFd;

pub struct SmolCompletionQueue<'umem> {
    inner: CompletionQueue<'umem>,
    async_fd: Arc<Async<SmolFd>>,
}

impl<'umem> SmolCompletionQueue<'umem> {
    pub fn new(completion_queue: CompletionQueue<'umem>, async_fd: Arc<Async<SmolFd>>) -> Self {
        Self {
            inner: completion_queue,
            async_fd,
        }
    }

    #[inline(always)]
    pub fn process_queue<'que, B: FrameBuffer<'umem>>(
        &'que mut self,
        batch: B,
    ) -> SmolCompFuture<'que, 'umem, B> {
        SmolCompFuture {
            completion_queue: self,
            batch,
        }
    }
}

impl<'umem> Deref for SmolCompletionQueue<'umem> {
    type Target = CompletionQueue<'umem>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'umem> DerefMut for SmolCompletionQueue<'umem> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

pub struct SmolCompFuture<'que, 'umem, B: FrameBuffer<'umem>> {
    completion_queue: &'que mut SmolCompletionQueue<'umem>,
    batch: B,
}

impl<'que, 'umem, B: FrameBuffer<'umem>> Future for SmolCompFuture<'que, 'umem, B> {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: We guarantee not to move self, just access its fields.
        // Those accesses are also guaranteed to not move self or the fields themselves.
        let this = unsafe { self.get_unchecked_mut() };

        if let Ok(_) = this.completion_queue.inner.process_queue(&mut this.batch) {
            return Poll::Ready(Ok(()));
        }

        let SmolCompletionQueue { inner, async_fd } = this.completion_queue;
        loop {
            ready!(async_fd.poll_readable(cx))?;

            if let Ok(_) = inner.process_queue(&mut this.batch) {
                return Poll::Ready(Ok(()));
            }
        }
    }
}
