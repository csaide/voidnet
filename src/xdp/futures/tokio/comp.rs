use std::{
    ops::{Deref, DerefMut},
    os::fd::{AsRawFd, RawFd},
    pin::Pin,
    task::{Context, Poll},
};

use futures_core::ready;
use tokio::io::{Ready, unix::AsyncFd};

use crate::xdp::{error::Result, frame::FrameBuffer, umem::CompletionQueue};

pub struct TokioCompletionQueue<'umem> {
    inner: AsyncFd<CompletionQueue<'umem>>,
}

impl<'umem> TokioCompletionQueue<'umem> {
    pub fn new(completion_queue: CompletionQueue<'umem>) -> Result<Self> {
        Ok(Self {
            inner: AsyncFd::new(completion_queue)?,
        })
    }

    #[inline(always)]
    pub fn process_queue<'que, B: FrameBuffer<'umem>>(
        &'que mut self,
        batch: B,
        expected: usize,
    ) -> TokioCompFuture<'que, 'umem, B> {
        TokioCompFuture {
            completion_queue: self,
            batch,
            expected,
        }
    }
}

impl<'umem> AsRawFd for CompletionQueue<'umem> {
    fn as_raw_fd(&self) -> RawFd {
        self.fd()
    }
}

impl<'umem> Deref for TokioCompletionQueue<'umem> {
    type Target = CompletionQueue<'umem>;

    fn deref(&self) -> &Self::Target {
        self.inner.get_ref()
    }
}

impl<'umem> DerefMut for TokioCompletionQueue<'umem> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner.get_mut()
    }
}

pub struct TokioCompFuture<'que, 'umem, B: FrameBuffer<'umem>> {
    pub(crate) completion_queue: &'que mut TokioCompletionQueue<'umem>,
    pub(crate) batch: B,
    pub(crate) expected: usize,
}

impl<'que, 'umem, B: FrameBuffer<'umem>> Future for TokioCompFuture<'que, 'umem, B> {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: We guarantee not to move self, just access its fields.
        // Those accesses are also guaranteed to not move self or the fields themselves.
        let this = unsafe { self.get_unchecked_mut() };

        this.completion_queue
            .inner
            .get_mut()
            .process_queue(&mut this.batch);
        if this.batch.num_frames() >= this.expected {
            return Poll::Ready(Ok(()));
        }

        let mut guard = ready!(this.completion_queue.inner.poll_read_ready_mut(cx))?;

        guard.get_inner_mut().process_queue(&mut this.batch);
        if this.batch.num_frames() >= this.expected {
            guard.clear_ready_matching(Ready::READABLE);
            return Poll::Ready(Ok(()));
        }

        Poll::Pending
    }
}
