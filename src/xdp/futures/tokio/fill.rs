use std::{
    ops::{Deref, DerefMut},
    os::{fd::RawFd, raw::c_int},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures_core::ready;
use tokio::io::{Ready, unix::AsyncFd};

use crate::xdp::{error::Result, frame::FrameBuffer, umem::FillQueue};

pub struct TokioFillQueue<'umem> {
    inner: FillQueue<'umem>,
    async_fd: Arc<AsyncFd<RawFd>>,
}

impl<'umem> TokioFillQueue<'umem> {
    pub fn new(fill_queue: FillQueue<'umem>, async_fd: Arc<AsyncFd<RawFd>>) -> Self {
        Self {
            inner: fill_queue,
            async_fd,
        }
    }

    #[inline(always)]
    pub fn process_queue<'fd, B: FrameBuffer<'umem>>(
        &mut self,
        batch: B,
        fds: &'fd [c_int],
    ) -> TokioFillFuture<'_, 'umem, 'fd, B> {
        TokioFillFuture {
            fill_queue: self,
            batch,
            fds,
        }
    }
}

impl<'umem> Deref for TokioFillQueue<'umem> {
    type Target = FillQueue<'umem>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'umem> DerefMut for TokioFillQueue<'umem> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

pub struct TokioFillFuture<'que, 'umem, 'fd, B: FrameBuffer<'umem>> {
    fill_queue: &'que mut TokioFillQueue<'umem>,
    batch: B,
    fds: &'fd [c_int],
}

impl<'que, 'umem, 'fd, B: FrameBuffer<'umem>> Future for TokioFillFuture<'que, 'umem, 'fd, B> {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: We guarantee not to move self, just access its fields.
        // Those accesses are also guaranteed to not move self or the fields themselves.
        let this = unsafe { self.get_unchecked_mut() };

        for fd in this.fds.iter() {
            if let Err(e) = this.fill_queue.maybe_wake(*fd) {
                return Poll::Ready(Err(e));
            }
        }

        this.fill_queue.inner.process_queue(&mut this.batch);
        if this.batch.num_frames() == 0 {
            return Poll::Ready(Ok(()));
        }

        let TokioFillQueue { inner, async_fd } = this.fill_queue;
        loop {
            let mut guard = ready!(async_fd.poll_write_ready(cx))?;

            inner.process_queue(&mut this.batch);
            if this.batch.num_frames() == 0 {
                return Poll::Ready(Ok(()));
            }

            guard.clear_ready_matching(Ready::WRITABLE);
        }
    }
}
