use std::{
    ops::{Deref, DerefMut},
    os::raw::c_int,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use async_io::Async;
use futures_core::ready;

use crate::xdp::{error::Result, frame::FrameBuffer, umem::FillQueue};

use super::SmolFd;

/// A fill queue designed to work on the [Smol] runtime.
///
/// [Smol]: smol
pub struct SmolFillQueue<'umem> {
    inner: FillQueue<'umem>,
    async_fd: Arc<Async<SmolFd>>,
}

impl<'umem> SmolFillQueue<'umem> {
    pub(crate) fn new(fill_queue: FillQueue<'umem>, async_fd: Arc<Async<SmolFd>>) -> Self {
        Self {
            inner: fill_queue,
            async_fd,
        }
    }

    /// Asynchronously processes the fill queue, allocating new frames from the frame stack and submitting them to the fill ring up to the size of the fill ring.
    #[inline(always)]
    pub fn process_queue<'fd, B: FrameBuffer<'umem>>(
        &mut self,
        batch: B,
        fds: &'fd [c_int],
    ) -> SmolFillFuture<'_, 'umem, 'fd, B> {
        SmolFillFuture {
            fill_queue: self,
            batch,
            fds,
        }
    }
}

impl<'umem> Deref for SmolFillQueue<'umem> {
    type Target = FillQueue<'umem>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'umem> DerefMut for SmolFillQueue<'umem> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

/// A future that asynchronously processes the fill queue, allocating new frames from the frame stack and submitting them to the fill ring up to the size of the fill ring.
pub struct SmolFillFuture<'que, 'umem, 'fd, B: FrameBuffer<'umem>> {
    fill_queue: &'que mut SmolFillQueue<'umem>,
    batch: B,
    fds: &'fd [c_int],
}

impl<'que, 'umem, 'fd, B: FrameBuffer<'umem>> Future for SmolFillFuture<'que, 'umem, 'fd, B> {
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

        let SmolFillQueue { inner, async_fd } = this.fill_queue;
        loop {
            ready!(async_fd.poll_writable(cx))?;

            inner.process_queue(&mut this.batch);
            if this.batch.num_frames() == 0 {
                return Poll::Ready(Ok(()));
            }
        }
    }
}
