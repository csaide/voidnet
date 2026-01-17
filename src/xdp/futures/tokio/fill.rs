use std::{
    ops::{Deref, DerefMut},
    os::{
        fd::{AsRawFd, RawFd},
        raw::c_int,
    },
    pin::Pin,
    task::{Context, Poll},
};

use futures_core::ready;
use tokio::io::{Ready, unix::AsyncFd};

use crate::xdp::{error::Result, frame::FrameBuffer, umem::FillQueue};

pub struct TokioFillQueue<'umem> {
    inner: AsyncFd<FillQueue<'umem>>,
}

impl<'umem> TokioFillQueue<'umem> {
    pub fn new(fill_queue: FillQueue<'umem>) -> Result<Self> {
        Ok(Self {
            inner: AsyncFd::new(fill_queue)?,
        })
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

impl<'umem> AsRawFd for FillQueue<'umem> {
    fn as_raw_fd(&self) -> RawFd {
        self.fd()
    }
}

impl<'umem> Deref for TokioFillQueue<'umem> {
    type Target = FillQueue<'umem>;

    fn deref(&self) -> &Self::Target {
        self.inner.get_ref()
    }
}

impl<'umem> DerefMut for TokioFillQueue<'umem> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner.get_mut()
    }
}

pub struct TokioFillFuture<'que, 'umem, 'fd, B: FrameBuffer<'umem>> {
    pub(crate) fill_queue: &'que mut TokioFillQueue<'umem>,
    pub(crate) batch: B,
    pub(crate) fds: &'fd [c_int],
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

        this.fill_queue
            .inner
            .get_mut()
            .process_queue(&mut this.batch);
        if this.batch.num_frames() == 0 {
            return Poll::Ready(Ok(()));
        }

        let mut guard = ready!(this.fill_queue.inner.poll_write_ready_mut(cx))?;

        guard.get_inner_mut().process_queue(&mut this.batch);
        if this.batch.num_frames() == 0 {
            guard.clear_ready_matching(Ready::WRITABLE);
            return Poll::Ready(Ok(()));
        }

        Poll::Pending
    }
}
