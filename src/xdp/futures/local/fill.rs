use std::{
    ops::{Deref, DerefMut},
    os::raw::c_int,
    pin::Pin,
    task::{Context, Poll},
};

use crate::xdp::{error::Result, frame::FrameBuffer, umem::FillQueue};

/// A fill queue designed to work on the [LocalExecutor] executor.
///
/// [LocalExecutor]: crate::xdp::futures::local::LocalExecutor
pub struct LocalFillQueue<'umem> {
    inner: FillQueue<'umem>,
}

impl<'umem> LocalFillQueue<'umem> {
    pub(crate) fn new(fill_queue: FillQueue<'umem>) -> Result<Self> {
        Ok(Self { inner: fill_queue })
    }

    /// Processes the fill queue, allocating new frames from the frame stack and submitting them to the fill ring up to the size of the fill ring.
    #[inline(always)]
    pub fn process_queue<'fd, B: FrameBuffer<'umem>>(
        &mut self,
        batch: B,
        fds: &'fd [c_int],
    ) -> LocalFillFuture<'_, 'umem, 'fd, B> {
        LocalFillFuture {
            fill_queue: self,
            batch,
            fds,
        }
    }
}

impl<'umem> Deref for LocalFillQueue<'umem> {
    type Target = FillQueue<'umem>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'umem> DerefMut for LocalFillQueue<'umem> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

/// A future that asynchronously processes the fill queue, allocating new frames from the frame stack and submitting them to the fill ring up to the size of the fill ring.
pub struct LocalFillFuture<'que, 'umem, 'fd, B: FrameBuffer<'umem>> {
    pub(crate) fill_queue: &'que mut LocalFillQueue<'umem>,
    pub(crate) batch: B,
    pub(crate) fds: &'fd [c_int],
}

impl<'que, 'umem, 'fd, B: FrameBuffer<'umem>> Future for LocalFillFuture<'que, 'umem, 'fd, B> {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: We guarantee not to move self, just access its fields.
        // Those accesses are also guaranteed to not move self or the fields themselves.
        let this = unsafe { self.get_unchecked_mut() };

        for fd in this.fds.iter() {
            if let Err(e) = this.fill_queue.maybe_wake(*fd) {
                return Poll::Ready(Err(e));
            }
        }

        match this.fill_queue.inner.process_queue(&mut this.batch) {
            Ok(_) => Poll::Ready(Ok(())),
            Err(_) => Poll::Pending,
        }
    }
}
