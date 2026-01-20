use std::{
    ops::{Deref, DerefMut},
    os::fd::RawFd,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures_core::ready;
use tokio::io::{Ready, unix::AsyncFd};

use crate::xdp::{error::Result, frame::FrameBuffer, socket::SocketTx};

/// A socket transmitter designed to work on the [Tokio] runtime.
///
/// [Tokio]: tokio
pub struct TokioSocketTx<'umem> {
    inner: SocketTx<'umem>,
    async_fd: Arc<AsyncFd<RawFd>>,
}

impl<'umem> TokioSocketTx<'umem> {
    pub(crate) fn new(socket: SocketTx<'umem>, async_fd: Arc<AsyncFd<RawFd>>) -> Self {
        Self {
            inner: socket,
            async_fd,
        }
    }

    /// Asynchronously sends a batch of frames to the socket.
    #[inline(always)]
    pub fn send<B: FrameBuffer<'umem>>(&mut self, batch: B) -> TokioSendFuture<'_, 'umem, B> {
        TokioSendFuture {
            socket: self,
            batch,
        }
    }
}

impl<'umem> Deref for TokioSocketTx<'umem> {
    type Target = SocketTx<'umem>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'umem> DerefMut for TokioSocketTx<'umem> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

/// A future that asynchronously sends a batch of frames to the socket.
pub struct TokioSendFuture<'sock, 'umem, B: FrameBuffer<'umem>> {
    socket: &'sock mut TokioSocketTx<'umem>,
    batch: B,
}

impl<'sock, 'umem, B: FrameBuffer<'umem>> Future for TokioSendFuture<'sock, 'umem, B> {
    type Output = Result<u32>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: We guarantee not to move self, just access its fields.
        // Those accesses are also guaranteed to not move self or the fields themselves.
        let this = unsafe { self.get_unchecked_mut() };

        if let Ok(sent) = this.socket.inner.send(&mut this.batch) {
            this.socket.maybe_wake()?;
            return Poll::Ready(Ok(sent));
        }

        let TokioSocketTx { inner, async_fd } = this.socket;
        loop {
            let mut guard = ready!(async_fd.poll_write_ready(cx))?;

            match inner.send(&mut this.batch) {
                Ok(sent) => {
                    inner.maybe_wake()?;
                    return Poll::Ready(Ok(sent));
                }
                Err(_) => guard.clear_ready_matching(Ready::WRITABLE),
            }
        }
    }
}
