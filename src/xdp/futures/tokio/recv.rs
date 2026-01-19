use std::{
    ops::{Deref, DerefMut},
    os::fd::RawFd,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures_core::ready;
use tokio::io::{Ready, unix::AsyncFd};

use crate::xdp::{error::Result, frame::FrameBuffer, socket::SocketRx};

pub struct TokioSocketRx<'umem> {
    inner: SocketRx<'umem>,
    async_fd: Arc<AsyncFd<RawFd>>,
}

impl<'umem> TokioSocketRx<'umem> {
    pub fn new(socket: SocketRx<'umem>, async_fd: Arc<AsyncFd<RawFd>>) -> Self {
        Self {
            inner: socket,
            async_fd,
        }
    }

    #[inline(always)]
    pub fn recv<B: FrameBuffer<'umem>>(&mut self, batch: B) -> TokioRecvFuture<'_, 'umem, B> {
        TokioRecvFuture {
            socket: self,
            batch,
        }
    }
}

impl<'umem> Deref for TokioSocketRx<'umem> {
    type Target = SocketRx<'umem>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'umem> DerefMut for TokioSocketRx<'umem> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

pub struct TokioRecvFuture<'sock, 'umem, B: FrameBuffer<'umem>> {
    socket: &'sock mut TokioSocketRx<'umem>,
    batch: B,
}

impl<'sock, 'umem, B: FrameBuffer<'umem>> Future for TokioRecvFuture<'sock, 'umem, B> {
    type Output = Result<u32>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: We guarantee not to move self, just access its fields.
        // Those accesses are also guaranteed to not move self or the fields themselves.
        let this = unsafe { self.get_unchecked_mut() };

        if let Ok(received) = this.socket.inner.recv(&mut this.batch) {
            return Poll::Ready(Ok(received));
        }

        let TokioSocketRx { inner, async_fd } = this.socket;
        loop {
            let mut guard = ready!(async_fd.poll_read_ready(cx))?;

            match inner.recv(&mut this.batch) {
                Ok(received) => {
                    return Poll::Ready(Ok(received));
                }
                Err(_) => guard.clear_ready_matching(Ready::READABLE),
            }
        }
    }
}
