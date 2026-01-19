use std::{
    ops::{Deref, DerefMut},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use async_io::Async;
use futures_core::ready;

use crate::xdp::{error::Result, frame::FrameBuffer, socket::SocketRx};

use super::SmolFd;

pub struct SmolSocketRx<'umem> {
    inner: SocketRx<'umem>,
    async_fd: Arc<Async<SmolFd>>,
}

impl<'umem> SmolSocketRx<'umem> {
    pub fn new(socket: SocketRx<'umem>, async_fd: Arc<Async<SmolFd>>) -> Self {
        Self {
            inner: socket,
            async_fd,
        }
    }

    #[inline(always)]
    pub fn recv<B: FrameBuffer<'umem>>(&mut self, batch: B) -> SmolRecvFuture<'_, 'umem, B> {
        SmolRecvFuture {
            socket: self,
            batch,
        }
    }
}

impl<'umem> Deref for SmolSocketRx<'umem> {
    type Target = SocketRx<'umem>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'umem> DerefMut for SmolSocketRx<'umem> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

pub struct SmolRecvFuture<'sock, 'umem, B: FrameBuffer<'umem>> {
    pub(crate) socket: &'sock mut SmolSocketRx<'umem>,
    pub(crate) batch: B,
}

impl<'sock, 'umem, B: FrameBuffer<'umem>> Future for SmolRecvFuture<'sock, 'umem, B> {
    type Output = Result<u32>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: We guarantee not to move self, just access its fields.
        // Those accesses are also guaranteed to not move self or the fields themselves.
        let this = unsafe { self.get_unchecked_mut() };

        if let Ok(received) = this.socket.inner.recv(&mut this.batch) {
            return Poll::Ready(Ok(received));
        }

        let SmolSocketRx { inner, async_fd } = this.socket;
        loop {
            ready!(async_fd.poll_readable(cx))?;

            if let Ok(received) = inner.recv(&mut this.batch) {
                return Poll::Ready(Ok(received));
            }
        }
    }
}
