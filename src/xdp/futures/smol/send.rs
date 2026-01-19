use std::{
    ops::{Deref, DerefMut},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use async_io::Async;
use futures_core::ready;

use crate::xdp::{error::Result, frame::FrameBuffer, socket::SocketTx};

use super::SmolFd;

pub struct SmolSocketTx<'umem> {
    inner: SocketTx<'umem>,
    async_fd: Arc<Async<SmolFd>>,
}

impl<'umem> SmolSocketTx<'umem> {
    pub fn new(socket: SocketTx<'umem>, async_fd: Arc<Async<SmolFd>>) -> Self {
        Self {
            inner: socket,
            async_fd,
        }
    }

    #[inline(always)]
    pub fn send<B: FrameBuffer<'umem>>(&mut self, batch: B) -> SmolSendFuture<'_, 'umem, B> {
        SmolSendFuture {
            socket: self,
            batch,
        }
    }
}

impl<'umem> Deref for SmolSocketTx<'umem> {
    type Target = SocketTx<'umem>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'umem> DerefMut for SmolSocketTx<'umem> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

pub struct SmolSendFuture<'sock, 'umem, B: FrameBuffer<'umem>> {
    socket: &'sock mut SmolSocketTx<'umem>,
    batch: B,
}

impl<'sock, 'umem, B: FrameBuffer<'umem>> Future for SmolSendFuture<'sock, 'umem, B> {
    type Output = Result<u32>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: We guarantee not to move self, just access its fields.
        // Those accesses are also guaranteed to not move self or the fields themselves.
        let this = unsafe { self.get_unchecked_mut() };

        if let Ok(sent) = this.socket.inner.send(&mut this.batch) {
            this.socket.maybe_wake()?;
            return Poll::Ready(Ok(sent));
        }

        let SmolSocketTx { inner, async_fd } = this.socket;
        loop {
            ready!(async_fd.poll_writable(cx))?;

            if let Ok(sent) = inner.send(&mut this.batch) {
                inner.maybe_wake()?;
                return Poll::Ready(Ok(sent));
            }
        }
    }
}
