use std::{
    ops::{Deref, DerefMut},
    os::fd::{AsRawFd, RawFd},
    pin::Pin,
    task::{Context, Poll},
};

use futures_core::ready;
use tokio::io::{Ready, unix::AsyncFd};

use crate::xdp::{error::Result, frame::FrameBuffer, socket::SocketTx};

pub struct TokioSocketTx<'umem> {
    inner: AsyncFd<SocketTx<'umem>>,
}

impl<'umem> TokioSocketTx<'umem> {
    pub fn new(socket: SocketTx<'umem>) -> Result<Self> {
        Ok(Self {
            inner: AsyncFd::new(socket)?,
        })
    }

    #[inline(always)]
    pub fn send<B: FrameBuffer<'umem>>(&mut self, batch: B) -> TokioSendFuture<'_, 'umem, B> {
        TokioSendFuture {
            socket: self,
            batch,
        }
    }
}

impl<'umem> AsRawFd for SocketTx<'umem> {
    fn as_raw_fd(&self) -> RawFd {
        self.fd()
    }
}

impl<'umem> Deref for TokioSocketTx<'umem> {
    type Target = SocketTx<'umem>;

    fn deref(&self) -> &Self::Target {
        self.inner.get_ref()
    }
}

impl<'umem> DerefMut for TokioSocketTx<'umem> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner.get_mut()
    }
}

pub struct TokioSendFuture<'sock, 'umem, B: FrameBuffer<'umem>> {
    pub(crate) socket: &'sock mut TokioSocketTx<'umem>,
    pub(crate) batch: B,
}

impl<'sock, 'umem, B: FrameBuffer<'umem>> Future for TokioSendFuture<'sock, 'umem, B> {
    type Output = Result<u32>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: We guarantee not to move self, just access its fields.
        // Those accesses are also guaranteed to not move self or the fields themselves.
        let this = unsafe { self.get_unchecked_mut() };

        if let Ok(sent) = this.socket.inner.get_mut().send(&mut this.batch) {
            this.socket.maybe_wake()?;
            return Poll::Ready(Ok(sent));
        }

        loop {
            let mut guard = ready!(this.socket.inner.poll_write_ready_mut(cx))?;

            let sock = guard.get_inner_mut();
            match sock.send(&mut this.batch) {
                Ok(sent) => {
                    sock.maybe_wake()?;
                    return Poll::Ready(Ok(sent));
                }
                Err(_) => guard.clear_ready_matching(Ready::WRITABLE),
            }
        }
    }
}
