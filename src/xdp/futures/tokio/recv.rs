use std::{
    ops::{Deref, DerefMut},
    os::fd::{AsRawFd, RawFd},
    pin::Pin,
    task::{Context, Poll},
};

use futures_core::ready;
use tokio::io::{Ready, unix::AsyncFd};

use crate::xdp::{error::Result, frame::FrameBuffer, socket::SocketRx};

pub struct TokioSocketRx<'umem> {
    inner: AsyncFd<SocketRx<'umem>>,
}

impl<'umem> TokioSocketRx<'umem> {
    pub fn new(socket: SocketRx<'umem>) -> Result<Self> {
        Ok(Self {
            inner: AsyncFd::new(socket)?,
        })
    }

    #[inline(always)]
    pub fn recv<B: FrameBuffer<'umem>>(&mut self, batch: B) -> TokioRecvFuture<'_, 'umem, B> {
        TokioRecvFuture {
            socket: self,
            batch,
        }
    }
}

impl<'umem> AsRawFd for SocketRx<'umem> {
    fn as_raw_fd(&self) -> RawFd {
        self.fd()
    }
}

impl<'umem> Deref for TokioSocketRx<'umem> {
    type Target = SocketRx<'umem>;

    fn deref(&self) -> &Self::Target {
        self.inner.get_ref()
    }
}

impl<'umem> DerefMut for TokioSocketRx<'umem> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner.get_mut()
    }
}

pub struct TokioRecvFuture<'sock, 'umem, B: FrameBuffer<'umem>> {
    pub(crate) socket: &'sock mut TokioSocketRx<'umem>,
    pub(crate) batch: B,
}

impl<'sock, 'umem, B: FrameBuffer<'umem>> Future for TokioRecvFuture<'sock, 'umem, B> {
    type Output = Result<u32>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: We guarantee not to move self, just access its fields.
        // Those accesses are also guaranteed to not move self or the fields themselves.
        let this = unsafe { self.get_unchecked_mut() };

        if let Ok(received) = this.socket.inner.get_mut().recv(&mut this.batch) {
            return Poll::Ready(Ok(received));
        }

        loop {
            let mut guard = ready!(this.socket.inner.poll_read_ready_mut(cx))?;

            let sock = guard.get_inner_mut();
            match sock.recv(&mut this.batch) {
                Ok(received) => {
                    return Poll::Ready(Ok(received));
                }
                Err(_) => guard.clear_ready_matching(Ready::READABLE),
            }
        }
    }
}
