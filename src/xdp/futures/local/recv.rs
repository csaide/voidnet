use std::{
    ops::{Deref, DerefMut},
    pin::Pin,
    task::{Context, Poll},
};

use crate::xdp::{error::Result, frame::FrameBuffer, socket::SocketRx};

pub struct LocalSocketRx<'umem> {
    inner: SocketRx<'umem>,
}

impl<'umem> LocalSocketRx<'umem> {
    pub fn new(socket: SocketRx<'umem>) -> Result<Self> {
        Ok(Self { inner: socket })
    }

    #[inline(always)]
    pub fn recv<B: FrameBuffer<'umem>>(&mut self, batch: B) -> LocalRecvFuture<'_, 'umem, B> {
        LocalRecvFuture {
            socket: self,
            batch,
        }
    }
}

impl<'umem> Deref for LocalSocketRx<'umem> {
    type Target = SocketRx<'umem>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'umem> DerefMut for LocalSocketRx<'umem> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

pub struct LocalRecvFuture<'sock, 'umem, B: FrameBuffer<'umem>> {
    pub(crate) socket: &'sock mut LocalSocketRx<'umem>,
    pub(crate) batch: B,
}

impl<'sock, 'umem, B: FrameBuffer<'umem>> Future for LocalRecvFuture<'sock, 'umem, B> {
    type Output = Result<u32>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: We guarantee not to move self, just access its fields.
        // Those accesses are also guaranteed to not move self or the fields themselves.
        let this = unsafe { self.get_unchecked_mut() };

        if let Ok(received) = this.socket.inner.recv(&mut this.batch) {
            return Poll::Ready(Ok(received));
        }

        Poll::Pending
    }
}
