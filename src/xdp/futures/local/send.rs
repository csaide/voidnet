use std::{
    ops::{Deref, DerefMut},
    pin::Pin,
    task::{Context, Poll},
};

use crate::xdp::{error::Result, frame::FrameBuffer, socket::SocketTx};

pub struct LocalSocketTx<'umem> {
    inner: SocketTx<'umem>,
}

impl<'umem> LocalSocketTx<'umem> {
    pub fn new(socket: SocketTx<'umem>) -> Result<Self> {
        Ok(Self { inner: socket })
    }

    #[inline(always)]
    pub fn send<B: FrameBuffer<'umem>>(&mut self, batch: B) -> LocalSendFuture<'_, 'umem, B> {
        LocalSendFuture {
            socket: self,
            batch,
        }
    }
}

impl<'umem> Deref for LocalSocketTx<'umem> {
    type Target = SocketTx<'umem>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'umem> DerefMut for LocalSocketTx<'umem> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

pub struct LocalSendFuture<'sock, 'umem, B: FrameBuffer<'umem>> {
    pub(crate) socket: &'sock mut LocalSocketTx<'umem>,
    pub(crate) batch: B,
}

impl<'sock, 'umem, B: FrameBuffer<'umem>> Future for LocalSendFuture<'sock, 'umem, B> {
    type Output = Result<u32>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: We guarantee not to move self, just access its fields.
        // Those accesses are also guaranteed to not move self or the fields themselves.
        let this = unsafe { self.get_unchecked_mut() };

        if let Ok(sent) = this.socket.inner.send(&mut this.batch) {
            this.socket.maybe_wake()?;
            return Poll::Ready(Ok(sent));
        }

        Poll::Pending
    }
}
