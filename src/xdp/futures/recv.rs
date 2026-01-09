use std::{
    pin::Pin,
    task::{Context, Poll},
};

use crate::xdp::{
    error::{Error, Result},
    frame::FrameBuffer,
    socket::SocketRx,
};

pub struct RecvFuture<'sock, 'umem, B: FrameBuffer<'umem>> {
    pub(crate) socket: &'sock mut SocketRx<'umem>,
    pub(crate) batch: B,
}

impl<'sock, 'umem, B: FrameBuffer<'umem>> Future for RecvFuture<'sock, 'umem, B> {
    type Output = Result<u32>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: We guarantee not to move self, just access its fields.
        // Those accesses are also guaranteed to not move self or the fields themselves.
        let this = unsafe { self.get_unchecked_mut() };

        match this.socket.recv(&mut this.batch) {
            Ok(received) => Poll::Ready(Ok(received)),
            Err(_) => {
                match this.socket.get_poller() {
                    Some(poller) => poller.register_waker(this.socket.fd(), cx.waker())?,
                    None => return Poll::Ready(Err(Error::PollerNotInitialized)),
                }
                Poll::Pending
            }
        }
    }
}
