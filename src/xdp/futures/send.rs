use std::{
    pin::Pin,
    task::{Context, Poll},
};

use crate::xdp::{error::Result, frame::FrameBuffer, socket::SocketTx};

use super::get_poller;

pub struct SendFuture<'sock, 'umem, B: FrameBuffer<'umem>> {
    pub(crate) socket: &'sock mut SocketTx<'umem>,
    pub(crate) batch: B,
}

impl<'sock, 'umem, B: FrameBuffer<'umem>> Future for SendFuture<'sock, 'umem, B> {
    type Output = Result<u32>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: We guarantee not to move self, just access its fields.
        // Those accesses are also guaranteed to not move self or the fields themselves.
        let this = unsafe { self.get_unchecked_mut() };

        let sent = match this.socket.send(&mut this.batch) {
            Ok(sent) => sent,
            Err(_) => {
                match get_poller().register_waker(this.socket.fd(), cx.waker()) {
                    Ok(_) => (),
                    Err(e) => return Poll::Ready(Err(e)),
                }
                return Poll::Pending;
            }
        };

        if let Err(e) = this.socket.maybe_wake() {
            return Poll::Ready(Err(e));
        }

        Poll::Ready(Ok(sent))
    }
}
