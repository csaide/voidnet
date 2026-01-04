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

impl<'a, 'umem, B: FrameBuffer<'umem>> Future for SendFuture<'a, 'umem, B> {
    type Output = Result<u32>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };
        match this.socket.send(&mut this.batch) {
            Ok(sent) => Poll::Ready(Ok(sent)),
            Err(_) => {
                match get_poller().register_waker(this.socket.fd(), cx.waker()) {
                    Ok(_) => (),
                    Err(e) => return Poll::Ready(Err(e)),
                }
                Poll::Pending
            }
        }
    }
}
