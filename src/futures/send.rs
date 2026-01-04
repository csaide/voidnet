use std::{
    pin::Pin,
    task::{Context, Poll},
};

use crate::xdp::{frame::FrameBuffer, socket::SocketTx};

pub struct SendFuture<'sock, 'umem, B: FrameBuffer<'umem>> {
    pub(crate) socket: &'sock mut SocketTx<'umem>,
    pub(crate) batch: B,
}

impl<'a, 'umem, B: FrameBuffer<'umem>> Future for SendFuture<'a, 'umem, B> {
    type Output = u32;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };
        match this.socket.send(&mut this.batch) {
            Ok(sent) => Poll::Ready(sent),
            Err(_) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}
