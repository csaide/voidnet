use std::{
    pin::Pin,
    task::{Context, Poll},
};

use crate::xdp::{frame::FrameBuffer, socket::SocketRx};

pub struct RecvFuture<'a, B: FrameBuffer> {
    pub(crate) socket: &'a mut SocketRx,
    pub(crate) batch: B,
}

impl<'a, B: FrameBuffer> Future for RecvFuture<'a, B> {
    type Output = u32;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // We guarantee not to move self, just access its fields.
        // Those accesses are also guaranteed to not move self or the fields themselves.
        let this = unsafe { self.get_unchecked_mut() };

        match this.socket.recv(&mut this.batch) {
            Ok(received) => Poll::Ready(received),
            Err(_) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}
