use std::{
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use crate::xdp::{frame_v2::FrameBuffer, socket::SocketRx};

pub struct RecvFuture<'a, 'umem, B: FrameBuffer<'umem>> {
    pub(crate) socket: &'a mut SocketRx,
    pub(crate) batch: B,
    pub(crate) _lifetime: PhantomData<&'umem ()>,
}

impl<'a, 'umem, B: FrameBuffer<'umem>> Future for RecvFuture<'a, 'umem, B> {
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
