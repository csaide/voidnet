use std::{
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use crate::xdp::{frame_v2::FrameBuffer, socket::SocketTx};

pub struct SendFuture<'a, 'umem, B: FrameBuffer<'umem>> {
    pub(crate) socket: &'a mut SocketTx,
    pub(crate) batch: B,
    pub(crate) _lifetime: PhantomData<&'umem ()>,
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
