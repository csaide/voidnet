use std::{
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use crate::xdp::{error::Result, frame_v2::FrameBuffer, socket::SocketTx, umem::CompletionQueue};

pub struct CompFuture<'s, 'umem, 'sock, B: FrameBuffer<'umem>> {
    pub(crate) completion_queue: &'s mut CompletionQueue,
    pub(crate) socket: &'sock mut SocketTx,
    pub(crate) batch: B,
    pub(crate) expected: usize,
    pub(crate) _lifetime: PhantomData<&'umem ()>,
}

impl<'a, 'owner, 'b, B: FrameBuffer<'owner>> Future for CompFuture<'a, 'owner, 'b, B> {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        if let Err(e) = this.socket.maybe_wake() {
            return Poll::Ready(Err(e));
        }

        this.completion_queue.process_queue(&mut this.batch);
        if this.batch.num_frames() < this.expected {
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
}
