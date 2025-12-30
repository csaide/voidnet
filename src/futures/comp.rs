use std::{
    pin::Pin,
    task::{Context, Poll},
};

use crate::xdp::{error::Result, frame::FrameBuffer, socket::SocketTx, umem::CompletionQueue};

pub struct CompFuture<'a, 'b, B: FrameBuffer> {
    pub(crate) completion_queue: &'a mut CompletionQueue,
    pub(crate) socket: &'b mut SocketTx,
    pub(crate) batch: B,
    pub(crate) expected: usize,
}

impl<'a, 'b, B: FrameBuffer> Future for CompFuture<'a, 'b, B> {
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
