use std::{
    pin::Pin,
    task::{Context, Poll},
};

use crate::xdp::{error::Result, frame::FrameBuffer, socket::SocketTx, umem::CompletionQueue};

use super::get_poller;

pub struct CompFuture<'que, 'umem, 'sock, B: FrameBuffer<'umem>> {
    pub(crate) completion_queue: &'que mut CompletionQueue<'umem>,
    pub(crate) socket: &'sock mut SocketTx<'umem>,
    pub(crate) batch: B,
    pub(crate) expected: usize,
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
            match get_poller().register_waker(this.completion_queue.fd(), cx.waker()) {
                Ok(_) => (),
                err => return Poll::Ready(err),
            }
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
}
