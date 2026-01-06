use std::{
    pin::Pin,
    task::{Context, Poll},
};

use crate::xdp::{error::Result, frame::FrameBuffer, umem::CompletionQueue};

use super::get_poller;

pub struct CompFuture<'que, 'umem, B: FrameBuffer<'umem>> {
    pub(crate) completion_queue: &'que mut CompletionQueue<'umem>,
    pub(crate) batch: B,
    pub(crate) expected: usize,
}

impl<'que, 'umem, B: FrameBuffer<'umem>> Future for CompFuture<'que, 'umem, B> {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: We guarantee not to move self, just access its fields.
        // Those accesses are also guaranteed to not move self or the fields themselves.
        let this = unsafe { self.get_unchecked_mut() };

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
