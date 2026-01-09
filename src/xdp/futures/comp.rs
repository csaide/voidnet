use std::{
    pin::Pin,
    task::{Context, Poll},
};

use crate::xdp::{
    error::{Error, Result},
    frame::FrameBuffer,
    umem::CompletionQueue,
};

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
            match this.completion_queue.get_poller() {
                Some(poller) => poller.register_waker(this.completion_queue.fd(), cx.waker())?,
                None => return Poll::Ready(Err(Error::PollerNotInitialized)),
            }
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
}
