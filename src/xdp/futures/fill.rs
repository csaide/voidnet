use std::{
    pin::Pin,
    task::{Context, Poll},
};

use crate::xdp::{error::Result, frame::FrameBuffer, umem::FillQueue};

use super::get_poller;

pub struct ProcessFillQueueFuture<'que, 'umem, 'fd, B: FrameBuffer<'umem>> {
    pub(crate) fill_queue: &'que mut FillQueue<'umem>,
    pub(crate) batch: B,
    pub(crate) fds: &'fd [i32],
}

impl<'que, 'umem, 'fd, B: FrameBuffer<'umem>> Future
    for ProcessFillQueueFuture<'que, 'umem, 'fd, B>
{
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: We guarantee not to move self, just access its fields.
        // Those accesses are also guaranteed to not move self or the fields themselves.
        let this = unsafe { self.get_unchecked_mut() };

        for fd in this.fds.iter() {
            if let Err(e) = this.fill_queue.maybe_wake(*fd) {
                return Poll::Ready(Err(e));
            }
        }

        this.fill_queue.process_queue(&mut this.batch);
        if this.batch.num_frames() > 0 {
            match get_poller().register_waker(this.fill_queue.fd(), cx.waker()) {
                Ok(_) => (),
                err => return Poll::Ready(err),
            }
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
}
