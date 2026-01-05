use std::{
    pin::Pin,
    task::{Context, Poll},
};

use crate::xdp::{error::Result, frame::FrameBuffer, umem::FillQueue};

use super::get_poller;

pub struct ProcessFillQueueFuture<'que, 'umem, B: FrameBuffer<'umem>> {
    pub(crate) fill_queue: &'que mut FillQueue<'umem>,
    pub(crate) batch: B,
}

impl<'a, 'owner, B: FrameBuffer<'owner>> Future for ProcessFillQueueFuture<'a, 'owner, B> {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

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
