use std::{
    ffi::c_int,
    pin::Pin,
    task::{Context, Poll},
};

use crate::xdp::{error::Result, frame::FrameBuffer, umem::FillQueue};

pub struct FillFuture<'a, B: FrameBuffer> {
    pub(crate) fill_queue: &'a mut FillQueue,
    pub(crate) batch: B,
    pub(crate) fd: c_int,
}

impl<'a, B: FrameBuffer> Future for FillFuture<'a, B> {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        if let Err(e) = this.fill_queue.maybe_wake(this.fd) {
            return Poll::Ready(Err(e));
        }

        this.fill_queue.process_queue(&mut this.batch);
        if this.batch.num_frames() > 0 {
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
}
