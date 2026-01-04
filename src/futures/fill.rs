use std::{
    ffi::c_int,
    pin::Pin,
    task::{Context, Poll},
};

use crate::xdp::{
    error::{Error, Result},
    frame::FrameBuffer,
    umem::FillQueue,
};

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
                Err(e) => return Poll::Ready(Err(Error::Poller(e))),
            }
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

pub struct WakeFillQueueFuture<'que, 'umem> {
    pub(crate) fill_queue: &'que FillQueue<'umem>,
    pub(crate) fd: c_int,
}

impl<'que, 'umem> Future for WakeFillQueueFuture<'que, 'umem> {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Err(e) = self.fill_queue.maybe_wake(self.fd) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(()))
    }
}
