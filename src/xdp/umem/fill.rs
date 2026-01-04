use std::{ptr::null_mut, sync::Arc};

use errno::errno;
use libc::{EAGAIN, EBUSY, ENETDOWN, ENOBUFS, MSG_DONTWAIT, c_int, recvfrom};
use libxdp_sys::xsk_ring_prod;

use crate::{
    futures::{ProcessFillQueueFuture, WakeFillQueueFuture},
    xdp::{
        error::{Error, Result},
        frame::FrameBuffer,
        ring::{Init, Producer},
    },
};

use super::UmemOwner;

pub struct FillQueue<'umem> {
    _owner: Arc<UmemOwner<'umem>>,
    ring: Producer<Init>,
    busy_poll: bool,
}

impl<'umem> FillQueue<'umem> {
    pub fn new(ring: Producer<Init>, owner: Arc<UmemOwner<'umem>>, busy_poll: bool) -> Self {
        Self {
            ring,
            _owner: owner,
            busy_poll,
        }
    }

    #[inline(always)]
    pub fn size(&self) -> u32 {
        self.ring.size()
    }

    /// Possibly wakes the fill queue, so the kernel continues to process incoming packets.
    ///
    /// This is done by first checking the needs wakeup flag, given its set we fire a empty recvfrom on the supplied fd.
    #[inline(always)]
    pub fn maybe_wake(&self, fd: c_int) -> Result<()> {
        if self.busy_poll || self.ring.needs_wakeup() {
            let ret = unsafe { recvfrom(fd, null_mut(), 0, MSG_DONTWAIT, null_mut(), null_mut()) };
            let errno = errno();
            if ret < 0
                && errno.0 != ENOBUFS
                && errno.0 != EAGAIN
                && errno.0 != EBUSY
                && errno.0 != ENETDOWN
            {
                return Err(Error::WakeFillQueue(errno));
            }
        }
        Ok(())
    }

    #[inline(always)]
    pub fn maybe_wake_async(&self, fd: c_int) -> WakeFillQueueFuture<'_, 'umem> {
        WakeFillQueueFuture {
            fill_queue: &self,
            fd,
        }
    }

    /// Processes the fill queue, allocating new frames from the frame stack and submitting them to the fill ring up to the size of the fill ring.
    #[inline(always)]
    pub fn process_queue<B: FrameBuffer<'umem>>(&mut self, mut batch: B) {
        let (mut idx, ready) = self.ring.reserve(batch.num_frames() as u32);
        if ready == 0 {
            return;
        }

        for frame in batch.take_frames() {
            let ptr = self.ring.fill_addr(idx);
            unsafe { *ptr = frame.addr() };
            idx += 1;
        }

        self.ring.submit(ready);
    }

    #[inline(always)]
    pub fn process_queue_async<B: FrameBuffer<'umem>>(
        &mut self,
        batch: B,
    ) -> ProcessFillQueueFuture<'_, 'umem, B> {
        ProcessFillQueueFuture {
            fill_queue: self,
            batch,
        }
    }

    #[inline(always)]
    pub fn as_mut(&mut self) -> *mut xsk_ring_prod {
        self.ring.as_mut_ptr()
    }

    #[inline(always)]
    pub fn as_ref(&self) -> *const xsk_ring_prod {
        self.ring.as_ptr()
    }
}
