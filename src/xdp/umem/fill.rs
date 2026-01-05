use std::{ptr::null_mut, sync::Arc};

use errno::errno;
use libc::{EAGAIN, EBUSY, ENETDOWN, ENOBUFS, MSG_DONTWAIT, c_int, recvfrom};

use crate::xdp::{
    error::{Error, Result},
    frame::FrameBuffer,
    futures::ProcessFillQueueFuture,
    ring::{Init, Producer},
};

use super::UmemOwner;

/// A fill queue is a ring of descriptors that are used to transfer packets from the user to the kernel. This is a thin wrapper around
/// the xsk_ring_prod struct, exposing a safe API for interacting with the ring.
pub struct FillQueue<'umem> {
    _owner: Arc<UmemOwner<'umem>>,
    ring: Producer<Init>,
    busy_poll: bool,
}

impl<'umem> FillQueue<'umem> {
    /// Creates a new fill queue.
    pub(crate) fn new(ring: Producer<Init>, owner: Arc<UmemOwner<'umem>>, busy_poll: bool) -> Self {
        Self {
            ring,
            _owner: owner,
            busy_poll,
        }
    }

    #[inline(always)]
    pub(crate) fn fd(&self) -> i32 {
        self._owner.fd()
    }

    /// Returns the size of the fill ring.
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

    /// Processes the fill queue asynchronously, returning a future that will be ready when the fill queue is processed.
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
}
