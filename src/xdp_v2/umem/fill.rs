use std::{cmp::min, ptr::null_mut, sync::Arc};

use errno::errno;
use libc::{EAGAIN, EBUSY, ENETDOWN, ENOBUFS, MSG_DONTWAIT, c_int, recvfrom};
use libxdp_sys::xsk_ring_prod;

use crate::xdp_v2::{
    error::{Error, Result},
    frame::{Frame, FrameStack},
    ring::Producer,
};

pub struct FillQueue {
    stack: Arc<FrameStack>,
    ring: Producer,
    process_threshold: usize,
}

impl FillQueue {
    pub fn new(ring: Producer, stack: Arc<FrameStack>, process_threshold: usize) -> Self {
        Self {
            ring,
            stack,
            process_threshold,
        }
    }

    /// Possibly wakes the fill queue, so the kernel continues to process incoming packets.
    ///
    /// This is done by first checking the needs wakeup flag, given its set we fire a empty recvfrom on the supplied fd.
    #[inline]
    pub fn maybe_wake(&self, fd: c_int) -> Result<()> {
        unsafe {
            if self.ring.needs_wakeup() {
                let ret = recvfrom(fd, null_mut(), 0, MSG_DONTWAIT, null_mut(), null_mut());
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
        }
        Ok(())
    }

    /// Processes the fill queue, allocating new frames from the frame stack and submitting them to the fill ring up to the size of the fill ring.
    #[inline]
    pub fn process_queue(&mut self, batch: &mut Vec<Frame>) {
        if batch.len() < self.process_threshold {
            return;
        }

        let batch_size = min(batch.len(), self.stack.len());
        let (mut idx, ready) = self.ring.reserve(batch_size as u32);
        if ready == 0 {
            return;
        }

        for frame in batch.drain(..batch_size) {
            let ptr = self.ring.fill_addr(idx);
            unsafe { *ptr = frame.addr() as u64 };
            idx += 1;
        }

        self.ring.submit(ready);
    }

    pub fn as_mut(&mut self) -> *mut xsk_ring_prod {
        self.ring.as_mut()
    }

    pub fn as_ref(&self) -> *const xsk_ring_prod {
        self.ring.as_ref()
    }
}
