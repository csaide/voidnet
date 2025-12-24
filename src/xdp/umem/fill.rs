use std::{collections::VecDeque, ptr::null_mut, sync::Arc};

use errno::errno;
use libc::{EAGAIN, EBUSY, ENETDOWN, ENOBUFS, MSG_DONTWAIT, c_int, recvfrom};
use libxdp_sys::xsk_ring_prod;

use crate::xdp::{
    error::{Error, Result},
    frame::{Frame, FrameStack},
    ring::Producer,
};

pub struct FillQueue {
    _stack: Arc<FrameStack>,
    ring: Producer,
    busy_poll: bool,
}

impl FillQueue {
    pub fn new(ring: Producer, stack: Arc<FrameStack>, busy_poll: bool) -> Self {
        Self {
            ring,
            _stack: stack,
            busy_poll,
        }
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
    pub fn process_queue(&mut self, batch: &mut VecDeque<Frame>) {
        let (mut idx, ready) = self.ring.reserve(batch.len() as u32);
        if ready == 0 {
            return;
        }

        for frame in batch.drain(..ready as usize) {
            let ptr = self.ring.fill_addr(idx);
            unsafe { *ptr = frame.addr() as u64 };
            idx += 1;
        }

        self.ring.submit(ready);
    }

    #[inline(always)]
    pub fn as_mut(&mut self) -> *mut xsk_ring_prod {
        self.ring.as_mut()
    }

    #[inline(always)]
    pub fn as_ref(&self) -> *const xsk_ring_prod {
        self.ring.as_ref()
    }
}
