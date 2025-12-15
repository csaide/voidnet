use std::{ptr::null_mut, sync::Arc};

use errno::errno;
use libc::{EAGAIN, EBUSY, ENETDOWN, ENOBUFS, MSG_DONTWAIT, c_int, recvfrom};
use libxdp_sys::{xsk_ring_prod, xsk_ring_prod__needs_wakeup};

use crate::xdp::{
    error::{Error, Result},
    ring::Producer,
    umem::FrameStack,
};

use super::Umem;

pub struct FillQueue {
    _umem: Arc<Umem>,
    ring: Producer,
    stack: Arc<FrameStack>,
}

impl FillQueue {
    pub fn new(umem: Arc<Umem>, ring: Producer, stack: Arc<FrameStack>) -> Self {
        Self {
            _umem: umem,
            ring,
            stack,
        }
    }

    /// Possibly wakes the fill queue, so the kernel continues to process incoming packets.
    ///
    /// This is done by first checking the needs wakeup flag, given its set we fire a empty recvfrom on the supplied fd.
    #[inline]
    pub fn maybe_wake(&self, fd: c_int) -> Result<()> {
        unsafe {
            if xsk_ring_prod__needs_wakeup(self.ring.as_ref()) == 1 {
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
    pub fn process_queue(&mut self) {
        let free = match self.ring.free(self.stack.len() as u32) {
            Some(free) => free,
            None => return,
        };

        let (mut idx, ready) = self.ring.reserve(free).unwrap_or((0, 0));
        for _ in 0..ready {
            let addr = self.stack.pop().unwrap();
            let ptr = self.ring.fill_addr(idx);
            unsafe { *ptr = addr as u64 };
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
