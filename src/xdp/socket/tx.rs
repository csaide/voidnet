use std::{mem::ManuallyDrop, ptr::null, sync::Arc};

use errno::errno;
use libc::{EAGAIN, EBUSY, ENETDOWN, ENOBUFS, MSG_DONTWAIT, sendto};
use libxdp_sys::xsk_ring_prod__needs_wakeup;

use crate::xdp::{
    error::{Error, Result},
    ring::Producer,
    umem::{Frame, Umem},
};

use super::SocketOwner;

pub struct SocketTx {
    socket: Arc<SocketOwner>,
    ring: Producer,
    umem: Arc<Umem>,
}

impl SocketTx {
    pub fn new(socket: Arc<SocketOwner>, ring: Producer, umem: Arc<Umem>) -> Self {
        Self { socket, ring, umem }
    }

    #[inline]
    pub fn maybe_wake(&self) -> Result<()> {
        unsafe {
            if xsk_ring_prod__needs_wakeup(self.ring.as_ref()) == 1 {
                let ret = sendto(self.socket.fd, null(), 0, MSG_DONTWAIT, null(), 0);
                let errno = errno();
                if ret < 0
                    && errno.0 != ENOBUFS
                    && errno.0 != EAGAIN
                    && errno.0 != EBUSY
                    && errno.0 != ENETDOWN
                {
                    return Err(Error::TxQueueWake(errno));
                }
            }
        }
        Ok(())
    }

    pub fn prepare_frames(&mut self, num_frames: usize) -> Result<Vec<Frame>> {
        let mut frames = Vec::with_capacity(num_frames);

        for _ in 0..num_frames {
            if let Some(frame) = self.umem.get_write_frame() {
                frames.push(frame);
            } else {
                break;
            }
        }

        if frames.is_empty() {
            return Err(Error::WouldBlock);
        }
        Ok(frames)
    }

    pub fn send(&mut self, frames: &mut Vec<Frame>) -> Result<()> {
        let (mut idx_tx, ready) = loop {
            if let Some((idx_tx, ready)) = self.ring.reserve(frames.len() as u32) {
                break (idx_tx, ready);
            }

            self.maybe_wake()?;
        };

        for _ in 0..ready {
            let frame = frames.pop().map(ManuallyDrop::new).unwrap();
            let desc = self.ring.tx_desc(idx_tx);
            unsafe {
                (*desc).addr = frame.addr();
                (*desc).len = frame.len() as u32;
                (*desc).options = 0;
            }
            idx_tx += 1;
        }

        self.ring.submit(ready);
        self.maybe_wake()?;
        Ok(())
    }
}
