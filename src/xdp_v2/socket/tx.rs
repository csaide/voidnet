use std::{mem::ManuallyDrop, ptr::null, sync::Arc};

use errno::errno;
use libc::{EAGAIN, EBUSY, ENETDOWN, ENOBUFS, MSG_DONTWAIT, sendto};

use crate::xdp_v2::{
    error::{Error, Result},
    frame::{Frame, FrameStack},
    ring::Producer,
};

use super::SocketOwner;

pub struct SocketTx {
    socket: Arc<SocketOwner>,
    ring: Producer,
    stack: Arc<FrameStack>,
}

impl SocketTx {
    pub fn new(socket: Arc<SocketOwner>, ring: Producer, stack: Arc<FrameStack>) -> Self {
        Self {
            socket,
            ring,
            stack,
        }
    }

    #[inline]
    pub fn maybe_wake(&self) -> Result<()> {
        unsafe {
            if self.ring.needs_wakeup() {
                let ret = sendto(self.socket.fd, null(), 0, MSG_DONTWAIT, null(), 0);
                let errno = errno();
                if ret < 0
                    && errno.0 != ENOBUFS
                    && errno.0 != EAGAIN
                    && errno.0 != EBUSY
                    && errno.0 != ENETDOWN
                {
                    return Err(Error::WakeTxQueue(errno));
                }
            }
        }
        Ok(())
    }

    pub fn prepare_frames(&mut self, num_frames: usize) -> Result<Vec<Frame>> {
        self.stack.pop_batch(num_frames)
    }

    pub fn send(&mut self, frames: &mut Vec<Frame>) -> Result<()> {
        let (mut idx_tx, ready) = loop {
            let (idx_tx, ready) = self.ring.reserve(frames.len() as u32);
            if ready > 0 {
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
