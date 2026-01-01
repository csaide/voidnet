use std::{ptr::null, sync::Arc};

use errno::errno;
use libc::{EAGAIN, EBUSY, ENETDOWN, ENOBUFS, MSG_DONTWAIT, XDP_PKT_CONTD, sendto};

use crate::{
    futures::SendFuture,
    xdp::{
        error::{Error, NonBlocking, Result, WouldBlock},
        frame::FrameBuffer,
        ring::{Init, Producer},
    },
};

use super::SocketOwner;

pub struct SocketTx {
    socket: Arc<SocketOwner>,
    ring: Producer<Init>,
    busy_poll: bool,
}

impl SocketTx {
    pub fn new(socket: Arc<SocketOwner>, ring: Producer<Init>, busy_poll: bool) -> Self {
        Self {
            socket,
            ring,
            busy_poll,
        }
    }

    #[inline(always)]
    pub fn maybe_wake(&self) -> Result<()> {
        if self.busy_poll || self.ring.needs_wakeup() {
            let ret = unsafe { sendto(self.socket.fd, null(), 0, MSG_DONTWAIT, null(), 0) };
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
        Ok(())
    }

    #[inline(always)]
    pub fn send<B: FrameBuffer>(&mut self, mut frames: B) -> NonBlocking<u32> {
        // Take exactly the number of frames we need to send.
        let (mut idx_tx, ready) = self.ring.reserve(frames.num_frames() as u32);
        if ready == 0 {
            return Err(WouldBlock);
        }

        for frame in frames.take_frames() {
            let desc = self.ring.tx_desc(idx_tx);
            unsafe {
                (*desc).addr = frame.addr();
                (*desc).len = frame.len() as u32;
                (*desc).options = if frame.is_fragment() {
                    XDP_PKT_CONTD
                } else {
                    0
                };
            }
            idx_tx += 1;
        }

        self.ring.submit(ready);
        Ok(ready)
    }

    #[inline(always)]
    pub fn send_async<B: FrameBuffer>(&mut self, batch: B) -> SendFuture<'_, B> {
        SendFuture {
            socket: self,
            batch,
        }
    }
}
