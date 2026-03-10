use std::{ops::Deref, ptr::null, sync::Arc};

use errno::errno;
use libc::{EAGAIN, EBUSY, ENETDOWN, ENOBUFS, MSG_DONTWAIT, XDP_PKT_CONTD, sendto};

use crate::xdp::{
    error::{Error, NonBlocking, Result, WouldBlock},
    frame::FrameBuffer,
    ring::{Init, Producer},
};

use super::SocketOwner;

/// A socket transmitter for writing packets to an XDP socket.
pub struct SocketTx<'umem> {
    socket: Arc<SocketOwner<'umem>>,
    ring: Producer<Init>,
    busy_poll: bool,
}

impl<'umem> SocketTx<'umem> {
    pub(crate) fn new(
        socket: Arc<SocketOwner<'umem>>,
        ring: Producer<Init>,
        busy_poll: bool,
    ) -> Self {
        Self {
            socket,
            ring,
            busy_poll,
        }
    }

    /// Returns the file descriptor of the socket.
    #[inline(always)]
    pub fn fd(&self) -> i32 {
        self.socket.fd()
    }

    /// Possibly wakes the tx queue, so the kernel continues to process outgoing packets. This first checks if either busy poll is enabled or the ring needs a wakeup, before
    /// executing a sendto system call. This will kick the TX processing in the kernel to activate.
    #[inline(always)]
    pub fn maybe_wake(&self) -> Result<()> {
        if self.busy_poll || self.ring.needs_wakeup() {
            let ret = unsafe { sendto(self.socket.fd(), null(), 0, MSG_DONTWAIT, null(), 0) };
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

    /// Sends a batch of frames to the socket.
    #[inline(always)]
    pub fn send<B: FrameBuffer<'umem>>(&mut self, mut frames: B) -> NonBlocking<u32> {
        // Take exactly the number of frames we need to send.
        let batch_size = frames.num_frames().min(self.ring.size() as usize);
        let (mut idx_tx, ready) = self.ring.reserve(batch_size as u32);
        if ready == 0 {
            return Err(WouldBlock);
        }

        for _ in 0..ready {
            let frame = frames.pop().unwrap();
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
}

impl<'umem> Deref for SocketTx<'umem> {
    type Target = SocketOwner<'umem>;

    fn deref(&self) -> &Self::Target {
        &self.socket
    }
}
