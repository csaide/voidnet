use std::{ops::Deref, sync::Arc};

use libc::XDP_PKT_CONTD;
use libxdp_sys::XSK_UNALIGNED_BUF_ADDR_MASK;

use crate::xdp::{
    error::{NonBlocking, WouldBlock},
    frame::FrameBuffer,
    futures::RecvFuture,
    ring::{Consumer, Init},
};

use super::SocketOwner;

pub struct SocketRx<'umem> {
    socket: Arc<SocketOwner<'umem>>,
    ring: Consumer<Init>,
}

impl<'umem> SocketRx<'umem> {
    pub fn new(socket: Arc<SocketOwner<'umem>>, ring: Consumer<Init>) -> Self {
        Self { socket, ring }
    }

    #[inline(always)]
    pub fn fd(&self) -> i32 {
        self.socket.fd()
    }

    #[inline(always)]
    pub fn recv<B: FrameBuffer<'umem>>(&mut self, mut batch: B) -> NonBlocking<u32> {
        // Take at least 1 frame up to the number of free slots in the batch.
        let (mut idx_rx, rcvd) = self.ring.peek(batch.free_space() as u32);
        if rcvd == 0 {
            return Err(WouldBlock);
        }

        for _ in 0..rcvd as usize {
            let desc = self.ring.rx_desc(idx_rx);
            // SAFETY: The address/length/options are valid because it is from the RX ring and kernel guarantees them.
            batch.push(self.socket.umem().to_frame(
                desc.addr & XSK_UNALIGNED_BUF_ADDR_MASK,
                desc.len as usize,
                desc.options & XDP_PKT_CONTD == XDP_PKT_CONTD,
            ));
            idx_rx += 1;
        }

        self.ring.release(rcvd);
        Ok(rcvd)
    }

    #[inline(always)]
    pub fn recv_async<B: FrameBuffer<'umem>>(&mut self, batch: B) -> RecvFuture<'_, 'umem, B> {
        RecvFuture {
            socket: self,
            batch,
        }
    }
}

impl<'umem> Deref for SocketRx<'umem> {
    type Target = SocketOwner<'umem>;

    fn deref(&self) -> &Self::Target {
        &self.socket
    }
}
