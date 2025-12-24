use std::sync::Arc;

use libc::XDP_PKT_CONTD;

use crate::xdp::{
    error::{NonBlocking, WouldBlock},
    frame::{FrameBuffer, FrameStack},
    ring::Consumer,
};

use super::SocketOwner;

pub struct SocketRx {
    _socket: Arc<SocketOwner>,
    ring: Consumer,
    stack: Arc<FrameStack>,
}

impl SocketRx {
    pub fn new(socket: Arc<SocketOwner>, ring: Consumer, stack: Arc<FrameStack>) -> Self {
        Self {
            _socket: socket,
            ring,
            stack,
        }
    }

    #[inline(always)]
    pub fn recv<B: FrameBuffer>(&mut self, mut batch: B) -> NonBlocking<u32> {
        let (mut idx_rx, rcvd) = self.ring.peek((batch.capacity() - batch.len()) as u32);
        if rcvd == 0 {
            return Err(WouldBlock);
        }

        for _ in 0..rcvd as usize {
            let desc = self.ring.rx_desc(idx_rx);
            batch.push(self.stack.to_frame(
                desc.addr,
                desc.len as usize,
                desc.options & XDP_PKT_CONTD == XDP_PKT_CONTD,
            ));
            idx_rx += 1;
        }

        self.ring.release(rcvd);
        Ok(rcvd)
    }
}
