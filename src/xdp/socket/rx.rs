use std::{collections::VecDeque, sync::Arc};

use libc::XDP_PKT_CONTD;

use crate::xdp::{
    frame::{Frame, FrameStack},
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
    pub fn recv(&mut self, batch: &mut VecDeque<Frame>) -> std::result::Result<u32, ()> {
        let (mut idx_rx, rcvd) = self.ring.peek((batch.capacity() - batch.len()) as u32);
        if rcvd == 0 {
            return Err(());
        }

        for _ in 0..rcvd as usize {
            let desc = self.ring.rx_desc(idx_rx);
            batch.push_back(self.stack.to_frame(
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
