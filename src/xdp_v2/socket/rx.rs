use std::{collections::VecDeque, sync::Arc};

use crate::xdp_v2::{
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

    pub fn recv(&mut self, batch: &mut VecDeque<Frame>) -> usize {
        let (mut idx_rx, rcvd) = self.ring.peek((batch.capacity() - batch.len()) as u32);
        if rcvd == 0 {
            return 0;
        }

        for _ in 0..rcvd as usize {
            let desc = self.ring.rx_desc(idx_rx);
            batch.push_back(self.stack.to_frame(desc.addr, desc.len as usize));
            idx_rx += 1;
        }

        self.ring.release(rcvd);
        rcvd as usize
    }
}
