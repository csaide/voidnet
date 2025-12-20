use std::sync::Arc;

use crate::xdp::{
    ring::Consumer,
    umem::{Frame, Umem},
};

use super::SocketOwner;

pub struct SocketRx {
    _socket: Arc<SocketOwner>,
    ring: Consumer,
    umem: Arc<Umem>,
}

impl SocketRx {
    pub fn new(socket: Arc<SocketOwner>, ring: Consumer, umem: Arc<Umem>) -> Self {
        Self {
            _socket: socket,
            ring,
            umem,
        }
    }

    pub fn recv(&mut self, batch_size: u32) -> Vec<Frame> {
        let (mut idx_rx, rcvd) = self.ring.peek(batch_size);
        if rcvd == 0 {
            return Vec::new();
        }

        let mut batch = Vec::with_capacity(rcvd as usize);
        for _ in 0..rcvd {
            let desc = self.ring.rx_desc(idx_rx);
            batch.push(self.umem.get_read_frame(desc.addr, desc.len as usize));
            idx_rx += 1;
        }

        self.ring.release(rcvd);
        batch
    }
}
