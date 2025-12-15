use std::{cmp::min, sync::Arc};

use crate::xdp::umem::Umem;
use crate::xdp::{ring::Consumer, umem::Frame};

use super::{Error, Result, SocketOwner};

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

    pub fn recv(&mut self, batch_size: u32) -> Result<Vec<Frame>> {
        let batch_size = match self.ring.available() {
            Some(available) => min(batch_size, available),
            None => return Err(Error::WouldBlock),
        };

        let (mut idx_rx, rcvd) = match self.ring.peek(batch_size) {
            Some((idx, rcvd)) if rcvd > 0 => (idx, rcvd),
            _ => return Err(Error::WouldBlock),
        };

        let mut batch = Vec::with_capacity(rcvd as usize);
        for _ in 0..rcvd {
            let desc = self.ring.rx_desc(idx_rx);
            batch.push(self.umem.get_read_frame(desc.addr, desc.len as usize));
            idx_rx += 1;
        }

        self.ring.release(rcvd);
        Ok(batch)
    }
}
