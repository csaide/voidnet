use std::sync::Arc;

use libxdp_sys::xsk_ring_cons;

use crate::xdp_v2::{frame::FrameStack, ring::Consumer};

pub struct CompletionQueue {
    ring: Consumer,
    stack: Arc<FrameStack>,
    batch: Vec<u64>,
}

impl CompletionQueue {
    pub fn new(ring: Consumer, stack: Arc<FrameStack>) -> Self {
        let batch = Vec::with_capacity(ring.size() as usize);
        Self { ring, stack, batch }
    }

    pub fn process_queue(&mut self) {
        let (mut idx, ready) = self.ring.peek(self.batch.capacity() as u32);
        if ready == 0 {
            return;
        }

        for _ in 0..ready {
            let addr = self.ring.comp_addr(idx);
            self.batch.push(addr);
            idx += 1;
        }

        self.ring.release(ready as u32);
        self.stack.push_addrs(&mut self.batch);
    }

    pub fn as_mut(&mut self) -> *mut xsk_ring_cons {
        self.ring.as_mut()
    }

    pub fn as_ref(&self) -> *const xsk_ring_cons {
        self.ring.as_ref()
    }
}
