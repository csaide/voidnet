use std::{collections::VecDeque, sync::Arc};

use libxdp_sys::xsk_ring_cons;

use crate::xdp_v2::{
    frame::{Frame, FrameStack},
    ring::Consumer,
};

pub struct CompletionQueue {
    ring: Consumer,
    stack: Arc<FrameStack>,
}

impl CompletionQueue {
    pub fn new(ring: Consumer, stack: Arc<FrameStack>) -> Self {
        Self { ring, stack }
    }

    pub fn process_queue(&mut self, batch: &mut VecDeque<Frame>) {
        let (mut idx, ready) = self.ring.peek((batch.capacity() - batch.len()) as u32);
        if ready == 0 {
            return;
        }

        for _ in 0..ready {
            let addr = self.ring.comp_addr(idx);
            batch.push_back(self.stack.to_frame(addr, 0));
            idx += 1;
        }

        self.ring.release(ready as u32);
    }

    pub fn as_mut(&mut self) -> *mut xsk_ring_cons {
        self.ring.as_mut()
    }

    pub fn as_ref(&self) -> *const xsk_ring_cons {
        self.ring.as_ref()
    }
}
