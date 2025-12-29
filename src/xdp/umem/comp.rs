use std::sync::Arc;

use libxdp_sys::xsk_ring_cons;

use crate::xdp::{
    frame::{FrameBuffer, FrameStack},
    ring::{Consumer, Init},
};

pub struct CompletionQueue {
    ring: Consumer<Init>,
    stack: Arc<FrameStack>,
}

impl CompletionQueue {
    pub fn new(ring: Consumer<Init>, stack: Arc<FrameStack>) -> Self {
        Self { ring, stack }
    }

    #[inline(always)]
    pub fn process_queue<B: FrameBuffer>(&mut self, mut batch: B) {
        let (mut idx, ready) = self.ring.peek(batch.free_space() as u32);
        if ready == 0 {
            return;
        }

        for _ in 0..ready {
            let addr = self.ring.comp_addr(idx);
            batch.push(self.stack.to_frame(addr, 0, false));
            idx += 1;
        }

        self.ring.release(ready as u32);
    }

    #[inline(always)]
    pub fn as_mut(&mut self) -> *mut xsk_ring_cons {
        self.ring.as_mut_ptr()
    }

    #[inline(always)]
    pub fn as_ref(&self) -> *const xsk_ring_cons {
        self.ring.as_ptr()
    }
}
