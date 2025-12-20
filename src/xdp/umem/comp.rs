use std::sync::Arc;

use libxdp_sys::xsk_ring_cons;

use crate::xdp::ring::Consumer;

use super::{FrameStack, Umem};

pub struct CompletionQueue {
    _umem: Arc<Umem>,
    ring: Consumer,
    stack: Arc<FrameStack>,
}

impl CompletionQueue {
    pub fn new(umem: Arc<Umem>, ring: Consumer, stack: Arc<FrameStack>) -> Self {
        Self {
            _umem: umem,
            ring,
            stack,
        }
    }

    pub fn process_queue(&mut self) {
        let (mut idx, ready) = self.ring.peek(u32::MAX);
        if ready == 0 {
            return;
        }

        for _ in 0..ready {
            let addr = self.ring.comp_addr(idx);
            self.stack
                .push(addr)
                .expect("Some how we ran out of frames.");
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
