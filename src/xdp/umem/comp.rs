use std::sync::Arc;

use libxdp_sys::xsk_ring_cons;

use crate::{
    futures::CompFuture,
    xdp::{
        frame::FrameBuffer,
        ring::{Consumer, Init},
        socket::SocketTx,
    },
};

use super::UmemOwner;

pub struct CompletionQueue {
    ring: Consumer<Init>,
    owner: Arc<UmemOwner>,
}

impl CompletionQueue {
    pub fn new(ring: Consumer<Init>, owner: Arc<UmemOwner>) -> Self {
        Self { ring, owner }
    }

    #[inline(always)]
    pub fn process_queue<B: FrameBuffer>(&mut self, mut batch: B) {
        let (mut idx, ready) = self.ring.peek(batch.free_space() as u32);
        if ready == 0 {
            return;
        }

        for _ in 0..ready {
            let addr = self.ring.comp_addr(idx);
            // SAFETY: The address is valid because it is from the completion ring and kernel guarantees it is valid.
            // a length of 0 is always valid.
            batch.push(unsafe { self.owner.to_frame(addr, 0, false) });
            idx += 1;
        }

        self.ring.release(ready as u32);
    }

    #[inline(always)]
    pub fn process_queue_async<'a, 'b, B: FrameBuffer>(
        &'a mut self,
        batch: B,
        expected: usize,
        socket: &'b mut SocketTx,
    ) -> CompFuture<'a, 'b, B> {
        CompFuture {
            completion_queue: self,
            socket,
            batch,
            expected,
        }
    }

    pub fn as_mut(&mut self) -> *mut xsk_ring_cons {
        self.ring.as_mut_ptr()
    }

    #[inline(always)]
    pub fn as_ref(&self) -> *const xsk_ring_cons {
        self.ring.as_ptr()
    }
}
