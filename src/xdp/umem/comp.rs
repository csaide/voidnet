use std::{marker::PhantomData, mem::transmute, sync::Arc};

use libxdp_sys::xsk_ring_cons;

use crate::{
    futures::CompFuture,
    xdp::{
        frame_v2::{Frame, FrameBuffer},
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
    pub fn process_queue<'umem, B: FrameBuffer<'umem>>(&mut self, mut batch: B) {
        let (mut idx, ready) = self.ring.peek(batch.free_space() as u32);
        if ready == 0 {
            return;
        }

        for _ in 0..ready {
            let addr = self.ring.comp_addr(idx);
            // SAFETY: The address is valid because it is from the completion ring and kernel guarantees it is valid.
            // a length of 0 is always valid.
            let frame = self.owner.to_frame(addr, 0, false);
            let frame = unsafe { transmute::<Frame<'_>, Frame<'umem>>(frame) };
            batch.push(frame);
            idx += 1;
        }

        self.ring.release(ready as u32);
    }

    #[inline(always)]
    pub fn process_queue_async<'s, 'umem, 'sock, B: FrameBuffer<'umem>>(
        &'s mut self,
        batch: B,
        expected: usize,
        socket: &'sock mut SocketTx,
    ) -> CompFuture<'s, 'umem, 'sock, B> {
        CompFuture {
            completion_queue: self,
            socket,
            batch,
            expected,
            _lifetime: PhantomData,
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
