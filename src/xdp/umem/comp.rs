use std::sync::Arc;

use crate::xdp::{
    frame::FrameBuffer,
    futures::CompFuture,
    ring::{Consumer, Init},
    socket::SocketTx,
};

use super::UmemOwner;

/// A completion queue is a ring of descriptors that are used to transfer packets from the kernel to the user. This is a thin wrapper around
/// the xsk_ring_cons struct, exposing a safe API for interacting with the ring.
pub struct CompletionQueue<'umem> {
    ring: Consumer<Init>,
    owner: Arc<UmemOwner<'umem>>,
}

impl<'umem> CompletionQueue<'umem> {
    /// Creates a new completion queue.
    pub(crate) fn new(ring: Consumer<Init>, owner: Arc<UmemOwner<'umem>>) -> Self {
        Self { ring, owner }
    }

    /// Returns the file descriptor of the completion queue, which is actually the file descriptor of the UMEM.
    #[inline(always)]
    pub(crate) fn fd(&self) -> i32 {
        self.owner.fd()
    }

    /// Processes the completion queue, allocating new frames from the frame stack and submitting them to the completion ring up to the size of the completion ring.
    #[inline(always)]
    pub fn process_queue<B: FrameBuffer<'umem>>(&mut self, mut batch: B) {
        let (mut idx, ready) = self.ring.peek(batch.free_space() as u32);
        if ready == 0 {
            return;
        }

        for _ in 0..ready {
            let addr = self.ring.comp_addr(idx);
            // SAFETY: The address is valid because it is from the completion ring and kernel guarantees it is valid.
            // a length of 0 is always valid.
            batch.push(self.owner.to_frame(addr, 0, false));
            idx += 1;
        }

        self.ring.release(ready as u32);
    }

    /// Processes the completion queue asynchronously, returning a future that will be ready when the completion queue is processed.
    #[inline(always)]
    pub fn process_queue_async<'que, 'sock, B: FrameBuffer<'umem>>(
        &'que mut self,
        batch: B,
        expected: usize,
        socket: &'sock mut SocketTx<'umem>,
    ) -> CompFuture<'que, 'umem, 'sock, B> {
        CompFuture {
            completion_queue: self,
            socket,
            batch,
            expected,
        }
    }
}
