use std::{ops::Deref, sync::Arc};

use crate::xdp::{
    error::{NonBlocking, WouldBlock},
    frame::FrameBuffer,
    ring::{Consumer, Init},
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

    /// Processes the completion queue, allocating new frames from the frame stack and submitting them to the completion ring up to the size of the completion ring.
    #[inline(always)]
    pub fn process_queue<B: FrameBuffer<'umem>>(&mut self, mut batch: B) -> NonBlocking<u32> {
        let (mut idx, ready) = self.ring.peek(batch.free_space() as u32);
        if ready != batch.free_space() as u32 {
            self.ring.cancel(ready);
            return Err(WouldBlock);
        }

        for _ in 0..ready {
            let addr = self.ring.comp_addr(idx);
            // SAFETY: The address is valid because it is from the completion ring and kernel guarantees it is valid.
            // a length of 0 is always valid.
            batch.push(self.owner.to_frame(addr, 0, false));
            idx += 1;
        }

        self.ring.release(ready as u32);
        Ok(ready)
    }
}

impl<'umem> Deref for CompletionQueue<'umem> {
    type Target = UmemOwner<'umem>;

    fn deref(&self) -> &Self::Target {
        &self.owner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xdp::context::XdpContext;
    use crate::xdp::frame::{BasicFrameBuffer, FrameBuffer};
    use crate::xdp::umem::Umem;
    use std::sync::Arc;

    struct TestContext {
        _ctx: XdpContext,
        cq: CompletionQueue<'static>,
        _owner: Arc<crate::xdp::umem::UmemOwner<'static>>,
    }

    fn create_cq(num_frames: usize) -> TestContext {
        let mut ctx = XdpContext::new_no_init().unwrap();
        let (owner, _fq, cq) = Umem::builder(&mut ctx)
            .num_frames(num_frames)
            .fill_ring_size(num_frames as u32)
            .completion_ring_size(num_frames as u32)
            .build()
            .unwrap()
            .split();

        let owner_static: Arc<crate::xdp::umem::UmemOwner<'static>> =
            unsafe { std::mem::transmute(owner) };

        TestContext {
            _ctx: ctx,
            cq,
            _owner: owner_static,
        }
    }

    #[test]
    fn test_process_queue_empty_ring() {
        let mut ctx = create_cq(8);
        let mut buffer = BasicFrameBuffer::new(8);

        // No TX completions, ring is empty
        assert_eq!(buffer.num_frames(), 0);
        assert_eq!(buffer.free_space(), 8);

        let e = ctx.cq.process_queue(&mut buffer).unwrap_err();
        assert_eq!(e, WouldBlock);

        // Still empty — no frames to complete
        assert_eq!(buffer.num_frames(), 0);
        assert_eq!(buffer.free_space(), 8);
    }

    #[test]
    fn test_process_queue_zero_free_space() {
        let mut ctx = create_cq(4);

        // Buffer with zero free space (full)
        let mut buffer = BasicFrameBuffer::new(0);
        assert_eq!(buffer.free_space(), 0);

        // Should be no-op even if ring had completions
        ctx.cq.process_queue(&mut buffer).unwrap();
        assert_eq!(buffer.num_frames(), 0);
    }

    #[test]
    fn test_process_queue_limited_free_space() {
        let mut ctx = create_cq(8);

        // Buffer that can only hold 2 frames
        let mut buffer = BasicFrameBuffer::new(2);
        assert_eq!(buffer.free_space(), 2);
        assert_eq!(buffer.num_frames(), 0);

        // Process queue respects free_space limit
        // (Ring is empty, so no frames added, but tests the path)
        let e = ctx.cq.process_queue(&mut buffer).unwrap_err();
        assert_eq!(e, WouldBlock);
        assert_eq!(buffer.num_frames(), 0);
    }

    #[test]
    fn test_process_queue_multiple_calls() {
        let mut ctx = create_cq(8);
        let mut buffer = BasicFrameBuffer::new(8);

        // Multiple calls on empty ring are safe
        for _ in 0..5 {
            let e = ctx.cq.process_queue(&mut buffer).unwrap_err();
            assert_eq!(e, WouldBlock);
            assert_eq!(buffer.num_frames(), 0);
        }
    }

    #[test]
    fn test_different_ring_sizes() {
        // Verify completion queue works with various sizes
        for size in [4, 8, 16, 32] {
            let mut ctx = create_cq(size);
            let mut buffer = BasicFrameBuffer::new(size);

            let e = ctx.cq.process_queue(&mut buffer).unwrap_err();
            assert_eq!(e, WouldBlock);
            assert_eq!(buffer.num_frames(), 0);
        }
    }
}
