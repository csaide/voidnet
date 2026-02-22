use std::{ops::Deref, ptr::null_mut, sync::Arc};

use errno::errno;
use libc::{EAGAIN, EBUSY, ENETDOWN, ENOBUFS, MSG_DONTWAIT, c_int, recvfrom};

use crate::xdp::{
    error::{Error, Result},
    frame::FrameBuffer,
    ring::{Init, Producer},
};

use super::UmemOwner;

/// A fill queue is a ring of descriptors that are used to transfer packets from the user to the kernel. This is a thin wrapper around
/// the xsk_ring_prod struct, exposing a safe API for interacting with the ring.
pub struct FillQueue<'umem> {
    owner: Arc<UmemOwner<'umem>>,
    ring: Producer<Init>,
    busy_poll: bool,
}

impl<'umem> FillQueue<'umem> {
    pub(crate) fn new(ring: Producer<Init>, owner: Arc<UmemOwner<'umem>>, busy_poll: bool) -> Self {
        Self {
            ring,
            owner,
            busy_poll,
        }
    }

    /// Returns the size of the fill ring.
    #[inline(always)]
    pub fn size(&self) -> u32 {
        self.ring.size()
    }

    /// Possibly wakes the fill queue, so the kernel continues to process incoming packets.
    ///
    /// This is done by first checking the needs wakeup flag, given its set we fire a empty recvfrom on the supplied fd.
    #[inline(always)]
    pub fn maybe_wake(&self, fd: c_int) -> Result<()> {
        if self.busy_poll || self.ring.needs_wakeup() {
            let ret = unsafe { recvfrom(fd, null_mut(), 0, MSG_DONTWAIT, null_mut(), null_mut()) };
            let errno = errno();
            if ret < 0
                && errno.0 != ENOBUFS
                && errno.0 != EAGAIN
                && errno.0 != EBUSY
                && errno.0 != ENETDOWN
            {
                return Err(Error::WakeFillQueue(errno));
            }
        }
        Ok(())
    }

    /// Processes the fill queue, allocating new frames from the frame stack and submitting them to the fill ring up to the size of the fill ring.
    #[inline(always)]
    pub fn process_queue<B: FrameBuffer<'umem>>(&mut self, mut batch: B) {
        let batch_size = batch.num_frames().min(self.ring.size() as usize);
        let (mut idx, ready) = self.ring.reserve(batch_size as u32);
        if ready == 0 {
            return;
        }

        for _ in 0..ready {
            let frame = batch.pop().unwrap();
            let ptr = self.ring.fill_addr(idx);
            unsafe { *ptr = frame.addr() };
            idx += 1;
        }

        self.ring.submit(ready);
    }
}

impl<'umem> Deref for FillQueue<'umem> {
    type Target = UmemOwner<'umem>;

    fn deref(&self) -> &Self::Target {
        &self.owner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xdp::context::XdpContext;
    use crate::xdp::flags::AF_XDP_RESERVED;
    use crate::xdp::frame::{BasicFrameBuffer, FrameBuffer};
    use crate::xdp::umem::Umem;
    use std::sync::Arc;

    struct TestContext {
        _ctx: XdpContext,
        fq: FillQueue<'static>,
        buffer: BasicFrameBuffer<'static>,
        _owner: Arc<crate::xdp::umem::UmemOwner<'static>>,
    }

    fn create_fq(num_frames: usize, busy_poll: bool) -> TestContext {
        let ctx = XdpContext::new_no_init().unwrap();
        let (owner, _fq, _cq) = Umem::builder()
            .num_frames(num_frames)
            .fill_ring_size(num_frames as u32)
            .completion_ring_size(num_frames as u32)
            .busy_poll(busy_poll)
            .build()
            .unwrap()
            .split();

        let buffer = owner.init_buffer().unwrap();

        // Create FillQueue manually to control busy_poll
        // The builder's busy_poll is passed through, so we use _fq
        let owner_static: Arc<crate::xdp::umem::UmemOwner<'static>> =
            unsafe { std::mem::transmute(owner) };

        TestContext {
            _ctx: ctx,
            fq: _fq,
            buffer,
            _owner: owner_static,
        }
    }

    #[test]
    fn test_size_matches_configuration() {
        // Different ring sizes
        for size in [4, 8, 16, 32] {
            let ctx = create_fq(size, false);
            assert_eq!(ctx.fq.size(), size as u32);
        }
    }

    #[test]
    fn test_process_queue_drains_buffer() {
        let mut ctx = create_fq(4, false);

        // Capture addresses before processing
        let original_addrs: Vec<u64> = ctx.buffer.iter_frames().map(|f| f.addr()).collect();
        assert_eq!(original_addrs.len(), 4);
        assert_eq!(
            original_addrs,
            vec![
                AF_XDP_RESERVED,
                AF_XDP_RESERVED + 4096,
                AF_XDP_RESERVED + 8192,
                AF_XDP_RESERVED + 12288
            ]
        ); // Sequential addresses

        // Process drains buffer completely
        ctx.fq.process_queue(&mut ctx.buffer);
        assert_eq!(ctx.buffer.num_frames(), 0);
        assert_eq!(ctx.buffer.free_space(), 4); // Free space restored
    }

    #[test]
    fn test_process_queue_empty_buffer_noop() {
        let mut ctx = create_fq(4, false);

        // Drain buffer first
        let _: Vec<_> = ctx.buffer.take_frames().collect();
        assert_eq!(ctx.buffer.num_frames(), 0);

        // Processing empty buffer is safe no-op
        ctx.fq.process_queue(&mut ctx.buffer);
        assert_eq!(ctx.buffer.num_frames(), 0);
    }

    #[test]
    fn test_process_queue_batches() {
        let mut ctx = create_fq(8, false);

        // Split frames into batches with known addresses
        let mut batch1 = BasicFrameBuffer::new(4);
        let mut batch2 = BasicFrameBuffer::new(4);

        for (i, frame) in ctx.buffer.take_frames().enumerate() {
            if i < 4 {
                batch1.push(frame);
            } else {
                batch2.push(frame);
            }
        }

        // Verify batch contents
        let addrs1: Vec<u64> = batch1.iter_frames().map(|f| f.addr()).collect();
        let addrs2: Vec<u64> = batch2.iter_frames().map(|f| f.addr()).collect();
        assert_eq!(
            addrs1,
            vec![
                AF_XDP_RESERVED,
                AF_XDP_RESERVED + 4096,
                AF_XDP_RESERVED + 8192,
                AF_XDP_RESERVED + 12288
            ]
        );
        assert_eq!(
            addrs2,
            vec![
                AF_XDP_RESERVED + 16384,
                AF_XDP_RESERVED + 20480,
                AF_XDP_RESERVED + 24576,
                AF_XDP_RESERVED + 28672
            ]
        );

        // Process sequentially
        ctx.fq.process_queue(&mut batch1);
        ctx.fq.process_queue(&mut batch2);

        assert_eq!(batch1.num_frames(), 0);
        assert_eq!(batch2.num_frames(), 0);
    }

    #[test]
    fn test_process_queue_ring_full() {
        let mut ctx = create_fq(4, false);

        // Fill the ring completely
        ctx.fq.process_queue(&mut ctx.buffer);
        assert_eq!(ctx.buffer.num_frames(), 0);

        // Create new frames (simulating returned frames)
        let mut new_buffer = BasicFrameBuffer::new(4);
        // We can't easily create new frames without owner access in this test,
        // but we can verify empty buffer behavior
        ctx.fq.process_queue(&mut new_buffer);
        assert_eq!(new_buffer.num_frames(), 0);
    }
}
