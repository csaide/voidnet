use std::{
    os::raw::{c_int, c_void},
    sync::Arc,
};

use errno::errno;
use libxdp_sys::{
    XDP_UMEM_UNALIGNED_CHUNK_FLAG, XSK_RING_CONS__DEFAULT_NUM_DESCS,
    XSK_RING_PROD__DEFAULT_NUM_DESCS, XSK_UMEM__DEFAULT_FRAME_HEADROOM,
    XSK_UMEM__DEFAULT_FRAME_SIZE, libxdp_get_error, xsk_umem__create_opts, xsk_umem_opts,
};
use memmap2::MmapOptions;

use crate::xdp::{
    context::XdpContext,
    error::{Error, Result},
    frame::{Frame, FrameBuffer},
    ring::{Consumer, Producer},
};

#[cfg(feature = "local")]
use crate::xdp::futures::LocalUmem;
#[cfg(feature = "smol")]
use crate::xdp::futures::SmolUmem;
#[cfg(feature = "tokio")]
use crate::xdp::futures::TokioUmem;

use super::{CompletionQueue, FillQueue, UmemOwner};

/// A builder for creating a new [Umem] instance.
pub struct UmemBuilder<'ctx> {
    ctx: &'ctx mut XdpContext,
    completion_ring_size: u32,
    fill_ring_size: u32,
    frame_size: usize,
    num_frames: Option<usize>,
    busy_poll: bool,
    huge_tables: bool,
    unaligned: bool,
}

impl<'ctx> UmemBuilder<'ctx> {
    fn new(ctx: &'ctx mut XdpContext) -> Self {
        let completion_ring_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
        let fill_ring_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
        let frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE as usize;
        Self {
            ctx,
            completion_ring_size,
            fill_ring_size,
            frame_size,
            num_frames: None,
            busy_poll: false,
            huge_tables: false,
            unaligned: false,
        }
    }

    /// Sets the size of the completion ring, the maximum number of frames that can be outstanding in the completion ring.
    ///
    /// Note this value must be a power of two.
    pub fn completion_ring_size(mut self, completion_ring_size: u32) -> Self {
        self.completion_ring_size = completion_ring_size;
        self
    }

    /// Sets the size of the fill ring, the maximum number of frames that can be outstanding in the fill ring.
    ///
    /// Note this value must be a power of two.
    pub fn fill_ring_size(mut self, fill_ring_size: u32) -> Self {
        self.fill_ring_size = fill_ring_size;
        self
    }

    /// Sets the size of the frame, the size of each frame in the UMEM.
    ///
    /// Note this value must be a power of two.
    pub fn frame_size(mut self, frame_size: usize) -> Self {
        self.frame_size = frame_size;
        self
    }

    /// Sets the total number of frames in the UMEM.
    ///
    /// Note this value is optional, if not set it will be calculated as the sum of the completion and fill ring sizes.
    pub fn num_frames(mut self, num_frames: usize) -> Self {
        self.num_frames = Some(num_frames);
        self
    }

    /// Sets whether to use busy polling for the UMEM.
    pub fn busy_poll(mut self, busy_poll: bool) -> Self {
        self.busy_poll = busy_poll;
        self
    }

    /// Sets whether to use huge tables for the UMEM.
    pub fn huge_tables(mut self, huge_tables: bool) -> Self {
        self.huge_tables = huge_tables;
        self
    }

    /// Sets whether to use unaligned chunks for the UMEM.
    pub fn unaligned(mut self, unaligned: bool) -> Self {
        self.unaligned = unaligned;
        self
    }

    fn build_internal<'umem>(&mut self) -> Result<Umem<'umem>> {
        if self.frame_size & (self.frame_size - 1) != 0 && !self.unaligned {
            return Err(Error::InvalidFrameSize(self.frame_size));
        }
        if self.fill_ring_size & (self.fill_ring_size - 1) != 0 {
            return Err(Error::InvalidFillRingSize(self.fill_ring_size));
        }
        if self.completion_ring_size & (self.completion_ring_size - 1) != 0 {
            return Err(Error::InvalidCompletionRingSize(self.completion_ring_size));
        }

        let num_frames = self
            .num_frames
            .unwrap_or_else(|| (self.completion_ring_size + self.fill_ring_size) as usize);

        Umem::new(
            self.ctx,
            self.completion_ring_size,
            self.fill_ring_size,
            self.busy_poll,
            num_frames,
            self.frame_size,
            self.huge_tables,
            self.unaligned,
        )
    }

    /// Builds the Umem.
    pub fn build<'umem>(mut self) -> Result<Umem<'umem>> {
        self.build_internal()
    }

    /// Builds the Umem as a Tokio Umem.
    #[cfg(feature = "tokio")]
    pub fn build_tokio<'umem>(mut self) -> Result<TokioUmem<'umem>> {
        let (owner, fq, cq) = self.build_internal()?.split();
        let async_fd = self.ctx.get_tokio_fd(owner.fd())?;

        Ok(TokioUmem::new(owner, fq, cq, async_fd))
    }

    #[cfg(feature = "local")]
    pub fn build_local<'umem>(self) -> Result<LocalUmem<'umem>> {
        let (owner, fq, cq) = self.build()?.split();

        Ok(LocalUmem::new(owner, fq, cq)?)
    }

    #[cfg(feature = "smol")]
    pub fn build_smol<'umem>(mut self) -> Result<SmolUmem<'umem>> {
        let (owner, fq, cq) = self.build_internal()?.split();
        let async_fd = self.ctx.get_smol_fd(owner.fd())?;

        Ok(SmolUmem::new(owner, fq, cq, async_fd))
    }
}

/// A high level wrapper around a kernel UMEM object.
///
/// This wraps the UmemOwner, FillQueue, and CompletionQueue objects and provides a safe API for interacting with the UMEM.
pub struct Umem<'umem> {
    owner: Arc<UmemOwner<'umem>>,
    fill_queue: FillQueue<'umem>,
    completion_queue: CompletionQueue<'umem>,
}

impl<'umem> Umem<'umem> {
    /// Returns a builder for creating a new [Umem] instance.
    pub fn builder<'ctx>(ctx: &'ctx mut XdpContext) -> UmemBuilder<'ctx> {
        UmemBuilder::new(ctx)
    }

    fn new(
        _ctx: &mut XdpContext,
        completion_ring_size: u32,
        fill_ring_size: u32,
        busy_poll: bool,
        num_frames: usize,
        frame_size: usize,
        huge_tables: bool,
        unaligned: bool,
    ) -> Result<Self> {
        let size = (num_frames * frame_size) as u64;

        let mut opts = xsk_umem_opts {
            sz: size_of::<xsk_umem_opts>(),
            fd: 0,
            size: size,
            fill_size: fill_ring_size,
            comp_size: completion_ring_size,
            frame_size: frame_size as u32,
            frame_headroom: XSK_UMEM__DEFAULT_FRAME_HEADROOM,
            flags: if unaligned {
                XDP_UMEM_UNALIGNED_CHUNK_FLAG
            } else {
                0
            },
            tx_metadata_len: 0,
        };

        let mut comp_ring = Consumer::new();
        let mut fill_ring = Producer::new();

        let mut map_opts = MmapOptions::new();
        map_opts.len(num_frames * frame_size);
        if huge_tables {
            map_opts.huge(None);
        }
        let mut mmap = map_opts.map_anon().map_err(|e| Error::MmapAllocate(e))?;

        let umem = unsafe {
            xsk_umem__create_opts(
                mmap.as_mut_ptr() as *mut c_void,
                fill_ring.as_mut_ptr(),
                comp_ring.as_mut_ptr(),
                &mut opts,
            )
        };
        let err = unsafe { libxdp_get_error(umem as *const _) };
        if err < 0 {
            return Err(Error::CreateUmem(errno()));
        }

        let fill_ring = unsafe { fill_ring.assume_init() };
        let comp_ring = unsafe { comp_ring.assume_init() };

        let owner = Arc::new(UmemOwner::new(umem, Arc::new(mmap), frame_size, num_frames));
        let fq = FillQueue::new(fill_ring, owner.clone(), busy_poll);
        let cq = CompletionQueue::new(comp_ring, owner.clone());

        Ok(Self {
            owner,
            fill_queue: fq,
            completion_queue: cq,
        })
    }

    /// Splits the umem into its owner, fill queue, and completion queue components.
    #[inline(always)]
    pub fn split(
        self,
    ) -> (
        Arc<UmemOwner<'umem>>,
        FillQueue<'umem>,
        CompletionQueue<'umem>,
    ) {
        (self.owner, self.fill_queue, self.completion_queue)
    }

    /// Returns the owner of the umem.
    #[inline(always)]
    pub fn owner(&self) -> &Arc<UmemOwner<'umem>> {
        &self.owner
    }

    /// Initialize the frame buffer with the frames from the UMEM, its then up to the caller what to do with these frames, you can push them into the fill queue, use them
    /// for writing packets, or some combination of the two. This can only be called once on the [UmemOwner] instance, and will return None on every subsequent call.
    pub fn init_buffer<B: FrameBuffer<'umem> + FromIterator<Frame<'umem>>>(&self) -> Option<B> {
        self.owner.init_buffer()
    }

    /// Possibly wakes the fill queue, so the kernel continues to process incoming packets.
    ///
    /// This is done by first checking the needs wakeup flag, given its set we fire a empty recvfrom on the supplied fd.
    #[inline(always)]
    pub fn maybe_wake_fill_queue(&self, fd: c_int) -> Result<()> {
        self.fill_queue.maybe_wake(fd)
    }

    /// Processes the fill queue, allocating new frames from the frame stack and submitting them to the fill ring up to the size of the fill ring.
    #[inline(always)]
    pub fn process_fill_queue<B: FrameBuffer<'umem>>(&mut self, batch: B) {
        self.fill_queue.process_queue(batch)
    }

    /// Processes the completion queue, allocating new frames from the frame stack and submitting them to the completion ring up to the size of the completion ring.
    #[inline(always)]
    pub fn process_completion_queue<B: FrameBuffer<'umem>>(&mut self, batch: B) {
        self.completion_queue.process_queue(batch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xdp::frame::{BasicFrameBuffer, FrameBuffer};

    #[test]
    fn test_builder_defaults() {
        let mut ctx = XdpContext::new_no_init().unwrap();
        let b = UmemBuilder::new(&mut ctx);

        assert_eq!(b.frame_size, XSK_UMEM__DEFAULT_FRAME_SIZE as usize);
        assert_eq!(b.fill_ring_size, XSK_RING_PROD__DEFAULT_NUM_DESCS);
        assert_eq!(b.completion_ring_size, XSK_RING_CONS__DEFAULT_NUM_DESCS);
        assert_eq!(b.num_frames, None);
        assert!(!b.busy_poll && !b.huge_tables && !b.unaligned);
    }

    #[test]
    fn test_validation() {
        let mut ctx = XdpContext::new_no_init().unwrap();
        // Frame size not power of 2
        assert!(matches!(
            Umem::builder(&mut ctx)
                .frame_size(3000)
                .fill_ring_size(8)
                .completion_ring_size(8)
                .build(),
            Err(Error::InvalidFrameSize(3000))
        ));

        // Fill ring not power of 2
        assert!(matches!(
            Umem::builder(&mut ctx)
                .fill_ring_size(7)
                .completion_ring_size(8)
                .build(),
            Err(Error::InvalidFillRingSize(7))
        ));

        // Completion ring not power of 2
        assert!(matches!(
            Umem::builder(&mut ctx)
                .fill_ring_size(8)
                .completion_ring_size(5)
                .build(),
            Err(Error::InvalidCompletionRingSize(5))
        ));

        // Unaligned mode bypasses frame_size power-of-2 check
        assert!(
            Umem::builder(&mut ctx)
                .frame_size(3000)
                .fill_ring_size(4)
                .completion_ring_size(4)
                .unaligned(true)
                .build()
                .is_ok()
        );
    }

    #[test]
    fn test_build() {
        // Test with explicit num_frames
        let mut ctx = XdpContext::new_no_init().unwrap();
        let (owner, fq, _cq) = Umem::builder(&mut ctx)
            .num_frames(8)
            .frame_size(2048)
            .fill_ring_size(8)
            .completion_ring_size(8)
            .build()
            .unwrap()
            .split();

        assert!(!owner.as_ptr().is_null());
        assert_eq!(fq.size(), 8);

        let buffer: BasicFrameBuffer<'_> = owner.init_buffer().unwrap();
        assert_eq!(buffer.num_frames(), 8);
        assert!(buffer.iter_frames().all(|f| f.capacity() == 2048));

        // Test num_frames defaults to fill + completion ring sizes
        let (owner, _, _) = Umem::builder(&mut ctx)
            .fill_ring_size(8)
            .completion_ring_size(4)
            .build()
            .unwrap()
            .split();

        let buffer: BasicFrameBuffer<'_> = owner.init_buffer().unwrap();
        assert_eq!(buffer.num_frames(), 12); // 8 + 4
    }
}
