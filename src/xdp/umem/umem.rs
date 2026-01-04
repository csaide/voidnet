use std::{ffi::c_int, os::raw::c_void, sync::Arc};

use errno::errno;
use libxdp_sys::{
    XDP_UMEM_UNALIGNED_CHUNK_FLAG, XSK_RING_CONS__DEFAULT_NUM_DESCS,
    XSK_RING_PROD__DEFAULT_NUM_DESCS, XSK_UMEM__DEFAULT_FRAME_HEADROOM,
    XSK_UMEM__DEFAULT_FRAME_SIZE, libxdp_get_error, xsk_umem, xsk_umem__create_opts, xsk_umem_opts,
};
use memmap2::MmapOptions;

use crate::{
    futures::{CompFuture, ProcessFillQueueFuture, WakeFillQueueFuture},
    xdp::{
        error::{Error, Result},
        frame::{Frame, FrameBuffer},
        ring::{Consumer, Producer},
        socket::SocketTx,
    },
};

use super::{CompletionQueue, FillQueue, UmemOwner};

/// A builder for creating a new [Umem] instance.
pub struct UmemBuilder {
    completion_ring_size: u32,
    fill_ring_size: u32,
    frame_size: usize,
    num_frames: usize,
    busy_poll: bool,
    huge_tables: bool,
    unaligned: bool,
}

impl UmemBuilder {
    pub fn new() -> Self {
        let completion_ring_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
        let fill_ring_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2;
        let frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE as usize;
        let busy_poll = false;
        Self {
            completion_ring_size,
            fill_ring_size,
            frame_size,
            num_frames: (completion_ring_size + fill_ring_size) as usize,
            busy_poll,
            huge_tables: false,
            unaligned: false,
        }
    }

    pub fn completion_ring_size(mut self, completion_ring_size: u32) -> Self {
        self.completion_ring_size = completion_ring_size;
        self
    }

    pub fn fill_ring_size(mut self, fill_ring_size: u32) -> Self {
        self.fill_ring_size = fill_ring_size;
        self
    }

    pub fn frame_size(mut self, frame_size: usize) -> Self {
        self.frame_size = frame_size;
        self
    }

    pub fn num_frames(mut self, num_frames: usize) -> Self {
        self.num_frames = num_frames;
        self
    }

    pub fn busy_poll(mut self, busy_poll: bool) -> Self {
        self.busy_poll = busy_poll;
        self
    }

    pub fn huge_tables(mut self, huge_tables: bool) -> Self {
        self.huge_tables = huge_tables;
        self
    }

    pub fn unaligned(mut self, unaligned: bool) -> Self {
        self.unaligned = unaligned;
        self
    }

    pub fn build<B: FrameBuffer + FromIterator<Frame>>(self) -> Result<(Umem, B)> {
        if self.frame_size & (self.frame_size - 1) != 0 && !self.unaligned {
            return Err(Error::InvalidFrameSize(self.frame_size));
        }
        if self.fill_ring_size & (self.fill_ring_size - 1) != 0 {
            return Err(Error::InvalidFillRingSize(self.fill_ring_size));
        }
        if self.completion_ring_size & (self.completion_ring_size - 1) != 0 {
            return Err(Error::InvalidCompletionRingSize(self.completion_ring_size));
        }

        Umem::new(
            self.completion_ring_size,
            self.fill_ring_size,
            self.busy_poll,
            self.num_frames,
            self.frame_size,
            self.huge_tables,
            self.unaligned,
        )
    }
}

/// A high level wrapper around a kernel UMEM object.
///
/// This wraps the UmemOwner, FillQueue, and CompletionQueue objects and provides a safe API for interacting with the UMEM.
pub struct Umem {
    owner: Arc<UmemOwner>,
    fq: FillQueue,
    cq: CompletionQueue,
}

impl Umem {
    /// Returns a builder for creating a new [Umem] instance.
    pub fn builder() -> UmemBuilder {
        UmemBuilder::new()
    }

    fn new<B: FrameBuffer + FromIterator<Frame>>(
        completion_ring_size: u32,
        fill_ring_size: u32,
        busy_poll: bool,
        num_frames: usize,
        frame_size: usize,
        huge_tables: bool,
        unaligned: bool,
    ) -> Result<(Self, B)> {
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

        let owner = Arc::new(UmemOwner {
            umem,
            mmap: Arc::new(mmap),
            frame_size,
        });
        let fq = FillQueue::new(fill_ring, owner.clone(), busy_poll);
        let cq = CompletionQueue::new(comp_ring, owner.clone());

        let frames = (0..num_frames)
            // SAFETY: The frames are created with based on the configuration for the mmap so these are valid.
            .map(|i| unsafe { owner.to_frame(i as u64 * frame_size as u64, 0, false) })
            .collect();
        Ok((Self { owner, fq, cq }, frames))
    }

    /// Returns a pointer to the kernel UMEM object.
    #[inline(always)]
    pub fn umem(&self) -> *mut xsk_umem {
        self.owner.umem
    }

    /// Returns a reference to the owner of the UMEM.
    #[inline(always)]
    pub fn owner(&self) -> &Arc<UmemOwner> {
        &self.owner
    }

    /// Returns a reference to the fill queue.
    #[inline(always)]
    pub fn fill_queue(&mut self) -> &mut FillQueue {
        &mut self.fq
    }

    /// Returns a reference to the completion queue.
    #[inline(always)]
    pub fn completion_queue(&mut self) -> &mut CompletionQueue {
        &mut self.cq
    }

    /// Possibly wakes the fill queue, so the kernel continues to process incoming packets.
    #[inline(always)]
    pub fn maybe_wake(&self, fd: c_int) -> Result<()> {
        self.fq.maybe_wake(fd)
    }

    /// Possibly wakes the fill queue asynchronously, so the kernel continues to process incoming packets.
    #[inline(always)]
    pub fn maybe_wake_async(&self, fd: c_int) -> WakeFillQueueFuture<'_> {
        self.fq.maybe_wake_async(fd)
    }

    /// Processes the fill queue, allocating new frames from the frame stack and submitting them to the fill ring up to the size of the fill ring.
    #[inline(always)]
    pub fn process_fill_queue<B: FrameBuffer>(&mut self, mut batch: B) {
        self.fq.process_queue(&mut batch);
    }

    /// Processes the fill queue asynchronously, allocating new frames from the frame stack and submitting them to the fill ring up to the size of the fill ring.
    #[inline(always)]
    pub fn process_fill_queue_async<B: FrameBuffer>(
        &mut self,
        batch: B,
    ) -> ProcessFillQueueFuture<'_, B> {
        self.fq.process_queue_async(batch)
    }

    /// Processes the completion queue, submitting the completed frames to the socket.
    #[inline(always)]
    pub fn process_completion_queue<B: FrameBuffer>(&mut self, mut batch: B) {
        self.cq.process_queue(&mut batch);
    }

    /// Processes the completion queue asynchronously, submitting the completed frames to the socket.
    #[inline(always)]
    pub fn process_completion_queue_async<'a, 'b, B: FrameBuffer>(
        &'a mut self,
        batch: B,
        expected: usize,
        socket: &'b mut SocketTx,
    ) -> CompFuture<'a, 'b, B> {
        self.cq.process_queue_async(batch, expected, socket)
    }
}
