use std::{os::raw::c_void, sync::Arc};

use errno::errno;
use libxdp_sys::{
    XDP_UMEM_UNALIGNED_CHUNK_FLAG, XSK_RING_CONS__DEFAULT_NUM_DESCS,
    XSK_RING_PROD__DEFAULT_NUM_DESCS, XSK_UMEM__DEFAULT_FRAME_HEADROOM,
    XSK_UMEM__DEFAULT_FRAME_SIZE, libxdp_get_error, xsk_umem, xsk_umem__create_opts,
    xsk_umem__delete, xsk_umem_opts,
};

use crate::xdp::{
    error::{Error, Result},
    frame::{FrameBufferBuilder, FrameStack},
    ring::{Consumer, Producer},
};

use super::{CompletionQueue, FillQueue};

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

    pub fn build<B: FrameBufferBuilder>(
        self,
    ) -> Result<(Arc<Umem>, FillQueue, CompletionQueue, B)> {
        if self.frame_size & (self.frame_size - 1) != 0 && !self.unaligned {
            return Err(Error::InvalidFrameSize(self.frame_size));
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
pub struct Umem {
    umem: *mut xsk_umem,
    frame_stack: Arc<FrameStack>,
}

unsafe impl Send for Umem {}

impl Umem {
    /// Returns a builder for creating a new [Umem] instance.
    pub fn builder() -> UmemBuilder {
        UmemBuilder::new()
    }

    fn new<B: FrameBufferBuilder>(
        completion_ring_size: u32,
        fill_ring_size: u32,
        busy_poll: bool,
        num_frames: usize,
        frame_size: usize,
        huge_tables: bool,
        unaligned: bool,
    ) -> Result<(Arc<Self>, FillQueue, CompletionQueue, B)> {
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
        let (mut frame_stack, frames) = FrameStack::new(num_frames, frame_size, huge_tables)?;

        let umem = unsafe {
            xsk_umem__create_opts(
                frame_stack.as_mut_ptr() as *mut c_void,
                fill_ring.as_mut_ptr(),
                comp_ring.as_mut_ptr(),
                &mut opts,
            )
        };
        let err = unsafe { libxdp_get_error(umem as *const _) };
        if err < 0 {
            return Err(Error::CreateUmem(errno()));
        }

        let fill_ring = unsafe { fill_ring.init() };
        let comp_ring = unsafe { comp_ring.assume_init() };

        let frame_stack = Arc::new(frame_stack);
        let umem = Arc::new(Self {
            umem,
            frame_stack: frame_stack.clone(),
        });
        let fq = FillQueue::new(fill_ring, frame_stack.clone(), busy_poll);
        let cq = CompletionQueue::new(comp_ring, frame_stack);

        Ok((umem, fq, cq, frames))
    }

    /// Returns a pointer to the kernel UMEM object.
    #[inline(always)]
    pub fn umem(&self) -> *mut xsk_umem {
        self.umem
    }

    /// Returns a reference to the frame stack.
    #[inline(always)]
    pub fn frame_stack(&self) -> Arc<FrameStack> {
        self.frame_stack.clone()
    }
}

impl Drop for Umem {
    fn drop(&mut self) {
        // SAFETY: xsk_umem__delete is safe to call even if the umem is not initialized.
        unsafe {
            xsk_umem__delete(self.umem);
        }
    }
}
