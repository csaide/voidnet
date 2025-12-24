use std::{collections::VecDeque, os::raw::c_void, sync::Arc};

use errno::errno;
use libxdp_sys::{
    XSK_RING_CONS__DEFAULT_NUM_DESCS, XSK_RING_PROD__DEFAULT_NUM_DESCS,
    XSK_UMEM__DEFAULT_FRAME_HEADROOM, XSK_UMEM__DEFAULT_FRAME_SIZE, xsk_umem, xsk_umem__create,
    xsk_umem__delete, xsk_umem_config,
};

use crate::xdp::{
    error::{Error, Result},
    frame::{Frame, FrameStack},
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

    pub fn build(self) -> Result<(Arc<Umem>, FillQueue, CompletionQueue, VecDeque<Frame>)> {
        Umem::new(
            self.completion_ring_size,
            self.fill_ring_size,
            self.busy_poll,
            self.num_frames,
            self.frame_size,
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

    fn new(
        completion_ring_size: u32,
        fill_ring_size: u32,
        busy_poll: bool,
        num_frames: usize,
        frame_size: usize,
    ) -> Result<(Arc<Self>, FillQueue, CompletionQueue, VecDeque<Frame>)> {
        let cfg = xsk_umem_config {
            fill_size: fill_ring_size,
            comp_size: completion_ring_size,
            frame_size: frame_size as u32,
            frame_headroom: XSK_UMEM__DEFAULT_FRAME_HEADROOM,
            flags: 0,
        };

        let mut comp_ring = Consumer::new(completion_ring_size);
        let mut fill_ring = Producer::new(fill_ring_size);
        let (mut frame_stack, frames) = FrameStack::new(num_frames, frame_size)?;

        let mut umem: *mut xsk_umem = std::ptr::null_mut();
        let umem_ptr: *mut *mut xsk_umem = &mut umem;
        let size = (num_frames * frame_size) as u64;

        let ret: std::os::raw::c_int = unsafe {
            xsk_umem__create(
                umem_ptr,
                frame_stack.as_mut_ptr() as *mut c_void,
                size,
                fill_ring.as_mut(),
                comp_ring.as_mut(),
                &cfg,
            )
        };
        if ret != 0 {
            return Err(Error::CreateUmem(errno()));
        }

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
