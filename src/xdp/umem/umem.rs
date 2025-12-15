use std::{os::raw::c_void, sync::Arc};

use errno::errno;
use libxdp_sys::{
    XSK_RING_CONS__DEFAULT_NUM_DESCS, XSK_RING_PROD__DEFAULT_NUM_DESCS,
    XSK_UMEM__DEFAULT_FRAME_HEADROOM, xsk_umem, xsk_umem__create, xsk_umem__delete,
    xsk_umem_config,
};

use crate::xdp::{
    ring::{Consumer, Producer},
    umem::{CompletionQueue, FillQueue, FrameStack},
};

use super::{Error, Frame, Mmap, Result};

/// A builder for creating a new [Umem] instance.
pub struct UmemBuilder {
    completion_ring_size: u32,
    fill_ring_size: u32,
    frame_size: usize,
    num_frames: usize,
}

impl UmemBuilder {
    pub fn new() -> Self {
        let completion_ring_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
        let fill_ring_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2;
        Self {
            completion_ring_size,
            fill_ring_size,
            frame_size: 2048,
            num_frames: (completion_ring_size + fill_ring_size) as usize,
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

    pub fn build(self) -> Result<(Arc<Umem>, FillQueue, CompletionQueue)> {
        let pool = Mmap::new(self.num_frames, self.frame_size)?;
        Umem::new(pool, self.completion_ring_size, self.fill_ring_size)
    }
}

/// A high level wrapper around a kernel UMEM object.
pub struct Umem {
    map: Mmap,
    umem: *mut xsk_umem,
    frame_stack: Arc<FrameStack>,
}

unsafe impl Send for Umem {}
unsafe impl Sync for Umem {}

impl Umem {
    /// Returns a builder for creating a new [Umem] instance.
    pub fn builder() -> UmemBuilder {
        UmemBuilder::new()
    }

    fn new(
        mut map: Mmap,
        completion_ring_size: u32,
        fill_ring_size: u32,
    ) -> Result<(Arc<Self>, FillQueue, CompletionQueue)> {
        let cfg = xsk_umem_config {
            fill_size: fill_ring_size,
            comp_size: completion_ring_size,
            frame_size: map.frame_size() as u32,
            frame_headroom: XSK_UMEM__DEFAULT_FRAME_HEADROOM,
            flags: 0,
        };

        let mut comp_ring = Consumer::new(completion_ring_size);
        let mut fill_ring = Producer::new(fill_ring_size);

        let mut umem: *mut xsk_umem = std::ptr::null_mut();
        let umem_ptr: *mut *mut xsk_umem = &mut umem;
        let size = (map.num_frames() * map.frame_size()) as u64;

        let ret: std::os::raw::c_int = unsafe {
            xsk_umem__create(
                umem_ptr,
                map.as_mut_ptr() as *mut c_void,
                size,
                fill_ring.as_mut(),
                comp_ring.as_mut(),
                &cfg,
            )
        };
        if ret != 0 {
            return Err(Error::Create(errno()));
        }

        let frame_stack = Arc::new(FrameStack::new(map.num_frames(), map.frame_size()));
        let umem = Arc::new(Self {
            map,
            umem,
            frame_stack: frame_stack.clone(),
        });
        let fq = FillQueue::new(umem.clone(), fill_ring, frame_stack.clone());
        let cq = CompletionQueue::new(umem.clone(), comp_ring, frame_stack);
        Ok((umem, fq, cq))
    }

    /// Returns a pointer to the kernel UMEM object.
    #[inline]
    pub fn umem(&self) -> *mut xsk_umem {
        self.umem
    }

    /// Returns the number of frames that are available to be used.
    #[inline]
    pub fn available_frames(&self) -> usize {
        self.frame_stack.len()
    }

    #[inline(always)]
    fn to_frame(&self, addr: u64, len: usize) -> Frame {
        unsafe {
            Frame::new(
                addr,
                self.map.as_ptr().offset(addr as isize) as *mut u8,
                len,
                self.map.frame_size(),
                self.frame_stack.clone(),
            )
        }
    }

    /// Returns a new [Frame] for the given address and length, if the frame is not consumed directly by passing it to a call to [Socket::send], it will be returned to the frame stack.
    ///
    /// [Socket::send]: crate::xdp::socket::Socket::send
    #[inline]
    pub fn get_read_frame(&self, addr: u64, len: usize) -> Frame {
        self.to_frame(addr, len)
    }

    /// Returns a new empty [Frame], if the frame is not consumed directly by passing it to a call to [Socket::send], it will be returned to the frame stack.
    ///
    /// [Socket::send]: crate::xdp::socket::Socket::send
    #[inline]
    pub fn get_write_frame(&self) -> Option<Frame> {
        self.frame_stack.pop().map(|addr| self.to_frame(addr, 0))
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
