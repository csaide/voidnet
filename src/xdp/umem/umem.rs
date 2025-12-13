use std::{cmp::min, os::raw::c_void};

use errno::errno;
use libc::c_int;
use libxdp_sys::{
    XSK_RING_CONS__DEFAULT_NUM_DESCS, XSK_RING_PROD__DEFAULT_NUM_DESCS,
    XSK_UMEM__DEFAULT_FRAME_HEADROOM, xsk_umem, xsk_umem__create, xsk_umem__delete,
    xsk_umem_config,
};

use crate::xdp::{
    ring::{Consumer, Fq, Producer},
    umem::ThreadLocalFrameStack,
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

    pub fn build(self) -> Result<Umem> {
        let pool = Mmap::new(self.num_frames, self.frame_size)?;
        let mut umem = Umem::new(pool, self.completion_ring_size, self.fill_ring_size)?;
        umem.process_fill_queue();
        Ok(umem)
    }
}

/// A high level wrapper around a kernel UMEM object.
pub struct Umem {
    map: Mmap,
    umem: *mut xsk_umem,
    frame_stack: ThreadLocalFrameStack,
    fill_ring: Producer<Fq>,
    comp_ring: Consumer,
}

impl Umem {
    /// Returns a builder for creating a new [Umem] instance.
    pub fn builder() -> UmemBuilder {
        UmemBuilder::new()
    }

    fn new(mut map: Mmap, completion_ring_size: u32, fill_ring_size: u32) -> Result<Self> {
        let cfg = xsk_umem_config {
            fill_size: fill_ring_size,
            comp_size: completion_ring_size,
            frame_size: map.frame_size() as u32,
            frame_headroom: XSK_UMEM__DEFAULT_FRAME_HEADROOM,
            flags: 0,
        };

        let mut comp_ring = Consumer::new(completion_ring_size);
        let mut fill_ring = Producer::new_fq(fill_ring_size);

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
        let frame_stack = ThreadLocalFrameStack::new(map.num_frames(), map.frame_size());
        Ok(Self {
            map,
            umem,
            frame_stack,
            fill_ring,
            comp_ring,
        })
    }

    /// Returns a pointer to the kernel UMEM object.
    #[inline]
    pub fn umem(&mut self) -> *mut xsk_umem {
        self.umem
    }

    /// Possibly wakes the fill queue, so the kernel continues to process incoming packets.
    #[inline]
    pub fn maybe_wake(&mut self, fd: c_int) -> Result<()> {
        self.fill_ring.maybe_wake(fd).map_err(Error::WakeFillQueue)
    }

    /// Returns the number of frames that are available to be used.
    #[inline]
    pub fn available_frames(&self) -> usize {
        self.frame_stack.len()
    }

    /// Returns a new [Frame] for the given address and length, if the frame is not consumed directly by passing it to a call to [Socket::send], it will be returned to the frame stack.
    ///
    /// [Socket::send]: crate::xdp::socket::Socket::send
    #[inline]
    pub fn get_frame(&self, addr: u64, len: usize) -> Frame {
        unsafe {
            Frame::new(
                addr,
                self.map.as_ptr().offset(addr as isize) as *mut u8,
                len,
                self.map.frame_size(),
                &self.frame_stack as *const ThreadLocalFrameStack,
            )
        }
    }

    /// Returns a new empty [Frame], if the frame is not consumed directly by passing it to a call to [Socket::send], it will be returned to the frame stack.
    ///
    /// [Socket::send]: crate::xdp::socket::Socket::send
    #[inline]
    pub fn pop_frame(&self) -> Option<Frame> {
        self.frame_stack.pop().map(|addr| self.get_frame(addr, 0))
    }

    /// Processes the fill queue, allocating new frames from the frame stack and submitting them to the fill ring up to the size of the fill ring.
    #[inline]
    pub fn process_fill_queue(&mut self) {
        let batch_size = min(self.fill_ring.size(), self.frame_stack.len() as u32);
        if batch_size == 0 {
            return;
        }

        let (mut idx, ready) = self.fill_ring.reserve(batch_size).unwrap_or((0, 0));
        for _ in 0..ready {
            let addr = self
                .frame_stack
                .pop()
                .expect("Some how we ran out of frames.");
            let ptr = self.fill_ring.fill_addr(idx);
            unsafe { *ptr = addr as u64 };
            idx += 1;
        }
        if ready > 0 {
            self.fill_ring.submit(ready as u32);
        }
    }

    /// Processes the completion queue, returning frames to the frame stack up to the size of the completion ring.
    #[inline]
    pub fn process_comp_queue(&mut self) {
        let batch_size = min(self.comp_ring.size(), self.frame_stack.free_space() as u32);
        if batch_size == 0 {
            return;
        }

        let (mut idx, ready) = match self.comp_ring.peek(batch_size) {
            Some(res) => res,
            None => return,
        };
        for _ in 0..ready {
            let addr = self.comp_ring.comp_addr(idx);
            self.frame_stack
                .push(addr)
                .expect("Some how we ran out of frames.");
            idx += 1;
        }

        // No conditional here as we know we have this many ready descriptors.
        self.comp_ring.release(ready as u32);
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
