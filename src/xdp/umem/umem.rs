use std::{
    cmp::min,
    ops::{Deref, DerefMut},
};

use errno::errno;
use libxdp_sys::{
    XSK_RING_CONS__DEFAULT_NUM_DESCS, XSK_RING_PROD__DEFAULT_NUM_DESCS,
    XSK_UMEM__DEFAULT_FRAME_HEADROOM, xsk_umem, xsk_umem__create, xsk_umem__delete,
    xsk_umem_config,
};

use crate::xdp::{
    ring::{Consumer, Fq, Producer},
    umem::{Frame, Mmap},
};

use super::{Error, Result};

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
        umem.fill_packets()?;
        Ok(umem)
    }
}

pub struct Umem {
    pool: Mmap,
    umem: Box<xsk_umem>,
    cq: Consumer,
    fq: Producer<Fq>,
    free_frames: Vec<u64>,
}

impl Umem {
    pub fn builder() -> UmemBuilder {
        UmemBuilder::new()
    }

    fn new(mut pool: Mmap, completion_ring_size: u32, fill_ring_size: u32) -> Result<Self> {
        let cfg = xsk_umem_config {
            fill_size: fill_ring_size,
            comp_size: completion_ring_size,
            frame_size: pool.frame_size() as u32,
            frame_headroom: XSK_UMEM__DEFAULT_FRAME_HEADROOM,
            flags: 0,
        };

        let mut cq = Consumer::new();
        let mut fq = Producer::new_fq();

        // Double indirection in C function
        let mut umem: *mut xsk_umem = std::ptr::null_mut();
        let umem_ptr: *mut *mut xsk_umem = &mut umem;
        let size = (pool.num_frames() * pool.frame_size()) as u64;

        let ret: std::os::raw::c_int = unsafe {
            xsk_umem__create(
                umem_ptr,
                pool.as_ptr(),
                size,
                fq.as_mut(),
                cq.as_mut(),
                &cfg,
            )
        };

        if ret != 0 {
            let errno = errno().0;
            return Err(Error::Create(std::io::Error::from_raw_os_error(errno)));
        }

        let free_frames = (0..pool.num_frames())
            .map(|i| i as u64 * pool.frame_size() as u64)
            .collect();

        Ok(Self {
            pool,
            umem: unsafe { Box::from_raw(*umem_ptr) },
            cq,
            fq,
            free_frames,
        })
    }

    pub fn umem(&mut self) -> *mut xsk_umem {
        self.umem.as_mut()
    }

    pub fn cq(&self) -> &Consumer {
        &self.cq
    }

    pub fn fq(&self) -> &Producer<Fq> {
        &self.fq
    }

    pub fn cq_mut(&mut self) -> &mut Consumer {
        &mut self.cq
    }

    pub fn fq_mut(&mut self) -> &mut Producer<Fq> {
        &mut self.fq
    }

    pub fn get_next_free_frame(&mut self) -> Option<Frame> {
        self.free_frames
            .pop()
            .map(|addr| self.pool.get_frame(addr, 0))
    }

    pub fn free_frame(&mut self, addr: u64) {
        self.free_frames.push(addr);
    }

    pub fn handle_completions(&mut self) -> Result<usize> {
        let batch_size = min(
            self.cq.size(),
            (self.free_frames.capacity() - self.free_frames.len()) as u32,
        );

        let (mut idx, ready) = match self.cq.peek(batch_size) {
            Some(res) => res,
            None => return Ok(0),
        };

        for _ in 0..ready {
            let addr = self.cq.comp_addr(idx);
            self.free_frames.push(addr);
            idx += 1;
        }

        self.cq.release(ready);

        Ok(ready as usize)
    }

    pub fn fill_packets(&mut self) -> Result<usize> {
        let batch_size = min(self.fq.size(), self.free_frames.len() as u32);

        if batch_size == 0 {
            return Ok(0);
        }

        let (mut idx, ready) = self.fq.reserve(batch_size).unwrap_or((0, 0));

        for _ in 0..ready {
            let addr = self.free_frames.pop().unwrap();
            let ptr = self.fq.fill_addr(idx);
            unsafe { *ptr = addr as u64 };
            idx += 1;
        }

        if ready > 0 {
            self.fq.submit(ready as u32);
        }

        Ok(ready as usize)
    }
}

impl Drop for Umem {
    fn drop(&mut self) {
        // SAFETY: xsk_umem__delete is safe to call even if the umem is not initialized.
        unsafe {
            xsk_umem__delete(self.umem.as_mut());
        }
    }
}

impl Deref for Umem {
    type Target = Mmap;

    fn deref(&self) -> &Self::Target {
        &self.pool
    }
}

impl DerefMut for Umem {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.pool
    }
}
