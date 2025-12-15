use std::cmp::min;

use libxdp_sys::{
    xdp_desc, xsk_ring_prod, xsk_ring_prod__fill_addr, xsk_ring_prod__reserve,
    xsk_ring_prod__submit, xsk_ring_prod__tx_desc,
};

/// A producer ring is a ring of descriptors that are used to transfer packets from the user to the kernel.
pub struct Producer {
    ring: Box<xsk_ring_prod>,
    ring_size: u32,
}

// SAFETY: The only reason [Producer] is not send is because of the *mut u32 in xsk_ring_prod, the pointer is tied to this
// xsk_ring_prod so its lifetime is tied to it and we can safely send this to another thread.
unsafe impl Send for Producer {}

impl Producer {
    /// Creates a new producer ring.
    #[inline]
    pub fn new(ring_size: u32) -> Producer {
        let ring = Box::new(xsk_ring_prod {
            cached_prod: 0,
            cached_cons: 0,
            mask: 0,
            size: 0,
            producer: std::ptr::null_mut(),
            consumer: std::ptr::null_mut(),
            ring: std::ptr::null_mut(),
            flags: std::ptr::null_mut(),
        });
        Self { ring, ring_size }
    }

    /// Returns the size of the producer ring.
    #[inline(always)]
    pub fn size(&self) -> u32 {
        self.ring_size
    }

    /// Reserves a batch of descriptors from the ring.
    #[inline]
    pub fn reserve(&mut self, batch_size: u32) -> Option<(u32, u32)> {
        let mut idx: u32 = 0;
        let batch_size = min(batch_size, self.ring_size);
        let ready: u32 =
            unsafe { xsk_ring_prod__reserve(self.ring.as_mut(), batch_size, &mut idx) };
        if ready == 0 { None } else { Some((idx, ready)) }
    }

    /// Returns a mutable reference to the TX descriptor at the given index.
    #[inline]
    pub fn tx_desc(&mut self, index: u32) -> *mut xdp_desc {
        unsafe { xsk_ring_prod__tx_desc(self.ring.as_mut(), index) }
    }

    /// Returns a mutable reference to the fill address at the given index.
    #[inline]
    pub fn fill_addr(&mut self, index: u32) -> *mut u64 {
        unsafe { xsk_ring_prod__fill_addr(self.ring.as_mut(), index) }
    }

    /// Submits a batch of descriptors to the ring.
    #[inline]
    pub fn submit(&mut self, count: u32) {
        unsafe { xsk_ring_prod__submit(self.ring.as_mut(), count) };
    }

    /// Returns a read-only reference to the producer ring.
    #[inline]
    pub fn as_ref(&self) -> *const xsk_ring_prod {
        self.ring.as_ref()
    }

    /// Returns a mutable reference to the producer ring.
    #[inline]
    pub fn as_mut(&mut self) -> *mut xsk_ring_prod {
        self.ring.as_mut()
    }
}
