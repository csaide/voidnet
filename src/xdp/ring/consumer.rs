use libxdp_sys::{
    xdp_desc, xsk_ring_cons, xsk_ring_cons__comp_addr, xsk_ring_cons__peek, xsk_ring_cons__release,
    xsk_ring_cons__rx_desc,
};

/// A consumer ring is a ring of descriptors that are used to transfer packets from the kernel to the user.
pub struct Consumer {
    ring: Box<xsk_ring_cons>,
}

impl Consumer {
    /// Creates a new consumer ring.
    ///
    /// # Returns
    ///
    /// A new consumer ring.
    ///
    /// Note: the ring is not initialized, it must be initialized by the caller using the XDP functionality.
    pub fn new() -> Self {
        let ring = Box::new(xsk_ring_cons {
            cached_prod: 0,
            cached_cons: 0,
            mask: 0,
            size: 0,
            producer: std::ptr::null_mut(),
            consumer: std::ptr::null_mut(),
            ring: std::ptr::null_mut(),
            flags: std::ptr::null_mut(),
        });
        Self { ring }
    }

    /// Returns the size of the consumer ring.
    pub fn size(&self) -> u32 {
        self.ring.as_ref().size
    }

    /// Peeks the ring for the given batch size, and returns the index of the first descriptor and the number of descriptors received.
    ///
    /// # Arguments
    ///
    /// * `batch_size` - The maximum batch size to peek.
    pub fn peek(&mut self, batch_size: u32) -> Option<(u32, u32)> {
        let mut idx: u32 = 0;
        let rcvd = unsafe { xsk_ring_cons__peek(self.ring.as_mut(), batch_size, &mut idx) };
        if rcvd == 0 { None } else { Some((idx, rcvd)) }
    }

    /// Returns a read-only reference to the RX descriptor at the given index.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the RX descriptor to return.
    pub fn rx_desc(&mut self, index: u32) -> &xdp_desc {
        unsafe { &*xsk_ring_cons__rx_desc(self.ring.as_mut(), index) }
    }

    /// Returns the completion address of the descriptor at the given index.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the descriptor to return the completion address of.
    pub fn comp_addr(&mut self, index: u32) -> u64 {
        unsafe { *xsk_ring_cons__comp_addr(self.ring.as_mut(), index) }
    }

    /// Releases the given number of descriptors from the ring.
    ///
    /// # Arguments
    ///
    /// * `count` - The number of descriptors to release.
    pub fn release(&mut self, count: u32) {
        unsafe { xsk_ring_cons__release(self.ring.as_mut(), count) };
    }

    /// Returns a read-only reference to the consumer ring.
    pub fn as_ref(&self) -> *const xsk_ring_cons {
        self.ring.as_ref() as *const xsk_ring_cons
    }

    /// Returns a mutable reference to the consumer ring.
    pub fn as_mut(&mut self) -> *mut xsk_ring_cons {
        self.ring.as_mut() as *mut xsk_ring_cons
    }
}
