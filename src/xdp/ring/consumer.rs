use std::sync::atomic::{AtomicU32, Ordering};

use libxdp_sys::{xdp_desc, xsk_ring_cons};

/// A consumer ring is a ring of descriptors that are used to transfer packets from the kernel to the user.
pub struct Consumer {
    ring: Box<xsk_ring_cons>,
    ring_size: u32,
}

// SAFETY: The only reason [Consumer] is not send is because of the *mut u32 in xsk_ring_cons, the pointer is tied to this
// xsk_ring_cons so its lifetime is tied to it and we can safely send this to another thread.
unsafe impl Send for Consumer {}

impl Consumer {
    /// Creates a new consumer ring.
    ///
    /// Note: the ring is not initialized, it must be initialized by the caller using the XDP functionality.
    pub fn new(ring_size: u32) -> Self {
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
        Self { ring, ring_size }
    }

    /// Returns the size of the consumer ring.
    #[inline]
    pub fn size(&self) -> u32 {
        self.ring_size
    }

    /// Peeks the ring for the given batch size, and returns the index of the first descriptor and the number of descriptors received.
    #[inline]
    pub fn peek(&mut self, batch_size: u32) -> (u32, u32) {
        xsk_ring_cons_peek(self.ring.as_mut(), batch_size)
    }

    /// Returns a read-only reference to the RX descriptor at the given index.
    #[inline]
    pub fn rx_desc(&mut self, index: u32) -> &xdp_desc {
        xsk_ring_cons_rx_desc(self.ring.as_ref(), index)
    }

    /// Returns the completion address of the descriptor at the given index.
    #[inline]
    pub fn comp_addr(&mut self, index: u32) -> u64 {
        xsk_ring_cons_comp_addr(self.ring.as_ref(), index)
    }

    /// Releases the given number of descriptors from the ring.
    #[inline]
    pub fn release(&mut self, count: u32) {
        xsk_ring_cons_release(self.ring.as_mut(), count);
    }

    /// Returns a read-only reference to the consumer ring.
    #[inline]
    pub fn as_ref(&self) -> *const xsk_ring_cons {
        self.ring.as_ref() as *const xsk_ring_cons
    }

    /// Returns a mutable reference to the consumer ring.
    #[inline]
    pub fn as_mut(&mut self) -> *mut xsk_ring_cons {
        self.ring.as_mut() as *mut xsk_ring_cons
    }
}

#[inline(always)]
fn xsk_ring_cons_peek(ring: &mut xsk_ring_cons, batch_size: u32) -> (u32, u32) {
    let mut idx: u32 = 0;
    let entries = xsk_cons_nb_avail(ring, batch_size);

    if entries > 0 {
        idx = ring.cached_cons;
        ring.cached_cons += entries;
    }

    (idx, entries)
}

#[inline(always)]
fn xsk_cons_nb_avail(ring: &mut xsk_ring_cons, batch_size: u32) -> u32 {
    let mut entries = ring.cached_prod - ring.cached_cons;

    if entries == 0 {
        ring.cached_prod = unsafe { AtomicU32::from_ptr(ring.producer) }.load(Ordering::Acquire);
        entries = ring.cached_prod - ring.cached_cons;
    }

    if entries > batch_size {
        batch_size
    } else {
        entries
    }
}

#[inline(always)]
fn xsk_ring_cons_release(ring: &mut xsk_ring_cons, count: u32) {
    unsafe { AtomicU32::from_ptr(ring.consumer).store(*ring.consumer + count, Ordering::Release) };
}

#[inline(always)]
fn xsk_ring_cons_comp_addr(ring: &xsk_ring_cons, index: u32) -> u64 {
    let addrs = unsafe { core::slice::from_raw_parts(ring.ring as *const u64, ring.size as usize) };
    addrs[(index & ring.mask) as usize]
}

#[inline(always)]
fn xsk_ring_cons_rx_desc(ring: &xsk_ring_cons, index: u32) -> &xdp_desc {
    let descs =
        unsafe { core::slice::from_raw_parts(ring.ring as *const xdp_desc, ring.size as usize) };

    &descs[(index & ring.mask) as usize]
}
