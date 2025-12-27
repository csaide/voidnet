use std::sync::atomic::{AtomicU32, Ordering};

use libxdp_sys::{XDP_RING_NEED_WAKEUP, xdp_desc, xsk_ring_prod};

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
    pub fn reserve(&mut self, batch_size: u32) -> (u32, u32) {
        debug_assert!(
            batch_size <= self.ring_size,
            "batch size is greater than the ring size"
        );

        xsk_ring_prod_reserve(self.ring.as_mut(), batch_size)
    }

    /// Returns a mutable reference to the TX descriptor at the given index.
    #[inline]
    pub fn tx_desc(&mut self, index: u32) -> *mut xdp_desc {
        xsk_ring_prod_tx_desc(self.ring.as_mut(), index)
    }

    /// Returns a mutable reference to the fill address at the given index.
    #[inline]
    pub fn fill_addr(&mut self, index: u32) -> *mut u64 {
        xsk_ring_prod_fill_addr(self.ring.as_ref(), index)
    }

    /// Submits a batch of descriptors to the ring.
    #[inline]
    pub fn submit(&mut self, count: u32) {
        xsk_ring_prod_submit(self.ring.as_mut(), count);
    }

    pub fn needs_wakeup(&self) -> bool {
        xsk_ring_prod_needs_wakeup(self.ring.as_ref())
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

#[inline(always)]
fn xsk_ring_prod_fill_addr(ring: &xsk_ring_prod, index: u32) -> *mut u64 {
    let addrs =
        unsafe { core::slice::from_raw_parts_mut(ring.ring as *mut u64, ring.size as usize) };
    &mut addrs[(index & ring.mask) as usize]
}

#[inline(always)]
fn xsk_prod_nb_free(ring: &mut xsk_ring_prod, batch_size: u32) -> u32 {
    let free_entries = ring.cached_cons - ring.cached_prod;

    if free_entries >= batch_size {
        return free_entries;
    }

    /* Refresh the local tail pointer.
     * cached_cons is r->size bigger than the real consumer pointer so
     * that this addition can be avoided in the more frequently
     * executed code that computs free_entries in the beginning of
     * this function. Without this optimization it whould have been
     * free_entries = r->cached_cons - r->cached_prod + r->size
     */
    ring.cached_cons = unsafe { AtomicU32::from_ptr(ring.consumer) }.load(Ordering::Acquire);
    ring.cached_cons += ring.size;

    return ring.cached_cons - ring.cached_prod;
}

#[inline(always)]
fn xsk_ring_prod_reserve(ring: &mut xsk_ring_prod, batch_size: u32) -> (u32, u32) {
    if xsk_prod_nb_free(ring, batch_size) < batch_size {
        return (0, 0);
    }

    let idx = ring.cached_prod;
    ring.cached_prod += batch_size;
    (idx, batch_size)
}

#[inline(always)]
fn xsk_ring_prod_submit(ring: &mut xsk_ring_prod, count: u32) {
    unsafe { AtomicU32::from_ptr(ring.producer).store(*ring.producer + count, Ordering::Release) };
}

#[inline(always)]
fn xsk_ring_prod_tx_desc(ring: &mut xsk_ring_prod, index: u32) -> *mut xdp_desc {
    let descs =
        unsafe { core::slice::from_raw_parts_mut(ring.ring as *mut xdp_desc, ring.size as usize) };
    &mut descs[(index & ring.mask) as usize]
}

#[inline(always)]
fn xsk_ring_prod_needs_wakeup(ring: &xsk_ring_prod) -> bool {
    unsafe { *ring.flags & XDP_RING_NEED_WAKEUP != 0 }
}
