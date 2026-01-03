use std::{
    marker::PhantomData,
    sync::atomic::{AtomicU32, Ordering},
};

use libxdp_sys::{XDP_RING_NEED_WAKEUP, xdp_desc, xsk_ring_prod};

use super::{Init, Uninit};

/// A producer ring is a ring of descriptors that are used to transfer packets from the user to the kernel. This is a thin wrapper around
/// the xsk_ring_prod struct, exposing a safe API for interacting with the ring.
pub struct Producer<I> {
    ring: xsk_ring_prod,
    _init: PhantomData<I>,
}

// SAFETY: The only reason [Producer] is not send is because of the *mut u32 in xsk_ring_prod, the pointer is tied to this
// xsk_ring_prod so its lifetime is tied to it and we can safely send this to another thread because the pointer is into a heap
// allocated memory region that cannot move.
unsafe impl<I> Send for Producer<I> {}

impl<I> Producer<I> {
    /// Returns a read-only reference to the producer ring.
    #[inline]
    pub fn as_ptr(&self) -> *const xsk_ring_prod {
        &self.ring as *const xsk_ring_prod
    }

    /// Returns a mutable reference to the producer ring.
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut xsk_ring_prod {
        &mut self.ring as *mut xsk_ring_prod
    }
}

impl Producer<Uninit> {
    /// Creates a new producer ring.
    #[inline]
    pub fn new() -> Producer<Uninit> {
        let ring = xsk_ring_prod {
            cached_prod: 0,
            cached_cons: 0,
            mask: 0,
            size: 0,
            producer: std::ptr::null_mut(),
            consumer: std::ptr::null_mut(),
            ring: std::ptr::null_mut(),
            flags: std::ptr::null_mut(),
        };
        Self {
            ring,
            _init: PhantomData,
        }
    }

    /// Assume the producer has been initialized by the kernel, returning a wrapped Producer<Init> which can be used to access the ring safely.
    ///
    /// # Safety
    ///
    /// It is on the caller to ensure that the producer has been properly initialized by the kernel, by a call to `xsk_umem__create`/`xsk_socket__create`/`xsk_socket__create_shared`.
    pub unsafe fn assume_init(self) -> Producer<Init> {
        Producer::<Init> {
            ring: self.ring,
            _init: PhantomData,
        }
    }
}

impl Producer<Init> {
    /// Returns the size of the producer ring.
    #[inline]
    pub fn size(&self) -> u32 {
        self.ring.size
    }

    /// Reserves a batch of descriptors from the ring.
    #[inline]
    pub fn reserve(&mut self, batch_size: u32) -> (u32, u32) {
        debug_assert!(
            batch_size <= self.ring.size,
            "batch size is greater than the ring size"
        );

        xsk_ring_prod_reserve(&mut self.ring, batch_size)
    }

    /// Returns a mutable reference to the TX descriptor at the given index.
    #[inline]
    pub fn tx_desc(&mut self, index: u32) -> *mut xdp_desc {
        xsk_ring_prod_tx_desc(&mut self.ring, index)
    }

    /// Returns a mutable reference to the fill address at the given index.
    #[inline]
    pub fn fill_addr(&mut self, index: u32) -> *mut u64 {
        xsk_ring_prod_fill_addr(&self.ring, index)
    }

    /// Submits a batch of descriptors to the ring.
    #[inline]
    pub fn submit(&mut self, count: u32) {
        xsk_ring_prod_submit(&mut self.ring, count);
    }

    pub fn needs_wakeup(&self) -> bool {
        xsk_ring_prod_needs_wakeup(&self.ring)
    }
}

#[inline(always)]
fn xsk_ring_prod_fill_addr(ring: &xsk_ring_prod, index: u32) -> *mut u64 {
    unsafe { (ring.ring as *mut u64).add((index & ring.mask) as usize) }
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
    unsafe { (ring.ring as *mut xdp_desc).add((index & ring.mask) as usize) }
}

#[inline(always)]
fn xsk_ring_prod_needs_wakeup(ring: &xsk_ring_prod) -> bool {
    unsafe { *ring.flags & XDP_RING_NEED_WAKEUP != 0 }
}
