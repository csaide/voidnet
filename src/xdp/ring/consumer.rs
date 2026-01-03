use std::{
    marker::PhantomData,
    sync::atomic::{AtomicU32, Ordering},
};

use libxdp_sys::{xdp_desc, xsk_ring_cons};

use crate::xdp::ring::{Init, Uninit};

/// A consumer ring is a ring of descriptors that are used to transfer packets from the kernel to the user. This is a thin wrapper around
/// the xsk_ring_cons struct, exposing a safe API for interacting with the ring.
pub struct Consumer<I> {
    ring: xsk_ring_cons,
    _init: PhantomData<I>,
}

// SAFETY: The only reason [Consumer] is not send is because of the *mut u32 in xsk_ring_cons, the pointer is tied to this
// xsk_ring_cons so its lifetime is tied to it and we can safely send this to another thread because the pointer is into a heap
// allocated memory region that cannot move.
unsafe impl<I> Send for Consumer<I> {}

impl<I> Consumer<I> {
    /// Returns a read-only reference to the consumer ring.
    #[inline]
    pub fn as_ptr(&self) -> *const xsk_ring_cons {
        &self.ring as *const xsk_ring_cons
    }

    /// Returns a mutable reference to the consumer ring.
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut xsk_ring_cons {
        &mut self.ring as *mut xsk_ring_cons
    }
}

impl Consumer<Uninit> {
    /// Creates a new consumer ring.
    ///
    /// Note: the ring is not initialized, it must be initialized by the caller using the XDP functionality.
    pub fn new() -> Consumer<Uninit> {
        let ring = xsk_ring_cons {
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

    /// Assume the consumer has been initialized by the kernel, returning a wrapped Consumer<Init> which can be used to access the ring safely.
    ///
    /// # Safety
    ///
    /// It is on the caller to ensure that the consumer has been properly initialized by the kernel, by a call to `xsk_umem__create`/`xsk_socket__create`/`xsk_socket__create_shared`.
    pub unsafe fn assume_init(self) -> Consumer<Init> {
        Consumer::<Init> {
            ring: self.ring,
            _init: PhantomData,
        }
    }
}

impl Consumer<Init> {
    /// Returns the size of the consumer ring.
    #[inline]
    pub fn size(&self) -> u32 {
        self.ring.size
    }

    /// Peeks the ring for the given batch size, and returns the index of the first descriptor and the number of descriptors received.
    #[inline]
    pub fn peek(&mut self, batch_size: u32) -> (u32, u32) {
        xsk_ring_cons_peek(&mut self.ring, batch_size)
    }

    /// Returns a read-only reference to the RX descriptor at the given index.
    #[inline]
    pub fn rx_desc(&mut self, index: u32) -> &xdp_desc {
        xsk_ring_cons_rx_desc(&self.ring, index)
    }

    /// Returns the completion address of the descriptor at the given index.
    #[inline]
    pub fn comp_addr(&mut self, index: u32) -> u64 {
        xsk_ring_cons_comp_addr(&self.ring, index)
    }

    /// Releases the given number of descriptors from the ring.
    #[inline]
    pub fn release(&mut self, count: u32) {
        xsk_ring_cons_release(&mut self.ring, count);
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
    unsafe { *(ring.ring as *const u64).add((index & ring.mask) as usize) }
}

#[inline(always)]
fn xsk_ring_cons_rx_desc(ring: &xsk_ring_cons, index: u32) -> &xdp_desc {
    unsafe { &*(ring.ring as *const xdp_desc).add((index & ring.mask) as usize) }
}
