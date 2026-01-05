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

// SAFETY: The only reason [Consumer] is not send is because of the raw pointers in xsk_ring_cons, the pointer is tied to this
// xsk_ring_cons so its lifetime is tied to it and we can safely send this to another thread because the pointer is into a heap
// allocated memory region that cannot move, and more so not controlled by us or the caller.
unsafe impl<I> Send for Consumer<I> {}

impl<I> Consumer<I> {
    /// Returns a read-only reference to the consumer ring.
    #[inline(always)]
    pub fn as_ptr(&self) -> *const xsk_ring_cons {
        &self.ring as *const xsk_ring_cons
    }

    /// Returns a mutable reference to the consumer ring.
    #[inline(always)]
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
    #[inline(always)]
    pub fn size(&self) -> u32 {
        self.ring.size
    }

    /// Returns the number of available descriptors in the ring.
    ///
    /// This mirrors the functionality of the `xsk_cons_nb_avail` function:
    /// Path: `vendor/xdp-tools/headers/xdp/xsk.h:112`
    ///
    /// ```c
    /// XDP_ALWAYS_INLINE __u32 xsk_cons_nb_avail(struct xsk_ring_cons *r, __u32 nb)
    /// {
    /// 	__u32 entries = r->cached_prod - r->cached_cons;
    ///
    /// 	if (entries == 0) {
    /// 		r->cached_prod = __atomic_load_n(r->producer, __ATOMIC_ACQUIRE);
    /// 		entries = r->cached_prod - r->cached_cons;
    /// 	}
    ///
    /// 	return (entries > nb) ? nb : entries;
    /// }
    /// ```
    #[inline(always)]
    pub fn nb_avail(&mut self, batch_size: u32) -> u32 {
        let mut entries = self.ring.cached_prod - self.ring.cached_cons;

        if entries == 0 {
            self.ring.cached_prod =
                unsafe { AtomicU32::from_ptr(self.ring.producer) }.load(Ordering::Acquire);
            entries = self.ring.cached_prod - self.ring.cached_cons;
        }

        if entries > batch_size {
            batch_size
        } else {
            entries
        }
    }

    /// Peeks the ring for the given batch size, and returns the index of the first descriptor and the number of descriptors received.
    ///
    /// This mirrors the functionality of the `xsk_ring_cons__peek` function:
    /// Path: `vendor/xdp-tools/headers/xdp/xsk.h:143`
    ///
    /// ```c
    /// XDP_ALWAYS_INLINE __u32 xsk_ring_cons__peek(struct xsk_ring_cons *cons, __u32 nb, __u32 *idx)
    /// {
    ///     __u32 entries = xsk_cons_nb_avail(cons, nb);
    ///
    ///     if (entries > 0) {
    ///         *idx = cons->cached_cons;
    ///         cons->cached_cons += entries;
    ///     }
    ///
    ///     return entries;
    /// }
    /// ```
    #[inline(always)]
    pub fn peek(&mut self, batch_size: u32) -> (u32, u32) {
        let mut idx: u32 = 0;
        let entries = self.nb_avail(batch_size);

        if entries > 0 {
            idx = self.ring.cached_cons;
            self.ring.cached_cons += entries;
        }

        (idx, entries)
    }

    /// Returns a read-only reference to the RX descriptor at the given index.
    ///
    /// This mirrors the functionality of the `xsk_ring_cons__rx_desc` function:
    /// Path: `vendor/xdp-tools/headers/xdp/xsk.h:79`
    ///
    /// ```c
    /// XDP_ALWAYS_INLINE const struct xdp_desc *
    /// xsk_ring_cons__rx_desc(const struct xsk_ring_cons *rx, __u32 idx)
    /// {
    ///     const struct xdp_desc *descs = (const struct xdp_desc *)rx->ring;
    ///
    ///     return &descs[idx & rx->mask];
    /// }
    /// ```
    #[inline(always)]
    pub fn rx_desc(&mut self, index: u32) -> &xdp_desc {
        unsafe { &*(self.ring.ring as *const xdp_desc).add((index & self.ring.mask) as usize) }
    }

    /// Returns the completion address of the descriptor at the given index.
    ///
    /// This mirrors the functionality of the `xsk_ring_cons__comp_addr` function:
    /// Path: `vendor/xdp-tools/headers/xdp/xsk.h:64`
    ///
    /// ```c
    /// XDP_ALWAYS_INLINE const __u64 *
    /// xsk_ring_cons__comp_addr(const struct xsk_ring_cons *comp, __u32 idx)
    /// {
    ///     const __u64 *addrs = (const __u64 *)comp->ring;
    ///
    ///     return &addrs[idx & comp->mask];
    /// }
    /// ```
    #[inline(always)]
    pub fn comp_addr(&mut self, index: u32) -> u64 {
        unsafe { *(self.ring.ring as *const u64).add((index & self.ring.mask) as usize) }
    }

    /// Releases the given number of descriptors from the ring.
    ///
    /// This mirrors the functionality of the `xsk_ring_cons__release` function:
    /// Path: `vendor/xdp-tools/headers/xdp/xsk.h:160`
    ///
    /// ```c
    /// XDP_ALWAYS_INLINE void xsk_ring_cons__release(struct xsk_ring_cons *cons, __u32 nb)
    /// {
    ///     /* Make sure data has been read before indicating we are done
    ///      * with the entries by updating the consumer pointer.
    ///      */
    ///     __atomic_store_n(cons->consumer, *cons->consumer + nb, __ATOMIC_RELEASE);
    /// }
    /// ```
    #[inline(always)]
    pub fn release(&mut self, count: u32) {
        unsafe {
            AtomicU32::from_ptr(self.ring.consumer)
                .store(*self.ring.consumer + count, Ordering::Release)
        };
    }

    /// Cancels the given number of descriptors from the ring.
    ///
    /// This mirrors the functionality of the `xsk_ring_cons__cancel` function:
    /// Path: `vendor/xdp-tools/headers/xdp/xsk.h:155`
    ///
    /// ```c
    /// XDP_ALWAYS_INLINE void xsk_ring_cons__cancel(struct xsk_ring_cons *cons, __u32 nb)
    /// {
    ///     cons->cached_cons -= nb;
    /// }
    /// ```
    #[inline(always)]
    pub fn cancel(&mut self, count: u32) {
        self.ring.cached_cons -= count;
    }
}
