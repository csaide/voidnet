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
    #[inline(always)]
    pub fn as_ptr(&self) -> *const xsk_ring_prod {
        &self.ring as *const xsk_ring_prod
    }

    /// Returns a mutable reference to the producer ring.
    #[inline(always)]
    pub fn as_mut_ptr(&mut self) -> *mut xsk_ring_prod {
        &mut self.ring as *mut xsk_ring_prod
    }
}

impl Producer<Uninit> {
    /// Creates a new producer ring, ready to be initialized by the kernel.
    ///
    /// Note: the ring is not initialized, it must be initialized by the caller using the XDP functionality.
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
    #[inline(always)]
    pub fn size(&self) -> u32 {
        self.ring.size
    }

    /// Returns the number of free descriptors in the ring.
    ///
    /// This mirrors the functionality of the `xsk_prod_nb_free` function:
    /// Path: `vendor/xdp-tools/headers/xdp/xsk.h:92`
    ///
    /// ```c
    /// XDP_ALWAYS_INLINE __u32 xsk_prod_nb_free(struct xsk_ring_prod *r, __u32 nb)
    /// {
    ///     __u32 free_entries = r->cached_cons - r->cached_prod;
    ///
    ///     if (free_entries >= nb)
    ///         return free_entries;
    ///
    ///     /* Refresh the local tail pointer.
    ///      * cached_cons is r->size bigger than the real consumer pointer so
    ///      * that this addition can be avoided in the more frequently
    ///      * executed code that computs free_entries in the beginning of
    ///      * this function. Without this optimization it whould have been
    ///      * free_entries = r->cached_cons - r->cached_prod + r->size
    ///      */
    ///     r->cached_cons = __atomic_load_n(r->consumer, __ATOMIC_ACQUIRE);
    ///     r->cached_cons += r->size;
    ///
    ///     return r->cached_cons - r->cached_prod;
    /// }
    /// ```
    #[inline(always)]
    pub fn nb_free(&mut self, batch_size: u32) -> u32 {
        let free_entries = self.ring.cached_cons - self.ring.cached_prod;

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
        self.ring.cached_cons =
            unsafe { AtomicU32::from_ptr(self.ring.consumer) }.load(Ordering::Acquire);
        self.ring.cached_cons += self.ring.size;

        return self.ring.cached_cons - self.ring.cached_prod;
    }

    /// Reserves a batch of descriptors from the ring.
    ///
    /// This mirrors the functionality of the `xsk_ring_prod__reserve` function:
    /// Path: `vendor/xdp-tools/headers/xdp/xsk.h:124`
    ///
    /// ```c
    /// XDP_ALWAYS_INLINE __u32 xsk_ring_prod__reserve(struct xsk_ring_prod *prod, __u32 nb, __u32 *idx)
    /// {
    ///     if (xsk_prod_nb_free(prod, nb) < nb)
    ///         return 0;
    ///
    ///    *idx = prod->cached_prod;
    ///     prod->cached_prod += nb;
    ///
    ///     return nb;
    /// }
    /// ```
    #[inline(always)]
    pub fn reserve(&mut self, batch_size: u32) -> (u32, u32) {
        if self.nb_free(batch_size) < batch_size {
            return (0, 0);
        }

        let idx = self.ring.cached_prod;
        self.ring.cached_prod += batch_size;
        (idx, batch_size)
    }

    /// Returns a mutable reference to the TX descriptor at the given index.
    ///
    /// This mirrors the functionality of the `xsk_ring_prod__tx_desc` function:
    /// Path: `vendor/xdp-tools/headers/xdp/xsk.h:71`
    ///
    /// ```c
    /// XDP_ALWAYS_INLINE struct xdp_desc *xsk_ring_prod__tx_desc(struct xsk_ring_prod *tx, __u32 idx)
    /// {
    /// 	struct xdp_desc *descs = (struct xdp_desc *)tx->ring;
    ///
    /// 	return &descs[idx & tx->mask];
    /// }
    /// ```
    #[inline(always)]
    pub fn tx_desc(&mut self, index: u32) -> *mut xdp_desc {
        unsafe { (self.ring.ring as *mut xdp_desc).add((index & self.ring.mask) as usize) }
    }

    /// Returns a mutable reference to the fill address at the given index.
    ///
    /// This mirrors the functionality of the `xsk_ring_prod__fill_addr` function:
    /// Path: `vendor/xdp-tools/headers/xdp/xsk.h:55`
    ///
    /// ```c
    /// XDP_ALWAYS_INLINE __u64 *xsk_ring_prod__fill_addr(struct xsk_ring_prod *fill, __u32 idx)
    /// {
    /// 	__u64 *addrs = (__u64 *)fill->ring;
    ///
    /// 	return &addrs[idx & fill->mask];
    /// }
    /// ```
    #[inline(always)]
    pub fn fill_addr(&mut self, index: u32) -> *mut u64 {
        unsafe { (self.ring.ring as *mut u64).add((index & self.ring.mask) as usize) }
    }

    /// Submits a batch of descriptors to the ring.
    ///
    /// This mirrors the functionality of the `xsk_ring_prod__submit` function:
    /// Path: `vendor/xdp-tools/headers/xdp/xsk.h:135`
    ///
    /// ```c
    /// XDP_ALWAYS_INLINE void xsk_ring_prod__submit(struct xsk_ring_prod *prod, __u32 nb)
    /// {
    /// 	/* Make sure everything has been written to the ring before indicating
    /// 	* this to the kernel by writing the producer pointer.
    /// 	*/
    /// 	__atomic_store_n(prod->producer, *prod->producer + nb, __ATOMIC_RELEASE);
    /// }
    /// ```
    #[inline(always)]
    pub fn submit(&mut self, count: u32) {
        unsafe {
            AtomicU32::from_ptr(self.ring.producer)
                .store(*self.ring.producer + count, Ordering::Release)
        };
    }

    /// Returns true if the producer ring needs to be woken up.
    ///
    /// This mirrors the functionality of the `xsk_ring_prod__needs_wakeup` function:
    /// Path: `vendor/xdp-tools/headers/xdp/xsk.h:87`
    ///
    /// ```c
    /// XDP_ALWAYS_INLINE int xsk_ring_prod__needs_wakeup(const struct xsk_ring_prod *r)
    /// {
    /// 	return *r->flags & XDP_RING_NEED_WAKEUP;
    /// }
    /// ```
    #[inline(always)]
    pub fn needs_wakeup(&self) -> bool {
        unsafe { *self.ring.flags & XDP_RING_NEED_WAKEUP != 0 }
    }
}
