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

// SAFETY: The only reason [Producer] is not send is because of the raw pointers in xsk_ring_prod, these pointers are tied to this
// xsk_ring_prod so their lifetime is tied to it and we can safely send this to another thread because the pointers are into a heap
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

    /// Assume the producer has been initialized by the kernel, returning a wrapped [`Producer<Init>`] which can be used to access the ring safely.
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

impl Default for Producer<Uninit> {
    fn default() -> Self {
        Self::new()
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

        self.ring.cached_cons - self.ring.cached_prod
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

    /// Returns a mutable pointer to the TX descriptor at the given index.
    ///
    /// This mirrors the functionality of the `xsk_ring_prod__tx_desc` function:
    /// Path: `vendor/xdp-tools/headers/xdp/xsk.h:71`
    ///
    /// ```c
    /// XDP_ALWAYS_INLINE struct xdp_desc *xsk_ring_prod__tx_desc(struct xsk_ring_prod *tx, __u32 idx)
    /// {
    ///     struct xdp_desc *descs = (struct xdp_desc *)tx->ring;
    ///
    ///     return &descs[idx & tx->mask];
    /// }
    /// ```
    #[inline(always)]
    pub fn tx_desc(&mut self, index: u32) -> *mut xdp_desc {
        unsafe { (self.ring.ring as *mut xdp_desc).add((index & self.ring.mask) as usize) }
    }

    /// Returns a mutable pointer to the fill address at the given index.
    ///
    /// This mirrors the functionality of the `xsk_ring_prod__fill_addr` function:
    /// Path: `vendor/xdp-tools/headers/xdp/xsk.h:55`
    ///
    /// ```c
    /// XDP_ALWAYS_INLINE __u64 *xsk_ring_prod__fill_addr(struct xsk_ring_prod *fill, __u32 idx)
    /// {
    ///     __u64 *addrs = (__u64 *)fill->ring;
    ///
    ///     return &addrs[idx & fill->mask];
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
    ///     /* Make sure everything has been written to the ring before indicating
    ///     * this to the kernel by writing the producer pointer.
    ///     */
    ///     __atomic_store_n(prod->producer, *prod->producer + nb, __ATOMIC_RELEASE);
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
    ///     return *r->flags & XDP_RING_NEED_WAKEUP;
    /// }
    /// ```
    #[inline(always)]
    pub fn needs_wakeup(&self) -> bool {
        unsafe { *self.ring.flags & XDP_RING_NEED_WAKEUP != 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test harness that simulates a kernel-initialized Producer ring.
    /// Uses boxed slice for stable pointers that won't move.
    struct Harness<T: Copy + Default> {
        ring: Box<[T]>,
        producer: Box<u32>,
        consumer: Box<u32>,
        flags: Box<u32>,
    }

    impl<T: Copy + Default> Harness<T> {
        fn new(size: u32) -> Self {
            assert!(size.is_power_of_two());
            Self {
                ring: vec![T::default(); size as usize].into_boxed_slice(),
                producer: Box::new(0),
                consumer: Box::new(0),
                flags: Box::new(0),
            }
        }

        fn init(&mut self, cached_prod: u32, cached_cons: u32) -> Producer<Init> {
            let mut p = Producer::<Uninit>::new();
            unsafe {
                let r = p.as_mut_ptr();
                (*r).size = self.ring.len() as u32;
                (*r).mask = self.ring.len() as u32 - 1;
                (*r).producer = self.producer.as_mut();
                (*r).consumer = self.consumer.as_mut();
                (*r).ring = self.ring.as_mut_ptr() as *mut _;
                (*r).flags = self.flags.as_mut();
                (*r).cached_prod = cached_prod;
                (*r).cached_cons = cached_cons;
            }
            unsafe { p.assume_init() }
        }
    }

    // Wrapper to provide Default for xdp_desc
    #[derive(Copy, Clone)]
    #[repr(transparent)]
    struct Desc(xdp_desc);

    impl Default for Desc {
        fn default() -> Self {
            Self(xdp_desc {
                addr: 0,
                len: 0,
                options: 0,
            })
        }
    }

    // ============================================================================
    // Construction & Pointer Access
    // ============================================================================

    #[test]
    fn test_uninit_producer() {
        let mut p = Producer::<Uninit>::new();

        // Verify zeroed state and pointer access
        unsafe {
            let r = &*p.as_ptr();
            assert_eq!((r.cached_prod, r.cached_cons, r.mask, r.size), (0, 0, 0, 0));
            assert!(r.producer.is_null() && r.consumer.is_null() && r.ring.is_null());
            (*p.as_mut_ptr()).size = 42;
        }
        assert_eq!(p.ring.size, 42);

        // Verify size after init
        let mut h = Harness::<u64>::new(32);
        assert_eq!(h.init(0, 0).size(), 32);
    }

    // ============================================================================
    // nb_free & reserve
    // ============================================================================

    #[test]
    fn test_nb_free() {
        let mut h = Harness::<u64>::new(16);

        // Fast path: cached free >= batch, returns cached value without refresh
        *h.consumer = 100; // Set different value to verify no refresh
        let mut p = h.init(5, 20); // free = 15 >= 10
        assert_eq!(p.nb_free(10), 15);
        unsafe { assert_eq!((*p.as_ptr()).cached_cons, 20) }; // Unchanged

        // Slow path: cached free < batch, triggers refresh from consumer
        *h.consumer = 10;
        let mut p = h.init(5, 5); // free = 0 < 8, triggers refresh
        // After refresh: cached_cons = consumer(10) + size(16) = 26, free = 21
        assert_eq!(p.nb_free(8), 21);
        unsafe { assert_eq!((*p.as_ptr()).cached_cons, 26) };
    }

    #[test]
    fn test_reserve() {
        let mut h = Harness::<u64>::new(16);

        // Success: returns (idx, count) and advances cached_prod
        let mut p = h.init(5, 20); // free = 15
        assert_eq!(p.reserve(10), (5, 10));
        unsafe { assert_eq!((*p.as_ptr()).cached_prod, 15) };

        // Failure: returns (0, 0) when insufficient even after refresh
        *h.consumer = 0;
        let mut p = h.init(10, 10); // free = 0, after refresh = 6 < 8
        assert_eq!(p.reserve(8), (0, 0));

        // Sequential: idx advances correctly
        let mut p = h.init(0, 32);
        assert_eq!(p.reserve(5), (0, 5));
        assert_eq!(p.reserve(5), (5, 5));
        assert_eq!(p.reserve(5), (10, 5));
        assert_eq!(p.reserve(20), (0, 0)); // Only 17 free
    }

    // ============================================================================
    // Ring Access (tx_desc, fill_addr)
    // ============================================================================

    #[test]
    fn test_tx_desc() {
        let mut h = Harness::<Desc>::new(8); // mask = 7
        let mut p = h.init(0, 16);

        // Direct and masked access
        unsafe {
            (*p.tx_desc(0)).addr = 0x1000;
            (*p.tx_desc(3)).addr = 0xDEAD;
            (*p.tx_desc(8)).addr = 0x8888; // 8 & 7 = 0 (wraparound)
            (*p.tx_desc(19)).addr = 0x1919; // 19 & 7 = 3 (wraparound)
        }
        assert_eq!(h.ring[0].0.addr, 0x8888); // Overwritten by idx 8
        assert_eq!(h.ring[3].0.addr, 0x1919); // Overwritten by idx 19
    }

    #[test]
    fn test_fill_addr() {
        let mut h = Harness::<u64>::new(8); // mask = 7
        let mut p = h.init(0, 16);

        // Direct and masked access
        unsafe {
            *p.fill_addr(0) = 0x1000;
            *p.fill_addr(3) = 0xDEAD;
            *p.fill_addr(8) = 0x8888; // 8 & 7 = 0 (wraparound)
            *p.fill_addr(19) = 0x1919; // 19 & 7 = 3 (wraparound)
        }
        assert_eq!(h.ring[0], 0x8888); // Overwritten by idx 8
        assert_eq!(h.ring[3], 0x1919); // Overwritten by idx 19
    }

    // ============================================================================
    // submit & needs_wakeup
    // ============================================================================

    #[test]
    fn test_submit() {
        let mut h = Harness::<u64>::new(16);
        let mut p = h.init(0, 16);

        p.submit(3);
        assert_eq!(*h.producer, 3);
        p.submit(5);
        assert_eq!(*h.producer, 8);
    }

    #[test]
    fn test_needs_wakeup() {
        let mut h = Harness::<u64>::new(16);

        *h.flags = 0;
        assert!(!h.init(0, 0).needs_wakeup());

        *h.flags = XDP_RING_NEED_WAKEUP;
        assert!(h.init(0, 0).needs_wakeup());

        *h.flags = XDP_RING_NEED_WAKEUP | 0xF0; // Mixed bits
        assert!(h.init(0, 0).needs_wakeup());
    }

    // ============================================================================
    // Integration: Full Workflows
    // ============================================================================

    #[test]
    fn test_tx_workflow() {
        let mut h = Harness::<Desc>::new(8);
        let mut p = h.init(0, 8);

        // Reserve, fill, submit
        let (idx, n) = p.reserve(4);
        assert_eq!((idx, n), (0, 4));
        for i in 0..n {
            unsafe {
                (*p.tx_desc(idx + i)).addr = (i as u64) * 4096;
                (*p.tx_desc(idx + i)).len = 64;
            }
        }
        p.submit(n);
        assert_eq!(*h.producer, 4);

        // Ring is now full, reserve fails
        assert_eq!(p.reserve(8), (0, 0));

        // Kernel consumes, wakeup flag set
        *h.consumer = 4;
        *h.flags = XDP_RING_NEED_WAKEUP;
        assert!(p.needs_wakeup());

        // After wakeup, can reserve again (refresh: cached_cons = 4 + 8 = 12)
        let (idx, n) = p.reserve(4);
        assert_eq!((idx, n), (4, 4));
    }

    #[test]
    fn test_fill_workflow() {
        let mut h = Harness::<u64>::new(8);
        let mut p = h.init(0, 8);

        // Reserve, fill addresses, submit
        let (idx, n) = p.reserve(3);
        for i in 0..n {
            unsafe { *p.fill_addr(idx + i) = (i as u64) * 0x1000 };
        }
        p.submit(n);

        assert_eq!((h.ring[0], h.ring[1], h.ring[2]), (0x0000, 0x1000, 0x2000));
        assert_eq!(*h.producer, 3);
    }
}
