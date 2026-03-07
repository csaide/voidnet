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

// SAFETY: The only reason [Consumer] is not send is because of the raw pointers in xsk_ring_cons, these pointers are tied to this
// xsk_ring_cons so their lifetime is tied to it and we can safely send this to another thread because the pointers are into a heap
// allocated memory region that cannot move, and more so not controlled by us or the caller.
unsafe impl<I> Send for Consumer<I> {}

impl<I> Consumer<I> {
    /// Returns a read-only pointer to the consumer ring.
    #[inline(always)]
    pub fn as_ptr(&self) -> *const xsk_ring_cons {
        &self.ring as *const xsk_ring_cons
    }

    /// Returns a mutable pointer to the consumer ring.
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

    /// Assume the consumer has been initialized by the kernel, returning a wrapped [`Consumer<Init>`] which can be used to access the ring safely.
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

impl Default for Consumer<Uninit> {
    fn default() -> Self {
        Self::new()
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
    ///     __u32 entries = r->cached_prod - r->cached_cons;
    ///
    ///     if (entries == 0) {
    ///         r->cached_prod = __atomic_load_n(r->producer, __ATOMIC_ACQUIRE);
    ///         entries = r->cached_prod - r->cached_cons;
    ///     }
    ///
    ///     return (entries > nb) ? nb : entries;
    /// }
    /// ```
    #[inline(always)]
    pub fn nb_avail(&mut self, batch_size: u32) -> u32 {
        let mut entries = self.ring.cached_prod - self.ring.cached_cons;

        // TODO(csaide): This feels like a bug, but I'm not sure if its a bug or just my misunderstanding here.
        // without this change i.e. checking if entries < batch_size, we end up with _very_ small numbers per batch, generally 1-2.
        // This feels completely wrong and this works just fine, but I am reaching out to the libxdp authors to confirm.
        //
        // if entries == 0 {
        if entries < batch_size {
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
    // #[inline(always)]
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
    // #[inline(always)]
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
    // #[inline(always)]
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Test harness that simulates a kernel-initialized Consumer ring.
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

        fn init(&mut self, cached_prod: u32, cached_cons: u32) -> Consumer<Init> {
            let mut c = Consumer::<Uninit>::new();
            unsafe {
                let r = c.as_mut_ptr();
                (*r).size = self.ring.len() as u32;
                (*r).mask = self.ring.len() as u32 - 1;
                (*r).producer = self.producer.as_mut();
                (*r).consumer = self.consumer.as_mut();
                (*r).ring = self.ring.as_mut_ptr() as *mut _;
                (*r).flags = self.flags.as_mut();
                (*r).cached_prod = cached_prod;
                (*r).cached_cons = cached_cons;
            }
            unsafe { c.assume_init() }
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
    fn test_uninit_consumer() {
        let mut c = Consumer::<Uninit>::new();

        // Verify zeroed state
        unsafe {
            let r = &*c.as_ptr();
            assert_eq!((r.cached_prod, r.cached_cons, r.mask, r.size), (0, 0, 0, 0));
            assert!(r.producer.is_null() && r.consumer.is_null() && r.ring.is_null());
        }

        // Verify mutable access
        unsafe { (*c.as_mut_ptr()).size = 42 };
        assert_eq!(c.ring.size, 42);
    }

    #[test]
    fn test_size() {
        let mut h = Harness::<u64>::new(32);
        assert_eq!(h.init(0, 0).size(), 32);
    }

    // ============================================================================
    // nb_avail
    // ============================================================================

    #[test]
    fn test_nb_avail() {
        let mut h = Harness::<u64>::new(16);
        *h.producer = 8;

        // Returns min(entries, batch)
        assert_eq!(h.init(7, 5).nb_avail(10), 3); // entries < batch
        assert_eq!(h.init(20, 5).nb_avail(8), 8); // entries > batch
        assert_eq!(h.init(15, 5).nb_avail(10), 10); // entries == batch

        // Returns zero when empty
        *h.producer = 5;
        assert_eq!(h.init(5, 5).nb_avail(10), 0);

        // Refreshes from producer when cached empty
        *h.producer = 8;
        let mut c = h.init(0, 0);
        assert_eq!(c.nb_avail(10), 8);
        unsafe { assert_eq!((*c.as_ptr()).cached_prod, 8) };
    }

    // ============================================================================
    // peek
    // ============================================================================

    #[test]
    fn test_peek() {
        let mut h = Harness::<u64>::new(16);

        // Returns idx and advances cached_cons
        let mut c = h.init(10, 3);
        assert_eq!(c.peek(5), (3, 5));
        unsafe { assert_eq!((*c.as_ptr()).cached_cons, 8) };

        // Returns (0, 0) and doesn't modify when empty
        *h.producer = 5;
        let mut c = h.init(5, 5);
        assert_eq!(c.peek(10), (0, 0));
        unsafe { assert_eq!((*c.as_ptr()).cached_cons, 5) };

        // Sequential calls advance correctly
        *h.producer = 20;
        let mut c = h.init(20, 0);
        assert_eq!(c.peek(5), (0, 5));
        assert_eq!(c.peek(5), (5, 5));
        assert_eq!(c.peek(100), (10, 10)); // capped at remaining
    }

    // ============================================================================
    // rx_desc (RX ring access)
    // ============================================================================

    #[test]
    fn test_rx_desc() {
        let mut h = Harness::<Desc>::new(8); // mask = 7
        h.ring[0] = Desc(xdp_desc {
            addr: 0x1000,
            len: 64,
            options: 0,
        });
        h.ring[3] = Desc(xdp_desc {
            addr: 0xDEADBEEF,
            len: 1500,
            options: 0xFF,
        });
        h.ring[7] = Desc(xdp_desc {
            addr: 0x7000,
            len: 256,
            options: 2,
        });

        let mut c = h.init(0, 0);

        // Direct access with all fields
        let d = c.rx_desc(3);
        assert_eq!((d.addr, d.len, d.options), (0xDEADBEEF, 1500, 0xFF));

        // Boundary and wraparound (mask = 7)
        assert_eq!(c.rx_desc(7).addr, 0x7000);
        assert_eq!(c.rx_desc(8).addr, 0x1000); // 8 & 7 = 0
        assert_eq!(c.rx_desc(19).addr, 0xDEADBEEF); // 19 & 7 = 3
    }

    // ============================================================================
    // comp_addr (Completion ring access)
    // ============================================================================

    #[test]
    fn test_comp_addr() {
        let mut h = Harness::<u64>::new(8); // mask = 7
        h.ring[0] = 0;
        h.ring[3] = 0xAAAA_BBBB_CCCC_DDDD;
        h.ring[7] = u64::MAX;

        let mut c = h.init(0, 0);

        // Direct access with edge values
        assert_eq!(c.comp_addr(0), 0);
        assert_eq!(c.comp_addr(7), u64::MAX);

        // Masking and wraparound
        assert_eq!(c.comp_addr(3), 0xAAAA_BBBB_CCCC_DDDD);
        assert_eq!(c.comp_addr(19), 0xAAAA_BBBB_CCCC_DDDD); // 19 & 7 = 3
        assert_eq!(c.comp_addr(8), 0); // 8 & 7 = 0
    }

    // ============================================================================
    // release
    // ============================================================================

    #[test]
    fn test_release() {
        let mut h = Harness::<u64>::new(16);
        let mut c = h.init(0, 0);

        c.release(3);
        assert_eq!(*h.consumer, 3);

        c.release(5);
        assert_eq!(*h.consumer, 8);

        c.release(0);
        assert_eq!(*h.consumer, 8); // no-op
    }

    // ============================================================================
    // cancel
    // ============================================================================

    #[test]
    fn test_cancel() {
        let mut h = Harness::<u64>::new(16);
        let mut c = h.init(10, 0);

        c.peek(8);
        unsafe { assert_eq!((*c.as_ptr()).cached_cons, 8) };

        c.cancel(3);
        unsafe { assert_eq!((*c.as_ptr()).cached_cons, 5) };

        c.cancel(5);
        unsafe { assert_eq!((*c.as_ptr()).cached_cons, 0) };

        c.cancel(0);
        unsafe { assert_eq!((*c.as_ptr()).cached_cons, 0) }; // no-op
    }

    // ============================================================================
    // Integration: Full Workflows
    // ============================================================================

    #[test]
    fn test_rx_workflow() {
        let mut h = Harness::<Desc>::new(8);
        for i in 0..4 {
            h.ring[i] = Desc(xdp_desc {
                addr: (i as u64) * 4096,
                len: 64 + (i as u32) * 10,
                options: 0,
            });
        }
        *h.producer = 4;

        let mut c = h.init(4, 0);

        let (idx, n) = c.peek(10);
        assert_eq!((idx, n), (0, 4));

        for i in 0..n {
            assert_eq!(c.rx_desc(idx + i).addr, (i as u64) * 4096);
        }

        c.release(n);
        assert_eq!(*h.consumer, 4);
    }

    #[test]
    fn test_completion_workflow() {
        let mut h = Harness::<u64>::new(8);
        for i in 0..3 {
            h.ring[i] = (i as u64) * 0x1000;
        }
        *h.producer = 3;

        let mut c = h.init(3, 0);

        let (idx, n) = c.peek(10);
        let addrs: Vec<_> = (0..n).map(|i| c.comp_addr(idx + i)).collect();
        assert_eq!(addrs, [0x0000, 0x1000, 0x2000]);

        c.release(n);
        assert_eq!(*h.consumer, 3);
    }

    #[test]
    fn test_cancel_workflow() {
        let mut h = Harness::<Desc>::new(8);
        h.ring[0] = Desc(xdp_desc {
            addr: 0x1000,
            len: 100,
            options: 0,
        });
        *h.producer = 1;

        let mut c = h.init(1, 0);

        // Peek, cancel, re-peek should yield same result
        let first = c.peek(5);
        c.cancel(first.1);
        assert_eq!(c.peek(5), first);

        c.release(first.1);
        assert_eq!(*h.consumer, 1);
    }

    #[test]
    fn test_producer_refresh_on_exhaustion() {
        let mut h = Harness::<Desc>::new(8);
        for i in 0..4 {
            h.ring[i] = Desc(xdp_desc {
                addr: i as u64,
                len: 64,
                options: 0,
            });
        }
        *h.producer = 4;

        let mut c = h.init(4, 0);

        // Drain initial batch
        let (_, n) = c.peek(10);
        c.release(n);
        assert_eq!(c.peek(10), (0, 0)); // exhausted cached

        // Kernel produces more
        for i in 4..7 {
            h.ring[i] = Desc(xdp_desc {
                addr: i as u64,
                len: 64,
                options: 0,
            });
        }
        *h.producer = 7;

        // Should refresh and see new entries
        let (_, n) = c.peek(10);
        assert_eq!(n, 3);
        c.release(n);
        assert_eq!(*h.consumer, 7);
    }
}
