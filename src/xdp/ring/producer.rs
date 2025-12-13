use std::{cmp::min, marker::PhantomData, ptr::null_mut};

use errno::errno;
use libc::{EAGAIN, EBUSY, ENETDOWN, ENOBUFS, MSG_DONTWAIT, c_int, recvfrom, sendto};
use libxdp_sys::{
    xdp_desc, xsk_ring_prod, xsk_ring_prod__fill_addr, xsk_ring_prod__needs_wakeup,
    xsk_ring_prod__reserve, xsk_ring_prod__submit, xsk_ring_prod__tx_desc,
};

use super::{Error, Result};

/// A TX producer ring is a ring of descriptors that are used to transfer packets from the user to the kernel for write purposes.
pub struct Tx;

/// A FQ producer ring is a ring of descriptors that are used to transfer packets from the user to the kernelf ror read purposes.
pub struct Fq;

/// A producer ring is a ring of descriptors that are used to transfer packets from the user to the kernel.
pub struct Producer<T> {
    ring: Box<xsk_ring_prod>,
    ring_size: u32,
    phantom: PhantomData<T>,
}

impl<T> Producer<T> {
    /// Creates a new producer ring.
    #[inline]
    fn new(ring_size: u32) -> Producer<T> {
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
        Self {
            ring,
            ring_size,
            phantom: PhantomData,
        }
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

impl Producer<Tx> {
    /// Creates a new TX producer ring.
    #[inline]
    pub fn new_tx(ring_size: u32) -> Producer<Tx> {
        Producer::<Tx>::new(ring_size)
    }

    /// Maybe wake this producer ring's associated socket.
    #[inline]
    pub fn maybe_wake(&self, fd: c_int) -> Result<()> {
        unsafe {
            if xsk_ring_prod__needs_wakeup(self.ring.as_ref()) == 1 {
                let ret = sendto(fd, null_mut(), 0, MSG_DONTWAIT, null_mut(), 0);
                let errno = errno();
                if ret < 0
                    && errno.0 != ENOBUFS
                    && errno.0 != EAGAIN
                    && errno.0 != EBUSY
                    && errno.0 != ENETDOWN
                {
                    return Err(Error::Wake(errno));
                }
            }
        }
        Ok(())
    }
}

impl Producer<Fq> {
    /// Creates a new FQ producer ring.
    #[inline]
    pub fn new_fq(ring_size: u32) -> Producer<Fq> {
        Producer::<Fq>::new(ring_size)
    }

    /// Maybe wake this producer ring's associated socket.
    #[inline]
    pub fn maybe_wake(&self, fd: c_int) -> Result<()> {
        unsafe {
            if xsk_ring_prod__needs_wakeup(self.ring.as_ref()) == 1 {
                let ret = recvfrom(fd, null_mut(), 0, MSG_DONTWAIT, null_mut(), null_mut());
                let errno = errno();
                if ret < 0
                    && errno.0 != ENOBUFS
                    && errno.0 != EAGAIN
                    && errno.0 != EBUSY
                    && errno.0 != ENETDOWN
                {
                    return Err(Error::Wake(errno));
                }
            }
        }
        Ok(())
    }
}
