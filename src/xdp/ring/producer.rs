use std::{marker::PhantomData, ptr::null_mut};

use errno::errno;
use libc::{EAGAIN, EBUSY, ENETDOWN, ENOBUFS, MSG_DONTWAIT, c_int, recvfrom, sendto};
use libxdp_sys::{
    xdp_desc, xsk_ring_prod, xsk_ring_prod__fill_addr, xsk_ring_prod__needs_wakeup,
    xsk_ring_prod__reserve, xsk_ring_prod__submit, xsk_ring_prod__tx_desc,
};

/// A TX producer ring is a ring of descriptors that are used to transfer packets from the user to the kernel for write purposes.
pub struct Tx;

/// A FQ producer ring is a ring of descriptors that are used to transfer packets from the user to the kernelf ror read purposes.
pub struct Fq;

/// A producer ring is a ring of descriptors that are used to transfer packets from the user to the kernel.
pub struct Producer<T> {
    ring: Box<xsk_ring_prod>,
    phantom: PhantomData<T>,
}

impl<T> Producer<T> {
    fn new() -> Producer<T> {
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
            phantom: PhantomData,
        }
    }

    /// Returns the size of the producer ring.
    pub fn size(&self) -> u32 {
        self.ring.as_ref().size
    }

    /// Reserves a batch of descriptors from the ring.
    ///
    /// # Arguments
    ///
    /// * `batch_size` - The maximum batch size to reserve.
    pub fn reserve(&mut self, batch_size: u32) -> Option<(u32, u32)> {
        let mut idx: u32 = 0;
        let ready: u32 =
            unsafe { xsk_ring_prod__reserve(self.ring.as_mut(), batch_size, &mut idx) };
        if ready == 0 { None } else { Some((idx, ready)) }
    }

    /// Returns a mutable reference to the TX descriptor at the given index.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the TX descriptor to return.
    pub fn tx_desc(&mut self, index: u32) -> *mut xdp_desc {
        unsafe { xsk_ring_prod__tx_desc(self.ring.as_mut(), index) }
    }

    /// Returns a mutable reference to the fill address at the given index.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the fill address to return.
    pub fn fill_addr(&mut self, index: u32) -> *mut u64 {
        unsafe { xsk_ring_prod__fill_addr(self.ring.as_mut(), index) }
    }

    /// Submits a batch of descriptors to the ring.
    ///
    /// # Arguments
    ///
    /// * `count` - The number of descriptors to submit.
    pub fn submit(&mut self, count: u32) {
        unsafe { xsk_ring_prod__submit(self.ring.as_mut(), count) };
    }

    /// Returns a read-only reference to the producer ring.
    pub fn as_ref(&self) -> *const xsk_ring_prod {
        self.ring.as_ref()
    }

    /// Returns a mutable reference to the producer ring.
    pub fn as_mut(&mut self) -> *mut xsk_ring_prod {
        self.ring.as_mut()
    }
}

impl Producer<Tx> {
    /// Creates a new TX producer ring.
    pub fn new_tx() -> Producer<Tx> {
        Producer::<Tx>::new()
    }

    /// Maybe wake this producer ring's associated socket.
    ///
    /// # Arguments
    ///
    /// * `fd` - The file descriptor of the socket to wake.
    pub fn maybe_wake(&self, fd: c_int) -> std::io::Result<()> {
        unsafe {
            if xsk_ring_prod__needs_wakeup(self.ring.as_ref()) == 1 {
                let ret = sendto(fd, null_mut(), 0, MSG_DONTWAIT, null_mut(), 0);
                let errno = errno().0;
                if ret < 0
                    && errno != ENOBUFS
                    && errno != EAGAIN
                    && errno != EBUSY
                    && errno != ENETDOWN
                {
                    return Err(std::io::Error::from_raw_os_error(errno));
                }
            }
        }
        Ok(())
    }
}

impl Producer<Fq> {
    /// Creates a new FQ producer ring.
    pub fn new_fq() -> Producer<Fq> {
        Producer::<Fq>::new()
    }

    /// Maybe wake this producer ring's associated socket.
    ///
    /// # Arguments
    ///
    /// * `fd` - The file descriptor of the socket to wake.
    pub fn maybe_wake(&self, fd: c_int) -> std::io::Result<()> {
        unsafe {
            if xsk_ring_prod__needs_wakeup(self.ring.as_ref()) == 1 {
                let ret = recvfrom(fd, null_mut(), 0, MSG_DONTWAIT, null_mut(), null_mut());
                let errno = errno().0;
                if ret < 0
                    && errno != ENOBUFS
                    && errno != EAGAIN
                    && errno != EBUSY
                    && errno != ENETDOWN
                {
                    return Err(std::io::Error::from_raw_os_error(errno));
                }
            }
        }
        Ok(())
    }
}
