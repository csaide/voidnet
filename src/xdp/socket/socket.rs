use std::{ffi::CString, ptr::null_mut};

use errno::errno;
use libc::{MSG_DONTWAIT, recvfrom};
use libxdp_sys::{
    XDP_USE_NEED_WAKEUP, xsk_ring_cons, xsk_ring_cons__peek, xsk_ring_cons__release,
    xsk_ring_cons__rx_desc, xsk_ring_prod, xsk_ring_prod__needs_wakeup, xsk_ring_prod__reserve,
    xsk_socket, xsk_socket__create, xsk_socket__delete, xsk_socket__fd, xsk_socket_config,
    xsk_socket_config__bindgen_ty_1, xsk_umem,
};

use crate::xdp::umem::{Frame, MemoryArea, Umem};

use super::{Error, Result};

pub struct Socket<P: MemoryArea> {
    umem: Umem<P>,
    _if_name: CString,
    socket: Box<xsk_socket>,
    _fd: std::os::raw::c_int,
    rx: Box<xsk_ring_cons>,
    _tx: Box<xsk_ring_prod>,
}

impl<P: MemoryArea> Socket<P> {
    pub fn new(
        if_name: &str,
        queue: u32,
        umem: Umem<P>,
        rx_ring_size: u32,
        tx_ring_size: u32,
    ) -> Result<Self> {
        let cfg = xsk_socket_config {
            rx_size: rx_ring_size,
            tx_size: tx_ring_size,
            xdp_flags: 0,
            bind_flags: XDP_USE_NEED_WAKEUP as u16,
            __bindgen_anon_1: xsk_socket_config__bindgen_ty_1 { libxdp_flags: 0 },
        };

        let mut rx: Box<xsk_ring_cons> = Box::new(xsk_ring_cons {
            cached_prod: 0,
            cached_cons: 0,
            mask: 0,
            size: 0,
            producer: std::ptr::null_mut(),
            consumer: std::ptr::null_mut(),
            ring: std::ptr::null_mut(),
            flags: std::ptr::null_mut(),
        });
        let mut tx: Box<xsk_ring_prod> = Box::new(xsk_ring_prod {
            cached_prod: 0,
            cached_cons: 0,
            mask: 0,
            size: 0,
            producer: std::ptr::null_mut(),
            consumer: std::ptr::null_mut(),
            ring: std::ptr::null_mut(),
            flags: std::ptr::null_mut(),
        });

        // C function has double indirection
        let mut xsk: *mut xsk_socket = std::ptr::null_mut();
        let xsk_ptr: *mut *mut xsk_socket = &mut xsk;

        let if_name_c = CString::new(if_name).unwrap();

        let ret: std::os::raw::c_int;
        unsafe {
            ret = xsk_socket__create(
                xsk_ptr,
                if_name_c.as_ptr(),
                queue as u32,
                umem.get_ptr() as *mut xsk_umem,
                rx.as_mut(),
                tx.as_mut(),
                &cfg,
            );
        }

        if ret != 0 {
            let errno = errno().0;
            return Err(Error::Create(std::io::Error::from_raw_os_error(errno)));
        }

        Ok(Self {
            umem,
            _if_name: if_name_c,
            socket: unsafe { Box::from_raw(*xsk_ptr) },
            _fd: unsafe { xsk_socket__fd(*xsk_ptr) },
            rx,
            _tx: tx,
        })
    }

    fn maybe_wake(&self, ring: *const xsk_ring_prod) {
        unsafe {
            if xsk_ring_prod__needs_wakeup(ring) == 1 {
                recvfrom(
                    self._fd,
                    null_mut(),
                    0,
                    MSG_DONTWAIT,
                    null_mut(),
                    null_mut(),
                );
            }
        }
    }

    fn reserve_fq(&mut self, rcvd: u32) -> Result<u32> {
        let mut idx_fq: u32 = 0;
        let mut ready: u32 =
            unsafe { xsk_ring_prod__reserve(self.umem.fq.as_mut(), rcvd, &mut idx_fq) };
        while ready != rcvd {
            ready = unsafe { xsk_ring_prod__reserve(self.umem.fq.as_mut(), rcvd, &mut idx_fq) };
            self.maybe_wake(self.umem.fq.as_ref());
        }

        Ok(idx_fq)
    }

    pub fn recv(&mut self) -> Result<Frame<'_>> {
        self.umem.fill_packets()?;

        let mut idx_rx: u32 = 0;

        let rcvd = unsafe { xsk_ring_cons__peek(self.rx.as_mut(), 1, &mut idx_rx) };
        if rcvd != 1 {
            return Err(Error::WouldBlock);
        }

        let (addr, len) = unsafe {
            let desc = xsk_ring_cons__rx_desc(self.rx.as_mut(), idx_rx);
            ((*desc).addr, (*desc).len.try_into().unwrap())
        };

        unsafe {
            xsk_ring_cons__release(self.rx.as_mut(), 1);
        }

        Ok(self.umem.get_frame(addr, len))
    }
}

impl<P: MemoryArea> Drop for Socket<P> {
    fn drop(&mut self) {
        unsafe {
            // No null pointer check here because it is initialized to null and if the create fails,
            // it should still be null and xsk_socket__delete handles null.
            xsk_socket__delete(self.socket.as_mut());
        }
    }
}
