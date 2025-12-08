use std::{ffi::CString, ptr::null_mut};

use errno::errno;
use libc::{EAGAIN, EBUSY, ENETDOWN, ENOBUFS, MSG_DONTWAIT, recvfrom, sendto};
use libxdp_sys::{
    XDP_USE_NEED_WAKEUP, xsk_ring_cons, xsk_ring_cons__peek, xsk_ring_cons__release,
    xsk_ring_cons__rx_desc, xsk_ring_prod, xsk_ring_prod__fill_addr, xsk_ring_prod__needs_wakeup,
    xsk_ring_prod__reserve, xsk_ring_prod__submit, xsk_ring_prod__tx_desc, xsk_socket,
    xsk_socket__create, xsk_socket__delete, xsk_socket__fd, xsk_socket_config,
    xsk_socket_config__bindgen_ty_1, xsk_umem,
};

use crate::xdp::{
    socket::FinalizedFrame,
    umem::{Frame, Umem},
};

use super::{Error, Result, SendFrame};

pub struct Socket {
    umem: Umem,
    socket: Box<xsk_socket>,
    fd: std::os::raw::c_int,
    rx: Box<xsk_ring_cons>,
    tx: Box<xsk_ring_prod>,
}

impl Socket {
    pub fn new(
        if_name: &str,
        queue: u32,
        umem: Umem,
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
                umem.umem() as *mut xsk_umem,
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
            socket: unsafe { Box::from_raw(*xsk_ptr) },
            fd: unsafe { xsk_socket__fd(*xsk_ptr) },
            rx,
            tx,
        })
    }

    fn maybe_wake_fq(&self, ring: *const xsk_ring_prod) {
        unsafe {
            if xsk_ring_prod__needs_wakeup(ring) == 1 {
                // Intentionally ignoring the return value.
                recvfrom(self.fd, null_mut(), 0, MSG_DONTWAIT, null_mut(), null_mut());
            }
        }
    }

    fn maybe_wake_tx(&self) -> Result<()> {
        unsafe {
            if xsk_ring_prod__needs_wakeup(self.tx.as_ref()) == 1 {
                let ret = sendto(self.fd, null_mut(), 0, MSG_DONTWAIT, null_mut(), 0);
                let errno = errno().0;
                if ret < 0
                    && errno != ENOBUFS
                    && errno != EAGAIN
                    && errno != EBUSY
                    && errno != ENETDOWN
                {
                    return Err(Error::Wake(std::io::Error::from_raw_os_error(errno)));
                }
            }
        }
        Ok(())
    }

    fn reserve_fq(&mut self, rcvd: u32) -> Result<u32> {
        let mut idx_fq: u32 = 0;
        let mut ready: u32 =
            unsafe { xsk_ring_prod__reserve(self.umem.fq_mut(), rcvd, &mut idx_fq) };
        while ready != rcvd {
            ready = unsafe { xsk_ring_prod__reserve(self.umem.fq_mut(), rcvd, &mut idx_fq) };
            self.maybe_wake_fq(self.umem.fq());
        }

        Ok(idx_fq)
    }

    pub fn recv_cb<F>(&mut self, batch_size: u32, mut f: F) -> Result<()>
    where
        F: FnMut(Frame),
    {
        let mut idx_rx: u32 = 0;
        let rcvd = unsafe { xsk_ring_cons__peek(self.rx.as_mut(), batch_size, &mut idx_rx) };
        if rcvd == 0 {
            self.maybe_wake_fq(self.umem.fq());
            return Err(Error::WouldBlock);
        }

        let mut idx_fq = self.reserve_fq(rcvd)?;

        for _ in 0..rcvd {
            let desc = unsafe { *xsk_ring_cons__rx_desc(self.rx.as_mut(), idx_rx) };

            f(self.umem.get_frame(desc.addr, desc.len as usize));

            unsafe {
                *xsk_ring_prod__fill_addr(self.umem.fq_mut(), idx_fq) = desc.addr as u64;
            }

            idx_rx += 1;
            idx_fq += 1;
        }

        unsafe {
            xsk_ring_prod__submit(self.umem.fq_mut(), rcvd);
            xsk_ring_cons__release(self.rx.as_mut(), rcvd);
        }

        Ok(())
    }

    pub fn recv(&mut self) -> Result<Frame> {
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

    pub fn send_cb<F>(&mut self, batch_size: u32, mut f: F) -> Result<()>
    where
        F: FnMut(SendFrame) -> FinalizedFrame,
    {
        let mut idx_tx: u32 = 0;
        while unsafe { xsk_ring_prod__reserve(self.tx.as_mut(), batch_size, &mut idx_tx) } == 0 {
            self.maybe_wake_tx()?;
            self.umem.handle_completions()?;
        }

        for _ in 0..batch_size {
            let frame = self.umem.get_next_free_frame().ok_or(Error::WouldBlock)?;
            let frame = match f(SendFrame::new(frame)) {
                FinalizedFrame::Committed(frame) => frame,
                FinalizedFrame::Aborted(frame) => {
                    let addr = frame.addr();
                    drop(frame);

                    self.umem.free_frame(addr);
                    return Err(Error::WouldBlock);
                }
            };

            unsafe {
                let desc = xsk_ring_prod__tx_desc(self.tx.as_mut(), idx_tx);
                (*desc).addr = frame.addr();
                (*desc).len = frame.len() as u32;
            }

            idx_tx += 1;
        }

        unsafe {
            xsk_ring_prod__submit(self.tx.as_mut(), batch_size);
        }

        Ok(())
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        unsafe {
            // No null pointer check here because it is initialized to null and if the create fails,
            // it should still be null and xsk_socket__delete handles null.
            xsk_socket__delete(self.socket.as_mut());
        }
    }
}
