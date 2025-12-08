use std::ffi::CString;

use errno::errno;
use libxdp_sys::{
    XDP_USE_NEED_WAKEUP, xsk_socket, xsk_socket__create, xsk_socket__delete, xsk_socket__fd,
    xsk_socket_config, xsk_socket_config__bindgen_ty_1,
};

use crate::xdp::{
    ring::{Consumer, Producer, Tx},
    socket::FinalizedFrame,
    umem::{Frame, Umem},
};

use super::{Error, Result, SendFrame};

pub struct Socket {
    umem: Umem,
    socket: Box<xsk_socket>,
    fd: std::os::raw::c_int,
    rx: Consumer,
    tx: Producer<Tx>,
}

impl Socket {
    pub fn new(
        if_name: &str,
        queue: u32,
        mut umem: Umem,
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

        let mut rx = Consumer::new();
        let mut tx = Producer::new_tx();

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
                umem.umem(),
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

    fn reserve_fq(&mut self, rcvd: u32) -> Result<u32> {
        let (mut idx_fq, mut ready) = self.umem.fq_mut().reserve(rcvd).unwrap_or((0, 0));
        while ready != rcvd {
            (idx_fq, ready) = self.umem.fq_mut().reserve(rcvd).unwrap_or((0, 0));
            self.umem.fq_mut().maybe_wake(self.fd)?;
        }

        Ok(idx_fq)
    }

    pub fn recv_cb<F>(&mut self, batch_size: u32, mut f: F) -> Result<()>
    where
        F: FnMut(Frame),
    {
        let (mut idx_rx, rcvd) = match self.rx.peek(batch_size) {
            Some((idx, rcvd)) => (idx, rcvd),
            None => {
                self.umem.fq_mut().maybe_wake(self.fd)?;
                return Err(Error::WouldBlock);
            }
        };

        let mut idx_fq = self.reserve_fq(rcvd)?;

        for _ in 0..rcvd {
            let desc = self.rx.rx_desc(idx_rx);

            f(self.umem.get_frame(desc.addr, desc.len as usize));

            let addr = self.umem.fq_mut().fill_addr(idx_fq);
            unsafe { *addr = desc.addr as u64 };

            idx_rx += 1;
            idx_fq += 1;
        }

        self.umem.fq_mut().submit(rcvd);
        self.rx.release(rcvd);

        Ok(())
    }

    pub fn send_cb<F>(&mut self, batch_size: u32, mut f: F) -> Result<()>
    where
        F: FnMut(SendFrame) -> FinalizedFrame,
    {
        let mut idx_tx = loop {
            if let Some((idx_tx, _)) = self.tx.reserve(batch_size) {
                break idx_tx;
            } else {
                self.tx.maybe_wake(self.fd)?;
                self.umem.handle_completions()?;
            }
        };

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
                let desc = self.tx.tx_desc(idx_tx);
                (*desc).addr = frame.addr();
                (*desc).len = frame.len() as u32;
            }

            idx_tx += 1;
        }

        self.tx.submit(batch_size);

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
