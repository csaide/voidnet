use std::{collections::VecDeque, ffi::CString, sync::Arc};

use errno::errno;
use libc::c_int;
use libxdp_sys::{
    XDP_USE_NEED_WAKEUP, XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD, XSK_RING_CONS__DEFAULT_NUM_DESCS,
    XSK_RING_PROD__DEFAULT_NUM_DESCS, xsk_socket, xsk_socket__create, xsk_socket__create_shared,
    xsk_socket__fd, xsk_socket_config, xsk_socket_config__bindgen_ty_1,
};

use crate::xdp_v2::{
    context::XdpContext,
    error::{Error, Result},
    frame::Frame,
    ring::{Consumer, Producer},
    umem::{CompletionQueue, FillQueue, Umem},
};

use super::{SocketOwner, SocketRx, SocketTx};

/// Builder for creating a new socket.
pub struct SocketBuilder<'a, 'b> {
    ctx: &'b mut XdpContext,
    if_name: &'a str,
    queue: u32,
    rx_ring_size: u32,
    tx_ring_size: u32,
}

impl<'a, 'b> SocketBuilder<'a, 'b> {
    /// Creates a new socket builder, using the supllied interface name and queue number.
    ///
    /// The defaults included are sane values for most use cases.
    pub fn new(ctx: &'b mut XdpContext, if_name: &'a str, queue: u32) -> Self {
        Self {
            ctx,
            if_name,
            queue,
            rx_ring_size: XSK_RING_CONS__DEFAULT_NUM_DESCS,
            tx_ring_size: XSK_RING_PROD__DEFAULT_NUM_DESCS,
        }
    }

    /// Sets the size of the RX ring.
    pub fn rx_ring_size(mut self, rx_ring_size: u32) -> Self {
        self.rx_ring_size = rx_ring_size;
        self
    }

    /// Sets the size of the TX ring.
    pub fn tx_ring_size(mut self, tx_ring_size: u32) -> Self {
        self.tx_ring_size = tx_ring_size;
        self
    }

    /// Builds the socket.
    pub fn build(self, umem: Arc<Umem>) -> Result<Socket> {
        // Then create the socket, this will allocate the RX/TX rings and bind the socket + rings to the UMEM object.
        let socket = Socket::new(
            self.if_name,
            self.queue,
            umem,
            self.rx_ring_size,
            self.tx_ring_size,
        )?;
        self.ctx.register_socket(&socket).map(|_| socket)
    }

    pub fn build_shared(
        self,
        umem: Arc<Umem>,
        fq: &mut FillQueue,
        cq: &mut CompletionQueue,
    ) -> Result<Socket> {
        let socket = Socket::new_shared(
            self.if_name,
            self.queue,
            umem,
            fq,
            cq,
            self.rx_ring_size,
            self.tx_ring_size,
        )?;
        self.ctx.register_socket(&socket).map(|_| socket)
    }
}

pub struct Socket {
    owner: Arc<SocketOwner>,
    rx: SocketRx,
    tx: SocketTx,
}

impl Socket {
    /// Returns a builder for creating a new socket.
    pub fn builder<'a, 'b>(
        xdp_ctx: &'b mut XdpContext,
        if_name: &'a str,
        queue: u32,
    ) -> SocketBuilder<'a, 'b> {
        SocketBuilder::new(xdp_ctx, if_name, queue)
    }

    pub fn new(
        if_name: &str,
        queue: u32,
        umem: Arc<Umem>,
        rx_ring_size: u32,
        tx_ring_size: u32,
    ) -> Result<Self> {
        let cfg = xsk_socket_config {
            rx_size: rx_ring_size,
            tx_size: tx_ring_size,
            xdp_flags: 0,
            bind_flags: XDP_USE_NEED_WAKEUP as u16,
            __bindgen_anon_1: xsk_socket_config__bindgen_ty_1 {
                libxdp_flags: XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD,
            },
        };

        let mut rx = Consumer::new(rx_ring_size);
        let mut tx = Producer::new(tx_ring_size);

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
            return Err(Error::CreateSocket(errno()));
        }

        let owner = Arc::new(SocketOwner {
            _umem: umem.clone(),
            socket: unsafe { Box::from_raw(*xsk_ptr) },
            fd: unsafe { xsk_socket__fd(*xsk_ptr) },
        });
        let rx = SocketRx::new(owner.clone(), rx, umem.frame_stack());
        let tx = SocketTx::new(owner.clone(), tx, umem.frame_stack());
        Ok(Self { owner, rx, tx })
    }

    pub fn new_shared(
        if_name: &str,
        queue: u32,
        umem: Arc<Umem>,
        fq: &mut FillQueue,
        cq: &mut CompletionQueue,
        rx_ring_size: u32,
        tx_ring_size: u32,
    ) -> Result<Self> {
        let cfg = xsk_socket_config {
            rx_size: rx_ring_size,
            tx_size: tx_ring_size,
            xdp_flags: 0,
            bind_flags: XDP_USE_NEED_WAKEUP as u16,
            __bindgen_anon_1: xsk_socket_config__bindgen_ty_1 {
                libxdp_flags: XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD,
            },
        };

        let mut rx = Consumer::new(rx_ring_size);
        let mut tx = Producer::new(tx_ring_size);

        // C function has double indirection
        let mut xsk: *mut xsk_socket = std::ptr::null_mut();
        let xsk_ptr: *mut *mut xsk_socket = &mut xsk;

        let if_name_c = CString::new(if_name).unwrap();

        let ret: std::os::raw::c_int;
        unsafe {
            ret = xsk_socket__create_shared(
                xsk_ptr,
                if_name_c.as_ptr(),
                queue as u32,
                umem.umem(),
                rx.as_mut(),
                tx.as_mut(),
                fq.as_mut(),
                cq.as_mut(),
                &cfg,
            );
        }

        if ret != 0 {
            return Err(Error::CreateSocket(errno()));
        }

        let owner = Arc::new(SocketOwner {
            _umem: umem.clone(),
            socket: unsafe { Box::from_raw(*xsk_ptr) },
            fd: unsafe { xsk_socket__fd(*xsk_ptr) },
        });
        let rx = SocketRx::new(owner.clone(), rx, umem.frame_stack());
        let tx = SocketTx::new(owner.clone(), tx, umem.frame_stack());
        Ok(Self { owner, rx, tx })
    }

    /// Splits the socket into its owner, rx, and tx components.
    #[inline]
    pub fn split(self) -> (Arc<SocketOwner>, SocketRx, SocketTx) {
        (self.owner, self.rx, self.tx)
    }

    /// Returns the file descriptor of the socket.
    #[inline]
    pub fn fd(&self) -> c_int {
        self.owner.fd
    }

    /// Possibly wakes the tx queue, so the kernel continues to process outgoing packets.
    #[inline]
    pub fn maybe_wake(&self) -> Result<()> {
        self.tx.maybe_wake()
    }

    /// Receives a batch of frames from the socket.
    ///
    /// Note that it is not guaranteed that the resulting Vec of frames will match the batch size supplied.
    /// It is considered a batch maximum and this function will return as soon as at least one frame is received.
    ///
    /// If no frames are available to read this returns None.
    #[inline]
    pub fn recv(&mut self, batch: &mut VecDeque<Frame>) -> usize {
        self.rx.recv(batch)
    }

    /// Sends a batch of frames to the socket.
    ///
    /// Note that it is not guaranteed that the resulting Vec of frames will match the batch size supplied.
    /// It is considered a batch maximum and this function will return as soon as at least one frame is sent.
    ///
    /// The caller should call this function until their batch of frames is empty.
    ///
    /// If no frames are availabel to send this returns an error of type [std::result::Result<(), ()>].
    #[inline]
    pub fn send(&mut self, frames: &mut VecDeque<Frame>) -> std::result::Result<u32, ()> {
        self.tx.send(frames)
    }
}
