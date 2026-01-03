use std::{ffi::CString, os::raw::c_void, sync::Arc};

use errno::errno;
use libc::{SO_BUSY_POLL, SO_BUSY_POLL_BUDGET, SO_PREFER_BUSY_POLL, SOL_SOCKET, c_int, setsockopt};
use libxdp_sys::{
    XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD, XSK_RING_CONS__DEFAULT_NUM_DESCS,
    XSK_RING_PROD__DEFAULT_NUM_DESCS, xsk_socket, xsk_socket__create, xsk_socket__fd,
    xsk_socket_config, xsk_socket_config__bindgen_ty_1,
};

use crate::{
    futures::{RecvFuture, SendFuture},
    xdp::{
        context::XdpContext,
        error::{Error, NonBlocking, Result},
        flags::{XDP_USE_NEED_WAKEUP, XDP_USE_SG},
        frame_v2::FrameBuffer,
        ring::{Consumer, Producer},
        socket::{BindMode, mode::CopyMode},
        umem::Umem,
    },
};

use super::{SocketOwner, SocketRx, SocketTx};

/// Builder for creating a new socket.
pub struct SocketBuilder<'a, 'b> {
    ctx: &'b mut XdpContext,
    if_name: &'a str,
    queue: u32,
    rx_ring_size: u32,
    tx_ring_size: u32,
    busy_poll: bool,
    busy_poll_batch_size: usize,
    busy_poll_timeout_us: i32,
    copy_mode: CopyMode,
    enable_fragmentation: bool,
}

impl<'a, 'b> SocketBuilder<'a, 'b> {
    /// Creates a new socket builder, using the supplied interface name and queue number.
    ///
    /// The defaults included are sane values for most use cases.
    pub fn new(ctx: &'b mut XdpContext, if_name: &'a str, queue: u32) -> Self {
        Self {
            ctx,
            if_name,
            queue,
            rx_ring_size: XSK_RING_CONS__DEFAULT_NUM_DESCS,
            tx_ring_size: XSK_RING_PROD__DEFAULT_NUM_DESCS,
            busy_poll: false,
            busy_poll_batch_size: 32,
            busy_poll_timeout_us: 20,
            copy_mode: CopyMode::default(),
            enable_fragmentation: false,
        }
    }

    /// Sets the size of the RX ring, the maximum number of frames that can be outstanding RX at a time in the kernel.
    ///
    /// Note: This value can be any power of two that fits in a u32, however note that the device driver has a limited number of RX descriptors available. That descriptor limit is effectively
    /// the upper bound of this value, any value greater will work as intended but you will not get any more throughput.
    pub fn rx_ring_size(mut self, rx_ring_size: u32) -> Self {
        self.rx_ring_size = rx_ring_size;
        self
    }

    /// Sets the size of the TX ring, the maximum number of frames that can be outstanding TX at a time in the kernel.
    ///
    /// Note: This value can be any power of two that fits in a u32, however note that the device driver has a limited number of TX descriptors available. That limit is effectively
    /// the upper bound of this value, any value greater will work as intended but you will not get any more throughput.
    pub fn tx_ring_size(mut self, tx_ring_size: u32) -> Self {
        self.tx_ring_size = tx_ring_size;
        self
    }

    /// Sets whether to use busy polling, this is a more efficient way to poll for frames than using a blocking read, but will eat more CPU cycles.
    pub fn busy_poll(mut self, busy_poll: bool) -> Self {
        self.busy_poll = busy_poll;
        self
    }

    /// Sets the busy poll batch size, this is the maximum number of frames to wait for while busy polling.
    pub fn busy_poll_batch_size(mut self, busy_poll_batch_size: usize) -> Self {
        self.busy_poll_batch_size = busy_poll_batch_size;
        self
    }

    /// Sets the busy poll timeout in microseconds, this is the maximum time to wait for a frame while busy polling.
    pub fn busy_poll_timeout_us(mut self, busy_poll_timeout_us: i32) -> Self {
        self.busy_poll_timeout_us = busy_poll_timeout_us;
        self
    }

    /// Sets the copy mode, this is the mode to use for copying packets to/from the socket.
    pub fn copy_mode(mut self, copy_mode: CopyMode) -> Self {
        self.copy_mode = copy_mode;
        self
    }

    /// Sets whether to enable fragmentation, this is the mode to use for copying packets to/from the socket.
    pub fn enable_fragmentation(mut self, enable_fragmentation: bool) -> Self {
        self.enable_fragmentation = enable_fragmentation;
        self
    }

    /// Builds the socket taking shared ownership of the Umem, allowing for multiple sockets on a single Device/Queue pair.
    ///
    /// Note: This will likely not get you more throughput or lower latency than a single socket, but it is useful for certain heavy loads where you need to offload packet processing onto different threads. Almost always prefer a single socket to a single Umem.
    pub fn build(self, umem: &mut Umem) -> Result<Socket> {
        let socket = Socket::new(
            self.if_name,
            self.queue,
            umem,
            self.rx_ring_size,
            self.tx_ring_size,
            self.busy_poll,
            self.busy_poll_batch_size,
            self.busy_poll_timeout_us,
            self.ctx.attach_mode().into(),
            self.copy_mode,
            self.enable_fragmentation,
        )?;
        self.ctx.register_socket(&socket).map(|_| socket)
    }
}

pub struct Socket {
    owner: Arc<SocketOwner>,
    rx: SocketRx,
    tx: SocketTx,
}

unsafe impl Send for Socket {}

impl Socket {
    fn setup_busy_poll(&self, busy_poll_timeout_us: i32, batch_size: usize) -> Result<()> {
        let opt = 1i32;
        let ret = unsafe {
            setsockopt(
                self.owner.fd,
                SOL_SOCKET,
                SO_PREFER_BUSY_POLL,
                &opt as *const _ as *const c_void,
                std::mem::size_of::<i32>() as u32,
            )
        };
        if ret < 0 {
            return Err(Error::SetSocketOption(errno()));
        }

        let opt = busy_poll_timeout_us;
        let ret = unsafe {
            setsockopt(
                self.owner.fd,
                SOL_SOCKET,
                SO_BUSY_POLL,
                &opt as *const _ as *const c_void,
                std::mem::size_of::<i32>() as u32,
            )
        };
        if ret < 0 {
            return Err(Error::SetSocketOption(errno()));
        }

        let opt = batch_size as i32;
        let ret = unsafe {
            setsockopt(
                self.owner.fd,
                SOL_SOCKET,
                SO_BUSY_POLL_BUDGET,
                &opt as *const _ as *const c_void,
                std::mem::size_of::<i32>() as u32,
            )
        };
        if ret < 0 {
            return Err(Error::SetSocketOption(errno()));
        }

        Ok(())
    }

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
        umem: &mut Umem,
        rx_ring_size: u32,
        tx_ring_size: u32,
        busy_poll: bool,
        busy_poll_batch_size: usize,
        busy_poll_timeout_us: i32,
        socket_mode: BindMode,
        copy_mode: CopyMode,
        enable_fragmentation: bool,
    ) -> Result<Self> {
        let mut bind_flags = XDP_USE_NEED_WAKEUP | copy_mode as u32;
        if enable_fragmentation {
            bind_flags |= XDP_USE_SG;
        }

        let cfg = xsk_socket_config {
            rx_size: rx_ring_size,
            tx_size: tx_ring_size,
            xdp_flags: socket_mode as u32,
            bind_flags: bind_flags as u16,
            __bindgen_anon_1: xsk_socket_config__bindgen_ty_1 {
                libxdp_flags: XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD,
            },
        };

        let mut rx = Consumer::new();
        let mut tx = Producer::new();

        // C function has double indirection
        let mut xsk: *mut xsk_socket = std::ptr::null_mut();
        let xsk_ptr: *mut *mut xsk_socket = &mut xsk;

        let if_name_c = CString::new(if_name).unwrap();

        let ret: std::os::raw::c_int = unsafe {
            xsk_socket__create(
                xsk_ptr,
                if_name_c.as_ptr(),
                queue as u32,
                umem.umem(),
                rx.as_mut_ptr(),
                tx.as_mut_ptr(),
                &cfg,
            )
        };

        if ret != 0 {
            return Err(Error::CreateSocket(errno()));
        }
        let rx = unsafe { rx.assume_init() };
        let tx = unsafe { tx.assume_init() };

        let owner = Arc::new(SocketOwner {
            _umem: umem.owner().clone(),
            socket: xsk,
            fd: unsafe { xsk_socket__fd(xsk) },
        });
        let rx = SocketRx::new(owner.clone(), rx, umem.owner().clone());
        let tx = SocketTx::new(owner.clone(), tx, busy_poll);
        let socket = Self { owner, rx, tx };
        if busy_poll {
            socket.setup_busy_poll(busy_poll_timeout_us, busy_poll_batch_size)?;
        }
        Ok(socket)
    }

    /// Splits the socket into its owner, rx, and tx components.
    #[inline(always)]
    pub fn split(self) -> (Arc<SocketOwner>, SocketRx, SocketTx) {
        (self.owner, self.rx, self.tx)
    }

    #[inline(always)]
    pub fn tx(&mut self) -> &mut SocketTx {
        &mut self.tx
    }

    #[inline(always)]
    pub fn rx(&mut self) -> &mut SocketRx {
        &mut self.rx
    }

    /// Returns the file descriptor of the socket.
    #[inline(always)]
    pub fn fd(&self) -> c_int {
        self.owner.fd()
    }

    /// Possibly wakes the tx queue, so the kernel continues to process outgoing packets.
    #[inline(always)]
    pub fn maybe_wake(&self) -> Result<()> {
        self.tx.maybe_wake()
    }

    /// Receives a batch of frames from the socket.
    ///
    /// Note that it is not guaranteed that the resulting Vec of frames will match the batch size supplied.
    /// It is considered a batch maximum and this function will return as soon as at least one frame is received.
    ///
    /// If no frames are available to read this returns None.
    #[inline(always)]
    pub fn recv<'umem, B: FrameBuffer<'umem>>(&mut self, batch: B) -> NonBlocking<u32> {
        self.rx.recv(batch)
    }

    /// Receives a batch of frames from the socket asynchronously.
    ///
    /// This function will return a future that will be ready when the frames are received.
    #[inline(always)]
    pub fn recv_async<'umem, B: FrameBuffer<'umem>>(
        &mut self,
        batch: B,
    ) -> RecvFuture<'_, 'umem, B> {
        self.rx.recv_async(batch)
    }

    /// Sends a batch of frames to the socket.
    ///
    /// Note that it is not guaranteed that the resulting Vec of frames will match the batch size supplied.
    /// It is considered a batch maximum and this function will return as soon as at least one frame is sent.
    ///
    /// The caller should call this function until their batch of frames is empty.
    ///
    /// If no frames are availabel to send this returns an error of type [std::result::Result<(), ()>].
    #[inline(always)]
    pub fn send<'umem, B: FrameBuffer<'umem>>(&mut self, frames: B) -> NonBlocking<u32> {
        self.tx.send(frames)
    }

    /// Sends a batch of frames to the socket asynchronously.
    ///
    /// This function will return a future that will be ready when the frames are sent.
    #[inline(always)]
    pub fn send_async<'umem, B: FrameBuffer<'umem>>(
        &mut self,
        frames: B,
    ) -> SendFuture<'_, 'umem, B> {
        self.tx.send_async(frames)
    }
}
