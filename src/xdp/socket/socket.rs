use std::{ffi::CString, os::raw::c_void, sync::Arc};

use errno::errno;
use libc::{SO_BUSY_POLL, SO_BUSY_POLL_BUDGET, SO_PREFER_BUSY_POLL, SOL_SOCKET, c_int, setsockopt};
use libxdp_sys::{
    XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD, XSK_RING_CONS__DEFAULT_NUM_DESCS,
    XSK_RING_PROD__DEFAULT_NUM_DESCS, xsk_socket, xsk_socket__create, xsk_socket_config,
    xsk_socket_config__bindgen_ty_1,
};

use crate::xdp::{
    context::XdpContext,
    error::{Error, NonBlocking, Result},
    flags::{XDP_USE_NEED_WAKEUP, XDP_USE_SG},
    frame::FrameBuffer,
    futures::{RecvFuture, SendFuture},
    ring::{Consumer, Producer},
    socket::{BindMode, mode::CopyMode},
    umem::UmemOwner,
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
    pub fn build<'umem>(self, umem: Arc<UmemOwner<'umem>>) -> Result<Socket<'umem>> {
        let info = self.ctx.info();
        if !info.fragmentation_support() && self.enable_fragmentation {
            return Err(Error::FragmentationNotSupported);
        }
        if !info.xsk_zero_copy_support() && self.copy_mode == CopyMode::ZeroCopy {
            return Err(Error::ZeroCopyNotSupported);
        }

        Socket::new(
            self.ctx,
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
        )
    }
}

pub struct Socket<'umem> {
    owner: Arc<SocketOwner<'umem>>,
    rx: SocketRx<'umem>,
    tx: SocketTx<'umem>,
}

// unsafe impl<'umem> Send for Socket<'umem> {}

impl<'umem> Socket<'umem> {
    /// Returns a builder for creating a new socket.
    pub fn builder<'a, 'b>(
        xdp_ctx: &'b mut XdpContext,
        if_name: &'a str,
        queue: u32,
    ) -> SocketBuilder<'a, 'b> {
        SocketBuilder::new(xdp_ctx, if_name, queue)
    }

    fn new(
        xdp_ctx: &mut XdpContext,
        if_name: &str,
        queue: u32,
        umem: Arc<UmemOwner<'umem>>,
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

        let if_name_c = match CString::new(if_name) {
            Ok(c) => c,
            Err(e) => return Err(Error::InterfaceNameToIndex(e)),
        };

        let ret: std::os::raw::c_int = unsafe {
            xsk_socket__create(
                xsk_ptr,
                if_name_c.as_ptr(),
                queue as u32,
                umem.as_ptr(),
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

        let mut owner = SocketOwner::new(umem.clone(), xsk, xdp_ctx.get_poller().cloned());
        xdp_ctx.register_socket(&mut owner)?;
        let owner = Arc::new(owner);
        let rx = SocketRx::new(owner.clone(), rx);
        let tx = SocketTx::new(owner.clone(), tx, busy_poll);
        let socket = Self { owner, rx, tx };
        if busy_poll {
            setup_busy_poll(socket.fd(), busy_poll_timeout_us, busy_poll_batch_size)?;
        }
        Ok(socket)
    }

    /// Splits the socket into its owner, rx, and tx components.
    #[inline(always)]
    pub fn split(self) -> (Arc<SocketOwner<'umem>>, SocketRx<'umem>, SocketTx<'umem>) {
        (self.owner, self.rx, self.tx)
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
    pub fn recv<B: FrameBuffer<'umem>>(&mut self, batch: B) -> NonBlocking<u32> {
        self.rx.recv(batch)
    }

    /// Receives a batch of frames from the socket asynchronously.
    ///
    /// This function will return a future that will be ready when the frames are received.
    #[inline(always)]
    pub fn recv_async<B: FrameBuffer<'umem>>(&mut self, batch: B) -> RecvFuture<'_, 'umem, B> {
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
    pub fn send<B: FrameBuffer<'umem>>(&mut self, frames: B) -> NonBlocking<u32> {
        self.tx.send(frames)
    }

    /// Sends a batch of frames to the socket asynchronously.
    ///
    /// This function will return a future that will be ready when the frames are sent.
    #[inline(always)]
    pub fn send_async<B: FrameBuffer<'umem>>(&mut self, frames: B) -> SendFuture<'_, 'umem, B> {
        self.tx.send_async(frames)
    }
}

fn setup_busy_poll(fd: c_int, busy_poll_timeout_us: i32, batch_size: usize) -> Result<()> {
    let opt = 1i32;
    let ret = unsafe {
        setsockopt(
            fd,
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
            fd,
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
            fd,
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

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use crate::xdp::context::XdpContext;
    use crate::xdp::frame::{BasicFrameBuffer, FrameBuffer};
    use crate::xdp::program::AttachMode;
    use crate::xdp::test_utils::TestVethPair;
    use crate::xdp::umem::Umem;

    use super::*;

    /// Helper to build a minimal Ethernet frame with a payload.
    /// Format: [dst MAC (6)] [src MAC (6)] [EtherType (2)] [payload]
    fn build_ethernet_frame(dst_mac: &[u8; 6], src_mac: &[u8; 6], payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(14 + payload.len());
        frame.extend_from_slice(dst_mac);
        frame.extend_from_slice(src_mac);
        // EtherType 0x0800 = IPv4, but we'll use a custom one for testing
        frame.extend_from_slice(&[0x88, 0xB5]); // Local Experimental EtherType
        frame.extend_from_slice(payload);
        frame
    }

    /// Test that sends a packet from one side of a veth pair and receives it on the other.
    #[test]
    fn test_socket_send_recv_sync() {
        // Create veth pair
        let veth = TestVethPair::new().expect("failed to create veth pair");

        // Create XDP contexts on both ends
        let mut ctx_outer = XdpContext::builder(veth.outer_name())
            .attach_mode(AttachMode::default())
            .enable_fragmentation(false)
            .async_mode(false)
            .poller_max_events(1024)
            .poller_timeout_ms(100)
            .build()
            .expect("failed to create outer context");
        let mut ctx_inner = XdpContext::builder(veth.inner_name())
            .attach_mode(AttachMode::default())
            .enable_fragmentation(false)
            .async_mode(false)
            .poller_max_events(1024)
            .poller_timeout_ms(100)
            .build()
            .expect("failed to create inner context");

        // Create UMEM for outer socket (sender)
        let (umem_outer, _fq_outer, mut cq_outer) = Umem::builder(&mut ctx_outer)
            .num_frames(64)
            .frame_size(4096)
            .fill_ring_size(32)
            .completion_ring_size(32)
            .build()
            .expect("failed to create outer umem");

        // Create UMEM for inner socket (receiver)
        let (umem_inner, mut fq_inner, _cq_inner) = Umem::builder(&mut ctx_inner)
            .num_frames(64)
            .frame_size(4096)
            .fill_ring_size(32)
            .completion_ring_size(32)
            .build()
            .expect("failed to create inner umem");

        // Initialize frame buffers
        let mut tx_buffer: BasicFrameBuffer<'_> = umem_outer.init_buffer().unwrap();
        let mut rx_buffer: BasicFrameBuffer<'_> = umem_inner.init_buffer().unwrap();

        // Create sockets
        let mut socket_outer = Socket::builder(&mut ctx_outer, veth.outer_name(), 0)
            .build(umem_outer.clone())
            .expect("failed to create outer socket");

        let mut socket_inner = Socket::builder(&mut ctx_inner, veth.inner_name(), 0)
            .build(umem_inner.clone())
            .expect("failed to create inner socket");

        // Prime the receiver's fill queue so it can receive packets
        // Take some frames and submit them to the fill queue
        let rx_prime_count = rx_buffer.num_frames().min(32);
        let mut prime_buffer = BasicFrameBuffer::new(rx_prime_count);
        for frame in rx_buffer.drain(..rx_prime_count) {
            prime_buffer.push(frame);
        }
        fq_inner.process_queue(&mut prime_buffer);
        fq_inner
            .maybe_wake(socket_inner.fd())
            .expect("failed to wake fill queue");

        // Build a test packet
        let payload = b"Hello XDP Socket Test!";
        let packet_data = build_ethernet_frame(
            veth.inner_mac().as_bytes(),
            veth.outer_mac().as_bytes(),
            payload,
        );

        // Prepare a frame for sending
        let mut send_buffer = BasicFrameBuffer::new(1);
        let mut frame = tx_buffer.drain(..1).next().expect("no frames available");
        frame.copy_from(&packet_data);
        send_buffer.push(frame);

        // Send the packet
        let sent = socket_outer.send(&mut send_buffer).expect("send failed");
        assert_eq!(sent, 1, "expected to send 1 frame");
        assert_eq!(send_buffer.num_frames(), 0, "buffer should be drained");

        // Wake the TX queue to actually transmit
        socket_outer.maybe_wake().expect("failed to wake tx");

        // Poll for received packet with timeout
        let mut recv_buffer = BasicFrameBuffer::new(16);
        let start = Instant::now();
        let timeout = Duration::from_secs(5);
        let mut received = false;

        while start.elapsed() < timeout {
            match socket_inner.recv(&mut recv_buffer) {
                Ok(count) if count > 0 => {
                    received = true;
                    break;
                }
                _ => {
                    // Try waking the fill queue periodically
                    fq_inner.maybe_wake(socket_inner.fd()).ok();
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }

        assert!(received, "did not receive packet within timeout");
        assert!(
            recv_buffer.num_frames() >= 1,
            "expected at least 1 received frame"
        );

        // Verify the received packet matches what we sent
        let recv_frame = recv_buffer.iter_frames().next().unwrap();
        assert!(
            recv_frame.len() >= packet_data.len(),
            "received frame too short"
        );
        assert_eq!(
            &recv_frame[..packet_data.len()],
            &packet_data[..],
            "packet data mismatch"
        );

        // Clean up: process completion queue to reclaim TX frame
        let mut reclaim_buffer = BasicFrameBuffer::new(1);
        cq_outer.process_queue(&mut reclaim_buffer);
    }

    /// Async version of test_socket_send_recv_sync using async methods.
    #[test]
    fn test_socket_send_recv_async() {
        use futures::executor::block_on;
        use std::future::Future;
        use std::pin::Pin;
        use std::task::{Context, Poll};

        // Simple timeout future wrapper
        struct Timeout<F> {
            future: F,
            deadline: Instant,
        }

        impl<F: Future + Unpin> Future for Timeout<F> {
            type Output = Option<F::Output>;

            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                // Check timeout first
                if Instant::now() >= self.deadline {
                    return Poll::Ready(None);
                }

                // Poll the inner future
                match Pin::new(&mut self.future).poll(cx) {
                    Poll::Ready(result) => Poll::Ready(Some(result)),
                    Poll::Pending => {
                        // Schedule a wake-up for timeout check
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }
            }
        }

        fn with_timeout<F: Future + Unpin>(future: F, timeout: Duration) -> Timeout<F> {
            Timeout {
                future,
                deadline: Instant::now() + timeout,
            }
        }

        // Create veth pair
        let veth = TestVethPair::new().expect("failed to create veth pair");

        // Create XDP contexts on both ends
        let mut ctx_outer = XdpContext::builder(veth.outer_name())
            .attach_mode(AttachMode::default())
            .enable_fragmentation(false)
            .async_mode(true)
            .poller_max_events(1024)
            .poller_timeout_ms(100)
            .build()
            .expect("failed to create outer context");
        let mut ctx_inner = XdpContext::builder(veth.inner_name())
            .attach_mode(AttachMode::default())
            .enable_fragmentation(false)
            .async_mode(true)
            .poller_max_events(1024)
            .poller_timeout_ms(100)
            .build()
            .expect("failed to create inner context");

        // Create UMEM for outer socket (sender)
        let (umem_outer, _fq_outer, mut cq_outer) = Umem::builder(&mut ctx_outer)
            .num_frames(64)
            .frame_size(4096)
            .fill_ring_size(32)
            .completion_ring_size(32)
            .build()
            .expect("failed to create outer umem");

        // Create UMEM for inner socket (receiver)
        let (umem_inner, mut fq_inner, _cq_inner) = Umem::builder(&mut ctx_inner)
            .num_frames(64)
            .frame_size(4096)
            .fill_ring_size(32)
            .completion_ring_size(32)
            .build()
            .expect("failed to create inner umem");

        // Initialize frame buffers
        let mut tx_buffer: BasicFrameBuffer<'_> = umem_outer.init_buffer().unwrap();
        let mut rx_buffer: BasicFrameBuffer<'_> = umem_inner.init_buffer().unwrap();

        // Create sockets
        let mut socket_outer = Socket::builder(&mut ctx_outer, veth.outer_name(), 0)
            .build(umem_outer.clone())
            .expect("failed to create outer socket");

        let mut socket_inner = Socket::builder(&mut ctx_inner, veth.inner_name(), 0)
            .build(umem_inner.clone())
            .expect("failed to create inner socket");

        // Prime the receiver's fill queue using async method
        let rx_prime_count = rx_buffer.num_frames().min(32);
        let mut prime_buffer = BasicFrameBuffer::new(rx_prime_count);
        for frame in rx_buffer.drain(..rx_prime_count) {
            prime_buffer.push(frame);
        }

        // Use async fill queue processing
        block_on(fq_inner.process_queue_async(&mut prime_buffer, &[socket_inner.fd()]))
            .expect("failed to process fill queue async");

        // Build a test packet
        let payload = b"Hello XDP Socket Test Async!";
        let packet_data = build_ethernet_frame(
            veth.inner_mac().as_bytes(),
            veth.outer_mac().as_bytes(),
            payload,
        );

        // Prepare a frame for sending
        let mut send_buffer = BasicFrameBuffer::new(1);
        let mut frame = tx_buffer.drain(..1).next().expect("no frames available");
        frame.copy_from(&packet_data);
        send_buffer.push(frame);

        // Send the packet using async method
        let sent = block_on(socket_outer.send_async(&mut send_buffer)).expect("async send failed");
        assert_eq!(sent, 1, "expected to send 1 frame");
        assert_eq!(send_buffer.num_frames(), 0, "buffer should be drained");

        // Receive the packet using async method with timeout
        let mut recv_buffer = BasicFrameBuffer::new(16);
        let timeout = Duration::from_secs(5);

        // We need to poll recv_async with a timeout
        // Since recv_async will block waiting for packets, we use our timeout wrapper
        let recv_future = socket_inner.recv_async(&mut recv_buffer);
        let result = block_on(with_timeout(recv_future, timeout));

        match result {
            Some(Ok(count)) => {
                assert!(count > 0, "expected to receive at least 1 frame");
            }
            Some(Err(e)) => {
                panic!("async recv failed with error: {:?}", e);
            }
            None => {
                panic!("async recv timed out after {:?}", timeout);
            }
        }

        assert!(
            recv_buffer.num_frames() >= 1,
            "expected at least 1 received frame"
        );

        // Verify the received packet matches what we sent
        let recv_frame = recv_buffer.iter_frames().next().unwrap();
        assert!(
            recv_frame.len() >= packet_data.len(),
            "received frame too short"
        );
        assert_eq!(
            &recv_frame[..packet_data.len()],
            &packet_data[..],
            "packet data mismatch"
        );

        // Clean up: use async completion queue processing
        // Split the socket to get access to SocketTx for the CompFuture
        let (_, _, tx) = socket_outer.split();
        tx.maybe_wake().expect("failed to wake tx");

        let mut reclaim_buffer = BasicFrameBuffer::new(1);
        block_on(cq_outer.process_queue_async(&mut reclaim_buffer, 1))
            .expect("failed to process completion queue async");
    }

    /// Test socket creation and basic properties.
    #[test]
    fn test_socket_creation() {
        let veth = TestVethPair::new().expect("failed to create veth pair");

        let mut ctx = XdpContext::builder(veth.outer_name())
            .attach_mode(AttachMode::default())
            .enable_fragmentation(false)
            .async_mode(false)
            .poller_max_events(1024)
            .poller_timeout_ms(100)
            .build()
            .expect("failed to create context");

        let (umem, _fq, _cq) = Umem::builder(&mut ctx)
            .num_frames(16)
            .frame_size(4096)
            .fill_ring_size(8)
            .completion_ring_size(8)
            .build()
            .expect("failed to create umem");

        let socket = Socket::builder(&mut ctx, veth.outer_name(), 0)
            .rx_ring_size(8)
            .tx_ring_size(8)
            .build(umem)
            .expect("failed to create socket");

        // Socket should have valid fd
        assert!(socket.fd() >= 0, "socket fd should be valid");

        // Context should now have 1 socket registered
        assert_eq!(ctx.num_sockets(), 1, "context should have 1 socket");
    }

    /// Test socket split into owner, rx, tx components.
    #[test]
    fn test_socket_split() {
        let veth = TestVethPair::new().expect("failed to create veth pair");

        let mut ctx = XdpContext::builder(veth.outer_name())
            .attach_mode(AttachMode::default())
            .enable_fragmentation(false)
            .async_mode(false)
            .poller_max_events(1024)
            .poller_timeout_ms(100)
            .build()
            .expect("failed to create context");

        let (umem, _fq, _cq) = Umem::builder(&mut ctx)
            .num_frames(16)
            .frame_size(4096)
            .fill_ring_size(8)
            .completion_ring_size(8)
            .build()
            .expect("failed to create umem");

        let socket = Socket::builder(&mut ctx, veth.outer_name(), 0)
            .build(umem)
            .expect("failed to create socket");

        let original_fd = socket.fd();
        let (owner, _rx, _tx) = socket.split();

        // Owner should have the same fd
        assert_eq!(owner.fd(), original_fd, "owner fd should match original");
    }

    /// Test that recv returns WouldBlock when no packets are available.
    #[test]
    fn test_socket_recv_would_block() {
        let veth = TestVethPair::new().expect("failed to create veth pair");

        let mut ctx = XdpContext::builder(veth.outer_name())
            .attach_mode(AttachMode::default())
            .enable_fragmentation(false)
            .async_mode(false)
            .poller_max_events(1024)
            .poller_timeout_ms(100)
            .build()
            .expect("failed to create context");

        let (umem, mut fq, _cq) = Umem::builder(&mut ctx)
            .num_frames(16)
            .frame_size(4096)
            .fill_ring_size(8)
            .completion_ring_size(8)
            .build()
            .expect("failed to create umem");

        let mut buffer: BasicFrameBuffer<'_> = umem.init_buffer().unwrap();

        let mut socket = Socket::builder(&mut ctx, veth.outer_name(), 0)
            .build(umem)
            .expect("failed to create socket");

        // Prime fill queue
        let mut prime_buffer = BasicFrameBuffer::new(8);
        for frame in buffer.drain(..8) {
            prime_buffer.push(frame);
        }
        fq.process_queue(&mut prime_buffer);

        // Try to receive with no packets pending
        let mut recv_buffer = BasicFrameBuffer::new(8);
        let result = socket.recv(&mut recv_buffer);

        // Should return WouldBlock (Err)
        assert!(
            result.is_err(),
            "recv should return WouldBlock when no packets"
        );
    }

    /// Test that send returns WouldBlock when TX ring is full.
    #[test]
    fn test_socket_send_would_block_on_full_ring() {
        let veth = TestVethPair::new().expect("failed to create veth pair");

        let mut ctx = XdpContext::builder(veth.outer_name())
            .attach_mode(AttachMode::default())
            .enable_fragmentation(false)
            .async_mode(true)
            .poller_max_events(1024)
            .poller_timeout_ms(100)
            .build()
            .expect("failed to create context");

        // Create socket with tiny TX ring
        let (umem, _fq, _cq) = Umem::builder(&mut ctx)
            .num_frames(8)
            .frame_size(4096)
            .fill_ring_size(4)
            .completion_ring_size(4)
            .build()
            .expect("failed to create umem");

        let mut buffer: BasicFrameBuffer<'_> = umem.init_buffer().unwrap();

        let mut socket = Socket::builder(&mut ctx, veth.outer_name(), 0)
            .tx_ring_size(4)
            .build(umem)
            .expect("failed to create socket");

        // Fill the TX ring completely
        let mut send_buffer = BasicFrameBuffer::new(4);
        for frame in buffer.drain(..4) {
            let mut f = frame;
            f.copy_from(&[0u8; 64]);
            send_buffer.push(f);
        }

        // First send should succeed
        let sent = socket
            .send(&mut send_buffer)
            .expect("first send should work");
        assert_eq!(sent, 4, "should send 4 frames");

        // Prepare more frames (remaining 4)
        let mut more_buffer = BasicFrameBuffer::new(4);
        for frame in buffer.drain(..) {
            let mut f = frame;
            f.copy_from(&[0u8; 64]);
            more_buffer.push(f);
        }

        // Second send should return WouldBlock because ring is full
        let result = socket.send(&mut more_buffer);
        assert!(
            result.is_err(),
            "send should return WouldBlock when ring is full"
        );
    }
}
