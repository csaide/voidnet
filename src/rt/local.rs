use std::{
    cell::UnsafeCell,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::Context,
};

use coarsetime::Duration;
use futures_util::pin_mut;

use crate::{
    net::{
        NeighborHandler, PmtuCache,
        handler::{
            ethernet::EthernetHandler, ipv4::Ipv4Handler, ipv6::Ipv6Handler, tcp::TcpHandler,
            udp::UdpHandler,
        },
    },
    rt::task::TaskQueue,
    xdp::{
        context::{XdpContext, XdpContextBuilder},
        error::Result,
        frame::{BasicFrameBuffer, FrameBuffer, SharedFrameBuffer},
        program::AttachMode,
        socket::{CopyMode, Socket, SocketBuilder},
        umem::{Umem, UmemBuilder},
    },
};

use super::context::{ContextDropGuard, RuntimeContext};

const DEFAULT_ARP_TTL: Duration = Duration::from_secs(60);

/// Builder for configuring and constructing a [`LocalRuntime`].
///
/// Wraps the underlying XDP context, UMEM, and socket builders with
/// sane defaults. All builder methods delegate to the appropriate
/// sub-builder so callers only interact with a single API.
pub struct LocalRuntimeBuilder<'name> {
    if_name: &'name str,
    queue: u32,
    ctx: XdpContextBuilder<'name>,
    umem: UmemBuilder,
    socket: SocketBuilder<'name>,
    arp_ttl: Duration,
}

impl<'name> LocalRuntimeBuilder<'name> {
    /// Creates a new [`LocalRuntimeBuilder`] with the given interface name and queue number.
    pub fn new(if_name: &'name str, queue: u32) -> Self {
        Self {
            if_name,
            queue,
            ctx: XdpContextBuilder::new(if_name),
            umem: UmemBuilder::new(),
            socket: SocketBuilder::new(if_name, queue),
            arp_ttl: DEFAULT_ARP_TTL,
        }
    }

    /// Sets the ARP TTL for the [`LocalRuntime`].
    pub fn arp_ttl(mut self, arp_ttl: Duration) -> Self {
        self.arp_ttl = arp_ttl;
        self
    }

    /// Sets the attach mode for the [`LocalRuntime`].
    pub fn attach_mode(mut self, attach_mode: AttachMode) -> Self {
        self.ctx = self.ctx.attach_mode(attach_mode);
        self
    }

    /// Enables fragmentation for the [`LocalRuntime`].
    pub fn enable_fragmentation(mut self, enable_fragmentation: bool) -> Self {
        self.ctx = self.ctx.enable_fragmentation(enable_fragmentation);
        self.socket = self.socket.enable_fragmentation(enable_fragmentation);
        self
    }

    /// Sets the completion ring size for the [`LocalRuntime`].
    pub fn completion_ring_size(mut self, completion_ring_size: u32) -> Self {
        self.umem = self.umem.completion_ring_size(completion_ring_size);
        self
    }

    /// Sets the fill ring size for the [`LocalRuntime`].
    pub fn fill_ring_size(mut self, fill_ring_size: u32) -> Self {
        self.umem = self.umem.fill_ring_size(fill_ring_size);
        self
    }

    /// Sets the frame size for the [`LocalRuntime`].
    pub fn frame_size(mut self, frame_size: usize) -> Self {
        self.umem = self.umem.frame_size(frame_size);
        self
    }

    /// Enables busy polling for the [`LocalRuntime`].
    pub fn busy_poll(mut self, busy_poll: bool) -> Self {
        self.umem = self.umem.busy_poll(busy_poll);
        self.socket = self.socket.busy_poll(busy_poll);
        self
    }

    /// Sets the busy poll batch size for the [`LocalRuntime`].
    pub fn busy_poll_batch_size(mut self, busy_poll_batch_size: usize) -> Self {
        self.socket = self.socket.busy_poll_batch_size(busy_poll_batch_size);
        self
    }

    /// Sets the busy poll timeout for the [`LocalRuntime`].
    pub fn busy_poll_timeout_us(mut self, busy_poll_timeout_us: i32) -> Self {
        self.socket = self.socket.busy_poll_timeout_us(busy_poll_timeout_us);
        self
    }

    /// Enables huge tables for the [`LocalRuntime`].
    pub fn huge_tables(mut self, huge_tables: bool) -> Self {
        self.umem = self.umem.huge_tables(huge_tables);
        self
    }

    /// Enables unaligned frames for the [`LocalRuntime`].
    pub fn unaligned(mut self, unaligned: bool) -> Self {
        self.umem = self.umem.unaligned(unaligned);
        self
    }

    /// Sets the RX ring size for the [`LocalRuntime`].
    pub fn rx_ring_size(mut self, rx_ring_size: u32) -> Self {
        self.socket = self.socket.rx_ring_size(rx_ring_size);
        self
    }

    /// Sets the TX ring size for the [`LocalRuntime`].
    pub fn tx_ring_size(mut self, tx_ring_size: u32) -> Self {
        self.socket = self.socket.tx_ring_size(tx_ring_size);
        self
    }

    /// Sets the copy mode for the [`LocalRuntime`].
    pub fn copy_mode(mut self, copy_mode: CopyMode) -> Self {
        self.socket = self.socket.copy_mode(copy_mode);
        self
    }

    /// Builds the [`LocalRuntime`].
    pub fn build<'umem>(self) -> Result<LocalRuntime<'umem>> {
        let mut ctx = self.ctx.build()?;
        let umem = self.umem.build()?;
        let socket = self.socket.build(&mut ctx, umem.owner().clone())?;
        LocalRuntime::new(self.if_name, self.queue, ctx, umem, socket, self.arp_ttl)
    }
}

/// Single-threaded packet processing runtime with integrated protocol handlers.
///
/// Owns the AF_XDP socket, UMEM, and all protocol handler state. The
/// `run` method drives the event loop: receive frames, dispatch through
/// the protocol stack, poll the user future, and transmit responses.
pub struct LocalRuntime<'umem> {
    // Overall context for the XDP program, this is used to own the underlying XDP program and socket.
    ctx: XdpContext,
    // Queue number for the XDP program.
    _queue: u32,
    // Shared memory for reading and writing frames to the network.
    umem: Umem<'umem>,
    // Raw AF_XDP socket for reading and writing frames to the network.
    socket: Socket<'umem>,
    // ARP/NDP neighbor handling for IPv4 and IPv6.
    neighbor_handler: Rc<NeighborHandler>,
    // Path MTU cache for handling path MTU discovery.
    pmtu: Rc<PmtuCache>,
    // Ethernet handler is used to handle Ethernet frames.
    ethernet_handler: EthernetHandler,
    // Main IPv4 protocol handler calls into udp_handler and tcp_handler.
    ipv4_handler: Ipv4Handler,
    // Main IPv6 protocol handler calls into neighbor_handler and udp_handler and tcp_handler.
    ipv6_handler: Ipv6Handler,
    // UDP handler is used to bind and send UDP packets, handling things like fragmentation and reassembly.
    udp_handler: Rc<UnsafeCell<UdpHandler<'umem>>>,
    // TCP handler manages TCP connections and the TCP state machine.
    tcp_handler: Rc<UnsafeCell<TcpHandler>>,
    // Set of empty ready to go frame structs that can be used for building outbound packets.
    free_frames: SharedFrameBuffer<'umem>,
    // Frames that are filled and ready to be sent to the network.
    tx_return: SharedFrameBuffer<'umem>,
    // Frames that were read from the network and should be handed back to the kernel for re-use.
    rx_return: SharedFrameBuffer<'umem>,
    // Counter for rate-limiting evict_stale() calls (~every 1024 iterations).
    evict_counter: u32,
}

impl<'umem> LocalRuntime<'umem> {
    /// Builder for configuring and constructing a [`LocalRuntime`].
    ///
    /// Wraps the underlying XDP context, UMEM, and socket builders with
    /// sane defaults. All builder methods delegate to the appropriate
    /// sub-builder so callers only interact with a single API.
    pub fn builder<'name>(if_name: &'name str, queue: u32) -> LocalRuntimeBuilder<'name> {
        LocalRuntimeBuilder::new(if_name, queue)
    }

    fn new(
        if_name: &str,
        queue: u32,
        ctx: XdpContext,
        umem: Umem<'umem>,
        socket: Socket<'umem>,
        arp_ttl: Duration,
    ) -> Result<Self> {
        let info = ctx.info();
        println!("info: {:?}", info);
        let mtu = info.mtu;
        let rx_offload = info.rx_offload;
        let tx_offload = info.tx_offload;

        let mut neighbor_handler = NeighborHandler::new(if_name, arp_ttl)?;
        neighbor_handler.set_offload(rx_offload, tx_offload);
        let neighbor_handler = Rc::new(neighbor_handler);
        let pmtu = Rc::new(PmtuCache::with_mtu(mtu));

        let tx_return = BasicFrameBuffer::new(umem.num_frames()).into();
        let rx_return = BasicFrameBuffer::new(umem.num_frames()).into();
        let free_frames = umem.init_buffer::<BasicFrameBuffer>().unwrap().into();

        Ok(Self {
            ctx,
            _queue: queue,
            umem,
            socket,
            neighbor_handler,
            pmtu,
            ethernet_handler: EthernetHandler,
            ipv4_handler: Ipv4Handler::new(rx_offload, tx_offload),
            ipv6_handler: Ipv6Handler::new(rx_offload, tx_offload),
            udp_handler: Rc::new(UnsafeCell::new(UdpHandler::new(256, rx_offload))),
            tcp_handler: Rc::new(UnsafeCell::new(TcpHandler::new(rx_offload, tx_offload))),
            free_frames,
            tx_return,
            rx_return,
            evict_counter: 0,
        })
    }

    /// Runs the event loop until `exit` is set or `fut` completes.
    ///
    /// Each iteration: receive frames, dispatch through the protocol stack,
    /// poll `fut` (if woken), poll spawned tasks, drive TCP timers, evict
    /// stale state, transmit, and wake capacity-blocked futures.
    pub fn run<F>(&mut self, exit: Arc<AtomicBool>, fut: F) -> Result<()>
    where
        F: Future<Output = ()>,
    {
        use super::waker::MainWaker;

        // Drop guard ensures the context is cleared even on early return/panic.
        let _guard = ContextDropGuard::new(RuntimeContext {
            free_frames: self.free_frames.clone(),
            tx_return: self.tx_return.clone(),
            rx_return: self.rx_return.clone(),
            pmtu: self.pmtu.clone(),
            neighbor_handler: self.neighbor_handler.clone(),
            udp_handler: self.udp_handler.clone(),
            tcp_handler: self.tcp_handler.clone(),
            tx_offload: self.ctx.info().tx_offload,
            task_queue: UnsafeCell::new(TaskQueue::new()),
            capacity_wakers: UnsafeCell::new(Vec::new()),
        });

        // Before we can operate properly we need to seed the kernel with free frames to read into.
        self.umem.maybe_wake_fill_queue(self.socket.fd())?;
        self.umem
            .process_fill_queue(&mut self.free_frames)
            .expect("failed to process fill queue");

        let expected_free_frames = self.free_frames.num_frames();

        // Main future gets a real waker (initialized to woken for first poll).
        let main_waker = MainWaker::new();
        let main_std_waker = main_waker.waker();
        let mut main_cx = Context::from_waker(&main_std_waker);
        pin_mut!(fut);

        // Task queue uses a no-op top-level waker — FuturesUnordered manages
        // its own per-task wakers internally. We poll it every iteration.
        let task_waker = super::waker::task_queue_waker();
        let mut task_cx = Context::from_waker(&task_waker);

        let mut buffer = BasicFrameBuffer::new(self.umem.num_frames());
        let mut now = coarsetime::Instant::now();
        while !exit.load(Ordering::Relaxed) {
            // ---- Receive & Protocol Dispatch ----
            let received = match self.socket.recv(&mut buffer) {
                Err(_) => 0,
                Ok(received) => {
                    // SAFETY: single-threaded, no reentrant handler calls.
                    let udp_handler = unsafe { &mut *self.udp_handler.get() };
                    let tcp_handler = unsafe { &mut *self.tcp_handler.get() };
                    let Self {
                        neighbor_handler,
                        pmtu,
                        ethernet_handler,
                        ipv4_handler,
                        ipv6_handler,
                        ..
                    } = self;

                    for frame in buffer.take_frames() {
                        ethernet_handler.handle(
                            frame,
                            ipv4_handler,
                            ipv6_handler,
                            udp_handler,
                            tcp_handler,
                            neighbor_handler,
                            pmtu,
                            now,
                            &mut self.free_frames,
                            &mut self.rx_return,
                            &mut self.tx_return,
                        );
                    }
                    received
                }
            };

            // ---- Poll Main Future (only if woken) ----
            if main_waker.take_woken() && fut.as_mut().poll(&mut main_cx).is_ready() {
                return Ok(());
            }

            // ---- Poll Spawned Tasks ----
            crate::rt::context::with_runtime_context(|ctx| {
                let tq = unsafe { &mut *ctx.task_queue.get() };
                tq.poll(&mut task_cx);
            });

            // ---- TCP Timers & Send ----
            //
            // SAFETY: single-threaded, no reentrant handler calls.
            unsafe { &mut *self.tcp_handler.get() }.poll_send(
                now,
                self.neighbor_handler.local_mac(),
                &self.neighbor_handler,
                &mut self.free_frames,
                &mut self.tx_return,
            );

            self.evict_counter = self.evict_counter.wrapping_add(1);
            if self.evict_counter & 65535 == 0 {
                now = coarsetime::Instant::now();

                // SAFETY: single-threaded, no reentrant handler calls.
                unsafe { &mut *self.udp_handler.get() }.evict_stale(
                    now,
                    Duration::from_secs(30),
                    &mut self.rx_return,
                );

                // SAFETY: single-threaded, no reentrant handler calls.
                let tcp_handler = unsafe { &mut *self.tcp_handler.get() };
                tcp_handler.evict_stale(now, &mut self.rx_return);
                tcp_handler.poll_timers(
                    now,
                    self.neighbor_handler.local_mac(),
                    &self.neighbor_handler,
                    &mut self.free_frames,
                    &mut self.tx_return,
                );

                self.neighbor_handler.evict_stale(now);
                self.pmtu.evict_stale(now);
            }

            // ---- Transmit & Frame Recycling ----
            let expected_size = self.tx_return.num_frames() + self.rx_return.num_frames();

            while self.tx_return.num_frames() > 0 {
                if self.socket.send(&mut self.tx_return).is_err() {
                    self.socket.maybe_wake()?;
                    let _ = self.umem.process_completion_queue(&mut self.rx_return);
                }
            }

            while self.rx_return.num_frames() < expected_size {
                if self
                    .umem
                    .process_completion_queue(&mut self.rx_return)
                    .is_err()
                {
                    self.socket.maybe_wake()?;
                }
            }

            while self.rx_return.num_frames() > received as usize {
                self.free_frames.push(self.rx_return.pop().unwrap());
            }

            while self.rx_return.num_frames() > 0 {
                if self.umem.process_fill_queue(&mut self.rx_return).is_err() {
                    self.umem.maybe_wake_fill_queue(self.socket.fd())?;
                }
            }

            // ---- Capacity-Driven Wakes ----
            // After frame recycling, wake any futures blocked on capacity.
            if expected_size > 0 {
                main_waker.set_woken();
                crate::rt::context::with_runtime_context(|ctx| {
                    let wakers = unsafe { &mut *ctx.capacity_wakers.get() };
                    for waker in wakers.drain(..) {
                        waker.wake();
                    }
                });
            }

            debug_assert_eq!(self.rx_return.num_frames(), 0);
            debug_assert_eq!(self.tx_return.num_frames(), 0);
            debug_assert_eq!(self.free_frames.num_frames(), expected_free_frames);
        }

        Ok(())
    }
}
