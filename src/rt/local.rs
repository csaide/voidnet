use std::{
    cell::UnsafeCell,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, SyncSender},
    },
    task::Context,
};

use coarsetime::Duration;
use futures_util::pin_mut;

use crate::{
    net::{
        NeighborHandler, NeighborUpdate, PmtuCache,
        handler::{
            ethernet::EthernetHandler, ipv4::Ipv4Handler, ipv6::Ipv6Handler, quic::QuicHandler,
            tcp::TcpHandler, udp::UdpHandler,
        },
        timer_wheel::TimerWheel,
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
    _ctx: Option<XdpContext>,
    // Queue number for the XDP program.
    _queue: u32,
    // Shared memory for reading and writing frames to the network.
    umem: Umem<'umem>,
    // Raw AF_XDP socket for reading and writing frames to the network.
    socket: Socket<'umem>,
    // ARP/NDP neighbor handling for IPv4 and IPv6.
    neighbor_handler: Rc<NeighborHandler>,
    // Path MTU cache for handling path MTU discovery.
    pmtu: Rc<UnsafeCell<PmtuCache>>,
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
    // QUIC handler manages QUIC connections and protocol state.
    quic_handler: QuicHandler,
    // Set of empty ready to go frame structs that can be used for building outbound packets.
    free_frames: SharedFrameBuffer<'umem>,
    // Frames that are filled and ready to be sent to the network.
    tx_return: SharedFrameBuffer<'umem>,
    // Frames that were read from the network and should be handed back to the kernel for re-use.
    rx_return: SharedFrameBuffer<'umem>,
    // Timer wheel for TCP timers.
    wheel: Rc<UnsafeCell<TimerWheel>>,
    // Counter for rate-limiting evict_stale() calls (~every 1024 iterations).
    evict_counter: u32,
    // Whether TX checksum offload is enabled on this interface.
    tx_offload: bool,
    /// Receiver for neighbor updates from peer queues (multi-queue only).
    neighbor_rx: Option<Receiver<NeighborUpdate>>,
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
        let mtu = info.mtu;
        let rx_offload = info.rx_offload;
        let tx_offload = info.tx_offload;

        let mut neighbor_handler = NeighborHandler::new(if_name, arp_ttl)?;
        neighbor_handler.set_offload(rx_offload, tx_offload);
        let neighbor_handler = Rc::new(neighbor_handler);
        let pmtu = Rc::new(UnsafeCell::new(PmtuCache::with_mtu(mtu)));

        let tx_return = BasicFrameBuffer::new(umem.num_frames()).into();
        let rx_return = BasicFrameBuffer::new(umem.num_frames()).into();
        let free_frames = umem.init_buffer::<BasicFrameBuffer>().unwrap().into();

        let base_instant = coarsetime::Instant::now();
        Ok(Self {
            _ctx: Some(ctx),
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
            quic_handler: QuicHandler::new(rx_offload, tx_offload),
            free_frames,
            tx_return,
            rx_return,
            wheel: Rc::new(UnsafeCell::new(TimerWheel::new(base_instant))),
            evict_counter: 0,
            tx_offload,
            neighbor_rx: None,
        })
    }

    /// Creates a `LocalRuntime` from pre-built components for use by the
    /// multi-threaded `Runtime` orchestrator. Does not own an `XdpContext` —
    /// the orchestrator retains that on the main thread.
    pub(crate) fn new_worker(
        if_name: &str,
        umem: Umem<'umem>,
        socket: Socket<'umem>,
        mtu: u32,
        rx_offload: bool,
        tx_offload: bool,
        arp_ttl: Duration,
        neighbor_tx: Vec<SyncSender<NeighborUpdate>>,
        neighbor_rx: Receiver<NeighborUpdate>,
    ) -> Result<Self> {
        let mut neighbor_handler = NeighborHandler::new(if_name, arp_ttl)?;
        neighbor_handler.set_offload(rx_offload, tx_offload);
        neighbor_handler.set_broadcast(neighbor_tx);
        let neighbor_handler = Rc::new(neighbor_handler);
        let pmtu = Rc::new(UnsafeCell::new(PmtuCache::with_mtu(mtu)));

        let tx_return = BasicFrameBuffer::new(umem.num_frames()).into();
        let rx_return = BasicFrameBuffer::new(umem.num_frames()).into();
        let free_frames = umem.init_buffer::<BasicFrameBuffer>().unwrap().into();

        let base_instant = coarsetime::Instant::now();
        Ok(Self {
            _ctx: None,
            _queue: 0,
            umem,
            socket,
            neighbor_handler,
            pmtu,
            ethernet_handler: EthernetHandler,
            ipv4_handler: Ipv4Handler::new(rx_offload, tx_offload),
            ipv6_handler: Ipv6Handler::new(rx_offload, tx_offload),
            udp_handler: Rc::new(UnsafeCell::new(UdpHandler::new(256, rx_offload))),
            tcp_handler: Rc::new(UnsafeCell::new(TcpHandler::new(rx_offload, tx_offload))),
            quic_handler: QuicHandler::new(rx_offload, tx_offload),
            free_frames,
            tx_return,
            rx_return,
            wheel: Rc::new(UnsafeCell::new(TimerWheel::new(base_instant))),
            evict_counter: 0,
            tx_offload,
            neighbor_rx: Some(neighbor_rx),
        })
    }

    /// Drains `rx_return` completely: fill queue first (ring-limited), overflow
    /// to `free_frames`.
    ///
    /// # Frame Accounting
    ///
    /// Every frame in `rx_return` moves to exactly one destination:
    /// - `fill_queue` via `process_fill_queue`: frame leaves our accounting
    ///   (kernel RX path owns it).
    /// - `free_frames`: frame stays in our accounting (available for TX).
    ///
    /// The fill queue ring size naturally caps how many frames enter the kernel
    /// RX path. Overflow goes to `free_frames` to maintain TX capacity.
    ///
    /// After return: `rx_return.num_frames() == 0`.
    #[inline(always)]
    fn recycle_rx_return(&mut self) -> Result<()> {
        // Feed fill queue — ring size prevents overfilling.
        while self.rx_return.num_frames() > 0 {
            if self.umem.process_fill_queue(&mut self.rx_return).is_err() {
                break; // Fill ring full
            }
        }
        // Overflow to free_frames — available for TX packet building.
        while self.rx_return.num_frames() > 0 {
            self.free_frames.push(self.rx_return.pop().unwrap());
        }
        // Wake fill queue so kernel processes newly submitted addresses.
        self.umem.maybe_wake_fill_queue(self.socket.fd())
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
            wheel: self.wheel.clone(),
            tx_offload: self.tx_offload,
            task_queue: UnsafeCell::new(TaskQueue::new()),
            capacity_wakers: UnsafeCell::new(Vec::new()),
        });

        // Before we can operate properly we need to seed the kernel with free frames to read into.
        self.umem.maybe_wake_fill_queue(self.socket.fd())?;
        self.umem
            .process_fill_queue(&mut self.free_frames)
            .expect("failed to process fill queue");

        let expected_total = self.free_frames.num_frames() as u32;
        let mut in_flight_tx: u32 = 0;

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
        let mut now;
        while !exit.load(Ordering::Relaxed) {
            // Update time every iteration for timer wheel accuracy.
            now = coarsetime::Instant::now();
            let wheel = unsafe { &mut *self.wheel.get() };
            // ---- Drain neighbor updates from peer queues ----
            if let Some(ref neighbor_rx) = self.neighbor_rx {
                while let Ok(update) = neighbor_rx.try_recv() {
                    self.neighbor_handler.apply_update(update, now);
                }
            }

            // ---- Receive & Protocol Dispatch ----
            match self.socket.recv(&mut buffer) {
                Err(_) => {}
                Ok(_) => {
                    // SAFETY: single-threaded, no reentrant handler calls.
                    let udp_handler = unsafe { &mut *self.udp_handler.get() };
                    let tcp_handler = unsafe { &mut *self.tcp_handler.get() };
                    let pmtu = unsafe { &mut *self.pmtu.get() };
                    let Self {
                        neighbor_handler,
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
                            &mut self.quic_handler,
                            neighbor_handler,
                            pmtu,
                            now,
                            wheel,
                            &mut self.free_frames,
                            &mut self.rx_return,
                            &mut self.tx_return,
                        );
                    }
                }
            }

            // ---- Poll Main Future (only if woken) ----
            if main_waker.take_woken() && fut.as_mut().poll(&mut main_cx).is_ready() {
                return Ok(());
            }

            // ---- Poll Spawned Tasks ----
            crate::rt::context::with_runtime_context(|ctx| {
                let tq = unsafe { &mut *ctx.task_queue.get() };
                tq.poll(&mut task_cx);
            });

            // ---- Timer wheel advance + dispatch ----
            {
                use crate::net::handler::tcp::timer_kinds::unpack_tcp_timer_id;
                let wheel = unsafe { &mut *self.wheel.get() };
                let fired = wheel.advance(now);
                if !fired.is_empty() {
                    let tcp_handler = unsafe { &mut *self.tcp_handler.get() };
                    for id in fired {
                        let (key, kind) = unpack_tcp_timer_id(id);
                        tcp_handler.handle_timer(
                            key,
                            kind,
                            now,
                            wheel,
                            self.neighbor_handler.local_mac(),
                            &self.neighbor_handler,
                            &mut self.free_frames,
                            &mut self.rx_return,
                            &mut self.tx_return,
                        );
                    }
                }
            }

            // ---- TCP Send ----
            //
            // SAFETY: single-threaded, no reentrant handler calls.
            let wheel = unsafe { &mut *self.wheel.get() };
            unsafe { &mut *self.tcp_handler.get() }.poll_send(
                now,
                wheel,
                self.neighbor_handler.local_mac(),
                &self.neighbor_handler,
                &mut self.free_frames,
                &mut self.rx_return,
                &mut self.tx_return,
            );

            // ---- QUIC Send ----
            {
                let wheel = unsafe { &mut *self.wheel.get() };
                self.quic_handler
                    .poll_send(now, wheel, &mut self.free_frames, &mut self.tx_return);
            }

            self.evict_counter = self.evict_counter.wrapping_add(1);
            if self.evict_counter & 65535 == 0 {
                // SAFETY: single-threaded, no reentrant handler calls.
                unsafe { &mut *self.udp_handler.get() }.evict_stale(
                    now,
                    Duration::from_secs(30),
                    &mut self.rx_return,
                );

                self.neighbor_handler.evict_stale(now);
                self.quic_handler.evict_stale(now);
                // SAFETY: single-threaded, no reentrant access.
                unsafe { &mut *self.pmtu.get() }.evict_stale(now);
            }

            // ---- Transmit ----
            let free_before = self.free_frames.num_frames();

            while self.tx_return.num_frames() > 0 {
                match self.socket.send(&mut self.tx_return) {
                    Ok(n) => in_flight_tx += n,
                    Err(_) => break, // TX ring full — will be drained below.
                }
            }

            // ---- Drain TX Completions ----
            // Kick the kernel repeatedly to produce completions (~32 per
            // sendto on veth) and collect them into rx_return. This keeps
            // pace with the send rate so free_frames doesn't starve.
            while in_flight_tx > 0 {
                self.socket.maybe_wake()?;
                match self.umem.process_completion_queue(&mut self.rx_return) {
                    Ok(n) => {
                        debug_assert!(
                            in_flight_tx >= n,
                            "completion underflow: in_flight={in_flight_tx} completed={n}"
                        );
                        in_flight_tx -= n;
                    }
                    Err(_) => break, // No more completions ready.
                }
            }

            // ---- Recycle rx_return → fill queue + free_frames ----
            // Single recycle pass: handler-returned RX frames and TX
            // completions all flow through here. Fill queue gets what it
            // needs (bounded by ring size), remainder goes to free_frames.
            self.recycle_rx_return()?;

            // ---- Capacity-Driven Wakes ----
            // After frame recycling, wake any futures blocked on capacity.
            // Only wake if free_frames actually grew (i.e., outbound capacity was freed).
            if self.free_frames.num_frames() > free_before {
                main_waker.set_woken();
                crate::rt::context::with_runtime_context(|ctx| {
                    let wakers = unsafe { &mut *ctx.capacity_wakers.get() };
                    for waker in wakers.drain(..) {
                        waker.wake();
                    }
                });
            }

            // ---- Frame Accounting Invariant ----
            debug_assert_eq!(
                self.rx_return.num_frames(),
                0,
                "rx_return must be fully drained"
            );
            // Use <= rather than == because frames held by UdpHandler's
            // FragmentReader are outside our tracked variables. The deficit
            // equals fragments currently awaiting reassembly. This also
            // corrects a pre-existing gap in the old == assertion.
            let tracked = self.free_frames.num_frames() as u32
                + in_flight_tx
                + self.tx_return.num_frames() as u32;
            debug_assert!(
                tracked <= expected_total,
                "Frame leak: tracked={} (free={} in_flight={} tx_pending={}) > expected={}",
                tracked,
                self.free_frames.num_frames(),
                in_flight_tx,
                self.tx_return.num_frames(),
                expected_total,
            );
        }

        Ok(())
    }
}
