use std::rc::Rc;
use std::task::Poll;
use std::time::Duration;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::Context,
};

use futures_util::pin_mut;

use crate::xdp::{
    context::{XdpContext, XdpContextBuilder},
    error::Result,
    frame::{BasicFrameBuffer, FrameBuffer},
    program::AttachMode,
    socket::{CopyMode, Socket, SocketBuilder},
    umem::{Umem, UmemBuilder},
};
use crate::{
    net::{
        NeighborHandler, PmtuCache,
        handler::{ipv4::Ipv4Handler, ipv6::Ipv6Handler, udp::UdpHandler},
        socket::UdpSocket,
        wire::{
            ethernet::{EtherTypes, EthernetFrame, MacAddress},
            ip::IpAddress,
        },
    },
    xdp::frame::SharedFrameBuffer,
};

use super::waker;

const DEFAULT_ARP_TTL: Duration = Duration::from_secs(60);

/// Builder for configuring and constructing a [`LocalRuntime`].
///
/// Wraps the underlying XDP context, UMEM, and socket builders with
/// sane defaults. All builder methods delegate to the appropriate
/// sub-builder so callers only interact with a single API.
pub struct LocalRuntimeBuilder<'name> {
    if_name: &'name str,
    ctx: XdpContextBuilder<'name>,
    umem: UmemBuilder,
    socket: SocketBuilder<'name>,
    local_mac: [u8; 6],
    arp_ttl: Duration,
}

impl<'name> LocalRuntimeBuilder<'name> {
    pub fn new(if_name: &'name str, queue: u32, local_mac: [u8; 6]) -> Self {
        Self {
            if_name,
            ctx: XdpContextBuilder::new(if_name),
            umem: UmemBuilder::new(),
            socket: SocketBuilder::new(if_name, queue),
            local_mac,
            arp_ttl: DEFAULT_ARP_TTL,
        }
    }

    pub fn arp_ttl(mut self, arp_ttl: Duration) -> Self {
        self.arp_ttl = arp_ttl;
        self
    }

    pub fn attach_mode(mut self, attach_mode: AttachMode) -> Self {
        self.ctx = self.ctx.attach_mode(attach_mode);
        self
    }

    pub fn enable_fragmentation(mut self, enable_fragmentation: bool) -> Self {
        self.ctx = self.ctx.enable_fragmentation(enable_fragmentation);
        self.socket = self.socket.enable_fragmentation(enable_fragmentation);
        self
    }

    pub fn completion_ring_size(mut self, completion_ring_size: u32) -> Self {
        self.umem = self.umem.completion_ring_size(completion_ring_size);
        self
    }

    pub fn fill_ring_size(mut self, fill_ring_size: u32) -> Self {
        self.umem = self.umem.fill_ring_size(fill_ring_size);
        self
    }

    pub fn frame_size(mut self, frame_size: usize) -> Self {
        self.umem = self.umem.frame_size(frame_size);
        self
    }

    pub fn busy_poll(mut self, busy_poll: bool) -> Self {
        self.umem = self.umem.busy_poll(busy_poll);
        self.socket = self.socket.busy_poll(busy_poll);
        self
    }

    pub fn busy_poll_batch_size(mut self, busy_poll_batch_size: usize) -> Self {
        self.socket = self.socket.busy_poll_batch_size(busy_poll_batch_size);
        self
    }

    pub fn busy_poll_timeout_us(mut self, busy_poll_timeout_us: i32) -> Self {
        self.socket = self.socket.busy_poll_timeout_us(busy_poll_timeout_us);
        self
    }

    pub fn huge_tables(mut self, huge_tables: bool) -> Self {
        self.umem = self.umem.huge_tables(huge_tables);
        self
    }

    pub fn unaligned(mut self, unaligned: bool) -> Self {
        self.umem = self.umem.unaligned(unaligned);
        self
    }

    pub fn rx_ring_size(mut self, rx_ring_size: u32) -> Self {
        self.socket = self.socket.rx_ring_size(rx_ring_size);
        self
    }

    pub fn tx_ring_size(mut self, tx_ring_size: u32) -> Self {
        self.socket = self.socket.tx_ring_size(tx_ring_size);
        self
    }

    pub fn copy_mode(mut self, copy_mode: CopyMode) -> Self {
        self.socket = self.socket.copy_mode(copy_mode);
        self
    }

    pub fn build<'umem>(self) -> Result<LocalRuntime<'umem>> {
        let mut ctx = self.ctx.build()?;
        let umem = self.umem.build()?;
        let socket = self.socket.build(&mut ctx, umem.owner().clone())?;
        LocalRuntime::new(
            self.if_name,
            ctx,
            umem,
            socket,
            self.local_mac,
            self.arp_ttl,
        )
    }
}

const DEFAULT_SOCKET_RX_CAPACITY: usize = 256;

/// Single-threaded packet processing runtime with integrated protocol handlers.
///
/// Owns the AF_XDP socket, UMEM, and all protocol handler state. The
/// `run` method drives the event loop: receive frames, dispatch through
/// the protocol stack, poll the user future, and transmit responses.
pub struct LocalRuntime<'umem> {
    // Overall context for the XDP program, this is used to own the underlying XDP program and socket.
    _ctx: XdpContext,
    // Shared memory for reading and writing frames to the network.
    umem: Umem<'umem>,
    // Raw AF_XDP socket for reading and writing frames to the network.
    socket: Socket<'umem>,
    // ARP/NDP neighbor handling for IPv4 and IPv6.
    neighbor_handler: Rc<NeighborHandler>,
    // Path MTU cache for handling path MTU discovery.
    pmtu: Rc<PmtuCache>,
    // Main IPv4 protocol handler calls into udp_handler and tcp_handler.
    ipv4_handler: Ipv4Handler,
    // Main IPv6 protocol handler calls into neighbor_handler and udp_handler and tcp_handler.
    ipv6_handler: Ipv6Handler,
    // UDP handler is used to bind and send UDP packets, handling things like fragmentation and reassembly.
    udp_handler: UdpHandler<'umem>,
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
    pub fn builder<'name>(
        if_name: &'name str,
        queue: u32,
        local_mac: [u8; 6],
    ) -> LocalRuntimeBuilder<'name> {
        LocalRuntimeBuilder::new(if_name, queue, local_mac)
    }

    fn new(
        if_name: &str,
        ctx: XdpContext,
        umem: Umem<'umem>,
        socket: Socket<'umem>,
        local_mac: [u8; 6],
        arp_ttl: Duration,
    ) -> Result<Self> {
        let mtu = ctx.info().mtu;
        let neighbor_handler = Rc::new(NeighborHandler::new(
            if_name,
            MacAddress::from(local_mac),
            arp_ttl,
        )?);
        let pmtu = Rc::new(PmtuCache::with_mtu(mtu));

        let tx_return = BasicFrameBuffer::new(umem.num_frames()).into();
        let rx_return = BasicFrameBuffer::new(umem.num_frames()).into();
        let free_frames = umem.init_buffer::<BasicFrameBuffer>().unwrap().into();

        Ok(Self {
            _ctx: ctx,
            umem,
            socket,
            neighbor_handler,
            pmtu,
            ipv4_handler: Ipv4Handler::new(),
            ipv6_handler: Ipv6Handler::new(),
            udp_handler: UdpHandler::new(256),
            free_frames,
            tx_return,
            rx_return,
            evict_counter: 0,
        })
    }

    /// Bind a UDP socket to the given address and port.
    pub fn bind_udp(&mut self, addr: IpAddress, port: u16) -> Result<UdpSocket<'umem>> {
        let rx_queue = self
            .udp_handler
            .bind(addr, port, DEFAULT_SOCKET_RX_CAPACITY)
            .map_err(|e| crate::xdp::error::Error::Other(e.to_string()))?;
        Ok(UdpSocket::new(
            addr,
            port,
            rx_queue,
            self.free_frames.clone(),
            self.rx_return.clone(),
            self.tx_return.clone(),
            self.pmtu.clone(),
            self.neighbor_handler.clone(),
        ))
    }

    /// Runs the event loop until `exit` is set or `fut` completes.
    ///
    /// Each iteration: receive frames, dispatch through the protocol stack,
    /// poll `fut`, drive TCP timers, evict stale state, and transmit.
    pub fn run<F>(&mut self, exit: Arc<AtomicBool>, fut: F) -> Result<()>
    where
        F: Future<Output = ()>,
    {
        // Before we can operate properly we need to seed the kernel with free frames to read into, this logic
        // will take as many frames as it can from the free_frames buffer and submit them to the kernel. Note the logic
        // ensures there will be a set of frames still present here equaling the number of slots in the completion (send) ring.
        self.umem.maybe_wake_fill_queue(self.socket.fd())?;
        self.umem
            .process_fill_queue(&mut self.free_frames)
            .expect("failed to process fill queue");

        let waker = waker();
        let mut cx = Context::from_waker(&waker);
        pin_mut!(fut);

        // We need a storage container for the incoming frames, this will be used to store the frames
        // that are read from the network while the runtime is processing them.
        let mut buffer = BasicFrameBuffer::new(self.umem.num_frames());
        while !exit.load(Ordering::Relaxed) {
            let now = std::time::Instant::now();

            // We only drive the network read logic if we have new network frames to process.
            //
            // This will return with 1 > N frames in the success case, as soon as possible. If there are no frames it will return an error,
            // at this point we would have blocked so execute the runtime loop again but don't bother processing the frames.
            if let Ok(_) = self.socket.recv(&mut buffer) {
                let Self {
                    neighbor_handler,
                    ipv4_handler,
                    ipv6_handler,
                    pmtu,
                    udp_handler,
                    ..
                } = self;

                for frame in buffer.take_frames() {
                    let ethernet_frame = EthernetFrame::from_bytes(&frame);
                    match ethernet_frame.ether_type {
                        EtherTypes::IPv4 => {
                            ipv4_handler.handle(
                                frame,
                                udp_handler,
                                pmtu,
                                now,
                                &mut self.free_frames,
                                &mut self.rx_return,
                                &mut self.tx_return,
                            );
                        }
                        EtherTypes::IPv6 => {
                            ipv6_handler.handle(
                                frame,
                                neighbor_handler,
                                udp_handler,
                                pmtu,
                                now,
                                &mut self.free_frames,
                                &mut self.rx_return,
                                &mut self.tx_return,
                            );
                        }
                        EtherTypes::Arp => {
                            neighbor_handler.handle_arp(
                                now,
                                frame,
                                &mut self.rx_return,
                                &mut self.tx_return,
                            );
                        }
                        _ => {
                            // Unsupported ethertype, return the frame to the kernel.
                            self.rx_return.push(frame);
                        }
                    }
                }
            }

            // Drive the user future, we aren't using wakers here, because in reality we don't
            // _actually_ have readiness due to the fact that the futures in use here are just
            // vectors of frames that can't fail. We are designed to be as low latency as possible,
            // the indirection of having a waker call just to add this back into play is unnecessary.
            if let Poll::Ready(_) = fut.as_mut().poll(&mut cx) {
                return Ok(());
            }

            // Periodically evict stale entries (~every 1024 iterations).
            self.evict_counter = self.evict_counter.wrapping_add(1);
            if self.evict_counter & 0x3FF == 0 {
                self.udp_handler
                    .evict_stale(now, Duration::from_secs(30), &mut self.rx_return);
                self.neighbor_handler.evict_stale(now);
                self.pmtu.evict_stale(now);
            }

            // Handle the frames ready to send this will push all of them into the socket for transmission.
            while self.tx_return.num_frames() > 0 {
                self.socket.maybe_wake()?;

                let _ = self.socket.send(&mut self.tx_return);
                let _ = self.umem.process_completion_queue(&mut self.rx_return);
            }

            // Now refill the fill queue with frames to read into, the rest of the frames get pushed back into the free_frames buffer.
            let _ = self.umem.process_fill_queue(&mut self.rx_return);
            self.umem.maybe_wake_fill_queue(self.socket.fd())?;

            for frame in self.rx_return.take_frames() {
                self.free_frames.push(frame);
            }
        }

        Ok(())
    }
}
