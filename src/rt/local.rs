use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use crate::net::{
    EtherTypes, EthernetFrame, IpAddress, Ipv4Handler, Ipv6Handler, MacAddress, NeighborHandler,
    PmtuCache, UdpHandler, UdpSocket,
};
use crate::xdp::{
    context::{XdpContext, XdpContextBuilder},
    error::Result,
    frame::{BasicFrameBuffer, FrameBuffer},
    program::AttachMode,
    socket::{CopyMode, Socket, SocketBuilder},
    umem::{Umem, UmemBuilder},
};

const DEFAULT_ARP_TTL: Duration = Duration::from_secs(60);

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

    pub fn num_frames(mut self, num_frames: usize) -> Self {
        self.umem = self.umem.num_frames(num_frames);
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

pub struct LocalRuntime<'umem> {
    _ctx: XdpContext,
    umem: Umem<'umem>,
    socket: Socket<'umem>,
    neighbor_handler: NeighborHandler,
    ipv4_handler: Ipv4Handler,
    ipv6_handler: Ipv6Handler,
    pmtu: PmtuCache,
    udp_handler: UdpHandler<'umem>,
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
        let neighbor_handler = NeighborHandler::new(if_name, MacAddress::from(local_mac), arp_ttl)?;

        Ok(Self {
            _ctx: ctx,
            umem,
            socket,
            neighbor_handler,
            ipv4_handler: Ipv4Handler::new(),
            ipv6_handler: Ipv6Handler::new(),
            pmtu: PmtuCache::with_mtu(mtu),
            udp_handler: UdpHandler::new(256),
        })
    }

    /// Bind a UDP socket to the given address and port.
    pub fn bind_udp(&mut self, addr: IpAddress, port: u16) -> Result<u32> {
        self.udp_handler
            .bind(addr, port, DEFAULT_SOCKET_RX_CAPACITY)
            .map_err(|e| crate::xdp::error::Error::Other(e.to_string()))
    }

    /// Access a bound socket by ID.
    pub fn udp_socket(&self, id: u32) -> Option<&UdpSocket<'umem>> {
        self.udp_handler.socket(id)
    }

    /// Mutably access a bound socket by ID (for recv).
    pub fn udp_socket_mut(&mut self, id: u32) -> Option<&mut UdpSocket<'umem>> {
        self.udp_handler.socket_mut(id)
    }

    pub fn run(&mut self, exit: Arc<AtomicBool>) -> Result<()> {
        let mut buffer = self.umem.init_buffer::<BasicFrameBuffer>().unwrap();

        let mut rx_return = BasicFrameBuffer::new(buffer.num_frames());
        let mut tx_return = BasicFrameBuffer::new(buffer.num_frames());

        self.umem.maybe_wake_fill_queue(self.socket.fd())?;
        self.umem.process_fill_queue(&mut buffer);

        while !exit.load(Ordering::Relaxed) {
            if let Err(_) = self.socket.recv(&mut buffer) {
                continue;
            }

            let Self {
                neighbor_handler,
                ipv4_handler,
                ipv6_handler,
                pmtu,
                udp_handler,
                ..
            } = self;

            for frame in buffer.take_frames() {
                let ethernet_frame = EthernetFrame::from_frame(&frame);
                match ethernet_frame.ether_type {
                    EtherTypes::IPv4 => {
                        ipv4_handler.handle(
                            frame,
                            udp_handler,
                            pmtu,
                            &mut rx_return,
                            &mut tx_return,
                        );
                    }
                    EtherTypes::IPv6 => {
                        ipv6_handler.handle(
                            frame,
                            neighbor_handler,
                            udp_handler,
                            pmtu,
                            &mut rx_return,
                            &mut tx_return,
                        );
                    }
                    EtherTypes::Arp => {
                        neighbor_handler.handle_arp(frame, &mut rx_return, &mut tx_return);
                    }
                    _ => {
                        // Unsupported ethertype, return the frame to the kernel.
                        rx_return.push(frame);
                    }
                }
            }

            // Periodically evict stale reassembly entries.
            self.udp_handler
                .evict_stale(Duration::from_secs(30), &mut rx_return);

            if tx_return.num_frames() > 0 {
                while let Err(_) = self.socket.send(&mut tx_return) {
                    self.socket.maybe_wake()?;
                }

                while let Err(_) = self.umem.process_completion_queue(&mut rx_return) {
                    self.socket.maybe_wake()?;
                }
            }

            self.umem.maybe_wake_fill_queue(self.socket.fd())?;
            self.umem.process_fill_queue(&mut rx_return);
        }

        Ok(())
    }
}
