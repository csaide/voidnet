use std::{
    cell::UnsafeCell,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
};

use coarsetime::Instant;

use crate::{
    net::{
        NeighborHandler, PmtuCache,
        checksum::{compute_udp_checksum_from_parts, compute_udp_checksum_v6_from_parts},
        fragment::{FragmentWriter, Packet},
        handler::udp::{BindError, ReceivedUdpPacket, UdpHandler},
        wire::{
            ethernet::MacAddress,
            ip::{IpAddress, Ipv4Address, Ipv6Address},
            udp::{UDP_HEADER_LEN, UdpHeader},
        },
    },
    rt::context::with_runtime_context,
    xdp::{
        error::WouldBlock,
        frame::{FrameBuffer, SharedFrameBuffer},
    },
};

use super::LocalQueue;

const DEFAULT_MTU: u32 = 1500;
const DEFAULT_SOCKET_RX_CAPACITY: usize = 256;

/// A user-facing UDP socket handle.
///
/// Created via `UdpSocket::new()` inside a `LocalRuntime::run()` closure,
/// then bound to an address and port via `bind()`.
#[derive(Debug)]
pub struct UdpSocket<'umem> {
    local_addr: IpAddress,
    local_port: u16,
    rx_queue: LocalQueue<ReceivedUdpPacket<'umem>>,
    free_frames: SharedFrameBuffer<'umem>,
    tx_return: SharedFrameBuffer<'umem>,
    rx_return: SharedFrameBuffer<'umem>,
    pmtu: Rc<PmtuCache>,
    neighbor_handler: Rc<NeighborHandler>,
    handler: Rc<UnsafeCell<UdpHandler<'umem>>>,
    tx_offload: bool,
}

impl<'umem> UdpSocket<'umem> {
    /// Create a new bound UDP socket.
    ///
    /// Must be called inside a `LocalRuntime::run()` closure. Panics otherwise.
    pub fn new(addr: IpAddress, port: u16) -> Result<Self, BindError> {
        with_runtime_context(|ctx| {
            let handler = unsafe { &mut *ctx.udp_handler.get() };
            let rx_queue = handler.bind(addr, port, DEFAULT_SOCKET_RX_CAPACITY)?;
            Ok(Self {
                local_addr: addr,
                local_port: port,
                rx_queue,
                free_frames: ctx.free_frames.clone(),
                tx_return: ctx.tx_return.clone(),
                rx_return: ctx.rx_return.clone(),
                pmtu: ctx.pmtu.clone(),
                neighbor_handler: ctx.neighbor_handler.clone(),
                handler: ctx.udp_handler.clone(),
                tx_offload: ctx.tx_offload,
            })
        })
    }

    /// Close this socket, unbinding from the address/port and draining queued packets.
    pub fn close(&mut self) {
        // SAFETY: single-threaded, no reentrant handler calls.
        let handler = unsafe { &mut *self.handler.get() };
        handler.unbind(self.local_addr, self.local_port);
        // Drain any queued packets back to rx_return.
        while let Some(pkt) = self.rx_queue.pop() {
            pkt.packet.drain_to(&mut self.rx_return);
        }
    }

    /// Returns the local address of this socket.
    pub fn local_addr(&self) -> IpAddress {
        self.local_addr
    }

    /// Returns the local port of this socket.
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// Receive a packet. Returns a future that resolves when a packet is available.
    #[inline(always)]
    pub fn recv_from(&self) -> RecvFrom<'_, 'umem> {
        RecvFrom {
            rx_queue: &self.rx_queue,
        }
    }

    /// Send a payload to a destination address and port.
    #[inline(always)]
    pub fn send_to<'buf>(
        &mut self,
        dst_addr: IpAddress,
        dst_port: u16,
        payload: &'buf [u8],
    ) -> SendTo<'_, 'buf, 'umem> {
        SendTo {
            free_frames: &mut self.free_frames,
            rx_return: &mut self.rx_return,
            tx_return: &mut self.tx_return,
            pmtu: &self.pmtu,
            neighbor_handler: &self.neighbor_handler,
            pkt: Packet::Empty,
            src_addr: self.local_addr,
            src_port: self.local_port,
            dst_addr,
            dst_port,
            payload,
            tx_offload: self.tx_offload,
        }
    }

    /// Echo a received packet back with backpressure (async).
    ///
    /// The caller should have already called `swap_addresses()` on the packet.
    #[inline(always)]
    pub fn echo(&mut self, packet: ReceivedUdpPacket<'umem>) -> Echo<'_, 'umem> {
        let payload_len = packet.packet.len() as u32;
        Echo {
            tx_return: &mut self.tx_return,
            pkt: packet.packet,
            payload_len,
        }
    }

    /// Echo a received packet back immediately without backpressure (sync).
    ///
    /// The caller should have already called `swap_addresses()` on the packet.
    #[inline(always)]
    pub fn echo_immediate(&mut self, packet: ReceivedUdpPacket<'umem>) -> u32 {
        let payload_len = packet.packet.len() as u32;
        packet.packet.drain_to(&mut self.tx_return);
        payload_len
    }

    /// Discard a received packet, returning its frames to the kernel.
    #[inline(always)]
    pub fn discard(&mut self, packet: ReceivedUdpPacket<'umem>) {
        packet.packet.drain_to(&mut self.rx_return);
    }

    /// Split into separate receive and send halves for concurrent use.
    pub fn split(&mut self) -> (RecvHalf<'_, 'umem>, SendHalf<'_, 'umem>) {
        let rx_queue = &self.rx_queue;
        let recv = RecvHalf { rx_queue };
        let send = SendHalf {
            free_frames: &mut self.free_frames,
            tx_return: &mut self.tx_return,
            rx_return: &mut self.rx_return,
            pmtu: &self.pmtu,
            neighbor_handler: &self.neighbor_handler,
            src_addr: self.local_addr,
            src_port: self.local_port,
            tx_offload: self.tx_offload,
        };
        (recv, send)
    }
}

impl<'umem> Drop for UdpSocket<'umem> {
    fn drop(&mut self) {
        self.close();
    }
}

/// Receive half of a split `UdpSocket`.
pub struct RecvHalf<'sock, 'umem> {
    rx_queue: &'sock LocalQueue<ReceivedUdpPacket<'umem>>,
}

impl<'sock, 'umem> RecvHalf<'sock, 'umem> {
    /// Receive a packet. Returns a future that resolves when a packet is available.
    #[inline(always)]
    pub fn recv_from(&self) -> RecvFrom<'_, 'umem> {
        RecvFrom {
            rx_queue: self.rx_queue,
        }
    }

    /// Receive a stream of packets. Returns a stream that yields packets as they are received.
    #[inline(always)]
    pub fn recv_stream(&self) -> RecvStream<'_, 'umem> {
        RecvStream {
            rx_queue: self.rx_queue,
        }
    }
}

/// Send half of a split `UdpSocket`.
pub struct SendHalf<'sock, 'umem> {
    free_frames: &'sock mut SharedFrameBuffer<'umem>,
    tx_return: &'sock mut SharedFrameBuffer<'umem>,
    rx_return: &'sock mut SharedFrameBuffer<'umem>,
    pmtu: &'sock PmtuCache,
    neighbor_handler: &'sock NeighborHandler,
    src_addr: IpAddress,
    src_port: u16,
    tx_offload: bool,
}

impl<'sock, 'umem> SendHalf<'sock, 'umem> {
    /// Send a payload to a destination address and port.
    #[inline(always)]
    pub fn send_to<'buf>(
        &mut self,
        dst_addr: IpAddress,
        dst_port: u16,
        payload: &'buf [u8],
    ) -> SendTo<'_, 'buf, 'umem> {
        SendTo {
            free_frames: self.free_frames,
            rx_return: self.rx_return,
            tx_return: self.tx_return,
            pmtu: self.pmtu,
            neighbor_handler: self.neighbor_handler,
            pkt: Packet::Empty,
            src_addr: self.src_addr,
            src_port: self.src_port,
            dst_addr,
            dst_port,
            payload,
            tx_offload: self.tx_offload,
        }
    }

    /// Echo a received packet back with backpressure (async).
    #[inline(always)]
    pub fn echo(&mut self, packet: ReceivedUdpPacket<'umem>) -> Echo<'_, 'umem> {
        let payload_len = packet.packet.len() as u32;
        Echo {
            tx_return: self.tx_return,
            pkt: packet.packet,
            payload_len,
        }
    }

    /// Echo a received packet back immediately without backpressure (sync).
    #[inline(always)]
    pub fn echo_immediate(&mut self, packet: ReceivedUdpPacket<'umem>) -> u32 {
        let payload_len = packet.packet.len() as u32;
        packet.packet.drain_to(&mut self.tx_return);
        payload_len
    }

    /// Discard a received packet, returning its frames to the kernel.
    #[inline(always)]
    pub fn discard(&mut self, packet: ReceivedUdpPacket<'umem>) {
        packet.packet.drain_to(&mut self.rx_return);
    }
}

/// Future returned by `recv_from()`.
pub struct RecvFrom<'sock, 'umem> {
    rx_queue: &'sock LocalQueue<ReceivedUdpPacket<'umem>>,
}

impl<'sock, 'umem> Future for RecvFrom<'sock, 'umem> {
    type Output = ReceivedUdpPacket<'umem>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match this.rx_queue.pop() {
            Some(packet) => Poll::Ready(packet),
            None => {
                this.rx_queue.register_waker(cx.waker());
                Poll::Pending
            }
        }
    }
}

/// Stream that yields received UDP packets.
pub struct RecvStream<'sock, 'umem> {
    rx_queue: &'sock LocalQueue<ReceivedUdpPacket<'umem>>,
}

impl<'sock, 'umem> futures_core::Stream for RecvStream<'sock, 'umem> {
    type Item = ReceivedUdpPacket<'umem>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match this.rx_queue.pop() {
            Some(packet) => Poll::Ready(Some(packet)),
            None => {
                this.rx_queue.register_waker(cx.waker());
                Poll::Pending
            }
        }
    }
}

/// Future returned by `send_to()`.
pub struct SendTo<'sock, 'buf, 'umem> {
    free_frames: &'sock mut SharedFrameBuffer<'umem>,
    rx_return: &'sock mut SharedFrameBuffer<'umem>,
    tx_return: &'sock mut SharedFrameBuffer<'umem>,
    pmtu: &'sock PmtuCache,
    neighbor_handler: &'sock NeighborHandler,
    pkt: Packet<'umem>,
    src_addr: IpAddress,
    src_port: u16,
    dst_addr: IpAddress,
    dst_port: u16,
    payload: &'buf [u8],
    tx_offload: bool,
}

impl<'sock, 'buf, 'umem> SendTo<'sock, 'buf, 'umem> {
    fn prepare_udp_packet(&mut self) -> Result<Packet<'umem>, WouldBlock> {
        let now = Instant::now();
        let dst_mac = match self.neighbor_handler.lookup(now, &self.dst_addr) {
            Some(mac) => mac,
            None => {
                let frame = self.free_frames.pop().ok_or(WouldBlock)?;
                match (self.src_addr, self.dst_addr) {
                    (IpAddress::V4(src), IpAddress::V4(dst)) => {
                        self.neighbor_handler.resolve_v4(
                            src,
                            dst,
                            frame,
                            &mut self.rx_return,
                            &mut self.tx_return,
                        );
                    }
                    (IpAddress::V6(src), IpAddress::V6(dst)) => {
                        self.neighbor_handler.resolve_v6(
                            src,
                            dst,
                            frame,
                            &mut self.rx_return,
                            &mut self.tx_return,
                        );
                    }
                    _ => {
                        self.rx_return.push(frame);
                    }
                }
                return Err(WouldBlock);
            }
        };
        let src_mac = self.neighbor_handler.local_mac();

        let pmtu = self.pmtu.get(now, &self.dst_addr).min(DEFAULT_MTU);

        match (self.src_addr, self.dst_addr) {
            (IpAddress::V4(src_ip), IpAddress::V4(dst_ip)) => {
                self.build_udp_v4(src_mac, dst_mac, src_ip, dst_ip, pmtu)
            }
            (IpAddress::V6(src_ip), IpAddress::V6(dst_ip)) => {
                self.build_udp_v6(src_mac, dst_mac, src_ip, dst_ip, pmtu)
            }
            _ => Err(WouldBlock),
        }
    }

    fn build_udp_v4(
        &mut self,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        pmtu: u32,
    ) -> Result<Packet<'umem>, WouldBlock> {
        let udp_len = (UDP_HEADER_LEN + self.payload.len()) as u16;
        let checksum = if self.tx_offload {
            [0, 0]
        } else {
            compute_udp_checksum_from_parts(
                &src_ip,
                &dst_ip,
                self.src_port,
                self.dst_port,
                udp_len,
                self.payload,
            )
        };
        let transport = UdpHeader::new(self.src_port, self.dst_port, udp_len, checksum);

        FragmentWriter::fragment_ipv4(
            src_mac,
            dst_mac,
            src_ip,
            dst_ip,
            64,
            &transport,
            self.payload,
            pmtu,
            self.tx_offload,
            &mut self.free_frames,
        )
    }

    fn build_udp_v6(
        &mut self,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        pmtu: u32,
    ) -> Result<Packet<'umem>, WouldBlock> {
        let udp_len = (UDP_HEADER_LEN + self.payload.len()) as u16;
        let checksum = if self.tx_offload {
            [0, 0]
        } else {
            compute_udp_checksum_v6_from_parts(
                &src_ip,
                &dst_ip,
                self.src_port,
                self.dst_port,
                udp_len,
                self.payload,
            )
        };
        let transport = UdpHeader::new(self.src_port, self.dst_port, udp_len, checksum);

        FragmentWriter::fragment_ipv6(
            src_mac,
            dst_mac,
            src_ip,
            dst_ip,
            64,
            &transport,
            self.payload,
            pmtu,
            &mut self.free_frames,
        )
    }
}

impl<'sock, 'buf, 'umem> Future for SendTo<'sock, 'buf, 'umem> {
    type Output = u32;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        let pkt = match std::mem::take(&mut this.pkt) {
            Packet::Empty => match this.prepare_udp_packet() {
                Ok(pkt) => pkt,
                Err(_) => {
                    crate::rt::context::register_capacity_waker(cx.waker());
                    return Poll::Pending;
                }
            },
            pkt => pkt,
        };

        if this.tx_return.free_space() < pkt.num_frames() {
            this.pkt = pkt;
            crate::rt::context::register_capacity_waker(cx.waker());
            return Poll::Pending;
        }

        pkt.drain_to(&mut this.tx_return);
        Poll::Ready(this.payload.len() as u32)
    }
}

/// Future returned by `echo()`.
pub struct Echo<'sock, 'umem> {
    tx_return: &'sock mut SharedFrameBuffer<'umem>,
    pkt: Packet<'umem>,
    payload_len: u32,
}

impl<'sock, 'umem> Future for Echo<'sock, 'umem> {
    type Output = u32;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if this.tx_return.free_space() < this.pkt.num_frames() {
            crate::rt::context::register_capacity_waker(cx.waker());
            return Poll::Pending;
        }

        let len = this.payload_len;
        let pkt = std::mem::take(&mut this.pkt);
        pkt.drain_to(&mut this.tx_return);
        Poll::Ready(len)
    }
}

#[cfg(test)]
mod tests {
    use coarsetime::Duration;

    use crate::{
        rt::{
            context::{ContextDropGuard, RuntimeContext},
            task::TaskQueue,
        },
        xdp::frame::BasicFrameBuffer,
    };

    use super::*;

    /// Set up a fake runtime context for testing.
    fn with_test_context<F: FnOnce()>(f: F) {
        let free_frames: SharedFrameBuffer = BasicFrameBuffer::new(128).into();
        let tx_return: SharedFrameBuffer = BasicFrameBuffer::new(128).into();
        let rx_return: SharedFrameBuffer = BasicFrameBuffer::new(128).into();
        let pmtu = Rc::new(PmtuCache::new());
        let neighbor_handler =
            Rc::new(NeighborHandler::new("test0", Duration::from_secs(60)).unwrap());
        let udp_handler = Rc::new(UnsafeCell::new(UdpHandler::new(256, false)));
        let tcp_handler = Rc::new(UnsafeCell::new(crate::net::handler::tcp::TcpHandler::new(
            false, false,
        )));

        let ctx = RuntimeContext {
            free_frames,
            tx_return,
            rx_return,
            pmtu,
            neighbor_handler,
            udp_handler,
            tcp_handler,
            tx_offload: false,
            task_queue: UnsafeCell::new(TaskQueue::new()),
            capacity_wakers: UnsafeCell::new(Vec::new()),
        };
        {
            let _guard = ContextDropGuard::new(ctx);
            f();
        }
    }

    #[test]
    fn new_and_accessors() {
        with_test_context(|| {
            let sock = UdpSocket::new(IpAddress::V4(Ipv4Address::unspecified()), 0).unwrap();
            assert_eq!(sock.local_addr(), IpAddress::V4(Ipv4Address::unspecified()));
            assert_eq!(sock.local_port(), 0);
        });
    }

    #[test]
    fn bind_and_close_lifecycle() {
        with_test_context(|| {
            let addr = IpAddress::V4(Ipv4Address::new([192, 168, 1, 1]));
            let mut sock = UdpSocket::new(addr, 5000).unwrap();

            assert_eq!(sock.local_addr(), addr);
            assert_eq!(sock.local_port(), 5000);

            sock.close();
        });
    }

    #[test]
    fn double_bind_returns_address_in_use() {
        with_test_context(|| {
            let addr = IpAddress::V4(Ipv4Address::new([192, 168, 1, 1]));
            let _sock = UdpSocket::new(addr, 5000).unwrap();
            let err = UdpSocket::new(addr, 5000).unwrap_err();
            assert_eq!(err, BindError::AddressInUse);
        });
    }

    #[test]
    #[should_panic(expected = "UdpSocket::new() called outside of LocalRuntime::run()")]
    fn new_panics_outside_runtime() {
        let _ = UdpSocket::new(IpAddress::V4(Ipv4Address::unspecified()), 0).unwrap();
    }
}
