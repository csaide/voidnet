use std::task::{Context, Poll};
use std::{pin::Pin, rc::Rc};

use crate::net::fragment::{FragmentWriter, Packet};
use crate::net::handler::udp::ReceivedUdpPacket;
use crate::net::wire::ethernet::MacAddress;
use crate::net::wire::ip::{IpAddress, Ipv4Address, Ipv6Address};
use crate::net::wire::udp::{self, UDP_HEADER_LEN, UdpHeader};
use crate::net::{NeighborHandler, PmtuCache};
use crate::xdp::error::WouldBlock;
use crate::xdp::frame::{FrameBuffer, SharedFrameBuffer};

use super::LocalQueue;

const DEFAULT_MTU: u32 = 1500;

/// A user-facing UDP socket handle.
///
/// Obtained via `LocalRuntime::bind_udp()`. The handler pushes received
/// packets into `rx_queue`; a future TX path will drain `tx_queue`.
pub struct UdpSocket<'umem> {
    local_addr: IpAddress,
    local_port: u16,
    rx_queue: LocalQueue<ReceivedUdpPacket<'umem>>,
    free_frames: SharedFrameBuffer<'umem>,
    tx_return: SharedFrameBuffer<'umem>,
    rx_return: SharedFrameBuffer<'umem>,
    pmtu: Rc<PmtuCache>,
    neighbor_handler: Rc<NeighborHandler>,
}

impl<'umem> UdpSocket<'umem> {
    pub(crate) fn new(
        local_addr: IpAddress,
        local_port: u16,
        rx_queue: LocalQueue<ReceivedUdpPacket<'umem>>,
        free_frames: SharedFrameBuffer<'umem>,
        rx_return: SharedFrameBuffer<'umem>,
        tx_return: SharedFrameBuffer<'umem>,
        pmtu: Rc<PmtuCache>,
        neighbor_handler: Rc<NeighborHandler>,
    ) -> Self {
        Self {
            local_addr,
            local_port,
            rx_queue,
            free_frames,
            rx_return,
            tx_return,
            pmtu,
            neighbor_handler,
        }
    }

    pub fn local_addr(&self) -> IpAddress {
        self.local_addr
    }

    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    pub fn discard_packet(&mut self, packet: ReceivedUdpPacket<'umem>) {
        packet.packet.drain_to(&mut self.rx_return);
    }

    pub fn send_packet_fast(&mut self, packet: ReceivedUdpPacket<'umem>) -> u32 {
        let payload_len = packet.packet.len() as u32;
        packet.packet.drain_to(&mut self.tx_return);
        payload_len
    }

    /// Send a received packet back out by draining its frames to the TX path.
    ///
    /// Typically used after [`ReceivedUdpPacket::swap_addresses`] to echo
    /// packets back to the sender without allocating new frames.
    #[inline(always)]
    pub fn send_packet(
        &mut self,
        packet: ReceivedUdpPacket<'umem>,
    ) -> UdpSendPacketFuture<'_, 'umem> {
        let payload_len = packet.packet.len() as u32;
        UdpSendPacketFuture {
            tx_return: &mut self.tx_return,
            pkt: packet.packet,
            payload_len,
        }
    }

    #[inline(always)]
    pub fn send_to<'buf>(
        &mut self,
        dst_addr: IpAddress,
        dst_port: u16,
        payload: &'buf [u8],
    ) -> UdpSendToFuture<'_, 'buf, 'umem> {
        UdpSendToFuture {
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
        }
    }

    #[inline(always)]
    pub fn recv_from(&self) -> UdpRecvFromFuture<'_, 'umem> {
        UdpRecvFromFuture {
            rx_queue: &self.rx_queue,
        }
    }
}

/// Future returned by [`UdpSocket::send_to`].
///
/// Designed for the `LocalRuntime`'s busy-poll model: the runtime
/// repeatedly polls this future from a packet-processing loop using a
/// no-op waker (see `rt/local.rs` and `rt/waker.rs`). Waker
/// registration is intentionally omitted because wake-ups are driven
/// by the polling loop, not by I/O readiness notifications.
pub struct UdpSendToFuture<'sock, 'buf, 'umem> {
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
}

impl<'sock, 'buf, 'umem> UdpSendToFuture<'sock, 'buf, 'umem> {
    fn prepare_udp_packet(&mut self) -> Result<Packet<'umem>, WouldBlock> {
        // Step 1: MAC address resolution.
        let dst_mac = match self.neighbor_handler.lookup(&self.dst_addr) {
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
                        // Mismatched address families — return frame and error.
                        self.rx_return.push(frame);
                    }
                }
                return Err(WouldBlock);
            }
        };
        let src_mac = self.neighbor_handler.local_mac();

        let pmtu = self.pmtu.get(&self.dst_addr).min(DEFAULT_MTU);

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
        let checksum = udp::compute_udp_checksum_from_parts(
            &src_ip,
            &dst_ip,
            self.src_port,
            self.dst_port,
            udp_len,
            self.payload,
        );
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
        let checksum = udp::compute_udp_checksum_v6_from_parts(
            &src_ip,
            &dst_ip,
            self.src_port,
            self.dst_port,
            udp_len,
            self.payload,
        );
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

impl<'sock, 'buf, 'umem> Future for UdpSendToFuture<'sock, 'buf, 'umem> {
    type Output = u32;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        let pkt = match std::mem::take(&mut this.pkt) {
            Packet::Empty => match this.prepare_udp_packet() {
                Ok(pkt) => pkt,
                Err(_) => return Poll::Pending,
            },
            pkt => pkt,
        };

        if this.tx_return.free_space() < pkt.num_frames() {
            this.pkt = pkt;
            return Poll::Pending;
        }

        pkt.drain_to(&mut this.tx_return);
        Poll::Ready(this.payload.len() as u32)
    }
}

/// Future returned by [`UdpSocket::send_packet`].
///
/// Waits until the TX return path has enough capacity for the packet's
/// frames, then drains them. No preparation step is needed since the
/// frames are already built.
pub struct UdpSendPacketFuture<'sock, 'umem> {
    tx_return: &'sock mut SharedFrameBuffer<'umem>,
    pkt: Packet<'umem>,
    payload_len: u32,
}

impl<'sock, 'umem> Future for UdpSendPacketFuture<'sock, 'umem> {
    type Output = u32;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if this.tx_return.free_space() < this.pkt.num_frames() {
            return Poll::Pending;
        }

        let len = this.payload_len;
        let pkt = std::mem::take(&mut this.pkt);
        pkt.drain_to(&mut this.tx_return);
        Poll::Ready(len)
    }
}

/// Future returned by [`UdpSocket::recv_from`].
///
/// Designed for the `LocalRuntime`'s busy-poll model: the runtime
/// repeatedly polls this future from a packet-processing loop using a
/// no-op waker. Waker registration is intentionally omitted because
/// wake-ups are driven by the polling loop, not by I/O readiness
/// notifications.
pub struct UdpRecvFromFuture<'sock, 'umem> {
    rx_queue: &'sock LocalQueue<ReceivedUdpPacket<'umem>>,
}

impl<'sock, 'umem> Future for UdpRecvFromFuture<'sock, 'umem> {
    type Output = ReceivedUdpPacket<'umem>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match this.rx_queue.pop() {
            Some(packet) => Poll::Ready(packet),
            None => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::net::wire::ethernet::MacAddress;
    use crate::net::wire::ip::Ipv4Address;
    use crate::xdp::frame::BasicFrameBuffer;

    #[test]
    fn accessors() {
        let rx = LocalQueue::new(128);
        let free_frames = BasicFrameBuffer::new(128).into();
        let tx_return = BasicFrameBuffer::new(128).into();
        let rx_return = BasicFrameBuffer::new(128).into();
        let addr = IpAddress::V4(Ipv4Address::new([192, 168, 1, 1]));
        let pmtu = Rc::new(PmtuCache::new());
        let neighbor_handler = Rc::new(
            NeighborHandler::new(
                "test0",
                MacAddress::new([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
                Duration::from_secs(60),
            )
            .unwrap(),
        );
        let sock = UdpSocket::new(
            addr,
            5000,
            rx,
            free_frames,
            rx_return,
            tx_return,
            pmtu,
            neighbor_handler,
        );

        assert_eq!(sock.local_addr(), addr);
        assert_eq!(sock.local_port(), 5000);
    }
}
