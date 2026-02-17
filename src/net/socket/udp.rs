use std::task::{Context, Poll};
use std::{pin::Pin, rc::Rc};

use crate::net::packet::ReceivedPacket;
use crate::net::wire::ip::IpAddress;
use crate::net::{NeighborHandler, PacketWriter, PmtuCache};
use crate::xdp::frame::{FrameBuffer, SharedFrameBuffer};

use super::SharedQueue;

/// A user-facing UDP socket handle.
///
/// Obtained via `LocalRuntime::bind_udp()`. The handler pushes received
/// packets into `rx_queue`; a future TX path will drain `tx_queue`.
pub struct UdpSocket<'umem> {
    local_addr: IpAddress,
    local_port: u16,
    rx_queue: SharedQueue<ReceivedPacket<'umem>>,
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
        rx_queue: SharedQueue<ReceivedPacket<'umem>>,
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

    pub fn discard_packet(&mut self, packet: ReceivedPacket<'umem>) {
        for frame in packet.packet.into_frames() {
            self.rx_return.push(frame);
        }
    }

    pub fn send_to<'buf>(
        &mut self,
        dst_addr: IpAddress,
        dst_port: u16,
        payload: &'buf [u8],
    ) -> UdpSendToFuture<'_, 'buf, 'umem> {
        UdpSendToFuture {
            src_addr: self.local_addr,
            src_port: self.local_port,
            writer: PacketWriter::new(
                &mut self.free_frames,
                &mut self.rx_return,
                &mut self.tx_return,
                &self.pmtu,
                &self.neighbor_handler,
            ),
            dst_addr,
            dst_port,
            payload,
        }
    }

    pub fn recv_from(&self) -> UdpRecvFromFuture<'_, 'umem> {
        UdpRecvFromFuture {
            rx_queue: &self.rx_queue,
        }
    }
}

pub struct UdpSendToFuture<'sock, 'buf, 'umem> {
    writer: PacketWriter<'sock, 'umem>,
    src_addr: IpAddress,
    src_port: u16,
    dst_addr: IpAddress,
    dst_port: u16,
    payload: &'buf [u8],
}

impl<'sock, 'buf, 'umem> Future for UdpSendToFuture<'sock, 'buf, 'umem> {
    type Output = u32;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match this.writer.send_udp_packet(
            this.src_addr,
            this.dst_addr,
            this.src_port,
            this.dst_port,
            this.payload,
        ) {
            Ok(sent) => Poll::Ready(sent),
            Err(_) => Poll::Pending,
        }
    }
}

pub struct UdpRecvFromFuture<'sock, 'umem> {
    rx_queue: &'sock SharedQueue<ReceivedPacket<'umem>>,
}

impl<'sock, 'umem> Future for UdpRecvFromFuture<'sock, 'umem> {
    type Output = ReceivedPacket<'umem>;

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
        let rx = SharedQueue::new(128);
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
