use std::fmt;
use std::time::Duration;

use std::collections::HashMap;

use crate::net::packet::{PacketReader, ReceivedPacket};
use crate::net::socket::SharedQueue;
use crate::xdp::frame::{Frame, FrameBuffer};

use super::wire::ip::IpAddress;

/// Error returned when a `bind` call fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindError {
    AddressInUse,
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BindError::AddressInUse => write!(f, "address already in use"),
        }
    }
}

/// Internal binding record kept by `UdpHandler`.
pub(crate) struct UdpBinding<'umem> {
    rx_queue: SharedQueue<ReceivedPacket<'umem>>,
}

/// Manages bound UDP sockets and routes reassembled packets to them.
///
/// Wraps [`PacketReader`] for fragment reassembly and dispatches completed
/// packets to the matching socket's receive queue. Called from IPv4/IPv6
/// handlers instead of `PacketReader` directly.
pub struct UdpHandler<'umem> {
    packet_reader: PacketReader<'umem>,
    bindings: HashMap<(IpAddress, u16), UdpBinding<'umem>>,
}

impl<'umem> UdpHandler<'umem> {
    pub fn new(max_reassembly_entries: usize) -> Self {
        Self {
            packet_reader: PacketReader::new(max_reassembly_entries),
            bindings: HashMap::new(),
        }
    }

    /// Bind a new socket to (addr, port).
    ///
    /// Returns `(id, rx_queue, tx_queue)` so the caller can build a
    /// user-facing `UdpSocket` that shares the same queues.
    pub fn bind(
        &mut self,
        addr: IpAddress,
        port: u16,
        rx_capacity: usize,
    ) -> Result<SharedQueue<ReceivedPacket<'umem>>, BindError> {
        let key = (addr, port);
        if self.bindings.contains_key(&key) {
            return Err(BindError::AddressInUse);
        }

        let rx_queue = SharedQueue::new(rx_capacity);

        self.bindings.insert(
            key,
            UdpBinding {
                rx_queue: rx_queue.clone(),
            },
        );

        Ok(rx_queue)
    }

    /// Called by `Ipv4Handler` for UDP frames/fragments.
    pub fn process_ipv4(&mut self, frame: Frame<'umem>, rx_return: &mut impl FrameBuffer<'umem>) {
        if let Some(packet) = self.packet_reader.process_ipv4(frame, rx_return) {
            self.route(packet, rx_return);
        }
    }

    /// Called by `Ipv6Handler` for UDP frames/fragments.
    pub fn process_ipv6(
        &mut self,
        frame: Frame<'umem>,
        frag_ext_offset: Option<usize>,
        udp_offset: usize,
        rx_return: &mut impl FrameBuffer<'umem>,
    ) {
        if let Some(packet) =
            self.packet_reader
                .process_ipv6(frame, frag_ext_offset, udp_offset, rx_return)
        {
            self.route(packet, rx_return);
        }
    }

    /// Evict stale reassembly entries (delegates to `PacketReader`).
    pub fn evict_stale(&mut self, timeout: Duration, rx_return: &mut impl FrameBuffer<'umem>) {
        self.packet_reader.evict_stale(timeout, rx_return);
    }

    /// Number of in-progress reassembly entries.
    pub fn pending_reassembly(&self) -> usize {
        self.packet_reader.pending_entries()
    }

    fn route(&mut self, received: ReceivedPacket<'umem>, rx_return: &mut impl FrameBuffer<'umem>) {
        let key = (received.dst_addr, received.dst_port);
        if let Some(binding) = self.bindings.get(&key) {
            if let Some(evicted) = binding.rx_queue.push(received) {
                // Queue was full — oldest packet evicted, return its frames.
                for frame in evicted.packet.into_frames() {
                    rx_return.push(frame);
                }
            }
        } else {
            // No socket bound — return frames to kernel.
            for frame in received.packet.into_frames() {
                rx_return.push(frame);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::wire::{
        ip::{
            IPV4_MIN_HEADER_LEN, IPV6_HEADER_LEN, IpAddress, Ipv4Address, Ipv6Address,
            compute_ipv4_checksum,
        },
        udp::UDP_HEADER_LEN,
    };
    use crate::xdp::frame::{BasicFrameBuffer, Frame};

    const LOCAL_IPV4: Ipv4Address = Ipv4Address::new([192, 168, 1, 1]);
    const REMOTE_IPV4: Ipv4Address = Ipv4Address::new([10, 0, 0, 2]);
    const LOCAL_IPV6: Ipv6Address =
        Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    const REMOTE_IPV6: Ipv6Address =
        Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

    const ETH_HEADER_LEN: usize = 14;

    /// Builds a minimal Ethernet + IPv4 + UDP frame for testing.
    fn build_ipv4_udp_frame(
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        use crate::net::wire::ip::IpProtocols;
        let total_ip_len = (IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN + payload.len()) as u16;
        let mut buf =
            vec![0u8; ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN + payload.len()];

        buf[12] = 0x08;
        buf[13] = 0x00;

        let ip = &mut buf[14..];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&total_ip_len.to_be_bytes());
        ip[6] = 0x40;
        ip[8] = 64;
        ip[9] = IpProtocols::Udp;
        let src_bytes: [u8; 4] = src_ip.into();
        ip[12..16].copy_from_slice(&src_bytes);
        let dst_bytes: [u8; 4] = dst_ip.into();
        ip[16..20].copy_from_slice(&dst_bytes);
        let cksum = compute_ipv4_checksum(&ip[..20]);
        ip[10] = cksum[0];
        ip[11] = cksum[1];

        let udp_off = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;
        buf[udp_off..udp_off + 2].copy_from_slice(&src_port.to_be_bytes());
        buf[udp_off + 2..udp_off + 4].copy_from_slice(&dst_port.to_be_bytes());
        buf[udp_off + 4..udp_off + 6].copy_from_slice(&udp_len.to_be_bytes());

        buf[udp_off + UDP_HEADER_LEN..].copy_from_slice(payload);
        buf
    }

    /// Builds a minimal Ethernet + IPv6 + UDP frame for testing.
    fn build_ipv6_udp_frame(
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        use crate::net::wire::ip::IpProtocols;
        let payload_len = (UDP_HEADER_LEN + payload.len()) as u16;
        let mut buf = vec![0u8; ETH_HEADER_LEN + IPV6_HEADER_LEN + UDP_HEADER_LEN + payload.len()];

        buf[12] = 0x86;
        buf[13] = 0xDD;

        let ip = &mut buf[14..];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&payload_len.to_be_bytes());
        ip[6] = IpProtocols::Udp;
        ip[7] = 64;
        let src_bytes: [u8; 16] = src_ip.into();
        ip[8..24].copy_from_slice(&src_bytes);
        let dst_bytes: [u8; 16] = dst_ip.into();
        ip[24..40].copy_from_slice(&dst_bytes);

        let udp_off = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;
        buf[udp_off..udp_off + 2].copy_from_slice(&src_port.to_be_bytes());
        buf[udp_off + 2..udp_off + 4].copy_from_slice(&dst_port.to_be_bytes());
        buf[udp_off + 4..udp_off + 6].copy_from_slice(&udp_len.to_be_bytes());

        buf[udp_off + UDP_HEADER_LEN..].copy_from_slice(payload);
        buf
    }

    #[test]
    fn bind_returns_shared_queues() {
        let mut handler = UdpHandler::new(256);
        let rx_queue = handler.bind(IpAddress::V4(LOCAL_IPV4), 5000, 128).unwrap();
        assert!(rx_queue.is_empty());
    }

    #[test]
    fn duplicate_bind_returns_address_in_use() {
        let mut handler = UdpHandler::new(256);
        handler.bind(IpAddress::V4(LOCAL_IPV4), 5000, 128).unwrap();
        let err = handler
            .bind(IpAddress::V4(LOCAL_IPV4), 5000, 128)
            .unwrap_err();
        assert_eq!(err, BindError::AddressInUse);
    }

    #[test]
    fn process_ipv4_routes_to_bound_socket() {
        let mut buf = build_ipv4_udp_frame(REMOTE_IPV4, LOCAL_IPV4, 12345, 53, b"hello");

        let mut handler = UdpHandler::new(256);
        let rx_queue = handler.bind(IpAddress::V4(LOCAL_IPV4), 53, 128).unwrap();

        let len = buf.len();
        let frame = Frame::new(0, &mut buf, len, false);
        let mut rx = BasicFrameBuffer::new(4);

        handler.process_ipv4(frame, &mut rx);

        assert_eq!(rx.num_frames(), 0);
        assert_eq!(rx_queue.len(), 1);
    }

    #[test]
    fn process_ipv4_no_bound_socket_returns_frames() {
        let mut buf = build_ipv4_udp_frame(REMOTE_IPV4, LOCAL_IPV4, 12345, 53, b"hello");

        let mut handler = UdpHandler::new(256);

        let len = buf.len();
        let frame = Frame::new(0, &mut buf, len, false);
        let mut rx = BasicFrameBuffer::new(4);

        handler.process_ipv4(frame, &mut rx);
        assert_eq!(rx.num_frames(), 1);
    }

    #[test]
    fn process_ipv4_full_rx_queue_drops_and_returns_frames() {
        let mut buf1 = build_ipv4_udp_frame(REMOTE_IPV4, LOCAL_IPV4, 12345, 53, b"first");
        let mut buf2 = build_ipv4_udp_frame(REMOTE_IPV4, LOCAL_IPV4, 12345, 53, b"second");

        let mut handler = UdpHandler::new(256);
        let rx_queue = handler.bind(IpAddress::V4(LOCAL_IPV4), 53, 1).unwrap();

        let len1 = buf1.len();
        let frame1 = Frame::new(0, &mut buf1, len1, false);
        let mut rx = BasicFrameBuffer::new(4);
        handler.process_ipv4(frame1, &mut rx);
        assert_eq!(rx_queue.len(), 1);
        assert_eq!(rx.num_frames(), 0);

        let len2 = buf2.len();
        let frame2 = Frame::new(1, &mut buf2, len2, false);
        handler.process_ipv4(frame2, &mut rx);

        assert_eq!(rx_queue.len(), 1);
        assert_eq!(rx.num_frames(), 1);
    }

    #[test]
    fn process_ipv6_routes_to_bound_socket() {
        let mut buf = build_ipv6_udp_frame(REMOTE_IPV6, LOCAL_IPV6, 12345, 53, b"hello");

        let mut handler = UdpHandler::new(256);
        let rx_queue = handler.bind(IpAddress::V6(LOCAL_IPV6), 53, 128).unwrap();

        let len = buf.len();
        let frame = Frame::new(0, &mut buf, len, false);
        let mut rx = BasicFrameBuffer::new(4);

        let udp_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        handler.process_ipv6(frame, None, udp_offset, &mut rx);

        assert_eq!(rx.num_frames(), 0);
        assert_eq!(rx_queue.len(), 1);
    }

    #[test]
    fn process_ipv6_no_bound_socket_returns_frames() {
        let mut buf = build_ipv6_udp_frame(REMOTE_IPV6, LOCAL_IPV6, 12345, 53, b"hello");

        let mut handler = UdpHandler::new(256);

        let len = buf.len();
        let frame = Frame::new(0, &mut buf, len, false);
        let mut rx = BasicFrameBuffer::new(4);

        let udp_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        handler.process_ipv6(frame, None, udp_offset, &mut rx);

        assert_eq!(rx.num_frames(), 1);
    }

    #[test]
    fn rx_queue_receives_routed_packet() {
        let mut buf = build_ipv4_udp_frame(REMOTE_IPV4, LOCAL_IPV4, 12345, 53, b"hello");

        let mut handler = UdpHandler::new(256);
        let rx_queue = handler.bind(IpAddress::V4(LOCAL_IPV4), 53, 128).unwrap();

        let len = buf.len();
        let frame = Frame::new(0, &mut buf, len, false);
        let mut rx = BasicFrameBuffer::new(4);
        handler.process_ipv4(frame, &mut rx);

        assert_eq!(rx_queue.len(), 1);
        let pkt = rx_queue.pop().unwrap();
        assert_eq!(pkt.src_addr, IpAddress::V4(REMOTE_IPV4));
        assert_eq!(pkt.dst_addr, IpAddress::V4(LOCAL_IPV4));
        assert_eq!(pkt.src_port, 12345);
        assert_eq!(pkt.dst_port, 53);
        assert!(rx_queue.is_empty());
        assert!(rx_queue.pop().is_none());
    }

    #[test]
    fn evict_stale_delegates_correctly() {
        let mut handler = UdpHandler::new(256);
        let mut rx = BasicFrameBuffer::new(4);

        handler.evict_stale(Duration::from_secs(30), &mut rx);
        assert_eq!(handler.pending_reassembly(), 0);
    }
}
