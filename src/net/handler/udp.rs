use std::fmt;

use coarsetime::{Duration, Instant};

use crate::net::checksum::{
    fold_and_verify, pseudo_header_sum_v4, pseudo_header_sum_v6, sum_words_carry,
    verify_udp_checksum, verify_udp_checksum_v6,
};
use crate::net::fragment::{FragmentReader, Packet};
use crate::net::socket::LocalQueue;
use crate::net::wire::ethernet::EthernetFrame;
use crate::net::wire::ip::{
    EXT_FRAGMENT, FRAGMENT_EXT_LEN, IPV6_HEADER_LEN, IpAddress, Ipv4Header, Ipv6Header,
};
use crate::net::wire::udp::{UDP_HEADER_LEN, UdpHeader};
use crate::xdp::frame::{Frame, FrameBuffer};

/// A completed received UDP packet, ready for delivery to user space.
#[derive(Debug)]
pub struct ReceivedUdpPacket<'umem> {
    pub src_addr: IpAddress,
    pub dst_addr: IpAddress,
    pub src_port: u16,
    pub dst_port: u16,
    pub packet: Packet<'umem>,
}

impl<'umem> ReceivedUdpPacket<'umem> {
    /// Swap source and destination addresses in-place (Ethernet MACs, IP
    /// addresses, UDP ports) so the packet can be echoed back to the sender.
    ///
    /// This performs zero-copy in-place mutations on the frame bytes. Checksums
    /// do not need recalculation because swapping src↔dst produces the same
    /// one's-complement sum (addition is commutative).
    pub fn swap_addresses(&mut self) {
        let is_ipv4 = matches!(self.src_addr, IpAddress::V4(_));
        let mut first = true;

        for frame in self.packet.frames_mut() {
            // Swap Ethernet MACs.
            {
                let eth = EthernetFrame::from_bytes_mut(frame);
                std::mem::swap(&mut eth.src_mac, &mut eth.dst_mac);
            }

            // Swap IP addresses.
            if is_ipv4 {
                let ip = Ipv4Header::from_bytes_mut(frame);
                std::mem::swap(&mut ip.src_addr, &mut ip.dst_addr);
            } else {
                let ip = Ipv6Header::from_bytes_mut(frame);
                std::mem::swap(&mut ip.src_addr, &mut ip.dst_addr);
            }

            // Swap UDP ports on the first frame only.
            if first {
                first = false;
                let udp_offset = if is_ipv4 {
                    Ipv4Header::from_bytes(frame).payload_offset()
                } else {
                    let next_header = Ipv6Header::from_bytes(frame).next_header;
                    let base = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;
                    if next_header == EXT_FRAGMENT {
                        base + FRAGMENT_EXT_LEN
                    } else {
                        base
                    }
                };
                let udp = unsafe { UdpHeader::from_bytes_at_mut(frame, udp_offset) };
                std::mem::swap(&mut udp.src_port, &mut udp.dst_port);
            }
        }

        // Swap metadata fields.
        std::mem::swap(&mut self.src_addr, &mut self.dst_addr);
        std::mem::swap(&mut self.src_port, &mut self.dst_port);
    }
}

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
    rx_queue: LocalQueue<ReceivedUdpPacket<'umem>>,
}

/// Groups bindings for a single port: explicit IP bindings and an optional wildcard.
struct PortBindings<'umem> {
    explicit: Vec<(IpAddress, UdpBinding<'umem>)>,
    wildcard: Option<UdpBinding<'umem>>,
}

/// Manages bound UDP sockets and routes reassembled packets to them.
///
/// Wraps [`FragmentReader`] for fragment reassembly and dispatches completed
/// packets to the matching socket's receive queue. Called from IPv4/IPv6
/// handlers instead of `FragmentReader` directly.
pub struct UdpHandler<'umem> {
    fragment_reader: FragmentReader<'umem>,
    bindings: Vec<(u16, PortBindings<'umem>)>,
    rx_offload: bool,
}

impl<'umem> UdpHandler<'umem> {
    pub fn new(max_reassembly_entries: usize, rx_offload: bool) -> Self {
        Self {
            fragment_reader: FragmentReader::new(max_reassembly_entries),
            bindings: Vec::new(),
            rx_offload,
        }
    }

    /// Bind a new socket to (addr, port).
    ///
    /// If `addr` is the unspecified address (`0.0.0.0` / `::`), the binding
    /// acts as a wildcard: packets that match the port but have no explicit IP
    /// binding will be delivered here. Only one wildcard per port is allowed.
    ///
    /// Returns the shared receive queue so the caller can build a
    /// user-facing `UdpSocket` that shares the same queue.
    pub fn bind(
        &mut self,
        addr: IpAddress,
        port: u16,
        rx_capacity: usize,
    ) -> Result<LocalQueue<ReceivedUdpPacket<'umem>>, BindError> {
        let rx_queue = LocalQueue::new(rx_capacity);
        let binding = UdpBinding {
            rx_queue: rx_queue.clone(),
        };

        if let Some((_, pb)) = self.bindings.iter_mut().find(|(p, _)| *p == port) {
            if addr.is_unspecified() {
                if pb.wildcard.is_some() {
                    return Err(BindError::AddressInUse);
                }
                pb.wildcard = Some(binding);
            } else {
                if pb.explicit.iter().any(|(a, _)| *a == addr) {
                    return Err(BindError::AddressInUse);
                }
                pb.explicit.push((addr, binding));
            }
        } else {
            let mut pb = PortBindings {
                explicit: Vec::new(),
                wildcard: None,
            };
            if addr.is_unspecified() {
                pb.wildcard = Some(binding);
            } else {
                pb.explicit.push((addr, binding));
            }
            self.bindings.push((port, pb));
        }

        Ok(rx_queue)
    }

    /// Unbind a previously bound socket from (addr, port).
    ///
    /// If `addr` is the unspecified address, removes the wildcard binding for that port.
    /// Otherwise removes the matching explicit IP binding. Cleans up the port entry
    /// entirely if no bindings remain.
    pub fn unbind(&mut self, addr: IpAddress, port: u16) {
        if let Some((_, pb)) = self.bindings.iter_mut().find(|(p, _)| *p == port) {
            if addr.is_unspecified() {
                pb.wildcard = None;
            } else {
                pb.explicit.retain(|(a, _)| *a != addr);
            }
        }
        self.bindings
            .retain(|(_, pb)| !pb.explicit.is_empty() || pb.wildcard.is_some());
    }

    /// Called by `Ipv4Handler` for UDP frames/fragments.
    pub fn process_ipv4(&mut self, frame: Frame<'umem>, rx_return: &mut impl FrameBuffer<'umem>) {
        if let Some(reassembled) = self.fragment_reader.process_ipv4(frame, rx_return) {
            let (src_addr, dst_addr, src_port, dst_port, valid) = {
                let first = match &reassembled.packet {
                    Packet::Single(f) => f,
                    Packet::Multi(fs) => &fs[0],
                    Packet::Empty => return,
                };
                let ip = Ipv4Header::from_bytes(first);
                let udp_offset = ip.payload_offset();
                if first.len() < udp_offset + UDP_HEADER_LEN {
                    reassembled.packet.drain_to(rx_return);
                    return;
                }
                let udp = unsafe { UdpHeader::from_bytes_at(first, udp_offset) };
                let udp_len = udp.length() as usize;
                if udp_len < UDP_HEADER_LEN {
                    reassembled.packet.drain_to(rx_return);
                    return;
                }

                let valid = if self.rx_offload {
                    true
                } else {
                    match &reassembled.packet {
                        Packet::Single(f) => {
                            let available = f.len() - udp_offset;
                            if available < udp_len {
                                false
                            } else {
                                verify_udp_checksum(
                                    &ip.src_addr,
                                    &ip.dst_addr,
                                    &f[udp_offset..udp_offset + udp_len],
                                )
                            }
                        }
                        Packet::Multi(fs) => {
                            // Zero checksum means "no checksum" for IPv4.
                            if fs[0][udp_offset + 6] == 0 && fs[0][udp_offset + 7] == 0 {
                                true
                            } else {
                                let mut sum: u64 = 0;
                                let mut pending: Option<u8> = None;
                                let mut total: usize = 0;

                                let slice = &fs[0][udp_offset..];
                                total += slice.len();
                                (sum, pending) = sum_words_carry(slice, sum, pending);

                                for f in &fs[1..] {
                                    let fip = Ipv4Header::from_bytes(f);
                                    let slice = &f[fip.payload_offset()..];
                                    total += slice.len();
                                    (sum, pending) = sum_words_carry(slice, sum, pending);
                                }

                                if let Some(hi) = pending {
                                    sum += (hi as u64) << 8;
                                }

                                if total < udp_len {
                                    false
                                } else {
                                    sum += pseudo_header_sum_v4(
                                        &ip.src_addr,
                                        &ip.dst_addr,
                                        17, // UDP
                                        total as u16,
                                    );
                                    fold_and_verify(sum, 0x0000)
                                }
                            }
                        }
                        Packet::Empty => return,
                    }
                };

                (
                    IpAddress::V4(ip.src_addr),
                    IpAddress::V4(ip.dst_addr),
                    udp.src_port(),
                    udp.dst_port(),
                    valid,
                )
            };
            if !valid {
                reassembled.packet.drain_to(rx_return);
                return;
            }
            self.route(
                ReceivedUdpPacket {
                    src_addr,
                    dst_addr,
                    src_port,
                    dst_port,
                    packet: reassembled.packet,
                },
                rx_return,
            );
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
        match frag_ext_offset {
            None => {
                // Non-fragmented UDP — hot path.
                let ip = Ipv6Header::from_bytes(&frame);
                let src_addr = ip.src_addr;
                let dst_addr = ip.dst_addr;

                if frame.len() < udp_offset + UDP_HEADER_LEN {
                    rx_return.push(frame);
                    return;
                }
                let udp = unsafe { UdpHeader::from_bytes_at(&frame, udp_offset) };
                let udp_len = udp.length() as usize;
                if udp_len < UDP_HEADER_LEN || frame.len() < udp_offset + udp_len {
                    rx_return.push(frame);
                    return;
                }
                if !self.rx_offload
                    && !verify_udp_checksum_v6(
                        &src_addr,
                        &dst_addr,
                        &frame[udp_offset..udp_offset + udp_len],
                    )
                {
                    rx_return.push(frame);
                    return;
                }
                let src_port = udp.src_port();
                let dst_port = udp.dst_port();
                self.route(
                    ReceivedUdpPacket {
                        src_addr: IpAddress::V6(src_addr),
                        dst_addr: IpAddress::V6(dst_addr),
                        src_port,
                        dst_port,
                        packet: Packet::Single(frame),
                    },
                    rx_return,
                );
            }
            Some(frag_off) => {
                if frame.len() < frag_off + FRAGMENT_EXT_LEN {
                    rx_return.push(frame);
                    return;
                }

                if let Some(reassembled) = self
                    .fragment_reader
                    .process_ipv6(frame, frag_off, rx_return)
                {
                    let (src_addr, dst_addr, src_port, dst_port, valid) = {
                        let first = match &reassembled.packet {
                            Packet::Single(f) => f,
                            Packet::Multi(fs) => &fs[0],
                            Packet::Empty => return,
                        };
                        let ip = Ipv6Header::from_bytes(first);
                        let udp_start = frag_off + FRAGMENT_EXT_LEN;
                        if first.len() < udp_start + UDP_HEADER_LEN {
                            reassembled.packet.drain_to(rx_return);
                            return;
                        }
                        let udp = unsafe { UdpHeader::from_bytes_at(first, udp_start) };
                        let udp_len = udp.length() as usize;
                        if udp_len < UDP_HEADER_LEN {
                            reassembled.packet.drain_to(rx_return);
                            return;
                        }

                        let valid = if self.rx_offload {
                            true
                        } else {
                            match &reassembled.packet {
                                Packet::Single(f) => {
                                    let available = f.len() - udp_start;
                                    if available < udp_len {
                                        false
                                    } else {
                                        verify_udp_checksum_v6(
                                            &ip.src_addr,
                                            &ip.dst_addr,
                                            &f[udp_start..udp_start + udp_len],
                                        )
                                    }
                                }
                                Packet::Multi(fs) => {
                                    let data_start = frag_off + FRAGMENT_EXT_LEN;
                                    // IPv6 does not allow zero checksum.
                                    if fs[0][data_start + 6] == 0 && fs[0][data_start + 7] == 0 {
                                        false
                                    } else {
                                        let mut sum: u64 = 0;
                                        let mut pending: Option<u8> = None;
                                        let mut total: usize = 0;

                                        let slice = &fs[0][data_start..];
                                        total += slice.len();
                                        (sum, pending) = sum_words_carry(slice, sum, pending);

                                        for f in &fs[1..] {
                                            let slice = &f[data_start..];
                                            total += slice.len();
                                            (sum, pending) = sum_words_carry(slice, sum, pending);
                                        }

                                        if let Some(hi) = pending {
                                            sum += (hi as u64) << 8;
                                        }

                                        if total < udp_len {
                                            false
                                        } else {
                                            sum += pseudo_header_sum_v6(
                                                &ip.src_addr,
                                                &ip.dst_addr,
                                                17, // UDP
                                                total as u32,
                                            );
                                            fold_and_verify(sum, 0x0000)
                                        }
                                    }
                                }
                                Packet::Empty => return,
                            }
                        };

                        (
                            IpAddress::V6(ip.src_addr),
                            IpAddress::V6(ip.dst_addr),
                            udp.src_port(),
                            udp.dst_port(),
                            valid,
                        )
                    };
                    if !valid {
                        reassembled.packet.drain_to(rx_return);
                        return;
                    }
                    self.route(
                        ReceivedUdpPacket {
                            src_addr,
                            dst_addr,
                            src_port,
                            dst_port,
                            packet: reassembled.packet,
                        },
                        rx_return,
                    );
                }
            }
        }
    }

    /// Evict stale reassembly entries (delegates to `FragmentReader`).
    pub fn evict_stale(
        &mut self,
        now: Instant,
        timeout: Duration,
        rx_return: &mut impl FrameBuffer<'umem>,
    ) {
        self.fragment_reader.evict_stale(now, timeout, rx_return);
    }

    /// Number of in-progress reassembly entries.
    pub fn pending_reassembly(&self) -> usize {
        self.fragment_reader.pending_entries()
    }

    fn route(
        &mut self,
        received: ReceivedUdpPacket<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let port = received.dst_port;
        let addr = received.dst_addr;

        if let Some((_, pb)) = self.bindings.iter().find(|(p, _)| *p == port) {
            // Try explicit match first.
            if let Some((_, binding)) = pb.explicit.iter().find(|(a, _)| *a == addr) {
                if let Some(evicted) = binding.rx_queue.push(received) {
                    evicted.packet.drain_to(rx_return);
                }
                return;
            }
            // Fall back to wildcard.
            if let Some(binding) = &pb.wildcard {
                if let Some(evicted) = binding.rx_queue.push(received) {
                    evicted.packet.drain_to(rx_return);
                }
                return;
            }
        }
        // No match — return frames to kernel.
        received.packet.drain_to(rx_return);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::checksum::{
        compute_ipv4_checksum, compute_udp_checksum, compute_udp_checksum_v6,
    };
    use crate::net::wire::ip::{
        IPV4_MIN_HEADER_LEN, IPV6_HEADER_LEN, IpAddress, Ipv4Address, Ipv6Address,
    };
    use crate::net::wire::udp::UDP_HEADER_LEN;
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
        // checksum bytes [6..8] are zero; fill payload first, then compute
        buf[udp_off + UDP_HEADER_LEN..].copy_from_slice(payload);

        let cksum = compute_udp_checksum(&src_ip, &dst_ip, &buf[udp_off..]);
        buf[udp_off + 6] = cksum[0];
        buf[udp_off + 7] = cksum[1];

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
        // checksum bytes [6..8] are zero; fill payload first, then compute
        buf[udp_off + UDP_HEADER_LEN..].copy_from_slice(payload);

        let cksum = compute_udp_checksum_v6(&src_ip, &dst_ip, &buf[udp_off..]);
        buf[udp_off + 6] = cksum[0];
        buf[udp_off + 7] = cksum[1];

        buf
    }

    #[test]
    fn bind_returns_shared_queues() {
        let mut handler = UdpHandler::new(256, false);
        let rx_queue = handler.bind(IpAddress::V4(LOCAL_IPV4), 5000, 128).unwrap();
        assert!(rx_queue.is_empty());
    }

    #[test]
    fn duplicate_bind_returns_address_in_use() {
        let mut handler = UdpHandler::new(256, false);
        handler.bind(IpAddress::V4(LOCAL_IPV4), 5000, 128).unwrap();
        let err = handler
            .bind(IpAddress::V4(LOCAL_IPV4), 5000, 128)
            .unwrap_err();
        assert_eq!(err, BindError::AddressInUse);
    }

    #[test]
    fn process_ipv4_routes_to_bound_socket() {
        let mut buf = build_ipv4_udp_frame(REMOTE_IPV4, LOCAL_IPV4, 12345, 53, b"hello");

        let mut handler = UdpHandler::new(256, false);
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

        let mut handler = UdpHandler::new(256, false);

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

        let mut handler = UdpHandler::new(256, false);
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

        let mut handler = UdpHandler::new(256, false);
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

        let mut handler = UdpHandler::new(256, false);

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

        let mut handler = UdpHandler::new(256, false);
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
        let mut handler = UdpHandler::new(256, false);
        let mut rx = BasicFrameBuffer::new(4);

        handler.evict_stale(Instant::now(), Duration::from_secs(30), &mut rx);
        assert_eq!(handler.pending_reassembly(), 0);
    }

    #[test]
    fn wildcard_bind_receives_packets() {
        let mut buf = build_ipv4_udp_frame(REMOTE_IPV4, LOCAL_IPV4, 12345, 53, b"hello");

        let mut handler = UdpHandler::new(256, false);
        let rx_queue = handler
            .bind(IpAddress::V4(Ipv4Address::unspecified()), 53, 128)
            .unwrap();

        let len = buf.len();
        let frame = Frame::new(0, &mut buf, len, false);
        let mut rx = BasicFrameBuffer::new(4);

        handler.process_ipv4(frame, &mut rx);

        assert_eq!(rx.num_frames(), 0);
        assert_eq!(rx_queue.len(), 1);
    }

    #[test]
    fn explicit_bind_takes_priority_over_wildcard() {
        let mut buf = build_ipv4_udp_frame(REMOTE_IPV4, LOCAL_IPV4, 12345, 53, b"hello");

        let mut handler = UdpHandler::new(256, false);
        let wildcard_q = handler
            .bind(IpAddress::V4(Ipv4Address::unspecified()), 53, 128)
            .unwrap();
        let explicit_q = handler.bind(IpAddress::V4(LOCAL_IPV4), 53, 128).unwrap();

        let len = buf.len();
        let frame = Frame::new(0, &mut buf, len, false);
        let mut rx = BasicFrameBuffer::new(4);

        handler.process_ipv4(frame, &mut rx);

        assert_eq!(explicit_q.len(), 1);
        assert_eq!(wildcard_q.len(), 0);
    }

    #[test]
    fn wildcard_receives_when_no_explicit_match() {
        // Packet destined for LOCAL_IPV4, but only a different explicit IP is bound.
        let other_ip = Ipv4Address::new([10, 0, 0, 99]);
        let mut buf = build_ipv4_udp_frame(REMOTE_IPV4, LOCAL_IPV4, 12345, 53, b"hello");

        let mut handler = UdpHandler::new(256, false);
        let wildcard_q = handler
            .bind(IpAddress::V4(Ipv4Address::unspecified()), 53, 128)
            .unwrap();
        let explicit_q = handler.bind(IpAddress::V4(other_ip), 53, 128).unwrap();

        let len = buf.len();
        let frame = Frame::new(0, &mut buf, len, false);
        let mut rx = BasicFrameBuffer::new(4);

        handler.process_ipv4(frame, &mut rx);

        assert_eq!(wildcard_q.len(), 1);
        assert_eq!(explicit_q.len(), 0);
    }

    #[test]
    fn duplicate_wildcard_bind_returns_address_in_use() {
        let mut handler = UdpHandler::new(256, false);
        handler
            .bind(IpAddress::V4(Ipv4Address::unspecified()), 53, 128)
            .unwrap();
        let err = handler
            .bind(IpAddress::V4(Ipv4Address::unspecified()), 53, 128)
            .unwrap_err();
        assert_eq!(err, BindError::AddressInUse);
    }

    // -- Checksum & length validation tests --

    #[test]
    fn process_ipv4_rejects_bad_udp_checksum() {
        let mut buf = build_ipv4_udp_frame(REMOTE_IPV4, LOCAL_IPV4, 12345, 53, b"hello");
        // Corrupt the UDP checksum byte
        let udp_off = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        buf[udp_off + 6] ^= 0xFF;

        let mut handler = UdpHandler::new(256, false);
        let rx_queue = handler.bind(IpAddress::V4(LOCAL_IPV4), 53, 128).unwrap();

        let len = buf.len();
        let frame = Frame::new(0, &mut buf, len, false);
        let mut rx = BasicFrameBuffer::new(4);

        handler.process_ipv4(frame, &mut rx);

        assert_eq!(rx_queue.len(), 0, "bad checksum should not be delivered");
        assert_eq!(rx.num_frames(), 1, "frame should be returned");
    }

    #[test]
    fn process_ipv4_accepts_zero_checksum() {
        let mut buf = build_ipv4_udp_frame(REMOTE_IPV4, LOCAL_IPV4, 12345, 53, b"hello");
        // Set checksum to zero (valid for IPv4 — means "no checksum")
        let udp_off = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        buf[udp_off + 6] = 0;
        buf[udp_off + 7] = 0;

        let mut handler = UdpHandler::new(256, false);
        let rx_queue = handler.bind(IpAddress::V4(LOCAL_IPV4), 53, 128).unwrap();

        let len = buf.len();
        let frame = Frame::new(0, &mut buf, len, false);
        let mut rx = BasicFrameBuffer::new(4);

        handler.process_ipv4(frame, &mut rx);

        assert_eq!(
            rx_queue.len(),
            1,
            "zero checksum should be accepted for IPv4"
        );
        assert_eq!(rx.num_frames(), 0);
    }

    #[test]
    fn process_ipv6_rejects_zero_checksum() {
        let mut buf = build_ipv6_udp_frame(REMOTE_IPV6, LOCAL_IPV6, 12345, 53, b"hello");
        // Set checksum to zero (INVALID for IPv6)
        let udp_off = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        buf[udp_off + 6] = 0;
        buf[udp_off + 7] = 0;

        let mut handler = UdpHandler::new(256, false);
        let rx_queue = handler.bind(IpAddress::V6(LOCAL_IPV6), 53, 128).unwrap();

        let len = buf.len();
        let frame = Frame::new(0, &mut buf, len, false);
        let mut rx = BasicFrameBuffer::new(4);

        let udp_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        handler.process_ipv6(frame, None, udp_offset, &mut rx);

        assert_eq!(
            rx_queue.len(),
            0,
            "zero checksum should be rejected for IPv6"
        );
        assert_eq!(rx.num_frames(), 1, "frame should be returned");
    }

    #[test]
    fn process_ipv6_rejects_bad_udp_checksum() {
        let mut buf = build_ipv6_udp_frame(REMOTE_IPV6, LOCAL_IPV6, 12345, 53, b"hello");
        // Corrupt the UDP checksum byte
        let udp_off = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        buf[udp_off + 6] ^= 0xFF;

        let mut handler = UdpHandler::new(256, false);
        let rx_queue = handler.bind(IpAddress::V6(LOCAL_IPV6), 53, 128).unwrap();

        let len = buf.len();
        let frame = Frame::new(0, &mut buf, len, false);
        let mut rx = BasicFrameBuffer::new(4);

        let udp_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        handler.process_ipv6(frame, None, udp_offset, &mut rx);

        assert_eq!(rx_queue.len(), 0, "bad checksum should not be delivered");
        assert_eq!(rx.num_frames(), 1, "frame should be returned");
    }

    #[test]
    fn process_ipv4_rejects_udp_length_too_small() {
        let mut buf = build_ipv4_udp_frame(REMOTE_IPV4, LOCAL_IPV4, 12345, 53, b"hello");
        // Set UDP length to 4 (< 8 minimum)
        let udp_off = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        buf[udp_off + 4] = 0;
        buf[udp_off + 5] = 4;

        let mut handler = UdpHandler::new(256, false);
        let rx_queue = handler.bind(IpAddress::V4(LOCAL_IPV4), 53, 128).unwrap();

        let len = buf.len();
        let frame = Frame::new(0, &mut buf, len, false);
        let mut rx = BasicFrameBuffer::new(4);

        handler.process_ipv4(frame, &mut rx);

        assert_eq!(rx_queue.len(), 0, "short UDP length should be rejected");
        assert_eq!(rx.num_frames(), 1, "frame should be returned");
    }

    #[test]
    fn process_ipv4_rejects_udp_length_exceeds_frame() {
        let mut buf = build_ipv4_udp_frame(REMOTE_IPV4, LOCAL_IPV4, 12345, 53, b"hi");
        // Set UDP length to 100 (much larger than actual data)
        let udp_off = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        buf[udp_off + 4] = 0;
        buf[udp_off + 5] = 100;

        let mut handler = UdpHandler::new(256, false);
        let rx_queue = handler.bind(IpAddress::V4(LOCAL_IPV4), 53, 128).unwrap();

        let len = buf.len();
        let frame = Frame::new(0, &mut buf, len, false);
        let mut rx = BasicFrameBuffer::new(4);

        handler.process_ipv4(frame, &mut rx);

        assert_eq!(rx_queue.len(), 0, "oversized UDP length should be rejected");
        assert_eq!(rx.num_frames(), 1, "frame should be returned");
    }

    // -- swap_addresses tests --

    #[test]
    fn swap_addresses_ipv4() {
        let src_mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let dst_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        let mut buf = build_ipv4_udp_frame(REMOTE_IPV4, LOCAL_IPV4, 12345, 53, b"hello");
        // Set MAC addresses in the Ethernet header.
        buf[0..6].copy_from_slice(&dst_mac);
        buf[6..12].copy_from_slice(&src_mac);

        let len = buf.len();
        let frame = Frame::new(0, &mut buf, len, false);

        let mut pkt = ReceivedUdpPacket {
            src_addr: IpAddress::V4(REMOTE_IPV4),
            dst_addr: IpAddress::V4(LOCAL_IPV4),
            src_port: 12345,
            dst_port: 53,
            packet: Packet::Single(frame),
        };

        pkt.swap_addresses();

        // Metadata should be swapped.
        assert_eq!(pkt.src_addr, IpAddress::V4(LOCAL_IPV4));
        assert_eq!(pkt.dst_addr, IpAddress::V4(REMOTE_IPV4));
        assert_eq!(pkt.src_port, 53);
        assert_eq!(pkt.dst_port, 12345);

        // Verify wire bytes.
        let frame = match &pkt.packet {
            Packet::Single(f) => f,
            _ => panic!("expected Single"),
        };

        // Ethernet MACs swapped.
        assert_eq!(&frame[0..6], &src_mac);
        assert_eq!(&frame[6..12], &dst_mac);

        // IPv4 addresses swapped.
        let ip = Ipv4Header::from_bytes(frame);
        assert_eq!(ip.src_addr, LOCAL_IPV4);
        assert_eq!(ip.dst_addr, REMOTE_IPV4);

        // UDP ports swapped.
        let udp_off = ip.payload_offset();
        let udp = unsafe { UdpHeader::from_bytes_at(frame, udp_off) };
        assert_eq!(udp.src_port(), 53);
        assert_eq!(udp.dst_port(), 12345);
    }

    #[test]
    fn swap_addresses_ipv6() {
        let src_mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let dst_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        let mut buf = build_ipv6_udp_frame(REMOTE_IPV6, LOCAL_IPV6, 12345, 53, b"hello");
        // Set MAC addresses in the Ethernet header.
        buf[0..6].copy_from_slice(&dst_mac);
        buf[6..12].copy_from_slice(&src_mac);

        let len = buf.len();
        let frame = Frame::new(0, &mut buf, len, false);

        let mut pkt = ReceivedUdpPacket {
            src_addr: IpAddress::V6(REMOTE_IPV6),
            dst_addr: IpAddress::V6(LOCAL_IPV6),
            src_port: 12345,
            dst_port: 53,
            packet: Packet::Single(frame),
        };

        pkt.swap_addresses();

        // Metadata should be swapped.
        assert_eq!(pkt.src_addr, IpAddress::V6(LOCAL_IPV6));
        assert_eq!(pkt.dst_addr, IpAddress::V6(REMOTE_IPV6));
        assert_eq!(pkt.src_port, 53);
        assert_eq!(pkt.dst_port, 12345);

        // Verify wire bytes.
        let frame = match &pkt.packet {
            Packet::Single(f) => f,
            _ => panic!("expected Single"),
        };

        // Ethernet MACs swapped.
        assert_eq!(&frame[0..6], &src_mac);
        assert_eq!(&frame[6..12], &dst_mac);

        // IPv6 addresses swapped.
        let ip = Ipv6Header::from_bytes(frame);
        assert_eq!(ip.src_addr, LOCAL_IPV6);
        assert_eq!(ip.dst_addr, REMOTE_IPV6);

        // UDP ports swapped.
        let udp_off = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        let udp = unsafe { UdpHeader::from_bytes_at(frame, udp_off) };
        assert_eq!(udp.src_port(), 53);
        assert_eq!(udp.dst_port(), 12345);
    }

    // -- unbind tests --

    #[test]
    fn unbind_explicit_removes_binding() {
        let mut handler = UdpHandler::new(256, false);
        handler.bind(IpAddress::V4(LOCAL_IPV4), 5000, 128).unwrap();

        handler.unbind(IpAddress::V4(LOCAL_IPV4), 5000);

        // Should be able to re-bind the same address.
        handler.bind(IpAddress::V4(LOCAL_IPV4), 5000, 128).unwrap();
    }

    #[test]
    fn unbind_wildcard_removes_binding() {
        let mut handler = UdpHandler::new(256, false);
        handler
            .bind(IpAddress::V4(Ipv4Address::unspecified()), 5000, 128)
            .unwrap();

        handler.unbind(IpAddress::V4(Ipv4Address::unspecified()), 5000);

        // Should be able to re-bind wildcard.
        handler
            .bind(IpAddress::V4(Ipv4Address::unspecified()), 5000, 128)
            .unwrap();
    }

    #[test]
    fn unbind_cleans_up_empty_port_entry() {
        let mut handler = UdpHandler::new(256, false);
        handler.bind(IpAddress::V4(LOCAL_IPV4), 5000, 128).unwrap();

        handler.unbind(IpAddress::V4(LOCAL_IPV4), 5000);

        // Port entry should be removed — no routing should happen.
        let mut buf = build_ipv4_udp_frame(REMOTE_IPV4, LOCAL_IPV4, 12345, 5000, b"hello");
        let len = buf.len();
        let frame = Frame::new(0, &mut buf, len, false);
        let mut rx = BasicFrameBuffer::new(4);
        handler.process_ipv4(frame, &mut rx);
        assert_eq!(rx.num_frames(), 1, "packet should be returned, not routed");
    }

    #[test]
    fn unbind_preserves_other_bindings_on_same_port() {
        let other_ip = Ipv4Address::new([10, 0, 0, 99]);
        let mut handler = UdpHandler::new(256, false);
        handler.bind(IpAddress::V4(LOCAL_IPV4), 5000, 128).unwrap();
        let other_q = handler.bind(IpAddress::V4(other_ip), 5000, 128).unwrap();

        // Unbind only LOCAL_IPV4.
        handler.unbind(IpAddress::V4(LOCAL_IPV4), 5000);

        // other_ip binding should still work.
        let mut buf = build_ipv4_udp_frame(REMOTE_IPV4, other_ip, 12345, 5000, b"hello");
        let len = buf.len();
        let frame = Frame::new(0, &mut buf, len, false);
        let mut rx = BasicFrameBuffer::new(4);
        handler.process_ipv4(frame, &mut rx);
        assert_eq!(other_q.len(), 1);
    }

    #[test]
    fn unbind_nonexistent_is_noop() {
        let mut handler = UdpHandler::new(256, false);
        // Should not panic.
        handler.unbind(IpAddress::V4(LOCAL_IPV4), 5000);
    }
}
