use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::mem::size_of;
use std::time::Duration;

use super::ip::{IpAddress, Ipv4Address, Ipv6Address};
use super::packet::{PacketReader, ReceivedPacket};
use crate::xdp::frame::{Frame, FrameBuffer};

/// UDP header length in bytes.
pub const UDP_HEADER_LEN: usize = 8;

/// Compile-time guarantee that our struct matches the wire size.
const _: () = assert!(size_of::<UdpHeader>() == UDP_HEADER_LEN);

/// UDP header wire format (8 bytes).
///
/// `#[repr(C, packed)]` allows zero-copy casting from raw frame memory,
/// following the same pattern as [`Ipv4Header`] and [`Icmpv4Header`].
///
/// Multi-byte fields are stored in network byte order as `[u8; 2]` to
/// avoid alignment issues on packed structs. Use the accessor methods
/// for host-order values.
#[repr(C, packed)]
pub struct UdpHeader {
    pub src_port: [u8; 2],
    pub dst_port: [u8; 2],
    pub length: [u8; 2],
    pub checksum: [u8; 2],
}

impl UdpHeader {
    /// Returns the source port in host byte order.
    #[inline]
    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes(self.src_port)
    }

    /// Returns the destination port in host byte order.
    #[inline]
    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes(self.dst_port)
    }

    /// Returns the UDP length (header + payload) in host byte order.
    #[inline]
    pub fn length(&self) -> u16 {
        u16::from_be_bytes(self.length)
    }

    /// Returns the payload length (total length minus header).
    ///
    /// Returns 0 if the length field is less than the header size (malformed).
    #[inline]
    pub fn payload_len(&self) -> usize {
        let total = self.length() as usize;
        if total > UDP_HEADER_LEN {
            total - UDP_HEADER_LEN
        } else {
            0
        }
    }
}

/// Computes the UDP checksum over the IPv4 pseudo-header and full UDP segment.
///
/// Per RFC 768, the checksum covers a pseudo-header (src IP, dst IP,
/// zero, protocol, UDP length) concatenated with the UDP header and data.
///
/// `udp_segment` must contain the full UDP header + payload with the
/// checksum field set to zero.
///
/// Returns the two-byte checksum in network byte order. If the computed
/// checksum is zero, returns `[0xFF, 0xFF]` per RFC 768 (a transmitted
/// checksum of zero means "no checksum").
#[inline]
pub fn compute_udp_checksum(
    src_addr: &Ipv4Address,
    dst_addr: &Ipv4Address,
    udp_segment: &[u8],
) -> [u8; 2] {
    let udp_len = udp_segment.len() as u16;
    let mut sum: u32 = 0;

    // Pseudo-header: src IP (4 bytes)
    sum += ((src_addr.octets[0] as u32) << 8) | (src_addr.octets[1] as u32);
    sum += ((src_addr.octets[2] as u32) << 8) | (src_addr.octets[3] as u32);

    // Pseudo-header: dst IP (4 bytes)
    sum += ((dst_addr.octets[0] as u32) << 8) | (dst_addr.octets[1] as u32);
    sum += ((dst_addr.octets[2] as u32) << 8) | (dst_addr.octets[3] as u32);

    // Pseudo-header: zero + protocol (2 bytes)
    sum += 17u32; // UDP protocol number

    // Pseudo-header: UDP length (2 bytes)
    sum += udp_len as u32;

    // UDP header + data
    let mut i = 0;
    while i + 1 < udp_segment.len() {
        let word = ((udp_segment[i] as u32) << 8) | (udp_segment[i + 1] as u32);
        sum += word;
        i += 2;
    }

    // Pad odd byte
    if i < udp_segment.len() {
        sum += (udp_segment[i] as u32) << 8;
    }

    // Fold carry bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let checksum = !(sum as u16);

    // RFC 768: a computed checksum of zero is transmitted as 0xFFFF.
    if checksum == 0 {
        [0xFF, 0xFF]
    } else {
        checksum.to_be_bytes()
    }
}

/// Verifies the UDP checksum.
///
/// Returns `true` if the checksum field is zero (no checksum, per RFC 768)
/// or if the one's complement sum of the pseudo-header and full UDP segment
/// yields the expected result.
#[inline]
pub fn verify_udp_checksum(
    src_addr: &Ipv4Address,
    dst_addr: &Ipv4Address,
    udp_segment: &[u8],
) -> bool {
    if udp_segment.len() < UDP_HEADER_LEN {
        return false;
    }

    // RFC 768: checksum field of zero means no checksum was computed.
    if udp_segment[6] == 0 && udp_segment[7] == 0 {
        return true;
    }

    // When the checksum is included in the sum, the result should be 0xFFFF
    // (all ones), which after one's complement negation gives 0x0000.
    let udp_len = udp_segment.len() as u16;
    let mut sum: u32 = 0;

    // Pseudo-header
    sum += ((src_addr.octets[0] as u32) << 8) | (src_addr.octets[1] as u32);
    sum += ((src_addr.octets[2] as u32) << 8) | (src_addr.octets[3] as u32);
    sum += ((dst_addr.octets[0] as u32) << 8) | (dst_addr.octets[1] as u32);
    sum += ((dst_addr.octets[2] as u32) << 8) | (dst_addr.octets[3] as u32);
    sum += 17u32;
    sum += udp_len as u32;

    // UDP segment (including checksum field)
    let mut i = 0;
    while i + 1 < udp_segment.len() {
        let word = ((udp_segment[i] as u32) << 8) | (udp_segment[i + 1] as u32);
        sum += word;
        i += 2;
    }

    if i < udp_segment.len() {
        sum += (udp_segment[i] as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    sum == 0xFFFF
}

/// Computes the UDP checksum over the IPv6 pseudo-header and full UDP segment.
///
/// Per RFC 2460 §8.1, the pseudo-header for IPv6 contains:
/// source address (16), destination address (16), UDP length as u32 (4),
/// three zero bytes (3), and next header = 17 (1) — totalling 40 bytes.
///
/// Unlike IPv4, the UDP checksum is **mandatory** for IPv6 — a zero
/// checksum is not permitted on transmit.
///
/// `udp_segment` must contain the full UDP header + payload with the
/// checksum field set to zero.
///
/// Returns the two-byte checksum in network byte order.
#[inline]
pub fn compute_udp_checksum_v6(
    src_addr: &Ipv6Address,
    dst_addr: &Ipv6Address,
    udp_segment: &[u8],
) -> [u8; 2] {
    let udp_len = udp_segment.len() as u32;
    let mut sum: u32 = 0;

    // Pseudo-header: src address (16 bytes)
    let mut i = 0;
    while i < 16 {
        sum += ((src_addr.octets[i] as u32) << 8) | (src_addr.octets[i + 1] as u32);
        i += 2;
    }

    // Pseudo-header: dst address (16 bytes)
    i = 0;
    while i < 16 {
        sum += ((dst_addr.octets[i] as u32) << 8) | (dst_addr.octets[i + 1] as u32);
        i += 2;
    }

    // Pseudo-header: UDP length as u32 (4 bytes)
    sum += (udp_len >> 16) & 0xFFFF;
    sum += udp_len & 0xFFFF;

    // Pseudo-header: zero (3 bytes) + next header = 17 (1 byte)
    sum += 17u32;

    // UDP header + data
    i = 0;
    while i + 1 < udp_segment.len() {
        let word = ((udp_segment[i] as u32) << 8) | (udp_segment[i + 1] as u32);
        sum += word;
        i += 2;
    }

    // Pad odd byte
    if i < udp_segment.len() {
        sum += (udp_segment[i] as u32) << 8;
    }

    // Fold carry bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let checksum = !(sum as u16);

    // IPv6 UDP checksum must never be zero on the wire; 0xFFFF is the
    // one's-complement representation of zero.
    if checksum == 0 {
        [0xFF, 0xFF]
    } else {
        checksum.to_be_bytes()
    }
}

/// Verifies the UDP checksum for an IPv6 packet.
///
/// Returns `true` if the one's complement sum of the pseudo-header and
/// full UDP segment yields the expected result. Unlike IPv4, a zero
/// checksum field is **invalid** for IPv6 and will cause this to return
/// `false`.
#[inline]
pub fn verify_udp_checksum_v6(
    src_addr: &Ipv6Address,
    dst_addr: &Ipv6Address,
    udp_segment: &[u8],
) -> bool {
    if udp_segment.len() < UDP_HEADER_LEN {
        return false;
    }

    // IPv6 does not allow a zero checksum field.
    if udp_segment[6] == 0 && udp_segment[7] == 0 {
        return false;
    }

    let udp_len = udp_segment.len() as u32;
    let mut sum: u32 = 0;

    // Pseudo-header: src address
    let mut i = 0;
    while i < 16 {
        sum += ((src_addr.octets[i] as u32) << 8) | (src_addr.octets[i + 1] as u32);
        i += 2;
    }

    // Pseudo-header: dst address
    i = 0;
    while i < 16 {
        sum += ((dst_addr.octets[i] as u32) << 8) | (dst_addr.octets[i + 1] as u32);
        i += 2;
    }

    // Pseudo-header: UDP length as u32
    sum += (udp_len >> 16) & 0xFFFF;
    sum += udp_len & 0xFFFF;

    // Pseudo-header: next header
    sum += 17u32;

    // UDP segment (including checksum field)
    i = 0;
    while i + 1 < udp_segment.len() {
        let word = ((udp_segment[i] as u32) << 8) | (udp_segment[i + 1] as u32);
        sum += word;
        i += 2;
    }

    if i < udp_segment.len() {
        sum += (udp_segment[i] as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    sum == 0xFFFF
}

// ---------------------------------------------------------------------------
// UdpSocket + UdpHandler: socket binding and packet routing
// ---------------------------------------------------------------------------

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

/// A bound UDP socket that receives packets matching its (addr, port).
pub struct UdpSocket<'umem> {
    id: u32,
    local_addr: IpAddress,
    local_port: u16,
    rx_queue: VecDeque<ReceivedPacket<'umem>>,
    rx_capacity: usize,
}

impl<'umem> UdpSocket<'umem> {
    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn local_addr(&self) -> IpAddress {
        self.local_addr
    }

    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// Pop the next received packet from this socket.
    pub fn recv(&mut self) -> Option<ReceivedPacket<'umem>> {
        self.rx_queue.pop_front()
    }

    /// Number of packets waiting to be read.
    pub fn pending(&self) -> usize {
        self.rx_queue.len()
    }

    pub fn rx_capacity(&self) -> usize {
        self.rx_capacity
    }
}

/// Manages bound UDP sockets and routes reassembled packets to them.
///
/// Wraps [`PacketReader`] for fragment reassembly and dispatches completed
/// packets to the matching socket's receive queue. Called from IPv4/IPv6
/// handlers instead of `PacketReader` directly.
pub struct UdpHandler<'umem> {
    packet_reader: PacketReader<'umem>,
    sockets: Vec<UdpSocket<'umem>>,
    bindings: HashMap<(IpAddress, u16), usize>,
    next_id: u32,
}

impl<'umem> UdpHandler<'umem> {
    pub fn new(max_reassembly_entries: usize) -> Self {
        Self {
            packet_reader: PacketReader::new(max_reassembly_entries),
            sockets: Vec::new(),
            bindings: HashMap::new(),
            next_id: 0,
        }
    }

    /// Bind a new socket to (addr, port). Returns the socket ID.
    pub fn bind(
        &mut self,
        addr: IpAddress,
        port: u16,
        rx_capacity: usize,
    ) -> Result<u32, BindError> {
        let key = (addr, port);
        if self.bindings.contains_key(&key) {
            return Err(BindError::AddressInUse);
        }

        let id = self.next_id;
        self.next_id += 1;

        let idx = self.sockets.len();
        self.sockets.push(UdpSocket {
            id,
            local_addr: addr,
            local_port: port,
            rx_queue: VecDeque::new(),
            rx_capacity,
        });
        self.bindings.insert(key, idx);

        Ok(id)
    }

    /// Called by `Ipv4Handler` for UDP frames/fragments.
    pub fn process_ipv4(
        &mut self,
        frame: Frame<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
    ) {
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

    /// Get a reference to a socket by ID.
    pub fn socket(&self, id: u32) -> Option<&UdpSocket<'umem>> {
        self.sockets.iter().find(|s| s.id == id)
    }

    /// Get a mutable reference to a socket by ID.
    pub fn socket_mut(&mut self, id: u32) -> Option<&mut UdpSocket<'umem>> {
        self.sockets.iter_mut().find(|s| s.id == id)
    }

    /// Evict stale reassembly entries (delegates to `PacketReader`).
    pub fn evict_stale(
        &mut self,
        timeout: Duration,
        rx_return: &mut impl FrameBuffer<'umem>,
    ) {
        self.packet_reader.evict_stale(timeout, rx_return);
    }

    /// Number of in-progress reassembly entries.
    pub fn pending_reassembly(&self) -> usize {
        self.packet_reader.pending_entries()
    }

    fn route(
        &mut self,
        received: ReceivedPacket<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let key = (received.dst_addr, received.dst_port);
        if let Some(&idx) = self.bindings.get(&key) {
            let socket = &mut self.sockets[idx];
            if socket.rx_queue.len() < socket.rx_capacity {
                socket.rx_queue.push_back(received);
            } else {
                // Queue full — return frames to kernel.
                for frame in received.packet.into_frames() {
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

    const SRC_IP: Ipv4Address = Ipv4Address::new([192, 168, 1, 1]);
    const DST_IP: Ipv4Address = Ipv4Address::new([10, 0, 0, 2]);

    const SRC_IPV6: Ipv6Address =
        Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    const DST_IPV6: Ipv6Address =
        Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

    /// Builds a UDP segment (header + payload) with checksum zeroed.
    fn build_udp_segment(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;
        let mut seg = vec![0u8; UDP_HEADER_LEN + payload.len()];
        seg[0..2].copy_from_slice(&src_port.to_be_bytes());
        seg[2..4].copy_from_slice(&dst_port.to_be_bytes());
        seg[4..6].copy_from_slice(&udp_len.to_be_bytes());
        // checksum = 0 (will be filled by compute)
        seg[UDP_HEADER_LEN..].copy_from_slice(payload);
        seg
    }

    #[test]
    fn struct_size() {
        assert_eq!(size_of::<UdpHeader>(), 8);
    }

    #[test]
    fn accessors() {
        let hdr = UdpHeader {
            src_port: 1234u16.to_be_bytes(),
            dst_port: 5678u16.to_be_bytes(),
            length: 28u16.to_be_bytes(),
            checksum: [0, 0],
        };
        assert_eq!(hdr.src_port(), 1234);
        assert_eq!(hdr.dst_port(), 5678);
        assert_eq!(hdr.length(), 28);
        assert_eq!(hdr.payload_len(), 20);
    }

    #[test]
    fn payload_len_malformed() {
        let hdr = UdpHeader {
            src_port: [0, 0],
            dst_port: [0, 0],
            length: 4u16.to_be_bytes(), // less than header
            checksum: [0, 0],
        };
        assert_eq!(hdr.payload_len(), 0);
    }

    #[test]
    fn compute_and_verify_roundtrip() {
        let mut seg = build_udp_segment(12345, 53, b"hello");
        let cksum = compute_udp_checksum(&SRC_IP, &DST_IP, &seg);
        seg[6] = cksum[0];
        seg[7] = cksum[1];

        assert!(verify_udp_checksum(&SRC_IP, &DST_IP, &seg));
    }

    #[test]
    fn corrupted_checksum_fails_verify() {
        let mut seg = build_udp_segment(12345, 53, b"hello");
        let cksum = compute_udp_checksum(&SRC_IP, &DST_IP, &seg);
        seg[6] = cksum[0];
        seg[7] = cksum[1];

        // Corrupt one byte of payload
        seg[UDP_HEADER_LEN] ^= 0xFF;
        assert!(!verify_udp_checksum(&SRC_IP, &DST_IP, &seg));
    }

    #[test]
    fn zero_checksum_field_means_no_checksum() {
        let seg = build_udp_segment(80, 80, b"anything");
        // checksum field is already zero
        assert!(verify_udp_checksum(&SRC_IP, &DST_IP, &seg));
    }

    #[test]
    fn verify_rejects_too_short_segment() {
        let short = [0u8; 4];
        assert!(!verify_udp_checksum(&SRC_IP, &DST_IP, &short));
    }

    #[test]
    fn compute_checksum_never_returns_zero() {
        // RFC 768: transmitted checksum must never be 0x0000.
        // We can't easily force a zero checksum, but we verify the
        // function handles it by checking the contract holds for
        // a variety of inputs.
        for port in [0u16, 1, 255, 1024, 65535] {
            let seg = build_udp_segment(port, port, &[]);
            let cksum = compute_udp_checksum(&SRC_IP, &DST_IP, &seg);
            assert_ne!(cksum, [0x00, 0x00]);
        }
    }

    #[test]
    fn odd_length_payload() {
        // Odd-length payload exercises the padding branch.
        let mut seg = build_udp_segment(1000, 2000, &[0xAB; 13]);
        let cksum = compute_udp_checksum(&SRC_IP, &DST_IP, &seg);
        seg[6] = cksum[0];
        seg[7] = cksum[1];

        assert!(verify_udp_checksum(&SRC_IP, &DST_IP, &seg));
    }

    #[test]
    fn empty_payload() {
        let mut seg = build_udp_segment(5000, 5001, &[]);
        let cksum = compute_udp_checksum(&SRC_IP, &DST_IP, &seg);
        seg[6] = cksum[0];
        seg[7] = cksum[1];

        assert!(verify_udp_checksum(&SRC_IP, &DST_IP, &seg));
    }

    #[test]
    fn different_addresses_produce_different_checksums() {
        let seg = build_udp_segment(1234, 5678, b"test");
        let cksum1 = compute_udp_checksum(&SRC_IP, &DST_IP, &seg);

        let other_dst = Ipv4Address::new([10, 0, 0, 99]);
        let cksum2 = compute_udp_checksum(&SRC_IP, &other_dst, &seg);

        assert_ne!(cksum1, cksum2);
    }

    #[test]
    fn wrong_addresses_fail_verify() {
        let mut seg = build_udp_segment(1234, 5678, b"test");
        let cksum = compute_udp_checksum(&SRC_IP, &DST_IP, &seg);
        seg[6] = cksum[0];
        seg[7] = cksum[1];

        // Verify with wrong source address
        let wrong_src = Ipv4Address::new([172, 16, 0, 1]);
        assert!(!verify_udp_checksum(&wrong_src, &DST_IP, &seg));
    }

    // --- IPv6 checksum tests ---

    #[test]
    fn v6_compute_and_verify_roundtrip() {
        let mut seg = build_udp_segment(12345, 53, b"hello");
        let cksum = compute_udp_checksum_v6(&SRC_IPV6, &DST_IPV6, &seg);
        seg[6] = cksum[0];
        seg[7] = cksum[1];

        assert!(verify_udp_checksum_v6(&SRC_IPV6, &DST_IPV6, &seg));
    }

    #[test]
    fn v6_corrupted_checksum_fails_verify() {
        let mut seg = build_udp_segment(12345, 53, b"hello");
        let cksum = compute_udp_checksum_v6(&SRC_IPV6, &DST_IPV6, &seg);
        seg[6] = cksum[0];
        seg[7] = cksum[1];

        seg[UDP_HEADER_LEN] ^= 0xFF;
        assert!(!verify_udp_checksum_v6(&SRC_IPV6, &DST_IPV6, &seg));
    }

    #[test]
    fn v6_zero_checksum_is_invalid() {
        // IPv6 UDP mandates a checksum; zero field is invalid.
        let seg = build_udp_segment(80, 80, b"anything");
        assert!(!verify_udp_checksum_v6(&SRC_IPV6, &DST_IPV6, &seg));
    }

    #[test]
    fn v6_verify_rejects_too_short_segment() {
        let short = [0u8; 4];
        assert!(!verify_udp_checksum_v6(&SRC_IPV6, &DST_IPV6, &short));
    }

    #[test]
    fn v6_compute_checksum_never_returns_zero() {
        for port in [0u16, 1, 255, 1024, 65535] {
            let seg = build_udp_segment(port, port, &[]);
            let cksum = compute_udp_checksum_v6(&SRC_IPV6, &DST_IPV6, &seg);
            assert_ne!(cksum, [0x00, 0x00]);
        }
    }

    #[test]
    fn v6_odd_length_payload() {
        let mut seg = build_udp_segment(1000, 2000, &[0xAB; 13]);
        let cksum = compute_udp_checksum_v6(&SRC_IPV6, &DST_IPV6, &seg);
        seg[6] = cksum[0];
        seg[7] = cksum[1];

        assert!(verify_udp_checksum_v6(&SRC_IPV6, &DST_IPV6, &seg));
    }

    #[test]
    fn v6_empty_payload() {
        let mut seg = build_udp_segment(5000, 5001, &[]);
        let cksum = compute_udp_checksum_v6(&SRC_IPV6, &DST_IPV6, &seg);
        seg[6] = cksum[0];
        seg[7] = cksum[1];

        assert!(verify_udp_checksum_v6(&SRC_IPV6, &DST_IPV6, &seg));
    }

    #[test]
    fn v6_different_addresses_produce_different_checksums() {
        let seg = build_udp_segment(1234, 5678, b"test");
        let cksum1 = compute_udp_checksum_v6(&SRC_IPV6, &DST_IPV6, &seg);

        let other_dst = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99]);
        let cksum2 = compute_udp_checksum_v6(&SRC_IPV6, &other_dst, &seg);

        assert_ne!(cksum1, cksum2);
    }

    #[test]
    fn v6_wrong_addresses_fail_verify() {
        let mut seg = build_udp_segment(1234, 5678, b"test");
        let cksum = compute_udp_checksum_v6(&SRC_IPV6, &DST_IPV6, &seg);
        seg[6] = cksum[0];
        seg[7] = cksum[1];

        let wrong_src =
            Ipv6Address::new([0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(!verify_udp_checksum_v6(&wrong_src, &DST_IPV6, &seg));
    }

    // --- UdpHandler tests ---

    use crate::net::ip::IpAddress;
    use crate::net::ipv4::{IPV4_MIN_HEADER_LEN, compute_ipv4_checksum};
    use crate::net::ipv6::IPV6_HEADER_LEN;
    use crate::xdp::frame::{BasicFrameBuffer, Frame};

    const HANDLER_LOCAL_IPV4: Ipv4Address = Ipv4Address::new([192, 168, 1, 1]);
    const HANDLER_REMOTE_IPV4: Ipv4Address = Ipv4Address::new([10, 0, 0, 2]);
    const HANDLER_LOCAL_IPV6: Ipv6Address =
        Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    const HANDLER_REMOTE_IPV6: Ipv6Address =
        Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

    const ETH_HEADER_LEN: usize = 14;

    /// Builds a minimal Ethernet + IPv4 + UDP frame for testing.
    fn build_test_ipv4_udp_frame(
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        use crate::net::ip::IpProtocols;
        let total_ip_len = (IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN + payload.len()) as u16;
        let mut buf = vec![0u8; ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN + payload.len()];

        // Ethernet
        buf[12] = 0x08;
        buf[13] = 0x00;

        // IPv4
        let ip = &mut buf[14..];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&total_ip_len.to_be_bytes());
        ip[6] = 0x40; // DF
        ip[7] = 0x00;
        ip[8] = 64; // TTL
        ip[9] = IpProtocols::Udp;
        let src_bytes: [u8; 4] = src_ip.into();
        ip[12..16].copy_from_slice(&src_bytes);
        let dst_bytes: [u8; 4] = dst_ip.into();
        ip[16..20].copy_from_slice(&dst_bytes);
        let cksum = compute_ipv4_checksum(&ip[..20]);
        ip[10] = cksum[0];
        ip[11] = cksum[1];

        // UDP header
        let udp_off = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;
        buf[udp_off..udp_off + 2].copy_from_slice(&src_port.to_be_bytes());
        buf[udp_off + 2..udp_off + 4].copy_from_slice(&dst_port.to_be_bytes());
        buf[udp_off + 4..udp_off + 6].copy_from_slice(&udp_len.to_be_bytes());
        // checksum = 0 (optional for IPv4)

        // Payload
        buf[udp_off + UDP_HEADER_LEN..].copy_from_slice(payload);
        buf
    }

    /// Builds a minimal Ethernet + IPv6 + UDP frame for testing.
    fn build_test_ipv6_udp_frame(
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        use crate::net::ip::IpProtocols;
        let payload_len = (UDP_HEADER_LEN + payload.len()) as u16;
        let mut buf = vec![0u8; ETH_HEADER_LEN + IPV6_HEADER_LEN + UDP_HEADER_LEN + payload.len()];

        // Ethernet
        buf[12] = 0x86;
        buf[13] = 0xDD;

        // IPv6
        let ip = &mut buf[14..];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&payload_len.to_be_bytes());
        ip[6] = IpProtocols::Udp;
        ip[7] = 64;
        let src_bytes: [u8; 16] = src_ip.into();
        ip[8..24].copy_from_slice(&src_bytes);
        let dst_bytes: [u8; 16] = dst_ip.into();
        ip[24..40].copy_from_slice(&dst_bytes);

        // UDP header
        let udp_off = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;
        buf[udp_off..udp_off + 2].copy_from_slice(&src_port.to_be_bytes());
        buf[udp_off + 2..udp_off + 4].copy_from_slice(&dst_port.to_be_bytes());
        buf[udp_off + 4..udp_off + 6].copy_from_slice(&udp_len.to_be_bytes());
        // checksum = 0 (will fail v6 verify but routing doesn't check)

        // Payload
        buf[udp_off + UDP_HEADER_LEN..].copy_from_slice(payload);
        buf
    }

    #[test]
    fn bind_creates_socket() {
        let mut handler = UdpHandler::new(256);
        let id = handler
            .bind(IpAddress::V4(HANDLER_LOCAL_IPV4), 5000, 128)
            .unwrap();
        let sock = handler.socket(id).unwrap();
        assert_eq!(sock.id(), id);
        assert_eq!(sock.local_addr(), IpAddress::V4(HANDLER_LOCAL_IPV4));
        assert_eq!(sock.local_port(), 5000);
        assert_eq!(sock.pending(), 0);
        assert_eq!(sock.rx_capacity(), 128);
    }

    #[test]
    fn duplicate_bind_returns_address_in_use() {
        let mut handler = UdpHandler::new(256);
        handler
            .bind(IpAddress::V4(HANDLER_LOCAL_IPV4), 5000, 128)
            .unwrap();
        let err = handler
            .bind(IpAddress::V4(HANDLER_LOCAL_IPV4), 5000, 128)
            .unwrap_err();
        assert_eq!(err, BindError::AddressInUse);
    }

    #[test]
    fn process_ipv4_routes_to_bound_socket() {
        let mut handler = UdpHandler::new(256);
        let id = handler
            .bind(IpAddress::V4(HANDLER_LOCAL_IPV4), 53, 128)
            .unwrap();

        let mut buf = build_test_ipv4_udp_frame(
            HANDLER_REMOTE_IPV4,
            HANDLER_LOCAL_IPV4,
            12345,
            53,
            b"hello",
        );
        let len = buf.len();
        let frame = Frame::new(0, &mut buf, len, false);
        let mut rx = BasicFrameBuffer::new(4);

        handler.process_ipv4(frame, &mut rx);

        assert_eq!(rx.num_frames(), 0);
        let sock = handler.socket(id).unwrap();
        assert_eq!(sock.pending(), 1);
    }

    #[test]
    fn process_ipv4_no_bound_socket_returns_frames() {
        let mut handler = UdpHandler::new(256);
        // No socket bound.

        let mut buf = build_test_ipv4_udp_frame(
            HANDLER_REMOTE_IPV4,
            HANDLER_LOCAL_IPV4,
            12345,
            53,
            b"hello",
        );
        let len = buf.len();
        let frame = Frame::new(0, &mut buf, len, false);
        let mut rx = BasicFrameBuffer::new(4);

        handler.process_ipv4(frame, &mut rx);

        // Frame returned to rx_return since no socket is bound.
        assert_eq!(rx.num_frames(), 1);
    }

    #[test]
    fn process_ipv4_full_rx_queue_drops_and_returns_frames() {
        let mut handler = UdpHandler::new(256);
        let id = handler
            .bind(IpAddress::V4(HANDLER_LOCAL_IPV4), 53, 1) // capacity of 1
            .unwrap();

        // First packet should be enqueued.
        let mut buf1 = build_test_ipv4_udp_frame(
            HANDLER_REMOTE_IPV4,
            HANDLER_LOCAL_IPV4,
            12345,
            53,
            b"first",
        );
        let len1 = buf1.len();
        let frame1 = Frame::new(0, &mut buf1, len1, false);
        let mut rx = BasicFrameBuffer::new(4);
        handler.process_ipv4(frame1, &mut rx);
        assert_eq!(handler.socket(id).unwrap().pending(), 1);
        assert_eq!(rx.num_frames(), 0);

        // Second packet should be dropped (queue full).
        let mut buf2 = build_test_ipv4_udp_frame(
            HANDLER_REMOTE_IPV4,
            HANDLER_LOCAL_IPV4,
            12345,
            53,
            b"second",
        );
        let len2 = buf2.len();
        let frame2 = Frame::new(1, &mut buf2, len2, false);
        handler.process_ipv4(frame2, &mut rx);

        // Still 1 in queue, dropped frame returned.
        assert_eq!(handler.socket(id).unwrap().pending(), 1);
        assert_eq!(rx.num_frames(), 1);
    }

    #[test]
    fn process_ipv6_routes_to_bound_socket() {
        let mut handler = UdpHandler::new(256);
        let id = handler
            .bind(IpAddress::V6(HANDLER_LOCAL_IPV6), 53, 128)
            .unwrap();

        let mut buf = build_test_ipv6_udp_frame(
            HANDLER_REMOTE_IPV6,
            HANDLER_LOCAL_IPV6,
            12345,
            53,
            b"hello",
        );
        let len = buf.len();
        let frame = Frame::new(0, &mut buf, len, false);
        let mut rx = BasicFrameBuffer::new(4);

        let udp_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        handler.process_ipv6(frame, None, udp_offset, &mut rx);

        assert_eq!(rx.num_frames(), 0);
        let sock = handler.socket(id).unwrap();
        assert_eq!(sock.pending(), 1);
    }

    #[test]
    fn socket_lookup_by_id() {
        let mut handler = UdpHandler::new(256);
        let id1 = handler
            .bind(IpAddress::V4(HANDLER_LOCAL_IPV4), 1000, 64)
            .unwrap();
        let id2 = handler
            .bind(IpAddress::V4(HANDLER_LOCAL_IPV4), 2000, 64)
            .unwrap();

        assert!(handler.socket(id1).is_some());
        assert!(handler.socket(id2).is_some());
        assert!(handler.socket(999).is_none());

        assert!(handler.socket_mut(id1).is_some());
        assert!(handler.socket_mut(id2).is_some());
        assert!(handler.socket_mut(999).is_none());
    }

    #[test]
    fn socket_recv_pops_packet() {
        let mut handler = UdpHandler::new(256);
        let id = handler
            .bind(IpAddress::V4(HANDLER_LOCAL_IPV4), 53, 128)
            .unwrap();

        let mut buf = build_test_ipv4_udp_frame(
            HANDLER_REMOTE_IPV4,
            HANDLER_LOCAL_IPV4,
            12345,
            53,
            b"hello",
        );
        let len = buf.len();
        let frame = Frame::new(0, &mut buf, len, false);
        let mut rx = BasicFrameBuffer::new(4);
        handler.process_ipv4(frame, &mut rx);

        let sock = handler.socket_mut(id).unwrap();
        assert_eq!(sock.pending(), 1);
        let pkt = sock.recv().unwrap();
        assert_eq!(pkt.src_addr, IpAddress::V4(HANDLER_REMOTE_IPV4));
        assert_eq!(pkt.dst_addr, IpAddress::V4(HANDLER_LOCAL_IPV4));
        assert_eq!(pkt.src_port, 12345);
        assert_eq!(pkt.dst_port, 53);
        assert_eq!(sock.pending(), 0);
        assert!(sock.recv().is_none());
    }

    #[test]
    fn evict_stale_delegates_correctly() {
        use std::time::Duration;

        let mut handler = UdpHandler::new(256);
        let mut rx = BasicFrameBuffer::new(4);

        // No entries — should be a no-op.
        handler.evict_stale(Duration::from_secs(30), &mut rx);
        assert_eq!(handler.pending_reassembly(), 0);
    }
}
