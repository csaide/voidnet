use std::mem::size_of;

use crate::xdp::frame::{Frame, FrameBuffer};

use super::{
    ethernet::EthernetFrame,
    icmp,
    ip::{IpProtocols, Ipv4Address},
    pmtu::PmtuCache,
    udp::UdpHandler,
};

/// Minimum IPv4 header length in bytes (no options, IHL = 5).
pub const IPV4_MIN_HEADER_LEN: usize = 20;

/// Compile-time guarantee that our struct matches the wire size.
const _: () = assert!(size_of::<Ipv4Header>() == IPV4_MIN_HEADER_LEN);

/// Minimum Ethernet + IPv4 frame length.
pub const IPV4_MIN_FRAME_LEN: usize = size_of::<EthernetFrame>() + IPV4_MIN_HEADER_LEN;

/// IPv4 header wire format (20 bytes, no options).
///
/// `#[repr(C, packed)]` allows zero-copy casting from raw frame memory,
/// following the same pattern as [`EthernetFrame`] and [`ArpPacket`].
///
/// Multi-byte fields are stored in network byte order as `[u8; 2]` to
/// avoid alignment issues on packed structs. Use the accessor methods
/// for host-order values.
#[repr(C, packed)]
pub struct Ipv4Header {
    /// Version (high 4 bits) + Internet Header Length (low 4 bits).
    pub version_ihl: u8,
    /// DSCP (high 6 bits) + ECN (low 2 bits).
    pub dscp_ecn: u8,
    /// Total length of the IP packet (header + payload), network byte order.
    pub total_length: [u8; 2],
    /// Identification field for fragment reassembly, network byte order.
    pub identification: [u8; 2],
    /// Flags (high 3 bits) + Fragment Offset (low 13 bits), network byte order.
    pub flags_fragment_offset: [u8; 2],
    /// Time to Live.
    pub ttl: u8,
    /// Upper-layer protocol number (e.g. TCP = 6, UDP = 17).
    pub protocol: u8,
    /// Header checksum, network byte order.
    pub header_checksum: [u8; 2],
    /// Source IPv4 address.
    pub src_addr: Ipv4Address,
    /// Destination IPv4 address.
    pub dst_addr: Ipv4Address,
}

impl Ipv4Header {
    /// Returns the IP version (should be 4).
    #[inline]
    pub fn version(&self) -> u8 {
        (self.version_ihl >> 4) & 0x0F
    }

    /// Returns the Internet Header Length in 32-bit words.
    ///
    /// A value of 5 means 20 bytes (no options). Values > 5 indicate
    /// options are present -- the extension point for future option
    /// parsing with zero overhead when IHL == 5.
    #[inline]
    pub fn ihl(&self) -> u8 {
        self.version_ihl & 0x0F
    }

    /// Returns the header length in bytes (`ihl() * 4`).
    #[inline]
    pub fn header_len(&self) -> usize {
        (self.ihl() as usize) * 4
    }

    /// Returns the total length of the IPv4 packet (header + payload).
    #[inline]
    pub fn total_length(&self) -> u16 {
        u16::from_be_bytes(self.total_length)
    }

    /// Returns the identification field.
    #[inline]
    pub fn identification(&self) -> u16 {
        u16::from_be_bytes(self.identification)
    }

    /// Returns `true` if the Don't Fragment (DF) flag is set.
    #[inline]
    pub fn dont_fragment(&self) -> bool {
        self.flags_fragment_offset[0] & 0x40 != 0
    }

    /// Returns `true` if the More Fragments (MF) flag is set.
    #[inline]
    pub fn more_fragments(&self) -> bool {
        self.flags_fragment_offset[0] & 0x20 != 0
    }

    /// Returns the fragment offset in 8-byte units.
    #[inline]
    pub fn fragment_offset(&self) -> u16 {
        let hi = (self.flags_fragment_offset[0] & 0x1F) as u16;
        let lo = self.flags_fragment_offset[1] as u16;
        (hi << 8) | lo
    }

    /// Returns `true` if this packet is an IP fragment.
    ///
    /// A packet is a fragment if MF is set or the fragment offset is non-zero.
    /// This is the single-branch fast-path check used by the handler.
    #[inline]
    pub fn is_fragment(&self) -> bool {
        let combined = u16::from_be_bytes(self.flags_fragment_offset);
        (combined & 0x3FFF) != 0
    }

    /// Byte offset from the start of the Ethernet frame to the IP payload.
    ///
    /// Equal to `sizeof(EthernetFrame) + header_len()`. When IHL == 5
    /// (no options) this compiles to a constant 34.
    #[inline]
    pub fn payload_offset(&self) -> usize {
        size_of::<EthernetFrame>() + self.header_len()
    }

    /// Returns the IP payload length (total_length minus header_len).
    ///
    /// Returns 0 if total_length < header_len (malformed).
    #[inline]
    pub fn payload_len(&self) -> usize {
        let total = self.total_length() as usize;
        let hdr = self.header_len();
        if total > hdr { total - hdr } else { 0 }
    }

    /// Fills `header_checksum` with the correct value.
    #[inline]
    pub fn fill_checksum(&mut self) {
        self.header_checksum = [0, 0];
        let bytes = unsafe {
            std::slice::from_raw_parts(self as *const Self as *const u8, self.header_len())
        };
        self.header_checksum = compute_ipv4_checksum(bytes);
    }

    /// Zero-copy borrow of the IPv4 header from a received frame.
    ///
    /// The header starts immediately after the Ethernet header.
    ///
    /// # Safety
    ///
    /// The caller must ensure `frame.len() >= IPV4_MIN_FRAME_LEN`.
    #[inline]
    pub fn from_frame<'f, 'u>(frame: &'f Frame<'u>) -> &'f Self {
        debug_assert!(frame.len() >= IPV4_MIN_FRAME_LEN);
        unsafe { &*(frame.as_ptr().add(size_of::<EthernetFrame>()) as *const Self) }
    }

    /// Mutable zero-copy borrow of the IPv4 header from a received frame.
    ///
    /// # Safety
    ///
    /// The caller must ensure `frame.len() >= IPV4_MIN_FRAME_LEN`.
    #[inline]
    pub fn from_frame_mut<'f, 'u>(frame: &'f mut Frame<'u>) -> &'f mut Self {
        debug_assert!(frame.len() >= IPV4_MIN_FRAME_LEN);
        unsafe { &mut *(frame.as_mut_ptr().add(size_of::<EthernetFrame>()) as *mut Self) }
    }
}

/// Computes the IPv4 header checksum per RFC 1071.
///
/// `header_bytes` must contain the full header with the checksum field
/// set to zero. Returns the two-byte checksum in network byte order.
#[inline]
pub fn compute_ipv4_checksum(header_bytes: &[u8]) -> [u8; 2] {
    let mut sum: u32 = 0;
    let len = header_bytes.len();

    let mut i = 0;
    while i + 1 < len {
        let word = ((header_bytes[i] as u32) << 8) | (header_bytes[i + 1] as u32);
        sum += word;
        i += 2;
    }

    if i < len {
        sum += (header_bytes[i] as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let checksum = !(sum as u16);
    checksum.to_be_bytes()
}

/// Verifies the IPv4 header checksum.
///
/// Returns `true` if the checksum is valid (the one's complement sum
/// of the entire header including the checksum field yields zero).
#[inline]
fn verify_ipv4_checksum(header_bytes: &[u8]) -> bool {
    let result = compute_ipv4_checksum(header_bytes);
    result == [0x00, 0x00]
}

/// Layer-3 handler for incoming IPv4 frames.
///
/// Validates the IPv4 header (version, length, checksum) and dispatches
/// to protocol-specific handlers based on the protocol field.
///
/// The frame is always consumed and pushed to exactly one buffer:
///
/// * `rx_return` -- validation failures or received data for upper layers.
/// * `tx_return` -- responses generated by protocol handlers (e.g.
///   ICMP echo reply, Destination Unreachable).
pub struct Ipv4Handler;

impl Ipv4Handler {
    pub fn new() -> Self {
        Self
    }

    /// Processes an incoming IPv4 frame.
    ///
    /// Validates the header and dispatches to the appropriate protocol
    /// handler. The frame is always consumed.
    pub fn handle<'umem>(
        &mut self,
        frame: Frame<'umem>,
        udp_handler: &mut UdpHandler<'umem>,
        pmtu: &mut PmtuCache,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        if frame.len() < IPV4_MIN_FRAME_LEN {
            eprintln!(
                "ipv4: frame too short ({} bytes, need {})",
                frame.len(),
                IPV4_MIN_FRAME_LEN,
            );
            rx_return.push(frame);
            return;
        }

        let ip = Ipv4Header::from_frame(&frame);

        if ip.version() != 4 {
            eprintln!("ipv4: unexpected version {}", ip.version());
            rx_return.push(frame);
            return;
        }

        if ip.ihl() < 5 {
            eprintln!("ipv4: IHL too small ({})", ip.ihl());
            rx_return.push(frame);
            return;
        }

        let total_length = ip.total_length() as usize;
        let header_len = ip.header_len();

        if total_length < header_len {
            eprintln!(
                "ipv4: total_length ({}) < header_len ({})",
                total_length, header_len,
            );
            rx_return.push(frame);
            return;
        }

        let eth_len = size_of::<EthernetFrame>();
        if frame.len() < eth_len + total_length {
            eprintln!(
                "ipv4: frame too short for total_length ({} bytes, need {})",
                frame.len(),
                eth_len + total_length,
            );
            rx_return.push(frame);
            return;
        }

        let ip_bytes = &frame[eth_len..eth_len + header_len];
        if !verify_ipv4_checksum(ip_bytes) {
            eprintln!("ipv4: invalid header checksum");
            rx_return.push(frame);
            return;
        }

        if ip.is_fragment() {
            if ip.protocol == IpProtocols::Udp {
                udp_handler.process_ipv4(frame, rx_return);
            } else {
                rx_return.push(frame);
            }
            return;
        }

        let protocol = ip.protocol;
        match protocol {
            IpProtocols::Icmp => icmp::handle_icmpv4(frame, pmtu, rx_return, tx_return),
            IpProtocols::Tcp => rx_return.push(frame),
            IpProtocols::Udp => udp_handler.process_ipv4(frame, rx_return),
            _ => icmp::send_destination_unreachable(
                frame,
                icmp::Icmpv4Codes::ProtocolUnreachable,
                0,
                rx_return,
                tx_return,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::ip::IpAddress;
    use crate::net::pmtu::PmtuCache;
    use crate::xdp::frame::BasicFrameBuffer;

    const REMOTE_IP: Ipv4Address = Ipv4Address::new([10, 0, 0, 2]);
    const LOCAL_IP: Ipv4Address = Ipv4Address::new([192, 168, 1, 1]);

    fn new_handler() -> Ipv4Handler {
        Ipv4Handler::new()
    }

    fn new_udp_handler<'umem>() -> UdpHandler<'umem> {
        UdpHandler::new(256)
    }

    /// Creates a UdpHandler with a socket bound to LOCAL_IP on port 0
    /// (to catch any UDP traffic destined to LOCAL_IP).
    fn new_udp_handler_with_socket<'umem>(port: u16) -> (UdpHandler<'umem>, u32) {
        let mut udp = UdpHandler::new(256);
        let id = udp.bind(IpAddress::V4(LOCAL_IP), port, 256).unwrap();
        (udp, id)
    }

    /// Builds a valid Ethernet + IPv4 frame with the given parameters.
    fn build_ipv4_frame(
        src: Ipv4Address,
        dst: Ipv4Address,
        protocol: u8,
        ttl: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let total_ip_len = (IPV4_MIN_HEADER_LEN + payload.len()) as u16;
        let eth_len = size_of::<EthernetFrame>();
        let mut buf = vec![0u8; eth_len + IPV4_MIN_HEADER_LEN + payload.len()];

        buf[12] = 0x08;
        buf[13] = 0x00;

        let ip = &mut buf[14..];
        ip[0] = 0x45;
        ip[1] = 0x00;
        ip[2..4].copy_from_slice(&total_ip_len.to_be_bytes());
        ip[6] = 0x40;
        ip[7] = 0x00;
        ip[8] = ttl;
        ip[9] = protocol;
        let src_bytes: [u8; 4] = src.into();
        ip[12..16].copy_from_slice(&src_bytes);
        let dst_bytes: [u8; 4] = dst.into();
        ip[16..20].copy_from_slice(&dst_bytes);

        let cksum = compute_ipv4_checksum(&ip[..20]);
        ip[10] = cksum[0];
        ip[11] = cksum[1];

        buf[eth_len + IPV4_MIN_HEADER_LEN..].copy_from_slice(payload);
        buf
    }

    /// Builds a fragmented IPv4 frame.
    fn build_fragment_frame(
        src: Ipv4Address,
        dst: Ipv4Address,
        protocol: u8,
        frag_offset: u16,
        more_fragments: bool,
        payload: &[u8],
    ) -> Vec<u8> {
        let total_ip_len = (IPV4_MIN_HEADER_LEN + payload.len()) as u16;
        let eth_len = size_of::<EthernetFrame>();
        let mut buf = vec![0u8; eth_len + IPV4_MIN_HEADER_LEN + payload.len()];

        buf[12] = 0x08;
        buf[13] = 0x00;

        let ip = &mut buf[14..];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&total_ip_len.to_be_bytes());

        let mf = if more_fragments { 0x20u8 } else { 0 };
        let hi = mf | ((frag_offset >> 8) as u8 & 0x1F);
        let lo = frag_offset as u8;
        ip[6] = hi;
        ip[7] = lo;

        ip[8] = 64;
        ip[9] = protocol;
        let src_bytes: [u8; 4] = src.into();
        ip[12..16].copy_from_slice(&src_bytes);
        let dst_bytes: [u8; 4] = dst.into();
        ip[16..20].copy_from_slice(&dst_bytes);

        let cksum = compute_ipv4_checksum(&ip[..20]);
        ip[10] = cksum[0];
        ip[11] = cksum[1];

        buf[eth_len + IPV4_MIN_HEADER_LEN..].copy_from_slice(payload);
        buf
    }

    #[test]
    fn struct_size() {
        assert_eq!(size_of::<Ipv4Header>(), 20);
    }

    #[test]
    fn version_and_ihl() {
        let mut buf = build_ipv4_frame(REMOTE_IP, LOCAL_IP, 17, 64, &[0xAA; 20]);
        let len = buf.len();
        let frame = Frame::new(0, &mut buf, len, false);
        let hdr = Ipv4Header::from_frame(&frame);

        assert_eq!(hdr.version(), 4);
        assert_eq!(hdr.ihl(), 5);
        assert_eq!(hdr.header_len(), 20);
    }

    #[test]
    fn total_length_and_payload() {
        let mut buf = build_ipv4_frame(REMOTE_IP, LOCAL_IP, 6, 128, &[0u8; 200]);
        let len = buf.len();
        let frame = Frame::new(0, &mut buf, len, false);
        let hdr = Ipv4Header::from_frame(&frame);

        assert_eq!(hdr.total_length(), 220);
        assert_eq!(hdr.payload_len(), 200);
        assert_eq!(hdr.payload_offset(), 34);
    }

    #[test]
    fn addresses_read_correctly() {
        let src = Ipv4Address::new([172, 16, 0, 1]);
        let dst = Ipv4Address::new([172, 16, 0, 254]);
        let mut buf = build_ipv4_frame(src, dst, 17, 64, &[]);
        let len = buf.len();
        let frame = Frame::new(0, &mut buf, len, false);
        let hdr = Ipv4Header::from_frame(&frame);

        assert_eq!(hdr.src_addr, src);
        assert_eq!(hdr.dst_addr, dst);
        assert_eq!(hdr.ttl, 64);
        assert_eq!(hdr.protocol, 17);
    }

    #[test]
    fn is_fragment_detection() {
        let mut buf = build_ipv4_frame(REMOTE_IP, LOCAL_IP, 17, 64, &[0; 8]);
        let len = buf.len();
        let frame = Frame::new(0, &mut buf, len, false);
        let hdr = Ipv4Header::from_frame(&frame);
        assert!(!hdr.is_fragment());

        let mut buf2 = build_fragment_frame(REMOTE_IP, LOCAL_IP, 17, 0, true, &[0; 8]);
        let len2 = buf2.len();
        let frame2 = Frame::new(0, &mut buf2, len2, false);
        let hdr2 = Ipv4Header::from_frame(&frame2);
        assert!(hdr2.is_fragment());

        let mut buf3 = build_fragment_frame(REMOTE_IP, LOCAL_IP, 17, 185, false, &[0; 8]);
        let len3 = buf3.len();
        let frame3 = Frame::new(0, &mut buf3, len3, false);
        let hdr3 = Ipv4Header::from_frame(&frame3);
        assert!(hdr3.is_fragment());
    }

    #[test]
    fn checksum_verify() {
        let buf = build_ipv4_frame(REMOTE_IP, LOCAL_IP, 6, 128, &[0xDE; 50]);
        let verify = compute_ipv4_checksum(&buf[14..34]);
        assert_eq!(verify, [0x00, 0x00]);
    }

    #[test]
    fn fill_checksum_method() {
        let mut header_bytes = [0u8; 20];
        header_bytes[0] = 0x45;
        header_bytes[8] = 64;
        header_bytes[9] = 6;
        header_bytes[12..16].copy_from_slice(&[10, 0, 0, 1]);
        header_bytes[16..20].copy_from_slice(&[10, 0, 0, 2]);

        let hdr = unsafe { &mut *(header_bytes.as_mut_ptr() as *mut Ipv4Header) };
        hdr.total_length = 20u16.to_be_bytes();
        hdr.fill_checksum();

        let verify = compute_ipv4_checksum(&header_bytes);
        assert_eq!(verify, [0x00, 0x00]);
    }

    #[test]
    fn frame_too_short_goes_to_rx() {
        let mut handler = new_handler();
        let mut udp = new_udp_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = [0u8; 30];
        let frame = Frame::new(0, &mut data, 30, false);

        handler.handle(frame, &mut udp, &mut PmtuCache::new(), &mut rx, &mut tx);
        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn wrong_version_goes_to_rx() {
        let mut handler = new_handler();
        let mut udp = new_udp_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = build_ipv4_frame(REMOTE_IP, LOCAL_IP, 17, 64, &[0; 8]);
        data[14] = 0x65;
        let cksum = compute_ipv4_checksum(&data[14..34]);
        data[24] = cksum[0];
        data[25] = cksum[1];

        let len = data.len();
        let frame = Frame::new(0, &mut data, len, false);

        handler.handle(frame, &mut udp, &mut PmtuCache::new(), &mut rx, &mut tx);
        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn bad_checksum_goes_to_rx() {
        let mut handler = new_handler();
        let mut udp = new_udp_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = build_ipv4_frame(REMOTE_IP, LOCAL_IP, 17, 64, &[0; 8]);
        data[24] ^= 0xFF;

        let len = data.len();
        let frame = Frame::new(0, &mut data, len, false);

        handler.handle(frame, &mut udp, &mut PmtuCache::new(), &mut rx, &mut tx);
        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn fragment_goes_to_udp_handler() {
        let mut handler = new_handler();
        let mut udp = new_udp_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = build_fragment_frame(REMOTE_IP, LOCAL_IP, 17, 0, true, &[0; 8]);
        let len = data.len();
        let frame = Frame::new(0, &mut data, len, false);

        handler.handle(frame, &mut udp, &mut PmtuCache::new(), &mut rx, &mut tx);
        // UDP fragment goes to udp_handler reassembly, not rx_return.
        assert_eq!(rx.num_frames(), 0);
        assert_eq!(tx.num_frames(), 0);
        assert_eq!(udp.pending_reassembly(), 1);
    }

    #[test]
    fn icmp_echo_request_generates_reply() {
        let mut handler = new_handler();
        let mut udp = new_udp_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        // Build a valid ICMP Echo Request.
        let eth_len = size_of::<EthernetFrame>();
        let icmp_len = 8 + 8; // header + 8 bytes data
        let ip_total = IPV4_MIN_HEADER_LEN + icmp_len;
        let frame_len = eth_len + ip_total;
        let mut data = vec![0u8; 256];

        // Ethernet
        data[12] = 0x08;
        data[13] = 0x00;

        // IPv4
        data[14] = 0x45;
        data[16..18].copy_from_slice(&(ip_total as u16).to_be_bytes());
        data[20] = 0x40;
        data[22] = 64;
        data[23] = IpProtocols::Icmp;
        let src_bytes: [u8; 4] = REMOTE_IP.into();
        data[26..30].copy_from_slice(&src_bytes);
        let dst_bytes: [u8; 4] = LOCAL_IP.into();
        data[30..34].copy_from_slice(&dst_bytes);
        let cksum = compute_ipv4_checksum(&data[14..34]);
        data[24] = cksum[0];
        data[25] = cksum[1];

        // ICMP Echo Request
        let icmp_off = eth_len + IPV4_MIN_HEADER_LEN;
        data[icmp_off] = 8; // type = Echo Request
        data[icmp_off + 1] = 0;
        // id, seq, and 8 bytes data are already zeros
        let cksum = compute_ipv4_checksum(&data[icmp_off..icmp_off + icmp_len]);
        data[icmp_off + 2] = cksum[0];
        data[icmp_off + 3] = cksum[1];

        let frame = Frame::new(0, &mut data, frame_len, false);
        handler.handle(frame, &mut udp, &mut PmtuCache::new(), &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 0);
        assert_eq!(tx.num_frames(), 1);
    }

    #[test]
    fn valid_tcp_accepted() {
        let mut handler = new_handler();
        let mut udp = new_udp_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = build_ipv4_frame(REMOTE_IP, LOCAL_IP, IpProtocols::Tcp, 64, &[0; 20]);
        let len = data.len();
        let frame = Frame::new(0, &mut data, len, false);

        handler.handle(frame, &mut udp, &mut PmtuCache::new(), &mut rx, &mut tx);
        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn valid_udp_routed_to_socket() {
        let mut handler = new_handler();
        // The UDP header in build_ipv4_frame has all zeros, so src_port=0, dst_port=0.
        let (mut udp, id) = new_udp_handler_with_socket(0);
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = build_ipv4_frame(REMOTE_IP, LOCAL_IP, IpProtocols::Udp, 64, &[0; 8]);
        let len = data.len();
        let frame = Frame::new(0, &mut data, len, false);

        handler.handle(frame, &mut udp, &mut PmtuCache::new(), &mut rx, &mut tx);
        // UDP routed to bound socket.
        assert_eq!(rx.num_frames(), 0);
        assert_eq!(tx.num_frames(), 0);
        assert_eq!(udp.socket(id).unwrap().pending(), 1);
    }

    #[test]
    fn unknown_protocol_sends_dest_unreachable() {
        let mut handler = new_handler();
        let mut udp = new_udp_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        // Use extra capacity so the ICMP error response fits.
        let raw = build_ipv4_frame(REMOTE_IP, LOCAL_IP, 255, 64, &[0; 8]);
        let mut data = vec![0u8; 256];
        data[..raw.len()].copy_from_slice(&raw);
        let frame = Frame::new(0, &mut data, raw.len(), false);

        handler.handle(frame, &mut udp, &mut PmtuCache::new(), &mut rx, &mut tx);
        assert_eq!(rx.num_frames(), 0);
        assert_eq!(tx.num_frames(), 1);
    }

    #[test]
    fn ihl_too_small_goes_to_rx() {
        let mut handler = new_handler();
        let mut udp = new_udp_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = build_ipv4_frame(REMOTE_IP, LOCAL_IP, 17, 64, &[0; 8]);
        data[14] = 0x44;
        let len = data.len();
        let frame = Frame::new(0, &mut data, len, false);

        handler.handle(frame, &mut udp, &mut PmtuCache::new(), &mut rx, &mut tx);
        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }
}
