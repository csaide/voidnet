use std::mem::size_of;

use crate::xdp::frame::{Frame, FrameBuffer};

use super::{
    ethernet::EthernetFrame,
    icmpv6,
    ip::{IpProtocols, Ipv6Address},
    neighbor::NeighborHandler,
    pmtu::PmtuCache,
};

/// Fixed IPv6 header length in bytes (always 40, no variable-length header).
pub const IPV6_HEADER_LEN: usize = 40;

/// Compile-time guarantee that our struct matches the wire size.
const _: () = assert!(size_of::<Ipv6Header>() == IPV6_HEADER_LEN);

/// Minimum Ethernet + IPv6 frame length.
pub const IPV6_MIN_FRAME_LEN: usize = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;

/// Hop-by-Hop Options extension header.
const EXT_HOP_BY_HOP: u8 = 0;
/// Routing extension header.
const EXT_ROUTING: u8 = 43;
/// Fragment extension header.
const EXT_FRAGMENT: u8 = 44;
/// Authentication Header.
const EXT_AH: u8 = 51;
/// Destination Options extension header.
const EXT_DESTINATION: u8 = 60;
/// No Next Header.
const NO_NEXT_HEADER: u8 = 59;

/// Fragment extension header length (always 8 bytes).
const FRAGMENT_EXT_LEN: usize = 8;

/// IPv6 fixed header wire format (40 bytes).
///
/// `#[repr(C, packed)]` allows zero-copy casting from raw frame memory.
/// The first 4 bytes encode version (4 bits), traffic class (8 bits),
/// and flow label (20 bits) in network byte order.
#[repr(C, packed)]
pub struct Ipv6Header {
    /// Version (4) + Traffic Class (8) + Flow Label (20), network byte order.
    pub version_tc_fl: [u8; 4],
    /// Payload length (excludes the 40-byte fixed header), network byte order.
    pub payload_length: [u8; 2],
    /// Next header protocol number (or extension header type).
    pub next_header: u8,
    /// Hop limit (analogous to IPv4 TTL).
    pub hop_limit: u8,
    /// Source IPv6 address.
    pub src_addr: Ipv6Address,
    /// Destination IPv6 address.
    pub dst_addr: Ipv6Address,
}

impl Ipv6Header {
    /// Returns the IP version (should be 6).
    #[inline]
    pub fn version(&self) -> u8 {
        (self.version_tc_fl[0] >> 4) & 0x0F
    }

    /// Returns the 8-bit traffic class (DSCP + ECN).
    #[inline]
    pub fn traffic_class(&self) -> u8 {
        ((self.version_tc_fl[0] & 0x0F) << 4) | ((self.version_tc_fl[1] >> 4) & 0x0F)
    }

    /// Returns the 20-bit flow label.
    #[inline]
    pub fn flow_label(&self) -> u32 {
        ((self.version_tc_fl[1] as u32 & 0x0F) << 16)
            | ((self.version_tc_fl[2] as u32) << 8)
            | (self.version_tc_fl[3] as u32)
    }

    /// Returns the payload length (bytes after the 40-byte fixed header).
    #[inline]
    pub fn payload_length(&self) -> u16 {
        u16::from_be_bytes(self.payload_length)
    }

    /// Zero-copy borrow of the IPv6 header from a received frame.
    ///
    /// The header starts immediately after the Ethernet header.
    ///
    /// # Safety
    ///
    /// The caller must ensure `frame.len() >= IPV6_MIN_FRAME_LEN`.
    #[inline]
    pub fn from_frame<'f, 'u>(frame: &'f Frame<'u>) -> &'f Self {
        debug_assert!(frame.len() >= IPV6_MIN_FRAME_LEN);
        unsafe { &*(frame.as_ptr().add(size_of::<EthernetFrame>()) as *const Self) }
    }

    /// Mutable zero-copy borrow of the IPv6 header from a received frame.
    ///
    /// # Safety
    ///
    /// The caller must ensure `frame.len() >= IPV6_MIN_FRAME_LEN`.
    #[inline]
    pub fn from_frame_mut<'f, 'u>(frame: &'f mut Frame<'u>) -> &'f mut Self {
        debug_assert!(frame.len() >= IPV6_MIN_FRAME_LEN);
        unsafe { &mut *(frame.as_mut_ptr().add(size_of::<EthernetFrame>()) as *mut Self) }
    }
}

/// Result of walking IPv6 extension headers.
#[allow(dead_code)] // payload_offset will be used by transport handlers.
enum NextHeaderResult {
    /// Upper-layer protocol found. `protocol` is the protocol number,
    /// `payload_offset` is the byte offset from the start of the frame
    /// to the upper-layer payload, and `next_header_offset` is the byte
    /// offset of the Next Header field that contained `protocol` (used
    /// for ICMPv6 Parameter Problem pointer).
    Protocol {
        protocol: u8,
        payload_offset: usize,
        next_header_offset: usize,
    },
    /// A Fragment extension header was found, indicating this packet
    /// is fragmented. We do not reassemble fragments.
    Fragment,
    /// The extension header chain is malformed (frame too short, etc.).
    Malformed,
    /// Reached `No Next Header` (protocol 59). The packet has no
    /// upper-layer payload.
    NoPayload,
}

/// Walks the IPv6 extension header chain starting from `next_header`
/// at byte offset `offset` (from the start of the frame).
///
/// Returns the final upper-layer protocol and its payload offset, or
/// an indication that the packet is fragmented or malformed.
///
/// Supported extension headers (skipped transparently):
/// - Hop-by-Hop Options (0)
/// - Routing (43)
/// - Destination Options (60)
/// - Authentication Header (51)
///
/// Terminal conditions:
/// - Fragment (44) -> [`NextHeaderResult::Fragment`]
/// - ESP (50) -> returned as a protocol (cannot see past encryption)
/// - No Next Header (59) -> [`NextHeaderResult::NoPayload`]
/// - Any other value -> returned as an upper-layer protocol
fn walk_extension_headers(
    frame: &[u8],
    mut next_header: u8,
    mut offset: usize,
    initial_nh_offset: usize,
) -> NextHeaderResult {
    const MAX_EXT_HEADERS: usize = 16;
    let mut nh_offset = initial_nh_offset;

    for _ in 0..MAX_EXT_HEADERS {
        match next_header {
            EXT_HOP_BY_HOP | EXT_ROUTING | EXT_DESTINATION => {
                if offset + 2 > frame.len() {
                    return NextHeaderResult::Malformed;
                }
                nh_offset = offset;
                let nh = frame[offset];
                let hdr_ext_len = frame[offset + 1] as usize;
                let ext_len = (hdr_ext_len + 1) * 8;
                if offset + ext_len > frame.len() {
                    return NextHeaderResult::Malformed;
                }
                next_header = nh;
                offset += ext_len;
            }

            EXT_AH => {
                if offset + 2 > frame.len() {
                    return NextHeaderResult::Malformed;
                }
                nh_offset = offset;
                let nh = frame[offset];
                let payload_len = frame[offset + 1] as usize;
                let ext_len = (payload_len + 2) * 4;
                if offset + ext_len > frame.len() {
                    return NextHeaderResult::Malformed;
                }
                next_header = nh;
                offset += ext_len;
            }

            EXT_FRAGMENT => {
                if offset + FRAGMENT_EXT_LEN > frame.len() {
                    return NextHeaderResult::Malformed;
                }
                return NextHeaderResult::Fragment;
            }

            NO_NEXT_HEADER => {
                return NextHeaderResult::NoPayload;
            }

            protocol => {
                return NextHeaderResult::Protocol {
                    protocol,
                    payload_offset: offset,
                    next_header_offset: nh_offset,
                };
            }
        }
    }

    NextHeaderResult::Malformed
}

/// Layer-3 handler for incoming IPv6 frames.
///
/// Validates the IPv6 header (version, length), walks extension headers,
/// and dispatches to protocol-specific handlers.
///
/// The frame is always consumed and pushed to exactly one buffer:
///
/// * `rx_return` -- validation failures, fragmented packets, or
///   received data for upper layers.
/// * `tx_return` -- responses generated by protocol handlers (e.g.
///   ICMPv6 echo reply, Destination Unreachable).
pub struct Ipv6Handler;

impl Ipv6Handler {
    pub fn new() -> Self {
        Self
    }

    /// Processes an incoming IPv6 frame.
    ///
    /// Validates the header, walks extension headers, and dispatches to
    /// the appropriate protocol handler. The frame is always consumed.
    ///
    /// NDP messages (ICMPv6 types 133-137) are dispatched to
    /// `neighbor_handler` instead of the generic ICMPv6 handler.
    pub fn handle<'umem>(
        &mut self,
        frame: Frame<'umem>,
        neighbor_handler: &mut NeighborHandler,
        pmtu: &mut PmtuCache,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        if frame.len() < IPV6_MIN_FRAME_LEN {
            eprintln!(
                "ipv6: frame too short ({} bytes, need {})",
                frame.len(),
                IPV6_MIN_FRAME_LEN,
            );
            rx_return.push(frame);
            return;
        }

        let ip = Ipv6Header::from_frame(&frame);

        if ip.version() != 6 {
            eprintln!("ipv6: unexpected version {}", ip.version());
            rx_return.push(frame);
            return;
        }

        let payload_length = ip.payload_length() as usize;
        let eth_len = size_of::<EthernetFrame>();

        if frame.len() < eth_len + IPV6_HEADER_LEN + payload_length {
            eprintln!(
                "ipv6: frame too short for payload_length ({} bytes, need {})",
                frame.len(),
                eth_len + IPV6_HEADER_LEN + payload_length,
            );
            rx_return.push(frame);
            return;
        }

        let first_next_header = ip.next_header;
        let ext_start = eth_len + IPV6_HEADER_LEN;
        let ip_end = ext_start + payload_length;
        let initial_nh_offset = eth_len + 6; // IPv6 Next Header field

        match walk_extension_headers(
            &frame[..ip_end],
            first_next_header,
            ext_start,
            initial_nh_offset,
        ) {
            NextHeaderResult::Protocol {
                protocol,
                payload_offset,
                next_header_offset,
            } => match protocol {
                IpProtocols::IcmpV6 => {
                    let icmpv6_len = ip_end - payload_offset;
                    icmpv6::handle_icmpv6(
                        frame,
                        payload_offset,
                        icmpv6_len,
                        neighbor_handler,
                        pmtu,
                        rx_return,
                        tx_return,
                    );
                }
                IpProtocols::Tcp => rx_return.push(frame),
                IpProtocols::Udp => rx_return.push(frame),
                _ => {
                    // RFC 4443 §3.4: send Parameter Problem (code 1) with
                    // pointer to the unrecognized Next Header field.
                    let pointer = (next_header_offset - eth_len) as u32;
                    icmpv6::send_icmpv6_error(
                        frame,
                        icmpv6::Icmpv6Types::ParameterProblem,
                        icmpv6::Icmpv6Codes::UnrecognizedNextHeader,
                        pointer.to_be_bytes(),
                        protocol,
                        payload_offset,
                        rx_return,
                        tx_return,
                    );
                }
            },
            NextHeaderResult::Fragment => {
                eprintln!("ipv6: dropping fragmented packet");
                rx_return.push(frame);
            }
            NextHeaderResult::Malformed => {
                eprintln!("ipv6: malformed extension header chain");
                rx_return.push(frame);
            }
            NextHeaderResult::NoPayload => {
                rx_return.push(frame);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::ethernet::MacAddress;
    use super::*;
    use crate::net::pmtu::PmtuCache;
    use crate::xdp::frame::BasicFrameBuffer;
    use std::time::Duration;

    const REMOTE_IP: Ipv6Address =
        Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    const LOCAL_IP: Ipv6Address =
        Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    const TEST_MAC: MacAddress = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

    fn new_handler() -> Ipv6Handler {
        Ipv6Handler::new()
    }

    fn new_neighbor_handler() -> NeighborHandler {
        NeighborHandler::new("test0", TEST_MAC, Duration::from_secs(60)).unwrap()
    }

    /// Builds a valid Ethernet + IPv6 frame with no extension headers.
    fn build_ipv6_frame(
        src: Ipv6Address,
        dst: Ipv6Address,
        next_header: u8,
        hop_limit: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let eth_len = size_of::<EthernetFrame>();
        let payload_len = payload.len() as u16;
        let mut buf = vec![0u8; eth_len + IPV6_HEADER_LEN + payload.len()];

        buf[12] = 0x86;
        buf[13] = 0xDD;

        let ip = &mut buf[14..];
        ip[0] = 0x60;
        ip[1] = 0x00;
        ip[2] = 0x00;
        ip[3] = 0x00;
        ip[4..6].copy_from_slice(&payload_len.to_be_bytes());
        ip[6] = next_header;
        ip[7] = hop_limit;
        let src_bytes: [u8; 16] = src.into();
        ip[8..24].copy_from_slice(&src_bytes);
        let dst_bytes: [u8; 16] = dst.into();
        ip[24..40].copy_from_slice(&dst_bytes);

        buf[eth_len + IPV6_HEADER_LEN..].copy_from_slice(payload);
        buf
    }

    /// Builds an IPv6 frame with a Hop-by-Hop extension header followed
    /// by the upper-layer protocol.
    fn build_ipv6_with_ext_header(
        src: Ipv6Address,
        dst: Ipv6Address,
        upper_protocol: u8,
        hop_limit: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let eth_len = size_of::<EthernetFrame>();
        let ext_len = 8;
        let payload_len = (ext_len + payload.len()) as u16;
        let mut buf = vec![0u8; eth_len + IPV6_HEADER_LEN + ext_len + payload.len()];

        buf[12] = 0x86;
        buf[13] = 0xDD;

        let ip = &mut buf[14..];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&payload_len.to_be_bytes());
        ip[6] = EXT_HOP_BY_HOP;
        ip[7] = hop_limit;
        let src_bytes: [u8; 16] = src.into();
        ip[8..24].copy_from_slice(&src_bytes);
        let dst_bytes: [u8; 16] = dst.into();
        ip[24..40].copy_from_slice(&dst_bytes);

        let ext_offset = eth_len + IPV6_HEADER_LEN;
        buf[ext_offset] = upper_protocol;
        buf[ext_offset + 1] = 0;

        buf[ext_offset + ext_len..].copy_from_slice(payload);
        buf
    }

    /// Builds an IPv6 frame with a Fragment extension header.
    fn build_ipv6_with_fragment(
        src: Ipv6Address,
        dst: Ipv6Address,
        upper_protocol: u8,
        frag_offset: u16,
        more_fragments: bool,
        payload: &[u8],
    ) -> Vec<u8> {
        let eth_len = size_of::<EthernetFrame>();
        let payload_len = (FRAGMENT_EXT_LEN + payload.len()) as u16;
        let mut buf = vec![0u8; eth_len + IPV6_HEADER_LEN + FRAGMENT_EXT_LEN + payload.len()];

        buf[12] = 0x86;
        buf[13] = 0xDD;

        let ip = &mut buf[14..];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&payload_len.to_be_bytes());
        ip[6] = EXT_FRAGMENT;
        ip[7] = 64;
        let src_bytes: [u8; 16] = src.into();
        ip[8..24].copy_from_slice(&src_bytes);
        let dst_bytes: [u8; 16] = dst.into();
        ip[24..40].copy_from_slice(&dst_bytes);

        let frag_offset_raw = eth_len + IPV6_HEADER_LEN;
        buf[frag_offset_raw] = upper_protocol;
        buf[frag_offset_raw + 1] = 0;
        let fo_m = (frag_offset << 3) | (if more_fragments { 1 } else { 0 });
        buf[frag_offset_raw + 2..frag_offset_raw + 4].copy_from_slice(&fo_m.to_be_bytes());

        buf[frag_offset_raw + FRAGMENT_EXT_LEN..].copy_from_slice(payload);
        buf
    }

    #[test]
    fn struct_size() {
        assert_eq!(size_of::<Ipv6Header>(), 40);
    }

    #[test]
    fn version_and_traffic_class() {
        let mut buf = build_ipv6_frame(REMOTE_IP, LOCAL_IP, IpProtocols::Udp, 64, &[0; 8]);
        let len = buf.len();
        let frame = Frame::new(0, &mut buf, len, false);
        let hdr = Ipv6Header::from_frame(&frame);

        assert_eq!(hdr.version(), 6);
        assert_eq!(hdr.traffic_class(), 0);
    }

    #[test]
    fn flow_label() {
        let mut buf = build_ipv6_frame(REMOTE_IP, LOCAL_IP, IpProtocols::Udp, 64, &[0; 8]);
        buf[14 + 1] = (buf[14 + 1] & 0xF0) | 0x0A;
        buf[14 + 2] = 0xBC;
        buf[14 + 3] = 0xDE;

        let len = buf.len();
        let frame = Frame::new(0, &mut buf, len, false);
        let hdr = Ipv6Header::from_frame(&frame);

        assert_eq!(hdr.flow_label(), 0xABCDE);
    }

    #[test]
    fn payload_length() {
        let mut buf = build_ipv6_frame(REMOTE_IP, LOCAL_IP, IpProtocols::Tcp, 64, &[0; 100]);
        let len = buf.len();
        let frame = Frame::new(0, &mut buf, len, false);
        let hdr = Ipv6Header::from_frame(&frame);

        assert_eq!(hdr.payload_length(), 100);
    }

    #[test]
    fn next_header_and_hop_limit() {
        let mut buf = build_ipv6_frame(REMOTE_IP, LOCAL_IP, IpProtocols::Tcp, 128, &[0; 20]);
        let len = buf.len();
        let frame = Frame::new(0, &mut buf, len, false);
        let hdr = Ipv6Header::from_frame(&frame);

        assert_eq!(hdr.next_header, IpProtocols::Tcp);
        assert_eq!(hdr.hop_limit, 128);
    }

    #[test]
    fn addresses_read_correctly() {
        let mut buf = build_ipv6_frame(REMOTE_IP, LOCAL_IP, IpProtocols::Udp, 64, &[]);
        let len = buf.len();
        let frame = Frame::new(0, &mut buf, len, false);
        let hdr = Ipv6Header::from_frame(&frame);

        assert_eq!(hdr.src_addr, REMOTE_IP);
        assert_eq!(hdr.dst_addr, LOCAL_IP);
    }

    #[test]
    fn walk_no_extensions() {
        let buf = build_ipv6_frame(REMOTE_IP, LOCAL_IP, IpProtocols::Udp, 64, &[0; 8]);
        let eth_len = size_of::<EthernetFrame>();
        let start = eth_len + IPV6_HEADER_LEN;
        let nh_offset = eth_len + 6;

        match walk_extension_headers(&buf, IpProtocols::Udp, start, nh_offset) {
            NextHeaderResult::Protocol {
                protocol,
                payload_offset,
                next_header_offset,
            } => {
                assert_eq!(protocol, IpProtocols::Udp);
                assert_eq!(payload_offset, start);
                assert_eq!(next_header_offset, nh_offset);
            }
            _ => panic!("expected Protocol"),
        }
    }

    #[test]
    fn walk_hop_by_hop_extension() {
        let buf = build_ipv6_with_ext_header(REMOTE_IP, LOCAL_IP, IpProtocols::Tcp, 64, &[0; 20]);
        let eth_len = size_of::<EthernetFrame>();
        let start = eth_len + IPV6_HEADER_LEN;
        let nh_offset = eth_len + 6;

        match walk_extension_headers(&buf, EXT_HOP_BY_HOP, start, nh_offset) {
            NextHeaderResult::Protocol {
                protocol,
                payload_offset,
                next_header_offset,
            } => {
                assert_eq!(protocol, IpProtocols::Tcp);
                assert_eq!(payload_offset, start + 8);
                // The ext header's Next Header field is at the start of the ext header.
                assert_eq!(next_header_offset, start);
            }
            _ => panic!("expected Protocol"),
        }
    }

    #[test]
    fn walk_fragment_returns_fragment() {
        let buf = build_ipv6_with_fragment(REMOTE_IP, LOCAL_IP, IpProtocols::Udp, 0, true, &[0; 8]);
        let eth_len = size_of::<EthernetFrame>();
        let start = eth_len + IPV6_HEADER_LEN;

        match walk_extension_headers(&buf, EXT_FRAGMENT, start, eth_len + 6) {
            NextHeaderResult::Fragment => {}
            _ => panic!("expected Fragment"),
        }
    }

    #[test]
    fn walk_no_next_header() {
        let buf = build_ipv6_frame(REMOTE_IP, LOCAL_IP, NO_NEXT_HEADER, 64, &[]);
        let eth_len = size_of::<EthernetFrame>();
        let start = eth_len + IPV6_HEADER_LEN;

        match walk_extension_headers(&buf, NO_NEXT_HEADER, start, eth_len + 6) {
            NextHeaderResult::NoPayload => {}
            _ => panic!("expected NoPayload"),
        }
    }

    #[test]
    fn walk_truncated_extension_is_malformed() {
        let eth_len = size_of::<EthernetFrame>();
        let mut buf = vec![0u8; eth_len + IPV6_HEADER_LEN + 2];
        buf[12] = 0x86;
        buf[13] = 0xDD;
        buf[14] = 0x60;
        let payload_len = 2u16;
        buf[18..20].copy_from_slice(&payload_len.to_be_bytes());
        buf[20] = EXT_HOP_BY_HOP;
        buf[21] = 64;

        let ext_start = eth_len + IPV6_HEADER_LEN;
        buf[ext_start] = IpProtocols::Udp;
        buf[ext_start + 1] = 0;

        match walk_extension_headers(&buf, EXT_HOP_BY_HOP, ext_start, eth_len + 6) {
            NextHeaderResult::Malformed => {}
            _ => panic!("expected Malformed"),
        }
    }

    #[test]
    fn frame_too_short_goes_to_rx() {
        let mut handler = new_handler();
        let mut nh = new_neighbor_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = [0u8; 50];
        let frame = Frame::new(0, &mut data, 50, false);

        handler.handle(frame, &mut nh, &mut PmtuCache::new(), &mut rx, &mut tx);
        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn wrong_version_goes_to_rx() {
        let mut handler = new_handler();
        let mut nh = new_neighbor_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = build_ipv6_frame(REMOTE_IP, LOCAL_IP, IpProtocols::Udp, 64, &[0; 8]);
        data[14] = (data[14] & 0x0F) | 0x40;

        let len = data.len();
        let frame = Frame::new(0, &mut data, len, false);

        handler.handle(frame, &mut nh, &mut PmtuCache::new(), &mut rx, &mut tx);
        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn fragment_dropped() {
        let mut handler = new_handler();
        let mut nh = new_neighbor_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data =
            build_ipv6_with_fragment(REMOTE_IP, LOCAL_IP, IpProtocols::Udp, 0, true, &[0; 8]);
        let len = data.len();
        let frame = Frame::new(0, &mut data, len, false);

        handler.handle(frame, &mut nh, &mut PmtuCache::new(), &mut rx, &mut tx);
        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn icmpv6_echo_request_generates_reply() {
        use super::icmpv6::{Icmpv6Types, compute_icmpv6_checksum};

        let mut handler = new_handler();
        let mut nh = new_neighbor_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let eth_len = size_of::<EthernetFrame>();
        let icmpv6_len = 8 + 8; // header + 8 bytes data
        let frame_len = eth_len + IPV6_HEADER_LEN + icmpv6_len;
        let mut data = vec![0u8; 512];

        // Ethernet
        data[12] = 0x86;
        data[13] = 0xDD;

        // IPv6
        data[14] = 0x60;
        data[18..20].copy_from_slice(&(icmpv6_len as u16).to_be_bytes());
        data[20] = IpProtocols::IcmpV6;
        data[21] = 64;
        let src_bytes: [u8; 16] = REMOTE_IP.into();
        data[22..38].copy_from_slice(&src_bytes);
        let dst_bytes: [u8; 16] = LOCAL_IP.into();
        data[38..54].copy_from_slice(&dst_bytes);

        // ICMPv6 Echo Request
        let icmp_off = eth_len + IPV6_HEADER_LEN;
        data[icmp_off] = Icmpv6Types::EchoRequest;
        let cksum = compute_icmpv6_checksum(
            &REMOTE_IP,
            &LOCAL_IP,
            &data[icmp_off..icmp_off + icmpv6_len],
        );
        data[icmp_off + 2] = cksum[0];
        data[icmp_off + 3] = cksum[1];

        let frame = Frame::new(0, &mut data, frame_len, false);
        handler.handle(frame, &mut nh, &mut PmtuCache::new(), &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 0);
        assert_eq!(tx.num_frames(), 1);
    }

    #[test]
    fn valid_tcp_accepted() {
        let mut handler = new_handler();
        let mut nh = new_neighbor_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = build_ipv6_frame(REMOTE_IP, LOCAL_IP, IpProtocols::Tcp, 64, &[0; 20]);
        let len = data.len();
        let frame = Frame::new(0, &mut data, len, false);

        handler.handle(frame, &mut nh, &mut PmtuCache::new(), &mut rx, &mut tx);
        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn valid_udp_accepted() {
        let mut handler = new_handler();
        let mut nh = new_neighbor_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = build_ipv6_frame(REMOTE_IP, LOCAL_IP, IpProtocols::Udp, 64, &[0; 8]);
        let len = data.len();
        let frame = Frame::new(0, &mut data, len, false);

        handler.handle(frame, &mut nh, &mut PmtuCache::new(), &mut rx, &mut tx);
        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn unknown_protocol_sends_parameter_problem() {
        let mut handler = new_handler();
        let mut nh = new_neighbor_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let raw = build_ipv6_frame(REMOTE_IP, LOCAL_IP, 255, 64, &[0; 8]);
        let mut data = vec![0u8; 2048];
        data[..raw.len()].copy_from_slice(&raw);
        let frame = Frame::new(0, &mut data, raw.len(), false);

        handler.handle(frame, &mut nh, &mut PmtuCache::new(), &mut rx, &mut tx);
        assert_eq!(rx.num_frames(), 0);
        assert_eq!(tx.num_frames(), 1);
    }

    #[test]
    fn extension_header_then_udp() {
        let mut handler = new_handler();
        let mut nh = new_neighbor_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data =
            build_ipv6_with_ext_header(REMOTE_IP, LOCAL_IP, IpProtocols::Udp, 64, &[0; 8]);
        let len = data.len();
        let frame = Frame::new(0, &mut data, len, false);

        handler.handle(frame, &mut nh, &mut PmtuCache::new(), &mut rx, &mut tx);
        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn no_next_header_goes_to_rx() {
        let mut handler = new_handler();
        let mut nh = new_neighbor_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = build_ipv6_frame(REMOTE_IP, LOCAL_IP, NO_NEXT_HEADER, 64, &[]);
        let len = data.len();
        let frame = Frame::new(0, &mut data, len, false);

        handler.handle(frame, &mut nh, &mut PmtuCache::new(), &mut rx, &mut tx);
        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }
}
