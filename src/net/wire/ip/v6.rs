use std::fmt::Display;

use super::{IpProtocol, Ipv6Address, ethernet::EthernetFrame};

/// Fixed IPv6 header length in bytes (always 40, no variable-length header).
pub const IPV6_HEADER_LEN: usize = 40;

/// Compile-time guarantee that our struct matches the wire size.
const _: () = assert!(size_of::<Ipv6Header>() == IPV6_HEADER_LEN);

/// Minimum Ethernet + IPv6 frame length.
pub const IPV6_MIN_FRAME_LEN: usize = size_of::<EthernetFrame>() + IPV6_HEADER_LEN;

/// Hop-by-Hop Options extension header.
pub const EXT_HOP_BY_HOP: u8 = 0;
/// Routing extension header.
pub const EXT_ROUTING: u8 = 43;
/// Fragment extension header.
pub const EXT_FRAGMENT: u8 = 44;
/// Authentication Header.
pub const EXT_AH: u8 = 51;
/// Destination Options extension header.
pub const EXT_DESTINATION: u8 = 60;
/// No Next Header.
pub const NO_NEXT_HEADER: u8 = 59;

/// Fragment extension header length (always 8 bytes).
pub const FRAGMENT_EXT_LEN: usize = 8;

/// Compile-time guarantee that our struct matches the wire size.
const _: () = assert!(size_of::<Ipv6FragmentHeader>() == FRAGMENT_EXT_LEN);

/// IPv6 Fragment Extension Header wire format (8 bytes, RFC 8200 §4.5).
///
/// `#[repr(C, packed)]` allows zero-copy casting from raw frame memory.
///
/// Layout:
/// - `next_header` (1 byte): identifies the upper-layer protocol.
/// - `reserved` (1 byte): must be zero.
/// - `fragment_offset_mf` (2 bytes): 13-bit offset in 8-byte units,
///   2 reserved bits, and 1 MF (More Fragments) bit.
/// - `identification` (4 bytes): unique datagram identifier.
#[repr(C, packed)]
pub struct Ipv6FragmentHeader {
    /// Next Header type after reassembly (e.g. 17 for UDP, 6 for TCP).
    pub next_header: u8,
    /// Reserved field, must be zero on transmit.
    pub reserved: u8,
    /// Fragment Offset (13 bits) | Reserved (2 bits) | MF (1 bit), network byte order.
    pub fragment_offset_mf: [u8; 2],
    /// Identification field for reassembly, network byte order.
    pub identification: [u8; 4],
}

impl Ipv6FragmentHeader {
    /// Returns the fragment offset in 8-byte units.
    #[inline]
    pub const fn fragment_offset(&self) -> u16 {
        u16::from_be_bytes(self.fragment_offset_mf) >> 3
    }

    /// Returns `true` if the More Fragments (MF) bit is set.
    #[inline]
    pub const fn more_fragments(&self) -> bool {
        self.fragment_offset_mf[1] & 0x01 != 0
    }

    /// Returns the 32-bit identification field.
    #[inline]
    pub const fn identification(&self) -> u32 {
        u32::from_be_bytes(self.identification)
    }

    /// Returns `true` if this header represents a fragment.
    ///
    /// A packet is a fragment if MF is set or the fragment offset is non-zero.
    #[inline]
    pub const fn is_fragment(&self) -> bool {
        let combined = u16::from_be_bytes(self.fragment_offset_mf);
        // offset bits (top 13) or MF bit (bottom 1) set
        (combined & 0xFFF9) != 0
    }

    /// Sets the fragment_offset_mf field from an offset (in 8-byte units) and MF flag.
    #[inline]
    pub const fn set_fragment_offset_mf(&mut self, offset_units: u16, more_fragments: bool) {
        let mf: u16 = if more_fragments { 1 } else { 0 };
        let value = (offset_units << 3) | mf;
        self.fragment_offset_mf = value.to_be_bytes();
    }

    /// Zero-copy borrow from a byte slice at the given offset.
    ///
    /// # Safety
    ///
    /// The caller must ensure `bytes.len() >= offset + FRAGMENT_EXT_LEN`.
    #[inline]
    pub fn from_bytes_at(bytes: &[u8], offset: usize) -> &Self {
        assert!(bytes.len() >= offset + FRAGMENT_EXT_LEN);
        unsafe { &*(bytes.as_ptr().add(offset) as *const Self) }
    }

    /// Mutable zero-copy borrow from a byte slice at the given offset.
    ///
    /// # Safety
    ///
    /// The caller must ensure `bytes.len() >= offset + FRAGMENT_EXT_LEN`.
    #[inline]
    pub fn from_bytes_at_mut(bytes: &mut [u8], offset: usize) -> &mut Self {
        assert!(bytes.len() >= offset + FRAGMENT_EXT_LEN);
        unsafe { &mut *(bytes.as_mut_ptr().add(offset) as *mut Self) }
    }
}

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
    pub fn from_bytes(bytes: &[u8]) -> &Self {
        assert!(bytes.len() >= IPV6_MIN_FRAME_LEN);
        unsafe { &*(bytes.as_ptr().add(size_of::<EthernetFrame>()) as *const Self) }
    }

    /// Mutable zero-copy borrow of the IPv6 header from a received frame.
    ///
    /// # Safety
    ///
    /// The caller must ensure `frame.len() >= IPV6_MIN_FRAME_LEN`.
    #[inline]
    pub fn from_bytes_mut(bytes: &mut [u8]) -> &mut Self {
        assert!(bytes.len() >= IPV6_MIN_FRAME_LEN);
        unsafe { &mut *(bytes.as_mut_ptr().add(size_of::<EthernetFrame>()) as *mut Self) }
    }
}

impl Display for Ipv6Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Ipv6Header {{ version: {}, traffic_class: {}, flow_label: {}, payload_length: {}, next_header: {}, hop_limit: {}, src_addr: {}, dst_addr: {} }}",
            self.version(),
            self.traffic_class(),
            self.flow_label(),
            self.payload_length(),
            IpProtocol(self.next_header),
            self.hop_limit,
            self.src_addr,
            self.dst_addr
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_accessors_zeroed() {
        let hdr = Ipv6Header {
            version_tc_fl: [0x60, 0x00, 0x00, 0x00],
            payload_length: [0x00, 0x00],
            next_header: 59, // No Next Header
            hop_limit: 255,
            src_addr: Ipv6Address::unspecified(),
            dst_addr: Ipv6Address::loopback(),
        };
        assert_eq!(hdr.version(), 6);
        assert_eq!(hdr.traffic_class(), 0);
        assert_eq!(hdr.flow_label(), 0);
        assert_eq!(hdr.payload_length(), 0);
    }

    #[test]
    fn header_accessors_with_tc_and_fl() {
        // version=6, tc=0xAB, fl=0xCDEF0
        // byte[0] = 0110_1010 = 0x6A
        // byte[1] = 1011_1100 = 0xBC
        // byte[2] = 1101_1110 = 0xDE
        // byte[3] = 1111_0000 = 0xF0
        let hdr = Ipv6Header {
            version_tc_fl: [0x6A, 0xBC, 0xDE, 0xF0],
            payload_length: [0x00, 0x20], // 32
            next_header: 17,
            hop_limit: 64,
            src_addr: Ipv6Address::unspecified(),
            dst_addr: Ipv6Address::loopback(),
        };
        assert_eq!(hdr.version(), 6);
        assert_eq!(hdr.traffic_class(), 0xAB);
        assert_eq!(hdr.flow_label(), 0xCDEF0);
        assert_eq!(hdr.payload_length(), 32);
    }

    #[test]
    fn header_layout() {
        assert_eq!(IPV6_HEADER_LEN, 40);
        assert_eq!(IPV6_MIN_FRAME_LEN, 54);
    }

    #[test]
    fn fragment_header_layout() {
        assert_eq!(FRAGMENT_EXT_LEN, 8);
        assert_eq!(size_of::<Ipv6FragmentHeader>(), 8);
    }

    #[test]
    fn fragment_header_offset_zero_mf_set() {
        let hdr = Ipv6FragmentHeader {
            next_header: 17,
            reserved: 0,
            fragment_offset_mf: [0x00, 0x01], // offset=0, MF=1
            identification: [0x00, 0x00, 0x00, 0x42],
        };
        assert_eq!(hdr.fragment_offset(), 0);
        assert!(hdr.more_fragments());
        assert_eq!(hdr.identification(), 0x42);
        assert!(hdr.is_fragment());
    }

    #[test]
    fn fragment_header_offset_nonzero_mf_clear() {
        let hdr = Ipv6FragmentHeader {
            next_header: 17,
            reserved: 0,
            fragment_offset_mf: [0x00, 0x08], // offset=1 (1<<3=8), MF=0
            identification: [0x00, 0x00, 0x01, 0x00],
        };
        assert_eq!(hdr.fragment_offset(), 1);
        assert!(!hdr.more_fragments());
        assert_eq!(hdr.identification(), 256);
        assert!(hdr.is_fragment());
    }

    #[test]
    fn fragment_header_not_fragment() {
        let hdr = Ipv6FragmentHeader {
            next_header: 17,
            reserved: 0,
            fragment_offset_mf: [0x00, 0x00], // offset=0, MF=0
            identification: [0x00, 0x00, 0x00, 0x01],
        };
        assert_eq!(hdr.fragment_offset(), 0);
        assert!(!hdr.more_fragments());
        assert!(!hdr.is_fragment());
    }

    #[test]
    fn fragment_header_set_offset_mf() {
        let mut hdr = Ipv6FragmentHeader {
            next_header: 17,
            reserved: 0,
            fragment_offset_mf: [0, 0],
            identification: [0; 4],
        };

        hdr.set_fragment_offset_mf(185, true); // offset=185, MF=1
        assert_eq!(hdr.fragment_offset(), 185);
        assert!(hdr.more_fragments());

        hdr.set_fragment_offset_mf(370, false); // offset=370, MF=0
        assert_eq!(hdr.fragment_offset(), 370);
        assert!(!hdr.more_fragments());
    }

    #[test]
    fn fragment_header_from_bytes() {
        let mut buf = [0u8; 16];
        buf[4] = 17; // next_header
        buf[6] = 0x05; // fragment_offset_mf high
        buf[7] = 0xC9; // fragment_offset_mf low: offset = 0x05C9>>3 = 185, MF=1
        buf[8..12].copy_from_slice(&42u32.to_be_bytes());

        let hdr = Ipv6FragmentHeader::from_bytes_at(&buf, 4);
        assert_eq!(hdr.next_header, 17);
        assert_eq!(hdr.fragment_offset(), 185);
        assert!(hdr.more_fragments());
        assert_eq!(hdr.identification(), 42);
    }

    #[test]
    fn fragment_header_from_bytes_mut() {
        let mut buf = [0u8; 16];
        let hdr = Ipv6FragmentHeader::from_bytes_at_mut(&mut buf, 4);
        hdr.next_header = 6;
        hdr.set_fragment_offset_mf(100, false);
        hdr.identification = 999u32.to_be_bytes();

        let hdr = Ipv6FragmentHeader::from_bytes_at(&buf, 4);
        assert_eq!(hdr.next_header, 6);
        assert_eq!(hdr.fragment_offset(), 100);
        assert!(!hdr.more_fragments());
        assert_eq!(hdr.identification(), 999);
    }
}
