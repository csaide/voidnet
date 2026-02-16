use crate::xdp::frame::Frame;

use super::{Ipv6Address, ethernet::EthernetFrame};

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
}
