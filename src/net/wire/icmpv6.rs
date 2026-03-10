use super::{
    ethernet::EthernetFrame,
    ip::{IPV6_HEADER_LEN, Ipv6Header},
};

/// ICMPv6 header length in bytes (type + code + checksum + body).
pub const ICMPV6_HEADER_LEN: usize = 8;

const _: () = assert!(size_of::<Icmpv6Header>() == ICMPV6_HEADER_LEN);

/// Minimum IPv6 MTU per RFC 2460.
const IPV6_MIN_MTU: usize = 1280;

/// Maximum bytes of the original packet that can be included in an
/// ICMPv6 error payload without exceeding the minimum IPv6 MTU.
/// 1280 (min MTU) - 40 (IPv6 header) - 8 (ICMPv6 header) = 1232.
pub const MAX_ERROR_PAYLOAD: usize = IPV6_MIN_MTU - IPV6_HEADER_LEN - ICMPV6_HEADER_LEN;

/// ICMPv6 header wire format (8 bytes).
///
/// The `body` field is type-dependent:
/// * Echo Request/Reply: identifier (2 bytes) + sequence number (2 bytes)
/// * Destination Unreachable: unused (4 bytes)
/// * Packet Too Big: MTU (4 bytes, network byte order)
/// * Time Exceeded: unused (4 bytes)
/// * Parameter Problem: pointer (4 bytes, network byte order)
#[repr(C, packed)]
pub struct Icmpv6Header {
    /// ICMP type.
    pub icmp_type: u8,
    /// ICMP code.
    pub code: u8,
    /// ICMP checksum.
    pub checksum: [u8; 2],
    /// Body.
    pub body: [u8; 4],
}

impl Icmpv6Header {
    /// Returns the raw bytes of this header.
    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }

    /// Zero-copy borrow of the ICMPv6 header at the given byte offset in a frame.
    ///
    /// The caller must ensure `offset + ICMPV6_HEADER_LEN <= frame.len()`.
    #[inline(always)]
    pub fn from_bytes_at(bytes: &[u8], offset: usize) -> &Self {
        debug_assert!(offset + ICMPV6_HEADER_LEN <= bytes.len());
        unsafe { &*(bytes.as_ptr().add(offset) as *const Self) }
    }

    /// Mutable zero-copy borrow of the ICMPv6 header at the given byte offset.
    ///
    /// The caller must ensure `offset + ICMPV6_HEADER_LEN <= frame.len()`.
    #[inline(always)]
    pub fn from_bytes_at_mut(bytes: &mut [u8], offset: usize) -> &mut Self {
        debug_assert!(offset + ICMPV6_HEADER_LEN <= bytes.len());
        unsafe { &mut *(bytes.as_mut_ptr().add(offset) as *mut Self) }
    }

    /// Returns the body field as a big-endian `u32`.
    ///
    /// The interpretation depends on the ICMPv6 type:
    /// * Packet Too Big: MTU
    /// * Parameter Problem: pointer to the offending field
    /// * Destination Unreachable / Time Exceeded: unused (zero)
    #[inline]
    pub fn body_as_u32(&self) -> u32 {
        u32::from_be_bytes(self.body)
    }
}

/// ICMPv6 types.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod Icmpv6Types {
    /// Destination Unreachable.
    pub const DestinationUnreachable: u8 = 1;
    /// Packet Too Big.
    pub const PacketTooBig: u8 = 2;
    /// Time Exceeded.
    pub const TimeExceeded: u8 = 3;
    /// Parameter Problem.
    pub const ParameterProblem: u8 = 4;
    /// Echo Request.
    pub const EchoRequest: u8 = 128;
    /// Echo Reply.
    pub const EchoReply: u8 = 129;
    /// Router Solicitation.
    pub const RouterSolicitation: u8 = 133;
    /// Router Advertisement.
    pub const RouterAdvertisement: u8 = 134;
    /// Neighbor Solicitation.
    pub const NeighborSolicitation: u8 = 135;
    /// Neighbor Advertisement.
    pub const NeighborAdvertisement: u8 = 136;
    /// Redirect.
    pub const Redirect: u8 = 137;
}

/// ICMPv6 codes.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod Icmpv6Codes {
    /// No Route To Destination.
    pub const NoRouteToDestination: u8 = 0;
    /// Admin Prohibited.
    pub const AdminProhibited: u8 = 1;
    /// Beyond Scope.
    pub const BeyondScope: u8 = 2;
    /// Address Unreachable.
    pub const AddressUnreachable: u8 = 3;
    /// Port Unreachable.
    pub const PortUnreachable: u8 = 4;
    /// Erroneous Header Field.
    pub const ErroneousHeaderField: u8 = 0;
    /// Unrecognized Next Header.
    pub const UnrecognizedNextHeader: u8 = 1;
    /// Unrecognized Option.
    pub const UnrecognizedOption: u8 = 2;
}

/// Ethernet + IPv6 + ICMPv6 header frame overlay.
///
/// Used for building ICMPv6 responses where no IPv6 extension headers
/// are present. Any ICMPv6 payload follows immediately after.
#[repr(C, packed)]
pub struct Icmpv6Frame {
    pub ethernet: EthernetFrame,
    pub ipv6: Ipv6Header,
    pub icmpv6: Icmpv6Header,
}

/// Minimum frame length for Ethernet + IPv6 + ICMPv6 header.
pub const ICMPV6_FRAME_LEN: usize = size_of::<Icmpv6Frame>();
const _: () = assert!(ICMPV6_FRAME_LEN == 62); // 14 + 40 + 8

impl Icmpv6Frame {
    /// Mutable zero-copy borrow of the Ethernet + IPv6 + ICMPv6 headers.
    ///
    /// The caller must ensure `frame.len() >= ICMPV6_FRAME_LEN`.
    #[inline(always)]
    pub fn from_bytes_mut(bytes: &mut [u8]) -> &mut Self {
        debug_assert!(bytes.len() >= ICMPV6_FRAME_LEN);
        unsafe { &mut *(bytes.as_mut_ptr() as *mut Self) }
    }
}

/// Returns `true` if the ICMPv6 type is an error message.
///
/// Per RFC 4443 §2.4, ICMPv6 error messages have types in the range
/// 0--127. Informational messages occupy 128--255.
#[inline]
pub fn is_icmpv6_error(icmpv6_type: u8) -> bool {
    icmpv6_type < 128
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_icmpv6_error_boundary() {
        // Error types (0-127)
        assert!(is_icmpv6_error(0));
        assert!(is_icmpv6_error(127));
        assert!(is_icmpv6_error(Icmpv6Types::DestinationUnreachable));
        assert!(is_icmpv6_error(Icmpv6Types::PacketTooBig));
        assert!(is_icmpv6_error(Icmpv6Types::TimeExceeded));
        assert!(is_icmpv6_error(Icmpv6Types::ParameterProblem));

        // Informational types (128-255)
        assert!(!is_icmpv6_error(128));
        assert!(!is_icmpv6_error(255));
        assert!(!is_icmpv6_error(Icmpv6Types::EchoRequest));
        assert!(!is_icmpv6_error(Icmpv6Types::EchoReply));
        assert!(!is_icmpv6_error(Icmpv6Types::NeighborSolicitation));
    }

    #[test]
    fn max_error_payload_value() {
        // 1280 (min MTU) - 40 (IPv6 hdr) - 8 (ICMPv6 hdr)
        assert_eq!(MAX_ERROR_PAYLOAD, 1232);
    }

    #[test]
    fn icmpv6_header_layout() {
        assert_eq!(ICMPV6_HEADER_LEN, 8);
        assert_eq!(size_of::<Icmpv6Header>(), 8);
    }

    #[test]
    fn icmpv6_frame_layout() {
        assert_eq!(ICMPV6_FRAME_LEN, 62); // 14 + 40 + 8
    }

    #[test]
    fn body_as_u32_parsing() {
        let hdr = Icmpv6Header {
            icmp_type: Icmpv6Types::PacketTooBig,
            code: 0,
            checksum: [0, 0],
            body: 1280u32.to_be_bytes(),
        };
        assert_eq!(hdr.body_as_u32(), 1280);
    }
}
