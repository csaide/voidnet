use super::{ethernet::EthernetFrame, ip::Ipv4Header};

/// ICMPv4 header length in bytes (type + code + checksum + rest-of-header).
pub const ICMPV4_HEADER_LEN: usize = 8;

const _: () = assert!(size_of::<Icmpv4Header>() == ICMPV4_HEADER_LEN);

/// ICMPv4 header wire format (8 bytes).
///
/// The `rest_of_header` field is type-dependent:
/// * Echo Request/Reply: identifier (2 bytes) + sequence number (2 bytes)
/// * Destination Unreachable: unused (2 bytes) + next-hop MTU (2 bytes, code 4 only)
/// * Time Exceeded / Parameter Problem: unused (4 bytes)
#[repr(C, packed)]
pub struct Icmpv4Header {
    /// ICMP type.
    pub icmp_type: u8,
    /// ICMP code.
    pub code: u8,
    /// ICMP checksum.
    pub checksum: [u8; 2],
    /// Rest of the header.
    ///
    /// For Echo Request/Reply: identifier (2 bytes) + sequence number (2 bytes)
    /// For Destination Unreachable: unused (2 bytes) + next-hop MTU (2 bytes, code 4 only)
    /// For Time Exceeded / Parameter Problem: unused (4 bytes)
    pub rest_of_header: [u8; 4],
}

impl Icmpv4Header {
    /// Returns the raw bytes of this header.
    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }

    /// Zero-copy borrow of the ICMPv4 header at the given byte offset in a frame.
    ///
    /// The caller must ensure `offset + ICMPV4_HEADER_LEN <= frame.len()`.
    #[inline(always)]
    pub fn from_bytes_at(bytes: &[u8], offset: usize) -> &Self {
        debug_assert!(offset + ICMPV4_HEADER_LEN <= bytes.len());
        unsafe { &*(bytes.as_ptr().add(offset) as *const Self) }
    }

    /// Mutable zero-copy borrow of the ICMPv4 header at the given byte offset.
    ///
    /// The caller must ensure `offset + ICMPV4_HEADER_LEN <= frame.len()`.
    #[inline(always)]
    pub fn from_bytes_at_mut(bytes: &mut [u8], offset: usize) -> &mut Self {
        debug_assert!(offset + ICMPV4_HEADER_LEN <= bytes.len());
        unsafe { &mut *(bytes.as_mut_ptr().add(offset) as *mut Self) }
    }

    /// Returns the next-hop MTU from a Destination Unreachable / Fragmentation
    /// Needed message. Bytes 6-7 of the ICMP header (`rest_of_header[2..4]`)
    /// contain the next-hop MTU in network byte order.
    #[inline]
    pub fn next_hop_mtu(&self) -> u16 {
        u16::from_be_bytes([self.rest_of_header[2], self.rest_of_header[3]])
    }
}

/// ICMPv4 types.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod Icmpv4Types {
    /// Echo Reply.
    pub const EchoReply: u8 = 0;
    /// Destination Unreachable.
    pub const DestinationUnreachable: u8 = 3;
    /// Source Quench.
    pub const SourceQuench: u8 = 4;
    /// Redirect.
    pub const Redirect: u8 = 5;
    /// Echo Request.
    pub const EchoRequest: u8 = 8;
    /// Time Exceeded.
    pub const TimeExceeded: u8 = 11;
    /// Parameter Problem.
    pub const ParameterProblem: u8 = 12;
}

/// ICMPv4 codes.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod Icmpv4Codes {
    /// Protocol Unreachable.
    pub const ProtocolUnreachable: u8 = 2;
    /// Port Unreachable.
    pub const PortUnreachable: u8 = 3;
    /// Fragmentation Needed.
    pub const FragmentationNeeded: u8 = 4;
}

/// Returns `true` if the given ICMPv4 type is an error message.
///
/// Per RFC 1122, ICMP error messages MUST NOT be sent in response to
/// other ICMP error messages.
#[inline]
pub fn is_icmp_error(icmp_type: u8) -> bool {
    matches!(
        icmp_type,
        Icmpv4Types::DestinationUnreachable
            | Icmpv4Types::SourceQuench
            | Icmpv4Types::Redirect
            | Icmpv4Types::TimeExceeded
            | Icmpv4Types::ParameterProblem
    )
}

/// Ethernet + IPv4 (minimum header) + ICMPv4 header frame overlay.
///
/// Used for building ICMP responses where the IPv4 header has no options
/// (IHL = 5). Any ICMP payload follows immediately after.
#[repr(C, packed)]
pub struct Icmpv4Frame {
    pub ethernet: EthernetFrame,
    pub ipv4: Ipv4Header,
    pub icmpv4: Icmpv4Header,
}

/// Minimum frame length for Ethernet + IPv4 + ICMPv4 header.
pub const ICMPV4_FRAME_LEN: usize = size_of::<Icmpv4Frame>();
const _: () = assert!(ICMPV4_FRAME_LEN == 42);

impl Icmpv4Frame {
    /// Mutable zero-copy borrow of the Ethernet + IPv4 + ICMPv4 headers.
    ///
    /// The caller must ensure `frame.len() >= ICMPV4_FRAME_LEN`.
    #[inline(always)]
    pub fn from_bytes_mut(bytes: &mut [u8]) -> &mut Self {
        debug_assert!(bytes.len() >= ICMPV4_FRAME_LEN);
        unsafe { &mut *(bytes.as_mut_ptr() as *mut Self) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_icmp_error_classification() {
        // All error types return true
        assert!(is_icmp_error(Icmpv4Types::DestinationUnreachable));
        assert!(is_icmp_error(Icmpv4Types::SourceQuench));
        assert!(is_icmp_error(Icmpv4Types::Redirect));
        assert!(is_icmp_error(Icmpv4Types::TimeExceeded));
        assert!(is_icmp_error(Icmpv4Types::ParameterProblem));

        // Non-error types return false
        assert!(!is_icmp_error(Icmpv4Types::EchoReply));
        assert!(!is_icmp_error(Icmpv4Types::EchoRequest));
        assert!(!is_icmp_error(0xFF));
    }

    #[test]
    fn icmpv4_header_layout() {
        assert_eq!(ICMPV4_HEADER_LEN, 8);
        assert_eq!(size_of::<Icmpv4Header>(), 8);
    }

    #[test]
    fn icmpv4_frame_layout() {
        assert_eq!(ICMPV4_FRAME_LEN, 42); // 14 + 20 + 8
    }

    #[test]
    fn next_hop_mtu_parsing() {
        let hdr = Icmpv4Header {
            icmp_type: Icmpv4Types::DestinationUnreachable,
            code: Icmpv4Codes::FragmentationNeeded,
            checksum: [0, 0],
            rest_of_header: [0, 0, 0x05, 0x00], // MTU = 1280
        };
        assert_eq!(hdr.next_hop_mtu(), 1280);
    }
}
