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
}
