use super::ip::{IPV6_HEADER_LEN, IpProtocols, Ipv6Address};

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

/// Returns `true` if the ICMPv6 type is an error message.
///
/// Per RFC 4443 §2.4, ICMPv6 error messages have types in the range
/// 0--127. Informational messages occupy 128--255.
#[inline]
pub fn is_icmpv6_error(icmpv6_type: u8) -> bool {
    icmpv6_type < 128
}

/// Computes the ICMPv6 checksum per RFC 4443 §2.3.
///
/// The checksum covers an IPv6 pseudo-header (source address,
/// destination address, upper-layer packet length, next header = 58)
/// followed by the ICMPv6 message data.
///
/// When computing a fresh checksum, zero the checksum field in
/// `icmpv6_data` first. When verifying, pass the data as-is and
/// check for a `[0x00, 0x00]` result.
pub fn compute_icmpv6_checksum(
    src_addr: &Ipv6Address,
    dst_addr: &Ipv6Address,
    icmpv6_data: &[u8],
) -> [u8; 2] {
    let mut sum: u32 = 0;

    let src: [u8; 16] = (*src_addr).into();
    let mut i = 0;
    while i < 16 {
        sum += ((src[i] as u32) << 8) | (src[i + 1] as u32);
        i += 2;
    }

    let dst: [u8; 16] = (*dst_addr).into();
    i = 0;
    while i < 16 {
        sum += ((dst[i] as u32) << 8) | (dst[i + 1] as u32);
        i += 2;
    }

    let len = icmpv6_data.len() as u32;
    sum += (len >> 16) & 0xFFFF;
    sum += len & 0xFFFF;

    sum += IpProtocols::IcmpV6 as u32;

    i = 0;
    while i + 1 < icmpv6_data.len() {
        sum += ((icmpv6_data[i] as u32) << 8) | (icmpv6_data[i + 1] as u32);
        i += 2;
    }
    if i < icmpv6_data.len() {
        sum += (icmpv6_data[i] as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let checksum = !(sum as u16);
    checksum.to_be_bytes()
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
    fn compute_icmpv6_checksum_echo_request() {
        let src = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        // ICMPv6 Echo Request: type=128, code=0, checksum=0, id=1, seq=1
        let data = [0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01];
        let checksum = compute_icmpv6_checksum(&src, &dst, &data);
        assert_eq!(checksum, [0x82, 0xB6]);
    }

    #[test]
    fn icmpv6_checksum_verify_roundtrip() {
        let src = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let mut data = [0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01];

        let checksum = compute_icmpv6_checksum(&src, &dst, &data);
        data[2] = checksum[0];
        data[3] = checksum[1];

        // Recomputing over data with correct checksum should yield [0, 0]
        let verify = compute_icmpv6_checksum(&src, &dst, &data);
        assert_eq!(verify, [0x00, 0x00]);
    }

    #[test]
    fn icmpv6_checksum_odd_length_data() {
        let src = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        // 9 bytes: echo request header + 1 byte payload (odd length)
        let mut data = [0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0xAB];

        let checksum = compute_icmpv6_checksum(&src, &dst, &data);
        data[2] = checksum[0];
        data[3] = checksum[1];

        let verify = compute_icmpv6_checksum(&src, &dst, &data);
        assert_eq!(verify, [0x00, 0x00]);
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
}
