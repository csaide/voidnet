use crate::net::wire::ip::{IpProtocols, Ipv4Address, Ipv6Address};

use super::{
    checksum_to_bytes, fold_checksum, pseudo_header_sum_v4, pseudo_header_sum_v6, sum_words,
};

/// Computes the IPv4 header checksum per RFC 1071.
///
/// `header_bytes` must contain the full header with the checksum field
/// set to zero. Returns the two-byte checksum in network byte order.
#[inline]
pub fn compute_ipv4_checksum(header_bytes: &[u8]) -> [u8; 2] {
    let checksum = fold_checksum(sum_words(header_bytes));
    checksum.to_be_bytes()
}

/// Compute IPv4 UDP checksum without allocating (from port/payload parts).
#[inline]
pub fn compute_udp_checksum_from_parts(
    src_addr: &Ipv4Address,
    dst_addr: &Ipv4Address,
    src_port: u16,
    dst_port: u16,
    udp_len: u16,
    payload: &[u8],
) -> [u8; 2] {
    let sum = pseudo_header_sum_v4(src_addr, dst_addr, IpProtocols::Udp, udp_len)
        + src_port as u64
        + dst_port as u64
        + udp_len as u64
        // checksum field is zero, contributes nothing
        + sum_words(payload);
    checksum_to_bytes(fold_checksum(sum))
}

/// Compute IPv6 UDP checksum without allocating (from port/payload parts).
#[inline]
pub fn compute_udp_checksum_v6_from_parts(
    src_addr: &Ipv6Address,
    dst_addr: &Ipv6Address,
    src_port: u16,
    dst_port: u16,
    udp_len: u16,
    payload: &[u8],
) -> [u8; 2] {
    let sum = pseudo_header_sum_v6(src_addr, dst_addr, IpProtocols::Udp, udp_len as u32)
        + src_port as u64
        + dst_port as u64
        + udp_len as u64
        // checksum field is zero, contributes nothing
        + sum_words(payload);
    checksum_to_bytes(fold_checksum(sum))
}

/// Computes the ICMPv6 checksum per RFC 4443 s2.3.
///
/// The checksum covers an IPv6 pseudo-header (source address,
/// destination address, upper-layer packet length, next header = 58)
/// followed by the ICMPv6 message data.
///
/// When computing a fresh checksum, zero the checksum field in
/// `icmpv6_data` first. When verifying, pass the data as-is and
/// check for a `[0x00, 0x00]` result.
#[inline]
pub fn compute_icmpv6_checksum(
    src_addr: &Ipv6Address,
    dst_addr: &Ipv6Address,
    icmpv6_data: &[u8],
) -> [u8; 2] {
    let sum = pseudo_header_sum_v6(
        src_addr,
        dst_addr,
        IpProtocols::IcmpV6,
        icmpv6_data.len() as u32,
    ) + sum_words(icmpv6_data);
    let checksum = fold_checksum(sum);
    checksum.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use crate::net::{checksum::test_utils::*, wire::udp::UDP_HEADER_LEN};

    use super::*;

    #[test]
    fn ipv4_checksum_compute_and_verify() {
        let bytes: [u8; 20] = [
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xC0, 0xA8,
            0x01, 0x01, 0x0A, 0x00, 0x00, 0x01,
        ];
        let checksum = compute_ipv4_checksum(&bytes);
        assert_eq!(checksum, [0x6F, 0x1A]);

        let mut with_checksum = bytes;
        with_checksum[10] = checksum[0];
        with_checksum[11] = checksum[1];
        // Recomputing over the full header (including checksum) should yield [0, 0]
        assert_eq!(compute_ipv4_checksum(&with_checksum), [0x00, 0x00]);
    }

    #[test]
    fn udp_checksum_v4_compute_and_verify() {
        let src = Ipv4Address::new([192, 168, 1, 1]);
        let dst = Ipv4Address::new([10, 0, 0, 1]);
        let segment = [
            0x12, 0x34, // src port
            0x00, 0x35, // dst port
            0x00, 0x0C, // length = 12
            0x00, 0x00, // checksum (zeroed)
            0x01, 0x02, 0x03, 0x04, // payload
        ];

        let checksum = compute_udp_checksum(&src, &dst, &segment);
        assert_eq!(checksum, [0x1D, 0xBD]);
    }

    #[test]
    fn udp_checksum_v6_compute() {
        let src = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let segment = [
            0x12, 0x34, // src port
            0x00, 0x35, // dst port
            0x00, 0x0C, // length = 12
            0x00, 0x00, // checksum (zeroed)
            0x01, 0x02, 0x03, 0x04, // payload
        ];

        let checksum = compute_udp_checksum_v6(&src, &dst, &segment);
        assert_eq!(checksum, [0xEC, 0x62]);
    }

    #[test]
    fn from_parts_v4_matches_segment() {
        let src = Ipv4Address::new([192, 168, 1, 1]);
        let dst = Ipv4Address::new([10, 0, 0, 1]);
        let payload = [0x01, 0x02, 0x03, 0x04];
        let src_port: u16 = 0x1234;
        let dst_port: u16 = 53;
        let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;

        let segment = [
            0x12, 0x34, 0x00, 0x35, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
        ];
        let expected = compute_udp_checksum(&src, &dst, &segment);
        let actual =
            compute_udp_checksum_from_parts(&src, &dst, src_port, dst_port, udp_len, &payload);
        assert_eq!(actual, expected);
    }

    #[test]
    fn from_parts_v6_matches_segment() {
        let src = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let payload = [0x01, 0x02, 0x03, 0x04];
        let src_port: u16 = 0x1234;
        let dst_port: u16 = 53;
        let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;

        let segment = [
            0x12, 0x34, 0x00, 0x35, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
        ];
        let expected = compute_udp_checksum_v6(&src, &dst, &segment);
        let actual =
            compute_udp_checksum_v6_from_parts(&src, &dst, src_port, dst_port, udp_len, &payload);
        assert_eq!(actual, expected);
    }

    #[test]
    fn from_parts_v4_odd_payload() {
        let src = Ipv4Address::new([10, 0, 0, 1]);
        let dst = Ipv4Address::new([10, 0, 0, 2]);
        let payload = [0x01, 0x02, 0x03, 0x04, 0x05]; // odd
        let src_port: u16 = 8000;
        let dst_port: u16 = 9000;
        let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;

        let mut segment = Vec::with_capacity(UDP_HEADER_LEN + payload.len());
        segment.extend_from_slice(&src_port.to_be_bytes());
        segment.extend_from_slice(&dst_port.to_be_bytes());
        segment.extend_from_slice(&udp_len.to_be_bytes());
        segment.extend_from_slice(&[0u8; 2]);
        segment.extend_from_slice(&payload);

        let expected = compute_udp_checksum(&src, &dst, &segment);
        let actual =
            compute_udp_checksum_from_parts(&src, &dst, src_port, dst_port, udp_len, &payload);
        assert_eq!(actual, expected);
    }

    #[test]
    fn from_parts_v6_odd_payload() {
        let src = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let payload = [0x01, 0x02, 0x03, 0x04, 0x05]; // odd
        let src_port: u16 = 8000;
        let dst_port: u16 = 9000;
        let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;

        let mut segment = Vec::with_capacity(UDP_HEADER_LEN + payload.len());
        segment.extend_from_slice(&src_port.to_be_bytes());
        segment.extend_from_slice(&dst_port.to_be_bytes());
        segment.extend_from_slice(&udp_len.to_be_bytes());
        segment.extend_from_slice(&[0u8; 2]);
        segment.extend_from_slice(&payload);

        let expected = compute_udp_checksum_v6(&src, &dst, &segment);
        let actual =
            compute_udp_checksum_v6_from_parts(&src, &dst, src_port, dst_port, udp_len, &payload);
        assert_eq!(actual, expected);
    }

    #[test]
    fn tcp_checksum_v4_compute() {
        let src = Ipv4Address::new([192, 168, 1, 1]);
        let dst = Ipv4Address::new([10, 0, 0, 1]);
        let segment = [
            0x12, 0x34, // src port
            0x00, 0x50, // dst port (80)
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x02, // data offset=5, SYN
            0x72, 0x10, // window
            0x00, 0x00, // checksum (zeroed)
            0x00, 0x00, // urgent
        ];

        let checksum = compute_tcp_checksum(&src, &dst, &segment);
        assert_ne!(checksum, [0x00, 0x00]);
    }

    #[test]
    fn tcp_checksum_v6_compute() {
        let src = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let segment = [
            0x12, 0x34, // src port
            0x00, 0x50, // dst port
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x02, // data offset=5, SYN
            0x72, 0x10, // window
            0x00, 0x00, // checksum (zeroed)
            0x00, 0x00, // urgent
        ];

        let checksum = compute_tcp_checksum_v6(&src, &dst, &segment);
        assert_ne!(checksum, [0x00, 0x00]);
    }

    #[test]
    fn icmpv6_checksum_echo_request() {
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
}
