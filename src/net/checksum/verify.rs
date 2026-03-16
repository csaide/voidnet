use crate::net::wire::{
    ip::{IpProtocols, IpVersion, Ipv4Address},
    tcp::TCP_HEADER_LEN,
    udp::UDP_HEADER_LEN,
};

use super::{
    common::{fold_and_verify, sum_words},
    compute::compute_ipv4_checksum,
};

/// Verifies the IPv4 header checksum.
///
/// Returns `true` if the checksum is valid (the one's complement sum
/// of the entire header including the checksum field yields zero).
#[inline]
pub fn verify_ipv4_checksum(header_bytes: &[u8]) -> bool {
    compute_ipv4_checksum(header_bytes) == [0x00, 0x00]
}

/// Verifies the TCP checksum for any IP version using the `IpVersion` trait.
///
/// Returns `true` if the one's complement sum of the pseudo-header and
/// full TCP segment yields the expected result. A zero checksum field
/// is **invalid** for TCP and will cause this to return `false`.
#[inline]
pub fn verify_tcp_checksum_ip<V: IpVersion>(
    src_addr: &V::Address,
    dst_addr: &V::Address,
    tcp_segment: &[u8],
) -> bool {
    if tcp_segment.len() < TCP_HEADER_LEN {
        return false;
    }
    if tcp_segment[16] == 0 && tcp_segment[17] == 0 {
        return false;
    }
    let sum = V::pseudo_header_sum(
        src_addr,
        dst_addr,
        IpProtocols::Tcp,
        tcp_segment.len() as u32,
    ) + sum_words(tcp_segment);
    fold_and_verify(sum, 0x0000)
}

/// Verifies the UDP checksum for any IP version using the `IpVersion` trait.
///
/// Returns `false` if the checksum field is zero (callers that need the
/// IPv4 zero-means-no-checksum behavior should check before calling).
/// Returns `true` if the one's complement sum of the pseudo-header and
/// full UDP segment yields the expected result.
#[inline]
pub fn verify_udp_checksum_ip<V: IpVersion>(
    src_addr: &V::Address,
    dst_addr: &V::Address,
    udp_segment: &[u8],
) -> bool {
    if udp_segment.len() < UDP_HEADER_LEN {
        return false;
    }
    if udp_segment[6] == 0 && udp_segment[7] == 0 {
        return false;
    }
    let sum = V::pseudo_header_sum(
        src_addr,
        dst_addr,
        IpProtocols::Udp,
        udp_segment.len() as u32,
    ) + sum_words(udp_segment);
    fold_and_verify(sum, 0x0000)
}

/// Verifies the UDP checksum for an IPv4 packet.
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
    // IPv4 UDP: zero checksum means "no checksum" (RFC 768)
    if udp_segment.len() >= UDP_HEADER_LEN && udp_segment[6] == 0 && udp_segment[7] == 0 {
        return true;
    }
    verify_udp_checksum_ip::<crate::net::wire::ip::Ipv4>(src_addr, dst_addr, udp_segment)
}

#[cfg(test)]
mod tests {
    use crate::net::{
        checksum::test_utils::*,
        wire::ip::{Ipv4, Ipv4Address, Ipv6, Ipv6Address},
    };

    use super::*;

    #[test]
    fn ipv4_checksum_verify_valid() {
        let mut bytes: [u8; 20] = [
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xC0, 0xA8,
            0x01, 0x01, 0x0A, 0x00, 0x00, 0x01,
        ];
        let checksum = compute_ipv4_checksum(&bytes);
        bytes[10] = checksum[0];
        bytes[11] = checksum[1];
        assert!(verify_ipv4_checksum(&bytes));
    }

    #[test]
    fn ipv4_checksum_verify_rejects_bad() {
        let bytes: [u8; 20] = [
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x40, 0x00, 0x40, 0x11, 0xFF, 0xFF, 0xC0, 0xA8,
            0x01, 0x01, 0x0A, 0x00, 0x00, 0x01,
        ];
        assert!(!verify_ipv4_checksum(&bytes));
    }

    #[test]
    fn udp_v4_verify_valid() {
        let src = Ipv4Address::new([192, 168, 1, 1]);
        let dst = Ipv4Address::new([10, 0, 0, 1]);
        let mut segment = [
            0x12, 0x34, 0x00, 0x35, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
        ];
        let checksum = compute_udp_checksum(&src, &dst, &segment);
        segment[6] = checksum[0];
        segment[7] = checksum[1];
        assert!(verify_udp_checksum(&src, &dst, &segment));
    }

    #[test]
    fn udp_v4_zero_means_no_checksum() {
        let src = Ipv4Address::new([0; 4]);
        let dst = Ipv4Address::new([0; 4]);
        let segment = [0u8; 8];
        assert!(verify_udp_checksum(&src, &dst, &segment));
    }

    #[test]
    fn udp_v4_too_short() {
        let src = Ipv4Address::new([0; 4]);
        let dst = Ipv4Address::new([0; 4]);
        assert!(!verify_udp_checksum(&src, &dst, &[0; 7]));
    }

    #[test]
    fn udp_v4_rejects_bad_checksum() {
        let src = Ipv4Address::new([192, 168, 1, 1]);
        let dst = Ipv4Address::new([10, 0, 0, 1]);
        let segment = [
            0x12, 0x34, 0x00, 0x35, 0x00, 0x0C, 0xFF, 0xFF, 0x01, 0x02, 0x03, 0x04,
        ];
        assert!(!verify_udp_checksum(&src, &dst, &segment));
    }

    #[test]
    fn udp_v6_verify_valid() {
        let src = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let mut segment = [
            0x12, 0x34, 0x00, 0x35, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
        ];
        let checksum = compute_udp_checksum_v6(&src, &dst, &segment);
        segment[6] = checksum[0];
        segment[7] = checksum[1];
        assert!(verify_udp_checksum_ip::<Ipv6>(&src, &dst, &segment));
    }

    #[test]
    fn udp_v6_zero_is_invalid() {
        let src = Ipv6Address::new([0; 16]);
        let dst = Ipv6Address::new([0; 16]);
        let segment = [0u8; 8];
        assert!(!verify_udp_checksum_ip::<Ipv6>(&src, &dst, &segment));
    }

    #[test]
    fn udp_v6_too_short() {
        let src = Ipv6Address::new([0; 16]);
        let dst = Ipv6Address::new([0; 16]);
        assert!(!verify_udp_checksum_ip::<Ipv6>(&src, &dst, &[0; 7]));
    }

    #[test]
    fn udp_v6_odd_length_payload() {
        let src = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let mut segment = [
            0x12, 0x34, 0x00, 0x35, 0x00, 0x0D, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        ];
        let checksum = compute_udp_checksum_v6(&src, &dst, &segment);
        segment[6] = checksum[0];
        segment[7] = checksum[1];
        assert!(verify_udp_checksum_ip::<Ipv6>(&src, &dst, &segment));
    }

    #[test]
    fn tcp_v4_verify_valid() {
        let src = Ipv4Address::new([192, 168, 1, 1]);
        let dst = Ipv4Address::new([10, 0, 0, 1]);
        let mut segment = [
            0x12, 0x34, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
            0x72, 0x10, 0x00, 0x00, 0x00, 0x00,
        ];
        let checksum = compute_tcp_checksum(&src, &dst, &segment);
        segment[16] = checksum[0];
        segment[17] = checksum[1];
        assert!(verify_tcp_checksum_ip::<Ipv4>(&src, &dst, &segment));
    }

    #[test]
    fn tcp_v4_rejects_zero() {
        let src = Ipv4Address::new([0; 4]);
        let dst = Ipv4Address::new([0; 4]);
        let segment = [0u8; 20];
        assert!(!verify_tcp_checksum_ip::<Ipv4>(&src, &dst, &segment));
    }

    #[test]
    fn tcp_v4_rejects_bad() {
        let src = Ipv4Address::new([192, 168, 1, 1]);
        let dst = Ipv4Address::new([10, 0, 0, 1]);
        let segment = [
            0x12, 0x34, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
            0x72, 0x10, 0xFF, 0xFF, 0x00, 0x00,
        ];
        assert!(!verify_tcp_checksum_ip::<Ipv4>(&src, &dst, &segment));
    }

    #[test]
    fn tcp_v4_too_short() {
        let src = Ipv4Address::new([0; 4]);
        let dst = Ipv4Address::new([0; 4]);
        assert!(!verify_tcp_checksum_ip::<Ipv4>(&src, &dst, &[0; 19]));
    }

    #[test]
    fn tcp_v6_verify_valid() {
        let src = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let mut segment = [
            0x12, 0x34, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
            0x72, 0x10, 0x00, 0x00, 0x00, 0x00,
        ];
        let checksum = compute_tcp_checksum_v6(&src, &dst, &segment);
        segment[16] = checksum[0];
        segment[17] = checksum[1];
        assert!(verify_tcp_checksum_ip::<Ipv6>(&src, &dst, &segment));
    }

    #[test]
    fn tcp_v6_rejects_zero() {
        let src = Ipv6Address::new([0; 16]);
        let dst = Ipv6Address::new([0; 16]);
        let segment = [0u8; 20];
        assert!(!verify_tcp_checksum_ip::<Ipv6>(&src, &dst, &segment));
    }

    #[test]
    fn tcp_v6_too_short() {
        let src = Ipv6Address::new([0; 16]);
        let dst = Ipv6Address::new([0; 16]);
        assert!(!verify_tcp_checksum_ip::<Ipv6>(&src, &dst, &[0; 19]));
    }

    #[test]
    fn tcp_v6_odd_length_payload() {
        let src = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let mut segment = [
            0x12, 0x34, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x50, 0x18,
            0x72, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        ];
        let checksum = compute_tcp_checksum_v6(&src, &dst, &segment);
        segment[16] = checksum[0];
        segment[17] = checksum[1];
        assert!(verify_tcp_checksum_ip::<Ipv6>(&src, &dst, &segment));
    }
}
