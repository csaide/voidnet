use crate::net::wire::{
    ip::{IpProtocols, Ipv4Address, Ipv6Address},
    tcp::TCP_HEADER_LEN,
};

use super::{
    checksum_to_bytes, fold_and_verify, fold_checksum, pseudo_header_sum_v4, pseudo_header_sum_v6,
    sum_words,
};

/// Computes the UDP checksum over the IPv4 pseudo-header and full UDP segment.
///
/// Per RFC 768, the checksum covers a pseudo-header (src IP, dst IP,
/// zero, protocol, UDP length) concatenated with the UDP header and data.
///
/// `udp_segment` must contain the full UDP header + payload with the
/// checksum field set to zero.
///
/// Returns the two-byte checksum in network byte order. If the computed
/// checksum is zero, returns `[0xFF, 0xFF]` per RFC 768 (a transmitted
/// checksum of zero means "no checksum").
#[inline]
pub fn compute_udp_checksum(
    src_addr: &Ipv4Address,
    dst_addr: &Ipv4Address,
    udp_segment: &[u8],
) -> [u8; 2] {
    let sum = pseudo_header_sum_v4(
        src_addr,
        dst_addr,
        IpProtocols::Udp,
        udp_segment.len() as u16,
    ) + sum_words(udp_segment);
    checksum_to_bytes(fold_checksum(sum))
}

/// Computes the UDP checksum over the IPv6 pseudo-header and full UDP segment.
///
/// Per RFC 2460 s8.1, the pseudo-header for IPv6 contains:
/// source address (16), destination address (16), UDP length as u32 (4),
/// three zero bytes (3), and next header = 17 (1) -- totalling 40 bytes.
///
/// Unlike IPv4, the UDP checksum is **mandatory** for IPv6 -- a zero
/// checksum is not permitted on transmit.
///
/// `udp_segment` must contain the full UDP header + payload with the
/// checksum field set to zero.
///
/// Returns the two-byte checksum in network byte order.
#[inline]
pub fn compute_udp_checksum_v6(
    src_addr: &Ipv6Address,
    dst_addr: &Ipv6Address,
    udp_segment: &[u8],
) -> [u8; 2] {
    let sum = pseudo_header_sum_v6(
        src_addr,
        dst_addr,
        IpProtocols::Udp,
        udp_segment.len() as u32,
    ) + sum_words(udp_segment);
    checksum_to_bytes(fold_checksum(sum))
}

/// Computes the TCP checksum over the IPv4 pseudo-header and full TCP segment.
///
/// `tcp_segment` must contain the full TCP header + payload with the
/// checksum field set to zero.
#[inline]
pub fn compute_tcp_checksum(
    src_addr: &Ipv4Address,
    dst_addr: &Ipv4Address,
    tcp_segment: &[u8],
) -> [u8; 2] {
    let sum = pseudo_header_sum_v4(
        src_addr,
        dst_addr,
        IpProtocols::Tcp,
        tcp_segment.len() as u16,
    ) + sum_words(tcp_segment);
    checksum_to_bytes(fold_checksum(sum))
}

/// Computes the TCP checksum over the IPv6 pseudo-header and full TCP segment.
///
/// `tcp_segment` must contain the full TCP header + payload with the
/// checksum field set to zero.
#[inline]
pub fn compute_tcp_checksum_v6(
    src_addr: &Ipv6Address,
    dst_addr: &Ipv6Address,
    tcp_segment: &[u8],
) -> [u8; 2] {
    let sum = pseudo_header_sum_v6(
        src_addr,
        dst_addr,
        IpProtocols::Tcp,
        tcp_segment.len() as u32,
    ) + sum_words(tcp_segment);
    checksum_to_bytes(fold_checksum(sum))
}

/// Verifies the TCP checksum for an IPv4 packet.
///
/// Returns `true` if the one's complement sum of the pseudo-header and
/// full TCP segment yields the expected result. A zero checksum field
/// is **invalid** for TCP and will cause this to return `false`.
///
/// Uses inclusive verification (sums everything including the checksum
/// field) to avoid mutating the frame buffer.
#[inline]
pub fn verify_tcp_checksum(
    src_addr: &Ipv4Address,
    dst_addr: &Ipv4Address,
    tcp_segment: &[u8],
) -> bool {
    if tcp_segment.len() < TCP_HEADER_LEN {
        return false;
    }
    // TCP checksum is mandatory — zero is invalid.
    if tcp_segment[16] == 0 && tcp_segment[17] == 0 {
        return false;
    }
    let sum = pseudo_header_sum_v4(
        src_addr,
        dst_addr,
        IpProtocols::Tcp,
        tcp_segment.len() as u16,
    ) + sum_words(tcp_segment);
    fold_and_verify(sum, 0x0000)
}

/// Verifies the TCP checksum for an IPv6 packet.
///
/// Returns `true` if the one's complement sum of the pseudo-header and
/// full TCP segment yields the expected result. A zero checksum field
/// is **invalid** and will cause this to return `false`.
///
/// Uses inclusive verification (sums everything including the checksum
/// field) to avoid mutating the frame buffer.
#[inline]
pub fn verify_tcp_checksum_v6(
    src_addr: &Ipv6Address,
    dst_addr: &Ipv6Address,
    tcp_segment: &[u8],
) -> bool {
    if tcp_segment.len() < TCP_HEADER_LEN {
        return false;
    }
    // TCP checksum is mandatory — zero is invalid.
    if tcp_segment[16] == 0 && tcp_segment[17] == 0 {
        return false;
    }
    let sum = pseudo_header_sum_v6(
        src_addr,
        dst_addr,
        IpProtocols::Tcp,
        tcp_segment.len() as u32,
    ) + sum_words(tcp_segment);
    fold_and_verify(sum, 0x0000)
}
