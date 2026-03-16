use std::mem::size_of;

use super::addr::{IpAddress, Ipv4Address, Ipv6Address};
use super::proto::IpProtocols;
use super::v4::{IPV4_MIN_HEADER_LEN, Ipv4Header};
use super::v6::IPV6_HEADER_LEN;
use crate::net::checksum::{pseudo_header_sum_v4, pseudo_header_sum_v6};
use crate::net::wire::ethernet::{EtherType, EtherTypes, EthernetFrame};

const ETH_LEN: usize = size_of::<EthernetFrame>();

/// Zero-cost abstraction over IPv4 and IPv6 for generic network code.
///
/// Implementations are zero-sized types that monomorphize away, enabling
/// the compiler to generate specialized code for each IP version without
/// any runtime dispatch overhead.
pub trait IpVersion {
    type Address: Copy + Eq + Into<IpAddress>;

    const VERSION: u8;
    const ETHER_TYPE: EtherType;
    const IP_HEADER_LEN: usize;
    const VERSION_BYTE: u8;
    const NEXT_HEADER_OFFSET: usize;
    const TTL_OFFSET: usize;

    fn write_ip_header(
        frame: &mut [u8],
        src: &Self::Address,
        dst: &Self::Address,
        payload_len: usize,
    );
    fn get_ecn_bits(frame: &[u8], eth_len: usize) -> u8;
    /// Set ECN ECT(0) bit in the IP header.
    /// IPv4: sets ToS byte to 0x02, then recomputes IPv4 header checksum.
    /// IPv6: sets Traffic Class ECT(0) via `ip[1] |= 0x20`.
    fn set_ecn_ect(frame: &mut [u8], eth_len: usize);
    fn pseudo_header_sum(
        src: &Self::Address,
        dst: &Self::Address,
        protocol: u8,
        transport_len: u32,
    ) -> u64;
}

/// Zero-sized type for IPv4 version-specific operations.
pub struct Ipv4;

/// Zero-sized type for IPv6 version-specific operations.
pub struct Ipv6;

impl IpVersion for Ipv4 {
    type Address = Ipv4Address;

    const VERSION: u8 = 4;
    const ETHER_TYPE: EtherType = EtherTypes::IPv4;
    const IP_HEADER_LEN: usize = IPV4_MIN_HEADER_LEN;
    const VERSION_BYTE: u8 = 0x45;
    const NEXT_HEADER_OFFSET: usize = 9;
    const TTL_OFFSET: usize = 8;

    #[inline]
    fn write_ip_header(frame: &mut [u8], src: &Ipv4Address, dst: &Ipv4Address, payload_len: usize) {
        let ip = &mut frame[ETH_LEN..ETH_LEN + IPV4_MIN_HEADER_LEN];
        ip.fill(0);
        ip[0] = 0x45;
        let total_ip_len = (IPV4_MIN_HEADER_LEN + payload_len) as u16;
        ip[2..4].copy_from_slice(&total_ip_len.to_be_bytes());
        ip[6] = 0x40; // Don't Fragment
        ip[8] = 64; // TTL
        ip[9] = IpProtocols::Tcp;
        let src_bytes: [u8; 4] = (*src).into();
        ip[12..16].copy_from_slice(&src_bytes);
        let dst_bytes: [u8; 4] = (*dst).into();
        ip[16..20].copy_from_slice(&dst_bytes);
        // Compute IPv4 header checksum
        let ip_header = Ipv4Header::from_bytes_mut(frame);
        ip_header.fill_checksum();
    }

    #[inline]
    fn get_ecn_bits(frame: &[u8], eth_len: usize) -> u8 {
        frame[eth_len + 1] & 0x03
    }

    #[inline]
    fn set_ecn_ect(frame: &mut [u8], eth_len: usize) {
        frame[eth_len + 1] = 0x02;
        // Recompute IPv4 header checksum since we modified the ToS field.
        let ip = Ipv4Header::from_bytes_mut(frame);
        ip.fill_checksum();
    }

    #[inline]
    fn pseudo_header_sum(
        src: &Ipv4Address,
        dst: &Ipv4Address,
        protocol: u8,
        transport_len: u32,
    ) -> u64 {
        pseudo_header_sum_v4(src, dst, protocol, transport_len as u16)
    }
}

impl IpVersion for Ipv6 {
    type Address = Ipv6Address;

    const VERSION: u8 = 6;
    const ETHER_TYPE: EtherType = EtherTypes::IPv6;
    const IP_HEADER_LEN: usize = IPV6_HEADER_LEN;
    const VERSION_BYTE: u8 = 0x60;
    const NEXT_HEADER_OFFSET: usize = 6;
    const TTL_OFFSET: usize = 7;

    #[inline]
    fn write_ip_header(frame: &mut [u8], src: &Ipv6Address, dst: &Ipv6Address, payload_len: usize) {
        let ip = &mut frame[ETH_LEN..ETH_LEN + IPV6_HEADER_LEN];
        ip.fill(0);
        ip[0] = 0x60; // version=6
        let payload_len_u16 = payload_len as u16;
        ip[4..6].copy_from_slice(&payload_len_u16.to_be_bytes());
        ip[6] = IpProtocols::Tcp; // Next Header
        ip[7] = 64; // Hop Limit
        let src_bytes: [u8; 16] = (*src).into();
        ip[8..24].copy_from_slice(&src_bytes);
        let dst_bytes: [u8; 16] = (*dst).into();
        ip[24..40].copy_from_slice(&dst_bytes);
    }

    #[inline]
    fn get_ecn_bits(frame: &[u8], eth_len: usize) -> u8 {
        (frame[eth_len + 1] >> 4) & 0x03
    }

    #[inline]
    fn set_ecn_ect(frame: &mut [u8], eth_len: usize) {
        frame[eth_len + 1] |= 0x20;
    }

    #[inline]
    fn pseudo_header_sum(
        src: &Ipv6Address,
        dst: &Ipv6Address,
        protocol: u8,
        transport_len: u32,
    ) -> u64 {
        pseudo_header_sum_v6(src, dst, protocol, transport_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::checksum::verify_ipv4_checksum;

    const ETH: usize = size_of::<EthernetFrame>();

    // --- IPv4 write_ip_header ---

    #[test]
    fn ipv4_write_ip_header_fields() {
        let src = Ipv4Address::new([192, 168, 1, 10]);
        let dst = Ipv4Address::new([10, 0, 0, 1]);
        let payload_len = 20; // e.g. TCP header only
        let mut frame = vec![0u8; ETH + IPV4_MIN_HEADER_LEN + payload_len];

        Ipv4::write_ip_header(&mut frame, &src, &dst, payload_len);

        let ip = &frame[ETH..ETH + IPV4_MIN_HEADER_LEN];
        // version=4, IHL=5
        assert_eq!(ip[0], 0x45);
        // total length = 20 (header) + 20 (payload) = 40
        assert_eq!(u16::from_be_bytes([ip[2], ip[3]]), 40);
        // Don't Fragment flag
        assert_eq!(ip[6] & 0x40, 0x40);
        // TTL = 64
        assert_eq!(ip[8], 64);
        // Protocol = TCP (6)
        assert_eq!(ip[9], IpProtocols::Tcp);
        // Source address
        assert_eq!(&ip[12..16], &[192, 168, 1, 10]);
        // Destination address
        assert_eq!(&ip[16..20], &[10, 0, 0, 1]);
    }

    #[test]
    fn ipv4_write_ip_header_valid_checksum() {
        let src = Ipv4Address::new([172, 16, 0, 1]);
        let dst = Ipv4Address::new([172, 16, 0, 2]);
        let mut frame = vec![0u8; ETH + IPV4_MIN_HEADER_LEN + 32];

        Ipv4::write_ip_header(&mut frame, &src, &dst, 32);

        let ip = &frame[ETH..ETH + IPV4_MIN_HEADER_LEN];
        assert!(verify_ipv4_checksum(ip));
    }

    // --- IPv6 write_ip_header ---

    #[test]
    fn ipv6_write_ip_header_fields() {
        let src = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let payload_len = 20;
        let mut frame = vec![0u8; ETH + IPV6_HEADER_LEN + payload_len];

        Ipv6::write_ip_header(&mut frame, &src, &dst, payload_len);

        let ip = &frame[ETH..ETH + IPV6_HEADER_LEN];
        // Version = 6 (high nibble of byte 0)
        assert_eq!(ip[0] >> 4, 6);
        // Payload length
        assert_eq!(u16::from_be_bytes([ip[4], ip[5]]), 20);
        // Next Header = TCP (6)
        assert_eq!(ip[6], IpProtocols::Tcp);
        // Hop Limit = 64
        assert_eq!(ip[7], 64);
        // Source address
        assert_eq!(
            &ip[8..24],
            &[0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        // Destination address
        assert_eq!(
            &ip[24..40],
            &[0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]
        );
    }

    // --- IPv4 ECN ---

    #[test]
    fn ipv4_get_ecn_bits_zero() {
        let src = Ipv4Address::new([10, 0, 0, 1]);
        let dst = Ipv4Address::new([10, 0, 0, 2]);
        let mut frame = vec![0u8; ETH + IPV4_MIN_HEADER_LEN + 20];
        Ipv4::write_ip_header(&mut frame, &src, &dst, 20);

        // After write_ip_header, ToS/DSCP_ECN byte (ip[1]) is 0 => ECN bits = 0
        assert_eq!(Ipv4::get_ecn_bits(&frame, ETH), 0);
    }

    #[test]
    fn ipv4_set_ecn_ect_sets_ect0() {
        let src = Ipv4Address::new([10, 0, 0, 1]);
        let dst = Ipv4Address::new([10, 0, 0, 2]);
        let mut frame = vec![0u8; ETH + IPV4_MIN_HEADER_LEN + 20];
        Ipv4::write_ip_header(&mut frame, &src, &dst, 20);

        Ipv4::set_ecn_ect(&mut frame, ETH);

        // ECN bits should now be 0x02 (ECT(0))
        assert_eq!(Ipv4::get_ecn_bits(&frame, ETH), 0x02);
        // ToS byte should be exactly 0x02
        assert_eq!(frame[ETH + 1], 0x02);
        // Checksum should still be valid after recomputation
        let ip = &frame[ETH..ETH + IPV4_MIN_HEADER_LEN];
        assert!(verify_ipv4_checksum(ip));
    }

    // --- IPv6 ECN ---

    #[test]
    fn ipv6_get_ecn_bits_zero() {
        let src = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let mut frame = vec![0u8; ETH + IPV6_HEADER_LEN + 20];
        Ipv6::write_ip_header(&mut frame, &src, &dst, 20);

        // Traffic class is 0 after write => ECN bits = 0
        assert_eq!(Ipv6::get_ecn_bits(&frame, ETH), 0);
    }

    #[test]
    fn ipv6_set_ecn_ect_sets_ect0() {
        let src = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let mut frame = vec![0u8; ETH + IPV6_HEADER_LEN + 20];
        Ipv6::write_ip_header(&mut frame, &src, &dst, 20);

        Ipv6::set_ecn_ect(&mut frame, ETH);

        // ECN ECT(0) = bit 5 of byte 1 set => get_ecn_bits extracts (byte1 >> 4) & 0x03
        // byte1 was 0x00, now 0x20 => (0x20 >> 4) & 0x03 = 0x02
        assert_eq!(Ipv6::get_ecn_bits(&frame, ETH), 0x02);
    }

    // --- Pseudo-header sums ---

    #[test]
    fn ipv4_pseudo_header_sum_nonzero() {
        let src = Ipv4Address::new([192, 168, 1, 1]);
        let dst = Ipv4Address::new([10, 0, 0, 1]);
        let sum = Ipv4::pseudo_header_sum(&src, &dst, IpProtocols::Tcp, 20);
        assert!(sum > 0);
    }

    #[test]
    fn ipv4_pseudo_header_sum_matches_direct() {
        let src = Ipv4Address::new([192, 168, 1, 1]);
        let dst = Ipv4Address::new([10, 0, 0, 1]);
        let sum_trait = Ipv4::pseudo_header_sum(&src, &dst, IpProtocols::Tcp, 100);
        let sum_direct = pseudo_header_sum_v4(&src, &dst, IpProtocols::Tcp, 100);
        assert_eq!(sum_trait, sum_direct);
    }

    #[test]
    fn ipv6_pseudo_header_sum_nonzero() {
        let src = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let sum = Ipv6::pseudo_header_sum(&src, &dst, IpProtocols::Tcp, 20);
        assert!(sum > 0);
    }

    #[test]
    fn ipv6_pseudo_header_sum_matches_direct() {
        let src = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let sum_trait = Ipv6::pseudo_header_sum(&src, &dst, IpProtocols::Tcp, 100);
        let sum_direct = pseudo_header_sum_v6(&src, &dst, IpProtocols::Tcp, 100);
        assert_eq!(sum_trait, sum_direct);
    }

    // --- Constants ---

    #[test]
    fn ipv4_constants() {
        assert_eq!(Ipv4::VERSION, 4);
        assert_eq!(Ipv4::ETHER_TYPE, EtherTypes::IPv4);
        assert_eq!(Ipv4::IP_HEADER_LEN, 20);
        assert_eq!(Ipv4::VERSION_BYTE, 0x45);
        assert_eq!(Ipv4::NEXT_HEADER_OFFSET, 9);
        assert_eq!(Ipv4::TTL_OFFSET, 8);
    }

    #[test]
    fn ipv6_constants() {
        assert_eq!(Ipv6::VERSION, 6);
        assert_eq!(Ipv6::ETHER_TYPE, EtherTypes::IPv6);
        assert_eq!(Ipv6::IP_HEADER_LEN, 40);
        assert_eq!(Ipv6::VERSION_BYTE, 0x60);
        assert_eq!(Ipv6::NEXT_HEADER_OFFSET, 6);
        assert_eq!(Ipv6::TTL_OFFSET, 7);
    }
}
