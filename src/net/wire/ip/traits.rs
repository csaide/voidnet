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
    fn pseudo_header_sum(
        src: &Ipv6Address,
        dst: &Ipv6Address,
        protocol: u8,
        transport_len: u32,
    ) -> u64 {
        pseudo_header_sum_v6(src, dst, protocol, transport_len)
    }
}
