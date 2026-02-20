mod addr;
mod v4;
mod v6;

use super::ethernet;

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod IpProtocols {
    pub const Icmp: u8 = 1;
    pub const IcmpV6: u8 = 58;
    pub const Udp: u8 = 17;
    pub const Tcp: u8 = 6;
}

pub use addr::{IpAddress, Ipv4Address, Ipv6Address};
pub use v4::{
    IPV4_MIN_FRAME_LEN, IPV4_MIN_HEADER_LEN, Ipv4Header, compute_ipv4_checksum,
    verify_ipv4_checksum,
};
pub use v6::{
    EXT_AH, EXT_DESTINATION, EXT_FRAGMENT, EXT_HOP_BY_HOP, EXT_ROUTING, FRAGMENT_EXT_LEN,
    IPV6_HEADER_LEN, IPV6_MIN_FRAME_LEN, Ipv6FragmentHeader, Ipv6Header, NO_NEXT_HEADER,
};
