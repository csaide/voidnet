mod addr;
mod proto;
pub mod traits;
mod v4;
mod v6;

use super::ethernet;

pub use traits::{IpVersion, Ipv4, Ipv6};

pub use addr::{IpAddress, Ipv4Address, Ipv6Address, SocketAddr};
pub use proto::{IpProtocol, IpProtocols};
pub use v4::{IPV4_MIN_FRAME_LEN, IPV4_MIN_HEADER_LEN, Ipv4Header};
pub use v6::{
    EXT_AH, EXT_DESTINATION, EXT_FRAGMENT, EXT_HOP_BY_HOP, EXT_ROUTING, FRAGMENT_EXT_LEN,
    IPV6_HEADER_LEN, IPV6_MIN_FRAME_LEN, Ipv6FragmentHeader, Ipv6Header, NO_NEXT_HEADER,
};
