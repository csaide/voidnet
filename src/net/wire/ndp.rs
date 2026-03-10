use super::{
    ethernet::{EthernetFrame, MacAddress},
    ip::{Ipv6Address, Ipv6Header},
};

/// NDP Neighbor Solicitation ICMPv6 message with Source Link-Layer Address option.
///
/// Layout (32 bytes total):
/// - ICMPv6 type (1) + code (1) + checksum (2) + reserved (4)
/// - Target address (16)
/// - Source Link-Layer Address option: type (1) + length (1) + MAC (6)
#[repr(C, packed)]
pub struct NdpNsMessage {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: [u8; 2],
    pub reserved: [u8; 4],
    pub target: Ipv6Address,
    pub opt_type: u8,
    pub opt_len: u8,
    pub opt_mac: MacAddress,
}

const _: () = assert!(size_of::<NdpNsMessage>() == 32);

impl NdpNsMessage {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
}

/// Complete NDP Neighbor Solicitation frame (Ethernet + IPv6 + NS message).
#[repr(C, packed)]
pub struct NdpNsFrame {
    pub ethernet: EthernetFrame,
    pub ipv6: Ipv6Header,
    pub ns: NdpNsMessage,
}

impl NdpNsFrame {
    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }

    #[inline(always)]
    pub fn from_bytes_mut(bytes: &mut [u8]) -> &mut Self {
        debug_assert!(bytes.len() >= NDP_NS_FRAME_LEN);
        unsafe { &mut *(bytes.as_mut_ptr() as *mut Self) }
    }
}

/// Ethernet header (14) + IPv6 header (40) + ICMPv6 NS message (32) = 86 bytes.
pub const NDP_NS_FRAME_LEN: usize = size_of::<NdpNsFrame>();
const _: () = assert!(NDP_NS_FRAME_LEN == 86);

/// NDP Neighbor Advertisement ICMPv6 message with Target Link-Layer Address option.
///
/// Layout (32 bytes total):
/// - ICMPv6 type (1) + code (1) + checksum (2) + flags (4)
/// - Target address (16)
/// - Target Link-Layer Address option: type (1) + length (1) + MAC (6)
#[repr(C, packed)]
pub struct NdpNaMessage {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: [u8; 2],
    pub flags: [u8; 4],
    pub target: Ipv6Address,
    pub opt_type: u8,
    pub opt_len: u8,
    pub opt_mac: MacAddress,
}

const _: () = assert!(size_of::<NdpNaMessage>() == 32);

impl NdpNaMessage {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
}

/// Complete NDP Neighbor Advertisement frame (Ethernet + IPv6 + NA message).
#[repr(C, packed)]
pub struct NdpNaFrame {
    pub ethernet: EthernetFrame,
    pub ipv6: Ipv6Header,
    pub na: NdpNaMessage,
}

impl NdpNaFrame {
    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }

    #[inline(always)]
    pub fn from_bytes_mut(bytes: &mut [u8]) -> &mut Self {
        debug_assert!(bytes.len() >= NDP_NA_FRAME_LEN);
        unsafe { &mut *(bytes.as_mut_ptr() as *mut Self) }
    }
}

/// Ethernet header (14) + IPv6 header (40) + ICMPv6 NA message (32) = 86 bytes.
pub const NDP_NA_FRAME_LEN: usize = size_of::<NdpNaFrame>();
const _: () = assert!(NDP_NA_FRAME_LEN == 86);

/// Minimum NDP message body length: 8 (ICMPv6 header) + 16 (target address).
pub const NDP_MIN_NS_NA_LEN: usize = 24;

/// Minimum Router Advertisement body length: 8 (ICMPv6 header) +
/// 4 (cur hop limit + flags + router lifetime) + 4 (reachable time) + 4 (retrans timer).
pub const NDP_MIN_RA_LEN: usize = 16;

/// IPv6 all-nodes link-local multicast address (ff02::1).
pub const ALL_NODES_MULTICAST: Ipv6Address =
    Ipv6Address::new([0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

#[cfg(test)]
mod tests {
    use crate::net::wire::ip::IPV6_HEADER_LEN;

    use super::*;

    #[test]
    fn ndp_ns_message_layout() {
        assert_eq!(size_of::<NdpNsMessage>(), 32);
    }

    #[test]
    fn ndp_ns_frame_layout() {
        assert_eq!(size_of::<NdpNsFrame>(), 86);
        assert_eq!(
            NDP_NS_FRAME_LEN,
            size_of::<EthernetFrame>() + IPV6_HEADER_LEN + 32
        );
    }

    #[test]
    fn ndp_na_message_layout() {
        assert_eq!(size_of::<NdpNaMessage>(), 32);
    }

    #[test]
    fn ndp_na_frame_layout() {
        assert_eq!(size_of::<NdpNaFrame>(), 86);
        assert_eq!(
            NDP_NA_FRAME_LEN,
            size_of::<EthernetFrame>() + IPV6_HEADER_LEN + 32
        );
    }
}
