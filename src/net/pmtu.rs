use std::collections::HashMap;

use super::wire::ip::IpAddress;

/// Minimum MTU for IPv4 per RFC 791.
pub const IPV4_MIN_MTU: u32 = 68;

/// Minimum MTU for IPv6 per RFC 2460.
pub const IPV6_MIN_MTU: u32 = 1280;

/// A cache of discovered Path MTU values keyed by destination IP address.
///
/// When the network stack receives an ICMP "Fragmentation Needed" (IPv4)
/// or "Packet Too Big" (IPv6) message, the reported next-hop MTU is
/// stored here so that upper layers can size outgoing packets accordingly.
pub struct PmtuCache {
    table: HashMap<IpAddress, u32>,
    mtu: u32,
}

impl PmtuCache {
    pub fn new() -> Self {
        Self {
            table: HashMap::new(),
            mtu: 1500,
        }
    }

    pub fn with_mtu(mtu: u32) -> Self {
        Self {
            table: HashMap::new(),
            mtu,
        }
    }

    /// Records a discovered path MTU for `addr`.
    ///
    /// The value is clamped to the protocol minimum (68 for IPv4,
    /// 1280 for IPv6) before storing.
    pub fn update(&mut self, addr: IpAddress, mtu: u32) {
        let min = match addr {
            IpAddress::V4(_) => IPV4_MIN_MTU,
            IpAddress::V6(_) => IPV6_MIN_MTU,
        };
        self.table.insert(addr, mtu.max(min));
    }

    /// Returns the cached path MTU for `addr`, if any.
    pub fn get(&self, addr: &IpAddress) -> u32 {
        self.table.get(addr).copied().unwrap_or(self.mtu)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::wire::ip::{Ipv4Address, Ipv6Address};

    #[test]
    fn insert_and_get_ipv4() {
        let mut cache = PmtuCache::new();
        let addr = IpAddress::V4(Ipv4Address::new([10, 0, 0, 1]));
        cache.update(addr, 1500);
        assert_eq!(cache.get(&addr), 1500);
    }

    #[test]
    fn insert_and_get_ipv6() {
        let mut cache = PmtuCache::new();
        let addr = IpAddress::V6(Ipv6Address::new([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]));
        cache.update(addr, 1400);
        assert_eq!(cache.get(&addr), 1400);
    }

    #[test]
    fn clamp_ipv4_to_minimum() {
        let mut cache = PmtuCache::new();
        let addr = IpAddress::V4(Ipv4Address::new([10, 0, 0, 1]));
        cache.update(addr, 20);
        assert_eq!(cache.get(&addr), IPV4_MIN_MTU);
    }

    #[test]
    fn clamp_ipv6_to_minimum() {
        let mut cache = PmtuCache::new();
        let addr = IpAddress::V6(Ipv6Address::new([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]));
        cache.update(addr, 500);
        assert_eq!(cache.get(&addr), IPV6_MIN_MTU);
    }

    #[test]
    fn overwrite_with_smaller_mtu() {
        let mut cache = PmtuCache::new();
        let addr = IpAddress::V4(Ipv4Address::new([10, 0, 0, 1]));
        cache.update(addr, 1500);
        assert_eq!(cache.get(&addr), 1500);
        cache.update(addr, 1200);
        assert_eq!(cache.get(&addr), 1200);
    }

    #[test]
    fn get_unknown_returns_none() {
        let cache = PmtuCache::new();
        let addr = IpAddress::V4(Ipv4Address::new([10, 0, 0, 1]));
        assert_eq!(cache.get(&addr), 1500);
    }
}
