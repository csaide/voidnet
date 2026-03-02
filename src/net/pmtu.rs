use std::time::{Duration, Instant};

use dashmap::DashMap;

use super::wire::ip::IpAddress;

/// Minimum MTU for IPv4 per RFC 791.
pub const IPV4_MIN_MTU: u32 = 68;

/// Minimum MTU for IPv6 per RFC 2460.
pub const IPV6_MIN_MTU: u32 = 1280;

/// Default TTL for PMTU cache entries (10 minutes per RFC 1191).
const DEFAULT_PMTU_TTL: Duration = Duration::from_secs(600);

/// A cache of discovered Path MTU values keyed by destination IP address.
///
/// When the network stack receives an ICMP "Fragmentation Needed" (IPv4)
/// or "Packet Too Big" (IPv6) message, the reported next-hop MTU is
/// stored here so that upper layers can size outgoing packets accordingly.
///
/// Entries expire after a configurable TTL (default 10 minutes per
/// RFC 1191). Expired entries are treated as absent (the default MTU is
/// returned) and can be removed in bulk via [`evict_stale`](Self::evict_stale).
#[derive(Debug)]
pub struct PmtuCache {
    /// PMTU table mappings for destination IP addresses.
    table: DashMap<IpAddress, (u32, Instant)>,
    /// The default MTU to use when no PMTU is found for a destination.
    default_mtu: u32,
    /// The TTL for PMTU entries.
    /// Expired entries are treated as absent (the default MTU is
    /// returned) and can be removed in bulk via [`evict_stale`](Self::evict_stale).
    ttl: Duration,
}

impl PmtuCache {
    /// Creates a new PMTU cache with the default MTU and TTL.
    pub fn new() -> Self {
        Self {
            table: DashMap::new(),
            default_mtu: 1500,
            ttl: DEFAULT_PMTU_TTL,
        }
    }

    /// Creates a new PMTU cache with the given MTU and default TTL.
    pub fn with_mtu(mtu: u32) -> Self {
        Self {
            table: DashMap::new(),
            default_mtu: mtu,
            ttl: DEFAULT_PMTU_TTL,
        }
    }

    /// Creates a new PMTU cache with the given MTU and TTL.
    pub fn with_mtu_and_ttl(mtu: u32, ttl: Duration) -> Self {
        Self {
            table: DashMap::new(),
            default_mtu: mtu,
            ttl,
        }
    }

    /// Records a discovered path MTU for `addr`.
    ///
    /// The value is clamped to the protocol minimum (68 for IPv4,
    /// 1280 for IPv6) before storing.
    pub fn update(&self, now: Instant, addr: IpAddress, mtu: u32) {
        let min = match addr {
            IpAddress::V4(_) => IPV4_MIN_MTU,
            IpAddress::V6(_) => IPV6_MIN_MTU,
        };
        self.table.insert(addr, (mtu.max(min), now));
    }

    /// Returns the cached path MTU for `addr`, or the default MTU if
    /// the entry is absent or expired.
    pub fn get(&self, now: Instant, addr: &IpAddress) -> u32 {
        self.table
            .get(addr)
            .and_then(|entry| {
                let (mtu, inserted_at) = *entry.value();
                if now.duration_since(inserted_at) <= self.ttl {
                    Some(mtu)
                } else {
                    None
                }
            })
            .unwrap_or(self.default_mtu)
    }

    /// Removes all entries older than the configured TTL.
    pub fn evict_stale(&self, now: Instant) {
        self.table
            .retain(|_, (_, inserted_at)| now.duration_since(*inserted_at) <= self.ttl);
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Add;

    use super::*;
    use crate::net::wire::ip::{Ipv4Address, Ipv6Address};

    #[test]
    fn insert_and_get_ipv4() {
        let now = Instant::now();
        let cache = PmtuCache::new();
        let addr = IpAddress::V4(Ipv4Address::new([10, 0, 0, 1]));
        cache.update(now, addr, 1500);
        assert_eq!(cache.get(now, &addr), 1500);
    }

    #[test]
    fn insert_and_get_ipv6() {
        let now = Instant::now();
        let cache = PmtuCache::new();
        let addr = IpAddress::V6(Ipv6Address::new([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]));
        cache.update(now, addr, 1400);
        assert_eq!(cache.get(now, &addr), 1400);
    }

    #[test]
    fn clamp_ipv4_to_minimum() {
        let now = Instant::now();
        let cache = PmtuCache::new();
        let addr = IpAddress::V4(Ipv4Address::new([10, 0, 0, 1]));
        cache.update(now, addr, 20);
        assert_eq!(cache.get(now, &addr), IPV4_MIN_MTU);
    }

    #[test]
    fn clamp_ipv6_to_minimum() {
        let now = Instant::now();
        let cache = PmtuCache::new();
        let addr = IpAddress::V6(Ipv6Address::new([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]));
        cache.update(now, addr, 500);
        assert_eq!(cache.get(now, &addr), IPV6_MIN_MTU);
    }

    #[test]
    fn overwrite_with_smaller_mtu() {
        let now = Instant::now();
        let cache = PmtuCache::new();
        let addr = IpAddress::V4(Ipv4Address::new([10, 0, 0, 1]));
        cache.update(now, addr, 1500);
        assert_eq!(cache.get(now, &addr), 1500);
        cache.update(now, addr, 1200);
        assert_eq!(cache.get(now, &addr), 1200);
    }

    #[test]
    fn get_unknown_returns_default() {
        let now = Instant::now();
        let cache = PmtuCache::new();
        let addr = IpAddress::V4(Ipv4Address::new([10, 0, 0, 1]));
        assert_eq!(cache.get(now, &addr), 1500);
    }

    #[test]
    fn expired_entry_returns_default() {
        let now = Instant::now();
        let cache = PmtuCache::with_mtu_and_ttl(1500, Duration::ZERO);
        let addr = IpAddress::V4(Ipv4Address::new([10, 0, 0, 1]));
        cache.update(now, addr, 1200);
        assert_eq!(cache.get(now.add(Duration::from_millis(5)), &addr), 1500);
    }

    #[test]
    fn evict_stale_removes_expired() {
        let now = Instant::now();
        let cache = PmtuCache::with_mtu_and_ttl(1500, Duration::ZERO);
        let addr = IpAddress::V4(Ipv4Address::new([10, 0, 0, 1]));
        cache.update(now, addr, 1200);
        cache.evict_stale(now.add(Duration::from_millis(5)));
        assert_eq!(cache.table.len(), 0);
    }

    #[test]
    fn evict_stale_keeps_fresh() {
        let now = Instant::now();
        let cache = PmtuCache::with_mtu_and_ttl(1500, Duration::from_secs(3600));
        let addr = IpAddress::V4(Ipv4Address::new([10, 0, 0, 1]));
        cache.update(now, addr, 1200);
        cache.evict_stale(now.add(Duration::from_secs(3600)));
        assert_eq!(cache.table.len(), 1);
        assert_eq!(cache.get(now, &addr), 1200);
    }
}
