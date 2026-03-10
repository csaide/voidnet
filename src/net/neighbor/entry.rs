use coarsetime::Instant;

use crate::net::wire::ethernet::MacAddress;

/// A neighbor entry representation.
#[derive(Debug)]
pub(super) struct NeighborEntry {
    mac: MacAddress,
    expires_at: Instant,
}

impl NeighborEntry {
    /// Creates a new neighbor entry.
    pub const fn new(mac: MacAddress, expires_at: Instant) -> Self {
        Self { mac, expires_at }
    }

    /// Returns true if the entry is expired.
    pub fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }

    /// Returns the MAC address.
    pub const fn mac(&self) -> MacAddress {
        self.mac
    }
}
