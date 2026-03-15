use std::hash::{DefaultHasher, Hash, Hasher};

use coarsetime::Instant;

use super::tcb::ConnectionId;

/// ISN (Initial Sequence Number) generator per RFC 9293.
///
/// Combines a clock component (~4µs ticks) with a keyed hash
/// of the connection 4-tuple and a random secret. This makes ISNs
/// unpredictable to off-path attackers while still monotonically
/// increasing per-connection to avoid overlap with old segments.
pub struct IsnGenerator {
    secret: [u64; 2],
    epoch: Instant,
}

fn random_u64() -> u64 {
    let mut buf = [0u8; 8];
    let ret = unsafe { libc::getrandom(buf.as_mut_ptr().cast(), 8, 0) };
    assert!(
        ret == 8,
        "getrandom failed to fill ISN secret: returned {ret}"
    );
    u64::from_ne_bytes(buf)
}

impl IsnGenerator {
    /// Creates a new ISN generator with a random secret.
    pub fn new() -> Self {
        Self {
            secret: [random_u64(), random_u64()],
            epoch: Instant::now(),
        }
    }

    /// Generates an ISN for the given connection 4-tuple.
    ///
    /// The result is `Hash(4-tuple, secret) + clock_ticks` where
    /// clock_ticks increments at approximately 250,000 per second (~4µs).
    #[inline]
    pub fn generate(&self, id: &ConnectionId) -> u32 {
        let mut hasher = DefaultHasher::new();
        self.secret[0].hash(&mut hasher);
        self.secret[1].hash(&mut hasher);
        id.local_addr.hash(&mut hasher);
        id.local_port.hash(&mut hasher);
        id.remote_addr.hash(&mut hasher);
        id.remote_port.hash(&mut hasher);
        let hash = hasher.finish() as u32;

        // Clock component: ~4µs ticks = 250,000 ticks/sec.
        let elapsed_us = self.epoch.elapsed().as_micros();
        let clock_ticks = (elapsed_us / 4) as u32;

        hash.wrapping_add(clock_ticks)
    }
}

#[cfg(test)]
mod tests {
    use crate::net::wire::ip::{IpAddress, Ipv4Address};

    use super::*;

    #[test]
    fn different_connections_get_different_isns() {
        let generator = IsnGenerator::new();
        let id1 = ConnectionId {
            local_addr: IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])),
            local_port: 1234,
            remote_addr: IpAddress::V4(Ipv4Address::new([10, 0, 0, 2])),
            remote_port: 80,
        };
        let id2 = ConnectionId {
            local_addr: IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])),
            local_port: 1235,
            remote_addr: IpAddress::V4(Ipv4Address::new([10, 0, 0, 2])),
            remote_port: 80,
        };
        assert_ne!(generator.generate(&id1), generator.generate(&id2));
    }

    #[test]
    fn same_connection_produces_consistent_isn() {
        let generator = IsnGenerator::new();
        let id = ConnectionId {
            local_addr: IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])),
            local_port: 1234,
            remote_addr: IpAddress::V4(Ipv4Address::new([10, 0, 0, 2])),
            remote_port: 80,
        };
        let isn1 = generator.generate(&id);
        let isn2 = generator.generate(&id);
        assert!(isn1.wrapping_sub(isn2) < 1000 || isn2.wrapping_sub(isn1) < 1000);
    }
}
