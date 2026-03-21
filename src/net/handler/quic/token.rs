//! Retry and NEW_TOKEN token generation/validation (RFC 9000 §8.1).

use super::connection_id::ConnectionId;
use std::net::SocketAddr;
use std::time::Instant;

/// Retry token for address validation (RFC 9000 §8.1.2)
pub struct RetryToken {
    pub original_dcid: ConnectionId,
    pub client_addr: SocketAddr,
    pub timestamp: Instant,
}

impl RetryToken {
    pub fn new(original_dcid: ConnectionId, client_addr: SocketAddr, now: Instant) -> Self {
        Self {
            original_dcid,
            client_addr,
            timestamp: now,
        }
    }

    /// Check if token has expired (recommended: 30 seconds)
    pub fn is_expired(&self, now: Instant, max_age: std::time::Duration) -> bool {
        now.duration_since(self.timestamp) > max_age
    }
}
