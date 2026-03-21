//! Retry and NEW_TOKEN token generation/validation (RFC 9000 §8.1).
//!
//! Full implementation in Task 27.

use super::connection_id::ConnectionId;
use std::net::SocketAddr;
use std::time::Instant;

/// Retry token for address validation (RFC 9000 §8.1.2).
pub struct RetryToken {
    pub original_dcid: ConnectionId,
    pub client_addr: SocketAddr,
    pub timestamp: Instant,
}
