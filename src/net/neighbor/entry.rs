use coarsetime::{Duration, Instant};

use crate::net::wire::ethernet::MacAddress;

/// Time before an [`NeighborState::Incomplete`] entry is considered timed out.
const INCOMPLETE_TIMEOUT: Duration = Duration::from_secs(3);

/// Time before a [`NeighborState::Stale`] entry is evicted from the cache.
const STALE_TIMEOUT: Duration = Duration::from_secs(30);

/// Minimum gap between solicitations for the same entry.
const SOLICIT_GUARD: Duration = Duration::from_secs(1);

/// Three-state model for a neighbor cache entry.
///
/// The state machine mirrors the relevant subset of RFC 4861 §7.3:
///
/// ```text
/// [new IP]          [reply received]      [TTL expires]
///   │                     │                     │
///   ▼                     ▼                     ▼
/// Incomplete ──────► Reachable ──────────► Stale
///   │                                        │
///   └─ evicted after INCOMPLETE_TIMEOUT      └─ evicted after STALE_TIMEOUT
/// ```
#[derive(Debug, Clone)]
pub(super) enum NeighborState {
    /// A solicitation has been sent but no reply has been received yet.
    Incomplete {
        /// When the solicitation was (last) sent.
        solicited_at: Instant,
    },
    /// The mapping is confirmed and the TTL has not yet expired.
    Reachable {
        /// The resolved hardware address.
        mac: MacAddress,
        /// Absolute time at which the entry expires and transitions to `Stale`.
        expires_at: Instant,
    },
    /// The TTL has expired but the MAC is probably still valid.
    ///
    /// A new solicitation will be sent lazily (on next use) unless one has
    /// already been sent recently.
    Stale {
        /// The most-recently confirmed hardware address.
        mac: MacAddress,
        /// When the entry transitioned to `Stale`.
        stale_since: Instant,
        /// When a solicitation was last sent (if any) while in this state.
        solicited_at: Option<Instant>,
    },
}

impl NeighborState {
    /// Creates a new `Incomplete` entry representing a just-sent solicitation.
    #[inline]
    pub fn incomplete(now: Instant) -> Self {
        Self::Incomplete { solicited_at: now }
    }

    /// Creates a new `Reachable` entry with a known MAC and expiry time.
    #[inline]
    pub fn reachable(mac: MacAddress, expires_at: Instant) -> Self {
        Self::Reachable { mac, expires_at }
    }

    /// Creates a new `Stale` entry from a previously-known MAC.
    #[inline]
    pub fn stale(mac: MacAddress, stale_since: Instant) -> Self {
        Self::Stale {
            mac,
            stale_since,
            solicited_at: None,
        }
    }

    /// Returns the cached MAC address, if one is available.
    ///
    /// Returns `None` for [`NeighborState::Incomplete`] because no reply has
    /// been received yet.
    #[inline]
    pub fn mac(&self) -> Option<MacAddress> {
        match self {
            Self::Incomplete { .. } => None,
            Self::Reachable { mac, .. } | Self::Stale { mac, .. } => Some(*mac),
        }
    }

    /// Returns `true` if a `Reachable` entry's TTL has expired.
    ///
    /// `Incomplete` and `Stale` entries are **never** considered expired by
    /// this predicate; use [`should_evict`](Self::should_evict) to decide
    /// whether to remove those states from the cache.
    #[inline]
    pub fn is_expired(&self, now: Instant) -> bool {
        match self {
            Self::Reachable { expires_at, .. } => now >= *expires_at,
            _ => false,
        }
    }

    /// Returns `true` if the entry should be removed from the cache.
    ///
    /// | State       | Evict when                                        |
    /// |-------------|---------------------------------------------------|
    /// | Incomplete  | `now ≥ solicited_at + INCOMPLETE_TIMEOUT` (3 s)  |
    /// | Reachable   | never — use [`is_expired`](Self::is_expired)      |
    /// | Stale       | `now ≥ stale_since + STALE_TIMEOUT` (30 s)       |
    #[inline]
    pub fn should_evict(&self, now: Instant) -> bool {
        match self {
            Self::Incomplete { solicited_at } => now >= *solicited_at + INCOMPLETE_TIMEOUT,
            Self::Reachable { .. } => false,
            Self::Stale { stale_since, .. } => now >= *stale_since + STALE_TIMEOUT,
        }
    }

    /// Returns `true` if a new solicitation should be sent for this entry.
    ///
    /// | State      | Solicit when                                                    |
    /// |------------|-----------------------------------------------------------------|
    /// | Incomplete | `now ≥ solicited_at + SOLICIT_GUARD` (rate-limit retransmits)   |
    /// | Reachable  | never                                                           |
    /// | Stale      | never solicited **or** `now ≥ solicited_at + SOLICIT_GUARD`    |
    #[inline]
    pub fn should_solicit(&self, now: Instant) -> bool {
        match self {
            Self::Incomplete { solicited_at } => now >= *solicited_at + SOLICIT_GUARD,
            Self::Reachable { .. } => false,
            Self::Stale { solicited_at, .. } => match solicited_at {
                None => true,
                Some(t) => now >= *t + SOLICIT_GUARD,
            },
        }
    }

    /// Records that a solicitation was sent at `now`.
    ///
    /// Updates `solicited_at` for `Incomplete` and `Stale` states.  Has no
    /// effect on `Reachable` entries.
    #[inline]
    pub fn mark_solicited(&mut self, now: Instant) {
        match self {
            Self::Incomplete { solicited_at } => *solicited_at = now,
            Self::Stale { solicited_at, .. } => *solicited_at = Some(now),
            Self::Reachable { .. } => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    const TEST_MAC: MacAddress = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    const TEST_MAC2: MacAddress = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    // -----------------------------------------------------------------------
    // NeighborState::incomplete
    // -----------------------------------------------------------------------

    #[test]
    fn incomplete_mac_is_none() {
        let now = Instant::now();
        let entry = NeighborState::incomplete(now);
        assert!(entry.mac().is_none());
    }

    #[test]
    fn incomplete_is_not_expired() {
        let now = Instant::now();
        let entry = NeighborState::incomplete(now);
        assert!(!entry.is_expired(now));
        assert!(!entry.is_expired(now + secs(100)));
    }

    #[test]
    fn incomplete_should_not_evict_immediately() {
        let now = Instant::now();
        let entry = NeighborState::incomplete(now);
        assert!(!entry.should_evict(now));
        // Just before timeout
        assert!(!entry.should_evict(now + secs(2)));
    }

    #[test]
    fn incomplete_should_evict_after_timeout() {
        let now = Instant::now();
        let entry = NeighborState::incomplete(now);
        assert!(entry.should_evict(now + secs(3)));
        assert!(entry.should_evict(now + secs(10)));
    }

    #[test]
    fn incomplete_should_not_solicit_within_guard() {
        let now = Instant::now();
        let entry = NeighborState::incomplete(now);
        assert!(!entry.should_solicit(now));
        assert!(!entry.should_solicit(now + Duration::from_millis(500)));
    }

    #[test]
    fn incomplete_should_solicit_after_guard() {
        let now = Instant::now();
        let entry = NeighborState::incomplete(now);
        assert!(entry.should_solicit(now + secs(1)));
        assert!(entry.should_solicit(now + secs(5)));
    }

    #[test]
    fn incomplete_mark_solicited_updates_guard() {
        let now = Instant::now();
        let mut entry = NeighborState::incomplete(now);
        let t1 = now + secs(2);
        entry.mark_solicited(t1);
        // Guard restarts from t1
        assert!(!entry.should_solicit(t1));
        assert!(entry.should_solicit(t1 + secs(1)));
    }

    // -----------------------------------------------------------------------
    // NeighborState::reachable
    // -----------------------------------------------------------------------

    #[test]
    fn reachable_mac_is_some() {
        let now = Instant::now();
        let entry = NeighborState::reachable(TEST_MAC, now + secs(60));
        assert_eq!(entry.mac(), Some(TEST_MAC));
    }

    #[test]
    fn reachable_not_expired_before_ttl() {
        let now = Instant::now();
        let entry = NeighborState::reachable(TEST_MAC, now + secs(60));
        assert!(!entry.is_expired(now));
        assert!(!entry.is_expired(now + secs(59)));
    }

    #[test]
    fn reachable_expired_at_and_after_ttl() {
        let now = Instant::now();
        let entry = NeighborState::reachable(TEST_MAC, now + secs(60));
        assert!(entry.is_expired(now + secs(60)));
        assert!(entry.is_expired(now + secs(120)));
    }

    #[test]
    fn reachable_never_evicted() {
        let now = Instant::now();
        let entry = NeighborState::reachable(TEST_MAC, now + secs(60));
        assert!(!entry.should_evict(now));
        assert!(!entry.should_evict(now + secs(1000)));
    }

    #[test]
    fn reachable_never_solicited() {
        let now = Instant::now();
        let entry = NeighborState::reachable(TEST_MAC, now + secs(60));
        assert!(!entry.should_solicit(now));
        assert!(!entry.should_solicit(now + secs(1000)));
    }

    #[test]
    fn reachable_mark_solicited_is_noop() {
        let now = Instant::now();
        let mut entry = NeighborState::reachable(TEST_MAC, now + secs(60));
        entry.mark_solicited(now + secs(5));
        // Still reachable, still has the same mac
        assert_eq!(entry.mac(), Some(TEST_MAC));
        assert!(!entry.should_solicit(now + secs(1000)));
    }

    // -----------------------------------------------------------------------
    // NeighborState::stale
    // -----------------------------------------------------------------------

    #[test]
    fn stale_mac_is_some() {
        let now = Instant::now();
        let entry = NeighborState::stale(TEST_MAC2, now);
        assert_eq!(entry.mac(), Some(TEST_MAC2));
    }

    #[test]
    fn stale_is_not_expired() {
        let now = Instant::now();
        let entry = NeighborState::stale(TEST_MAC, now);
        assert!(!entry.is_expired(now));
        assert!(!entry.is_expired(now + secs(1000)));
    }

    #[test]
    fn stale_should_not_evict_immediately() {
        let now = Instant::now();
        let entry = NeighborState::stale(TEST_MAC, now);
        assert!(!entry.should_evict(now));
        assert!(!entry.should_evict(now + secs(29)));
    }

    #[test]
    fn stale_should_evict_after_timeout() {
        let now = Instant::now();
        let entry = NeighborState::stale(TEST_MAC, now);
        assert!(entry.should_evict(now + secs(30)));
        assert!(entry.should_evict(now + secs(60)));
    }

    #[test]
    fn stale_should_solicit_immediately_when_never_solicited() {
        let now = Instant::now();
        let entry = NeighborState::stale(TEST_MAC, now);
        // No solicitation has been sent yet → should solicit right away
        assert!(entry.should_solicit(now));
    }

    #[test]
    fn stale_should_not_solicit_within_guard_after_solicitation() {
        let now = Instant::now();
        let mut entry = NeighborState::stale(TEST_MAC, now);
        entry.mark_solicited(now);
        assert!(!entry.should_solicit(now));
        assert!(!entry.should_solicit(now + Duration::from_millis(500)));
    }

    #[test]
    fn stale_should_solicit_after_guard() {
        let now = Instant::now();
        let mut entry = NeighborState::stale(TEST_MAC, now);
        entry.mark_solicited(now);
        assert!(entry.should_solicit(now + secs(1)));
        assert!(entry.should_solicit(now + secs(10)));
    }

    #[test]
    fn stale_mark_solicited_updates_guard() {
        let now = Instant::now();
        let mut entry = NeighborState::stale(TEST_MAC, now);
        let t1 = now + secs(5);
        entry.mark_solicited(t1);
        // Guard restarts from t1
        assert!(!entry.should_solicit(t1));
        let t2 = t1 + secs(1);
        assert!(entry.should_solicit(t2));
        // Update again
        entry.mark_solicited(t2);
        assert!(!entry.should_solicit(t2));
        assert!(entry.should_solicit(t2 + secs(1)));
    }

    // -----------------------------------------------------------------------
    // State transitions
    // -----------------------------------------------------------------------

    #[test]
    fn reachable_to_stale_transition() {
        let now = Instant::now();
        let ttl = secs(60);
        let reachable = NeighborState::reachable(TEST_MAC, now + ttl);
        let mac = reachable.mac().expect("reachable must have a mac");

        // When TTL expires, caller converts to Stale
        let expired_at = now + ttl;
        let stale = NeighborState::stale(mac, expired_at);

        assert_eq!(stale.mac(), Some(TEST_MAC));
        assert!(!stale.is_expired(expired_at));
        assert!(stale.should_solicit(expired_at)); // no solicitation yet
    }

    #[test]
    fn incomplete_to_reachable_transition() {
        let now = Instant::now();
        let mut incomplete = NeighborState::incomplete(now);
        // Record that we sent a solicitation
        incomplete.mark_solicited(now);

        // Reply arrives → transition to Reachable
        let reachable = NeighborState::reachable(TEST_MAC, now + secs(60));
        assert_eq!(reachable.mac(), Some(TEST_MAC));
        assert!(!reachable.is_expired(now));
        assert!(!reachable.should_evict(now));
    }

    #[test]
    fn stale_to_reachable_on_reply() {
        let now = Instant::now();
        let stale = NeighborState::stale(TEST_MAC, now);

        // Updated MAC arrives via NA → transition to Reachable with new MAC
        let reachable = NeighborState::reachable(TEST_MAC2, now + secs(60));
        assert_eq!(reachable.mac(), Some(TEST_MAC2));
        assert!(!reachable.is_expired(now));

        // Old stale entry's mac is still accessible before replacement
        assert_eq!(stale.mac(), Some(TEST_MAC));
    }

    // -----------------------------------------------------------------------
    // Constants sanity checks
    // -----------------------------------------------------------------------

    #[test]
    fn constants_have_expected_values() {
        assert_eq!(INCOMPLETE_TIMEOUT, Duration::from_secs(3));
        assert_eq!(STALE_TIMEOUT, Duration::from_secs(30));
        assert_eq!(SOLICIT_GUARD, Duration::from_secs(1));
    }
}
