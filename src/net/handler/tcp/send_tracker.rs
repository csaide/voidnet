use rustc_hash::FxHashSet;

use super::tcb::ConnectionId;

/// Marker returned by Tcb methods that make a connection sendable.
/// Must be consumed by passing to `SendTracker::mark()`.
#[must_use = "connection must be marked for sending via SendTracker::mark()"]
pub struct SendReady(pub ConnectionId);

/// Tracks which connections have pending send work.
/// poll_send iterates only this set instead of all connections.
pub struct SendTracker {
    set: FxHashSet<ConnectionId>,
}

impl SendTracker {
    pub fn new() -> Self {
        Self {
            set: FxHashSet::default(),
        }
    }

    /// Register a connection as needing send processing.
    #[inline(always)]
    pub fn mark(&mut self, ready: SendReady) {
        self.set.insert(ready.0);
    }

    /// Remove a connection from the active set.
    #[inline(always)]
    pub fn unmark(&mut self, id: &ConnectionId) {
        self.set.remove(id);
    }

    /// Drain all tracked connection IDs for processing.
    /// Returns an iterator of ConnectionIds that need poll_send attention.
    #[inline(always)]
    pub fn drain(&mut self) -> impl Iterator<Item = ConnectionId> + '_ {
        self.set.drain()
    }

    /// Check if any connections need sending.
    #[inline(always)]
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}
