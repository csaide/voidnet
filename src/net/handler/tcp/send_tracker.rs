use rustc_hash::FxHashSet;

use super::tcb::ConnectionId;

/// Marker returned by Tcb methods that make a connection sendable.
/// Must be consumed by passing to `SendTracker::mark()`.
#[must_use = "connection must be marked for sending via SendTracker::mark()"]
pub struct SendReady(pub ConnectionId);

/// Tracks which connections have pending send work using a dual-set
/// swap pattern. `poll_send` calls `swap()` then `drain_active()` to
/// iterate without heap allocation. New marks go into `pending`, which
/// becomes `active` on the next `swap()`.
pub struct SendTracker {
    active: FxHashSet<ConnectionId>,
    pending: FxHashSet<ConnectionId>,
}

impl SendTracker {
    pub fn new() -> Self {
        Self {
            active: FxHashSet::default(),
            pending: FxHashSet::default(),
        }
    }

    /// Swap active/pending sets. Call once at the start of poll_send.
    /// O(1) pointer swap — no allocation, no iteration.
    #[inline(always)]
    pub fn swap(&mut self) {
        std::mem::swap(&mut self.active, &mut self.pending);
    }

    /// Drain the active set for iteration. Call after `swap()`.
    #[inline(always)]
    pub fn drain_active(&mut self) -> impl Iterator<Item = ConnectionId> + '_ {
        self.active.drain()
    }

    /// Register a connection as needing send processing.
    /// Always inserts into `pending` — safe to call during drain_active iteration.
    #[inline(always)]
    pub fn mark(&mut self, ready: SendReady) {
        self.pending.insert(ready.0);
    }

    /// Remove a connection from both sets (connection closed/removed).
    #[inline(always)]
    pub fn unmark(&mut self, id: &ConnectionId) {
        self.active.remove(id);
        self.pending.remove(id);
    }

    /// Check if any connections need sending (across both sets).
    #[inline(always)]
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.active.is_empty() && self.pending.is_empty()
    }
}
