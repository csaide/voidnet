use rustc_hash::FxHashSet;

/// Marker returned by Tcb methods that make a connection sendable.
/// Must be consumed by passing to `SendTracker::mark()`.
#[must_use = "connection must be marked for sending via SendTracker::mark()"]
pub struct SendReady(pub usize);

/// Tracks which connections have pending send work using a dual-set
/// swap pattern. `poll_send` calls `swap()` then `drain_active()` to
/// iterate without heap allocation. New marks go into `pending`, which
/// becomes `active` on the next `swap()`.
pub struct SendTracker {
    active: FxHashSet<usize>,
    pending: FxHashSet<usize>,
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
    pub fn drain_active(&mut self) -> impl Iterator<Item = usize> + '_ {
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
    pub fn unmark(&mut self, key: usize) {
        self.active.remove(&key);
        self.pending.remove(&key);
    }

    /// Check if any connections need sending (across both sets).
    #[inline(always)]
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.active.is_empty() && self.pending.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_and_drain_active() {
        let mut tracker = SendTracker::new();
        tracker.mark(SendReady(42));
        tracker.mark(SendReady(7));
        tracker.swap();
        let active: Vec<usize> = tracker.drain_active().collect();
        assert_eq!(active.len(), 2);
        assert!(active.contains(&42));
        assert!(active.contains(&7));
    }

    #[test]
    fn unmark_removes_from_both_sets() {
        let mut tracker = SendTracker::new();
        tracker.mark(SendReady(10));
        tracker.swap();
        tracker.mark(SendReady(10));
        tracker.unmark(10);
        assert!(tracker.is_empty());
    }
}
