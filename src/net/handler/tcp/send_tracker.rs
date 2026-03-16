/// Marker returned by Tcb methods that make a connection sendable.
/// Must be consumed by passing to `SendTracker::mark()`.
#[must_use = "connection must be marked for sending via SendTracker::mark()"]
pub struct SendReady(pub usize);

/// Tracks which connections have pending send work using a dual-bitset
/// swap pattern. `poll_send` calls `swap()` then iterates the active
/// bitset directly — no hashing, no heap allocation, O(1) set/clear.
/// New marks go into `pending`, which becomes `active` on the next `swap()`.
pub struct SendTracker {
    active: BitSet,
    pending: BitSet,
}

impl SendTracker {
    pub fn new() -> Self {
        Self {
            active: BitSet::new(),
            pending: BitSet::new(),
        }
    }

    /// Swap active/pending sets. Call once at the start of poll_send.
    /// O(1) pointer swap — no allocation, no iteration.
    #[inline(always)]
    pub fn swap(&mut self) {
        std::mem::swap(&mut self.active, &mut self.pending);
    }

    /// Pop the next set bit from the active set. O(1) amortized.
    /// Unlike `drain_active()`, this doesn't hold a borrow across the
    /// call site, so `mark()` can be called between pops.
    #[inline(always)]
    pub fn pop_active(&mut self) -> Option<usize> {
        for (i, word) in self.active.words.iter_mut().enumerate() {
            if *word != 0 {
                let bit = word.trailing_zeros() as usize;
                *word &= *word - 1; // clear lowest set bit
                return Some(i * 64 + bit);
            }
        }
        None
    }

    /// Register a connection as needing send processing.
    /// Always inserts into `pending` — safe to call during drain_active iteration.
    #[inline(always)]
    pub fn mark(&mut self, ready: SendReady) {
        self.pending.set(ready.0);
    }

    /// Remove a connection from both sets (connection closed/removed).
    #[inline(always)]
    pub fn unmark(&mut self, key: usize) {
        self.active.clear(key);
        self.pending.clear(key);
    }

    /// Check if any connections need sending (across both sets).
    #[inline(always)]
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.active.is_empty() && self.pending.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Inline bitset — grows in 64-bit word chunks, no hashing
// ---------------------------------------------------------------------------

/// A dynamically-sized bitset backed by a `Vec<u64>`.
/// Word-level operations make set/clear/iterate very cheap.
struct BitSet {
    words: Vec<u64>,
}

impl BitSet {
    #[inline(always)]
    fn new() -> Self {
        Self { words: Vec::new() }
    }

    #[inline(always)]
    fn set(&mut self, bit: usize) {
        let word = bit / 64;
        let mask = 1u64 << (bit % 64);
        if word >= self.words.len() {
            self.words.resize(word + 1, 0);
        }
        self.words[word] |= mask;
    }

    #[inline(always)]
    fn clear(&mut self, bit: usize) {
        let word = bit / 64;
        if word < self.words.len() {
            self.words[word] &= !(1u64 << (bit % 64));
        }
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.words.iter().all(|&w| w == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: drain all active keys via pop_active.
    fn collect_active(tracker: &mut SendTracker) -> Vec<usize> {
        let mut out = Vec::new();
        while let Some(key) = tracker.pop_active() {
            out.push(key);
        }
        out
    }

    #[test]
    fn mark_and_drain_active() {
        let mut tracker = SendTracker::new();
        tracker.mark(SendReady(42));
        tracker.mark(SendReady(7));
        tracker.swap();
        let active = collect_active(&mut tracker);
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

    #[test]
    fn drain_clears_active_set() {
        let mut tracker = SendTracker::new();
        tracker.mark(SendReady(0));
        tracker.mark(SendReady(63));
        tracker.mark(SendReady(64));
        tracker.mark(SendReady(200));
        tracker.swap();

        let active = collect_active(&mut tracker);
        assert_eq!(active, vec![0, 63, 64, 200]);

        // Active should be empty after drain.
        assert!(tracker.active.is_empty());
    }

    #[test]
    fn mark_during_drain_goes_to_pending() {
        let mut tracker = SendTracker::new();
        tracker.mark(SendReady(5));
        tracker.swap();

        // Simulate marking during iteration (goes to pending, not active).
        tracker.mark(SendReady(99));

        let active = collect_active(&mut tracker);
        assert_eq!(active, vec![5]);

        // 99 should appear in next cycle.
        tracker.swap();
        let active = collect_active(&mut tracker);
        assert_eq!(active, vec![99]);
    }

    #[test]
    fn duplicate_marks_produce_single_entry() {
        let mut tracker = SendTracker::new();
        tracker.mark(SendReady(10));
        tracker.mark(SendReady(10));
        tracker.mark(SendReady(10));
        tracker.swap();
        let active = collect_active(&mut tracker);
        assert_eq!(active, vec![10]);
    }
}
