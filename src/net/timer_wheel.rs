use slab::Slab;
use smallvec::SmallVec;

// --- Public types ---

/// Opaque timer identity. Callers create these; the wheel stores and returns them on expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerId(pub u64);

/// Handle returned by [`TimerWheel::arm`]. Pass to [`TimerWheel::cancel`] to disarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerHandle(usize);

impl TimerHandle {
    /// Construct a handle from a raw slab key. Intended for tests and internal use only.
    pub(crate) fn from_raw(key: usize) -> Self {
        Self(key)
    }
}

// --- Internal types ---

struct TimerEntry {
    id: TimerId,
    deadline_ms: u64,
    /// Next entry key in the slot's doubly-linked list (slab key).
    next: Option<usize>,
    /// Previous entry key in the slot's doubly-linked list (slab key).
    prev: Option<usize>,
    /// Packed: bits [9:8] = tier index (0-2), bits [7:0] = slot index within tier.
    slot: u16,
}

struct Slot {
    head: Option<usize>,
}

impl Slot {
    const fn new() -> Self {
        Self { head: None }
    }
}

struct Tier {
    slots: [Slot; 256],
    /// Number of bits to right-shift a deadline_ms to get the slot index.
    shift: u8,
}

impl Tier {
    fn new(shift: u8) -> Self {
        // SAFETY: Slot is a struct with no padding issues; initializing an array of 256 items
        // via a const fn is idiomatic.
        Self {
            slots: std::array::from_fn(|_| Slot::new()),
            shift,
        }
    }
}

/// Hierarchical timer wheel with three tiers.
///
/// - Tier 0 (inner):  shift=0,  1 ms resolution,  256 ms range
/// - Tier 1 (middle): shift=8,  256 ms resolution, ~65.5 s range
/// - Tier 2 (outer):  shift=16, ~65.5 s resolution, ~4.66 hr range
pub struct TimerWheel {
    tiers: [Tier; 3],
    entries: Slab<TimerEntry>,
    current_tick_ms: u64,
}

impl TimerWheel {
    /// Create a new wheel with `current_tick_ms` as the reference time.
    pub fn new(current_tick_ms: u64) -> Self {
        Self {
            tiers: [Tier::new(0), Tier::new(8), Tier::new(16)],
            entries: Slab::new(),
            current_tick_ms,
        }
    }

    /// Arm a timer that fires at `deadline_ms` (absolute ms since epoch/start).
    ///
    /// Returns a [`TimerHandle`] that can be passed to [`cancel`](Self::cancel).
    pub fn arm(&mut self, id: TimerId, deadline_ms: u64) -> TimerHandle {
        let delta = deadline_ms.saturating_sub(self.current_tick_ms);

        // Select tier based on how far out the deadline is.
        let tier_idx: usize = if delta < 256 {
            0
        } else if delta < 65536 {
            1
        } else {
            2
        };

        let shift = self.tiers[tier_idx].shift;
        let slot_idx = ((deadline_ms >> shift) & 0xFF) as usize;

        // Pack tier_idx (2 bits high) | slot_idx (8 bits low) into slot field.
        let slot_packed = ((tier_idx as u16) << 8) | (slot_idx as u16);

        // Grab current head before borrowing entries.
        let old_head = self.tiers[tier_idx].slots[slot_idx].head;

        let entry = TimerEntry {
            id,
            deadline_ms,
            next: old_head,
            prev: None,
            slot: slot_packed,
        };

        let key = self.entries.insert(entry);

        // If there was an old head, update its prev pointer.
        if let Some(old_head_key) = old_head {
            self.entries[old_head_key].prev = Some(key);
        }

        // The new entry becomes the head.
        self.tiers[tier_idx].slots[slot_idx].head = Some(key);

        TimerHandle(key)
    }

    /// Returns `true` if the timer identified by `handle` is still armed.
    pub fn is_armed(&self, handle: TimerHandle) -> bool {
        self.entries.contains(handle.0)
    }

    /// Returns the number of currently armed timers.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Advance the wheel to `now_ms`, firing all timers whose deadline has
    /// passed.  Returns the [`TimerId`]s of every fired timer.
    pub fn advance(&mut self, now_ms: u64) -> SmallVec<[TimerId; 16]> {
        let mut fired: SmallVec<[TimerId; 16]> = SmallVec::new();

        while self.current_tick_ms < now_ms {
            let inner_slot_idx = (self.current_tick_ms & 0xFF) as usize;

            // Drain the inner wheel slot for this tick.
            let mut cursor = self.tiers[0].slots[inner_slot_idx].head;
            self.tiers[0].slots[inner_slot_idx].head = None;
            while let Some(key) = cursor {
                let entry = self.entries.remove(key);
                cursor = entry.next;
                fired.push(entry.id);
            }

            self.current_tick_ms += 1;

            // After incrementing, check whether we need to cascade.
            // Inner → middle cascade: inner slot just wrapped back to 0.
            if (self.current_tick_ms & 0xFF) == 0 && self.current_tick_ms > 0 {
                self.cascade(1);

                // Middle → outer cascade: middle slot also just wrapped.
                let middle_slot_idx =
                    ((self.current_tick_ms >> self.tiers[1].shift) & 0xFF) as usize;
                if middle_slot_idx == 0 {
                    self.cascade(2);
                }
            }
        }

        fired
    }

    /// Re-distribute entries from one tier's current slot into lower tiers.
    ///
    /// Tier `tier_idx` has just advanced such that its slot pointer has wrapped
    /// to 0.  We drain the slot that `current_tick_ms` now points to in that
    /// tier and re-arm each entry using its stored `deadline_ms` so it lands in
    /// the correct (lower) tier.
    fn cascade(&mut self, tier_idx: usize) {
        let shift = self.tiers[tier_idx].shift;
        let slot_idx = ((self.current_tick_ms >> shift) & 0xFF) as usize;

        // Collect all entries from the slot BEFORE re-arming (arm() mutates
        // the entries slab, so we cannot hold borrows across that call).
        let mut to_rearm: SmallVec<[(TimerId, u64); 64]> = SmallVec::new();
        let mut cursor = self.tiers[tier_idx].slots[slot_idx].head;
        self.tiers[tier_idx].slots[slot_idx].head = None;
        while let Some(key) = cursor {
            let entry = self.entries.remove(key);
            cursor = entry.next;
            to_rearm.push((entry.id, entry.deadline_ms));
        }

        // Re-arm each entry; the smaller delta will place it in a lower tier.
        for (id, deadline_ms) in to_rearm {
            self.arm(id, deadline_ms);
        }
    }

    /// Cancel a previously armed timer.
    ///
    /// If `handle` does not refer to an active timer (already fired or already
    /// cancelled), this is a no-op.
    pub fn cancel(&mut self, handle: TimerHandle) {
        // Remove the entry from the slab; bail silently if not present.
        let entry = match self.entries.try_remove(handle.0) {
            Some(e) => e,
            None => return,
        };

        // Decode the packed slot field.
        let tier_idx = ((entry.slot >> 8) & 0x3) as usize;
        let slot_idx = (entry.slot & 0xFF) as usize;

        // Unlink from the doubly-linked list.
        match entry.prev {
            Some(prev_key) => {
                // There is a predecessor — point it past the removed entry.
                self.entries[prev_key].next = entry.next;
            }
            None => {
                // No predecessor: this entry was the slot head.
                self.tiers[tier_idx].slots[slot_idx].head = entry.next;
            }
        }

        if let Some(next_key) = entry.next {
            self.entries[next_key].prev = entry.prev;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm_returns_handle() {
        let mut wheel = TimerWheel::new(0);
        let handle = wheel.arm(TimerId(1), 50);
        assert!(wheel.is_armed(handle));
    }

    #[test]
    fn arm_places_in_correct_inner_slot() {
        let mut wheel = TimerWheel::new(0);
        // delta = 50 < 256 → tier 0, slot = (50 >> 0) & 0xFF = 50
        wheel.arm(TimerId(2), 50);
        assert!(wheel.tiers[0].slots[50].head.is_some());
    }

    #[test]
    fn arm_places_in_middle_tier_for_large_delta() {
        let mut wheel = TimerWheel::new(0);
        // delta = 1000; 256 ≤ 1000 < 65536 → tier 1
        // slot = (1000 >> 8) & 0xFF = 3
        let expected_slot = (1000usize >> 8) & 0xFF;
        wheel.arm(TimerId(3), 1000);
        assert!(wheel.tiers[1].slots[expected_slot].head.is_some());
    }

    #[test]
    fn arm_places_in_outer_tier_for_huge_delta() {
        let mut wheel = TimerWheel::new(0);
        // delta = 100_000 ≥ 65536 → tier 2
        // slot = (100_000 >> 16) & 0xFF = 1
        let expected_slot = (100_000usize >> 16) & 0xFF;
        wheel.arm(TimerId(4), 100_000);
        assert!(wheel.tiers[2].slots[expected_slot].head.is_some());
    }

    #[test]
    fn arm_multiple_same_slot_chains_correctly() {
        let mut wheel = TimerWheel::new(0);
        let h1 = wheel.arm(TimerId(10), 50);
        let h2 = wheel.arm(TimerId(11), 50);

        // Both handles must be armed.
        assert!(wheel.is_armed(h1));
        assert!(wheel.is_armed(h2));

        // Both slab keys must differ.
        assert_ne!(h1, h2);

        // The slot head must point to h2 (most recently armed, prepended).
        let head_key = wheel.tiers[0].slots[50]
            .head
            .expect("slot should have a head");
        assert_eq!(head_key, h2.0);

        // h2.next must be h1.
        let h2_entry = &wheel.entries[h2.0];
        assert_eq!(h2_entry.next, Some(h1.0));

        // h1.prev must be h2.
        let h1_entry = &wheel.entries[h1.0];
        assert_eq!(h1_entry.prev, Some(h2.0));
    }

    // --- cancel tests ---

    #[test]
    fn cancel_removes_entry() {
        let mut wheel = TimerWheel::new(0);
        let h = wheel.arm(TimerId(1), 50);
        assert!(wheel.is_armed(h));
        wheel.cancel(h);
        assert!(!wheel.is_armed(h));
    }

    #[test]
    fn cancel_unlinks_head() {
        // arm h1, then h2 → chain: h2(head) → h1
        // cancel h2 (head) → h1 should become the new head
        let mut wheel = TimerWheel::new(0);
        let h1 = wheel.arm(TimerId(1), 50);
        let h2 = wheel.arm(TimerId(2), 50);

        wheel.cancel(h2);

        assert!(!wheel.is_armed(h2));
        assert!(wheel.is_armed(h1));

        // h1 should now be the slot head
        let tier_idx = 0usize; // delta=50 < 256
        let slot_idx = 50usize; // (50 >> 0) & 0xFF
        let head_key = wheel.tiers[tier_idx].slots[slot_idx]
            .head
            .expect("slot should still have a head after cancelling h2");
        assert_eq!(head_key, h1.0);

        // h1.prev should be None (it is now the head)
        assert_eq!(wheel.entries[h1.0].prev, None);
    }

    #[test]
    fn cancel_unlinks_middle() {
        // arm h1, h2, h3 → chain: h3(head) → h2 → h1
        // cancel h2 → chain should be: h3 → h1
        let mut wheel = TimerWheel::new(0);
        let h1 = wheel.arm(TimerId(1), 50);
        let h2 = wheel.arm(TimerId(2), 50);
        let h3 = wheel.arm(TimerId(3), 50);

        wheel.cancel(h2);

        assert!(wheel.is_armed(h1));
        assert!(!wheel.is_armed(h2));
        assert!(wheel.is_armed(h3));

        // h3.next should now point to h1
        assert_eq!(wheel.entries[h3.0].next, Some(h1.0));
        // h1.prev should now point to h3
        assert_eq!(wheel.entries[h1.0].prev, Some(h3.0));
    }

    #[test]
    fn cancel_unlinks_tail() {
        // arm h1, h2 → chain: h2(head) → h1(tail)
        // cancel h1 (tail) → chain: h2 only
        let mut wheel = TimerWheel::new(0);
        let h1 = wheel.arm(TimerId(1), 50);
        let h2 = wheel.arm(TimerId(2), 50);

        wheel.cancel(h1);

        assert!(!wheel.is_armed(h1));
        assert!(wheel.is_armed(h2));

        // h2.next should now be None (h1 was removed)
        assert_eq!(wheel.entries[h2.0].next, None);
    }

    #[test]
    fn cancel_invalid_handle_is_noop() {
        let mut wheel = TimerWheel::new(0);
        let h = wheel.arm(TimerId(1), 50);
        wheel.cancel(h);
        // Cancelling the same handle again should not panic.
        wheel.cancel(h);
    }

    // -----------------------------------------------------------------------
    // Task 3: advance basic tests
    // -----------------------------------------------------------------------

    #[test]
    fn advance_fires_inner_slot_timer() {
        let mut wheel = TimerWheel::new(0);
        wheel.arm(TimerId(1), 50);
        let fired = wheel.advance(51);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0], TimerId(1));
    }

    #[test]
    fn advance_fires_multiple_timers_same_slot() {
        let mut wheel = TimerWheel::new(0);
        wheel.arm(TimerId(1), 50);
        wheel.arm(TimerId(2), 50);
        let fired = wheel.advance(51);
        assert_eq!(fired.len(), 2);
    }

    #[test]
    fn advance_does_not_fire_future_timer() {
        let mut wheel = TimerWheel::new(0);
        wheel.arm(TimerId(1), 100);
        let fired = wheel.advance(50);
        assert!(fired.is_empty());
    }

    // -----------------------------------------------------------------------
    // Task 4: Cascade verification tests
    // -----------------------------------------------------------------------

    /// Arm at 300 ms (goes to middle tier). Advance to 256 (triggers
    /// inner→middle cascade). The timer should now live in inner tier slot 44
    /// (300 & 0xFF == 44) but must NOT yet have fired.
    #[test]
    fn cascade_middle_to_inner() {
        let mut wheel = TimerWheel::new(0);
        let handle = wheel.arm(TimerId(42), 300);
        assert!(wheel.is_armed(handle));

        // Advancing to 256 crosses the inner wrap boundary and cascades tier 1.
        let fired = wheel.advance(256);
        assert!(fired.is_empty(), "timer not due yet; should not fire");

        // After cascade the entry should be in inner tier slot 44 (300 & 0xFF).
        let expected_slot = 300usize & 0xFF; // 44
        assert!(
            wheel.tiers[0].slots[expected_slot].head.is_some(),
            "cascaded entry should now be in inner slot {expected_slot}"
        );
    }

    /// Arm at 300 ms. Advance all the way to 301. The timer must fire.
    #[test]
    fn cascade_fires_on_correct_tick() {
        let mut wheel = TimerWheel::new(0);
        wheel.arm(TimerId(7), 300);
        let fired = wheel.advance(301);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0], TimerId(7));
    }

    /// Arm at 70_000 ms (outer tier). Advance to 65_536 (triggers
    /// middle→outer cascade). The entry should now be in the middle tier.
    #[test]
    fn cascade_outer_to_middle() {
        let mut wheel = TimerWheel::new(0);
        let handle = wheel.arm(TimerId(99), 70_000);
        assert!(wheel.is_armed(handle));

        // 65_536 == 256 * 256; crossing this wraps the middle wheel and
        // triggers a cascade from the outer tier.
        let fired = wheel.advance(65_536);
        assert!(fired.is_empty(), "timer not due yet");

        // After cascade, entry should be in middle tier, not outer.
        // Outer tier slot for 70_000: (70_000 >> 16) & 0xFF == 1
        assert!(
            wheel.tiers[2].slots[1].head.is_none(),
            "outer slot should be empty after cascade"
        );
        // Middle tier: delta from 65_536 to 70_000 is 4_464 < 65_536, and
        // slot = (70_000 >> 8) & 0xFF == 273 & 0xFF == 17.
        let expected_slot = (70_000usize >> 8) & 0xFF; // 17
        assert!(
            wheel.tiers[1].slots[expected_slot].head.is_some(),
            "cascaded entry should now be in middle slot {expected_slot}"
        );
    }

    /// Arm at 300, 310, 500. Advance to 311. Timers at 300 and 310 must fire;
    /// the one at 500 must not.
    #[test]
    fn cascade_multiple_entries() {
        let mut wheel = TimerWheel::new(0);
        wheel.arm(TimerId(1), 300);
        wheel.arm(TimerId(2), 310);
        wheel.arm(TimerId(3), 500);

        let fired = wheel.advance(311);
        assert_eq!(fired.len(), 2, "exactly two timers should fire");

        let mut ids: Vec<u64> = fired.iter().map(|t| t.0).collect();
        ids.sort_unstable();
        assert_eq!(ids, vec![1, 2]);
    }

    // -----------------------------------------------------------------------
    // Task 5: entry_count and edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn rearm_cancel_then_arm() {
        let mut wheel = TimerWheel::new(0);
        let h1 = wheel.arm(TimerId(1), 50);
        wheel.cancel(h1);
        // Timer should no longer be armed immediately after cancel.
        assert!(!wheel.is_armed(h1));

        // Re-arm the same logical timer with a new deadline.  The slab may
        // reuse the freed key, so h1 and h2 might be equal; what matters is
        // that only one timer fires at the new deadline and not at the old one.
        let _h2 = wheel.arm(TimerId(1), 150);
        assert_eq!(wheel.entry_count(), 1, "exactly one timer should be armed");

        // Nothing fires before the new deadline.
        let not_fired = wheel.advance(100);
        assert!(not_fired.is_empty(), "should not fire before new deadline");

        // Fires at the new deadline.
        let fired = wheel.advance(151);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0], TimerId(1));
    }

    /// Wheel at 100; arm at 100. Advancing to 101 should fire the timer.
    #[test]
    fn arm_at_current_tick_fires_on_next_advance() {
        let mut wheel = TimerWheel::new(100);
        // delta = 0, saturating_sub → goes to inner slot (100 & 0xFF == 100).
        wheel.arm(TimerId(55), 100);
        let fired = wheel.advance(101);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0], TimerId(55));
    }

    /// Wheel at 100; arm deadline in the past (50). Delta saturates to 0 →
    /// goes to inner slot (50 & 0xFF == 50). The wheel must wrap around to
    /// that slot to fire it.
    #[test]
    fn arm_in_past_fires_on_next_advance() {
        let mut wheel = TimerWheel::new(100);
        // delta = 0 (saturated), slot = (50 >> 0) & 0xFF = 50.
        // current_tick_ms starts at 100 so slot 50 is behind us in this
        // rotation.  The inner wheel wraps at 256, so slot 50 is drained when
        // current_tick_ms == 306 (306 & 0xFF == 50).  advance(N) processes
        // ticks up to but not including N, so we need advance(307) to include
        // tick 306.
        wheel.arm(TimerId(77), 50);

        let fired = wheel.advance(307);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0], TimerId(77));
    }

    #[test]
    fn entry_count_returns_armed_count() {
        let mut wheel = TimerWheel::new(0);
        assert_eq!(wheel.entry_count(), 0);

        let h1 = wheel.arm(TimerId(1), 100);
        let _h2 = wheel.arm(TimerId(2), 200);
        assert_eq!(wheel.entry_count(), 2);

        wheel.cancel(h1);
        assert_eq!(wheel.entry_count(), 1);
    }

    #[test]
    fn advance_noop_when_time_unchanged() {
        let mut wheel = TimerWheel::new(100);
        wheel.arm(TimerId(1), 100);
        // advance(100) — current_tick_ms is already 100, loop does not execute.
        let fired = wheel.advance(100);
        assert!(fired.is_empty());
    }

    #[test]
    fn advance_catches_up_burst() {
        let mut wheel = TimerWheel::new(0);
        wheel.arm(TimerId(1), 5);
        wheel.arm(TimerId(2), 50);
        wheel.arm(TimerId(3), 200);

        let fired = wheel.advance(201);
        assert_eq!(fired.len(), 3);
        let mut ids: Vec<u64> = fired.iter().map(|t| t.0).collect();
        ids.sort_unstable();
        assert_eq!(ids, vec![1, 2, 3]);
    }

    #[test]
    fn advance_fires_nothing_when_no_timers_due() {
        let mut wheel = TimerWheel::new(0);
        wheel.arm(TimerId(1), 100);
        let fired = wheel.advance(50);
        assert!(fired.is_empty());
        assert_eq!(wheel.entry_count(), 1, "timer should still be armed");
    }
}
