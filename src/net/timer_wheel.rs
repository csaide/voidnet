use coarsetime::Instant;
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
    #[cfg(test)]
    pub(crate) fn from_raw(key: usize) -> Self {
        Self(key)
    }
}

// --- Internal types ---

struct TimerEntry {
    id: TimerId,
    deadline_ms: u64,
    next: Option<usize>,
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
    shift: u8,
}

impl Tier {
    fn new(shift: u8) -> Self {
        Self {
            slots: std::array::from_fn(|_| Slot::new()),
            shift,
        }
    }
}

/// Total range of the 3-tier wheel in milliseconds (256^3 ≈ 16.7M ms ≈ 4.66 hrs).
const TOTAL_RANGE_MS: u64 = 256 * 256 * 256;

/// Hierarchical timer wheel with three tiers.
///
/// - Tier 0 (inner):  shift=0,  1 ms resolution,  256 ms range
/// - Tier 1 (middle): shift=8,  256 ms resolution, ~65.5 s range
/// - Tier 2 (outer):  shift=16, ~65.5 s resolution, ~4.66 hr range
///
/// The wheel stores a base [`Instant`] and converts all deadlines to
/// millisecond offsets internally. Callers work with `Instant` values.
pub struct TimerWheel {
    tiers: [Tier; 3],
    entries: Slab<TimerEntry>,
    current_tick_ms: u64,
    base: Instant,
}

impl TimerWheel {
    /// Create a new wheel. The provided `base` instant is the time origin —
    /// all deadlines are measured as millisecond offsets from this point.
    pub fn new(base: Instant) -> Self {
        Self {
            tiers: [Tier::new(0), Tier::new(8), Tier::new(16)],
            entries: Slab::new(),
            current_tick_ms: 0,
            base,
        }
    }

    /// Convert an [`Instant`] to internal milliseconds relative to base.
    #[inline]
    fn to_ms(&self, t: Instant) -> u64 {
        t.duration_since(self.base).as_millis()
    }

    /// Arm a timer that fires at `deadline`.
    ///
    /// Returns a [`TimerHandle`] that can be passed to [`cancel`](Self::cancel).
    pub fn arm(&mut self, id: TimerId, deadline: Instant) -> TimerHandle {
        self.arm_ms(id, self.to_ms(deadline))
    }

    /// Internal arm using raw millisecond offset. Used by cascade and tests.
    fn arm_ms(&mut self, id: TimerId, deadline_ms: u64) -> TimerHandle {
        let delta = deadline_ms.saturating_sub(self.current_tick_ms);

        let tier_idx: usize = if delta < 256 {
            0
        } else if delta < 65536 {
            1
        } else {
            2
        };

        let shift = self.tiers[tier_idx].shift;
        let slot_idx = ((deadline_ms >> shift) & 0xFF) as usize;
        let slot_packed = ((tier_idx as u16) << 8) | (slot_idx as u16);

        let old_head = self.tiers[tier_idx].slots[slot_idx].head;

        let key = self.entries.insert(TimerEntry {
            id,
            deadline_ms,
            next: old_head,
            prev: None,
            slot: slot_packed,
        });

        if let Some(old_head_key) = old_head {
            self.entries[old_head_key].prev = Some(key);
        }
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

    /// Advance the wheel to `now`, firing all expired timers.
    ///
    /// Uses rotation-based skipping: instead of ticking one ms at a time,
    /// processes inner-wheel slots in bulk and cascades at rotation boundaries.
    /// If the wheel is empty or the jump exceeds the total wheel range,
    /// fast-paths avoid unnecessary work.
    pub fn advance(&mut self, now: Instant) -> SmallVec<[TimerId; 16]> {
        let now_ms = self.to_ms(now);
        self.advance_ms(now_ms)
    }

    /// Internal advance using raw milliseconds.
    fn advance_ms(&mut self, now_ms: u64) -> SmallVec<[TimerId; 16]> {
        let mut fired: SmallVec<[TimerId; 16]> = SmallVec::new();

        if self.current_tick_ms >= now_ms {
            return fired;
        }

        // Fast path: no entries — just jump.
        if self.entries.is_empty() {
            self.current_tick_ms = now_ms;
            return fired;
        }

        let remaining = now_ms - self.current_tick_ms;

        // Fast path: jump exceeds total wheel range — drain everything.
        if remaining >= TOTAL_RANGE_MS {
            self.drain_all_tiers(&mut fired);
            self.current_tick_ms = now_ms;
            return fired;
        }

        // Rotation-based advance: process inner slots in bulk per rotation.
        while self.current_tick_ms < now_ms {
            // Fast exit if all entries were fired.
            if self.entries.is_empty() {
                self.current_tick_ms = now_ms;
                break;
            }

            let current_inner = (self.current_tick_ms & 0xFF) as usize;
            let ticks_to_wrap = (256 - current_inner) as u64;
            let remaining = now_ms - self.current_tick_ms;

            if remaining >= ticks_to_wrap {
                // Complete this inner rotation: drain slots [current_inner..256)
                for slot_idx in current_inner..256 {
                    self.drain_inner_slot(slot_idx, &mut fired);
                }
                self.current_tick_ms += ticks_to_wrap;

                // Inner wrapped to 0 — cascade tier 1.
                self.cascade(1);

                // Check if middle also wrapped — cascade tier 2.
                if ((self.current_tick_ms >> 8) & 0xFF) == 0 && self.current_tick_ms > 0 {
                    self.cascade(2);
                }
            } else {
                // Partial rotation: drain slots [current_inner..now_inner)
                let end_inner = (now_ms & 0xFF) as usize;
                for slot_idx in current_inner..end_inner {
                    self.drain_inner_slot(slot_idx, &mut fired);
                }
                self.current_tick_ms = now_ms;
            }
        }

        fired
    }

    /// Drain a single inner-tier slot, collecting fired timer IDs.
    fn drain_inner_slot(&mut self, slot_idx: usize, fired: &mut SmallVec<[TimerId; 16]>) {
        let mut cursor = self.tiers[0].slots[slot_idx].head;
        self.tiers[0].slots[slot_idx].head = None;
        while let Some(key) = cursor {
            let entry = self.entries.remove(key);
            cursor = entry.next;
            fired.push(entry.id);
        }
    }

    /// Drain all entries from all tiers. Used when advance jumps past the
    /// total wheel range.
    fn drain_all_tiers(&mut self, fired: &mut SmallVec<[TimerId; 16]>) {
        for tier in &mut self.tiers {
            for slot in &mut tier.slots {
                let mut cursor = slot.head;
                slot.head = None;
                while let Some(key) = cursor {
                    let entry = self.entries.remove(key);
                    cursor = entry.next;
                    fired.push(entry.id);
                }
            }
        }
    }

    /// Cascade: redistribute entries from one tier's current slot into lower tiers.
    fn cascade(&mut self, tier_idx: usize) {
        let shift = self.tiers[tier_idx].shift;
        let slot_idx = ((self.current_tick_ms >> shift) & 0xFF) as usize;

        let mut to_rearm: SmallVec<[(TimerId, u64); 64]> = SmallVec::new();
        let mut cursor = self.tiers[tier_idx].slots[slot_idx].head;
        self.tiers[tier_idx].slots[slot_idx].head = None;
        while let Some(key) = cursor {
            let entry = self.entries.remove(key);
            cursor = entry.next;
            to_rearm.push((entry.id, entry.deadline_ms));
        }

        for (id, deadline_ms) in to_rearm {
            self.arm_ms(id, deadline_ms);
        }
    }

    /// Cancel a previously armed timer. No-op if already fired or cancelled.
    pub fn cancel(&mut self, handle: TimerHandle) {
        let Some(entry) = self.entries.try_remove(handle.0) else {
            return;
        };

        let tier_idx = ((entry.slot >> 8) & 0x3) as usize;
        let slot_idx = (entry.slot & 0xFF) as usize;

        match entry.prev {
            Some(prev_key) => {
                self.entries[prev_key].next = entry.next;
            }
            None => {
                self.tiers[tier_idx].slots[slot_idx].head = entry.next;
            }
        }

        if let Some(next_key) = entry.next {
            self.entries[next_key].prev = entry.prev;
        }
    }

    /// Drain all timers and return their IDs. Useful in tests.
    pub fn drain_all(&mut self) -> SmallVec<[TimerId; 16]> {
        let mut fired = SmallVec::new();
        self.drain_all_tiers(&mut fired);
        fired
    }
}

// ---------------------------------------------------------------------------
// Tests — use raw ms via arm_ms / advance_ms to test wheel mechanics directly.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a wheel at ms=0 for unit tests.
    fn test_wheel(start_ms: u64) -> TimerWheel {
        let mut w = TimerWheel::new(Instant::now());
        w.current_tick_ms = start_ms;
        w
    }

    #[test]
    fn arm_returns_handle() {
        let mut wheel = test_wheel(0);
        let handle = wheel.arm_ms(TimerId(1), 50);
        assert!(wheel.is_armed(handle));
    }

    #[test]
    fn arm_places_in_correct_inner_slot() {
        let mut wheel = test_wheel(0);
        wheel.arm_ms(TimerId(2), 50);
        assert!(wheel.tiers[0].slots[50].head.is_some());
    }

    #[test]
    fn arm_places_in_middle_tier_for_large_delta() {
        let mut wheel = test_wheel(0);
        let expected_slot = (1000usize >> 8) & 0xFF;
        wheel.arm_ms(TimerId(3), 1000);
        assert!(wheel.tiers[1].slots[expected_slot].head.is_some());
    }

    #[test]
    fn arm_places_in_outer_tier_for_huge_delta() {
        let mut wheel = test_wheel(0);
        let expected_slot = (100_000usize >> 16) & 0xFF;
        wheel.arm_ms(TimerId(4), 100_000);
        assert!(wheel.tiers[2].slots[expected_slot].head.is_some());
    }

    #[test]
    fn arm_multiple_same_slot_chains_correctly() {
        let mut wheel = test_wheel(0);
        let h1 = wheel.arm_ms(TimerId(10), 50);
        let h2 = wheel.arm_ms(TimerId(11), 50);
        assert!(wheel.is_armed(h1));
        assert!(wheel.is_armed(h2));
        assert_ne!(h1, h2);
        let head_key = wheel.tiers[0].slots[50].head.expect("should have head");
        assert_eq!(head_key, h2.0);
        assert_eq!(wheel.entries[h2.0].next, Some(h1.0));
        assert_eq!(wheel.entries[h1.0].prev, Some(h2.0));
    }

    // --- cancel ---

    #[test]
    fn cancel_removes_entry() {
        let mut wheel = test_wheel(0);
        let h = wheel.arm_ms(TimerId(1), 50);
        assert!(wheel.is_armed(h));
        wheel.cancel(h);
        assert!(!wheel.is_armed(h));
    }

    #[test]
    fn cancel_unlinks_head() {
        let mut wheel = test_wheel(0);
        let h1 = wheel.arm_ms(TimerId(1), 50);
        let h2 = wheel.arm_ms(TimerId(2), 50);
        wheel.cancel(h2);
        assert!(!wheel.is_armed(h2));
        assert!(wheel.is_armed(h1));
        assert_eq!(wheel.tiers[0].slots[50].head, Some(h1.0));
        assert_eq!(wheel.entries[h1.0].prev, None);
    }

    #[test]
    fn cancel_unlinks_middle() {
        let mut wheel = test_wheel(0);
        let h1 = wheel.arm_ms(TimerId(1), 50);
        let h2 = wheel.arm_ms(TimerId(2), 50);
        let h3 = wheel.arm_ms(TimerId(3), 50);
        wheel.cancel(h2);
        assert!(wheel.is_armed(h1));
        assert!(!wheel.is_armed(h2));
        assert!(wheel.is_armed(h3));
        assert_eq!(wheel.entries[h3.0].next, Some(h1.0));
        assert_eq!(wheel.entries[h1.0].prev, Some(h3.0));
    }

    #[test]
    fn cancel_unlinks_tail() {
        let mut wheel = test_wheel(0);
        let h1 = wheel.arm_ms(TimerId(1), 50);
        let h2 = wheel.arm_ms(TimerId(2), 50);
        wheel.cancel(h1);
        assert!(!wheel.is_armed(h1));
        assert!(wheel.is_armed(h2));
        assert_eq!(wheel.entries[h2.0].next, None);
    }

    #[test]
    fn cancel_invalid_handle_is_noop() {
        let mut wheel = test_wheel(0);
        let h = wheel.arm_ms(TimerId(1), 50);
        wheel.cancel(h);
        wheel.cancel(h); // double cancel — must not panic
    }

    // --- advance ---

    #[test]
    fn advance_fires_inner_slot_timer() {
        let mut wheel = test_wheel(0);
        wheel.arm_ms(TimerId(1), 50);
        let fired = wheel.advance_ms(51);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0], TimerId(1));
    }

    #[test]
    fn advance_fires_multiple_timers_same_slot() {
        let mut wheel = test_wheel(0);
        wheel.arm_ms(TimerId(1), 50);
        wheel.arm_ms(TimerId(2), 50);
        let fired = wheel.advance_ms(51);
        assert_eq!(fired.len(), 2);
    }

    #[test]
    fn advance_does_not_fire_future_timer() {
        let mut wheel = test_wheel(0);
        wheel.arm_ms(TimerId(1), 100);
        let fired = wheel.advance_ms(50);
        assert!(fired.is_empty());
    }

    // --- cascade ---

    #[test]
    fn cascade_middle_to_inner() {
        let mut wheel = test_wheel(0);
        let handle = wheel.arm_ms(TimerId(42), 300);
        assert!(wheel.is_armed(handle));
        let fired = wheel.advance_ms(256);
        assert!(fired.is_empty());
        let expected_slot = 300usize & 0xFF; // 44
        assert!(wheel.tiers[0].slots[expected_slot].head.is_some());
    }

    #[test]
    fn cascade_fires_on_correct_tick() {
        let mut wheel = test_wheel(0);
        wheel.arm_ms(TimerId(7), 300);
        let fired = wheel.advance_ms(301);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0], TimerId(7));
    }

    #[test]
    fn cascade_outer_to_middle() {
        let mut wheel = test_wheel(0);
        let handle = wheel.arm_ms(TimerId(99), 70_000);
        assert!(wheel.is_armed(handle));
        let fired = wheel.advance_ms(65_536);
        assert!(fired.is_empty());
        assert!(wheel.tiers[2].slots[1].head.is_none());
        let expected_slot = (70_000usize >> 8) & 0xFF;
        assert!(wheel.tiers[1].slots[expected_slot].head.is_some());
    }

    #[test]
    fn cascade_multiple_entries() {
        let mut wheel = test_wheel(0);
        wheel.arm_ms(TimerId(1), 300);
        wheel.arm_ms(TimerId(2), 310);
        wheel.arm_ms(TimerId(3), 500);
        let fired = wheel.advance_ms(311);
        assert_eq!(fired.len(), 2);
        let mut ids: Vec<u64> = fired.iter().map(|t| t.0).collect();
        ids.sort_unstable();
        assert_eq!(ids, vec![1, 2]);
    }

    // --- edge cases ---

    #[test]
    fn rearm_cancel_then_arm() {
        let mut wheel = test_wheel(0);
        let h1 = wheel.arm_ms(TimerId(1), 50);
        wheel.cancel(h1);
        assert!(!wheel.is_armed(h1));
        let _h2 = wheel.arm_ms(TimerId(1), 150);
        assert_eq!(wheel.entry_count(), 1);
        let not_fired = wheel.advance_ms(100);
        assert!(not_fired.is_empty());
        let fired = wheel.advance_ms(151);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0], TimerId(1));
    }

    #[test]
    fn arm_at_current_tick_fires_on_next_advance() {
        let mut wheel = test_wheel(100);
        wheel.arm_ms(TimerId(55), 100);
        let fired = wheel.advance_ms(101);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0], TimerId(55));
    }

    #[test]
    fn arm_in_past_fires_on_wrap() {
        let mut wheel = test_wheel(100);
        wheel.arm_ms(TimerId(77), 50);
        // Slot 50 is behind current_tick (100). Must wrap inner wheel to reach it.
        // Wraps at 256, then slot 50 is hit at tick 256+50=306. advance_ms(307) includes it.
        let fired = wheel.advance_ms(307);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0], TimerId(77));
    }

    #[test]
    fn entry_count_returns_armed_count() {
        let mut wheel = test_wheel(0);
        assert_eq!(wheel.entry_count(), 0);
        let h1 = wheel.arm_ms(TimerId(1), 100);
        let _h2 = wheel.arm_ms(TimerId(2), 200);
        assert_eq!(wheel.entry_count(), 2);
        wheel.cancel(h1);
        assert_eq!(wheel.entry_count(), 1);
    }

    #[test]
    fn advance_noop_when_time_unchanged() {
        let mut wheel = test_wheel(100);
        wheel.arm_ms(TimerId(1), 100);
        let fired = wheel.advance_ms(100);
        assert!(fired.is_empty());
    }

    #[test]
    fn advance_catches_up_burst() {
        let mut wheel = test_wheel(0);
        wheel.arm_ms(TimerId(1), 5);
        wheel.arm_ms(TimerId(2), 50);
        wheel.arm_ms(TimerId(3), 200);
        let fired = wheel.advance_ms(201);
        assert_eq!(fired.len(), 3);
        let mut ids: Vec<u64> = fired.iter().map(|t| t.0).collect();
        ids.sort_unstable();
        assert_eq!(ids, vec![1, 2, 3]);
    }

    #[test]
    fn advance_fires_nothing_when_no_timers_due() {
        let mut wheel = test_wheel(0);
        wheel.arm_ms(TimerId(1), 100);
        let fired = wheel.advance_ms(50);
        assert!(fired.is_empty());
        assert_eq!(wheel.entry_count(), 1);
    }

    // --- efficiency ---

    #[test]
    fn advance_large_jump_empty_wheel_is_instant() {
        let mut wheel = test_wheel(0);
        // Jump 1 billion ms with no entries — should not hang.
        let fired = wheel.advance_ms(1_000_000_000);
        assert!(fired.is_empty());
        assert_eq!(wheel.current_tick_ms, 1_000_000_000);
    }

    #[test]
    fn advance_huge_jump_drains_all() {
        let mut wheel = test_wheel(0);
        wheel.arm_ms(TimerId(1), 100);
        wheel.arm_ms(TimerId(2), 50_000);
        wheel.arm_ms(TimerId(3), 10_000_000);
        // Jump past total wheel range — all should fire.
        let fired = wheel.advance_ms(TOTAL_RANGE_MS + 1);
        assert_eq!(fired.len(), 3);
    }

    #[test]
    fn drain_all_returns_all_entries() {
        let mut wheel = test_wheel(0);
        wheel.arm_ms(TimerId(1), 10);
        wheel.arm_ms(TimerId(2), 1000);
        wheel.arm_ms(TimerId(3), 100_000);
        let fired = wheel.drain_all();
        assert_eq!(fired.len(), 3);
        assert_eq!(wheel.entry_count(), 0);
    }
}
