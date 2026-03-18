use slab::Slab;

// --- Public types ---

/// Opaque timer identity. Callers create these; the wheel stores and returns them on expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerId(pub u64);

/// Handle returned by [`TimerWheel::arm`]. Pass to [`TimerWheel::cancel`] to disarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerHandle(usize);

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
}
