# Timer Wheel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace O(n) TCP timer scanning with a protocol-agnostic hierarchical timer wheel that supports 10k+ connections with O(1) arm/cancel and O(fired) advance.

**Architecture:** A 3-tier hierarchical timer wheel (1ms/256ms/65.5s resolution) with entries in a slab-allocated doubly-linked list. The wheel lives at `src/net/timer_wheel.rs`, protocol-agnostic. TCP-specific timer kinds and handle storage live in `src/net/handler/tcp/timer_kinds.rs`. The event loop owns the wheel and dispatches fired `TimerId` values to protocol handlers.

**Tech Stack:** Rust, `slab` crate (already a dependency), `coarsetime` (already a dependency), `smallvec` (already a dependency).

**Spec:** `docs/superpowers/specs/2026-03-17-timer-wheel-design.md`

**Test runner:** `cargo test` (no feature flags, runs as root via `.cargo/config.toml`)

---

## File Structure

| File | Responsibility |
|------|---------------|
| `src/net/timer_wheel.rs` | **New.** Protocol-agnostic wheel core: `TimerWheel`, `TimerEntry`, `TimerHandle`, `TimerId`, `Slot`, `Tier`. All wheel operations: `arm`, `cancel`, `advance` (with cascade). Owns a `Slab<TimerEntry>`. |
| `src/net/handler/tcp/timer_kinds.rs` | **New.** `TcpTimerKind` enum, `TcpTimerHandles` struct (6 × `Option<TimerHandle>`), `TimerId` packing/unpacking helpers for TCP. |
| `src/net/handler/tcp/timers.rs` | **Rewrite.** Delete `poll_timers()` and `evict_stale()`. Add `handle_timer()` → `fire_delayed_ack()`, `fire_retransmit()`, `fire_keep_alive()`, `fire_persist()`, `fire_linger()`, `fire_time_wait()`. Each is `#[inline]`, independently testable. |
| `src/net/handler/tcp/transmit.rs` | **Modify.** Remove persist deadline check and linger deadline check from `poll_send()`. Convert retransmit/delayed-ack/persist arming from field writes to wheel arm calls. |
| `src/net/handler/tcp/tcb.rs` | **Modify.** Remove 5 `Option<Instant>` deadline fields. |
| `src/net/handler/tcp/handler.rs` | **Modify.** Add `timer_handles: Slab<TcpTimerHandles>` field. Update `insert_connection`/`remove_connection_by_key` to manage handle lifecycle. |
| `src/net/handler/tcp/connection.rs` | **Modify.** Remove deadline field initialization from active-open TCB construction. Arm initial retransmit via wheel. |
| `src/net/handler/tcp/inbound/listen.rs` | **Modify.** Remove deadline field initialization from passive-open TCB construction. Arm initial retransmit via wheel. |
| `src/net/handler/tcp/inbound/established.rs` | **Modify.** Replace ~20 deadline field read/writes with wheel arm/cancel calls. |
| `src/net/handler/tcp/inbound/syn_received.rs` | **Modify.** Replace retransmit_deadline cancel with wheel cancel. |
| `src/net/handler/tcp/inbound/syn_sent.rs` | **Modify.** Replace retransmit_deadline writes with wheel arm/cancel. |
| `src/net/handler/tcp/inbound/teardown.rs` | **Modify.** Replace time_wait_deadline and retransmit_deadline writes with wheel arm/cancel. |
| `src/net/handler/tcp/inbound/segment.rs` | **Modify.** Replace `persist_deadline.is_some()` / `retransmit_deadline.is_some()` checks with handle-based checks. |
| `src/rt/local.rs` | **Modify.** Own the `TimerWheel`. Increase clock refresh frequency. Replace `tcp.poll_timers()` + `tcp.evict_stale()` with `wheel.advance()` + protocol dispatch loop. |
| `src/net/mod.rs` | **Modify.** Add `pub mod timer_wheel;` |
| `src/net/handler/tcp/mod.rs` | **Modify.** Add `pub(crate) mod timer_kinds;` |

---

### Task 1: Timer wheel core — types and arm

**Files:**
- Create: `src/net/timer_wheel.rs`
- Modify: `src/net/mod.rs`

- [ ] **Step 1: Write failing test — arm returns handle and stores entry**

In `src/net/timer_wheel.rs`, add a `#[cfg(test)] mod tests` block:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm_returns_handle() {
        let mut wheel = TimerWheel::new(0);
        let id = TimerId(42);
        let handle = wheel.arm(id, 100);
        assert!(wheel.is_armed(handle));
    }

    #[test]
    fn arm_places_in_correct_inner_slot() {
        let mut wheel = TimerWheel::new(0);
        let id = TimerId(1);
        // Deadline 50ms from now → inner tier, slot 50
        let _handle = wheel.arm(id, 50);
        assert_eq!(wheel.tiers[0].slots[50].head.is_some(), true);
    }

    #[test]
    fn arm_places_in_middle_tier_for_large_delta() {
        let mut wheel = TimerWheel::new(0);
        let id = TimerId(1);
        // Deadline 1000ms → beyond inner (256ms), goes to middle tier
        let _handle = wheel.arm(id, 1000);
        // Middle tier slot = (1000 >> 8) & 0xFF = 3
        assert_eq!(wheel.tiers[1].slots[3].head.is_some(), true);
    }

    #[test]
    fn arm_places_in_outer_tier_for_huge_delta() {
        let mut wheel = TimerWheel::new(0);
        let id = TimerId(1);
        // Deadline 100_000ms → beyond middle (65536ms), goes to outer tier
        let _handle = wheel.arm(id, 100_000);
        // Outer tier slot = (100_000 >> 16) & 0xFF = 1
        assert_eq!(wheel.tiers[2].slots[1].head.is_some(), true);
    }

    #[test]
    fn arm_multiple_same_slot_chains_correctly() {
        let mut wheel = TimerWheel::new(0);
        let h1 = wheel.arm(TimerId(1), 50);
        let h2 = wheel.arm(TimerId(2), 50);
        // Both in slot 50, h2 is head (prepend)
        assert!(wheel.is_armed(h1));
        assert!(wheel.is_armed(h2));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test timer_wheel`
Expected: FAIL — `TimerWheel` not defined.

- [ ] **Step 3: Implement types and `arm()`**

In `src/net/timer_wheel.rs`, implement:

```rust
use slab::Slab;
use smallvec::SmallVec;

/// Opaque identifier stored in the wheel and returned on expiry.
/// The wheel never inspects this — protocol handlers pack/unpack their own meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerId(pub u64);

/// Handle returned by `arm()`. Used to cancel or check if a timer is still armed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerHandle(usize);

struct TimerEntry {
    id: TimerId,
    next: Option<usize>,
    prev: Option<usize>,
    slot: u16, // tier (2 bits high) | slot_index (8 bits low)
}

struct Slot {
    head: Option<usize>,
}

struct Tier {
    slots: [Slot; 256],
    shift: u8,
}

pub struct TimerWheel {
    tiers: [Tier; 3],
    entries: Slab<TimerEntry>,
    current_tick_ms: u64,
}

impl Slot {
    const fn new() -> Self {
        Self { head: None }
    }
}

impl Tier {
    fn new(shift: u8) -> Self {
        Self {
            slots: [const { Slot::new() }; 256],
            shift,
        }
    }
}

impl TimerWheel {
    pub fn new(start_ms: u64) -> Self {
        Self {
            tiers: [Tier::new(0), Tier::new(8), Tier::new(16)],
            entries: Slab::new(),
            current_tick_ms: start_ms,
        }
    }

    pub fn arm(&mut self, id: TimerId, deadline_ms: u64) -> TimerHandle {
        let delta = deadline_ms.saturating_sub(self.current_tick_ms);
        let (tier_idx, slot_idx) = if delta < 256 {
            (0usize, (deadline_ms & 0xFF) as usize)
        } else if delta < 65536 {
            (1, ((deadline_ms >> 8) & 0xFF) as usize)
        } else {
            (2, ((deadline_ms >> 16) & 0xFF) as usize)
        };

        let packed_slot = (tier_idx as u16) << 8 | slot_idx as u16;
        let entry_key = self.entries.insert(TimerEntry {
            id,
            next: None,
            prev: None,
            slot: packed_slot,
        });

        // Prepend to slot's linked list.
        let slot = &mut self.tiers[tier_idx].slots[slot_idx];
        if let Some(old_head) = slot.head {
            self.entries[old_head].prev = Some(entry_key);
        }
        self.entries[entry_key].next = slot.head;
        slot.head = Some(entry_key);

        TimerHandle(entry_key)
    }

    pub fn is_armed(&self, handle: TimerHandle) -> bool {
        self.entries.contains(handle.0)
    }
}
```

- [ ] **Step 4: Add `pub mod timer_wheel;` to `src/net/mod.rs`**

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test timer_wheel`
Expected: All 5 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/net/timer_wheel.rs src/net/mod.rs
git commit -m "feat(timer_wheel): Add core types and arm operation"
```

---

### Task 2: Timer wheel core — cancel

**Files:**
- Modify: `src/net/timer_wheel.rs`

- [ ] **Step 1: Write failing tests for cancel**

```rust
#[test]
fn cancel_removes_entry() {
    let mut wheel = TimerWheel::new(0);
    let handle = wheel.arm(TimerId(1), 50);
    assert!(wheel.is_armed(handle));
    wheel.cancel(handle);
    assert!(!wheel.is_armed(handle));
}

#[test]
fn cancel_unlinks_head() {
    let mut wheel = TimerWheel::new(0);
    let h1 = wheel.arm(TimerId(1), 50);
    let h2 = wheel.arm(TimerId(2), 50);
    // h2 is head. Cancel h2, h1 becomes head.
    wheel.cancel(h2);
    assert!(!wheel.is_armed(h2));
    assert!(wheel.is_armed(h1));
    assert_eq!(wheel.tiers[0].slots[50].head, Some(h1.0));
}

#[test]
fn cancel_unlinks_middle() {
    let mut wheel = TimerWheel::new(0);
    let h1 = wheel.arm(TimerId(1), 50);
    let h2 = wheel.arm(TimerId(2), 50);
    let h3 = wheel.arm(TimerId(3), 50);
    // Chain: h3 → h2 → h1. Cancel h2.
    wheel.cancel(h2);
    assert!(wheel.is_armed(h1));
    assert!(!wheel.is_armed(h2));
    assert!(wheel.is_armed(h3));
}

#[test]
fn cancel_unlinks_tail() {
    let mut wheel = TimerWheel::new(0);
    let h1 = wheel.arm(TimerId(1), 50);
    let _h2 = wheel.arm(TimerId(2), 50);
    // Chain: h2 → h1. Cancel h1 (tail).
    wheel.cancel(h1);
    assert!(!wheel.is_armed(h1));
}

#[test]
fn cancel_invalid_handle_is_noop() {
    let mut wheel = TimerWheel::new(0);
    let handle = wheel.arm(TimerId(1), 50);
    wheel.cancel(handle);
    // Double cancel — should not panic.
    wheel.cancel(handle);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test timer_wheel`
Expected: FAIL — `cancel` not defined.

- [ ] **Step 3: Implement `cancel()`**

```rust
impl TimerWheel {
    pub fn cancel(&mut self, handle: TimerHandle) {
        let Some(entry) = self.entries.try_remove(handle.0) else {
            return;
        };
        let tier_idx = (entry.slot >> 8) as usize;
        let slot_idx = (entry.slot & 0xFF) as usize;

        // Unlink from doubly-linked list.
        if let Some(prev) = entry.prev {
            self.entries[prev].next = entry.next;
        } else {
            // Was head of slot.
            self.tiers[tier_idx].slots[slot_idx].head = entry.next;
        }
        if let Some(next) = entry.next {
            self.entries[next].prev = entry.prev;
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test timer_wheel`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/net/timer_wheel.rs
git commit -m "feat(timer_wheel): Add cancel operation"
```

---

### Task 3: Timer wheel core — advance (inner tier, no cascade)

**Files:**
- Modify: `src/net/timer_wheel.rs`

- [ ] **Step 1: Write failing tests for advance**

```rust
#[test]
fn advance_fires_expired_timer() {
    let mut wheel = TimerWheel::new(0);
    wheel.arm(TimerId(42), 10);
    let fired = wheel.advance(10);
    assert_eq!(fired.len(), 1);
    assert_eq!(fired[0], TimerId(42));
}

#[test]
fn advance_fires_nothing_when_no_timers_due() {
    let mut wheel = TimerWheel::new(0);
    wheel.arm(TimerId(1), 100);
    let fired = wheel.advance(50);
    assert!(fired.is_empty());
}

#[test]
fn advance_fires_multiple_in_same_slot() {
    let mut wheel = TimerWheel::new(0);
    wheel.arm(TimerId(1), 10);
    wheel.arm(TimerId(2), 10);
    let fired = wheel.advance(10);
    assert_eq!(fired.len(), 2);
    assert!(fired.contains(&TimerId(1)));
    assert!(fired.contains(&TimerId(2)));
}

#[test]
fn advance_fires_across_multiple_slots() {
    let mut wheel = TimerWheel::new(0);
    wheel.arm(TimerId(1), 5);
    wheel.arm(TimerId(2), 10);
    let fired = wheel.advance(10);
    assert_eq!(fired.len(), 2);
}

#[test]
fn advance_removes_fired_entries() {
    let mut wheel = TimerWheel::new(0);
    let handle = wheel.arm(TimerId(1), 10);
    wheel.advance(10);
    assert!(!wheel.is_armed(handle));
}

#[test]
fn advance_noop_when_time_unchanged() {
    let mut wheel = TimerWheel::new(100);
    wheel.arm(TimerId(1), 100);
    let fired = wheel.advance(100);
    // current_tick_ms == now_ms, no slots to drain
    assert!(fired.is_empty());
}

#[test]
fn advance_catches_up_burst() {
    let mut wheel = TimerWheel::new(0);
    wheel.arm(TimerId(1), 5);
    wheel.arm(TimerId(2), 50);
    wheel.arm(TimerId(3), 200);
    // Jump from 0 to 201 in one call.
    let fired = wheel.advance(201);
    assert_eq!(fired.len(), 3);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test timer_wheel`
Expected: FAIL — `advance` not defined.

- [ ] **Step 3: Implement `advance()` (inner tier only, cascade placeholder)**

```rust
impl TimerWheel {
    pub fn advance(&mut self, now_ms: u64) -> SmallVec<[TimerId; 16]> {
        let mut fired = SmallVec::new();

        while self.current_tick_ms < now_ms {
            let slot_idx = (self.current_tick_ms & 0xFF) as usize;

            // Drain inner wheel slot.
            let mut cursor = self.tiers[0].slots[slot_idx].head;
            while let Some(key) = cursor {
                let entry = self.entries.remove(key);
                cursor = entry.next;
                fired.push(entry.id);
            }
            self.tiers[0].slots[slot_idx].head = None;

            // Cascade on inner wheel wrap.
            if slot_idx == 0 && self.current_tick_ms > 0 {
                self.cascade(1);
                let mid_slot = ((self.current_tick_ms >> 8) & 0xFF) as usize;
                if mid_slot == 0 {
                    self.cascade(2);
                }
            }

            self.current_tick_ms += 1;
        }

        fired
    }

    fn cascade(&mut self, tier_idx: usize) {
        let slot_idx = ((self.current_tick_ms >> self.tiers[tier_idx].shift) & 0xFF) as usize;
        let mut cursor = self.tiers[tier_idx].slots[slot_idx].head;
        self.tiers[tier_idx].slots[slot_idx].head = None;

        while let Some(key) = cursor {
            let entry = self.entries.remove(key);
            cursor = entry.next;
            // Re-arm into a lower tier with the original deadline.
            // We need the deadline to recompute the slot — but we don't store it.
            // Solution: re-arm using the TimerId. But we don't know the deadline.
            //
            // This is the cascade problem: we need to store the deadline_ms in the entry.
            // TODO: Add deadline_ms to TimerEntry in the next step.
            // For now, this is a stub — tests for cascade come in Task 4.
        }
    }
}
```

Wait — cascade needs the deadline. Let me fix the entry struct now.

- [ ] **Step 4: Add `deadline_ms` to `TimerEntry` and update `arm()`/`advance()`**

Update `TimerEntry`:
```rust
struct TimerEntry {
    id: TimerId,
    deadline_ms: u64,
    next: Option<usize>,
    prev: Option<usize>,
    slot: u16,
}
```

Update `arm()` to store `deadline_ms`. Update `cascade()` to re-insert entries:
```rust
fn cascade(&mut self, tier_idx: usize) {
    let slot_idx = ((self.current_tick_ms >> self.tiers[tier_idx].shift) & 0xFF) as usize;
    let mut cursor = self.tiers[tier_idx].slots[slot_idx].head;
    self.tiers[tier_idx].slots[slot_idx].head = None;

    while let Some(key) = cursor {
        let entry = self.entries.remove(key);
        cursor = entry.next;
        // Re-arm into the correct lower-tier slot.
        self.arm(entry.id, entry.deadline_ms);
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test timer_wheel`
Expected: All tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/net/timer_wheel.rs
git commit -m "feat(timer_wheel): Add advance with inner tier draining and cascade stub"
```

---

### Task 4: Timer wheel core — cascade

**Files:**
- Modify: `src/net/timer_wheel.rs`

- [ ] **Step 1: Write failing tests for cascade behavior**

```rust
#[test]
fn cascade_middle_to_inner() {
    let mut wheel = TimerWheel::new(0);
    // Deadline 300ms — goes to middle tier (delta >= 256).
    wheel.arm(TimerId(1), 300);
    assert!(wheel.tiers[1].slots[(300 >> 8) & 0xFF].head.is_some());

    // Advance to 256 — triggers cascade at inner wrap.
    let fired = wheel.advance(256);
    // Timer not due yet (deadline=300), but should have cascaded to inner tier.
    assert!(fired.is_empty());
    // After cascade, entry should be in inner tier slot 300 & 0xFF = 44.
    assert!(wheel.tiers[0].slots[44].head.is_some());
}

#[test]
fn cascade_fires_on_correct_tick() {
    let mut wheel = TimerWheel::new(0);
    wheel.arm(TimerId(1), 300);
    // Advance past deadline.
    let fired = wheel.advance(301);
    assert_eq!(fired.len(), 1);
    assert_eq!(fired[0], TimerId(1));
}

#[test]
fn cascade_outer_to_middle() {
    let mut wheel = TimerWheel::new(0);
    // Deadline 70_000ms — goes to outer tier (delta >= 65536).
    wheel.arm(TimerId(1), 70_000);
    assert!(wheel.tiers[2].slots[(70_000 >> 16) & 0xFF].head.is_some());

    // Advance to 65536 — triggers outer cascade.
    let fired = wheel.advance(65536);
    assert!(fired.is_empty());
    // Should have cascaded to middle tier.
    let mid_slot = (70_000 >> 8) & 0xFF;
    assert!(wheel.tiers[1].slots[mid_slot].head.is_some());
}

#[test]
fn cascade_multiple_entries() {
    let mut wheel = TimerWheel::new(0);
    wheel.arm(TimerId(1), 300);
    wheel.arm(TimerId(2), 310);
    wheel.arm(TimerId(3), 500);
    // All in middle tier. Advance to 256 — cascade middle slot 1.
    let fired = wheel.advance(311);
    assert_eq!(fired.len(), 2); // TimerId(1) at 300 and TimerId(2) at 310
}
```

- [ ] **Step 2: Run tests to verify current cascade behavior**

Run: `cargo test timer_wheel`
Expected: Some tests may already pass if cascade was implemented in Task 3 step 4. Verify which pass, which fail.

- [ ] **Step 3: Fix any cascade issues found**

The `cascade()` method from Task 3 calls `self.arm()` which does full tier selection based on `deadline_ms - current_tick_ms`. At cascade time, `current_tick_ms` has advanced so the delta is smaller — the entry naturally falls into a lower tier. This should work correctly. Fix any edge cases discovered by the tests.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test timer_wheel`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/net/timer_wheel.rs
git commit -m "feat(timer_wheel): Verify cascade from outer/middle tiers to inner"
```

---

### Task 5: Timer wheel core — re-arm and edge cases

**Files:**
- Modify: `src/net/timer_wheel.rs`

- [ ] **Step 1: Write tests for re-arm and edge cases**

```rust
#[test]
fn rearm_cancel_then_arm() {
    let mut wheel = TimerWheel::new(0);
    let h1 = wheel.arm(TimerId(1), 50);
    wheel.cancel(h1);
    let h2 = wheel.arm(TimerId(1), 100);
    assert!(!wheel.is_armed(h1));
    assert!(wheel.is_armed(h2));
    let fired = wheel.advance(101);
    assert_eq!(fired.len(), 1);
    assert_eq!(fired[0], TimerId(1));
}

#[test]
fn arm_at_current_tick_fires_immediately() {
    let mut wheel = TimerWheel::new(100);
    wheel.arm(TimerId(1), 100);
    // Deadline == current_tick — should be in slot 100 & 0xFF = 100.
    // Advance by 1 tick to drain slot 100.
    let fired = wheel.advance(101);
    assert_eq!(fired.len(), 1);
}

#[test]
fn arm_in_past_fires_on_next_advance() {
    let mut wheel = TimerWheel::new(100);
    // Deadline in the past.
    wheel.arm(TimerId(1), 50);
    // delta saturates to 0, goes to inner slot (50 & 0xFF) = 50.
    // Since current_tick is 100, slot 50 was already passed.
    // It will fire when the wheel wraps back to slot 50 (at tick 256+50=306).
    // This is acceptable — past deadlines fire on the next wrap.
    let fired = wheel.advance(307);
    assert_eq!(fired.len(), 1);
}

#[test]
fn entry_count_returns_armed_count() {
    let mut wheel = TimerWheel::new(0);
    assert_eq!(wheel.entry_count(), 0);
    let h1 = wheel.arm(TimerId(1), 50);
    let _h2 = wheel.arm(TimerId(2), 100);
    assert_eq!(wheel.entry_count(), 2);
    wheel.cancel(h1);
    assert_eq!(wheel.entry_count(), 1);
}
```

- [ ] **Step 2: Run tests to verify failures**

Run: `cargo test timer_wheel`
Expected: `entry_count` test fails (not defined). Other tests may pass or reveal edge cases.

- [ ] **Step 3: Add `entry_count()` and fix any edge cases**

```rust
impl TimerWheel {
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test timer_wheel`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/net/timer_wheel.rs
git commit -m "feat(timer_wheel): Add re-arm, entry_count, and edge case handling"
```

---

### Task 6: TCP timer kinds and handle storage

**Files:**
- Create: `src/net/handler/tcp/timer_kinds.rs`
- Modify: `src/net/handler/tcp/mod.rs`

- [ ] **Step 1: Write failing tests for TimerId packing/unpacking**

In `src/net/handler/tcp/timer_kinds.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_unpack_roundtrip() {
        let key = 12345usize;
        let kind = TcpTimerKind::Retransmit;
        let id = TimerId::tcp(key, kind);
        let (k, t) = id.unpack_tcp();
        assert_eq!(k, key);
        assert_eq!(t, kind);
    }

    #[test]
    fn pack_unpack_all_kinds() {
        for kind in [
            TcpTimerKind::Retransmit,
            TcpTimerKind::DelayedAck,
            TcpTimerKind::Persist,
            TcpTimerKind::KeepAlive,
            TcpTimerKind::TimeWait,
            TcpTimerKind::Linger,
        ] {
            let id = TimerId::tcp(999, kind);
            let (k, t) = id.unpack_tcp();
            assert_eq!(k, 999);
            assert_eq!(t, kind);
        }
    }

    #[test]
    fn tcp_timer_handles_default_all_none() {
        let handles = TcpTimerHandles::new();
        for i in 0..6 {
            assert!(handles.handles[i].is_none());
        }
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test timer_kinds`
Expected: FAIL — module doesn't exist.

- [ ] **Step 3: Implement `timer_kinds.rs`**

```rust
use crate::net::timer_wheel::{TimerHandle, TimerId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TcpTimerKind {
    Retransmit = 0,
    DelayedAck = 1,
    Persist    = 2,
    KeepAlive  = 3,
    TimeWait   = 4,
    Linger     = 5,
}

impl From<u8> for TcpTimerKind {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Retransmit,
            1 => Self::DelayedAck,
            2 => Self::Persist,
            3 => Self::KeepAlive,
            4 => Self::TimeWait,
            5 => Self::Linger,
            _ => panic!("invalid TcpTimerKind: {v}"),
        }
    }
}

impl TimerId {
    pub fn tcp(key: usize, kind: TcpTimerKind) -> Self {
        TimerId((key as u64) << 8 | kind as u64)
    }

    pub fn unpack_tcp(self) -> (usize, TcpTimerKind) {
        let kind = TcpTimerKind::from(self.0 as u8);
        let key = (self.0 >> 8) as usize;
        (key, kind)
    }
}

pub struct TcpTimerHandles {
    pub handles: [Option<TimerHandle>; 6],
}

impl TcpTimerHandles {
    pub fn new() -> Self {
        Self {
            handles: [None; 6],
        }
    }

    #[inline]
    pub fn get(&self, kind: TcpTimerKind) -> Option<TimerHandle> {
        self.handles[kind as usize]
    }

    #[inline]
    pub fn set(&mut self, kind: TcpTimerKind, handle: TimerHandle) {
        self.handles[kind as usize] = Some(handle);
    }

    #[inline]
    pub fn clear(&mut self, kind: TcpTimerKind) {
        self.handles[kind as usize] = None;
    }

    #[inline]
    pub fn is_armed(&self, kind: TcpTimerKind) -> bool {
        self.handles[kind as usize].is_some()
    }
}
```

- [ ] **Step 4: Add `pub(crate) mod timer_kinds;` to `src/net/handler/tcp/mod.rs`**

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test timer_kinds`
Expected: All tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/net/handler/tcp/timer_kinds.rs src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): Add TcpTimerKind, TimerId packing, and TcpTimerHandles"
```

---

### Task 7: Add timer handle storage to TcpHandler

**Files:**
- Modify: `src/net/handler/tcp/handler.rs`

- [ ] **Step 1: Add `timer_handles: Slab<TcpTimerHandles>` to `TcpHandler`**

Add field to `TcpHandler` struct and initialize in `new()`. Update `insert_connection` to also insert a `TcpTimerHandles` entry with the same key. Update `remove_connection_by_key` to also remove the handles entry.

The slab key synchronization requires inserting into both slabs and asserting the keys match. Since `slab::Slab` assigns keys sequentially and both start empty, the keys will stay in sync as long as inserts and removes are paired.

```rust
// In TcpHandler struct:
pub(crate) timer_handles: Slab<TcpTimerHandles>,

// In new():
timer_handles: Slab::new(),

// In insert_connection():
let handle_key = self.timer_handles.insert(TcpTimerHandles::new());
debug_assert_eq!(key, handle_key, "timer_handles slab key mismatch");

// In remove_connection_by_key():
if self.timer_handles.contains(key) {
    // TODO: cancel all armed timers via wheel before removing.
    self.timer_handles.remove(key);
}
```

- [ ] **Step 2: Run full test suite to verify nothing breaks**

Run: `cargo test`
Expected: All existing tests PASS. The timer_handles slab is added but not yet used for scheduling.

- [ ] **Step 3: Commit**

```bash
git add src/net/handler/tcp/handler.rs
git commit -m "feat(tcp): Add TcpTimerHandles parallel slab to TcpHandler"
```

---

### Task 8: Extract `fire_*` methods from `poll_timers()` and `poll_send()`

This is the largest task. Extract the per-connection timer logic from the current O(n) scan loops into individual `fire_*` methods. Do NOT wire them to the wheel yet — that comes in Task 10. The existing `poll_timers()` and `evict_stale()` continue to work as before during this task.

**Files:**
- Modify: `src/net/handler/tcp/timers.rs`

- [ ] **Step 1: Write tests for `fire_delayed_ack`**

Tests should set up a TCB with `ack_pending = true` in Established state, call `fire_delayed_ack`, and assert that an ACK segment was produced in `tx_return` and `ack_pending` was cleared.

Use the existing test harness patterns from `src/net/handler/tcp/tests/timers.rs` — look at how it constructs a `TcpHandler` with test connections and checks frame output.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test fire_delayed_ack`
Expected: FAIL — method not defined.

- [ ] **Step 3: Implement `fire_delayed_ack`**

Extract lines 35-86 of `timers.rs` (the per-connection body of the delayed ACK pass) into:
```rust
#[inline]
pub fn fire_delayed_ack<'umem>(
    &mut self,
    key: usize,
    now: Instant,
    src_mac: MacAddress,
    neighbor_handler: &NeighborHandler,
    free_frames: &mut impl FrameBuffer<'umem>,
    rx_return: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) -> Option<SendReady> { ... }
```

- [ ] **Step 4: Run test to verify it passes**

- [ ] **Step 5: Repeat for `fire_retransmit`**

Extract lines 258-429 of `timers.rs`. This handles SYN/SYN-ACK/Established/FIN retransmit with R2 threshold check and exponential backoff.

- [ ] **Step 6: Repeat for `fire_keep_alive`**

Extract lines 91-155 of `timers.rs`. Sends keep-alive probe or aborts connection.

- [ ] **Step 7: Repeat for `fire_persist`**

Extract lines 231-276 of `transmit.rs`. Sends zero-window probe with backoff.

- [ ] **Step 8: Repeat for `fire_linger`**

Extract lines 278-290 of `transmit.rs`. Sends RST and marks for removal.

- [ ] **Step 9: Repeat for `fire_time_wait`**

Extract lines 448-466 of `timers.rs`. Removes the connection.

- [ ] **Step 10: Add `handle_timer` dispatch method**

```rust
pub fn handle_timer<'umem>(
    &mut self,
    key: usize,
    kind: TcpTimerKind,
    now: Instant,
    src_mac: MacAddress,
    neighbor_handler: &NeighborHandler,
    free_frames: &mut impl FrameBuffer<'umem>,
    rx_return: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) {
    match kind {
        TcpTimerKind::DelayedAck => { self.fire_delayed_ack(key, now, src_mac, neighbor_handler, free_frames, rx_return, tx_return); }
        TcpTimerKind::Retransmit => { self.fire_retransmit(key, now, src_mac, neighbor_handler, free_frames, rx_return, tx_return); }
        TcpTimerKind::KeepAlive => { self.fire_keep_alive(key, now, src_mac, neighbor_handler, free_frames, rx_return, tx_return); }
        TcpTimerKind::Persist => { self.fire_persist(key, now, src_mac, neighbor_handler, free_frames, rx_return, tx_return); }
        TcpTimerKind::Linger => { self.fire_linger(key, now, src_mac, neighbor_handler, free_frames, rx_return, tx_return); }
        TcpTimerKind::TimeWait => { self.fire_time_wait(key); }
    }
}
```

- [ ] **Step 11: Run full test suite**

Run: `cargo test`
Expected: All tests PASS. The `fire_*` methods exist alongside the old `poll_timers()` — nothing is removed yet.

- [ ] **Step 12: Commit**

```bash
git add src/net/handler/tcp/timers.rs
git commit -m "feat(tcp): Extract fire_* timer methods for wheel dispatch"
```

---

### Task 9: Remove deadline fields from TCB

**Files:**
- Modify: `src/net/handler/tcp/tcb.rs`
- Modify: `src/net/handler/tcp/connection.rs`
- Modify: `src/net/handler/tcp/inbound/listen.rs`
- Modify: `src/net/handler/tcp/inbound/established.rs`
- Modify: `src/net/handler/tcp/inbound/syn_received.rs`
- Modify: `src/net/handler/tcp/inbound/syn_sent.rs`
- Modify: `src/net/handler/tcp/inbound/teardown.rs`
- Modify: `src/net/handler/tcp/inbound/segment.rs`
- Modify: `src/net/handler/tcp/transmit.rs`
- Modify: `src/net/handler/tcp/timers.rs`
- Modify: `src/net/handler/tcp/tests/timers.rs` (and other test files that reference deadline fields)

This is a large mechanical refactor. Every read/write of the 5 `Option<Instant>` deadline fields must be replaced with wheel operations via `TcpTimerHandles`.

- [ ] **Step 1: Remove fields from TCB struct**

In `src/net/handler/tcp/tcb.rs`, remove:
- `delayed_ack_deadline: Option<Instant>`
- `retransmit_deadline: Option<Instant>`
- `time_wait_deadline: Option<Instant>`
- `persist_deadline: Option<Instant>`
- `linger_deadline: Option<Instant>`

- [ ] **Step 2: Fix all compilation errors**

The compiler will report every site that reads or writes these fields. For each site:

**Writes (arming):** `tcb.retransmit_deadline = Some(now + Duration::from_millis(rto))` becomes a wheel arm call. The `fire_*` methods and `handle_timer` need access to the wheel, so the wheel must be passed through or accessible. The cleanest path: `TcpHandler` gets a `&mut TimerWheel` parameter on methods that arm timers, or the event loop passes it when calling into TCP.

**Writes (cancelling):** `tcb.retransmit_deadline = None` becomes a wheel cancel via the handle.

**Reads (checking if armed):** `tcb.retransmit_deadline.is_some()` becomes `timer_handles[key].is_armed(TcpTimerKind::Retransmit)`.

**Reads (checking deadline value):** `tcb.persist_deadline` in `transmit.rs:231` checks `now >= deadline`. This no longer exists — the wheel fires when the deadline is reached, so these checks move into the `fire_*` methods (which are only called when the timer is actually due).

Key files and approximate change counts:
- `connection.rs`: ~5 field inits → remove, arm retransmit via wheel
- `inbound/listen.rs`: ~5 field inits → remove, arm retransmit via wheel
- `inbound/established.rs`: ~20 reads/writes → wheel arm/cancel
- `inbound/syn_received.rs`: ~1 cancel
- `inbound/syn_sent.rs`: ~2 writes
- `inbound/teardown.rs`: ~7 writes (time_wait + retransmit)
- `inbound/segment.rs`: ~2 `.is_some()` checks
- `transmit.rs`: ~10 reads/writes (retransmit, delayed_ack, persist, linger)
- `timers.rs`: remaining deadline references in old `poll_timers()`

- [ ] **Step 3: Decide how the wheel is threaded through TCP methods**

The wheel is owned by the event loop (`LocalRuntime`). TCP inbound handlers need to arm/cancel timers. Options:
- Pass `&mut TimerWheel` to every TCP method that might touch timers (verbose but explicit)
- Store a reference/pointer on `TcpHandler` (requires the wheel to be in an `UnsafeCell` like the other shared state in `local.rs`)

Look at how `local.rs` already handles `tcp_handler`, `udp_handler`, etc. via `UnsafeCell` — the wheel should follow the same pattern: `UnsafeCell<TimerWheel>` owned by `LocalRuntime`, passed as `&mut` into TCP methods.

- [ ] **Step 4: Run `cargo check` to verify compilation**

Run: `cargo check`
Expected: Compiles with no errors.

- [ ] **Step 5: Run full test suite**

Run: `cargo test`
Expected: Some tests in `tests/timers.rs` will fail because they manipulate deadline fields directly. These need to be updated to use wheel arm/cancel instead.

- [ ] **Step 6: Update tests to use wheel-based timer manipulation**

Tests that did `tcb.retransmit_deadline = Some(now - Duration::from_millis(1))` to simulate an expired timer now need to:
1. Arm a timer via the wheel at a deadline in the past
2. Call `wheel.advance()` to fire it
3. Assert the `fire_*` method produced the expected output

- [ ] **Step 7: Run full test suite**

Run: `cargo test`
Expected: All tests PASS.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "refactor(tcp): Replace deadline fields with timer wheel arm/cancel"
```

---

### Task 10: Wire event loop to timer wheel

**Files:**
- Modify: `src/rt/local.rs`

- [ ] **Step 1: Add `TimerWheel` to `LocalRuntime`**

Add `wheel: UnsafeCell<TimerWheel>` to the `LocalRuntime` struct. Initialize it in the builder with `TimerWheel::new(now_ms)` where `now_ms` is from the initial `coarsetime::Instant::now()`.

- [ ] **Step 2: Increase clock refresh frequency**

Move `now = coarsetime::Instant::now()` out of the `evict_counter & 65535` block. Place it before the wheel advance call. The exact check frequency can be tuned later — start with every iteration and measure.

- [ ] **Step 3: Add wheel advance + dispatch loop**

Replace the `tcp.poll_timers()` and `tcp.evict_stale()` calls with:

```rust
let wheel = unsafe { &mut *self.wheel.get() };
let now_ms = now.as_ticks() / /* ticks per ms — check coarsetime's tick rate */;
let fired = wheel.advance(now_ms);
let tcp_handler = unsafe { &mut *self.tcp_handler.get() };
for timer_id in &fired {
    let (key, kind) = timer_id.unpack_tcp();
    tcp_handler.handle_timer(
        key, kind, now,
        self.neighbor_handler.local_mac(),
        &self.neighbor_handler,
        &mut self.free_frames,
        &mut self.rx_return,
        &mut self.tx_return,
    );
}
```

**Important:** Check `coarsetime`'s tick-to-millisecond conversion. Look at `Duration::as_millis()` and `Instant::as_ticks()` to determine the conversion factor. The wheel works in milliseconds; coarsetime ticks may be a different unit.

- [ ] **Step 4: Remove old `tcp.poll_timers()` and `tcp.evict_stale()` calls**

Delete these lines from the `evict_counter & 65535` block:
```rust
tcp_handler.evict_stale(now, &mut self.rx_return);
tcp_handler.poll_timers(now, ...);
```

- [ ] **Step 5: Delete `poll_timers()` and `evict_stale()` from `timers.rs`**

These methods are now dead code. Remove them.

- [ ] **Step 6: Remove persist/linger deadline checks from `poll_send()`**

In `transmit.rs`, the persist deadline check (lines 225-276) and linger deadline check (lines 278-290) are now handled by the wheel. Remove these blocks from `poll_send()`. The `fire_persist` and `fire_linger` methods handle this logic when the wheel fires.

- [ ] **Step 7: Run full test suite**

Run: `cargo test`
Expected: All tests PASS.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "feat(rt): Wire timer wheel into event loop, remove O(n) timer scanning"
```

---

### Task 11: Keep-alive semantic change

**Files:**
- Modify: `src/net/handler/tcp/timers.rs` (fire_keep_alive)
- Modify: `src/net/handler/tcp/inbound/established.rs` (arm on packet activity)
- Modify: `src/net/handler/tcp/connection.rs` (arm on connect)
- Modify: `src/net/handler/tcp/inbound/listen.rs` (arm on passive open)

- [ ] **Step 1: Write test for keep-alive timer arm on connection**

Test that when a connection is established with keep-alive enabled, a KeepAlive timer is armed in the wheel.

- [ ] **Step 2: Implement keep-alive arm on connection establishment**

In the TCB construction paths (active open in `connection.rs`, passive open transition to Established in `inbound/syn_received.rs`), if `keep_alive_enabled`, arm a KeepAlive timer at `now + keep_alive_idle_ms`.

- [ ] **Step 3: Write test for keep-alive re-arm on activity**

Test that receiving a data segment cancels and re-arms the keep-alive timer.

- [ ] **Step 4: Implement keep-alive re-arm on packet activity**

In `inbound/established.rs`, where `tcb.last_activity = now` is set (on receiving data or ACK), also cancel and re-arm the KeepAlive timer. Reset `keep_alive_probes_sent`.

- [ ] **Step 5: Write test for keep-alive probe firing**

Test that when the keep-alive timer fires, a probe segment is sent and the timer is re-armed at `now + keep_alive_interval_ms`.

- [ ] **Step 6: Implement in `fire_keep_alive`**

Update `fire_keep_alive` to:
- Send probe (existing logic)
- Re-arm KeepAlive timer at `now + keep_alive_interval_ms`
- Increment `keep_alive_probes_sent`
- If `keep_alive_probes_sent >= keep_alive_count`, abort connection

- [ ] **Step 7: Run full test suite**

Run: `cargo test`
Expected: All tests PASS including existing keep-alive tests (updated as needed).

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "feat(tcp): Convert keep-alive to wheel-driven deadline timer"
```

---

### Task 12: Cleanup and final verification

**Files:**
- All modified files

- [ ] **Step 1: Run full test suite**

Run: `cargo test`
Expected: All tests PASS.

- [ ] **Step 2: Check for dead code**

Run: `cargo check 2>&1 | grep "warning.*dead_code\|warning.*unused"`
Remove any dead code warnings related to the old timer infrastructure.

- [ ] **Step 3: Fix any warnings**

- [ ] **Step 4: Run full test suite again**

Run: `cargo test`
Expected: All tests PASS, no warnings.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "chore(tcp): Remove dead timer code and fix warnings"
```
