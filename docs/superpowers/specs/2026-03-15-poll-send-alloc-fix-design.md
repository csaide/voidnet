# poll_send Allocation Storm Fix — VoidNet

**Date:** 2026-03-15
**Approach:** Swap-drain SendTracker + targeted connection removal
**Target:** Eliminate ~11% CPU overhead from per-tick allocations in `poll_send`

## Goals

Remove per-tick heap allocations and O(n) scans from `TcpHandler::poll_send`,
the hottest function in the net stack run loop. The perf profile shows:

- 1.79% `Vec::from_iter` + 1.47% `RawVec::grow_one` — `drain().collect::<Vec<_>>()`
- 3.85% `HashMap::insert` — re-inserting IDs into SendTracker after processing
- 2.19% `HashMap::retain` — scanning all connections for Closed state every tick
- 5.54% `poll_send` self-time — includes iteration overhead

Combined: ~11-13% of CPU in the http-server workload.

## Non-Goals

- HTTP response formatting (deferred to Approach B)
- HTTP request parsing optimizations (deferred to Approach C)
- `poll_timers` / `evict_stale` retain() calls (rate-limited to ~1/65536 ticks)
- Run loop (`LocalRuntime::run`) overhead (separate investigation)

---

## 1. SendTracker — Dual-Set Swap Pattern

### Problem

`SendTracker` uses a single `FxHashSet<ConnectionId>`. In `poll_send`:

```rust
let ids: Vec<ConnectionId> = self.send_tracker.drain().collect(); // line 31
```

This allocates a `Vec` every tick to avoid iterator invalidation (can't mutate
the set while iterating it). After processing, connections with remaining work
are re-inserted into the same set (lines 377-386), causing `HashMap::insert`
churn on a freshly-emptied set that may need to rehash.

### Design

Replace the single set with two sets that swap roles:

```rust
pub struct SendTracker {
    active: FxHashSet<ConnectionId>,
    pending: FxHashSet<ConnectionId>,
}
```

**Lifecycle per tick:**

1. `swap()` — `std::mem::swap(&mut self.active, &mut self.pending)`. O(1) pointer
   swap. `active` now contains IDs accumulated since last tick. `pending` is the
   old `active` which was drained last tick (empty).

2. `poll_send` collects `active.drain()` into a `SmallVec<[ConnectionId; 32]>`
   (stack-allocated for ≤32 connections). A zero-collect drain is not possible
   because the loop body requires `&mut self` (for `self.connections.get_mut()`
   and `self.send_tracker.mark()`), conflicting with the drain iterator's borrow.
   The SmallVec replaces the heap `Vec` — stack-allocated for the common case.

3. During iteration, any `mark()` calls (re-marks for connections that still have
   work, neighbor resolution pending, timer-driven sends) insert into `pending`.
   This is safe because `pending` is not being iterated.

4. Next tick, `swap()` makes `pending` the new `active`, and the cycle repeats.

**API changes:**

```rust
impl SendTracker {
    /// Swap active/pending sets. Call once at the start of poll_send.
    #[inline(always)]
    pub fn swap(&mut self) {
        std::mem::swap(&mut self.active, &mut self.pending);
        // active now has the IDs to process; pending is empty
    }

    /// Drain the active set for iteration.
    #[inline(always)]
    pub fn drain_active(&mut self) -> impl Iterator<Item = ConnectionId> + '_ {
        self.active.drain()
    }

    /// Register a connection as needing send processing (goes to pending).
    #[inline(always)]
    pub fn mark(&mut self, ready: SendReady) {
        self.pending.insert(ready.0);
    }

    /// Remove from both sets (connection closed/removed).
    #[inline(always)]
    pub fn unmark(&mut self, id: &ConnectionId) {
        self.active.remove(id);
        self.pending.remove(id);
    }
}
```

**One-tick delay:** A connection marked during tick N will be processed in tick
N+1. This is semantically identical to the current behavior: today,
`drain().collect()` snapshots the set, and any `mark()` calls during the loop
insert into the freshly-emptied set — which is not processed until next tick.
The dual-set pattern makes this implicit behavior explicit. Since `poll_send`
runs every tick of the run loop, the delay is sub-millisecond.

**Capacity preservation:** Both sets retain their hash table allocation across
ticks. After `drain()`, the set is empty but its capacity remains. The primary
win is not avoiding reallocation (which the current code also avoids) but
eliminating the ~3.85% insert cost from re-inserting IDs into the set after
processing — with dual sets, these inserts go into `pending` which already has
capacity from prior ticks, and there is no re-insertion into the set being
iterated.

**`is_empty()`:** The existing `is_empty()` method (currently `#[allow(dead_code)]`)
must check both sets: `self.active.is_empty() && self.pending.is_empty()`.

### Location

- `src/net/handler/tcp/send_tracker.rs` — struct and all methods

---

## 2. Targeted Connection Removal in poll_send

### Problem

`poll_send` ends with:

```rust
connections.retain(|id, tcb| {
    if tcb.state == TcpState::Closed {
        send_tracker.unmark(id);
        false
    } else {
        true
    }
});
```

This iterates ALL connections every tick to find the (typically 0-1) connections
that transitioned to `Closed` during this `poll_send` call. With thousands of
connections, this is O(n) wasted work — the 2.19% `HashMap::retain` in the
profile.

### Design

During the `poll_send` loop, the only path that sets `TcpState::Closed` is the
linger-deadline RST (transmit.rs line 315). Collect these IDs into a
stack-allocated `SmallVec`:

```rust
let mut closed: SmallVec<[ConnectionId; 4]> = SmallVec::new();

// ... in the loop, after setting tcb.state = TcpState::Closed:
closed.push(id);

// ... after the loop:
for id in &closed {
    self.send_tracker.unmark(&id);
    self.connections.remove(&id);
}
```

`SmallVec<[ConnectionId; 4]>` stores up to 4 IDs on the stack. `ConnectionId`
is ~40 bytes (two `IpAddress` enums at ~17 bytes each + two `u16` + padding),
so the inline buffer is ~160 bytes — well within stack budget. The common case
of 0 closures per tick has zero heap allocation. Even the rare case of >4
simultaneous linger timeouts only spills to heap once.

Note: `decrement_syn_received` is not needed here. The linger-deadline RST path
only fires for Established/CloseWait connections (gated by `tcb.pending_fin`),
which are never in SynReceived state.

The `retain()` call is deleted entirely.

### Location

- `src/net/handler/tcp/transmit.rs` — `poll_send` method

---

## 3. SmallVec for poll_timers Temporary Vecs (Minor)

### Problem

`poll_timers` allocates three `Vec`s per call:
- `to_mark: Vec<ConnectionId>` (line 31)
- `keep_alive_removals: Vec<ConnectionId>` (line 89)
- `to_remove: Vec<ConnectionId>` (line 253)

These are rate-limited to ~1/65536 ticks so the impact is negligible, but they
follow the same allocation-per-call pattern.

### Design

Replace all three with `SmallVec<[ConnectionId; 4]>`. This is a mechanical
change — same push/iterate/remove pattern, just stack-allocated for the common
case.

### Location

- `src/net/handler/tcp/timers.rs` — `poll_timers` method

---

## Implementation Order

1. **SendTracker dual-set** — change the struct and API
2. **poll_send** — use `swap()` + `drain_active()`, add SmallVec for closed IDs, remove `retain()`
3. **poll_timers** — swap Vec for SmallVec (mechanical)
4. **Verify** — run full test suite, re-profile

Steps 1 and 2 are tightly coupled. Step 3 is independent.

---

## File Summary

| File | Action |
|------|--------|
| `src/net/handler/tcp/send_tracker.rs` | Dual-set struct, new swap/drain_active API |
| `src/net/handler/tcp/transmit.rs` | Use new SendTracker API, SmallVec for closed, remove retain() |
| `src/net/handler/tcp/timers.rs` | Vec → SmallVec for to_mark, to_remove, keep_alive_removals |

No new dependencies — `smallvec` is already in `Cargo.toml`.

---

## Future: Approach B (HTTP Response Formatting)

The next optimization pass will target HTTP response formatting (~4.77% CPU):
- Replace `format!()` status line / header allocation with direct buffer writes
- Eliminate intermediate String allocations in `add_header()` / `flush_headers()`
- Stack-format chunked encoding hex size

This is a separate spec that builds on the same profiling data.
