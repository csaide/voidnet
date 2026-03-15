# poll_send Allocation Storm Fix — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate ~11% CPU overhead from per-tick heap allocations and O(n) scans in `TcpHandler::poll_send`.

**Architecture:** Replace single-set SendTracker with dual-set swap-drain pattern (zero allocation per tick). Replace `connections.retain()` O(n) scan with SmallVec-based targeted removal. Apply SmallVec to poll_timers temporary Vecs for consistency.

**Tech Stack:** Rust, `rustc_hash::FxHashSet`, `smallvec::SmallVec`

**Spec:** `docs/superpowers/specs/2026-03-15-poll-send-alloc-fix-design.md`

---

### Task 1: SendTracker dual-set swap pattern

**Files:**
- Modify: `src/net/handler/tcp/send_tracker.rs`

- [ ] **Step 1: Rewrite SendTracker struct with dual sets**

Replace the entire file content with the dual-set implementation:

```rust
use rustc_hash::FxHashSet;

use super::tcb::ConnectionId;

/// Marker returned by Tcb methods that make a connection sendable.
/// Must be consumed by passing to `SendTracker::mark()`.
#[must_use = "connection must be marked for sending via SendTracker::mark()"]
pub struct SendReady(pub ConnectionId);

/// Tracks which connections have pending send work using a dual-set
/// swap pattern. `poll_send` calls `swap()` then `drain_active()` to
/// iterate without allocation. New marks go into `pending`, which
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
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check 2>&1 | head -20`

Expected: The old `drain()` method is gone, so `transmit.rs:31` will fail to compile. This is expected — we fix it in Task 2.

- [ ] **Step 3: Commit**

```bash
git add src/net/handler/tcp/send_tracker.rs
git commit -m "perf(net::tcp): Rewrite SendTracker with dual-set swap pattern

Replaces single FxHashSet with active/pending pair. swap() + drain_active()
eliminate the Vec allocation from drain().collect() on every poll_send tick.
mark() always inserts into pending, safe during active iteration."
```

---

### Task 2: Update poll_send to use new SendTracker API

**Files:**
- Modify: `src/net/handler/tcp/transmit.rs`

- [ ] **Step 1: Add SmallVec import**

Add `smallvec::SmallVec` to the imports at the top of `transmit.rs`. Change the existing import block from:

```rust
use coarsetime::Instant;

use crate::{
    net::{NeighborHandler, wire::tcp::flags},
    xdp::frame::FrameBuffer,
};

use super::{
    TcpHandler,
    segment::SegmentBuilder,
    send_tracker::SendReady,
    state::TcpState,
    tcb::{ConnectionId, MAX_DELAYED_ACK_COUNT, TcpEvent},
};
```

to:

```rust
use coarsetime::Instant;
use smallvec::SmallVec;

use crate::{
    net::{NeighborHandler, wire::tcp::flags},
    xdp::frame::FrameBuffer,
};

use super::{
    TcpHandler,
    segment::SegmentBuilder,
    send_tracker::SendReady,
    state::TcpState,
    tcb::{ConnectionId, MAX_DELAYED_ACK_COUNT, TcpEvent},
};
```

- [ ] **Step 2: Replace drain().collect() with swap + drain_active, add closed SmallVec**

Replace the start of poll_send (lines 31-32):

```rust
        let ids: Vec<ConnectionId> = self.send_tracker.drain().collect();
        for id in ids {
```

with:

```rust
        self.send_tracker.swap();
        let ids: SmallVec<[ConnectionId; 32]> = self.send_tracker.drain_active().collect();
        let mut closed: SmallVec<[ConnectionId; 4]> = SmallVec::new();
        for id in ids {
```

Note: We still collect into a SmallVec (stack-allocated for <= 32 connections) because the loop body calls `self.send_tracker.mark()` and `self.connections.get_mut()` which require `&mut self`. The drain iterator borrows `self.send_tracker`, preventing simultaneous `&mut self` access. The key win is: (a) SmallVec is stack-allocated for the common case, (b) marks go to `pending` not `active`, eliminating re-insert churn.

- [ ] **Step 3: Track closed connections in the linger-deadline RST path**

Find the linger-deadline RST block (line 314-317):

```rust
                tcb.event_queue.push(TcpEvent::Reset);
                tcb.state = TcpState::Closed;
                tcb.pending_fin = false;
                continue; // connection is Closed, will be cleaned up by retain
```

Replace with:

```rust
                tcb.event_queue.push(TcpEvent::Reset);
                tcb.state = TcpState::Closed;
                tcb.pending_fin = false;
                closed.push(id);
                continue; // connection is Closed, will be removed after loop
```

- [ ] **Step 4: Replace retain() with targeted removal**

Replace the retain block at the end of poll_send (lines 391-404):

```rust
        // Remove connections aborted by linger deadline.
        let Self {
            connections,
            send_tracker,
            ..
        } = self;
        connections.retain(|id, tcb| {
            if tcb.state == TcpState::Closed {
                send_tracker.unmark(id);
                false
            } else {
                true
            }
        });
```

with:

```rust
        // Remove connections aborted by linger deadline.
        for id in &closed {
            self.send_tracker.unmark(id);
            self.connections.remove(id);
        }
```

- [ ] **Step 5: Verify it compiles**

Run: `cargo check 2>&1 | head -20`

Expected: Clean compile, no errors.

- [ ] **Step 6: Run the full test suite**

Run: `cargo test 2>&1 | tail -20`

Expected: All tests pass. The behavioral semantics are unchanged — connections marked during poll_send go to `pending` and are processed next tick, same as before.

- [ ] **Step 7: Commit**

```bash
git add src/net/handler/tcp/transmit.rs
git commit -m "perf(net::tcp): Eliminate poll_send per-tick Vec alloc and retain() scan

- Use SendTracker swap/drain_active pattern instead of drain().collect::<Vec>()
- Collect into stack-allocated SmallVec<[_; 32]> instead of heap Vec
- Track linger-closed connections in SmallVec<[_; 4]>, remove targeted
- Delete connections.retain() O(n) scan — replaced with O(k) removal"
```

---

### Task 3: SmallVec for poll_timers temporary Vecs

**Files:**
- Modify: `src/net/handler/tcp/timers.rs`

- [ ] **Step 1: Add SmallVec import**

Add `smallvec::SmallVec` to the imports. Change:

```rust
use coarsetime::Instant;

use crate::{
    net::{NeighborHandler, wire::tcp::flags},
    xdp::frame::FrameBuffer,
};
```

to:

```rust
use coarsetime::Instant;
use smallvec::SmallVec;

use crate::{
    net::{NeighborHandler, wire::tcp::flags},
    xdp::frame::FrameBuffer,
};
```

- [ ] **Step 2: Replace Vec with SmallVec for to_mark**

Replace line 31:

```rust
        let mut to_mark: Vec<ConnectionId> = Vec::new();
```

with:

```rust
        let mut to_mark: SmallVec<[ConnectionId; 4]> = SmallVec::new();
```

- [ ] **Step 3: Replace Vec with SmallVec for keep_alive_removals**

Replace line 89:

```rust
        let mut keep_alive_removals: Vec<ConnectionId> = Vec::new();
```

with:

```rust
        let mut keep_alive_removals: SmallVec<[ConnectionId; 4]> = SmallVec::new();
```

- [ ] **Step 4: Replace Vec with SmallVec for to_remove**

Replace line 253:

```rust
        let mut to_remove: Vec<ConnectionId> = Vec::new();
```

with:

```rust
        let mut to_remove: SmallVec<[ConnectionId; 4]> = SmallVec::new();
```

- [ ] **Step 5: Verify it compiles and tests pass**

Run: `cargo check 2>&1 | head -10 && cargo test 2>&1 | tail -20`

Expected: Clean compile, all tests pass. This is a mechanical type swap — SmallVec implements the same push/iter/drain API as Vec.

- [ ] **Step 6: Commit**

```bash
git add src/net/handler/tcp/timers.rs
git commit -m "perf(net::tcp): Replace poll_timers Vec allocs with stack SmallVec

Mechanical swap of Vec<ConnectionId> to SmallVec<[ConnectionId; 4]> for
to_mark, keep_alive_removals, and to_remove. These are rate-limited
(~1/65536 ticks) so impact is minor — consistency with poll_send pattern."
```

---

### Task 4: Final verification

- [ ] **Step 1: Run cargo fmt**

Run: `cargo fmt`

- [ ] **Step 2: Run cargo clippy**

Run: `cargo clippy 2>&1 | head -30`

Expected: No new warnings.

- [ ] **Step 3: Run full test suite one more time**

Run: `cargo test 2>&1 | tail -30`

Expected: All tests pass.

- [ ] **Step 4: Verify the changes look correct**

Run: `git diff HEAD~3 --stat`

Expected: 3 files changed — `send_tracker.rs`, `transmit.rs`, `timers.rs`.
