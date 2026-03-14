# Neighbor Solicitation on Cache Miss — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace broadcast MAC fallback on neighbor cache miss with proper ARP/NDP solicitation and a three-state entry model (Incomplete → Reachable → Stale).

**Architecture:** Replace `NeighborEntry { mac, expires_at }` with a `NeighborState` enum encoding Incomplete/Reachable/Stale. Add `lookup_or_resolve()` to `NeighborHandler` that centralizes cache lookup + solicitation-on-miss. Update all 9 TCP broadcast fallback sites and the UDP manual resolve to use it.

**Tech Stack:** Rust, coarsetime, dashmap

**Spec:** `docs/superpowers/specs/2026-03-13-neighbor-solicitation-on-miss-design.md`

---

## Chunk 1: NeighborState Enum and Entry Refactor

### Task 1: Replace NeighborEntry with NeighborState enum

**Files:**
- Modify: `src/net/neighbor/entry.rs` (full rewrite)

- [ ] **Step 1: Write tests for NeighborState**

Add tests at the bottom of `entry.rs` for the new enum:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use coarsetime::{Duration, Instant};
    use crate::net::wire::ethernet::MacAddress;

    const MAC_A: MacAddress = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

    #[test]
    fn incomplete_returns_none_for_mac() {
        let now = Instant::now();
        let entry = NeighborState::incomplete(now);
        assert!(entry.mac().is_none());
    }

    #[test]
    fn reachable_returns_mac_when_valid() {
        let now = Instant::now();
        let entry = NeighborState::reachable(MAC_A, now + Duration::from_secs(60));
        assert_eq!(entry.mac(), Some(MAC_A));
    }

    #[test]
    fn stale_returns_mac() {
        let now = Instant::now();
        let entry = NeighborState::stale(MAC_A, now);
        assert_eq!(entry.mac(), Some(MAC_A));
    }

    #[test]
    fn incomplete_is_expired_after_timeout() {
        let now = Instant::now();
        let entry = NeighborState::incomplete(now);
        let later = now + Duration::from_secs(4);
        assert!(entry.should_evict(later));
    }

    #[test]
    fn incomplete_not_expired_within_timeout() {
        let now = Instant::now();
        let entry = NeighborState::incomplete(now);
        let later = now + Duration::from_secs(2);
        assert!(!entry.should_evict(later));
    }

    #[test]
    fn reachable_not_evictable() {
        let now = Instant::now();
        let entry = NeighborState::reachable(MAC_A, now + Duration::from_secs(60));
        assert!(!entry.should_evict(now));
    }

    #[test]
    fn reachable_is_expired_checks_ttl() {
        let now = Instant::now();
        let entry = NeighborState::reachable(MAC_A, now + Duration::from_secs(60));
        assert!(!entry.is_expired(now));
        let later = now + Duration::from_secs(61);
        assert!(entry.is_expired(later));
    }

    #[test]
    fn stale_evicted_after_timeout() {
        let now = Instant::now();
        let entry = NeighborState::stale(MAC_A, now);
        let later = now + Duration::from_secs(31);
        assert!(entry.should_evict(later));
    }

    #[test]
    fn stale_not_evicted_within_timeout() {
        let now = Instant::now();
        let entry = NeighborState::stale(MAC_A, now);
        let later = now + Duration::from_secs(20);
        assert!(!entry.should_evict(later));
    }

    #[test]
    fn should_solicit_incomplete_respects_guard() {
        let now = Instant::now();
        let entry = NeighborState::incomplete(now);
        // Just solicited — should not re-solicit.
        assert!(!entry.should_solicit(now));
        // After guard period.
        let later = now + Duration::from_secs(2);
        assert!(entry.should_solicit(later));
    }

    #[test]
    fn should_solicit_stale_respects_guard() {
        let now = Instant::now();
        let mut entry = NeighborState::stale(MAC_A, now);
        // Not yet solicited.
        assert!(entry.should_solicit(now));
        // Mark solicited.
        entry.mark_solicited(now);
        assert!(!entry.should_solicit(now));
        let later = now + Duration::from_secs(2);
        assert!(entry.should_solicit(later));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib neighbor::entry`
Expected: FAIL — `NeighborState` does not exist yet.

- [ ] **Step 3: Implement NeighborState enum**

Replace the contents of `entry.rs` with:

```rust
use coarsetime::{Duration, Instant};

use crate::net::wire::ethernet::MacAddress;

/// Timeout before evicting an Incomplete entry (no reply received).
const INCOMPLETE_TIMEOUT: Duration = Duration::from_secs(3);

/// Timeout before evicting a Stale entry.
const STALE_TIMEOUT: Duration = Duration::from_secs(30);

/// Minimum interval between re-solicitations for the same address.
const SOLICIT_GUARD: Duration = Duration::from_secs(1);

/// Neighbor cache entry with three reachability states.
#[derive(Debug)]
pub(super) enum NeighborState {
    /// Solicitation sent, awaiting reply. No MAC known yet.
    Incomplete {
        solicited_at: Instant,
    },
    /// Reply received, MAC is valid until `expires_at`.
    Reachable {
        mac: MacAddress,
        expires_at: Instant,
    },
    /// TTL expired but MAC likely still valid. Re-validation in progress.
    Stale {
        mac: MacAddress,
        stale_since: Instant,
        solicited_at: Option<Instant>,
    },
}

impl NeighborState {
    pub fn incomplete(now: Instant) -> Self {
        Self::Incomplete { solicited_at: now }
    }

    pub fn reachable(mac: MacAddress, expires_at: Instant) -> Self {
        Self::Reachable { mac, expires_at }
    }

    pub fn stale(mac: MacAddress, stale_since: Instant) -> Self {
        Self::Stale {
            mac,
            stale_since,
            solicited_at: None,
        }
    }

    /// Returns the MAC address if known (Reachable or Stale).
    pub fn mac(&self) -> Option<MacAddress> {
        match self {
            Self::Incomplete { .. } => None,
            Self::Reachable { mac, .. } | Self::Stale { mac, .. } => Some(*mac),
        }
    }

    /// Returns true if a Reachable entry's TTL has expired.
    pub fn is_expired(&self, now: Instant) -> bool {
        match self {
            Self::Reachable { expires_at, .. } => now >= *expires_at,
            _ => false,
        }
    }

    /// Returns true if this entry should be removed by eviction sweep.
    pub fn should_evict(&self, now: Instant) -> bool {
        match self {
            Self::Incomplete { solicited_at } => now >= *solicited_at + INCOMPLETE_TIMEOUT,
            Self::Reachable { .. } => false,
            Self::Stale { stale_since, .. } => now >= *stale_since + STALE_TIMEOUT,
        }
    }

    /// Returns true if we should send a (re-)solicitation for this entry.
    pub fn should_solicit(&self, now: Instant) -> bool {
        match self {
            Self::Incomplete { solicited_at } => now >= *solicited_at + SOLICIT_GUARD,
            Self::Stale {
                solicited_at: None, ..
            } => true,
            Self::Stale {
                solicited_at: Some(at),
                ..
            } => now >= *at + SOLICIT_GUARD,
            Self::Reachable { .. } => false,
        }
    }

    /// Update the solicited_at timestamp after sending a solicitation.
    pub fn mark_solicited(&mut self, now: Instant) {
        match self {
            Self::Incomplete { solicited_at } => *solicited_at = now,
            Self::Stale { solicited_at, .. } => *solicited_at = Some(now),
            Self::Reachable { .. } => {}
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib neighbor::entry`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/net/neighbor/entry.rs
git commit -m "refactor(neighbor): replace NeighborEntry with three-state NeighborState enum"
```

---

### Task 2: Update NeighborHandler to use NeighborState

**Files:**
- Modify: `src/net/neighbor/handler.rs`
- Modify: `src/net/neighbor/mod.rs`

- [ ] **Step 1: Update mod.rs to export NeighborState**

Change `use entry::NeighborEntry;` to `use entry::NeighborState;` in `mod.rs`.

- [ ] **Step 2: Update handler.rs — table type and imports**

Change `DashMap<IpAddress, NeighborEntry>` to `DashMap<IpAddress, NeighborState>` in the struct.
Update the import from `use super::NeighborEntry` to `use super::NeighborState`.

- [ ] **Step 3: Update `lookup()` for NeighborState**

```rust
pub fn lookup(&self, now: Instant, ip: &IpAddress) -> Option<MacAddress> {
    self.table.get(ip).and_then(|e| {
        if !e.is_expired(now) {
            e.mac()
        } else {
            None
        }
    })
}
```

- [ ] **Step 4: Update `evict_stale()` for three-state model**

```rust
pub fn evict_stale(&self, now: Instant) {
    // First pass: transition expired Reachable → Stale.
    for mut entry in self.table.iter_mut() {
        if entry.is_expired(now) {
            if let NeighborState::Reachable { mac, .. } = *entry {
                *entry = NeighborState::stale(mac, now);
            }
        }
    }
    // Second pass: remove Incomplete and Stale entries past their timeouts.
    self.table.retain(|_, entry| !entry.should_evict(now));
}
```

- [ ] **Step 5: Update `learn_from_traffic()` for state transitions**

```rust
pub fn learn_from_traffic(&self, now: Instant, ip: IpAddress, mac: MacAddress) {
    if mac == MacAddress::broadcast() || mac == MacAddress::zero() {
        return;
    }
    if ip.is_unspecified() {
        return;
    }
    // Always transition to Reachable (handles Incomplete→Reachable, Stale→Reachable,
    // and fresh insert).
    self.table
        .insert(ip, NeighborState::reachable(mac, now + self.ttl));
}
```

- [ ] **Step 6: Add `lookup_or_resolve()` method**

Add this method to `NeighborHandler`:

```rust
/// Look up a neighbor MAC. On cache miss or expired entry, send an
/// ARP request (IPv4) or NDP Neighbor Solicitation (IPv6) and return
/// `None` (caller should drop the packet; TCP retransmit recovers).
///
/// On Stale hit, returns the MAC optimistically while re-validating.
pub fn lookup_or_resolve<'umem>(
    &self,
    now: Instant,
    addr: &IpAddress,
    src_addr: &IpAddress,
    free_frames: &mut impl FrameBuffer<'umem>,
    rx_return: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) -> Option<MacAddress> {
    // Fast path: entry exists.
    if let Some(mut entry) = self.table.get_mut(addr) {
        match *entry {
            NeighborState::Reachable { mac, expires_at } => {
                if now < expires_at {
                    return Some(mac);
                }
                // Transition to Stale, solicit, return MAC optimistically.
                *entry = NeighborState::Stale {
                    mac,
                    stale_since: now,
                    solicited_at: Some(now),
                };
                drop(entry);
                self.send_solicitation(now, addr, src_addr, free_frames, rx_return, tx_return);
                return Some(mac);
            }
            NeighborState::Stale { mac, .. } => {
                let needs_solicit = entry.should_solicit(now);
                if needs_solicit {
                    entry.mark_solicited(now);
                }
                drop(entry);
                if needs_solicit {
                    self.send_solicitation(now, addr, src_addr, free_frames, rx_return, tx_return);
                }
                return Some(mac);
            }
            NeighborState::Incomplete { .. } => {
                let needs_solicit = entry.should_solicit(now);
                if needs_solicit {
                    entry.mark_solicited(now);
                }
                drop(entry);
                if needs_solicit {
                    self.send_solicitation(now, addr, src_addr, free_frames, rx_return, tx_return);
                }
                return None;
            }
        }
    }

    // No entry — insert Incomplete and solicit.
    self.table
        .insert(*addr, NeighborState::incomplete(now));
    self.send_solicitation(now, addr, src_addr, free_frames, rx_return, tx_return);
    None
}

/// Send an ARP request or NDP NS based on address family.
fn send_solicitation<'umem>(
    &self,
    _now: Instant,
    addr: &IpAddress,
    src_addr: &IpAddress,
    free_frames: &mut impl FrameBuffer<'umem>,
    rx_return: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) {
    let Some(frame) = free_frames.pop() else {
        return;
    };
    match (src_addr, addr) {
        (IpAddress::V4(src), IpAddress::V4(dst)) => {
            resolve_v4(self.local_mac, *src, *dst, frame, rx_return, tx_return);
        }
        (IpAddress::V6(src), IpAddress::V6(dst)) => {
            resolve_v6(
                self.local_mac,
                *src,
                *dst,
                self.tx_offload,
                frame,
                rx_return,
                tx_return,
            );
        }
        _ => {
            // Mismatched address families — return the frame.
            rx_return.push(frame);
        }
    }
}
```

- [ ] **Step 7: Run existing handler tests**

Run: `cargo test --lib neighbor::handler`
Expected: All existing tests PASS (the API is backward compatible — `lookup()` still works).

- [ ] **Step 8: Commit**

```bash
git add src/net/neighbor/handler.rs src/net/neighbor/mod.rs
git commit -m "feat(neighbor): add lookup_or_resolve() with three-state cache"
```

---

### Task 3: Update ARP handler for state-aware inserts

**Files:**
- Modify: `src/net/neighbor/arp.rs`

- [ ] **Step 1: Update import**

Change `use super::NeighborEntry;` to `use super::NeighborState;`.

- [ ] **Step 2: Update `handle_arp()` cache insert**

Change line 103 from:
```rust
table.insert(IpAddress::V4(spa), NeighborEntry::new(sha, now + ttl));
```
to:
```rust
table.insert(IpAddress::V4(spa), NeighborState::reachable(sha, now + ttl));
```

This handles all transitions: no-entry→Reachable, Incomplete→Reachable, Stale→Reachable.

- [ ] **Step 3: Run ARP tests**

Run: `cargo test --lib neighbor::arp`
Expected: All tests PASS.

- [ ] **Step 4: Commit**

```bash
git add src/net/neighbor/arp.rs
git commit -m "refactor(neighbor): update ARP handler for NeighborState"
```

---

### Task 4: Update NDP handler for state-aware inserts

**Files:**
- Modify: `src/net/neighbor/ndp.rs`

- [ ] **Step 1: Update import**

Change `use super::NeighborEntry;` to `use super::NeighborState;`.

- [ ] **Step 2: Update all `table.insert()` calls**

There are 3 insert sites in ndp.rs. Change each `NeighborEntry::new(mac, now + ttl)` to `NeighborState::reachable(mac, now + ttl)`:

1. `handle_neighbor_solicitation` line 199
2. `handle_neighbor_advertisement` line 290-293
3. `handle_router_advertisement` line 322

- [ ] **Step 3: Run NDP tests**

Run: `cargo test --lib neighbor::ndp`
Expected: All tests PASS.

- [ ] **Step 4: Commit**

```bash
git add src/net/neighbor/ndp.rs
git commit -m "refactor(neighbor): update NDP handler for NeighborState"
```

---

## Chunk 2: TCP and UDP Call Site Updates

### Task 5: Add `rx_return` parameter to `poll_send` and `poll_timers`

Both functions need `rx_return` because `lookup_or_resolve()` requires it (the underlying
`resolve_v4`/`resolve_v6` use it for frame recycling on capacity errors).

**Files:**
- Modify: `src/net/handler/tcp/transmit.rs`
- Modify: `src/net/handler/tcp/timers.rs`
- Modify: `src/rt/local.rs`

- [ ] **Step 1: Add `rx_return` to `poll_send` signature**

In `transmit.rs`, change the signature to:

```rust
pub fn poll_send<'umem>(
    &mut self,
    now: Instant,
    src_mac: crate::net::wire::ethernet::MacAddress,
    neighbor_handler: &NeighborHandler,
    free_frames: &mut impl FrameBuffer<'umem>,
    rx_return: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) {
```

- [ ] **Step 2: Add `rx_return` to `poll_timers` signature**

In `timers.rs`, change the signature to:

```rust
pub fn poll_timers<'umem>(
    &mut self,
    now: Instant,
    src_mac: crate::net::wire::ethernet::MacAddress,
    neighbor_handler: &NeighborHandler,
    free_frames: &mut impl FrameBuffer<'umem>,
    rx_return: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) {
```

- [ ] **Step 3: Update caller in `src/rt/local.rs`**

Pass `&mut self.rx_return` to both calls:

For `poll_send` (~line 345):
```rust
unsafe { &mut *self.tcp_handler.get() }.poll_send(
    now,
    self.neighbor_handler.local_mac(),
    &self.neighbor_handler,
    &mut self.free_frames,
    &mut self.rx_return,
    &mut self.tx_return,
);
```

For `poll_timers` (~line 367):
```rust
tcp_handler.poll_timers(
    now,
    self.neighbor_handler.local_mac(),
    &self.neighbor_handler,
    &mut self.free_frames,
    &mut self.rx_return,
    &mut self.tx_return,
);
```

- [ ] **Step 4: Verify it compiles**

Run: `cargo check`
Expected: FAIL — test call sites don't pass `rx_return` yet. That's fine, we fix tests in the next step.

- [ ] **Step 5: Commit**

```bash
git add src/net/handler/tcp/transmit.rs src/net/handler/tcp/timers.rs src/rt/local.rs
git commit -m "refactor(tcp): add rx_return parameter to poll_send and poll_timers"
```

---

### Task 6: Replace broadcast fallback with `lookup_or_resolve()` in transmit.rs

**Files:**
- Modify: `src/net/handler/tcp/transmit.rs`

There are 5 sites in `transmit.rs` that do:
```rust
let dst_mac = neighbor_handler
    .lookup(now, &tcb.id.remote_addr)
    .unwrap_or(crate::net::wire::ethernet::MacAddress::broadcast());
```

Replace each with `lookup_or_resolve` + early exit on `None`.

**Important:** Site 1 is inside an inner `loop { }` block, so it must use `break`
(not `continue`, which would restart the inner loop and spin forever). Sites 2-5
are in the outer `for tcb in ...` loop, so they use `continue` to skip to the
next connection.

Site 1 (data send loop, ~line 104):
```rust
let Some(dst_mac) = neighbor_handler.lookup_or_resolve(
    now,
    &tcb.id.remote_addr,
    &tcb.id.local_addr,
    free_frames,
    rx_return,
    tx_return,
) else {
    break; // exit inner loop — TCP retransmit will retry later
};
```

Sites 2-5 (~lines 170, 221, 258, 294):
```rust
let Some(dst_mac) = neighbor_handler.lookup_or_resolve(
    now,
    &tcb.id.remote_addr,
    &tcb.id.local_addr,
    free_frames,
    rx_return,
    tx_return,
) else {
    continue; // skip to next connection
};
```

- [ ] **Step 1: Replace all 5 broadcast fallback sites**

Replace each of the 5 sites as described above. Use `break` for site 1 (inner loop)
and `continue` for sites 2-5 (outer for loop).

- [ ] **Step 2: Verify it compiles (ignoring test errors)**

Run: `cargo check --lib`
Expected: Should compile (test files may still fail).

- [ ] **Step 3: Commit**

```bash
git add src/net/handler/tcp/transmit.rs
git commit -m "feat(neighbor): replace broadcast fallback with lookup_or_resolve in TCP transmit"
```

---

### Task 7: Replace broadcast fallback with `lookup_or_resolve()` in timers.rs

**Files:**
- Modify: `src/net/handler/tcp/timers.rs`

There are 4 sites in `timers.rs` with the same broadcast fallback pattern:
1. ~42-44 (delayed ACK timer flush)
2. ~110-112 (keep-alive probe)
3. ~187-189 (SACK recovery retransmit)
4. ~263-265 (RTO retransmit)

Replace each with `lookup_or_resolve` + `continue` on `None`.

**Important — RTO retransmit site (~263):** The `continue` skips the `match tcb.state`
block, which means the exponential backoff at the bottom won't execute and the
retransmit timer won't be re-armed. To prevent the connection from stalling, re-arm
the timer before continuing:

```rust
let Some(dst_mac) = neighbor_handler.lookup_or_resolve(
    now,
    &id.remote_addr,
    &id.local_addr,
    free_frames,
    rx_return,
    tx_return,
) else {
    // Re-arm retransmit timer so we retry after the solicitation completes.
    tcb.retransmit_deadline =
        Some(now + coarsetime::Duration::from_millis(tcb.rto));
    continue;
};
```

For the other 3 sites (delayed ACK ~42, keep-alive ~110, SACK recovery ~187), a
plain `continue` is sufficient — those timers will naturally re-fire.

- [ ] **Step 1: Replace all 4 broadcast fallback sites**

- [ ] **Step 2: Verify the library compiles**

Run: `cargo check --lib`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add src/net/handler/tcp/timers.rs
git commit -m "feat(neighbor): replace broadcast fallback with lookup_or_resolve in TCP timers"
```

---

### Task 8: Update TCP test call sites

**Files:**
- Modify: `src/net/handler/tcp/tests/ecn.rs`
- Modify: `src/net/handler/tcp/tests/retransmission.rs`
- Modify: `src/net/handler/tcp/tests/teardown.rs`
- Modify: `src/net/handler/tcp/tests/nagle.rs`
- Modify: `src/net/handler/tcp/tests/persist.rs`
- Modify: `src/net/handler/tcp/tests/congestion_tests.rs`
- Modify: `src/net/handler/tcp/tests/data_transfer.rs`
- Modify: `src/net/handler/tcp/tests/delayed_ack.rs`
- Modify: `src/net/handler/tcp/tests/edge_cases.rs`
- Modify: `src/net/handler/tcp/tests/keepalive.rs`
- Modify: `src/net/handler/tcp/tests/sack.rs`

~49 call sites across 11 test files need to pass `rx_return`:

Every call like:
```rust
handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
```
becomes:
```rust
handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
```

And every call like:
```rust
handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut tx);
```
becomes:
```rust
handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
```

All test files already have an `rx` (`BasicFrameBuffer`) variable declared.

**Important:** Tests also need the neighbor handler to have the remote IP pre-populated
in the cache so that `lookup_or_resolve()` returns `Some(mac)` instead of `None`. Check
each test's `new_neighbor_handler()` or equivalent setup. If the test creates an
established connection to a remote IP, the neighbor cache should have that IP's MAC
pre-seeded via `learn_from_traffic()`. Look for the common test helper and add a
`learn_from_traffic` call there for the standard test remote address.

**Existing test breakage:** The test `evict_stale_removes_expired_entries` in
`handler.rs` (line 410) will fail because `evict_stale` now transitions expired
Reachable entries to Stale instead of removing them, and `lookup()` returns
`Some(mac)` for Stale entries. Update this test to call `evict_stale` twice —
once to transition to Stale, then again 31+ seconds later to evict the Stale
entry — or update the assertion to reflect the new Stale behavior.

- [ ] **Step 1: Find the test helper and seed the neighbor cache**

Look at the common test helpers (likely in a `mod.rs` or similar under tests/). The
`new_neighbor_handler()` function should seed the remote MAC. Add:
```rust
nh.learn_from_traffic(
    Instant::now(),
    IpAddress::V4(TEST_REMOTE_IP),
    TEST_REMOTE_MAC,
);
```
to the `new_neighbor_handler()` helper (or equivalent) so all tests that create
established connections have the remote peer in cache.

- [ ] **Step 2: Update all 45 call sites across 10 files**

Add `&mut rx,` as the new parameter before `&mut tx` in every `poll_send` and
`poll_timers` call.

- [ ] **Step 3: Run all TCP tests**

Run: `cargo test --lib handler::tcp`
Expected: All tests PASS.

- [ ] **Step 4: Commit**

```bash
git add src/net/handler/tcp/tests/
git commit -m "test(tcp): update poll_send/poll_timers calls for rx_return parameter"
```

---

### Task 9: Update UDP socket to use `lookup_or_resolve()`

**Files:**
- Modify: `src/net/socket/udp.rs`

- [ ] **Step 1: Replace manual resolve logic**

In `prepare_udp_packet()` (~line 326-352), replace the manual lookup + resolve pattern:

```rust
let dst_mac = match self.neighbor_handler.lookup(now, &self.dst_addr) {
    Some(mac) => mac,
    None => {
        let frame = self.free_frames.pop().ok_or(WouldBlock)?;
        match (self.src_addr, self.dst_addr) {
            (IpAddress::V4(src), IpAddress::V4(dst)) => {
                self.neighbor_handler.resolve_v4(src, dst, frame, ...);
            }
            (IpAddress::V6(src), IpAddress::V6(dst)) => {
                self.neighbor_handler.resolve_v6(src, dst, frame, ...);
            }
            _ => { ... }
        }
        return Err(WouldBlock);
    }
};
```

With:

```rust
let dst_mac = match self.neighbor_handler.lookup_or_resolve(
    now,
    &self.dst_addr,
    &self.src_addr,
    &mut self.free_frames,
    &mut self.rx_return,
    &mut self.tx_return,
) {
    Some(mac) => mac,
    None => return Err(WouldBlock),
};
```

- [ ] **Step 2: Run UDP tests**

Run: `cargo test --lib socket::udp`
Expected: All tests PASS.

- [ ] **Step 3: Commit**

```bash
git add src/net/socket/udp.rs
git commit -m "refactor(udp): use lookup_or_resolve instead of manual resolve"
```

---

## Chunk 3: Tests for New Behavior

### Task 10: Add tests for lookup_or_resolve behavior

**Files:**
- Modify: `src/net/neighbor/handler.rs` (add tests to existing test module)

- [ ] **Step 1: Add test — miss inserts Incomplete and sends solicitation**

```rust
#[test]
fn lookup_or_resolve_miss_sends_arp_request() {
    let handler = new_handler();
    let mut free = BasicFrameBuffer::new(4);
    let mut rx = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(4);

    // Seed free frames (resolve needs one frame to build the solicitation).
    let mut data = [0u8; 64];
    let frame = Frame::new(0, &mut data, 1, false);
    free.push(frame);

    let now = Instant::now();
    let target = IpAddress::V4(Ipv4Address::new([192, 168, 1, 200]));
    let src = IpAddress::V4(TEST_LOCAL_IP);

    let result = handler.lookup_or_resolve(now, &target, &src, &mut free, &mut rx, &mut tx);

    assert!(result.is_none(), "miss should return None");
    assert_eq!(tx.num_frames(), 1, "should have sent ARP request");
    assert_eq!(free.num_frames(), 0, "free frame consumed");
}

#[test]
fn lookup_or_resolve_incomplete_suppresses_re_solicit() {
    let handler = new_handler();
    let mut free = BasicFrameBuffer::new(4);
    let mut rx = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(4);

    let mut data1 = [0u8; 64];
    let frame1 = Frame::new(0, &mut data1, 1, false);
    free.push(frame1);

    let mut data2 = [0u8; 64];
    let frame2 = Frame::new(0, &mut data2, 1, false);
    free.push(frame2);

    let now = Instant::now();
    let target = IpAddress::V4(Ipv4Address::new([192, 168, 1, 200]));
    let src = IpAddress::V4(TEST_LOCAL_IP);

    // First miss — sends solicitation.
    handler.lookup_or_resolve(now, &target, &src, &mut free, &mut rx, &mut tx);
    assert_eq!(tx.num_frames(), 1);

    // Second miss at same time — suppressed.
    let result = handler.lookup_or_resolve(now, &target, &src, &mut free, &mut rx, &mut tx);
    assert!(result.is_none());
    assert_eq!(tx.num_frames(), 1, "no additional solicitation");
}

#[test]
fn lookup_or_resolve_reachable_returns_mac() {
    let now = Instant::now();
    let handler = new_handler();
    let mut free = BasicFrameBuffer::new(4);
    let mut rx = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(4);

    // Pre-populate cache.
    handler.learn_from_traffic(now, IpAddress::V4(TEST_REMOTE_IP), TEST_REMOTE_MAC);

    let result = handler.lookup_or_resolve(
        now,
        &IpAddress::V4(TEST_REMOTE_IP),
        &IpAddress::V4(TEST_LOCAL_IP),
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert_eq!(result, Some(TEST_REMOTE_MAC));
    assert_eq!(tx.num_frames(), 0, "no solicitation for reachable entry");
}

#[test]
fn lookup_or_resolve_expired_transitions_to_stale_and_returns_mac() {
    let now = Instant::now();
    let handler = new_handler();
    let mut free = BasicFrameBuffer::new(4);
    let mut rx = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(4);

    handler.learn_from_traffic(now, IpAddress::V4(TEST_REMOTE_IP), TEST_REMOTE_MAC);

    let mut data = [0u8; 64];
    let frame = Frame::new(0, &mut data, 1, false);
    free.push(frame);

    // Advance past TTL.
    let future = now + TEST_TTL + Duration::from_secs(1);
    let result = handler.lookup_or_resolve(
        future,
        &IpAddress::V4(TEST_REMOTE_IP),
        &IpAddress::V4(TEST_LOCAL_IP),
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert_eq!(result, Some(TEST_REMOTE_MAC), "stale returns MAC optimistically");
    assert_eq!(tx.num_frames(), 1, "solicitation sent for re-validation");
}

#[test]
fn lookup_or_resolve_ipv6_sends_ndp_ns() {
    let handler = new_handler();
    let mut free = BasicFrameBuffer::new(4);
    let mut rx = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(4);

    let mut data = [0u8; 128];
    let frame = Frame::new(0, &mut data, 1, false);
    free.push(frame);

    let now = Instant::now();
    let target = IpAddress::V6(Ipv6Address::new([
        0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42,
    ]));
    let src = IpAddress::V6(TEST_LOCAL_IPV6);

    let result = handler.lookup_or_resolve(now, &target, &src, &mut free, &mut rx, &mut tx);

    assert!(result.is_none());
    assert_eq!(tx.num_frames(), 1, "should have sent NDP NS");
}
```

- [ ] **Step 2: Run handler tests**

Run: `cargo test --lib neighbor::handler`
Expected: All tests PASS.

- [ ] **Step 3: Add tests for learn_from_traffic state transitions**

```rust
#[test]
fn learn_from_traffic_transitions_incomplete_to_reachable() {
    let now = Instant::now();
    let handler = new_handler();
    let mut free = BasicFrameBuffer::new(4);
    let mut rx = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(4);

    let mut data = [0u8; 64];
    let frame = Frame::new(0, &mut data, 1, false);
    free.push(frame);

    let target = IpAddress::V4(Ipv4Address::new([10, 0, 0, 42]));
    let src = IpAddress::V4(TEST_LOCAL_IP);

    // Create Incomplete entry via miss.
    let result = handler.lookup_or_resolve(now, &target, &src, &mut free, &mut rx, &mut tx);
    assert!(result.is_none());

    // Simulate inbound traffic from that IP (before ARP reply arrives).
    let mac = MacAddress::new([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
    handler.learn_from_traffic(now, target, mac);

    // Should now be Reachable.
    assert_eq!(handler.lookup(now, &target), Some(mac));
}

#[test]
fn learn_from_traffic_transitions_stale_to_reachable() {
    let now = Instant::now();
    let handler = new_handler();

    let ip = IpAddress::V4(TEST_REMOTE_IP);
    handler.learn_from_traffic(now, ip, TEST_REMOTE_MAC);

    // Expire → Stale.
    let after_ttl = now + TEST_TTL + Duration::from_secs(1);
    handler.evict_stale(after_ttl);

    // Re-learn from traffic → back to Reachable.
    let new_mac = MacAddress::new([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x02]);
    handler.learn_from_traffic(after_ttl, ip, new_mac);

    assert_eq!(handler.lookup(after_ttl, &ip), Some(new_mac));
}
```

- [ ] **Step 5: Add test — evict_stale transitions Reachable→Stale**

```rust
#[test]
fn evict_stale_transitions_reachable_to_stale() {
    let now = Instant::now();
    let handler = new_handler();

    handler.learn_from_traffic(now, IpAddress::V4(TEST_REMOTE_IP), TEST_REMOTE_MAC);

    // TTL expired.
    let future = now + TEST_TTL + Duration::from_secs(1);
    handler.evict_stale(future);

    // Entry should still exist (now Stale), not evicted.
    // lookup() returns None for expired entries, but the entry is in Stale state.
    // Use lookup_or_resolve to confirm it returns the MAC optimistically.
    let mut free = BasicFrameBuffer::new(4);
    let mut rx = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(4);

    let mut data = [0u8; 64];
    let frame = Frame::new(0, &mut data, 1, false);
    free.push(frame);

    let result = handler.lookup_or_resolve(
        future,
        &IpAddress::V4(TEST_REMOTE_IP),
        &IpAddress::V4(TEST_LOCAL_IP),
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(result, Some(TEST_REMOTE_MAC), "stale entry returns MAC");
}

#[test]
fn evict_stale_removes_old_stale_entries() {
    let now = Instant::now();
    let handler = new_handler();

    handler.learn_from_traffic(now, IpAddress::V4(TEST_REMOTE_IP), TEST_REMOTE_MAC);

    // TTL expired → transitions to Stale.
    let after_ttl = now + TEST_TTL + Duration::from_secs(1);
    handler.evict_stale(after_ttl);

    // 30s+ after stale → evicted.
    let after_stale = after_ttl + Duration::from_secs(31);
    handler.evict_stale(after_stale);

    assert!(handler.lookup(after_stale, &IpAddress::V4(TEST_REMOTE_IP)).is_none());
}

#[test]
fn evict_stale_removes_old_incomplete_entries() {
    let now = Instant::now();
    let handler = new_handler();
    let mut free = BasicFrameBuffer::new(4);
    let mut rx = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(4);

    let mut data = [0u8; 64];
    let frame = Frame::new(0, &mut data, 1, false);
    free.push(frame);

    let target = IpAddress::V4(Ipv4Address::new([10, 0, 0, 99]));
    let src = IpAddress::V4(TEST_LOCAL_IP);
    handler.lookup_or_resolve(now, &target, &src, &mut free, &mut rx, &mut tx);

    // 3s+ after incomplete → evicted.
    let after_timeout = now + Duration::from_secs(4);
    handler.evict_stale(after_timeout);

    // Subsequent lookup_or_resolve should re-insert Incomplete (fresh solicit).
    let mut data2 = [0u8; 64];
    let frame2 = Frame::new(0, &mut data2, 1, false);
    free.push(frame2);
    handler.lookup_or_resolve(after_timeout, &target, &src, &mut free, &mut rx, &mut tx);
    assert_eq!(tx.num_frames(), 2, "new solicitation after eviction");
}
```

- [ ] **Step 6: Run all handler tests**

Run: `cargo test --lib neighbor::handler`
Expected: All tests PASS.

- [ ] **Step 7: Commit**

```bash
git add src/net/neighbor/handler.rs
git commit -m "test(neighbor): add tests for lookup_or_resolve and eviction state transitions"
```

---

### Task 11: Run full test suite

- [ ] **Step 1: Run all tests**

Run: `cargo test`
Expected: All tests PASS.

- [ ] **Step 2: If failures, fix and re-run**

Address any compilation or logic errors. The most likely issues:
- Test helpers that need neighbor cache seeding
- Tests that assert exact frame counts (may now include solicitation frames)

- [ ] **Step 3: Final commit if any fixes were needed**

```bash
git add -A
git commit -m "fix: address test failures from neighbor state machine refactor"
```
