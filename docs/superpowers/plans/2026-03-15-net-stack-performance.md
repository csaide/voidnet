# Net Stack Performance Optimization Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate per-packet and per-loop-iteration bottlenecks in VoidNet's net stack for CDN/HTTP workloads with high connection counts.

**Architecture:** Five targeted changes in priority order: remove learn_from_traffic (per-packet hash insert), swap PmtuCache from DashMap to FxHashMap, fix capacity-wakes guard, replace TCP Vec<Tcb> with FxHashMap for O(1) lookup, and add compile-time-enforced active-connection tracking for poll_send. Steps 1-3 are independent. Steps 4-5 are sequential.

**Tech Stack:** Rust, rustc_hash (FxHashMap/FxHashSet — already a dependency), coarsetime, AF_XDP/XDP

**Spec:** `docs/superpowers/specs/2026-03-15-net-stack-performance-design.md`

**Testing:** Tests require root via `cargo test` (no feature flags). See MEMORY.md.

---

## Chunk 1: Remove learn_from_traffic + PmtuCache swap + Capacity-wakes fix

These three tasks are independent and can be done in any order.

---

### Task 1: Remove learn_from_traffic

**Files:**
- Modify: `src/net/handler/ipv4.rs:96-104`
- Modify: `src/net/handler/ipv6.rs:187-193`
- Modify: `src/net/neighbor/handler.rs:151-160`
- Modify: `src/net/handler/tcp/tests/mod.rs:32,220,280,348,414`

**Why:** `learn_from_traffic` calls `DashMap::insert` on every valid incoming IPv4/IPv6 packet. ARP/NDP already handles neighbor discovery. Removing this eliminates a per-packet hash+insert from the hot path.

- [ ] **Step 1: Remove the learn_from_traffic call in ipv4.rs**

In `src/net/handler/ipv4.rs`, delete lines 96-104 (the comment block + `EthernetFrame::from_bytes` + `neighbor_handler.learn_from_traffic` call):

```rust
// DELETE these lines:
        // Learn source IP → MAC mapping from every valid incoming packet.
        // Ensures the neighbor cache stays populated even if ARP completed
        // before the XDP runtime attached.
        let eth = EthernetFrame::from_bytes(&frame);
        neighbor_handler.learn_from_traffic(
            now,
            crate::net::wire::ip::IpAddress::V4(ip.src_addr),
            eth.src_mac,
        );
```

- [ ] **Step 2: Remove the learn_from_traffic call in ipv6.rs**

In `src/net/handler/ipv6.rs`, delete lines 187-193 (the comment + `EthernetFrame::from_bytes` + `learn_from_traffic` call):

```rust
// DELETE these lines:
        // Learn source IP → MAC mapping from every valid incoming packet.
        let eth = EthernetFrame::from_bytes(&frame);
        neighbor_handler.learn_from_traffic(
            now,
            crate::net::wire::ip::IpAddress::V6(ip.src_addr),
            eth.src_mac,
        );
```

- [ ] **Step 3: Replace learn_from_traffic calls in TCP tests**

In `src/net/handler/tcp/tests/mod.rs`, there are 5 calls to `nh.learn_from_traffic(...)` at lines 32, 220, 280, 348, 414. These are used in test helpers to seed the neighbor cache so TCP handlers can resolve MACs for outbound segments.

Replace each `learn_from_traffic` call with `nh.handle_arp(...)` using a crafted ARP reply frame. This mirrors the pattern already used in `src/net/neighbor/handler.rs` tests (see `build_arp_reply` helper at line ~417). Build an ARP reply frame with the desired IP→MAC mapping, pass it to `handle_arp`, and the cache gets populated the same way it would in production.

- [ ] **Step 4: Delete the learn_from_traffic method**

In `src/net/neighbor/handler.rs`, delete the `learn_from_traffic` method (lines 151-160). Verify no other callers exist first by checking that the build succeeds.

- [ ] **Step 5: Remove unused imports**

After deleting the call sites, remove any now-unused imports in `ipv4.rs` and `ipv6.rs`. The `EthernetFrame` import in `ipv4.rs` is still used at line 99 (`EthernetFrame::from_bytes` for MAC extraction in protocol dispatch) — keep it. In `ipv6.rs`, `EthernetFrame` is still used at line 180 as `size_of::<EthernetFrame>()` — keep the import. The `IpAddress` import and `crate::net::wire::ip::IpAddress` usage may become unused — check.

- [ ] **Step 6: Run tests**

```bash
cargo test
```

Expected: Some tests will fail.

- `handler.rs` line ~750 (`lookup_or_resolve_learn_from_traffic_refreshes_entry`) — tests `learn_from_traffic` directly. **Delete this test.**
- `handler.rs` lines ~697, ~720, ~788 — these test `lookup_or_resolve` and `evict_stale` but USE `learn_from_traffic` to seed the cache. **Replace their `learn_from_traffic` calls with `handle_arp` using crafted ARP replies**, same as the TCP test fix. Do NOT delete these tests — they provide valid coverage for lookup/eviction behavior.

- [ ] **Step 7: Commit**

```bash
git add src/net/handler/ipv4.rs src/net/handler/ipv6.rs src/net/neighbor/handler.rs src/net/handler/tcp/tests/mod.rs
git commit -m "perf(net): Remove learn_from_traffic from hot path

Eliminates per-packet DashMap::insert in IPv4/IPv6 handlers.
ARP/NDP resolution handles neighbor discovery; traffic-based
learning was redundant for CDN workloads."
```

---

### Task 2: PmtuCache DashMap → FxHashMap

**Files:**
- Modify: `src/net/pmtu.rs`
- Modify: `src/rt/local.rs:224,265,306`
- Modify: `src/net/handler/ethernet.rs:23`
- Modify: `src/net/handler/ipv4.rs:51`
- Modify: `src/net/handler/ipv6.rs:161`
- Modify: `src/net/handler/icmpv4.rs:29`
- Modify: `src/net/handler/icmpv6.rs:39`
- Modify: `src/rt/context.rs` (RuntimeContext struct)

**Why:** PmtuCache uses DashMap for thread-safe access, but LocalRuntime is single-threaded. FxHashMap eliminates sharding/locking overhead.

- [ ] **Step 1: Swap DashMap to FxHashMap in pmtu.rs**

In `src/net/pmtu.rs`:

1. Replace `use dashmap::DashMap;` with `use rustc_hash::FxHashMap;`
2. Change the `table` field from `DashMap<IpAddress, (u32, Instant)>` to `FxHashMap<IpAddress, (u32, Instant)>`
3. Change `DashMap::new()` to `FxHashMap::default()` in `new()`, `with_mtu()`, `with_mtu_and_ttl()`
4. Change `update(&self, ...)` to `update(&mut self, ...)`
5. In `update`: `self.table.insert(addr, (mtu.max(min), now));` — stays the same
6. Change `get(&self, ...)` to `get(&self, ...)` — keeps `&self` since FxHashMap::get takes `&self`
7. In `get`: change `.and_then(|entry| { let (mtu, inserted_at) = *entry.value(); ... })` to `.and_then(|&(mtu, inserted_at)| { ... })` since FxHashMap returns `Option<&V>` not `Ref<K, V>`
8. Change `evict_stale(&self, ...)` to `evict_stale(&mut self, ...)`

- [ ] **Step 2: Run tests in pmtu.rs**

```bash
cargo test pmtu
```

Expected: Tests may fail if they rely on `&self` methods that now require `&mut self`. Fix any test compilation errors.

- [ ] **Step 3: Update PmtuCache wrapping in local.rs**

In `src/rt/local.rs`, the `pmtu` field is `Rc<PmtuCache>`. Since `update` and `evict_stale` now need `&mut self`, wrap it like UdpHandler/TcpHandler:

1. Change `pmtu: Rc<PmtuCache>` to `pmtu: Rc<UnsafeCell<PmtuCache>>` in the `LocalRuntime` struct (line ~176)
2. Change construction at line ~224: `Rc::new(PmtuCache::with_mtu(mtu))` → `Rc::new(UnsafeCell::new(PmtuCache::with_mtu(mtu)))`
3. Add `use std::cell::UnsafeCell;` if not already imported

- [ ] **Step 4: Update RuntimeContext**

In `src/rt/context.rs`, the `RuntimeContext` struct has a `pmtu` field. Update its type from `Rc<PmtuCache>` to `Rc<UnsafeCell<PmtuCache>>` and update the construction in `local.rs` where `RuntimeContext` is built.

- [ ] **Step 5: Update handler signatures**

Change `pmtu: &PmtuCache` to `pmtu: &mut PmtuCache` in these function signatures:
- `src/net/handler/ethernet.rs:23` — `EthernetHandler::handle()`
- `src/net/handler/ipv4.rs:51` — `Ipv4Handler::handle()`
- `src/net/handler/ipv6.rs:161` — `Ipv6Handler::handle()`
- `src/net/handler/icmpv4.rs:29` — `handle_icmpv4()`
- `src/net/handler/icmpv6.rs:39` — `handle_icmpv6()`

Note: `send_destination_unreachable` (icmpv4.rs:127) and `send_icmpv6_error` (icmpv6.rs:156) do NOT take pmtu — no change needed.

- [ ] **Step 6: Update call sites in the run loop**

In `src/rt/local.rs`, the `run()` method passes `&self.pmtu` to `ethernet_handler.handle()`. Change to dereference through UnsafeCell:

```rust
let pmtu = unsafe { &mut *self.pmtu.get() };
```

Pass `pmtu` to `ethernet_handler.handle()`. Note: the existing destructuring block at lines 303-310 includes `pmtu` — remove `pmtu` from that destructure and access it separately via `UnsafeCell::get()` before the loop body.

Also update the `evict_stale` call at line ~378:

```rust
let pmtu = unsafe { &mut *self.pmtu.get() };
pmtu.evict_stale(now);
```

- [ ] **Step 7: Fix tests and unused imports**

Update all test files that construct `PmtuCache` directly — these should still work since `PmtuCache::new()` returns an owned value. Fix any test compilation errors from the `&self` → `&mut self` change.

Remove `dashmap` from `Cargo.toml` if no other crate uses it — check `NeighborHandler` still uses it (it does), so keep the dependency.

- [ ] **Step 8: Run full test suite**

```bash
cargo test
```

Expected: All tests pass.

- [ ] **Step 9: Commit**

```bash
git add src/net/pmtu.rs src/rt/local.rs src/rt/context.rs src/net/handler/ethernet.rs src/net/handler/ipv4.rs src/net/handler/ipv6.rs src/net/handler/icmpv4.rs src/net/handler/icmpv6.rs
git commit -m "perf(net::pmtu): Swap PmtuCache from DashMap to FxHashMap

LocalRuntime is single-threaded; DashMap's sharding and lock
overhead was unnecessary. Uses UnsafeCell wrapper matching the
existing pattern for UdpHandler/TcpHandler."
```

---

### Task 3: Capacity-Wakes Guard Fix

**Files:**
- Modify: `src/rt/local.rs:382-421`

**Why:** The `expected_size > 0` guard fires almost every iteration because it's computed before frame recycling. Replace with a check on whether `free_frames` actually grew.

- [ ] **Step 1: Read the current run loop code**

Read `src/rt/local.rs` lines 380-430 to see the current state (may have shifted after Task 2 changes).

- [ ] **Step 2: Add free_before capture**

Before the `// ---- Transmit & Frame Recycling ----` comment, add:

```rust
let free_before = self.free_frames.num_frames();
```

- [ ] **Step 3: Replace the capacity-wakes guard condition**

Change the guard from:

```rust
if expected_size > 0 {
```

To:

```rust
if self.free_frames.num_frames() > free_before {
```

Keep the body unchanged — `main_waker.set_woken()` and the capacity wakers drain.

- [ ] **Step 4: Run tests**

```bash
cargo test
```

Expected: All tests pass. The debug_assert at line ~425 (`debug_assert_eq!(self.free_frames.num_frames(), expected_free_frames)`) still works since `expected_free_frames` is captured earlier and is independent.

- [ ] **Step 5: Commit**

```bash
git add src/rt/local.rs
git commit -m "perf(rt): Fix capacity-wakes guard to check actual free_frames growth

The previous expected_size > 0 check fired almost every iteration
because it was captured before frame recycling. Now only wakes
capacity-blocked futures when free_frames actually grew."
```

---

## Chunk 2: TCP Connection Table — Vec<Tcb> → FxHashMap<ConnectionId, Tcb>

This is the most invasive change. It touches handler.rs, inbound.rs, transmit.rs, timers.rs, connection.rs, listener.rs, socket/tcp.rs, and all TCP test files.

The approach: change the data structure first, then fix compilation errors systematically file by file.

---

### Task 4: TCP Connection Table Refactoring

**Files:**
- Modify: `src/net/handler/tcp/handler.rs` — struct + public API
- Modify: `src/net/handler/tcp/inbound.rs` — process_segment + 4 state handlers
- Modify: `src/net/handler/tcp/transmit.rs` — poll_send
- Modify: `src/net/handler/tcp/timers.rs` — poll_timers, evict_stale
- Modify: `src/net/handler/tcp/connection.rs` — connect, initiate_close
- Modify: `src/net/handler/tcp/listener.rs` — unlisten, decrement_syn_received
- Modify: `src/net/socket/tcp.rs` — TcpStream cached_idx removal
- Modify: `src/net/handler/tcp/tests/*.rs` — all test files (~439 index references)

**Why:** `Vec<Tcb>` with linear scan is O(n) per inbound TCP segment. For a CDN with thousands of connections, this is the single biggest bottleneck. `FxHashMap<ConnectionId, Tcb>` gives O(1) lookup.

- [ ] **Step 1: Change the connections field type in handler.rs**

In `src/net/handler/tcp/handler.rs`:

1. Add import: `use rustc_hash::FxHashMap;`
2. Change field: `pub(super) connections: Vec<Tcb>` → `pub(super) connections: FxHashMap<ConnectionId, Tcb>`
3. Change constructor: `connections: Vec::new()` → `connections: FxHashMap::default()`
4. Delete `find_connection_idx` (line 55-57)
5. Delete `get_connection_by_idx_mut` (lines 63-80)
6. Simplify `get_connection`:
```rust
pub fn get_connection(&self, id: &ConnectionId) -> Option<&Tcb> {
    self.connections.get(id)
}
```
7. Simplify `get_connection_mut`:
```rust
pub fn get_connection_mut(&mut self, id: &ConnectionId) -> Option<&mut Tcb> {
    self.connections.get_mut(id)
}
```
8. Simplify `remove_connection` — replace `iter().position()` + `self.connections.remove(idx)` with `self.connections.remove(id)`. Extract needed data before removing to avoid borrow conflicts:
```rust
pub fn remove_connection<'umem>(
    &mut self,
    id: &ConnectionId,
    src_mac: MacAddress,
    dst_mac: MacAddress,
    free_frames: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) {
    // Extract what we need before removing (avoids borrow conflict).
    let should_rst = self.connections.get(id).map(|tcb| {
        let needs_rst = tcb.state.is_synchronized() || tcb.state == TcpState::SynReceived;
        (needs_rst, tcb.snd_nxt)
    });
    if let Some((true, snd_nxt)) = should_rst {
        SegmentBuilder::build_rst(
            id.local_addr, id.remote_addr,
            id.local_port, id.remote_port,
            0, snd_nxt, flags::ACK, 0,
            src_mac, dst_mac,
            self.tx_offload,
            free_frames, tx_return,
        );
    }
    self.connections.remove(id);
}
```

Do NOT try to compile yet — inbound.rs will have many errors.

- [ ] **Step 2: Update socket/tcp.rs — remove cached_idx**

In `src/net/socket/tcp.rs`:

1. Remove the `cached_idx: Cell<usize>` field from `TcpStream`
2. In `from_accepted` (line 283): remove `find_connection_idx` call and `cached_idx` field
3. In `from_accepted_for_test`: remove `cached_idx` field
4. In `TcpWrite::poll` (line 539-556): replace `get_connection_by_idx_mut(idx, &this.conn_id)` with `handler.get_connection_mut(&this.conn_id)`. Remove `this.cached_idx.set(new_idx)`.
5. In `TcpRead::poll` (line 583-600): same pattern — replace with `handler.get_connection_mut(&this.conn_id)`
6. In `TcpSplice::poll` (line 627-644): same pattern
7. In `Connect::poll` (line ~488): uses `find_connection_idx` to populate `cached_idx` on connection completion — replace with direct `get_connection_mut` lookup
8. Remove `cached_idx` from `TcpRead`, `TcpWrite`, `TcpSplice`, `TcpStream` struct definitions
9. In `initiate_close` and any other methods that use `find_connection_idx` — use `get_connection_mut` directly

- [ ] **Step 3: Update connection.rs**

In `src/net/handler/tcp/connection.rs`:

1. `connect_with_config` (line ~75): change the duplicate check from `self.connections.iter().any(|c| c.id == id)` to `self.connections.contains_key(&id)`
2. `connect_with_config` (line 172): change `self.connections.push(tcb)` to `self.connections.insert(tcb.id, tcb)`
3. `initiate_close` (line 178): change `iter_mut().find()` to `self.connections.get_mut(id)`. Note the method signature already takes `ConnectionId`.

- [ ] **Step 4: Update transmit.rs**

In `src/net/handler/tcp/transmit.rs`:

1. `poll_send` (line 29): `for tcb in &mut self.connections` → `for (_id, tcb) in &mut self.connections`
2. Line 364: `self.connections.retain(|tcb| tcb.state != TcpState::Closed)` → `self.connections.retain(|_id, tcb| tcb.state != TcpState::Closed)`

- [ ] **Step 5: Update timers.rs**

In `src/net/handler/tcp/timers.rs`:

1. **Delayed ACK pass** (line 30): `for tcb in &mut self.connections` → `for (_id, tcb) in &mut self.connections`
2. **Keep-alive pass** (lines 83-160): Currently uses `enumerate()` to collect indices for deferred removal. Change to collect `ConnectionId`s into a `Vec<ConnectionId>` (this is the cold eviction path — Vec allocation is fine):
   - Replace `let mut keep_alive_removals = [0usize; 64]` with `let mut keep_alive_removals: Vec<ConnectionId> = Vec::new()`
   - Remove `keep_alive_removal_count` counter — use `Vec::push` and `Vec::len` instead
   - Change the removal loop from `self.connections.remove(idx)` to `self.connections.remove(&id)`
   - Remove the reverse-iteration pattern — HashMap removal is O(1) and order-independent
3. **Retransmit pass** (lines 163-430): Same pattern — collect `ConnectionId`s into a Vec for deferred removal
4. **evict_stale** (line 434): `self.connections.retain(|tcb| ...)` → `self.connections.retain(|_id, tcb| ...)`
5. `decrement_syn_received` calls already take `&ConnectionId` — these stay the same

- [ ] **Step 6: Update listener.rs**

In `src/net/handler/tcp/listener.rs`:

1. `unlisten` (line 88): `self.connections.retain(|tcb| ...)` → `self.connections.retain(|_id, tcb| ...)`

- [ ] **Step 7: Update inbound.rs — process_segment dispatch**

This is the biggest change. In `src/net/handler/tcp/inbound.rs`:

**Main dispatch (lines 280-379):** Replace the `iter().position()` lookup with `get_mut()`:

```rust
// Before:
if let Some(idx) = self.connections.iter().position(|c| c.id == conn_id) {
    let state = self.connections[idx].state;
    match state {
        TcpState::SynSent => self.process_syn_sent(idx, ...),
        ...
    }
}

// After — destructure for split borrows:
let Self { connections, listeners, isn_generator, tx_offload, rx_offload, .. } = self;
if let Some(tcb) = connections.get_mut(&conn_id) {
    let state = tcb.state;
    match state {
        TcpState::SynSent => {
            Self::process_syn_sent(tcb, listeners, *tx_offload, ...);
            rx_return.push(frame);
        }
        TcpState::Established => {
            Self::process_established(tcb, listeners, *tx_offload, *rx_offload, ...);
        }
        // ... other states
    }
} else {
    // Check listeners for SYN
    Self::process_listen(connections, listeners, isn_generator, *tx_offload, *rx_offload, ...);
}
```

- [ ] **Step 8: Update inbound.rs — convert state handler functions**

Each of the 4 state handlers (`process_syn_sent`, `process_syn_received`, `process_established`, `process_teardown`) must change from `&mut self` methods to associated functions that take individual fields:

**Signature pattern:**
```rust
// Before:
fn process_established(&mut self, idx: usize, ...) {
    let tcb = &mut self.connections[idx];
    // uses self.tx_offload, self.listeners, etc.
}

// After:
fn process_established(
    tcb: &mut Tcb,
    listeners: &mut Vec<listener::ListenEntry>,
    tx_offload: bool,
    // ... other needed fields
    ...
) {
    // All self.connections[idx] references become just `tcb`
    // All self.tx_offload references become just `tx_offload`
}
```

For each handler, read the function body to determine which `self` fields it actually uses beyond `self.connections[idx]`. The exploration found:
- `self.tx_offload` — used in all handlers for SegmentBuilder calls
- `self.rx_offload` — used at entry points
- `self.listeners` — used in process_listen
- `self.isn_generator` — used in process_listen
- `self.connections` (for insertion/removal) — used in process_listen, some teardown paths

Where a handler needs to insert/remove connections (not just modify the current TCB), pass `connections: &mut FxHashMap<ConnectionId, Tcb>` as a parameter. This is needed for `process_listen` (creates new connections).

**Handlers that remove the current connection** (e.g., `process_syn_received` on RST, `process_teardown` on certain conditions): these cannot hold `&mut Tcb` and call `connections.remove()` simultaneously. Use a return-based pattern — have the handler return a `PostAction` enum indicating what to do after the borrow is released:

```rust
enum PostAction {
    None,
    RemoveConnection(ConnectionId),
}
```

The caller in `process_segment` matches on the return and performs removal after the `tcb` borrow ends:

```rust
let action = if let Some(tcb) = connections.get_mut(&conn_id) {
    match tcb.state {
        TcpState::SynReceived => Self::process_syn_received(tcb, listeners, ...),
        // ...
    }
} else { PostAction::None };

match action {
    PostAction::RemoveConnection(id) => {
        Self::decrement_syn_received(listeners, &id);
        connections.remove(&id);
    }
    PostAction::None => {}
}
```

**For `decrement_syn_received`:** This accesses `self.listeners`. Make it an associated function `Self::decrement_syn_received(listeners: &mut Vec<ListenEntry>, id: &ConnectionId)` so it can be called after the `tcb` borrow is released.

- [ ] **Step 9: Fix all remaining self.connections[idx] references**

After converting the handler functions, systematically replace every remaining `self.connections[idx]` reference with `tcb` (the direct reference). There are ~74 such references in inbound.rs alone.

This is mechanical — every `self.connections[idx].field` becomes `tcb.field` and every `self.connections[idx].method()` becomes `tcb.method()`.

- [ ] **Step 10: Compile check**

```bash
cargo check
```

Fix all compilation errors. Common issues:
- Missing imports for `FxHashMap`
- Borrow checker errors where `&mut connections` and `&mut listeners` overlap — use destructuring
- `retain` closure signature changes
- Places where code removes the current connection mid-processing — need to restructure to remove after the borrow is released

- [ ] **Step 11: Update TCP test files**

All test files in `src/net/handler/tcp/tests/` use `handler.connections[0]` to access the first connection. With FxHashMap, replace these with:

```rust
// Before:
assert_eq!(handler.connections[0].state, TcpState::Established);

// After:
let tcb = handler.connections.values().next().unwrap();
assert_eq!(tcb.state, TcpState::Established);

// Or for mutable access:
let tcb = handler.connections.values_mut().next().unwrap();
```

For tests that reference a specific connection by ID:
```rust
let tcb = handler.connections.get(&conn_id).unwrap();
```

Consider adding a test helper:
```rust
#[cfg(test)]
impl TcpHandler {
    pub fn first_connection(&self) -> &Tcb {
        self.connections.values().next().unwrap()
    }
    pub fn first_connection_mut(&mut self) -> &mut Tcb {
        self.connections.values_mut().next().unwrap()
    }
}
```

There are ~439 index references across 13 test files. Most are `handler.connections[0]` which all convert to the helper.

- [ ] **Step 12: Run full test suite**

```bash
cargo test
```

Expected: All tests pass.

- [ ] **Step 13: Commit**

```bash
git add src/net/handler/tcp/ src/net/socket/tcp.rs
git commit -m "perf(net::tcp): Replace Vec<Tcb> with FxHashMap for O(1) connection lookup

TCP connection lookup was O(n) linear scan per inbound segment.
With FxHashMap<ConnectionId, Tcb>, lookup is O(1). Sub-handlers
now take &mut Tcb directly via split-borrow pattern instead of
re-indexing through self.connections."
```

---

## Chunk 3: poll_send Active-Connection Tracking

This depends on Task 4 (FxHashMap connection table) being complete.

---

### Task 5: SendTracker with #[must_use] Enforcement

**Files:**
- Create: `src/net/handler/tcp/send_tracker.rs`
- Modify: `src/net/handler/tcp/mod.rs` — add module
- Modify: `src/net/handler/tcp/tcb.rs` — SendReady type, modified setter methods
- Modify: `src/net/handler/tcp/handler.rs` — add SendTracker field
- Modify: `src/net/handler/tcp/transmit.rs` — poll_send iterates tracker
- Modify: `src/net/handler/tcp/inbound.rs` — consume SendReady from mutations
- Modify: `src/net/handler/tcp/timers.rs` — timer-driven sends mark tracker

**Why:** poll_send iterates all connections every tick. With a SendTracker, it only visits connections with pending work. The #[must_use] SendReady type makes forgetting to register a compile error.

- [ ] **Step 1: Create SendReady type and SendTracker**

Create `src/net/handler/tcp/send_tracker.rs`:

```rust
use rustc_hash::FxHashSet;
use super::tcb::ConnectionId;

/// Marker returned by Tcb methods that make a connection sendable.
/// Must be consumed by passing to `SendTracker::mark()`.
#[must_use = "connection must be marked for sending via SendTracker::mark()"]
pub struct SendReady(pub ConnectionId);

/// Tracks which connections have pending send work.
/// poll_send iterates only this set instead of all connections.
pub struct SendTracker {
    set: FxHashSet<ConnectionId>,
}

impl SendTracker {
    pub fn new() -> Self {
        Self {
            set: FxHashSet::default(),
        }
    }

    /// Register a connection as needing send processing.
    #[inline(always)]
    pub fn mark(&mut self, ready: SendReady) {
        self.set.insert(ready.0);
    }

    /// Remove a connection from the active set.
    #[inline(always)]
    pub fn unmark(&mut self, id: &ConnectionId) {
        self.set.remove(id);
    }

    /// Drain all tracked connection IDs for processing.
    /// Returns an iterator of ConnectionIds that need poll_send attention.
    #[inline(always)]
    pub fn drain(&mut self) -> impl Iterator<Item = ConnectionId> + '_ {
        self.set.drain()
    }

    /// Check if any connections need sending.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}
```

- [ ] **Step 2: Add module declaration**

In `src/net/handler/tcp/mod.rs`, add:
```rust
pub(crate) mod send_tracker;
```

- [ ] **Step 3: Add #[deny(unused_must_use)] to the TCP module**

Rust's default behavior already emits a warning for unused `#[must_use]` values. Since this project uses `cargo test` which shows warnings, unused `SendReady` values will be caught. If stricter enforcement is desired, add `#[deny(unused_must_use)]` to the crate root in `src/lib.rs` — this is the standard location for crate-wide lint settings. Do NOT use `#![deny(...)]` in a non-root module as it is invalid syntax.

- [ ] **Step 4: Add SendTracker to TcpHandler**

In `src/net/handler/tcp/handler.rs`:

```rust
use super::send_tracker::SendTracker;

pub struct TcpHandler {
    pub(super) connections: FxHashMap<ConnectionId, Tcb>,
    pub(super) listeners: Vec<listener::ListenEntry>,
    pub(super) isn_generator: IsnGenerator,
    pub(super) send_tracker: SendTracker,  // NEW
    pub(super) rx_offload: bool,
    pub(super) tx_offload: bool,
}
```

Initialize in `new()`: `send_tracker: SendTracker::new()`

- [ ] **Step 5: Identify all Tcb mutation sites that trigger sendability**

Read through inbound.rs, timers.rs, and connection.rs to find every place that:
- Writes to `tcb.send_buffer`
- Sets `tcb.ack_pending = true`
- Sets `tcb.pending_fin = true`
- Modifies `tcb.snd_wnd` (window update)
- Sets/clears ECN state (`tcb.ecn_ce_received`, `tcb.ecn_cwr_sent`)
- Fires retransmit/persist timers

At each site, the code must either:
- Call a Tcb method that returns `SendReady`, then pass it to `send_tracker.mark()`
- Or directly construct `SendReady(tcb.id)` and mark it

Use a hybrid approach: create Tcb setter methods that return `SendReady` for the most commonly mutated fields (these provide type-system enforcement), and use explicit `send_tracker.mark(SendReady(tcb.id))` for less common paths (timer fires, ECN changes).

Key Tcb methods to add:

```rust
impl Tcb {
    pub fn mark_ack_pending(&mut self) -> SendReady {
        self.ack_pending = true;
        SendReady(self.id)
    }

    pub fn set_pending_fin(&mut self) -> SendReady {
        self.pending_fin = true;
        SendReady(self.id)
    }

    pub fn update_send_window(&mut self, wnd: u32) -> Option<SendReady> {
        let old = self.snd_wnd;
        self.snd_wnd = wnd;
        // Only signal if window opened from zero
        if old == 0 && wnd > 0 {
            Some(SendReady(self.id))
        } else {
            None
        }
    }
}
```

For timer-driven events (retransmit, persist, delayed ACK deadline), add `send_tracker.mark(SendReady(tcb.id))` explicitly at each timer fire site.

- [ ] **Step 6: Update poll_send to iterate SendTracker**

In `src/net/handler/tcp/transmit.rs`, change `poll_send`:

```rust
// Before:
for (_id, tcb) in &mut self.connections {
    if tcb.state != TcpState::Established && tcb.state != TcpState::CloseWait {
        continue;
    }
    // ... send logic
}

// After:
let ids: Vec<ConnectionId> = self.send_tracker.drain().collect();
for id in ids {
    let Some(tcb) = self.connections.get_mut(&id) else {
        continue; // connection was removed
    };
    if tcb.state != TcpState::Established && tcb.state != TcpState::CloseWait {
        continue;
    }
    // ... send logic (same as before)

    // Re-add to tracker if still has work
    let has_work = tcb.send_buffer.available() > 0
        || tcb.ack_pending
        || tcb.pending_fin
        || tcb.persist_deadline.is_some()
        || tcb.retransmit_deadline.is_some();
    if has_work {
        self.send_tracker.mark(SendReady(id));
    }
}
```

The `retain` at the end stays but only runs on the full connection map (it's for cleanup, not sending).

- [ ] **Step 7: Update inbound.rs to mark SendReady**

In each state handler, after any mutation that triggers sendability, add:

```rust
send_tracker.mark(SendReady(tcb.id));
```

Pass `send_tracker: &mut SendTracker` as an additional parameter to the state handler functions. This follows the same split-borrow pattern established in Task 4.

- [ ] **Step 8: Update timers.rs to mark SendReady**

Timer-driven sends (delayed ACK, retransmit, keep-alive probe) must mark the connection:

```rust
// After any timer fires that produces outbound data:
self.send_tracker.mark(SendReady(tcb.id));
```

- [ ] **Step 9: Run tests**

```bash
cargo test
```

Expected: All tests pass. If `#[deny(unused_must_use)]` catches any unhandled `SendReady` values, those are bugs to fix — the whole point of the design.

- [ ] **Step 10: Commit**

```bash
git add src/net/handler/tcp/
git commit -m "perf(net::tcp): Add SendTracker for active-connection tracking in poll_send

poll_send now iterates only connections with pending work instead of
all connections. SendReady marker type with #[must_use] provides
compile-time enforcement that sendability-triggering mutations are
registered with the tracker."
```
