# Net Stack Performance Optimization Design — VoidNet

**Date:** 2026-03-15
**Approach:** Targeted hot-path optimization (Approach A)
**Target:** CDN/HTTP server workloads with high connection counts

## Goals

Eliminate per-packet and per-loop-iteration bottlenecks identified through a
systematic bottom-to-top audit of the `LocalRuntime` run loop and the
`src/net/` protocol handlers. Focus on data structure changes that reduce
algorithmic complexity in the hottest code paths.

## Non-Goals

- NeighborHandler DashMap swap (deferred — low hot-path usage without `learn_from_traffic`)
- Ring batch/two-pass descriptor optimizations (needs benchmarking data first)
- `nb_avail` `== 0` vs `< batch_size` tuning (needs benchmarking data first)
- Multi-threaded runtime changes (all changes target `LocalRuntime` single-threaded context)

---

## 1. TCP Connection Table — Vec\<Tcb\> → FxHashMap\<ConnectionId, Tcb\>

### Problem

`TcpHandler::connections` is a `Vec<Tcb>`. Every inbound TCP segment does a
linear scan via `self.connections.iter().position(|c| c.id == conn_id)`
(inbound.rs:280). For a CDN with thousands of concurrent connections, this is
O(n) per packet. Additionally:

- `poll_send` iterates all connections every loop tick
- `get_connection_mut` / `find_connection_idx` are all linear scans
- `connections.remove(idx)` shifts the Vec tail — O(n)

### Design

Replace `connections: Vec<Tcb>` with `connections: FxHashMap<ConnectionId, Tcb>`.

**Lookup:** `process_segment` hashes `ConnectionId` once at entry, calls
`self.connections.get_mut(&conn_id)` — O(1).

**Split-borrow pattern:** Sub-handler functions (`process_established`,
`process_syn_sent`, etc.) currently take `idx: usize` and re-index into
`self.connections`. These change to take `&mut Tcb` directly as a parameter.
Functions that also need other `TcpHandler` fields (e.g., `listeners`,
`isn_generator`) become associated functions that take the specific fields:

```rust
// Before
self.process_established(idx, ...);

// After — destructure self for disjoint borrows
let Self { connections, listeners, isn_generator, .. } = self;
let tcb = connections.get_mut(&conn_id).unwrap();
Self::process_established(tcb, listeners, ...);
```

Destructuring `self` into its fields is required so the borrow checker can
see that `&mut connections` and `&mut listeners` are disjoint borrows. Taking
`&mut self` and then borrowing two fields through it will not compile.

**Connection insertion/removal:** SYN processing that creates new TCBs still
uses `&mut self.connections` directly. `remove_connection` becomes
`.remove(&conn_id)` — O(1) instead of position scan + Vec shift.

**Retain:** `HashMap::retain` takes `FnMut(&K, &mut V) -> bool` vs
`Vec::retain`'s `FnMut(&T) -> bool`. All `retain` closures change from
`|tcb| ...` to `|_id, tcb| ...` — mechanical but must be updated at every
call site (transmit.rs:364, timers.rs:434).

**`get_connection_by_idx_mut`:** Deleted entirely — it was a cached-index
optimization to work around linear scan cost. No longer needed.

### Location

- `src/net/handler/tcp/handler.rs` — struct definition, `get_connection*`, `remove_connection`
- `src/net/handler/tcp/inbound.rs` — `process_segment` and all sub-handlers
- `src/net/handler/tcp/transmit.rs` — `poll_send` iteration
- `src/net/handler/tcp/timers.rs` — `poll_timers`, `evict_stale`

### Risk

There are ~70+ references to `self.connections[idx]` in inbound.rs alone,
plus additional sites in transmit.rs and timers.rs. All must be converted to
the split-borrow pattern. This is the most invasive change but also the
highest-impact one for CDN workloads.

**Cross-field dependency:** Several removal paths call
`self.decrement_syn_received(&id)` before removing a connection (e.g.,
inbound.rs, timers.rs). This method accesses `self.listeners`, so these
sites need careful destructuring when the code also holds a mutable borrow
on `self.connections`.

---

## 2. PmtuCache — DashMap → FxHashMap

### Problem

`PmtuCache` uses `DashMap<IpAddress, (u32, Instant)>` for thread-safe
concurrent access. `LocalRuntime` is single-threaded, so the sharding and
lock overhead is pure waste on every `get`, `insert`, and `retain` call.

### Design

Replace `DashMap` with `FxHashMap` from the `rustc_hash` crate (already a
dependency — used by `FragmentReader`).

The API surface is small and self-contained in `pmtu.rs`:
- `insert` → `insert`
- `get` → `get` (returns `Option<&V>` instead of `Ref<K, V>`)
- `retain` → `retain`

Methods that currently take `&self` and rely on DashMap interior mutability
will change to `&mut self`. The `PmtuCache` is behind `Rc` in LocalRuntime —
this requires matching the existing `Rc<UnsafeCell<...>>` pattern used by
`UdpHandler`/`TcpHandler` (preferred over `RefCell` to avoid runtime borrow
checking overhead in the hot path).

**Downstream call sites:** `PmtuCache` is passed as `&PmtuCache` into
`Ipv4Handler::handle`, `Ipv6Handler::handle`, and through to ICMP handlers.
These signatures will need to accept the `UnsafeCell`-wrapped type or take
`&mut PmtuCache` after unwrapping at the call site in the run loop.

### Location

- `src/net/pmtu.rs` — full implementation
- `src/net/handler/ipv4.rs` — `handle()` signature
- `src/net/handler/ipv6.rs` — `handle()` signature
- `src/net/handler/icmpv4.rs` — PMTU update from Fragmentation Needed
- `src/net/handler/icmpv6.rs` — PMTU update from Packet Too Big
- `src/rt/local.rs` — `Rc<PmtuCache>` → `Rc<UnsafeCell<PmtuCache>>`

---

## 3. Remove learn_from_traffic

### Problem

`NeighborHandler::learn_from_traffic` is called on every valid incoming IPv4
and IPv6 packet (ipv4.rs:100, ipv6.rs:189). It performs a `DashMap::insert`
on every packet, updating the source IP → MAC mapping. This is a per-packet
hash + insert in the hot path.

### Design

Delete the two call sites:
- `src/net/handler/ipv4.rs:99-104` — remove the `EthernetFrame::from_bytes` +
  `learn_from_traffic` block and preceding comment (lines 96-104)
- `src/net/handler/ipv6.rs:188-193` — same

ARP/NDP resolution already handles neighbor discovery. The only scenario
where `learn_from_traffic` adds value is if a neighbor's MAC changes without
an ARP/NDP exchange (e.g., NIC failover). For a CDN behind known
infrastructure, this is not a concern.

### Location

- `src/net/handler/ipv4.rs`
- `src/net/handler/ipv6.rs`
- `src/net/neighbor/handler.rs` — `learn_from_traffic` method can be removed
  if no other callers exist
- TCP test files that call `learn_from_traffic` will also need updating

---

## 4. poll_send Active-Connection Tracking

### Problem

`TcpHandler::poll_send` iterates every connection in the connection table on
every loop iteration. Most established connections in a CDN workload are idle
(waiting for the next request, no pending data). With thousands of
connections, this is wasted iteration.

### Design

Introduce a `SendTracker` backed by `FxHashSet<ConnectionId>` that tracks
which connections have pending send work. `poll_send` iterates only this set.

**Compile-time enforcement via `#[must_use]`:**

Any `Tcb` method that makes a connection sendable returns a marker type:

```rust
#[must_use = "connection must be marked for sending"]
pub struct SendReady(pub ConnectionId);

impl Tcb {
    pub fn write_to_send_buffer(&mut self, data: &[u8]) -> SendReady {
        self.send_buffer.write(data);
        SendReady(self.id)
    }

    pub fn set_ack_pending(&mut self) -> SendReady {
        self.ack_pending = true;
        SendReady(self.id)
    }
}
```

The caller must consume `SendReady` by passing it to the tracker:

```rust
impl SendTracker {
    #[inline(always)]
    pub fn mark(&mut self, ready: SendReady) {
        self.set.insert(ready.0);
    }
}
```

With `#[deny(unused_must_use)]` on the TCP module, forgetting to register a
sendable connection becomes a compile error.

**Send-triggering events:**
- Data written to send buffer
- `ack_pending` set to true
- Retransmit or persist timer fires
- ECN state changes
- FIN pending
- Window update (peer advertises larger window after zero-window state)

**poll_send coverage:** The current `poll_send` handles data transmission,
delayed ACK flush, persist timer probes, linger deadline RST, and FIN
transmission. All of these paths must go through the `SendTracker` — a
connection is added to the set when any of these conditions become true, and
`poll_send` processes all of them for tracked connections only.

**Removal from set:** `poll_send` removes the connection ID from the set
after processing if no further work remains (empty send buffer, no pending
ACK, no pending FIN, no active persist/retransmit timer).

### Location

- `src/net/handler/tcp/tcb.rs` — `SendReady` type, modified Tcb methods
- `src/net/handler/tcp/handler.rs` — `SendTracker` field
- `src/net/handler/tcp/transmit.rs` — `poll_send` iterates tracker set
- `src/net/handler/tcp/inbound.rs` — consume `SendReady` from Tcb mutations
- `src/net/handler/tcp/timers.rs` — timer-driven sends mark tracker

---

## 5. Capacity-Wakes Guard Fix

### Problem

The capacity-driven wake check (local.rs:413) uses `expected_size > 0`, which
is captured *before* TX send and frame recycling. Since `rx_return` almost
always has frames from receive processing, this condition is almost always
true, causing spurious wakes of the main future and all capacity-blocked
futures every iteration.

### Design

Track whether `free_frames` actually grew during the recycling phase:

```rust
let free_before = self.free_frames.num_frames();

// ... TX send, completion drain, split to free_frames, fill queue ...

if self.free_frames.num_frames() > free_before {
    main_waker.set_woken();
    crate::rt::context::with_runtime_context(|ctx| {
        let wakers = unsafe { &mut *ctx.capacity_wakers.get() };
        for waker in wakers.drain(..) {
            waker.wake();
        }
    });
}
```

`free_frames` grows at L401-403 whenever `rx_return` has more frames than
`received`. This includes both TX completions (returned via the completion
queue) and frames recycled during protocol processing (validation failures,
consumed packets pushed to `rx_return` by handlers). This is still a much
tighter condition than `expected_size > 0` which fires on every iteration
that processes any frames at all. The `expected_size` variable is retained
for the completion queue drain loop (L391) and debug asserts (L425).

### Location

- `src/rt/local.rs` — run loop, lines 382-421

---

## Implementation Order

1. **Remove `learn_from_traffic`** — smallest change, immediate per-packet win
2. **PmtuCache DashMap → FxHashMap** — self-contained, low risk
3. **Capacity-wakes guard fix** — small, local change in the run loop
4. **TCP connection table Vec → FxHashMap** — most invasive, highest impact
5. **poll_send active-connection tracking** — depends on (4), adds compile-time safety

Steps 1-3 are independent and can be done in parallel. Steps 4-5 are
sequential — the SendTracker design depends on the FxHashMap connection table.
