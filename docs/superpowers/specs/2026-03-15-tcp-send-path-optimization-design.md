# TCP Send Path Optimization Design

## Problem

Profiling the HTTP server benchmark (5000 long-lived connections, 14-byte responses, ~36K samples) reveals that HashMap operations consume ~12.2% of CPU and the TCP send path consumes ~9.1%. The root cause: every `write_to_send_buffer` and `poll_send` call hashes a `ConnectionId` 4-tuple (local/remote addr+port) via `FxHashMap`. With stable long-lived connections, this hashing is pure overhead.

Secondary issues in the send path include SmallVec stack overflow to heap, redundant connection lookups within `poll_send`, and unnecessary intermediate buffer copies.

## Goals

- Eliminate hashing from the TCP send path entirely
- Reduce `poll_send` per-iteration overhead (redundant lookups, SmallVec overflow)
- Reduce memcpy overhead in segment construction pipeline
- All changes must be generally applicable, not benchmark-specific

## Non-Goals

- HTTP-layer optimizations (response fast path, parse improvements) — separate effort
- Async runtime overhead (FuturesUnordered, spawn allocations) — separate effort
- Multi-threaded runtime — out of scope

## Design

### Tier 1: Connection Lookup Overhaul

#### Current Architecture

```
TcpHandler {
    connections: FxHashMap<ConnectionId, Tcb>,
    send_tracker: SendTracker<ConnectionId>,
}

TcpStream {
    conn_id: ConnectionId,
    handler: Rc<UnsafeCell<TcpHandler>>,
}

TcpWrite/TcpRead {
    conn_id: ConnectionId,
    handler: &'stream Rc<UnsafeCell<TcpHandler>>,  // borrowed from TcpStream
}
```

Every operation (write, poll_send, process_segment) does `connections.get_mut(&conn_id)` which hashes the 4-tuple.

Additional types holding `ConnectionId`: `TcpSplice`, `Connect`, and `Accept` (receives `ConnectionId` from `accept_queue` in `ListenEntry`).

#### New Architecture

```
TcpHandler {
    connections: Slab<Tcb>,
    connection_map: FxHashMap<ConnectionId, usize>,
    send_tracker: SendTracker<usize>,
}

TcpStream {
    conn_key: usize,
    handler: Rc<UnsafeCell<TcpHandler>>,
}

TcpWrite/TcpRead {
    conn_key: usize,
    handler: &'stream Rc<UnsafeCell<TcpHandler>>,
}
```

- `Slab<Tcb>` — primary storage, O(1) index access, no hashing
- `FxHashMap<ConnectionId, usize>` — reverse lookup, only used on inbound packet path
- `TcpStream` holds `usize` slab key; `TcpWrite`/`TcpRead` copy it from `TcpStream`
- `TcpSplice`, `Connect` also updated to hold `usize` key
- `accept_queue` in `ListenEntry` delivers `usize` keys instead of `ConnectionId`

#### Connection Lifecycle

**Establishment:**
```rust
let tcb = Tcb::new(...);
let key = self.connections.insert(tcb);
self.connection_map.insert(conn_id, key);
// Return key to TcpWrite/TcpRead
```

**Teardown:**
```rust
let tcb = self.connections.remove(key);
self.connection_map.remove(&tcb.conn_id);
```

**Inbound packet path** (the only place we still hash):
```rust
// process_ipv6 / process_segment
let conn_id = ConnectionId::from_packet(&packet);
if let Some(&key) = self.connection_map.get(&conn_id) {
    let tcb = &mut self.connections[key];
    // process...
}
```

**Send path** (zero hashing):
```rust
// write_to_send_buffer
pub fn write_to_send_buffer(&mut self, key: usize, data: &[u8]) -> Option<usize> {
    let tcb = self.connections.get_mut(key)?;
    let n = tcb.send_buffer.write(data);
    if n > 0 {
        self.send_tracker.mark(key);
    }
    Some(n)
}
```

#### Dependency: `slab` crate

Add `slab = "0.4"` to dependencies. Battle-tested, used by tokio internally, minimal API surface.

#### Files Changed

- `src/net/handler/tcp/handler.rs` — `TcpHandler` struct: replace `FxHashMap<ConnectionId, Tcb>` with `Slab<Tcb>` + `FxHashMap<ConnectionId, usize>`; `write_to_send_buffer` takes `usize` key
- `src/net/handler/tcp/transmit.rs` — `poll_send`: iterate `usize` keys, index into slab
- `src/net/handler/tcp/inbound.rs` — `process_ipv4`/`process_ipv6`/`process_segment`: lookup via `connection_map` then index slab
- `src/net/handler/tcp/send_tracker.rs` — operate on `usize` instead of `SendReady(ConnectionId)`
- `src/net/handler/tcp/timers.rs` — `poll_timers`: iterate slab, collect `usize` keys for marking/removal instead of `ConnectionId`
- `src/net/handler/tcp/connection.rs` — `connect()`/`connect_with_config()`: insert into both slab and `connection_map`, return slab key; `initiate_close()`: accept slab key
- `src/net/handler/tcp/listener.rs` — `accept_queue: LocalQueue<usize>` instead of `LocalQueue<ConnectionId>`; `unlisten()` uses slab keys
- `src/net/handler/tcp/tcb.rs` — `Tcb` already stores `ConnectionId` (field `id`) for reverse-map cleanup on teardown
- `src/net/socket/tcp.rs` — `TcpStream`, `TcpWrite`, `TcpRead`, `TcpSplice`, `Connect`, `Accept`: store/consume `usize` key instead of `ConnectionId`

### Tier 2: Send Path Tightening

#### 2a: SmallVec Capacity for Active Connection Drain

**Current:** `SmallVec<[ConnectionId; 32]>` — `ConnectionId` is a large struct (two IP addrs + two ports), and 32 slots overflows with 5000 active connections.

**New:** `SmallVec<[usize; 128]>` — `usize` is 8 bytes, so 128 slots = 1KB stack. Handles typical active-per-tick counts without heap allocation. The switch from `ConnectionId` to `usize` (from tier 1) makes this natural.

**File:** `src/net/handler/tcp/transmit.rs`

#### 2b: Eliminate Redundant Lookups in `poll_send`

**Current:** `poll_send` does:
1. `self.connections.get_mut(&id)` at loop top
2. `self.connections.get(&id)` at loop bottom to check remaining work — this second lookup exists because `self.send_tracker.mark()` borrows `self` mutably, preventing the `&mut Tcb` from the first lookup from being held across it
3. `bytes_in_flight` is computed 4 times (lines 51, 222, 326, 382); the inner-loop recalculation is necessary since `snd_nxt` mutates, but the final recomputation at line 382 is avoidable

**New:**
1. Single `self.connections[key]` at loop top — slab indexing eliminates the borrow conflict because `self.connections` and `self.send_tracker` are separate fields that can be borrowed independently
2. Reuse the existing `&mut Tcb` reference for the bottom-of-loop check instead of a second lookup
3. Eliminate the final redundant `bytes_in_flight` computation

**File:** `src/net/handler/tcp/transmit.rs`

#### 2c: Reduce Intermediate Buffer Copies

**Current data flow for a 14-byte HTTP response:**
1. User calls `write_body(b"Hello, World!\n")` → writes to `WriteBuffer`
2. `WriteBuffer::flush()` → calls `stream.write()` → `TcpWrite::poll`
3. `TcpWrite::poll` → `write_to_send_buffer()` → copies into `Tcb::send_buffer`
4. `poll_send` → `send_buffer.peek_slices()` → `SegmentBuilder::build_data_from_slices()` → copies into XDP frame

Steps 1-3 involve at least two `memcpy` operations before data reaches the send buffer. Investigation needed to determine if `WriteBuffer` can be bypassed for small writes, writing directly to the TCP send buffer. If `WriteBuffer` serves as a coalescing buffer for multiple small writes (headers, body), it may still be needed but could be optimized to avoid double-copying.

**Action:** Profile `memcpy` call sites more precisely (perf annotate on the libc symbol). If the majority comes from step 1→2→3, explore direct-to-send-buffer writes. If from step 4 (frame construction), that's structural and harder to eliminate.

**Files:** `src/net/http/buffer.rs`, `src/net/http/response.rs`, `src/net/socket/tcp.rs`

#### 2d: SendTracker Key Type Change

**Current:** `SendTracker` operates on `SendReady(ConnectionId)`.

**New:** `SendTracker` operates on `usize` slab keys directly. The `SendReady` wrapper may become unnecessary — evaluate whether it should be kept for type safety or removed for simplicity.

The internal `FxHashSet` operations (insert into active set, drain) become cheaper with `usize` keys vs `ConnectionId` structs.

**File:** `src/net/handler/tcp/send_tracker.rs`

## Implementation Order

1. Add `slab` dependency
2. Update `SendTracker` to use `usize` keys (tier 2d — must happen before or atomically with step 3)
3. Migrate `TcpHandler` to `Slab<Tcb>` + `FxHashMap<ConnectionId, usize>` — includes `handler.rs`, `connection.rs`, `timers.rs` (tier 1)
4. Update `listener.rs`: `accept_queue` delivers `usize` keys (tier 1)
5. Thread slab key through `TcpStream`, `TcpWrite`, `TcpRead`, `TcpSplice`, `Connect`, `Accept` (tier 1)
6. Update inbound path (`process_ipv4`/`process_ipv6`/`process_segment`) to use `connection_map` → slab lookup (tier 1)
7. SmallVec capacity bump (tier 2a)
8. Eliminate redundant `poll_send` lookups (tier 2b)
9. Investigate and reduce memcpy overhead (tier 2c)

## Expected Impact

- **Tier 1:** ~12% CPU reduction from eliminating HashMap hashing on send path. Inbound path retains one hash per packet (~2.6% CPU) which is acceptable.
- **Tier 2a-b:** ~2-3% CPU reduction from eliminating SmallVec heap overflow and redundant lookups.
- **Tier 2c:** TBD pending investigation — potentially ~2-4% if intermediate copies can be eliminated.
- **Combined:** ~15-18% CPU freed, translating to proportional throughput increase.

## Risks

- **Slab key validity:** If a `TcpWrite`/`TcpRead` holds a stale key after connection teardown, `slab[key]` could panic or return a different connection's `Tcb`. Mitigation: connection teardown already invalidates the socket via event queue (Reset/Timeout events). The socket types check events before accessing the slab. Add a debug assertion that the Tcb's ConnectionId matches expectations.
- **Slab memory growth:** Slab doesn't shrink. With 5000 connections this is negligible. For workloads with millions of short-lived connections, slab could grow large. Acceptable for current use cases; can add periodic `slab.shrink_to_fit()` if needed.
- **API surface change:** `write_to_send_buffer` signature changes from `&ConnectionId` to `usize`. This is internal API, not user-facing. The user-facing socket types are unchanged in behavior.
