# Slab-Based TCP Connection Lookup Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `FxHashMap<ConnectionId, Tcb>` with `Slab<Tcb>` + reverse `FxHashMap<ConnectionId, usize>`, eliminating ~12% CPU from HashMap hashing on the TCP send path.

**Architecture:** Dual-structure approach — `Slab<Tcb>` as primary storage with O(1) index access, `FxHashMap<ConnectionId, usize>` as reverse index only used on inbound packet path. Socket types (`TcpStream`, `TcpWrite`, `TcpRead`, etc.) hold `usize` slab keys instead of `ConnectionId`. `SendTracker` operates on `usize` keys.

**Tech Stack:** `slab` crate (0.4), existing `rustc-hash` for reverse map.

**Spec:** `docs/superpowers/specs/2026-03-15-tcp-send-path-optimization-design.md`

---

## Important Notes

- **All changes in Tasks 2-10 must be made atomically** — the codebase will not compile between individual tasks. Do not try to `cargo check` until all tasks through Task 10 are complete.
- **Commit strategy:** Task 1 gets its own commit. Tasks 2-10 are one atomic commit. Task 11 (test fixes) gets its own commit. Task 12 (profiling) is separate.
- **Tests require root** — always run `cargo test` (configured via `.cargo/config.toml` with `sudo -E`).
- **Never use `--features` or `--all-features`** with cargo test.

## Chunk 1: Add Slab Dependency

### Task 1: Add `slab` dependency

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Add slab to Cargo.toml**

Add `slab = { version = "0.4", default-features = false }` to `[dependencies]` after the `smallvec` line.

- [ ] **Step 2: Verify it compiles**

Run: `cargo check 2>&1 | tail -5`
Expected: successful compilation, no errors.

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "deps: Add slab crate for O(1) connection lookup"
```

## Chunk 2: Full Slab Migration (Atomic — do not compile until complete)

All tasks in this chunk must be completed before attempting `cargo check`. The changes are interdependent and the codebase will not compile until all files are updated.

### Task 2: Migrate SendTracker from ConnectionId to usize

**Files:**
- Modify: `src/net/handler/tcp/send_tracker.rs`

- [ ] **Step 1: Replace send_tracker.rs**

Replace the full contents of `src/net/handler/tcp/send_tracker.rs` with:

```rust
use rustc_hash::FxHashSet;

/// Marker returned by Tcb methods that make a connection sendable.
/// Must be consumed by passing to `SendTracker::mark()`.
#[must_use = "connection must be marked for sending via SendTracker::mark()"]
pub struct SendReady(pub usize);

/// Tracks which connections have pending send work using a dual-set
/// swap pattern. `poll_send` calls `swap()` then `drain_active()` to
/// iterate without heap allocation. New marks go into `pending`, which
/// becomes `active` on the next `swap()`.
pub struct SendTracker {
    active: FxHashSet<usize>,
    pending: FxHashSet<usize>,
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
    pub fn drain_active(&mut self) -> impl Iterator<Item = usize> + '_ {
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
    pub fn unmark(&mut self, key: usize) {
        self.active.remove(&key);
        self.pending.remove(&key);
    }

    /// Check if any connections need sending (across both sets).
    #[inline(always)]
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.active.is_empty() && self.pending.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_and_drain_active() {
        let mut tracker = SendTracker::new();
        tracker.mark(SendReady(42));
        tracker.mark(SendReady(7));
        tracker.swap();
        let active: Vec<usize> = tracker.drain_active().collect();
        assert_eq!(active.len(), 2);
        assert!(active.contains(&42));
        assert!(active.contains(&7));
    }

    #[test]
    fn unmark_removes_from_both_sets() {
        let mut tracker = SendTracker::new();
        tracker.mark(SendReady(10));
        tracker.swap();
        tracker.mark(SendReady(10));
        tracker.unmark(10);
        assert!(tracker.is_empty());
    }
}
```

### Task 3: Migrate TcpHandler struct and core methods

**Files:**
- Modify: `src/net/handler/tcp/handler.rs`

- [ ] **Step 1: Rewrite handler.rs with Slab**

Replace `src/net/handler/tcp/handler.rs` with:

```rust
use rustc_hash::FxHashMap;
use slab::Slab;

use crate::{
    net::wire::{ethernet::MacAddress, tcp::flags},
    xdp::frame::FrameBuffer,
};

use super::{
    isn::IsnGenerator,
    listener,
    segment::SegmentBuilder,
    send_tracker::SendTracker,
    state::TcpState,
    tcb::{ConnectionId, Tcb},
};

/// Initial RTO for SYN retransmission (1 second in coarsetime ticks).
pub(super) const INITIAL_RTO_MS: u64 = 1000;

/// R2 threshold for SYN retransmission (~3 minutes per MUST-23).
pub(super) const SYN_R2_THRESHOLD_MS: u64 = 180_000;

/// TCP protocol handler.
///
/// Manages the connection table, listener table, and dispatches
/// incoming TCP segments through the appropriate state machine.
pub struct TcpHandler {
    pub(super) connections: Slab<Tcb>,
    pub(super) connection_map: FxHashMap<ConnectionId, usize>,
    pub(super) listeners: Vec<listener::ListenEntry>,
    pub(super) isn_generator: IsnGenerator,
    pub(crate) send_tracker: SendTracker,
    pub(super) rx_offload: bool,
    pub(super) tx_offload: bool,
}

impl TcpHandler {
    pub fn new(rx_offload: bool, tx_offload: bool) -> Self {
        Self {
            connections: Slab::new(),
            connection_map: FxHashMap::default(),
            listeners: Vec::new(),
            isn_generator: IsnGenerator::new(),
            send_tracker: SendTracker::new(),
            rx_offload,
            tx_offload,
        }
    }

    /// Get a reference to the connection for a given ConnectionId.
    pub fn get_connection(&self, id: &ConnectionId) -> Option<&Tcb> {
        let &key = self.connection_map.get(id)?;
        self.connections.get(key)
    }

    /// Get a mutable reference to the connection for a given ConnectionId.
    pub fn get_connection_mut(&mut self, id: &ConnectionId) -> Option<&mut Tcb> {
        let &key = self.connection_map.get(id)?;
        self.connections.get_mut(key)
    }

    /// Look up slab key for a ConnectionId.
    pub fn connection_key(&self, id: &ConnectionId) -> Option<usize> {
        self.connection_map.get(id).copied()
    }

    /// Get a reference to the connection by slab key.
    #[inline(always)]
    pub fn get_by_key(&self, key: usize) -> Option<&Tcb> {
        self.connections.get(key)
    }

    /// Get a mutable reference to the connection by slab key.
    #[inline(always)]
    pub fn get_by_key_mut(&mut self, key: usize) -> Option<&mut Tcb> {
        self.connections.get_mut(key)
    }

    /// Insert a new connection, returning its slab key.
    pub fn insert_connection(&mut self, tcb: Tcb) -> usize {
        let id = tcb.id;
        let key = self.connections.insert(tcb);
        self.connection_map.insert(id, key);
        key
    }

    /// Remove a connection by slab key.
    pub fn remove_connection_by_key(&mut self, key: usize) -> Option<Tcb> {
        if self.connections.contains(key) {
            let tcb = self.connections.remove(key);
            self.connection_map.remove(&tcb.id);
            Some(tcb)
        } else {
            None
        }
    }

    /// Remove a connection by ConnectionId and send RST if synchronized.
    pub fn remove_connection<'umem>(
        &mut self,
        id: &ConnectionId,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let Some(&key) = self.connection_map.get(id) else {
            return;
        };
        let should_rst = self.connections.get(key).map(|tcb| {
            let needs_rst = tcb.state.is_synchronized() || tcb.state == TcpState::SynReceived;
            (needs_rst, tcb.snd_nxt)
        });
        if let Some((true, snd_nxt)) = should_rst {
            SegmentBuilder::build_rst(
                id.local_addr,
                id.remote_addr,
                id.local_port,
                id.remote_port,
                0,
                snd_nxt,
                flags::ACK,
                0,
                src_mac,
                dst_mac,
                self.tx_offload,
                free_frames,
                tx_return,
            );
        }
        self.send_tracker.unmark(key);
        self.remove_connection_by_key(key);
    }

    /// Write data to a connection's send buffer and mark it for sending.
    /// Returns the number of bytes written.
    pub fn write_to_send_buffer(&mut self, key: usize, data: &[u8]) -> Option<usize> {
        let n = self.connections.get_mut(key)?.send_buffer.write(data);
        if n > 0 {
            self.send_tracker.mark(super::send_tracker::SendReady(key));
        }
        Some(n)
    }

    /// Transfer data from recv_buffer to send_buffer and mark for sending.
    /// Returns the number of bytes transferred, or None if connection not found.
    pub fn splice_buffers(&mut self, key: usize, max_len: usize) -> Option<(usize, bool)> {
        let tcb = self.connections.get_mut(key)?;
        let n = tcb.recv_buffer.transfer(&mut tcb.send_buffer, max_len);
        if n > 0 {
            self.send_tracker.mark(super::send_tracker::SendReady(key));
        }
        let is_remote_closed = tcb.state.is_remote_closed();
        Some((n, is_remote_closed))
    }

    /// Get the first connection (test helper).
    #[cfg(test)]
    pub fn first_connection(&self) -> &Tcb {
        self.connections.iter().next().unwrap().1
    }

    /// Get the first connection mutably (test helper).
    #[cfg(test)]
    pub fn first_connection_mut(&mut self) -> &mut Tcb {
        self.connections.iter_mut().next().unwrap().1
    }

    /// Get the first connection's slab key (test helper).
    #[cfg(test)]
    pub fn first_connection_key(&self) -> usize {
        self.connections.iter().next().unwrap().0
    }
}
```

### Task 4: Migrate connection.rs (connect, initiate_close)

**Files:**
- Modify: `src/net/handler/tcp/connection.rs`

- [ ] **Step 1: Update connect and connect_with_config**

Change return type of both `connect` and `connect_with_config` from `Result<LocalQueue<TcpEvent>, BindError>` to `Result<(usize, LocalQueue<TcpEvent>), BindError>`.

In `connect_with_config` body:
- Change `self.connections.contains_key(&id)` to `self.connection_map.contains_key(&id)`
- Replace `self.connections.insert(id, tcb)` with `let key = self.insert_connection(tcb);`
- Change `self.send_tracker.mark(SendReady(id))` to `self.send_tracker.mark(SendReady(key))`
- Return `Ok((key, event_queue))`

- [ ] **Step 2: Update initiate_close to take usize key**

Change signature from `pub fn initiate_close(&mut self, id: &ConnectionId)` to `pub fn initiate_close(&mut self, key: usize)`.

Change `self.connections.get_mut(id)` to `self.connections.get_mut(key)`.

### Task 5: Migrate listener.rs (accept_queue, unlisten)

**Files:**
- Modify: `src/net/handler/tcp/listener.rs`

- [ ] **Step 1: Update types**

- Change `pub accept_queue: LocalQueue<ConnectionId>` to `pub accept_queue: LocalQueue<usize>`
- Change `listen`/`listen_with_config` return types to `Result<LocalQueue<usize>, BindError>`

- [ ] **Step 2: Update push_to_accept_queue_on**

Change signature to accept both `id: &ConnectionId` (for matching) and `key: usize` (to push):

```rust
pub(super) fn push_to_accept_queue_on(listeners: &[ListenEntry], id: &ConnectionId, key: usize) {
    for listener in listeners {
        if listener.port == id.local_port
            && (listener.addr.is_unspecified() || listener.addr == id.local_addr)
        {
            listener.accept_queue.push(key);
            return;
        }
    }
}
```

- [ ] **Step 3: Update unlisten to use slab**

Replace `connections.retain()` with slab-compatible iteration:

```rust
pub fn unlisten(&mut self, addr: IpAddress, port: u16) {
    self.listeners
        .retain(|l| !(l.port == port && l.addr == addr));
    let keys_to_remove: SmallVec<[usize; 8]> = self
        .connection_map
        .iter()
        .filter_map(|(_id, &key)| {
            let tcb = &self.connections[key];
            if tcb.state == TcpState::SynReceived
                && tcb.from_passive_open
                && tcb.id.local_port == port
                && (addr.is_unspecified() || tcb.id.local_addr == addr)
            {
                Some(key)
            } else {
                None
            }
        })
        .collect();
    for key in keys_to_remove {
        self.send_tracker.unmark(key);
        self.remove_connection_by_key(key);
    }
}
```

Add `use smallvec::SmallVec;` and `use super::state::TcpState;` to imports.

### Task 6: Migrate transmit.rs (poll_send)

**Files:**
- Modify: `src/net/handler/tcp/transmit.rs`

- [ ] **Step 1: Update poll_send to use slab keys**

Key changes throughout `poll_send`:

1. Change drain type: `SmallVec<[usize; 128]>` (was `SmallVec<[ConnectionId; 32]>`)
2. Change closed type: `SmallVec<[usize; 4]>`
3. Main loop: `for key in keys { let Some(tcb) = self.connections.get_mut(key) else { continue; };`
4. All `SendReady(id)` → `SendReady(key)` (lines ~189, 249, 295, 341, 390)
5. Keep `let id = tcb.id;` where needed for SegmentBuilder calls that need addr/port
6. `closed.push(key);` instead of `closed.push(id);`
7. Bottom-of-loop re-mark: `self.connections.get(key)` instead of `self.connections.get(&id)` — this is the same slab key, no second hash needed
8. Closed cleanup: `self.send_tracker.unmark(*key); self.remove_connection_by_key(*key);`
9. Remove `ConnectionId` from imports if no longer needed (keep if used for SegmentBuilder `id` variable type)

### Task 7: Migrate timers.rs (poll_timers, evict_stale)

**Files:**
- Modify: `src/net/handler/tcp/timers.rs`

- [ ] **Step 1: Update poll_timers**

Key changes:
1. All `SmallVec<[ConnectionId; 4]>` → `SmallVec<[usize; 4]>`
2. All `self.connections.values_mut()` → `self.connections.iter_mut()` (yields `(key, &mut Tcb)`)
3. All `self.connections.iter_mut()` that used `(_id, tcb)` → `(key, tcb)`
4. All `to_mark.push(tcb.id)` / `to_remove.push(tcb.id)` / `keep_alive_removals.push(tcb.id)` → push `key`
5. All `SendReady(id)` → `SendReady(key)`
6. Removal loops: look up `tcb.id` from slab before removing (for `decrement_syn_received`), then `self.send_tracker.unmark(*key); self.remove_connection_by_key(*key);`

- [ ] **Step 2: Update evict_stale**

Replace `connections.retain()` with explicit iteration (slab doesn't support `retain`):

```rust
pub fn evict_stale<'umem>(&mut self, now: Instant, _rx_return: &mut impl FrameBuffer<'umem>) {
    let keys_to_remove: SmallVec<[usize; 4]> = self
        .connections
        .iter()
        .filter_map(|(key, tcb)| {
            if tcb.state == TcpState::TimeWait
                && let Some(deadline) = tcb.time_wait_deadline
                && now >= deadline
            {
                Some(key)
            } else {
                None
            }
        })
        .collect();
    for key in keys_to_remove {
        self.send_tracker.unmark(key);
        self.remove_connection_by_key(key);
    }
}
```

### Task 8: Migrate inbound.rs (process_segment, process_listen, state handlers)

**Files:**
- Modify: `src/net/handler/tcp/inbound.rs`

This is the largest and most complex migration. The inbound path is the one place we still hash (4-tuple → slab key via `connection_map`).

- [ ] **Step 1: Update imports**

Add `use slab::Slab;` alongside existing `use rustc_hash::FxHashMap;`.

- [ ] **Step 2: Update PostAction enum**

```rust
enum PostAction {
    None,
    RemoveConnection(usize),
    RemoveAndDecrement(usize),
}
```

- [ ] **Step 3: Update process_segment**

The destructure at ~line 294 now includes `connection_map`:
```rust
let Self {
    connections,
    connection_map,
    listeners,
    isn_generator,
    send_tracker,
    tx_offload,
    rx_offload: _,
    ..
} = self;
```

Connection lookup (~line 305): Change from `connections.get_mut(&conn_id)` to a two-step lookup. Define `key` at this scope level so it's available for `PostAction::None`:

```rust
let mut key_for_post = None;
if let Some(&key) = connection_map.get(&conn_id) {
    key_for_post = Some(key);
    if let Some(tcb) = connections.get_mut(key) {
        // ... existing state dispatch ...
```

PostAction handling (~lines 411-434): Use slab key for removal and connection_map cleanup:
```rust
match action {
    PostAction::RemoveConnection(key) => {
        send_tracker.unmark(key);
        if let Some(tcb) = connections.get(key) {
            connection_map.remove(&tcb.id);
        }
        connections.remove(key);
    }
    PostAction::RemoveAndDecrement(key) => {
        if let Some(tcb) = connections.get(key) {
            Self::decrement_syn_received(listeners, &tcb.id);
            connection_map.remove(&tcb.id);
        }
        send_tracker.unmark(key);
        connections.remove(key);
    }
    PostAction::None => {
        if let Some(key) = key_for_post {
            if let Some(tcb) = connections.get(key)
                && (tcb.ack_pending
                    || tcb.pending_fin
                    || tcb.send_buffer.available() > 0
                    || tcb.ecn_cwr_sent
                    || tcb.persist_deadline.is_some()
                    || tcb.retransmit_deadline.is_some())
            {
                send_tracker.mark(SendReady(key));
            }
        }
    }
}
```

After `process_listen` call (~line 467-475): Update new connection check:
```rust
if let Some(&key) = connection_map.get(&new_conn_id) {
    send_tracker.mark(SendReady(key));
}
```

- [ ] **Step 4: Thread slab key through all state processing functions**

All state handlers that return `PostAction` need a `key: usize` parameter so they can return `PostAction::RemoveConnection(key)` etc. Update these function signatures:

- `process_syn_sent(tcb, key, ...)` — add `key: usize` parameter, change `PostAction::RemoveConnection(tcb.id)` to `PostAction::RemoveConnection(key)`
- `process_syn_received(tcb, key, listeners, ...)` — add `key: usize` parameter. Update the `push_to_accept_queue_on` call at ~line 846 to pass `key`: `Self::push_to_accept_queue_on(listeners, &id, key);`
- `process_established(tcb, key, ...)` — add `key: usize` parameter
- Any other state handlers that return `PostAction::RemoveConnection` or `PostAction::RemoveAndDecrement`

Update all call sites in `process_segment` to pass `key` to these functions.

- [ ] **Step 5: Update process_listen signature**

Change from:
```rust
fn process_listen<'umem>(
    connections: &mut FxHashMap<ConnectionId, Tcb>,
    listeners: &mut [ListenEntry],
    ...
```
To:
```rust
fn process_listen<'umem>(
    connections: &mut Slab<Tcb>,
    connection_map: &mut FxHashMap<ConnectionId, usize>,
    listeners: &mut [ListenEntry],
    ...
```

At the connection insert (~line 706): Save `tcb.id` before the move, then insert into both structures:
```rust
let tcb_id = tcb.id;
let key = connections.insert(tcb);
connection_map.insert(tcb_id, key);
```

Update the call site in `process_segment` to pass `connection_map`.

### Task 9: Migrate socket/tcp.rs

**Files:**
- Modify: `src/net/socket/tcp.rs`

- [ ] **Step 1: Update TcpListener**

Change `accept_queue: LocalQueue<ConnectionId>` to `accept_queue: LocalQueue<usize>`.

- [ ] **Step 2: Update Accept**

Change `accept_queue: &'listener LocalQueue<ConnectionId>` to `&'listener LocalQueue<usize>`.

In `Accept::poll`: Pop `usize` key, look up `tcb.id` and `event_queue` via `handler.get_by_key(conn_key)`, pass both `conn_key` and `conn_id` to `TcpStream::from_accepted`.

- [ ] **Step 3: Update TcpStream**

Add `conn_key: usize` field. Keep `conn_id: ConnectionId` for user-facing getters.

```rust
pub struct TcpStream {
    conn_key: usize,
    conn_id: ConnectionId,
    #[allow(dead_code)]
    event_queue: LocalQueue<TcpEvent>,
    handler: Rc<UnsafeCell<TcpHandler>>,
    closed: bool,
    write_closed: bool,
}
```

Update `from_accepted` and `from_accepted_for_test` to take `conn_key: usize, conn_id: ConnectionId`.

Update all methods:
- `write()`, `read()`, `splice()` — pass `self.conn_key`
- `close()`, `shutdown()` — call `handler.initiate_close(self.conn_key)`
- `set_nodelay()`, `nodelay()`, `set_keepalive()`, `keepalive()`, `set_linger()`, `linger()` — use `handler.get_by_key_mut(self.conn_key)` / `handler.get_by_key(self.conn_key)`

- [ ] **Step 4: Update Connect**

Add `conn_key: usize` field. Update `TcpStream::connect()` and `connect_with_config()` to destructure the new `(key, event_queue)` return from `handler.connect()`.

```rust
pub struct Connect {
    conn_key: usize,
    conn_id: ConnectionId,
    event_queue: LocalQueue<TcpEvent>,
    handler: Rc<UnsafeCell<TcpHandler>>,
}
```

Update `Connect::poll` to pass `conn_key` to `TcpStream`.

- [ ] **Step 5: Update TcpWrite, TcpRead, TcpSplice**

Each gets `conn_key: usize` replacing `conn_id: ConnectionId`:

- `TcpWrite`: `handler.write_to_send_buffer(this.conn_key, remaining)`, `handler.get_by_key_mut(this.conn_key)` for buffer waker registration
- `TcpRead`: `handler.get_by_key_mut(this.conn_key)` for recv buffer access
- `TcpSplice`: `handler.splice_buffers(this.conn_key, this.max_len)`, `handler.get_by_key_mut(this.conn_key)` for waker registration

### Task 10: Fix remaining compilation errors

**Files:**
- Modify: Any remaining files that reference old APIs

- [ ] **Step 1: Run cargo check and fix all errors**

Run: `cargo check 2>&1`

Expected errors from these files (fix each one):

**TCP handler test files** (most impacted):
- `src/net/handler/tcp/tests/mod.rs` — `establish_connection`, `active_open_handshake`, `active_open_handshake_with_config` helpers. `connect()` now returns `(usize, LocalQueue)`. These helpers should return slab keys where callers need them.
- `src/net/handler/tcp/tests/handshake.rs` — calls `handler.connect()` directly
- `src/net/handler/tcp/tests/teardown.rs` — calls `handler.initiate_close(&conn_id)` (at least 3 sites) — change to use slab key via `handler.first_connection_key()`
- `src/net/handler/tcp/tests/keepalive.rs` — calls `handler.initiate_close(&conn_id)` and `handler.get_connection(&conn_id)` (at least 9 sites) — change to use slab key
- `src/net/handler/tcp/tests/ecn.rs` — calls `connect_with_config` (return type changed)
- `src/net/handler/tcp/tests/delayed_ack.rs` — may use `ConnectionId` directly
- All other test files in `src/net/handler/tcp/tests/` — check for `write_to_send_buffer`, `initiate_close`, `get_connection`, `get_connection_mut` calls that need updating

**HTTP layer** (test code only):
- `src/net/http/connection.rs` — test code uses `ConnectionId`
- `src/net/http/body.rs` — test code uses `ConnectionId`

**Runtime**:
- `src/rt/local.rs` — may call `TcpHandler` methods that changed signatures

**Common fix patterns:**
- `handler.connect()` return: destructure as `(key, event_queue)` instead of just `event_queue`
- `handler.initiate_close(&conn_id)` → `handler.initiate_close(key)` where key = `handler.first_connection_key()` or from connect return
- `handler.write_to_send_buffer(&conn_id, data)` → `handler.write_to_send_buffer(key, data)`
- `handler.get_connection(&conn_id)` → `handler.get_by_key(key)` or keep using `get_connection` if the ConnectionId is available
- `from_accepted_for_test(conn_id, ...)` → `from_accepted_for_test(key, conn_id, ...)`

- [ ] **Step 2: Verify full compilation**

Run: `cargo check 2>&1 | tail -5`
Expected: successful compilation, no errors.

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
refactor(net::tcp): Replace FxHashMap with Slab for connection lookup

Migrate TCP connection storage from FxHashMap<ConnectionId, Tcb> to
Slab<Tcb> + FxHashMap<ConnectionId, usize> reverse index. This eliminates
all hashing from the send path (write_to_send_buffer, poll_send) while
retaining O(1) reverse lookup for inbound packet processing.

- TcpHandler: Slab<Tcb> primary storage, FxHashMap reverse index
- SendTracker: operates on usize slab keys
- Socket types: TcpStream/TcpWrite/TcpRead hold usize conn_key
- accept_queue: delivers usize keys instead of ConnectionId
- poll_send: SmallVec<[usize; 128]> (was SmallVec<[ConnectionId; 32]>)
- Eliminates redundant connection lookup at bottom of poll_send
EOF
)"
```

## Chunk 3: Test Verification

### Task 11: Run and fix all tests

**Files:**
- Modify: `src/net/handler/tcp/tests/*.rs` and other test files as needed

- [ ] **Step 1: Run all tests**

Run: `cargo test 2>&1 | tail -30`

- [ ] **Step 2: Fix any test failures**

If tests fail, the most likely causes are:
- Test helpers returning wrong types (should return slab keys now)
- Tests using `ConnectionId` where slab key is now needed
- Assertions on connection counts using old FxHashMap API (`.len()` on Slab works the same way)

- [ ] **Step 3: Verify all tests pass**

Run: `cargo test 2>&1 | tail -10`
Expected: All tests pass.

- [ ] **Step 4: Commit if any test fixes were needed**

```bash
git add -A
git commit -m "test(net::tcp): Fix tests for slab-based connection lookup"
```

## Chunk 4: Profiling Verification

### Task 12: Re-profile and measure improvement

**Files:**
- No code changes — measurement only

- [ ] **Step 1: Rebuild with profiling and re-run benchmark**

```bash
cargo build --profile profiling --example http-server
```

Run the same wrk benchmark (5000 connections, 2 threads) and capture new `perf.data`.

- [ ] **Step 2: Compare profiles**

Run: `perf report -i perf.data --stdio --no-children --percent-limit 0.3 -g none 2>/dev/null | head -60`

Compare with the pre-migration profile. Expected changes:
- `hashbrown::map::HashMap::insert` should drop from ~7.8% to near-zero on send path
- `hashbrown::map::HashMap::get_mut` should drop from ~4.4% to ~2-3% (only inbound path)
- `poll_send` and `write_to_send_buffer` should drop proportionally
- `SmallVec::extend` should drop (larger inline capacity, smaller element size)

- [ ] **Step 3: Document findings for follow-up**

If `libc memcpy` is still >3%, annotate to identify call sites for Tier 2c investigation.
