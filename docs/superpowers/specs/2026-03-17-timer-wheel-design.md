# Timer Wheel Subsystem

## Problem

The event loop in `rt/local.rs` checks TCP timers by scanning all connections
every 65,536 iterations. At 10k+ connections this means ~50k TCB touches per
check cycle (5 full passes: delayed ACK, keep-alive, SACK recovery, RTO
retransmit, TIME-WAIT eviction). Most entries have no expired timer — the work
is wasted.

Timer precision is also poor: the check frequency is iteration-based, not
time-based. The loop is a busy loop whose iteration speed depends on workload
(user futures, packet volume, TX/RX ring ops). A 40ms delayed ACK target can
be missed by an arbitrary margin.

## Scope

**Initial implementation — TCP timers:**
- Retransmit (RTO)
- Delayed ACK
- Persist (zero-window probe)
- Keep-alive
- TIME-WAIT
- Linger

**Out of scope for now — stays as-is:**
- Neighbor cache eviction (small table, O(n) is fine)
- PMTU cache eviction (tiny table)
- Fragment reassembly timeout (bounded entry count)
- SACK recovery pass (ACK-feedback-driven, not timer-driven)

**Future consumers (the wheel must support these without redesign):**
- **DNS resolver** — query retransmission, response timeout, cache TTL expiry
- **QUIC** — loss detection, idle timeout, ACK delay, path validation,
  handshake timeout, key update, connection migration probes. QUIC has
  per-stream and per-connection timers, potentially 100k+ at scale.

## Design

### Protocol-agnostic wheel core

The wheel itself knows nothing about TCP, DNS, or QUIC. It stores opaque
`TimerId` values and returns them on expiry. Protocol handlers interpret the
IDs.

```rust
/// Opaque identifier returned by the wheel on expiry.
/// Encodes enough information for the caller to dispatch to the right
/// protocol handler, connection, and timer kind.
///
/// Layout: protocol-defined. TCP uses (slab_key, TimerKind). DNS and QUIC
/// will define their own packing. The wheel treats it as an opaque u64.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerId(pub u64);
```

Each protocol defines its own packing/unpacking. TCP example:

```rust
impl TimerId {
    fn tcp(key: usize, kind: TcpTimerKind) -> Self {
        TimerId((key as u64) << 8 | kind as u64)
    }
    fn unpack_tcp(self) -> (usize, TcpTimerKind) {
        let kind = TcpTimerKind::from(self.0 as u8);
        let key = (self.0 >> 8) as usize;
        (key, kind)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TcpTimerKind {
    Retransmit  = 0,
    DelayedAck  = 1,
    Persist     = 2,
    KeepAlive   = 3,
    TimeWait    = 4,
    Linger      = 5,
}
```

Future protocols pack their own IDs into the same `TimerId(u64)`:
- DNS: `(query_id, DnsTimerKind)` — retransmit, response timeout, cache TTL
- QUIC: `(connection_key, QuicTimerKind)` — loss detection, idle, ACK delay,
  path validation, etc.

The wheel doesn't care — it stores and returns `TimerId` values without
inspecting them.

### Hierarchical wheel structure

Three tiers, 256 slots each. Slot index is `(deadline_ms >> shift) & 0xFF`.

| Tier   | Shift | Resolution | Range     | Covers                              |
|--------|-------|-----------|-----------|-------------------------------------|
| Inner  | 0     | 1ms       | 256ms     | Delayed ACK (40ms), short RTOs      |
| Middle | 8     | 256ms     | 65.5s     | Retransmit, TIME-WAIT, persist      |
| Outer  | 16    | 65.536s   | ~4.66 hrs | Keep-alive (2h), long linger        |

```rust
pub struct TimerWheel {
    tiers: [Tier; 3],
    current_tick_ms: u64,
}

struct Tier {
    slots: [Slot; 256],
    shift: u8,
}

struct Slot {
    head: Option<usize>,  // index into TimerWheel::entries
}
```

Total fixed memory: ~6KB (3 x 256 slots x ~8 bytes).

### Timer entries and linked list

Timer entries live in a `Slab<TimerEntry>` owned by the wheel. Each entry
holds the opaque `TimerId` plus doubly-linked list pointers for its slot chain.

```rust
pub struct TimerEntry {
    id: TimerId,
    next: Option<usize>,  // entry index of next in slot chain
    prev: Option<usize>,  // entry index of prev in slot chain
    slot: u16,            // packed: tier (2 bits high) | slot_index (8 bits low)
}
```

**Entry handle**: `arm()` returns a `TimerHandle(usize)` (the entry's slab
key). The caller stores this handle to cancel or re-arm later. For TCP, the
handles live in a parallel `Slab<TcpTimerHandles>` indexed by the same keys
as `Slab<Tcb>`:

```rust
pub struct TcpTimerHandles {
    pub handles: [Option<TimerHandle>; 6],  // one per TcpTimerKind
}
```

This replaces the intrusive-list-through-TCB approach with a cleaner
separation: the wheel owns its entries, protocols own their handles.

**Extensibility**: DNS and QUIC add their own handle storage without touching
the wheel. DNS might store handles in a `HashMap<QueryId, TimerHandle>`. QUIC
might use a parallel slab like TCP. The wheel is unaware.

Mixed slots: a single slot chain can contain entries from TCP, DNS, and QUIC
interleaved. The chain is a standard doubly-linked list through `TimerEntry`
nodes in the wheel's entry slab — no protocol-specific traversal logic.

### Operations

**Arm** — called when setting a timer deadline. O(1).

1. Allocate a `TimerEntry` in the wheel's entry slab. Store `TimerId`.
2. Compute tier and slot index from `deadline_ms - current_tick_ms`.
3. Prepend to slot's linked list.
4. Return `TimerHandle` to caller.

**Cancel** — called with a `TimerHandle`. O(1).

1. Look up entry by handle. If not present, no-op.
2. Unlink from slot's linked list via prev/next.
3. Remove entry from slab, freeing the slot.

**Re-arm** — cancel + arm. Callers can also just arm with a new ID and let
the old handle go stale if they track validity externally (but explicit
cancel + arm is preferred to avoid entry slab bloat).

**Advance** — called from event loop after clock refresh. O(fired + cascade).

1. While `current_tick_ms < now_ms`:
   - Drain inner wheel slot at `current_tick_ms & 0xFF`.
   - Collect all `TimerId` values from drained entries as fired timers.
   - Remove drained entries from the entry slab.
   - On inner wheel wrap (every 256 ticks): cascade one middle-tier slot into
     inner slots (redistribute entries at finer granularity).
   - On middle wheel wrap (every 65,536 ticks): cascade one outer-tier slot
     into middle slots.
   - Increment `current_tick_ms`.
2. Return fired list.

When no timers are due, advance is a single integer comparison.

### Event loop integration

Changes to `rt/local.rs`:

1. **Clock refresh frequency increases.** Move `now = coarsetime::Instant::now()`
   out of the 65k-iteration block. The exact frequency (every iteration vs every
   N iterations) is a tuning decision. `coarsetime::Instant::now()` calls
   `clock_gettime(CLOCK_MONOTONIC_COARSE)` which is a vDSO call (tens of
   nanoseconds), not a bare atomic load. The wheel tolerates stale `now`
   gracefully — it just advances in a burst when `now` catches up.

2. **Wheel advance replaces `poll_timers()` and TCP `evict_stale()`.**
   The event loop dispatches fired timers by inspecting the `TimerId`:
   ```rust
   let fired = wheel.advance(now_ms);
   for timer_id in fired {
       // Top bits of TimerId encode protocol (0 = TCP, 1 = DNS, 2 = QUIC, etc.)
       // Each protocol handler unpacks its own IDs.
       let protocol = timer_id.protocol();
       match protocol {
           Protocol::Tcp => {
               let (key, kind) = timer_id.unpack_tcp();
               tcp_handler.handle_timer(key, kind, now, ...);
           }
           // Future:
           // Protocol::Dns => dns_handler.handle_timer(timer_id, now, ...),
           // Protocol::Quic => quic_handler.handle_timer(timer_id, now, ...),
       }
   }
   ```

3. **Non-TCP eviction stays on the 65k counter** (neighbor, PMTU, UDP fragments).

4. **`poll_send()` is unchanged.** Timer fire methods that produce outbound work
   call `send_tracker.mark()` so `poll_send()` picks it up on the next iteration.

### TCP timer dispatch

`handle_timer` dispatches to small, inline, independently testable methods:

```rust
pub fn handle_timer(...) {
    match kind {
        TcpTimerKind::DelayedAck => self.fire_delayed_ack(key, now, ...),
        TcpTimerKind::Retransmit => self.fire_retransmit(key, now, ...),
        TcpTimerKind::KeepAlive  => self.fire_keep_alive(key, now, ...),
        TcpTimerKind::Persist    => self.fire_persist(key, now, ...),
        TcpTimerKind::Linger     => self.fire_linger(key, now, ...),
        TcpTimerKind::TimeWait   => self.fire_time_wait(key),
    }
}
```

Each `fire_*` method is `#[inline]`, takes a slab key, does exactly one thing,
and is independently testable.

### TCB changes

**Removed fields** (scheduling moves to wheel):
- `delayed_ack_deadline: Option<Instant>`
- `retransmit_deadline: Option<Instant>`
- `time_wait_deadline: Option<Instant>`
- `persist_deadline: Option<Instant>`
- `linger_deadline: Option<Instant>`

Saves ~80 bytes per TCB (5 x 16-byte `Option<Instant>`).

**Retained fields** (configuration and state needed for re-arm logic):
- `rto`, `rto_backoff` — compute retransmit deadline
- `delayed_ack_ms` — compute delayed ACK deadline
- `time_wait_duration` — compute TIME-WAIT deadline
- `persist_backoff` — compute persist deadline with exponential backoff
- `keep_alive_enabled`, `keep_alive_idle_ms`, `keep_alive_interval_ms`,
  `keep_alive_count`, `keep_alive_probes_sent`, `last_activity` — keep-alive
  configuration and state
- `linger: Option<u64>` — configuration

### Connection lifecycle

- `insert_connection` also inserts a `TcpTimerHandles` entry in the parallel
  slab (same key). All handles start as `None`.
- `remove_connection_by_key` cancels all armed timers via their handles
  (which removes entries from the wheel's entry slab), then removes the
  `TcpTimerHandles` entry.

### Keep-alive semantic change

Currently keep-alive is a computed threshold (`last_activity + idle_ms`)
checked during the O(n) scan. With the wheel, it becomes a real armed timer:

- On connection establishment (if keep-alive enabled): arm at
  `now + keep_alive_idle_ms`.
- On any packet activity: cancel and re-arm at `now + keep_alive_idle_ms`.
  Reset `keep_alive_probes_sent`.
- On fire: send probe, arm next at `now + keep_alive_interval_ms`.
- After `keep_alive_count` fires with no activity: abort connection.

This is a behavioral change in mechanism but produces identical externally
observable behavior. The benefit is precision — probes fire at the configured
time instead of whenever the scan happens to run.

## Performance analysis

### Per timer-check cycle (10k connections)

| Pass              | Before (O(n) scan) | After (wheel)            |
|-------------------|--------------------|--------------------------|
| Delayed ACK       | 10k TCB touches    | O(fired), typically <100 |
| Keep-alive        | 10k TCB touches    | O(fired), typically <10  |
| RTO retransmit    | 10k TCB touches    | O(fired), typically <200 |
| TIME-WAIT         | 10k TCB touches    | O(fired), varies         |
| Persist           | (in poll_send)     | O(fired)                 |
| **Total**         | **~50k**           | **O(fired), typically hundreds** |

### Per packet (hot path)

| Operation          | Before          | After                                    |
|--------------------|-----------------|------------------------------------------|
| Arm retransmit     | 1 field write   | Unlink old + link new (2 slab index ops) |
| Cancel delayed ACK | 1 field write   | Unlink (1 slab index op)                 |
| Arm delayed ACK    | 1 field write   | Link into slot (1 slab index op)         |
| **Total**          | **~2 stores**   | **~4 slab-indexed pointer ops**          |

### Memory

| Component                    | Before | After   |
|------------------------------|--------|---------|
| Per-TCB timer fields         | ~80B   | Removed |
| Per-connection TcpTimerHandles | —    | ~48B (6 x `Option<TimerHandle>`) |
| Per-armed-timer entry (wheel slab) | — | ~40B (`TimerId` + next/prev/slot) |
| Wheel fixed                  | —      | ~6KB    |
| **Net per-connection**       | **0**  | **~+8B fixed + ~40B per armed timer** |

At 10k connections with ~2 timers armed on average (retransmit + delayed ACK),
net overhead is ~96B per connection — comparable to the old deadline fields.

### Where it wins

- Timer check goes from O(connections) to O(fired) — 100x+ reduction at 10k
  connections when most timers aren't due.
- Timer precision: fires within one wheel tick of the deadline, independent of
  loop iteration speed.
- TCB shrinks by 80 bytes — better cache packing for hot fields.

### Where it costs

- Per-packet: ~2 extra slab index lookups + pointer writes for arm/cancel.
- Complexity: linked list in wheel entry slab, cascade logic, handle lifecycle.
- Memory: ~96B per connection (at 2 armed timers avg), +6KB fixed.

## Files affected

| File | Change |
|------|--------|
| `src/net/timer_wheel.rs` | **New** — `TimerWheel`, `TimerEntry`, `TimerHandle`, `TimerId`, `Slot`, `Tier`. Protocol-agnostic, lives outside `handler/tcp/` so DNS and QUIC can use it. |
| `src/net/handler/tcp/timer_kinds.rs` | **New** — `TcpTimerKind`, `TcpTimerHandles`, `TimerId` packing/unpacking for TCP. |
| `src/net/handler/tcp/timers.rs` | Rewrite — delete `poll_timers()` and `evict_stale()`, add `handle_timer()` dispatching to `fire_*` methods |
| `src/net/handler/tcp/transmit.rs` | Remove persist/linger timer checks from `poll_send()` (persist and linger fire via wheel now) |
| `src/net/handler/tcp/tcb.rs` | Remove 5 `Option<Instant>` deadline fields |
| `src/net/handler/tcp/handler.rs` | Add `timer_handles: Slab<TcpTimerHandles>` to `TcpHandler`; update `insert_connection` / `remove_connection_by_key` |
| `src/rt/local.rs` | Own the `TimerWheel`; increase clock refresh frequency; replace `tcp.poll_timers()` + `tcp.evict_stale()` with `wheel.advance()` + protocol dispatch loop |
| `src/net/handler/tcp/inbound/*.rs` | Arm/cancel calls go through wheel via handles instead of writing deadline fields directly |
| `src/net/handler/tcp/tests/timers.rs` | Rewrite to test `fire_*` methods in isolation + wheel integration tests |
| `src/net/timer_wheel/tests.rs` | **New** — unit tests for wheel core (arm, cancel, advance, cascade) independent of any protocol |
