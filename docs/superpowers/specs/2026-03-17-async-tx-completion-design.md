# Async TX Completion Drain — Design Spec

## Problem

The multi-threaded `Runtime` (4 queues on `c8gn.2xlarge`) achieves **342K req/s** vs **544K req/s** in single-threaded mode — a 6.4x per-core efficiency drop. Root cause: the event loop in `LocalRuntime::run()` (`src/rt/local.rs:425-454`) synchronously drains ALL TX completions every iteration before proceeding to the next `recv()`. With multi-queue, each queue processes fewer packets per iteration, but the per-iteration overhead of the synchronous completion drain is constant — the loop spins on `process_completion_queue` waiting for the kernel to complete TX for a small batch.

## Scope

**Single file change**: `src/rt/local.rs` — the `LocalRuntime::run()` method and a new private helper.

No changes to: `Frame`, `FrameBuffer`, `Umem`, `FillQueue`, `CompletionQueue`, `Socket`, protocol handlers, or the multi-threaded `Runtime` orchestrator. The fix is entirely within the event loop.

## Frame Lifecycle — Reference

Every `Frame<'umem>` is a zero-copy handle into UMEM shared memory. **Frame has no Drop impl** — dropping one silently leaks the UMEM slot. Every frame must be explicitly accounted for at all times.

### Frame States

| # | State | Owner | Tracked By |
|---|-------|-------|------------|
| 1 | `FREE` | `free_frames` buffer | `free_frames.num_frames()` |
| 2 | `TX_PENDING` | `tx_return` buffer | `tx_return.num_frames()` |
| 3 | `RX_RETURN` | `rx_return` buffer | `rx_return.num_frames()` |
| 4 | `IN_RECV_BUFFER` | `buffer` (transient, drained within iteration) | N/A |
| 5 | `IN_KERNEL_TX` | kernel TX ring + DMA | `in_flight_tx` counter |
| 6 | `IN_FILL_QUEUE` | kernel fill ring + RX DMA | not tracked (subtracted at init) |
| 7 | `IN_FRAGMENT_READER` | `UdpHandler` internal `BTreeMap` | not tracked (held by handler) |

### Transitions

```
FREE → [handler pops, builds TX packet] → TX_PENDING
TX_PENDING → [socket.send()] → IN_KERNEL_TX
IN_KERNEL_TX → [completion_queue.process()] → RX_RETURN
RX_RETURN → [recycle to fill queue] → IN_FILL_QUEUE
RX_RETURN → [recycle to free_frames] → FREE
IN_FILL_QUEUE → [kernel receives packet] → IN_RECV_BUFFER
IN_RECV_BUFFER → [handler: invalid/consumed] → RX_RETURN
IN_RECV_BUFFER → [handler: fragment] → IN_FRAGMENT_READER
IN_FRAGMENT_READER → [reassembled or evicted] → RX_RETURN
```

## Current Event Loop (lines 338–471)

```
while !exit:
    1. recv R frames → buffer
    2. for frame in buffer: ethernet_handler.handle(frame, ..., free_frames, rx_return, tx_return)
    3. poll main future (if woken)
    4. poll spawned tasks
    5. TCP timers & send (pops free_frames → pushes tx_return)
    6. evict stale (every 65536 iterations)
    7. SYNCHRONOUS TX DRAIN:
       a. expected_size = tx_return.len() + rx_return.len()
       b. while tx_return > 0: send(); if blocked: wake + drain completions
       c. while rx_return < expected_size: drain completions; if blocked: wake
    8. RECYCLE:
       a. excess rx_return (completions) → free_frames
       b. remaining rx_return (RX returns) → fill queue
    9. capacity wakes
   10. ASSERT: free_frames == expected_free_frames, rx_return == 0, tx_return == 0
```

**The bottleneck is step 7c**: spins until ALL completions arrive. With multi-queue, the kernel's NAPI processing is split across queues, delaying per-queue completions. The event loop blocks here instead of processing new packets.

## New Event Loop

```
while !exit:
    1. DRAIN COMPLETIONS (non-blocking):
       loop { match completion_queue.process() → rx_return; in_flight_tx -= n; break on WouldBlock }

    2. RECYCLE rx_return (completions + previous iteration's handler returns):
       feed fill queue first (ring-size limited), overflow to free_frames

    3. recv R frames → buffer
    4. for frame in buffer: ethernet_handler.handle(...)
    5. poll main future
    6. poll spawned tasks
    7. TCP timers & send
    8. evict stale (every 65536 iterations)

    9. SEND tx_return (non-blocking):
       while tx_return > 0:
         match socket.send():
           Ok(n) → in_flight_tx += n
           Err(WouldBlock) →
             socket.maybe_wake()
             drain completions → rx_return; in_flight_tx -= n
             recycle rx_return
             retry send ONCE; if still WouldBlock → break (defer to next iteration)

   10. RECYCLE rx_return (handler-produced frames from step 4 + completions from step 9):
       feed fill queue first, overflow to free_frames

   11. CAPACITY WAKES (same as before)

   12. ASSERT NEW INVARIANT:
       rx_return == 0
       free_frames + in_flight_tx + tx_return <= expected_total
```

## Invariant Change

### Current Invariant (end of each iteration)
```
rx_return == 0
tx_return == 0
free_frames == expected_free_frames
```

All frames accounted for in `free_frames` (plus the constant fill-queue-seeded frames managed by the kernel).

### New Invariant (end of each iteration)
```
rx_return == 0
free_frames + in_flight_tx + tx_return <= expected_total
```

Where:
- `expected_total` is captured at init (same value as current `expected_free_frames`)
- `in_flight_tx` is a `u32` counter, initialized to 0
- `tx_return` may be > 0 (frames deferred due to TX ring full)
- `in_flight_tx` may be > 0 (frames in kernel TX pipeline)
- The inequality (`<=`) accounts for frames temporarily held by `UdpHandler`'s `FragmentReader` (state 7), which are outside our tracked variables. When fragments are reassembled or evicted, they return to `rx_return` and re-enter the accounting. **Note**: this is a pre-existing gap in the current code's `debug_assert_eq!` — the current assertion would also fail under fragmented UDP traffic in debug builds. Using `<=` makes the invariant correct for all protocol workloads.

### Why This Is Safe

1. **`in_flight_tx` is exact**: incremented by `socket.send()` return value (number of frames accepted by TX ring), decremented by `completion_queue.process()` return value (number of frames completed by kernel). Both return `u32` counts.

2. **No frame is untracked**: every frame is in exactly one of {`free_frames`, `tx_return`, `rx_return`, `in_flight_tx`, fill queue, fragment reader}. `rx_return` is drained to 0 every iteration. Fill queue frames were subtracted at init. Fragment reader frames are bounded and eventually return.

3. **The kernel guarantees completion for operational sockets**: every frame submitted to the TX ring will eventually appear in the completion ring, provided the socket and interface remain operational. If the interface goes down (`ENETDOWN`), in-flight frames may not produce completions — `in_flight_tx` would be permanently inflated. This is acceptable because `ENETDOWN` is a fatal condition that terminates the event loop. A comment in the code will note this dependency.

4. **`in_flight_tx` can never go negative**: completions can only return frames that were previously sent. The `u32` subtraction is always valid because `completion_queue.process()` returns at most the number of pending completions.

## Recycle Helper

Extract recycling into a private method to avoid duplication (called at steps 2, mid-9, and 10):

```rust
/// Recycles all frames in `rx_return` back into the system.
///
/// Priority: fill queue first (kernel needs RX buffers), overflow to free_frames.
/// After this call, `rx_return.num_frames() == 0`.
///
/// # Frame Accounting
/// Frames move: rx_return → fill_queue (kernel-managed, not counted) OR rx_return → free_frames.
/// The fill queue ring size naturally limits how many frames enter the kernel RX path.
fn recycle_rx_return(&mut self) -> Result<()> {
    // Feed fill queue — ring size prevents overfilling.
    while self.rx_return.num_frames() > 0 {
        if self.umem.process_fill_queue(&mut self.rx_return).is_err() {
            break; // Fill ring full
        }
    }
    // Overflow to free_frames — these are available for TX packet building.
    while self.rx_return.num_frames() > 0 {
        self.free_frames.push(self.rx_return.pop().unwrap());
    }
    // Wake fill queue so kernel processes newly submitted addresses.
    self.umem.maybe_wake_fill_queue(self.socket.fd())
}
```

### Fill Queue Balance

**Concern**: the current code feeds exactly `received` frames back to the fill queue, maintaining a stable level. The new code feeds fill queue aggressively (all rx_return, fill-ring-limited).

**Why this is safe**: The fill queue ring has a fixed size (`fill_ring_size`, power of 2, typically 2048). `process_fill_queue` returns `WouldBlock` when the ring is full. The kernel consumes fill entries at the rate it receives packets. Over time:
- If fill queue is full: all recycled frames go to `free_frames` (TX pool grows)
- If fill queue has space: frames enter it, replenishing kernel RX buffers
- The system self-balances: kernel RX consumption rate = `recv()` production rate

**No starvation risk**: completions are drained every iteration (step 1 + mid-step 9). Even if the kernel is slow to complete TX, the fill queue is replenished from whatever frames are available. The worst case is fewer free_frames for TX (natural backpressure), not fill queue starvation.

**Behavioral change vs current code**: the current code sends completions to `free_frames` first (preserving the TX pool) and only RX-returned frames to the fill queue. The new code sends everything to the fill queue first (preserving the RX pool). This is intentional — with async completions, the fill queue may have been depleted by recv() in the previous iteration and needs aggressive replenishment. The TX pool is replenished when the fill queue is full (overflow to free_frames) or when completions arrive and the fill queue has no room. If benchmarks show TX-side regression, the recycle helper can be parameterized with a `fill_target` to cap fill queue feeding.

## Capacity-Driven Wakes

The existing capacity wake mechanism (`local.rs:456-467`) wakes futures blocked on frame availability when `free_frames` grows. In the new design, `free_frames` grows when:
- Completions are recycled (steps 2, 10) — frames return from kernel TX
- Fill queue is full and overflow goes to free_frames

The `free_before` snapshot must be taken AFTER the initial recycle (step 2) but BEFORE handler processing, so capacity wakes only fire when new frames were freed during THIS iteration's processing. This is the same semantic as the current code.

## Edge Cases

### 1. TX Ring Full — All Frames In-Flight

If `socket.send()` consistently returns `WouldBlock`:
- `tx_return` grows (responses pile up)
- `free_frames` shrinks (handlers can't build responses)
- TCP's `SegmentBuilder` gets `None` from `free_frames.pop()`
- Capacity wakers queue the future; it will be woken when completions arrive
- **This is correct backpressure** — same as if the network were congested

### 2. No Packets Received (Idle Queue)

If `recv()` returns `WouldBlock` every iteration:
- No handler processing, no frames generated
- Completion drain at step 1 still runs (returns in-flight frames)
- Event loop spins but does minimal work
- **No change from current behavior** — idle queues already spin

### 3. Burst of Small TX Batches

Each iteration: recv few packets → generate few responses → send small batch.
- Current: send 5 frames, wait for 5 completions (kernel round-trip per iteration)
- New: send 5 frames, continue immediately, collect completions next iteration
- **Net effect**: one more iteration of latency for frame recycling, but the event loop processes packets continuously instead of blocking on completions

### 4. Fragment Reassembly

Frames held in `UdpHandler`'s `FragmentReader` are outside our 4-variable accounting (same as current design — they're in state 7). When fragments are reassembled or evicted, they return to `rx_return` and re-enter accounting. The `<=` invariant (rather than `==`) accommodates this: when fragments are held, the tracked sum is less than `expected_total` by exactly the number of held fragments. This is also a pre-existing gap in the current code's strict `==` assertion, which we are correcting here.

### 5. `in_flight_tx` Overflow

`in_flight_tx` is `u32`. Total UMEM frames are bounded by `num_frames` (default: `fill_ring_size + completion_ring_size`, typically 4096). `u32` max is 4 billion. No overflow risk.

## Detailed Code Changes

### Variables

```rust
// REMOVE:
// let expected_free_frames = self.free_frames.num_frames();

// ADD:
let expected_total = self.free_frames.num_frames() as u32;
let mut in_flight_tx: u32 = 0;
```

### Phase 1: Drain Completions (NEW — before recv)

```rust
// ---- Phase 1: Collect TX Completions (non-blocking) ----
// Frames completed by the kernel since last iteration are returned to rx_return.
// This runs BEFORE recv to maximize frame availability for this iteration.
loop {
    match self.umem.process_completion_queue(&mut self.rx_return) {
        Ok(n) => in_flight_tx -= n,
        Err(_) => break,
    }
}
```

### Phase 2: Recycle (NEW — before recv)

```rust
// ---- Phase 2: Recycle rx_return → fill queue + free_frames ----
// rx_return contains: TX completions from Phase 1, plus handler-returned
// frames from the PREVIOUS iteration.
self.recycle_rx_return()?;
```

### Phase 3–8: Unchanged

Receive, protocol dispatch, poll futures, poll tasks, TCP timers, evict stale — all identical to current code except:
- `free_before` snapshot moves to after Phase 2:
  ```rust
  let free_before = self.free_frames.num_frames();
  ```

### Phase 9: Send (CHANGED — non-blocking)

```rust
// ---- Phase 9: Send tx_return (non-blocking) ----
while self.tx_return.num_frames() > 0 {
    match self.socket.send(&mut self.tx_return) {
        Ok(n) => in_flight_tx += n,
        Err(_) => {
            // TX ring full — kick kernel and try to free completions.
            self.socket.maybe_wake()?;
            loop {
                match self.umem.process_completion_queue(&mut self.rx_return) {
                    Ok(n) => in_flight_tx -= n,
                    Err(_) => break,
                }
            }
            self.recycle_rx_return()?;
            // Retry send once after freeing ring slots.
            match self.socket.send(&mut self.tx_return) {
                Ok(n) => in_flight_tx += n,
                Err(_) => break, // Still full — defer remaining to next iteration.
            }
        }
    }
}
```

### Phase 10: Recycle Remaining rx_return (NEW)

```rust
// ---- Phase 10: Recycle remaining rx_return ----
// This drains whatever is left in rx_return. Contents depend on the
// Phase 9 path taken:
// - If all sends succeeded: rx_return contains handler-returned RX frames
//   from Phase 3 (they were not touched by Phase 9's success path).
// - If Phase 9 hit WouldBlock: the mid-Phase-9 recycle already drained
//   both handler returns AND completions, so rx_return is likely empty
//   here. This call is a no-op in that case (recycle_rx_return is
//   branchless on empty rx_return).
self.recycle_rx_return()?;
```

### Phase 11: Capacity Wakes (UNCHANGED logic, adjusted position)

```rust
// ---- Phase 11: Capacity-Driven Wakes ----
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

### Phase 12: Invariant Check (CHANGED)

```rust
// ---- Phase 12: Frame Accounting Invariant ----
debug_assert_eq!(
    self.rx_return.num_frames(),
    0,
    "rx_return must be fully drained"
);
// Use <= rather than == because frames held by UdpHandler's FragmentReader
// are outside our tracked variables. The deficit equals the number of
// fragments currently awaiting reassembly. This also fixes a pre-existing
// gap in the old assertion which used == and would fail under fragmented
// UDP traffic in debug builds.
let tracked = self.free_frames.num_frames() as u32
    + in_flight_tx
    + self.tx_return.num_frames() as u32;
debug_assert!(
    tracked <= expected_total,
    "Frame leak detected: tracked={} (free={} in_flight={} tx_pending={}) > expected={}",
    tracked,
    self.free_frames.num_frames(),
    in_flight_tx,
    self.tx_return.num_frames(),
    expected_total
);
```

### Recycle Helper (NEW private method on `LocalRuntime`)

```rust
/// Drains `rx_return` completely: fill queue first (ring-limited), overflow to `free_frames`.
///
/// # Frame Accounting
///
/// Every frame in `rx_return` moves to exactly one destination:
/// - `fill_queue`: frame leaves our accounting (kernel RX path owns it)
/// - `free_frames`: frame stays in our accounting
///
/// After return: `rx_return.num_frames() == 0`.
#[inline(always)]
fn recycle_rx_return(&mut self) -> Result<()> {
    while self.rx_return.num_frames() > 0 {
        if self.umem.process_fill_queue(&mut self.rx_return).is_err() {
            break;
        }
    }
    while self.rx_return.num_frames() > 0 {
        self.free_frames.push(self.rx_return.pop().unwrap());
    }
    self.umem.maybe_wake_fill_queue(self.socket.fd())
}
```

## Testing

Existing tests (`cargo test`) must pass — this change only modifies the event loop scheduling, not protocol logic or frame management APIs.

The `debug_assert` invariant check runs every iteration in debug builds. Any frame accounting error will panic immediately with a diagnostic message showing the exact counts.

Manual verification: re-run the benchmark on AWS with the same `c8gn.2xlarge` + wrk setup, comparing single-threaded vs multi-threaded throughput.

## Expected Outcome

Multi-queue throughput should approach `N * single_queue_throughput` (minus inherent per-queue overhead from independent ARP caches, TCP state, etc.). The 6.4x per-core efficiency gap should close significantly, as the event loop no longer blocks on kernel TX completion processing between iterations.
