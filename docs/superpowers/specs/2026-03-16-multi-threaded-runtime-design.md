# Multi-Threaded Runtime Design

## Overview

Extend the existing `src/rt/` runtime to support multi-threaded, thread-per-queue packet processing. A new `Runtime` orchestrator automatically discovers all hardware queues on an interface and spawns one worker thread per queue, each running an independent `LocalRuntime` with its own UMEM, socket, and protocol state.

## Architecture

### Shared-Nothing, Thread-Per-Queue

Each worker thread is fully independent — no shared state, no synchronization on the hot path. The existing `LocalRuntime` is unchanged and serves as the per-thread event loop. A new `Runtime` type sits on top as an orchestrator.

```
Main Thread                     Worker Threads
┌─────────────────┐
│  Runtime         │
│  ┌─────────────┐ │        ┌──────────────────┐
│  │ XdpContext   │ │   ┌──▶│ Thread 0          │
│  │ (BPF prog)  │ │   │   │  LocalRuntime     │
│  └─────────────┘ │   │   │  Umem + Socket (Q0)│
│                   │   │   │  Protocol Handlers │
│  Phase 1: Setup  │───┤   └──────────────────┘
│  Phase 2: Spawn  │   │   ┌──────────────────┐
│  Phase 3: Join   │   ├──▶│ Thread 1          │
│                   │   │   │  LocalRuntime     │
└─────────────────┘   │   │  Umem + Socket (Q1)│
                       │   │  Protocol Handlers │
                       │   └──────────────────┘
                       │   ┌──────────────────┐
                       └──▶│ Thread N          │
                           │  ...              │
                           └──────────────────┘
```

### Why Shared-Nothing

- No contention, no locks on the hot path
- RSS pins flows to hardware queues, so TCP/UDP connections are naturally queue-affine
- Each thread's protocol state (TCP state machine, UDP reassembly, ARP/NDP cache, PMTU cache) operates independently
- UMEM is tied to its queue and cannot be shared across queues

### Future Consideration: Shared NeighborHandler

ARP/NDP caches will be duplicated across threads. If duplicate resolution becomes a measurable issue, `NeighborHandler` storage can be migrated to a `DashMap` for cross-thread sharing. This is not part of the initial design — shared-nothing first, optimize later if needed.

## Queue Discovery

Extend `src/netlink/ethtool.rs` to query the combined RX/TX channel count via ethtool generic netlink (`ETHTOOL_MSG_CHANNELS_GET`). This returns the number of hardware queues available on the interface.

The `RuntimeBuilder` uses this to determine how many threads to spawn:

```rust
// Auto-discover all queues
let rt = Runtime::builder("eth0").build()?;

// Explicit queue list (no ethtool query)
let rt = Runtime::builder("eth0").queues(&[0, 2, 3]).build()?;

// Cap thread count (discover total, clamp)
let rt = Runtime::builder("eth0").max_queues(4).build()?;
```

If the user specifies queues explicitly, no ethtool query is needed. If they specify `max_queues`, the runtime discovers the total and clamps to the lesser value. Setting both `queues` and `max_queues` is an error — they are mutually exclusive.

**Fallback on ethtool failure:** If the ethtool channel query fails (e.g., the driver does not support it, or the interface is virtual like veth), the runtime defaults to 1 queue. This ensures testing environments work without special configuration.

## BPF Program Rework

The current BPF program (`bpf/xdp_kern.c`) uses per-CPU round-robin to distribute packets across sockets. This must change to deterministic queue-to-socket routing.

### Current Behavior

```c
// Round-robin across registered sockets
unsigned int *rr_ptr = bpf_map_lookup_elem(&rr_map, &rr_key);
*rr_ptr = (*rr_ptr + 1) % num_socks;
return bpf_redirect_map(&xsks_map, *rr_ptr, XDP_ABORTED);
```

### New Behavior

```c
SEC("xdp_sock")
int xdp_sock_prog(struct xdp_md *ctx) {
    unsigned int qid = ctx->rx_queue_index;
    return bpf_redirect_map(&xsks_map, qid, XDP_PASS);
}
```

Key changes:
- `ctx->rx_queue_index` gives the hardware queue that received the packet
- Socket registration in `xsks_map` is indexed by queue ID (slot 0 = queue 0's socket, etc.)
- `XDP_PASS` as the fallback flag: if `xsks_map[qid]` has no registered socket, the packet passes through to the kernel stack — unbound queues behave as if voidnet isn't there
- The `rr_map`, round-robin logic, `num_socks` counter, and the fast-path are all removed
- On the userspace side, the `.bss` data map update in `register_socket` and the `data_map` field on `XdpContext` become dead code and should be removed
- Sparse map: if the user binds queues 0, 2, 3 (skipping 1), slot 1 is empty and packets on queue 1 fall through to `XDP_PASS`
- The existing `xsks_map` has `max_entries = 2048`, which covers all practical hardware. Userspace should assert that queue IDs are within this bound
- Keep the existing BPF section name `"xdp_sock"` to avoid churn in the loading code

### Hard Invariant

Packets received on hardware queue N must be processed by the socket bound to queue N. There is no copying or redistribution between queues.

## Two-Phase Setup

### Phase 1: Setup (Main Thread)

1. Query ethtool for queue count (or use user-specified list)
2. Create single `XdpContext` for the interface
3. For each queue ID in order:
   a. Create a `Umem` with the builder config
   b. Create a `Socket` bound to that queue
   c. Register socket in `xsks_map` at index = queue ID (sparse, via updated `register_socket` that accepts an explicit map index)
4. All setup is sequential and deterministic — no races, no coordination
5. If any step fails, already-created resources are dropped via normal Rust ownership. Stale `xsks_map` entries for already-registered sockets remain until `XdpContext` is dropped, which happens immediately on early return — this is safe since no workers have started.

**Socket registration call site:** Currently `register_socket` is called inside `Socket::new`. For the multi-threaded runtime, registration must use the queue ID as the map index (not an auto-incrementing counter). The `register_socket` method will be updated to accept an explicit index parameter, and `Socket::new` will pass through the queue ID it already knows.

### Phase 2: Run (Worker Threads)

1. Create shared `Arc<AtomicBool>` exit flag
2. Spawn one `std::thread` per queue, named `voidnet-q{N}` for debuggability
3. Each thread receives: its `Socket`, `Umem`, queue ID, exit flag clone, builder config
4. The factory closure is called on the worker thread (not the main thread). The closure must be `Fn(u32) -> Fut + Send + Sync + 'static` since it is shared across threads via `Arc`.
5. Each thread pins to its core via `pin_core(queue_id)`. If queue_id >= num_cores, pinning wraps around (`queue_id % num_cores`).
6. Each thread constructs a `LocalRuntime` from its components and calls `run(exit, factory(queue_id))`
7. Main thread joins all handles, collects results

Note: There is a brief window between socket registration (Phase 1) and the first `recv` call (Phase 2) where packets may buffer in the RX ring. This is expected and absorbed by the ring buffers.

### XdpContext Ownership

`XdpContext` owns the BPF program lifecycle — dropping it detaches the program. The `Runtime` orchestrator retains ownership of `XdpContext` on the main thread. Worker threads do NOT receive the `XdpContext`. The internal `LocalRuntime` constructor used by `Runtime` will not take an `XdpContext` parameter — the existing `LocalRuntime::new` (which takes one) remains for the standalone single-queue API.

### LocalRuntime Constructor

`LocalRuntime` needs an internal constructor that accepts pre-built components (socket, umem, config) without an `XdpContext`. The most intuitive approach will be chosen during implementation — either a second internal constructor or refactoring `LocalRuntime::new` to accept pre-built parts.

## Error Handling & Shutdown

### Exit Coordination

- `Runtime` creates one `Arc<AtomicBool>` shared across all threads
- Each thread's event loop checks it every iteration (already the case in `LocalRuntime::run`)

### First-Failure Propagation

- If a thread's `LocalRuntime::run` returns `Err`, it sets the exit flag before the thread exits
- All other threads see the flag on their next iteration and wind down

### Join & Result Collection

- Main thread calls `join()` on all thread handles
- Thread panics are caught by `join()` and surfaced as errors
- Returns the first error encountered, or `Ok(())` if all threads exited cleanly

## Public API

### New Types

**`Runtime`** — Multi-threaded orchestrator.

**`RuntimeBuilder`** — Builder with the same configuration surface as `LocalRuntimeBuilder` plus queue selection:

```rust
let rt = Runtime::builder("eth0")
    .attach_mode(AttachMode::Skb)
    .busy_poll(true)
    .busy_poll_timeout_us(100)
    .rx_ring_size(4096)
    .tx_ring_size(4096)
    .frame_size(4096)
    .fill_ring_size(4096)
    .completion_ring_size(4096)
    .huge_tables(true)
    .unaligned(false)
    .enable_fragmentation(true)
    .arp_ttl(Duration::from_secs(120))
    .queues(&[0, 1, 2, 3])    // optional: explicit queue list
    .max_queues(4)             // optional: cap thread count
    .build()?;
```

**`Runtime::run`** — Takes an exit flag and a factory closure:

```rust
rt.run(exit, |queue_id: u32| async move {
    let socket = UdpSocket::bind("0.0.0.0:9000").await?;
    loop {
        let (data, addr) = socket.recv_from().await?;
        socket.send_to(&data, addr).await?;
    }
})?;
```

The factory closure must be `Fn(u32) -> Fut + Send + Sync + 'static` (shared across threads via `Arc`). The returned future must be `'static` but does not need to be `Send` or `Sync` — it is created and polled on a single thread.

### Unchanged Types

- `LocalRuntime` / `LocalRuntimeBuilder` — still available for single-queue use, no API changes
- All protocol handlers, context system, waker, task queue, frame buffers — unchanged

## Pre-Existing Issues to Fix

These are not introduced by this design but become more visible or impactful in the multi-threaded case:

- **`ContextDropGuard` memory leak:** `ContextDropGuard::new` calls `Box::into_raw` but the `Drop` impl only nulls the pointer — it never calls `Box::from_raw` to deallocate. This leaks once per thread. Fix during implementation.
- **`println!` in `LocalRuntime::new`:** Line 216 of `local.rs` prints interface info on every construction. With N threads, this prints N times. Should be moved to the orchestrator or removed.

## Files Changed

| File | Change |
|------|--------|
| `src/netlink/ethtool.rs` | Add `get_queue_count()` via `ETHTOOL_MSG_CHANNELS_GET` |
| `bpf/xdp_kern.c` | Replace round-robin with `rx_queue_index` routing, `XDP_PASS` fallback, remove `rr_map`/`num_socks` |
| `src/xdp/context/ctx.rs` | Update `register_socket` to accept explicit map index; remove `data_map` and `.bss` update |
| `src/rt/mod.rs` | Export new `Runtime` and `RuntimeBuilder` types |
| `src/rt/runtime.rs` (new) | `Runtime`, `RuntimeBuilder`, two-phase setup, thread management |
| `src/rt/local.rs` | Add internal constructor for pre-built components (without `XdpContext`) |
| `src/rt/context.rs` | Fix `ContextDropGuard` memory leak |
| `src/rt/affinity.rs` | Add modular wrapping for `pin_core` when queue_id >= num_cores |
