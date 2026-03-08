# TCP Performance Optimization — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Eliminate per-packet syscalls, redundant timestamp computations, and heap allocations from TCP hot paths to reach millions of pkt/s for TCP echo.

**Architecture:** Pure refactoring — no behavioral changes. Thread the runtime loop's cached `now` through the dispatch chain, pre-compute repeated timestamp values, replace Vec allocations with stack arrays. All existing tests must continue to pass unchanged.

**Tech Stack:** Rust, coarsetime::Instant, AF_XDP (libvoid)

---

### Task 1: Wire `now` through IPv4/IPv6 → TCP dispatch

**Files:**
- Modify: `src/net/handler/ipv4.rs:107-110`
- Modify: `src/net/handler/ipv6.rs:221-224`

The IPv4/IPv6 handlers already receive `now` from the runtime loop but call the no-`now` TCP variants. Fix both dispatch sites.

**Step 1: Update IPv4 handler to pass `now`**

In `src/net/handler/ipv4.rs`, change line 108-110 from:

```rust
IpProtocols::Tcp => {
    tcp_handler.process_ipv4(frame, neighbor_handler, free_frames, rx_return, tx_return)
}
```

to:

```rust
IpProtocols::Tcp => {
    tcp_handler.process_ipv4_with_now(frame, now, neighbor_handler, free_frames, rx_return, tx_return)
}
```

**Step 2: Update IPv6 handler to pass `now`**

In `src/net/handler/ipv6.rs`, change lines 222-224 from:

```rust
IpProtocols::Tcp => {
    tcp_handler.process_ipv6(
        frame, payload_offset, neighbor_handler, free_frames, rx_return, tx_return,
    );
}
```

to:

```rust
IpProtocols::Tcp => {
    tcp_handler.process_ipv6_with_now(
        frame, payload_offset, now, neighbor_handler, free_frames, rx_return, tx_return,
    );
}
```

**Step 3: Run tests**

```bash
cargo test
```

Expected: all tests pass (behavioral no-op — same `Instant` type, just sourced from caller instead of inline).

**Step 4: Commit**

```bash
git add src/net/handler/ipv4.rs src/net/handler/ipv6.rs
git commit -m "perf(tcp): pass cached now through IPv4/IPv6 dispatch to TCP"
```

---

### Task 2: Remove no-`now` wrappers, rename `_with_now` to primary API

**Files:**
- Modify: `src/net/handler/tcp/inbound.rs:57-74` (remove `process_ipv4`)
- Modify: `src/net/handler/tcp/inbound.rs:76-85` (rename `process_ipv4_with_now` → `process_ipv4`)
- Modify: `src/net/handler/tcp/inbound.rs:170-189` (remove `process_ipv6`)
- Modify: `src/net/handler/tcp/inbound.rs:191-200` (rename `process_ipv6_with_now` → `process_ipv6`)
- Modify: `src/net/handler/ipv4.rs` (update call from `process_ipv4_with_now` → `process_ipv4`)
- Modify: `src/net/handler/ipv6.rs` (update call from `process_ipv6_with_now` → `process_ipv6`)
- Modify: any test files that call `process_ipv4_with_now` or `process_ipv6_with_now`

**Step 1: Remove the no-`now` `process_ipv4` wrapper (lines 57-74)**

Delete the entire `process_ipv4` method that calls `Instant::now()`.

**Step 2: Rename `process_ipv4_with_now` → `process_ipv4`**

Change the method name and doc comment. The signature stays the same (with `now: Instant`).

**Step 3: Remove the no-`now` `process_ipv6` wrapper (lines 170-189)**

Delete the entire `process_ipv6` method that calls `Instant::now()`.

**Step 4: Rename `process_ipv6_with_now` → `process_ipv6`**

Change the method name and doc comment. The signature stays the same (with `now: Instant`).

**Step 5: Update callers**

- `src/net/handler/ipv4.rs`: `process_ipv4_with_now(` → `process_ipv4(`
- `src/net/handler/ipv6.rs`: `process_ipv6_with_now(` → `process_ipv6(`
- Search all test files under `src/net/handler/tcp/tests/` for `process_ipv4_with_now` and `process_ipv6_with_now` and rename to `process_ipv4` / `process_ipv6`.

**Step 6: Run tests**

```bash
cargo test
```

Expected: all pass.

**Step 7: Commit**

```bash
git add src/net/handler/tcp/inbound.rs src/net/handler/ipv4.rs src/net/handler/ipv6.rs src/net/handler/tcp/tests/
git commit -m "refactor(tcp): rename process_*_with_now to process_*, remove wrappers"
```

---

### Task 3: Add `Tcb::ts_option()` helper, pre-compute tsval in inbound.rs

**Files:**
- Modify: `src/net/handler/tcp/tcb.rs` (add helper method)
- Modify: `src/net/handler/tcp/inbound.rs` (replace ~21 inline tsval blocks)

The pattern `let ts = if tcb.ts_enabled { let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32; Some((tsval, tcb.ts_recent)) } else { None };` appears 21 times in inbound.rs alone. The `tsval` portion is constant for a given `(now, tcb.ts_offset)` pair. `ts_recent` varies as the segment is processed so it must be read at the point of use.

**Step 1: Add `ts_option` helper to Tcb**

In `src/net/handler/tcp/tcb.rs`, add to the `impl Tcb` block:

```rust
/// Build the timestamp option tuple using a pre-computed tsval.
/// `ts_recent` is read at call time since it may change during segment processing.
#[inline(always)]
pub(super) fn ts_option(&self, tsval: u32) -> Option<(u32, u32)> {
    if self.ts_enabled {
        Some((tsval, self.ts_recent))
    } else {
        None
    }
}
```

**Step 2: Pre-compute tsval after connection lookup in process_segment**

In `src/net/handler/tcp/inbound.rs`, after the connection lookup at line 314 (`if let Some(idx) = self.connections.iter().position(...)`), compute tsval once:

```rust
let tsval = if self.connections[idx].ts_enabled {
    now.duration_since(self.connections[idx].ts_offset).as_millis() as u32
} else {
    0
};
```

Then thread `tsval` into `process_established`, `process_syn_sent`, `process_syn_received`, and `process_teardown` as an additional parameter.

**Step 3: Replace all inline tsval blocks in inbound.rs**

In each sub-function, replace every occurrence of:

```rust
let ts = if tcb.ts_enabled {
    let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
    Some((tsval, tcb.ts_recent))
} else {
    None
};
```

with:

```rust
let ts = tcb.ts_option(tsval);
```

Also replace the one variant at line 1274:

```rust
let our_ts = now.duration_since(tcb.ts_offset).as_millis() as u32;
```

with just `tsval` (already computed).

There are 21 occurrences in inbound.rs to replace. The exact lines are: 680-685, 730-733, 926-929, 967-970, 1062-1065, 1101-1104, 1141-1144, 1170-1173, 1274, 1346-1349, 1448-1451, 1490-1494, 1533-1537, 1574-1577, 1641-1644, 1680-1683, 1723-1726, 1752-1755, 1851-1854, 1901-1904, 1966-1969.

**Step 4: Update sub-function signatures**

Add `tsval: u32` parameter to:
- `process_established()`
- `process_syn_sent()`
- `process_syn_received()`
- `process_teardown()`

**Step 5: Run tests**

```bash
cargo test
```

Expected: all pass.

**Step 6: Commit**

```bash
git add src/net/handler/tcp/tcb.rs src/net/handler/tcp/inbound.rs
git commit -m "perf(tcp): pre-compute tsval once per segment, add Tcb::ts_option()"
```

---

### Task 4: Pre-compute tsval in transmit.rs and timers.rs

**Files:**
- Modify: `src/net/handler/tcp/transmit.rs` (3 occurrences)
- Modify: `src/net/handler/tcp/timers.rs` (7 occurrences)

**Step 1: Pre-compute tsval per-connection in transmit.rs poll_send**

In the `for tcb in &mut self.connections` loop (line 23), compute tsval once at the top of the loop body after the state check:

```rust
let tsval = if tcb.ts_enabled {
    now.duration_since(tcb.ts_offset).as_millis() as u32
} else {
    0
};
```

Replace the 3 inline computations at lines 96, 182, 259 with `tcb.ts_option(tsval)`.

**Step 2: Pre-compute tsval per-connection in timers.rs poll_timers**

In each timer pass loop (`for tcb in &mut self.connections` or `for (i, tcb) in ...`), compute tsval once at the top after the `continue` guard:

```rust
let tsval = if tcb.ts_enabled {
    now.duration_since(tcb.ts_offset).as_millis() as u32
} else {
    0
};
```

Replace the 7 inline computations at lines 43, 106, 184, 256, 287, 317, 353 with `tcb.ts_option(tsval)`.

**Step 3: Run tests**

```bash
cargo test
```

Expected: all pass.

**Step 4: Commit**

```bash
git add src/net/handler/tcp/transmit.rs src/net/handler/tcp/timers.rs
git commit -m "perf(tcp): pre-compute tsval in transmit and timer loops"
```

---

### Task 5: Replace Vec allocations with stack arrays

**Files:**
- Modify: `src/net/handler/tcp/inbound.rs:1498` (SACK blocks)
- Modify: `src/net/handler/tcp/timers.rs:77` (keep-alive removals)
- Modify: `src/net/handler/tcp/timers.rs:219` (RTO removals)

**Step 1: Replace SACK blocks Vec with stack array**

In `src/net/handler/tcp/inbound.rs`, replace at line 1497-1511:

```rust
let max_blocks = if tcb.ts_enabled { 3 } else { 4 };
let mut sack_blocks: Vec<(u32, u32)> = Vec::new();
if tcb.sack_enabled {
    sack_blocks.push((seg_seq, seg_seq.wrapping_add(payload_len as u32)));
    for (&start, &len) in tcb.ooo_ranges.iter().rev() {
        if sack_blocks.len() >= max_blocks {
            break;
        }
        let end = start.wrapping_add(len);
        if start != seg_seq {
            sack_blocks.push((start, end));
        }
    }
}
```

with:

```rust
let max_blocks = if tcb.ts_enabled { 3 } else { 4 };
let mut sack_buf = [(0u32, 0u32); 4];
let mut sack_count = 0usize;
if tcb.sack_enabled {
    sack_buf[0] = (seg_seq, seg_seq.wrapping_add(payload_len as u32));
    sack_count = 1;
    for (&start, &len) in tcb.ooo_ranges.iter().rev() {
        if sack_count >= max_blocks {
            break;
        }
        let end = start.wrapping_add(len);
        if start != seg_seq {
            sack_buf[sack_count] = (start, end);
            sack_count += 1;
        }
    }
}
let sack_blocks = &sack_buf[..sack_count];
```

Update the `build_ack_with_sack` call to use `sack_blocks` (it already takes `&[(u32, u32)]` so this is a drop-in replacement).

**Step 2: Replace keep-alive removals Vec with stack array**

In `src/net/handler/tcp/timers.rs`, replace line 77:

```rust
let mut keep_alive_removals: Vec<usize> = Vec::new();
```

with:

```rust
let mut keep_alive_removals = [0usize; 64];
let mut keep_alive_removal_count = 0usize;
```

Replace `keep_alive_removals.push(i)` (line 96) with:

```rust
if keep_alive_removal_count < 64 {
    keep_alive_removals[keep_alive_removal_count] = i;
    keep_alive_removal_count += 1;
}
```

Replace the removal loop (line 138) from:

```rust
for idx in keep_alive_removals.into_iter().rev() {
```

to:

```rust
for &idx in keep_alive_removals[..keep_alive_removal_count].iter().rev() {
```

**Step 3: Replace RTO removals Vec with stack array**

In `src/net/handler/tcp/timers.rs`, replace line 219:

```rust
let mut to_remove = Vec::new();
```

with:

```rust
let mut to_remove = [0usize; 64];
let mut to_remove_count = 0usize;
```

Replace `to_remove.push(idx)` (line 243) with:

```rust
if to_remove_count < 64 {
    to_remove[to_remove_count] = idx;
    to_remove_count += 1;
}
```

Find the removal loop that iterates `to_remove` in reverse and update it to use `to_remove[..to_remove_count].iter().rev()`.

**Step 4: Run tests**

```bash
cargo test
```

Expected: all pass.

**Step 5: Commit**

```bash
git add src/net/handler/tcp/inbound.rs src/net/handler/tcp/timers.rs
git commit -m "perf(tcp): replace Vec allocations with stack arrays in hot paths"
```

---

### Task 6: Pass `now` into active-open connection constructor

**Files:**
- Modify: `src/net/handler/tcp/connection.rs:52-63` (add `now` parameter to `connect_with_config`)
- Modify: `src/net/handler/tcp/connection.rs:27-49` (add `now` parameter to `connect`)
- Modify: `src/net/socket/tcp.rs:183-221` (pass `now` from caller)

**Step 1: Add `now: Instant` parameter to `connect_with_config`**

In `src/net/handler/tcp/connection.rs`, add `now: Instant` after `dst_mac` in the `connect_with_config` signature.

Replace the 4 `Instant::now()` calls inside:
- Line 99: `Instant::now() + coarsetime::Duration::from_millis(INITIAL_RTO_MS)` → `now + coarsetime::Duration::from_millis(INITIAL_RTO_MS)`
- Line 127: `last_activity: Instant::now()` → `last_activity: now`
- Line 133: `ts_recent_age: Instant::now()` → `ts_recent_age: now`
- Line 134: `ts_offset: Instant::now()` → `ts_offset: now`

**Step 2: Add `now: Instant` parameter to `connect` wrapper**

Pass it through to `connect_with_config`.

**Step 3: Update callers in `src/net/socket/tcp.rs`**

In `TcpStream::connect()` (line 190), change `Instant::now()` to a single `let now = Instant::now();` and pass it to both `neighbor_handler.lookup(now, ...)` and `handler.connect(..., now, ...)`.

Same for `TcpStream::connect_with_config()` (line 244).

Note: These are called once at connection setup, not per-packet. The `Instant::now()` here is acceptable but we consolidate to a single call for consistency.

**Step 4: Run tests**

```bash
cargo test
```

Expected: all pass.

**Step 5: Commit**

```bash
git add src/net/handler/tcp/connection.rs src/net/socket/tcp.rs
git commit -m "perf(tcp): pass now into active-open constructor, eliminate 4x Instant::now()"
```

---

### Task 7: Final verification

**Step 1: Run full test suite**

```bash
cargo test
```

Expected: all pass with zero behavioral changes.

**Step 2: Verify no remaining hot-path `Instant::now()` calls**

```bash
# Should only find test files and the ISN generator (cold path)
grep -rn "Instant::now()" src/net/handler/tcp/ --include="*.rs" | grep -v tests | grep -v isn.rs
```

Expected: only `connection.rs` `initiate_close` (cold path, linger timeout) should remain.

**Step 3: Commit any final cleanup**

---

## Summary of Eliminated Overhead

| What | Before | After |
|------|--------|-------|
| `Instant::now()` per packet | 1 call per TCP segment | 0 (uses runtime cached `now`) |
| `duration_since().as_millis()` per segment | ~21 calls in inbound.rs | 1 per segment |
| `duration_since().as_millis()` in transmit | 3 per connection per tick | 1 per connection per tick |
| `duration_since().as_millis()` in timers | 7 per connection per tick | 1 per connection per tick |
| Vec allocation (SACK blocks) | 1 per OOO segment | 0 (stack `[_; 4]`) |
| Vec allocation (keep-alive removals) | 1 per timer tick | 0 (stack `[_; 64]`) |
| Vec allocation (RTO removals) | 1 per timer tick | 0 (stack `[_; 64]`) |
| `Instant::now()` per connect | 4 calls | 0 (uses passed `now`) |
