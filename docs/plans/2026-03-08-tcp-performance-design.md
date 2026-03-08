# TCP Performance Optimization — Design

**Date:** 2026-03-08
**Goal:** Improve TCP echo throughput from ~400K pkt/s to millions of pkt/s
**Approach:** Eliminate per-packet syscalls, redundant computations, and heap allocations in hot paths

## Current Bottlenecks

1. **`Instant::now()` per packet** — `process_ipv4()` and `process_ipv6()` in `inbound.rs:68,183` call `Instant::now()` on every incoming TCP segment. The runtime loop already caches `now` and passes it to IPv4/IPv6 handlers, but those handlers call the no-`now` TCP variants instead of threading it through.

2. **Repeated `duration_since().as_millis()` computation** — ~20+ identical calls to `now.duration_since(tcb.ts_offset).as_millis() as u32` throughout the TCP state machine for timestamp option generation. Each packet computes this multiple times across branches.

3. **Vec allocations in hot paths** — `timers.rs:77,219` allocate `Vec<usize>` for removal indices. `inbound.rs:1498` allocates `Vec<(u32, u32)>` for SACK blocks (max 4 per RFC).

4. **Connection creation calls `Instant::now()` 4 times** — `connection.rs:99,127,133,134` for retransmit_deadline, last_activity, ts_recent_age, ts_offset.

## Changes

### 1. Pass `now` through IPv4/IPv6 → TCP dispatch
- `ipv4.rs:109` — call `process_ipv4_with_now(..., now, ...)` instead of `process_ipv4(...)`
- `ipv6.rs:222` — call `process_ipv6_with_now(..., now, ...)` instead of `process_ipv6(...)`

### 2. Rename `_with_now` to primary API
- Rename `process_ipv4_with_now` → `process_ipv4`, `process_ipv6_with_now` → `process_ipv6`
- Remove the old no-`now` wrappers (or keep only for test convenience)

### 3. Pre-compute `tsval` once per segment
- After connection lookup in `process_segment()`, compute `tsval` once
- Thread pre-computed value into `process_established`, `process_syn_received`, etc.
- Replace all ~20 inline `now.duration_since(tcb.ts_offset).as_millis() as u32` calls

### 4. Stack arrays for small collections
- `timers.rs:77` — delayed ACK removals: `[usize; 64]` + count
- `timers.rs:219` — RTO removals: `[usize; 64]` + count
- `inbound.rs:1498` — SACK blocks: `[(u32, u32); 4]` + count (RFC max is 4)

### 5. Pass `now` into connection constructors
- Add `now: Instant` parameter to `new_client` and passive-open constructor
- Replace 4x `Instant::now()` with the passed-in value
- Update callers in `inbound.rs` and `connect()` paths

## Out of Scope
- Connection lookup optimization (Vec → HashMap) — deferred
- Ring buffer copies — unavoidable for payload transfer
- Checksum offload — already wired in for both RX and TX
