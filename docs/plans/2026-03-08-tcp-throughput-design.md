# TCP Throughput Optimization — Design

**Date:** 2026-03-08
**Goal:** Improve TCP echo throughput from ~560K pkt/s toward 2–5M pkt/s (64B payload over VETH pair)
**Context:** UDP echo achieves 11M pkt/s on the same setup. TCP will never match UDP due to
reliability guarantees, but a 20x gap indicates structural inefficiency.

## Root Cause Analysis

### Data Copy Overhead (4 copies per echo vs 0 for UDP)

UDP echo calls `swap_addresses()` in-place and pushes the same frame to TX — zero copies.
TCP echo does 4 memcpys per round trip:

1. **RX frame → recv_buffer** (`recv_buffer.write(payload)` in `process_established`)
2. **recv_buffer → user buf** (`recv_buffer.read(buf)` in `TcpRead::poll`)
3. **user buf → send_buffer** (`send_buffer.write(data)` in `TcpWrite::poll`)
4. **send_buffer → TX frame** (via `peek_slices` → `build_data_from_slices` in `poll_send`)

Copies #2 and #3 are redundant for echo — data goes from one ring buffer to user stack and
immediately back to another ring buffer.

### Redundant TCP Options Parsing

`parse_timestamp(options)` is called 3 times in `process_established`:
- Line 998: PAWS check
- Line 1138: `ts_recent` update
- Line 1203: RTT measurement

Each call re-scans the options byte array. Should be parsed once.

### Software Checksum on VETH

VETH pairs report checksum offload as disabled. Both RX verification and TX computation
are done in software per-packet. The RX checksum verification is particularly wasteful —
VETH is a virtual device; frames are never corrupted in transit.

### Instruction Cache Pressure

`process_established` is ~556 lines with many rarely-taken branches (RST handling, SYN-in-
established, PAWS rejection, OOO data, SACK recovery). The hot path (in-order data + valid
ACK) executes ~20% of the code but the entire function must be loaded into L1i cache.

### Connection Lookup in TcpRead/TcpWrite

Every `TcpRead::poll` and `TcpWrite::poll` calls `get_connection_mut(&self.conn_id)` which
does a linear scan of `Vec<Tcb>`. For echo, this means 2 extra O(n) lookups per packet on
top of the inbound lookup. With n=1 the cost is small, but it's still unnecessary work.

### Tcb Cache Line Layout

The `Tcb` struct is ~500+ bytes (metadata, not counting ring buffer backing). Hot fields
(`rcv_nxt`, `snd_nxt`, `snd_una`, `ack_pending`, buffer metadata) are scattered across
multiple cache lines. Each access to a cold field evicts hot data from L1d.

## Proposed Changes

### 1. Consolidated TCP Options Parsing

Parse all TCP options once at the top of `process_segment` after connection lookup, before
dispatching to `process_established`/etc. Store results in a stack struct:

```rust
struct ParsedOptions {
    timestamp: Option<(u32, u32)>,  // (tsval, tsecr)
    mss: Option<u16>,
    window_scale: Option<u8>,
    sack_permitted: bool,
    sack_blocks: ([(u32, u32); 4], usize),  // (blocks, count)
}
```

Pass `&ParsedOptions` to all state handlers. Eliminates 2 redundant `parse_timestamp`
calls per established-state packet.

### 2. Fast-Path for Established State

Add a fast-path branch at the top of `process_established` for the common case:
- ACK set, no RST/SYN/FIN flags
- In-order data (seg_seq == rcv_nxt)
- Valid new ACK (snd_una < seg_ack <= snd_nxt)
- No PAWS rejection
- Not in recovery

The fast path combines ACK advancement + data write + delayed ACK logic in a single
streamlined block, skipping the 11+ branch checks in the slow path. The slow path
remains for correctness on rare cases.

Estimated savings: ~100–150ns per packet.

### 3. RingBuffer::transfer() for Splice

Add a method to transfer data directly between ring buffers:

```rust
impl RingBuffer {
    /// Transfer up to `max_len` bytes from self to `dst` without intermediate copy.
    /// Returns the number of bytes transferred.
    pub fn transfer(&mut self, dst: &mut RingBuffer, max_len: usize) -> usize;
}
```

And a corresponding `TcpStream::splice()` API:

```rust
impl TcpStream {
    /// Transfer data from recv_buffer directly to send_buffer.
    /// Eliminates 2 copies vs read() + write().
    pub fn splice(&self, max_len: usize) -> Splice<'_>;
}
```

This eliminates copies #2 and #3 for echo-like workloads. The echo server becomes:
```rust
loop {
    let n = stream.splice(65535).await?;
    stats.update(n, false);
}
```

### 4. Checksum Bypass for Loopback/VETH

For virtual devices (VETH, lo), frames cannot be corrupted in transit. Add an option to
skip RX checksum verification when the NIC is virtual:

```rust
impl LocalRuntimeBuilder {
    /// Skip RX checksum verification. Safe for VETH/loopback where frames
    /// can't be corrupted. Unsafe for physical NICs.
    pub fn skip_rx_checksum(mut self, skip: bool) -> Self;
}
```

For TX, software checksums are still needed because the peer's stack verifies them. But
we could add a `skip_tx_checksum` option for testing/benchmarking when both sides are
ours.

### 5. Tcb Hot/Cold Field Splitting

Reorder `Tcb` fields to group frequently-accessed fields in the first 2 cache lines (128B):

**Cache line 1 (hot — accessed every packet):**
`rcv_nxt`, `snd_nxt`, `snd_una`, `snd_wnd`, `state`, `ack_pending`, `ack_delay_count`,
`ts_enabled`, `sack_enabled`, `ecn_enabled`, `eff_snd_mss`

**Cache line 2 (warm — accessed most packets):**
`recv_buffer` metadata (head, tail, len, mask — not the backing Vec ptr),
`send_buffer` metadata, `id` (for equality checks), `ts_recent`, `delayed_ack_deadline`

**Remaining (cold — rarely accessed):**
Keep-alive fields, linger, time_wait, congestion control state, recovery state,
SACK scoreboard, OOO ranges, F-RTO state

### 6. Eliminate Connection Lookup in Socket API

Cache a connection index in `TcpStream` and validate on access:

```rust
struct TcpStream {
    conn_id: ConnectionId,
    cached_idx: Cell<usize>,  // cached index, revalidated on use
    // ...
}
```

On `TcpRead::poll` / `TcpWrite::poll`, check if `connections[cached_idx].id == conn_id`.
If yes, skip the linear scan. If not (connection moved due to removal), fall back to
linear scan and update cache. For echo with n=1, this saves 2 linear scans per packet.

### 7. Separate Hot/Cold Paths with #[inline] Hints

Mark rarely-taken branches in `process_established` with `#[cold]` or extract them into
`#[inline(never)]` helper functions:

- RST handling → `handle_rst_in_established()`
- SYN-in-established (challenge ACK) → `handle_syn_in_established()`
- PAWS rejection → `handle_paws_rejection()`
- Out-of-order data → `handle_ooo_data()`
- Duplicate data → `handle_duplicate_data()`
- SACK recovery entry → `enter_sack_recovery()`

The hot path (in-order data + valid ACK) stays inline. Cold paths are outlined to reduce
instruction cache pressure.

### 8. Pre-compute Immutable Per-Connection Values

Several values are recomputed on every packet but don't change within a connection's
established state:
- `ack_flags` (depends on `ecn_ce_received` which changes rarely)
- `id` fields (never change)
- Timestamp option offset in the options buffer (fixed after SYN exchange)

Cache these in the Tcb or compute once per `process_segment` call.

## Performance Budget

At 2M pkt/s per side: 500ns per packet. Minus XDP baseline (~45ns): **455ns for TCP.**

| Component | Current (est.) | After optimization | Savings |
|-----------|---------------|-------------------|---------|
| process_established | 300–400ns | 150–200ns | 150ns |
| Ring buffer copies (4→2) | 60ns | 30ns | 30ns |
| RX checksum (skip on VETH) | 40ns | 0ns | 40ns |
| Options parsing (3→1) | 15ns | 5ns | 10ns |
| Socket API lookups (2→0) | 10ns | 2ns | 8ns |
| poll_send | 96ns | 80ns | 16ns |
| Segment building | 100ns | 90ns | 10ns |
| Tcb cache improvement | — | — | 50–100ns |
| **Total** | **~845ns** | **~400–500ns** | **~400ns** |

Expected result: **1.5–2.5M pkt/s** (3–4.5x improvement).

## Out of Scope

- **Connection lookup optimization (Vec → HashMap)** — Deferred; n=1 for echo benchmark.
- **Zero-copy frame echo** — Would require rewriting headers in-place on the RX frame
  and resubmitting it, breaking the frame ownership model. Not worth the complexity.
- **Async runtime overhead** — The no-op waker + poll pattern is already minimal.
- **CUBIC optimization** — Floating-point arithmetic only runs in congestion avoidance;
  echo benchmark stays in slow start (no losses on VETH).

## Implementation Order

1. Consolidated options parsing (low risk, clear improvement)
2. Checksum bypass for VETH (low risk, measurable improvement)
3. Fast-path in process_established (medium risk, biggest improvement)
4. RingBuffer::transfer() + TcpStream::splice() (medium risk, API addition)
5. Tcb field reordering (low risk, cache improvement)
6. Connection index caching in TcpStream (low risk)
7. Cold path extraction with #[inline(never)] (low risk)
8. Pre-compute immutable values (low risk)
