# TCP Throughput Optimization — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Improve TCP echo throughput from ~560K pkt/s toward 2–5M pkt/s over VETH

**Architecture:** Consolidate option parsing, add fast-path for established state, splice
recv↔send buffers, skip checksums on VETH, reorder Tcb for cache locality, cache connection
indices, outline cold paths.

**Tech Stack:** Rust, AF_XDP, coarsetime, zero-copy frame buffers

**Design:** See `docs/plans/2026-03-08-tcp-throughput-design.md`

---

### Task 1: Consolidated TCP Options Parsing

**Files:**
- Create: `src/net/handler/tcp/options.rs`
- Modify: `src/net/handler/tcp/mod.rs`
- Modify: `src/net/handler/tcp/inbound.rs`
- Test: `src/net/handler/tcp/tests/options.rs`

**Context:**
`parse_timestamp(options)` is called 3 times in `process_established` (PAWS check at ~998,
ts_recent update at ~1138, RTT measurement at ~1203). Each re-scans the options bytes.
SACK blocks are parsed separately in the ACK processing section. All option parsing should
happen once.

**Step 1: Create the ParsedOptions struct**

Create `src/net/handler/tcp/options.rs`:

```rust
use crate::net::wire::tcp::{parse_timestamp, parse_mss, parse_window_scale, parse_sack_permitted, parse_sack_blocks};

/// Pre-parsed TCP options. Computed once per segment, passed by reference.
#[derive(Debug, Clone, Copy)]
pub struct ParsedOptions {
    pub timestamp: Option<(u32, u32)>,
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub sack_permitted: bool,
    pub sack_blocks: ([Option<(u32, u32)>; 4], usize),
}

impl ParsedOptions {
    /// Parse all TCP options from a raw options byte slice.
    #[inline]
    pub fn parse(options: &[u8]) -> Self {
        Self {
            timestamp: parse_timestamp(options),
            mss: parse_mss(options),
            window_scale: parse_window_scale(options),
            sack_permitted: parse_sack_permitted(options),
            sack_blocks: parse_sack_blocks(options),
        }
    }

    /// Fast parse — only extracts timestamp (for established state where
    /// MSS/wscale/sack_permitted are already negotiated).
    #[inline]
    pub fn parse_established(options: &[u8]) -> Self {
        Self {
            timestamp: parse_timestamp(options),
            mss: None,
            window_scale: None,
            sack_permitted: false,
            sack_blocks: parse_sack_blocks(options),
        }
    }
}
```

Add `pub(crate) mod options;` to `mod.rs`.

**Step 2: Write tests**

Create `src/net/handler/tcp/tests/options.rs` with unit tests for `ParsedOptions::parse()`:
- Empty options → all None/false/empty
- Options with timestamp → timestamp is Some
- Options with SACK blocks → sack_blocks populated
- Options with all fields → all populated

**Step 3: Thread ParsedOptions through process_segment**

In `inbound.rs`, change `process_segment` to parse options once:

```rust
// After connection lookup, before state dispatch:
let opts = if state == TcpState::Established || state.is_teardown() {
    ParsedOptions::parse_established(options)
} else {
    ParsedOptions::parse(options)
};
```

Pass `&opts` (instead of `options: &[u8]`) to `process_established`, `process_syn_sent`,
`process_syn_received`, `process_teardown`.

**Step 4: Replace all inline parse calls in process_established**

Replace every `parse_timestamp(options)` call with `opts.timestamp`. Replace
`parse_sack_blocks(options)` calls with `opts.sack_blocks`. The `options: &[u8]` parameter
is no longer needed in these functions.

**Step 5: Update test files**

Update all test files that call `process_established`, `process_syn_sent`, etc. to pass
`ParsedOptions` instead of raw `&[u8]`.

**Step 6: Verify and commit**

Run: `cargo test`
Expected: All tests pass.

```bash
git add src/net/handler/tcp/options.rs src/net/handler/tcp/mod.rs src/net/handler/tcp/inbound.rs src/net/handler/tcp/tests/
git commit -m "perf(tcp): consolidate option parsing into ParsedOptions struct"
```

---

### Task 2: Checksum Bypass for VETH/Loopback

**Files:**
- Modify: `src/rt/local.rs` (LocalRuntimeBuilder + LocalRuntime)
- Modify: `src/net/handler/tcp/handler.rs` (TcpHandler)
- Modify: `src/net/handler/tcp/inbound.rs` (process_ipv4, process_ipv6)

**Context:**
VETH pairs report checksum offload as disabled, causing software checksum verification on
every RX packet and computation on every TX packet. VETH frames can't be corrupted, so RX
verification is pure waste. TX checksums can optionally be skipped when both endpoints are
ours (benchmarking).

**Step 1: Add skip_rx_checksum flag to LocalRuntimeBuilder**

In `src/rt/local.rs`, add a `skip_rx_checksum: bool` field to `LocalRuntimeBuilder` and a
builder method:

```rust
pub fn skip_rx_checksum(mut self, skip: bool) -> Self {
    self.skip_rx_checksum = skip;
    self
}
```

Thread this through to `TcpHandler::new()` (and the IPv4/IPv6 handlers if they also verify
TCP checksums). The flag overrides `rx_offload` for TCP — when `skip_rx_checksum` is true,
TCP checksum verification is skipped regardless of hardware capability.

**Step 2: Plumb through TcpHandler**

In `handler.rs`, TcpHandler already has `rx_offload: bool`. When `skip_rx_checksum` is true,
set `rx_offload = true` effectively skipping verification.

Alternative (cleaner): add a separate `skip_rx_checksum` field and check
`self.rx_offload || self.skip_rx_checksum` in the checksum verification paths of
`process_ipv4` and `process_ipv6`.

**Step 3: Update echo examples**

Add `.skip_rx_checksum(true)` to both `tcp-echo-server.rs` and `tcp-echo-client.rs` runtime
builders (or add it as a CLI flag `--skip-rx-checksum`).

**Step 4: Verify and commit**

Run: `cargo test`
Expected: All tests pass.

```bash
git add src/rt/local.rs src/net/handler/tcp/handler.rs src/net/handler/tcp/inbound.rs examples/
git commit -m "perf(tcp): add skip_rx_checksum option for VETH/loopback"
```

---

### Task 3: Fast-Path in process_established

**Files:**
- Modify: `src/net/handler/tcp/inbound.rs`

**Context:**
`process_established` is ~556 lines with 11+ branch checks for rare cases (RST, SYN,
PAWS rejection, OOO data). The common case for echo is: ACK set, no special flags, in-order
data, valid new ACK. A fast-path at the top of the function handles this case with minimal
branches.

**Step 1: Add fast-path check at top of process_established**

After the existing ECN check (lines 978–994), add:

```rust
// Fast-path: common case — in-order data + valid new ACK, no special flags.
let fast_path = {
    let tcb = &self.connections[idx];
    (seg_flags & (flags::RST | flags::SYN | flags::FIN)) == 0
        && seg_flags & flags::ACK != 0
        && payload_len > 0
        && seg_seq == tcb.rcv_nxt
        && seq_lt(tcb.snd_una, seg_ack)
        && seq_le(seg_ack, tcb.snd_nxt)
        && !tcb.recovery.in_recovery
        && tcb.ooo_ranges.is_empty()  // no pending OOO reassembly
};
```

**Step 2: Implement the fast-path body**

When `fast_path` is true, execute a streamlined version that combines:

1. **PAWS check** (inline, using pre-parsed timestamp from `opts`):
   - If ts_enabled and timestamp present, check `tsval >= ts_recent` (signed comparison)
   - On PAWS failure, fall through to slow path
   - On success, update `ts_recent` and `ts_recent_age`

2. **Segment acceptability** (simplified — seg_seq == rcv_nxt and we know payload_len > 0):
   - Just check `rcv_nxt + rcv_wnd > seg_seq` (always true if window > 0)

3. **ACK advancement**:
   - `bytes_acked = seg_ack - snd_una`
   - `snd_una = seg_ack`
   - `send_buffer.advance(bytes_acked)`
   - Reset keep-alive timer
   - Slow-start cwnd update: `cwnd += mss` (if cwnd < ssthresh)
   - Reset dup_ack_count
   - RTT measurement (using pre-parsed timestamp)
   - Window update
   - Retransmit timer: if `snd_una == snd_nxt`, clear deadline

4. **Data write**:
   - `recv_buffer.write(payload)` — in-order, no OOO handling needed
   - `rcv_nxt += written`

5. **Delayed ACK**:
   - Increment ack_delay_count
   - If >= MAX_DELAYED_ACK_COUNT, send ACK immediately
   - Otherwise set ack_pending + deadline

6. **Return** (skip slow path entirely)

If PAWS fails or any other condition isn't met, fall through to the existing slow path
(the entire current function body).

**Step 3: Extract slow-path helpers**

Move rarely-taken branches into `#[inline(never)]` helper functions to reduce code size
of the hot path:

```rust
#[inline(never)]
fn handle_rst_in_established(&mut self, idx: usize, ...) { ... }

#[inline(never)]
fn handle_syn_in_established(&mut self, idx: usize, ...) { ... }

#[inline(never)]
fn handle_ooo_data(&mut self, idx: usize, ...) { ... }
```

**Step 4: Verify and commit**

Run: `cargo test`
Expected: All tests pass.

```bash
git add src/net/handler/tcp/inbound.rs
git commit -m "perf(tcp): add fast-path for common established-state processing"
```

---

### Task 4: RingBuffer::transfer() and TcpStream::splice()

**Files:**
- Modify: `src/net/handler/tcp/ring_buffer.rs`
- Modify: `src/net/socket/tcp.rs`
- Modify: `examples/tcp-echo-server.rs`
- Test: `src/net/handler/tcp/tests/` (ring_buffer tests)

**Context:**
The echo server does `read()` → `write()` which copies data through a user buffer (2 extra
copies). `RingBuffer::transfer()` moves data directly between ring buffers.

**Step 1: Implement RingBuffer::transfer()**

In `ring_buffer.rs`:

```rust
/// Transfer up to `max_len` bytes from self (as source) to `dst` (as destination).
/// Reads from self's head, writes to dst's tail. Returns bytes transferred.
/// This is equivalent to `read()` + `write()` but avoids the intermediate buffer.
#[inline]
pub fn transfer(&mut self, dst: &mut RingBuffer, max_len: usize) -> usize {
    let available = self.available().min(max_len);
    let to_transfer = available.min(dst.free_space());
    if to_transfer == 0 {
        return 0;
    }
    // Get source slices (may wrap).
    let (s1, s2) = self.peek_slices(0, to_transfer);
    // Write to destination.
    let wrote1 = dst.write(s1);
    let wrote2 = if !s2.is_empty() { dst.write(s2) } else { 0 };
    let total = wrote1 + wrote2;
    // Advance source.
    self.advance(total);
    total
}
```

**Step 2: Write tests for transfer()**

Add tests to the ring_buffer tests:
- Transfer between empty/full buffers
- Transfer with wrap-around on source
- Transfer with wrap-around on destination
- Transfer with both wrapping
- Partial transfer when destination is nearly full

**Step 3: Add TcpStream::splice()**

In `tcp.rs`:

```rust
/// Transfer data from recv_buffer directly to send_buffer, avoiding the
/// intermediate user buffer copy. Returns a future that resolves when at
/// least 1 byte has been transferred.
pub fn splice(&self, max_len: usize) -> TcpSplice<'_> {
    TcpSplice {
        handler: &self.handler,
        conn_id: self.conn_id,
        event_queue: &self.event_queue,
        max_len,
    }
}
```

```rust
pub struct TcpSplice<'stream> {
    handler: &'stream Rc<UnsafeCell<TcpHandler>>,
    conn_id: ConnectionId,
    event_queue: &'stream LocalQueue<TcpEvent>,
    max_len: usize,
}

impl<'stream> Future for TcpSplice<'stream> {
    type Output = Result<usize, TcpError>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        // Check errors
        while let Some(event) = this.event_queue.pop() {
            match event {
                TcpEvent::Reset => return Poll::Ready(Err(TcpError::Reset)),
                TcpEvent::Timeout => return Poll::Ready(Err(TcpError::Timeout)),
                TcpEvent::RemoteClose => {
                    // Check if there's still data to drain before returning EOF
                }
                _ => {}
            }
        }
        let handler = unsafe { &mut *this.handler.get() };
        if let Some(tcb) = handler.get_connection_mut(&this.conn_id) {
            let n = tcb.recv_buffer.transfer(&mut tcb.send_buffer, this.max_len);
            if n > 0 {
                Poll::Ready(Ok(n))
            } else if tcb.state.is_remote_closed() {
                Poll::Ready(Ok(0))
            } else {
                Poll::Pending
            }
        } else {
            Poll::Ready(Err(TcpError::NotConnected))
        }
    }
}
```

**Step 4: Update echo server example**

Change `tcp-echo-server.rs` to use splice:

```rust
loop {
    match stream.splice(65535).await {
        Ok(0) => {
            println!("Disconnected from {}:{}", stream.remote_addr(), stream.remote_port());
            break;
        }
        Ok(n) => {
            stats.update(n, false);
            stats.maybe_print();
        }
        Err(e) => {
            println!("Splice error: {:?}", e);
            break;
        }
    }
}
```

**Step 5: Verify and commit**

Run: `cargo test`
Expected: All tests pass.

```bash
git add src/net/handler/tcp/ring_buffer.rs src/net/socket/tcp.rs examples/tcp-echo-server.rs
git commit -m "perf(tcp): add RingBuffer::transfer() and TcpStream::splice() for zero-copy echo"
```

---

### Task 5: Tcb Field Reordering for Cache Locality

**Files:**
- Modify: `src/net/handler/tcp/tcb.rs`

**Context:**
The `Tcb` struct is ~500+ bytes. Hot fields are scattered across cache lines. Reorder fields
so the most-accessed ones share cache lines.

**Step 1: Reorder Tcb fields**

Group fields by access frequency:

```rust
pub struct Tcb {
    // === Cache line 1: accessed every packet ===
    pub rcv_nxt: u32,
    pub snd_nxt: u32,
    pub snd_una: u32,
    pub snd_wnd: u32,
    pub state: TcpState,
    pub ack_pending: bool,
    pub ack_delay_count: u8,
    pub ts_enabled: bool,
    pub sack_enabled: bool,
    pub ecn_enabled: bool,
    pub ecn_ce_received: bool,
    pub wscale_enabled: bool,
    pub eff_snd_mss: u16,
    pub snd_wscale: u8,
    pub rcv_wscale: u8,
    pub rcv_mss: u16,
    pub nagle_enabled: bool,
    pub from_passive_open: bool,
    _pad1: [u8; 2],  // align to 64 bytes

    // === Cache line 2: accessed most packets ===
    pub id: ConnectionId,
    pub ts_recent: u32,
    pub delayed_ack_deadline: Option<Instant>,
    pub delayed_ack_ms: u64,

    // === Cache line 3+: buffers (accessed for data) ===
    pub recv_buffer: RingBuffer,
    pub send_buffer: RingBuffer,

    // === Warm: accessed on ACKs ===
    pub snd_wl1: u32,
    pub snd_wl2: u32,
    pub max_snd_wnd: u32,
    pub last_advertised_right_edge: u32,
    pub iss: u32,
    pub irs: u32,
    pub rcv_wnd: u32,
    pub snd_mss: u16,

    // === Congestion/recovery (accessed on ACKs, not data-only) ===
    pub cubic: CubicState,
    pub recovery: SackRecovery,
    pub prr: PrrState,
    pub frto: FRtoState,

    // === RTT (accessed on ACKs with timestamps) ===
    pub srtt: Option<u64>,
    pub rttvar: u64,
    pub rto: u64,
    pub last_send_time: Option<Instant>,
    pub ts_recent_age: Instant,
    pub ts_offset: Instant,

    // === Cold: rarely accessed ===
    pub retransmit_deadline: Option<Instant>,
    pub rto_backoff: u8,
    pub event_queue: LocalQueue<TcpEvent>,
    pub ooo_ranges: BTreeMap<u32, u32>,
    pub sack_scoreboard: BTreeMap<u32, u32>,
    pub ecn_cwr_sent: bool,
    pub pending_fin: bool,
    pub fin_seq: Option<u32>,
    pub time_wait_deadline: Option<Instant>,
    pub time_wait_duration: u64,
    pub persist_deadline: Option<Instant>,
    pub persist_backoff: u8,
    pub keep_alive_enabled: bool,
    pub keep_alive_idle_ms: u64,
    pub keep_alive_interval_ms: u64,
    pub keep_alive_count: u8,
    pub last_activity: Instant,
    pub keep_alive_probes_sent: u8,
    pub linger: Option<u64>,
    pub linger_deadline: Option<Instant>,
}
```

Note: exact layout depends on alignment and padding. Use `#[repr(C)]` to control layout,
or verify with `std::mem::offset_of!` that hot fields share cache lines.

**Step 2: Update all Tcb construction sites**

Update `make_tcb()` in `tcb.rs` tests, `connect` / `connect_with_config` in `connection.rs`,
passive-open constructor in `inbound.rs`, and all test helpers to use the new field order.

**Step 3: Verify and commit**

Run: `cargo test`
Expected: All tests pass.

```bash
git add src/net/handler/tcp/tcb.rs src/net/handler/tcp/connection.rs src/net/handler/tcp/inbound.rs src/net/handler/tcp/tests/
git commit -m "perf(tcp): reorder Tcb fields for cache locality"
```

---

### Task 6: Cache Connection Index in TcpStream

**Files:**
- Modify: `src/net/socket/tcp.rs`
- Modify: `src/net/handler/tcp/handler.rs`

**Context:**
`TcpRead::poll` and `TcpWrite::poll` each call `get_connection_mut(&conn_id)` which does
O(n) linear scan. For echo, that's 2 extra scans per packet. Cache the index and validate.

**Step 1: Add index-based lookup to TcpHandler**

In `handler.rs`:

```rust
/// Get a mutable reference by index, validating the connection ID matches.
/// Returns None if index is out of bounds or ID doesn't match.
#[inline]
pub fn get_connection_by_idx(&mut self, idx: usize, id: &ConnectionId) -> Option<&mut Tcb> {
    if let Some(tcb) = self.connections.get_mut(idx) {
        if tcb.id == *id {
            return Some(tcb);
        }
    }
    // Fallback to linear scan.
    self.get_connection_mut(id)
}

/// Find the index of a connection by ID.
pub fn find_connection_idx(&self, id: &ConnectionId) -> Option<usize> {
    self.connections.iter().position(|c| c.id == *id)
}
```

**Step 2: Add cached index to TcpStream**

```rust
use std::cell::Cell;

pub struct TcpStream {
    conn_id: ConnectionId,
    event_queue: LocalQueue<TcpEvent>,
    handler: Rc<UnsafeCell<TcpHandler>>,
    cached_idx: Cell<usize>,
    closed: bool,
    write_closed: bool,
}
```

Initialize `cached_idx` from `find_connection_idx` in `from_accepted` and `Connect::poll`.

**Step 3: Use cached index in TcpRead/TcpWrite**

```rust
// In TcpRead::poll:
let handler = unsafe { &mut *this.handler.get() };
let idx = this.cached_idx.get();
if let Some(tcb) = handler.get_connection_by_idx(idx, &this.conn_id) {
    // ... use tcb
} else if let Some(new_idx) = handler.find_connection_idx(&this.conn_id) {
    this.cached_idx.set(new_idx);
    // ... use connections[new_idx]
} else {
    return Poll::Ready(Err(TcpError::NotConnected));
}
```

Wait — `TcpRead` borrows `&self` from `TcpStream` but `cached_idx` is a `Cell<usize>`.
We need to pass the Cell by reference. Add `cached_idx: &'stream Cell<usize>` to
`TcpRead` and `TcpWrite`.

**Step 4: Verify and commit**

Run: `cargo test`
Expected: All tests pass.

```bash
git add src/net/socket/tcp.rs src/net/handler/tcp/handler.rs
git commit -m "perf(tcp): cache connection index in TcpStream to avoid linear scan"
```

---

### Task 7: Cold Path Extraction

**Files:**
- Modify: `src/net/handler/tcp/inbound.rs`

**Context:**
Rarely-taken branches in `process_established` pollute the instruction cache. Extract them
into `#[inline(never)]` functions.

**Step 1: Extract cold helpers**

Create these `#[inline(never)]` methods on `TcpHandler`:

```rust
/// Handle RST in established state (RFC 5961).
#[inline(never)]
fn handle_rst_in_established<'umem>(
    &mut self, idx: usize, seg_seq: u32, tsval: u32, ack_flags: u8,
    src_mac: MacAddress, dst_mac: MacAddress,
    free_frames: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) -> bool;  // returns true if connection was removed

/// Handle SYN in synchronized state (challenge ACK).
#[inline(never)]
fn send_challenge_ack<'umem>(
    &mut self, idx: usize, tsval: u32, ack_flags: u8,
    src_mac: MacAddress, dst_mac: MacAddress,
    free_frames: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
);

/// Handle out-of-order data segment.
#[inline(never)]
fn handle_ooo_data<'umem>(
    &mut self, idx: usize, frame: &Frame<'umem>, payload_offset: usize,
    payload_len: usize, seg_seq: u32, tsval: u32, ack_flags: u8,
    src_mac: MacAddress, dst_mac: MacAddress,
    free_frames: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
);

/// Enter SACK recovery on 3rd duplicate ACK.
#[inline(never)]
fn enter_sack_recovery(&mut self, idx: usize);
```

**Step 2: Replace inline code with helper calls**

In `process_established`, replace the RST handling block (~30 lines) with:
```rust
if seg_flags & flags::RST != 0 {
    if self.handle_rst_in_established(idx, seg_seq, tsval, ack_flags, src_mac, dst_mac, free_frames, tx_return) {
        rx_return.push(frame);
        return;
    }
    // Challenge ACK already sent by handler
    rx_return.push(frame);
    return;
}
```

Similarly for SYN check, OOO data, and SACK recovery entry.

**Step 3: Verify and commit**

Run: `cargo test`
Expected: All tests pass.

```bash
git add src/net/handler/tcp/inbound.rs
git commit -m "perf(tcp): extract cold paths to #[inline(never)] functions"
```

---

### Task 8: Verification and Benchmarking

**Files:**
- No code changes — verification only

**Step 1: Run full test suite**

```bash
cargo test
```

Expected: All tests pass.

**Step 2: Check for remaining hot-path inefficiencies**

Search for any remaining `parse_timestamp` or `parse_sack_blocks` calls in inbound.rs
that should use `ParsedOptions` instead.

Search for any `Instant::now()` calls in hot paths.

Search for any heap allocations (`Vec::new`, `Box`, `BTreeMap::new`) in hot paths.

**Step 3: Benchmark**

Run the TCP echo benchmark:

Terminal 1 (server namespace):
```bash
cargo run --release --example tcp-echo-server -- --if-name veth-server --queue 0
```

Terminal 2 (client namespace):
```bash
cargo run --release --example tcp-echo-client -- --if-name veth-client --queue 0 -m 64
```

Record pkt/s and compare against the 560K baseline.

**Step 4: Document results**

If pkt/s improved significantly, note the result. If not at target (2M+), identify
the next bottleneck for a follow-up optimization pass.
