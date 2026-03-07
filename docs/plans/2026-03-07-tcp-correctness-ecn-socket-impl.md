# TCP Correctness, ECN, and Socket API Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add PSH flag on outgoing segments, IPv6 fragment drop visibility, full ECN (RFC 3168), error-returning socket API, and simultaneous open verification.

**Architecture:** Five independent features. PSH and simultaneous open are small. ECN is multi-step (TCB fields → negotiation → send/receive → congestion response). Socket API changes read/write return types from `usize` to `Result<usize, TcpError>`. IPv6 fragment visibility is a counter addition.

**Tech Stack:** Rust, coarsetime for timers, existing TCP handler infrastructure in `src/net/handler/tcp/`.

**Testing:** `cargo test` (no feature flags, no `--all-features`). Tests run under `sudo -E` via `.cargo/config.toml`.

**Key files reference:**
- Wire format: `src/net/wire/tcp.rs` (flags: ECE=0x40, CWR=0x80, PSH=0x08)
- TCB/config: `src/net/handler/tcp/tcb.rs`
- Handler: `src/net/handler/tcp/mod.rs`
- Segment builder: `src/net/handler/tcp/segment.rs`
- Socket layer: `src/net/socket/tcp.rs`
- IPv6 handler: `src/net/handler/ipv6.rs`
- Examples: `examples/tcp-echo-server.rs`, `examples/tcp-echo-client.rs`

---

## Task 1: PSH Flag on Outgoing Data Segments

**Files:**
- Modify: `src/net/handler/tcp/segment.rs:548-616` (build_data_from_slices)
- Modify: `src/net/handler/tcp/mod.rs:2003-2050` (poll_send data path)

**Context:** `build_data_from_slices` hardcodes `flags::ACK` at lines 584 and 603 when calling the internal IPv4/IPv6 helpers. The internal helpers (`build_ipv4_data_segment_slices`, `build_ipv6_data_segment_slices`) already accept a `tcp_flags: u8` parameter — the public method just never passes anything other than ACK. In `poll_send`, after computing `to_send`, we can detect "last segment in burst" by checking if all available data will be sent.

**Step 1: Add `tcp_flags` parameter to `build_data_from_slices`**

In `src/net/handler/tcp/segment.rs`, change the signature of `build_data_from_slices` (line 548) to add a `tcp_flags: u8` parameter after `window`:

```rust
pub fn build_data_from_slices<'umem>(
    local_addr: IpAddress,
    remote_addr: IpAddress,
    local_port: u16,
    remote_port: u16,
    seq: u32,
    ack: u32,
    window: u16,
    tcp_flags: u8,                    // NEW — was hardcoded to flags::ACK
    payload: (&[u8], &[u8]),
    timestamp: Option<(u32, u32)>,
    src_mac: MacAddress,
    dst_mac: MacAddress,
    tx_offload: bool,
    free_frames: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
)
```

Then replace the hardcoded `flags::ACK` at lines 584 and 603 with `tcp_flags`.

**Step 2: Update all call sites in mod.rs**

There are 3 call sites for `build_data_from_slices` in mod.rs:

1. **poll_send data path** (~line 2029): Change to pass `flags::ACK` (for now — we'll add PSH logic in step 3).
2. **Fast retransmit** (~line 1797): Pass `flags::ACK` (retransmits don't set PSH).
3. **RTO retransmit** (~line 1922): Pass `flags::ACK` (retransmits don't set PSH).

Search for `build_data_from_slices` in mod.rs to find all 3 sites.

**Step 3: Add PSH flag logic in poll_send**

In `poll_send`, before the `build_data_from_slices` call, determine if this is the last segment in the burst:

```rust
// Set PSH on last segment in burst (all available data sent or window exhausted).
let remaining_after_send = data_available.saturating_sub(to_send);
let data_flags = if remaining_after_send == 0 || to_send >= can_send {
    flags::ACK | flags::PSH
} else {
    flags::ACK
};
```

Then pass `data_flags` to `build_data_from_slices` instead of `flags::ACK`.

Add `use crate::net::wire::tcp::flags;` if not already in scope (it's likely already available via the segment builder imports).

**Step 4: Write test**

Add a test in the `#[cfg(test)]` section of mod.rs:

```rust
#[test]
fn poll_send_sets_psh_on_last_segment() {
    // Setup: established connection with small amount of data (< MSS).
    // This is the last (and only) segment, so PSH should be set.
    // After poll_send, inspect the emitted frame's TCP flags.
    // The TCP flags byte is at offset ETH_LEN + IPV4_MIN_HEADER_LEN + 13.
    // Verify: flags & PSH != 0.
}
```

Follow existing test patterns (use `establish_connection` helper). Build the frame, call `poll_send`, pop from tx_return, check TCP flags byte in the frame. The TCP flags offset in an IPv6 frame is `ETH_LEN + IPV6_HEADER_LEN + 13`. For IPv4: `ETH_LEN + IPV4_MIN_HEADER_LEN + 13`.

Also add a test that sends more than 1 MSS of data — the first segment should NOT have PSH, but after poll_send loops or on the next poll_send when remaining data fits, PSH should be set.

**Step 5: Update segment.rs test**

The existing test `build_data_from_slices_produces_frame` needs updating to pass the new `tcp_flags` parameter. Add `flags::ACK` to the existing call.

**Step 6: Run tests**

Run: `cargo test`
Expected: All pass

**Step 7: Commit**

```bash
git add src/net/handler/tcp/segment.rs src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): set PSH flag on last data segment in burst"
```

---

## Task 2: IPv6 Fragment Drop Visibility

**Files:**
- Modify: `src/net/handler/ipv6.rs:248-250`

**Context:** The IPv6 handler at line 249 silently drops fragmented TCP segments with `rx_return.push(frame)`. We want to make this visible with a counter.

**Step 1: Add counter to Ipv6Handler**

Find the `Ipv6Handler` struct definition in `src/net/handler/ipv6.rs`. Add a field:

```rust
pub ipv6_tcp_fragments_dropped: u64,
```

Initialize to 0 in the constructor/default.

**Step 2: Increment counter on drop**

Replace the fragment drop code (line 249):

```rust
} else if frag_next_header == IpProtocols::Tcp {
    // TCP does not yet support fragment reassembly; drop to rx_return.
    self.ipv6_tcp_fragments_dropped += 1;
    rx_return.push(frame);
}
```

**Step 3: Write test**

Test that processing an IPv6 fragmented TCP frame increments the counter. Follow existing test patterns in the file. If there's no existing test infrastructure for IPv6 fragments, a simple unit test that constructs a minimal fragmented IPv6 frame and processes it is sufficient.

**Step 4: Run tests**

Run: `cargo test`
Expected: All pass

**Step 5: Commit**

```bash
git add src/net/handler/ipv6.rs
git commit -m "feat(ipv6): count dropped TCP fragments instead of silent discard"
```

---

## Task 3: ECN — TCB Fields and TcpConfig

**Files:**
- Modify: `src/net/handler/tcp/tcb.rs`

**Context:** Add ECN-related fields to TCB and TcpConfig before implementing the protocol logic.

**Step 1: Add fields to TcpConfig**

In `src/net/handler/tcp/tcb.rs`, add to `TcpConfig` struct (after `sack: bool`):

```rust
pub ecn: bool,
```

In `impl Default for TcpConfig`, add:

```rust
ecn: true,
```

**Step 2: Add fields to Tcb**

In the `Tcb` struct, add after the SACK fields:

```rust
// ECN (RFC 3168)
pub ecn_enabled: bool,
pub ecn_ce_received: bool,
pub ecn_cwr_sent: bool,
```

In the `Tcb` constructor (wherever `Tcb` is created — likely in `process_listen` and `connect`), initialize:

```rust
ecn_enabled: false,
ecn_ce_received: false,
ecn_cwr_sent: false,
```

**Step 3: Run tests**

Run: `cargo test`
Expected: All pass (fields added but unused — may get dead_code warnings, which is fine)

**Step 4: Commit**

```bash
git add src/net/handler/tcp/tcb.rs
git commit -m "feat(tcp): add ECN fields to TCB and TcpConfig"
```

---

## Task 4: ECN — Negotiation in SYN/SYN-ACK

**Files:**
- Modify: `src/net/handler/tcp/segment.rs` (build_syn, build_syn_ack)
- Modify: `src/net/handler/tcp/mod.rs` (connect, process_listen, process_syn_sent, process_syn_received)

**Context:** ECN negotiation per RFC 3168 §6.1.1:
- **Active open:** SYN with ECE+CWR flags → "I support ECN"
- **Passive open:** SYN-ACK with ECE flag (no CWR) → "I confirm ECN"
- Both sides must agree; if SYN-ACK lacks ECE, disable ECN.

**Step 1: Modify build_syn to accept ecn parameter**

In `src/net/handler/tcp/segment.rs`, find `build_syn` (around line 104). Add an `ecn: bool` parameter. When `ecn` is true, set flags to `flags::SYN | flags::ECE | flags::CWR` instead of just `flags::SYN`. The internal call to `build_ipv4_segment`/`build_ipv6_segment` passes the `tcp_flags` parameter — just change what's passed.

```rust
let syn_flags = if ecn { flags::SYN | flags::ECE | flags::CWR } else { flags::SYN };
```

**Step 2: Modify build_syn_ack to accept ecn parameter**

Find `build_syn_ack` (around line 181). Add `ecn: bool` parameter. When true, set flags to `flags::SYN | flags::ACK | flags::ECE` instead of `flags::SYN | flags::ACK`.

```rust
let syn_ack_flags = if ecn { flags::SYN | flags::ACK | flags::ECE } else { flags::SYN | flags::ACK };
```

**Step 3: Update connect() to pass ecn flag**

In `mod.rs`, in `connect()` and `connect_with_config()`, pass `config.ecn` to `build_syn`. Also set `tcb.ecn_enabled` provisionally (will be confirmed when SYN-ACK arrives).

Find the `build_syn` call in connect (around line 288). Add the ecn parameter.

**Step 4: Update process_listen to negotiate ECN**

In `process_listen`, when processing an incoming SYN:
1. Check if incoming SYN has both ECE and CWR flags set: `seg_flags & (flags::ECE | flags::CWR) == (flags::ECE | flags::CWR)`
2. If yes AND our config allows ECN, set `tcb.ecn_enabled = true` on the new connection
3. Pass `tcb.ecn_enabled` to `build_syn_ack`

Find where `build_syn_ack` is called in `process_listen` (~line 859) and the SYN-ACK retransmit in `poll_timers` for SynReceived.

**Step 5: Update process_syn_sent to confirm ECN**

In `process_syn_sent`, when processing SYN-ACK:
1. Check if SYN-ACK has ECE flag: `seg_flags & flags::ECE != 0`
2. If yes and we offered ECN (tcb.ecn_enabled was provisionally set), confirm: keep `ecn_enabled = true`
3. If no ECE in SYN-ACK: `tcb.ecn_enabled = false`

Find the SYN-ACK processing section in `process_syn_sent` (the `seg_flags & flags::ACK != 0` branch).

**Step 6: Update all build_syn/build_syn_ack call sites**

Search for `build_syn(` and `build_syn_ack(` in mod.rs. There are calls in:
- `connect()` / `connect_with_config()`
- `process_listen()` (SYN-ACK)
- `poll_timers()` (SYN retransmit for SynSent, SYN-ACK retransmit for SynReceived)

All need the new `ecn` parameter. For retransmits, use `tcb.ecn_enabled` (already stored).

**Step 7: Write tests**

```rust
#[test]
fn ecn_negotiated_when_both_sides_support() {
    // Connect with ecn=true. Verify SYN has ECE+CWR.
    // Send SYN-ACK with ECE. Verify ecn_enabled=true after handshake.
}

#[test]
fn ecn_disabled_when_peer_doesnt_support() {
    // Connect with ecn=true. Send SYN-ACK without ECE.
    // Verify ecn_enabled=false after handshake.
}

#[test]
fn ecn_negotiated_on_passive_open() {
    // Listen. Send SYN with ECE+CWR. Verify SYN-ACK has ECE.
    // Complete handshake. Verify ecn_enabled=true.
}
```

**Step 8: Run tests**

Run: `cargo test`
Expected: All pass

**Step 9: Commit**

```bash
git add src/net/handler/tcp/segment.rs src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): negotiate ECN in SYN/SYN-ACK handshake (RFC 3168)"
```

---

## Task 5: ECN — ECT Codepoint on Outgoing Data and CE Detection

**Files:**
- Modify: `src/net/handler/tcp/segment.rs` (build_ipv4_data_segment_slices, build_ipv6_data_segment_slices, build_data_from_slices)
- Modify: `src/net/handler/tcp/mod.rs` (poll_send, process_established)

**Context:** When ECN is enabled:
- **Outgoing:** Set ECT(0) codepoint (`0b10`) in IPv4 ToS byte (`ip[1]`) / IPv6 Traffic Class on data segments. NOT on retransmits per RFC 3168.
- **Incoming:** Check for CE codepoint (`0b11`) in IP header. If CE, set `ecn_ce_received = true`.

The IPv4 ToS byte is at `ip[1]` (offset 1 in IP header). Currently `ip.fill(0)` zeros it. ECN bits are the two low-order bits of the ToS byte. ECT(0) = `0b10` = 0x02.

For IPv6, Traffic Class spans bytes 0-1 of the IPv6 header (4 bits version + 8 bits TC + 20 bits flow label). The ECN bits are bits 6-7 of the Traffic Class (the two low-order bits). In the IPv6 header bytes: `ip[0]` has version(4 bits) + TC high 4 bits, `ip[1]` has TC low 4 bits + flow label high 4 bits. ECN bits are in the low 2 bits of the TC field, which map to bits 5-4 of `ip[1]`. So: `ip[1] = (ip[1] & 0xCF) | (ecn_value << 4)`. Actually, let's be more precise: the 8-bit TC field is `(ip[0] & 0x0F) << 4 | (ip[1] >> 4)`. ECN is the low 2 bits of TC. To set ECT(0)=0b10: `ip[1] = (ip[1] & 0xCF) | (0x02 << 4)` = `ip[1] | 0x20`.

**Step 1: Add `ecn_ect: bool` parameter to build_data_from_slices**

```rust
pub fn build_data_from_slices<'umem>(
    ...
    tcp_flags: u8,
    payload: (&[u8], &[u8]),
    timestamp: Option<(u32, u32)>,
    ecn_ect: bool,                // NEW — set ECT(0) in IP header
    ...
)
```

Pass it through to `build_ipv4_data_segment_slices` / `build_ipv6_data_segment_slices`.

**Step 2: Set ECT(0) in IP header**

In `build_ipv4_data_segment_slices`, after the IP header setup (after `ip.fill(0); ip[0] = 0x45;`), add:

```rust
if ecn_ect {
    ip[1] = 0x02; // ECT(0) in ToS byte
}
```

In `build_ipv6_data_segment_slices`, similarly set the ECN bits in the IPv6 Traffic Class field. After the IPv6 header is initialized:

```rust
if ecn_ect {
    ip[1] |= 0x20; // ECT(0) in Traffic Class low bits
}
```

**Step 3: Update call sites in mod.rs**

- **poll_send data path:** Pass `tcb.ecn_enabled` as `ecn_ect`.
- **Fast retransmit:** Pass `false` (retransmits don't get ECT marking per RFC 3168 §6.1.5).
- **RTO retransmit:** Pass `false`.
- **Zero-window probe:** Uses `build_data` not `build_data_from_slices` — leave as-is (probes don't need ECT).

**Step 4: Detect CE on incoming segments**

In `process_established`, at the top (before PAWS check), extract the ECN bits from the incoming IP header. The frame has already been parsed for IP — check how `process_ipv4_with_now` extracts the IP header.

For IPv4: ToS byte is at `frame[ETH_LEN + 1]`. CE = `(tos & 0x03) == 0x03`.
For IPv6: TC byte split across `frame[ETH_LEN]` and `frame[ETH_LEN + 1]`. ECN bits: `(frame[ETH_LEN + 1] >> 4) & 0x03`. CE = value == 0x03.

Since `process_established` doesn't currently receive the IP header ECN bits, you'll need to pass them through. Add an `ecn_bits: u8` parameter to `process_established` (and `process_ipv4_with_now` / `process_ipv6_with_now` extract it from the IP header and pass it).

In `process_established`, if `tcb.ecn_enabled && ecn_bits == 0x03`:
```rust
tcb.ecn_ce_received = true;
```

**Step 5: Write tests**

```rust
#[test]
fn ecn_ect_set_on_outgoing_data() {
    // Established connection with ecn_enabled=true.
    // Write data, call poll_send.
    // Check outgoing frame's IP ToS byte has ECT(0) (0x02).
}

#[test]
fn ecn_ect_not_set_on_retransmit() {
    // Trigger RTO retransmit with ecn_enabled=true.
    // Check outgoing frame's IP ToS byte is 0x00.
}

#[test]
fn ecn_ce_detected_on_incoming() {
    // Established connection with ecn_enabled=true.
    // Send a data segment with CE mark in IP header.
    // Verify ecn_ce_received=true on the TCB.
}
```

**Step 6: Run tests**

Run: `cargo test`
Expected: All pass

**Step 7: Commit**

```bash
git add src/net/handler/tcp/segment.rs src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): set ECT(0) on outgoing data, detect CE on incoming (RFC 3168)"
```

---

## Task 6: ECN — ECE/CWR Flag Signaling and Congestion Response

**Files:**
- Modify: `src/net/handler/tcp/mod.rs` (process_established, poll_send)

**Context:** When CE is detected, receiver must signal sender via ECE flag. Sender responds by halving cwnd and sending CWR.

**Step 1: Send ECE flag when ecn_ce_received is true**

In all ACK-sending paths within `process_established` (there are several `build_ack` / `build_ack_with_sack` calls), when `tcb.ecn_ce_received` is true, OR the ECE flag into the ACK's TCP flags.

The simplest approach: modify `build_ack` and `build_ack_with_sack` to accept a `tcp_flags: u8` parameter (similar to what we did for `build_data_from_slices`). Default callers pass `flags::ACK`, but when `ecn_ce_received`, pass `flags::ACK | flags::ECE`.

Alternatively, add ECE into all outgoing segments (including data piggybacked ACKs) when `ecn_ce_received` is true — this means also adding ECE to `build_data_from_slices` calls in `poll_send`. This is the correct behavior: keep sending ECE until CWR is received.

**Step 2: React to incoming ECE (sender side)**

In `process_established` ACK processing (the valid new ACK branch), check for ECE flag:

```rust
if tcb.ecn_enabled && seg_flags & flags::ECE != 0 && !tcb.ecn_cwr_sent {
    // Congestion response: halve cwnd (same as loss).
    tcb.ssthresh = (tcb.cwnd / 2).max(2 * tcb.eff_snd_mss as u32);
    tcb.cwnd = tcb.ssthresh;
    tcb.ecn_cwr_sent = true; // Will send CWR on next data segment
}
```

**Step 3: Send CWR flag on next data segment**

In `poll_send`, when `tcb.ecn_cwr_sent` is true, OR the CWR flag into the data segment's TCP flags:

```rust
let mut data_flags = if remaining_after_send == 0 || to_send >= can_send {
    flags::ACK | flags::PSH
} else {
    flags::ACK
};
if tcb.ecn_cwr_sent {
    data_flags |= flags::CWR;
}
```

After sending the CWR-marked segment, clear the flag:

```rust
tcb.ecn_cwr_sent = false;
```

**Step 4: Clear ecn_ce_received when CWR received**

In `process_established`, before data processing, check for CWR:

```rust
if tcb.ecn_enabled && seg_flags & flags::CWR != 0 {
    tcb.ecn_ce_received = false; // Stop sending ECE
}
```

**Step 5: Reset ecn_cwr_sent on new ACK**

In the valid new ACK branch, after advancing `snd_una`:

```rust
// Reset ECN CWR tracking for new RTT.
if tcb.ecn_cwr_sent {
    // CWR was already sent; new ACK means sender saw it.
    // (Actually we clear ecn_cwr_sent when the segment is sent in poll_send)
}
```

This is already handled in Step 3 (cleared after sending). No additional code needed.

**Step 6: Write tests**

```rust
#[test]
fn ecn_ece_sent_when_ce_received() {
    // Established with ecn_enabled. Set ecn_ce_received=true.
    // Trigger an ACK (e.g., by receiving data).
    // Check outgoing ACK has ECE flag set.
}

#[test]
fn ecn_cwnd_halved_on_ece() {
    // Established with ecn_enabled. Set cwnd to known value.
    // Send ACK with ECE flag.
    // Verify cwnd halved and ecn_cwr_sent=true.
}

#[test]
fn ecn_cwr_sent_on_next_data() {
    // Established with ecn_enabled and ecn_cwr_sent=true.
    // Write data, poll_send.
    // Verify outgoing segment has CWR flag.
    // Verify ecn_cwr_sent cleared after send.
}

#[test]
fn ecn_ce_received_cleared_on_cwr() {
    // Established with ecn_enabled and ecn_ce_received=true.
    // Receive segment with CWR flag.
    // Verify ecn_ce_received=false.
}
```

**Step 7: Run tests**

Run: `cargo test`
Expected: All pass

**Step 8: Commit**

```bash
git add src/net/handler/tcp/mod.rs src/net/handler/tcp/segment.rs
git commit -m "feat(tcp): ECN congestion signaling with ECE/CWR flags (RFC 3168)"
```

---

## Task 7: Socket API — read/write Return Result

**Files:**
- Modify: `src/net/socket/tcp.rs` (TcpRead, TcpWrite futures, TcpStream methods)
- Modify: `examples/tcp-echo-server.rs`
- Modify: `examples/tcp-echo-client.rs`

**Context:** `TcpRead` and `TcpWrite` futures currently return `usize`. They need to return `Result<usize, TcpError>` to surface Reset/Timeout events. `TcpError` already exists in `tcb.rs`.

**Step 1: Change TcpRead::Output to Result**

In `src/net/socket/tcp.rs`, find `impl Future for TcpRead` (around line 497). Change:

```rust
impl<'stream> Future for TcpRead<'stream> {
    type Output = Result<usize, TcpError>;
```

In the `poll` method:
- Before checking recv_buffer, check event_queue for error events:
  ```rust
  if let Some(event) = handler.check_event(&self.conn_id) {
      match event {
          TcpEvent::Reset => return Poll::Ready(Err(TcpError::Reset)),
          TcpEvent::Timeout => return Poll::Ready(Err(TcpError::Timeout)),
          _ => {}
      }
  }
  ```
- When connection is gone (not found): `return Poll::Ready(Err(TcpError::NotConnected))`
- When data available: `return Poll::Ready(Ok(n))`
- When remote closed (state is CloseWait/LastAck/TimeWait/Closed and no data): `return Poll::Ready(Ok(0))`

Note: You'll need to check how the event_queue is accessed. The TCB has `event_queue: LocalQueue<TcpEvent>`. The socket layer holds a clone of this queue. Check `TcpStream` struct fields — it has `event_queue: LocalQueue<TcpEvent>` at line 164.

**Step 2: Change TcpWrite::Output to Result**

Find `impl Future for TcpWrite` (around line 464). Change:

```rust
impl<'stream> Future for TcpWrite<'stream> {
    type Output = Result<usize, TcpError>;
```

In the `poll` method:
- Check event_queue for errors before writing
- When `write_closed`: `return Poll::Ready(Err(TcpError::NotConnected))`
- When connection gone: `return Poll::Ready(Err(TcpError::NotConnected))`
- When data written: `return Poll::Ready(Ok(n))`

**Step 3: Update TcpStream::read and TcpStream::write signatures**

These methods return the future types, so their return types change automatically. But check if there are any `async fn` wrappers or if callers expect `usize` directly.

```rust
pub fn read<'a>(&'a self, buf: &'a mut [u8]) -> TcpRead<'a> { ... }
pub fn write<'a>(&'a self, data: &'a [u8]) -> TcpWrite<'a> { ... }
```

These return `TcpRead` / `TcpWrite` which now resolve to `Result`. The `.await` callers will get `Result`.

**Step 4: Update TcpListener::accept if needed**

Check if `accept()` returns a future that depends on TcpRead/TcpWrite. It likely returns a `TcpStream` directly (via the accept queue). Probably no change needed, but verify.

**Step 5: Update tcp-echo-server.rs**

```rust
// Before:
let n = stream.read(&mut buf).await;
if n == 0 { break; }
stream.write(&buf[..n]).await;

// After:
let n = match stream.read(&mut buf).await {
    Ok(0) => break,
    Ok(n) => n,
    Err(e) => {
        println!("Read error: {:?}", e);
        break;
    }
};
if let Err(e) = stream.write(&buf[..n]).await {
    println!("Write error: {:?}", e);
    break;
}
```

**Step 6: Update tcp-echo-client.rs**

```rust
// Before:
stream.write(&payload).await;
let n = stream.read(&mut read_buf[total_read..]).await;
if n == 0 { break; }

// After:
if let Err(e) = stream.write(&payload).await {
    println!("Write error: {:?}", e);
    return;
}
let n = match stream.read(&mut read_buf[total_read..]).await {
    Ok(0) => {
        println!("Server closed connection");
        return;
    }
    Ok(n) => n,
    Err(e) => {
        println!("Read error: {:?}", e);
        return;
    }
};
```

**Step 7: Update any other callers**

Search for `.read(` and `.write(` on TcpStream across the codebase. Check tests in mod.rs or socket tests that use TcpStream.

**Step 8: Write tests**

```rust
#[test]
fn read_returns_error_on_reset() {
    // Setup TcpStream with a connection.
    // Push TcpEvent::Reset to event_queue.
    // Call read() — should return Err(TcpError::Reset).
}

#[test]
fn write_returns_error_on_timeout() {
    // Setup TcpStream with a connection.
    // Push TcpEvent::Timeout to event_queue.
    // Call write() — should return Err(TcpError::Timeout).
}
```

**Step 9: Run tests**

Run: `cargo test`
Expected: All pass

**Step 10: Commit**

```bash
git add src/net/socket/tcp.rs examples/tcp-echo-server.rs examples/tcp-echo-client.rs
git commit -m "feat(tcp): return Result from TcpStream read/write, surface Reset/Timeout errors"
```

---

## Task 8: Simultaneous Open Verification and Test

**Files:**
- Modify: `src/net/handler/tcp/mod.rs` (test section only, possibly small fix)

**Context:** Simultaneous open (both sides SYN at same time) transitions SynSent → SynReceived when a bare SYN (no ACK) arrives. Then the SynReceived side receives the peer's SYN-ACK or ACK and transitions to Established. The code exists in `process_syn_sent` (~line 1155-1199) but has never been tested.

**Step 1: Read and trace the simultaneous open path**

Read `process_syn_sent` carefully. Trace:
1. Both sides call `connect()` → both in `SynSent`
2. Side A receives Side B's SYN (no ACK) → A transitions to `SynReceived`, sends SYN-ACK
3. Side B receives Side A's SYN (no ACK) → B transitions to `SynReceived`, sends SYN-ACK
4. Side A receives Side B's SYN-ACK → A transitions to `Established`
5. Side B receives Side A's SYN-ACK → B transitions to `Established`

Step 4-5 happens in `process_syn_received` — verify it handles SYN-ACK correctly (the ACK for our SYN).

**Step 2: Write test**

```rust
#[test]
fn simultaneous_open_both_reach_established() {
    // Create two TcpHandlers (or one handler with two connections).
    // Both sides in SynSent state.
    //
    // Step 1: Feed Side A's SYN to Side B's handler.
    //   → B transitions to SynReceived, emits SYN-ACK.
    //
    // Step 2: Feed Side B's SYN to Side A's handler.
    //   → A transitions to SynReceived, emits SYN-ACK.
    //
    // Step 3: Feed B's SYN-ACK to A's handler.
    //   → A transitions to Established.
    //
    // Step 4: Feed A's SYN-ACK to B's handler.
    //   → B transitions to Established.
    //
    // Verify both connections are in Established state.
}
```

This test requires constructing SYN frames manually (use `build_tcp_frame` helper) and processing them through the handler. Follow existing test patterns.

**Step 3: Fix any issues found**

If the simultaneous open path fails (e.g., process_syn_received doesn't handle SYN-ACK correctly, or the ACK number is wrong), fix it. If it works, the test is the deliverable.

**Step 4: Run tests**

Run: `cargo test`
Expected: All pass

**Step 5: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "test(tcp): verify simultaneous open reaches Established on both sides"
```

---

## Summary

| Task | Feature | Key Files | Dependencies |
|------|---------|-----------|--------------|
| 1 | PSH flag on outgoing segments | segment.rs, mod.rs | None |
| 2 | IPv6 fragment drop counter | ipv6.rs | None |
| 3 | ECN TCB fields | tcb.rs | None |
| 4 | ECN negotiation in SYN/SYN-ACK | segment.rs, mod.rs | Task 3 |
| 5 | ECN ECT marking + CE detection | segment.rs, mod.rs | Task 4 |
| 6 | ECN ECE/CWR signaling | mod.rs, segment.rs | Task 5 |
| 7 | Socket API Result returns | tcp.rs, examples | None |
| 8 | Simultaneous open test | mod.rs | None |

**Independent groups:** Tasks 1, 2, 7, 8 are fully independent. Tasks 3→4→5→6 are sequential (ECN chain).

**Recommended execution order:** 1, 2, 3, 4, 5, 6, 7, 8 (ECN chain in the middle, bookended by simpler tasks).
