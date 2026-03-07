# TCP Phase 6 Remaining Features — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement zero-window probing, full SACK (send/receive/selective retransmit), and zero-copy send path — the 5 remaining Phase 6 features.

**Architecture:** Zero-window probing in `poll_send` prevents deadlocks when peer advertises window=0. SACK block sending lets the receiver report OOO ranges. SACK block receiving lets the sender track what the peer has. Selective retransmit uses the scoreboard to retransmit only gaps. Zero-copy send eliminates heap allocation by passing ring buffer slices directly to the segment builder.

**Tech Stack:** Rust, coarsetime for timers, existing TCP handler infrastructure in `src/net/handler/tcp/`.

**Testing:** `cargo test` (no feature flags, no `--all-features`). Tests run under `sudo -E` via `.cargo/config.toml`.

**Key files reference:**
- Wire format: `src/net/wire/tcp.rs`
- TCB/config: `src/net/handler/tcp/tcb.rs`
- Handler: `src/net/handler/tcp/mod.rs`
- Segment builder: `src/net/handler/tcp/segment.rs`
- Ring buffer: `src/net/handler/tcp/ring_buffer.rs`

**What's already done (do NOT re-implement):**
- Window scaling fix (advertised_window, scale_incoming_window)
- Segment acceptability checks (is_segment_acceptable)
- Timestamp negotiation, RTTM, PAWS
- SACK Permitted negotiation in SYN/SYN-ACK
- Wire functions: parse_sack_blocks, write_sack_option, parse_timestamp, write_timestamp_option
- TCB fields: persist_deadline, persist_backoff, sack_enabled, sack_scoreboard, ooo_ranges — all exist but are unused

---

## Task 1: Zero-Window Probing — Persist Timer in poll_send

**Files:**
- Modify: `src/net/handler/tcp/mod.rs:1896-2065` (poll_send)
- Modify: `src/net/handler/tcp/mod.rs:1323-1406` (process_established ACK processing)

**Context:** When `snd_wnd == 0` and there's data to send, the sender must probe periodically to detect window reopening. TCB already has `persist_deadline: Option<Instant>` and `persist_backoff: u8` — both initialized to None/0 and never used.

**Step 1: Write failing test for persist timer activation**

In `src/net/handler/tcp/mod.rs`, add to the `#[cfg(test)]` section:

```rust
#[test]
fn persist_timer_activates_on_zero_window() {
    // Setup: Established connection with peer window = 0 and data in send buffer.
    let (mut handler, idx) = make_established_handler();
    let tcb = &mut handler.connections[idx];
    tcb.snd_wnd = 0;
    tcb.send_buffer.write(b"hello");
    let now = Instant::recent();

    // poll_send should NOT send data (window is 0) but should set persist_deadline.
    let mut free = make_frame_buffer(4);
    let mut tx = make_frame_buffer(0);
    handler.poll_send(now, SRC_MAC, &make_neighbor_handler(), &mut free, &mut tx);

    let tcb = &handler.connections[idx];
    assert!(tcb.persist_deadline.is_some(), "persist timer should be set");
    assert_eq!(tx.len(), 0, "no data should be sent with zero window");
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test persist_timer_activates_on_zero_window`
Expected: FAIL — persist_deadline is never set.

**Step 3: Implement persist timer detection in poll_send**

In `src/net/handler/tcp/mod.rs` inside `poll_send`, after the `if can_send > 0 && data_available > 0` block (around line 1973), add a new block:

```rust
// Zero-window probing: when send window is 0 and we have data, start persist timer.
if send_window == 0 && data_available > 0 && tcb.persist_deadline.is_none() {
    tcb.persist_deadline = Some(now + coarsetime::Duration::from_millis(tcb.rto));
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test persist_timer_activates_on_zero_window`
Expected: PASS

**Step 5: Write failing test for probe sending**

```rust
#[test]
fn persist_timer_sends_probe() {
    let (mut handler, idx) = make_established_handler();
    let tcb = &mut handler.connections[idx];
    tcb.snd_wnd = 0;
    tcb.send_buffer.write(b"hello");
    tcb.rto = 1000;
    // Set persist deadline in the past so it fires.
    tcb.persist_deadline = Some(Instant::recent() - coarsetime::Duration::from_millis(1));
    let now = Instant::recent();

    let mut free = make_frame_buffer(4);
    let mut tx = make_frame_buffer(0);
    handler.poll_send(now, SRC_MAC, &make_neighbor_handler(), &mut free, &mut tx);

    assert_eq!(tx.len(), 1, "one probe segment should be sent");
    let tcb = &handler.connections[idx];
    assert_eq!(tcb.persist_backoff, 1, "backoff should increment");
    assert!(tcb.persist_deadline.is_some(), "next probe should be scheduled");
}
```

**Step 6: Run test to verify it fails**

Run: `cargo test persist_timer_sends_probe`
Expected: FAIL

**Step 7: Implement probe sending in poll_send**

In `poll_send`, after the persist timer detection block, add:

```rust
// Send zero-window probe if deadline expired.
if let Some(deadline) = tcb.persist_deadline {
    if now >= deadline && send_window == 0 && data_available > 0 {
        // Probe: send 1 byte from the send buffer at bytes_in_flight offset.
        let probe_len = 1;
        let mut probe_buf = [0u8; 1];
        tcb.send_buffer.peek_at(bytes_in_flight, &mut probe_buf);

        let dst_mac = neighbor_handler
            .lookup(now, &tcb.id.remote_addr)
            .unwrap_or(crate::net::wire::ethernet::MacAddress::broadcast());

        let ts = if tcb.ts_enabled {
            let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
            Some((tsval, tcb.ts_recent))
        } else {
            None
        };
        SegmentBuilder::build_data(
            tcb.id.local_addr,
            tcb.id.remote_addr,
            tcb.id.local_port,
            tcb.id.remote_port,
            tcb.snd_nxt,
            tcb.rcv_nxt,
            tcb.advertised_window(),
            &probe_buf[..probe_len],
            ts,
            src_mac,
            dst_mac,
            self.tx_offload,
            free_frames,
            tx_return,
        );

        tcb.snd_nxt = tcb.snd_nxt.wrapping_add(probe_len as u32);

        // Schedule next probe with exponential backoff (cap at 60s).
        let backoff_rto = (tcb.rto << tcb.persist_backoff).min(60_000);
        tcb.persist_deadline = Some(now + coarsetime::Duration::from_millis(backoff_rto));
        tcb.persist_backoff = tcb.persist_backoff.saturating_add(1).min(6);
    }
}
```

**Step 8: Run test to verify it passes**

Run: `cargo test persist_timer_sends_probe`
Expected: PASS

**Step 9: Write failing test for persist timer recovery**

```rust
#[test]
fn persist_timer_clears_on_window_reopen() {
    let (mut handler, idx) = make_established_handler();
    let tcb = &mut handler.connections[idx];
    tcb.persist_deadline = Some(Instant::recent());
    tcb.persist_backoff = 3;
    // Simulate receiving an ACK that opens the window.
    // This happens in process_established when snd_wnd becomes > 0.
    tcb.snd_wnd = 65535;
    tcb.persist_deadline = None;
    tcb.persist_backoff = 0;

    assert!(tcb.persist_deadline.is_none());
    assert_eq!(tcb.persist_backoff, 0);
}
```

**Step 10: Implement persist timer recovery in process_established**

In `process_established`, in the ACK processing section (around line 1394 where `tcb.snd_wnd` is updated), add after the window update:

```rust
// Clear persist timer when window reopens.
if tcb.snd_wnd > 0 && tcb.persist_deadline.is_some() {
    tcb.persist_deadline = None;
    tcb.persist_backoff = 0;
}
```

**Step 11: Run all persist tests**

Run: `cargo test persist`
Expected: All PASS

**Step 12: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): implement zero-window probing with persist timer"
```

---

## Task 2: SACK Block Sending (Receiver Side)

**Files:**
- Modify: `src/net/handler/tcp/segment.rs:259-323` (build_ack — add SACK block support)
- Modify: `src/net/handler/tcp/mod.rs:1473-1502` (OOO data path — generate SACK blocks)

**Context:** When OOO data arrives, the receiver should include SACK blocks in the duplicate ACK reporting which ranges it has received. Wire functions `write_sack_option` and `parse_sack_blocks` already exist. `build_ack` currently accepts only `timestamp: Option<(u32, u32)>`.

**Step 1: Write failing test for build_ack with SACK blocks**

In `src/net/handler/tcp/segment.rs`, add to the `#[cfg(test)]` section:

```rust
#[test]
fn build_ack_with_sack_blocks() {
    let mut free = make_test_frames(2);
    let mut tx = Vec::new();

    let sack_blocks = vec![(1000u32, 1500u32), (2000u32, 2500u32)];

    SegmentBuilder::build_ack_with_sack(
        IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])),
        IpAddress::V4(Ipv4Address::new([10, 0, 0, 2])),
        1234,
        80,
        100,   // seq
        200,   // ack
        65535, // window
        None,  // no timestamp
        &sack_blocks,
        MacAddress::broadcast(),
        MacAddress::broadcast(),
        false,
        &mut free,
        &mut tx,
    );

    assert_eq!(tx.len(), 1, "should produce one frame");
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test build_ack_with_sack_blocks`
Expected: FAIL — `build_ack_with_sack` doesn't exist.

**Step 3: Implement build_ack_with_sack in segment.rs**

Add a new method to `SegmentBuilder` after `build_ack` (after line 323):

```rust
/// Build an ACK segment with optional SACK blocks.
/// Used when sending duplicate ACKs for out-of-order data.
#[inline]
pub fn build_ack_with_sack<'umem>(
    local_addr: IpAddress,
    remote_addr: IpAddress,
    local_port: u16,
    remote_port: u16,
    seq: u32,
    ack: u32,
    window: u16,
    timestamp: Option<(u32, u32)>,
    sack_blocks: &[(u32, u32)],
    src_mac: MacAddress,
    dst_mac: MacAddress,
    tx_offload: bool,
    free_frames: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) {
    // Build options buffer: timestamp (12 bytes) + SACK (2 + 8*N bytes).
    // Max TCP option space = 40 bytes.
    let mut opt_buf = [0u8; 40];
    let mut opt_len = 0;

    if let Some((tsval, tsecr)) = timestamp {
        opt_buf[0] = options::NOP;
        opt_buf[1] = options::NOP;
        write_timestamp_option(&mut opt_buf[2..], tsval, tsecr);
        opt_len = 12;
    }

    if !sack_blocks.is_empty() {
        let sack_written =
            crate::net::wire::tcp::write_sack_option(&mut opt_buf[opt_len..], sack_blocks);
        opt_len += sack_written;
    }

    let tcp_options = &opt_buf[..opt_len];

    match (local_addr, remote_addr) {
        (IpAddress::V4(local_ip), IpAddress::V4(remote_ip)) => {
            Self::build_ipv4_segment(
                local_ip, remote_ip, local_port, remote_port,
                seq, ack, flags::ACK, window, tcp_options,
                src_mac, dst_mac, tx_offload, free_frames, tx_return,
            );
        }
        (IpAddress::V6(local_ip), IpAddress::V6(remote_ip)) => {
            Self::build_ipv6_segment(
                local_ip, remote_ip, local_port, remote_port,
                seq, ack, flags::ACK, window, tcp_options,
                src_mac, dst_mac, tx_offload, free_frames, tx_return,
            );
        }
        _ => {}
    }
}
```

Add `write_sack_option` to the imports at the top of `segment.rs` (line 9):

```rust
use crate::net::wire::tcp::{
    TCP_HEADER_LEN, TcpHeader, flags, options, write_mss_option,
    write_sack_option, write_sack_permitted_option, write_timestamp_option,
    write_window_scale_option,
};
```

**Step 4: Run test to verify it passes**

Run: `cargo test build_ack_with_sack_blocks`
Expected: PASS

**Step 5: Write failing test for SACK blocks in OOO duplicate ACK**

In `src/net/handler/tcp/mod.rs` tests:

```rust
#[test]
fn ooo_data_sends_sack_blocks() {
    // Setup: established connection, send OOO segment (gap at rcv_nxt).
    let (mut handler, idx) = make_established_handler();
    let tcb = &mut handler.connections[idx];
    tcb.sack_enabled = true;
    let rcv_nxt = tcb.rcv_nxt;

    // Send segment starting 100 bytes after rcv_nxt (creates gap).
    // The duplicate ACK should include SACK block (rcv_nxt+100, rcv_nxt+200).
    // We verify by checking that a frame was emitted (the dup ACK with SACK).
    let ooo_seq = rcv_nxt.wrapping_add(100);
    let payload = vec![0xAA; 100];

    // Build an inbound frame with OOO data and process it.
    // ... (use existing test helper to build inbound TCP segment)
    // After processing, verify ooo_ranges has the entry and a dup ACK was sent.
    let tcb = &handler.connections[idx];
    assert!(tcb.ooo_ranges.contains_key(&ooo_seq));
}
```

Note: The exact test construction depends on existing test helpers (`make_established_handler`, inbound frame builders). The implementer should follow the patterns already used in existing tests like `poll_send_builds_data_segment` (line 3301).

**Step 6: Implement SACK block generation in process_established OOO path**

In `src/net/handler/tcp/mod.rs`, in the OOO data branch (around line 1473-1502), replace the `SegmentBuilder::build_ack` call with `build_ack_with_sack`:

```rust
} else if seq_lt(rcv_nxt, seg_seq) {
    // Out-of-order data.
    let offset = seg_seq.wrapping_sub(rcv_nxt) as usize;
    let payload = &frame[payload_offset..payload_offset + payload_len];
    let tcb = &mut self.connections[idx];
    tcb.recv_buffer.write_at(offset, payload);
    tcb.ooo_ranges.insert(seg_seq, payload_len as u32);

    // Generate SACK blocks from ooo_ranges (most recent first, per RFC 2018 §3).
    // Max blocks: 3 with timestamps, 4 without.
    let max_blocks = if tcb.ts_enabled { 3 } else { 4 };
    let mut sack_blocks: Vec<(u32, u32)> = Vec::new();

    if tcb.sack_enabled {
        // Most recently inserted range first.
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

    // Send duplicate ACK (with current rcv_nxt) and SACK blocks.
    let ts = if tcb.ts_enabled {
        let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
        Some((tsval, tcb.ts_recent))
    } else {
        None
    };
    SegmentBuilder::build_ack_with_sack(
        tcb.id.local_addr,
        tcb.id.remote_addr,
        tcb.id.local_port,
        tcb.id.remote_port,
        tcb.snd_nxt,
        tcb.rcv_nxt,
        tcb.advertised_window(),
        ts,
        &sack_blocks,
        src_mac,
        dst_mac,
        self.tx_offload,
        free_frames,
        tx_return,
    );
}
```

Add `SegmentBuilder::build_ack_with_sack` to the imports if needed — it's on `SegmentBuilder` which is already imported.

**Step 7: Run tests**

Run: `cargo test ooo_data_sends_sack`
Expected: PASS

**Step 8: Commit**

```bash
git add src/net/handler/tcp/segment.rs src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): send SACK blocks in duplicate ACKs for OOO data"
```

---

## Task 3: SACK Block Receiving (Sender Scoreboard)

**Files:**
- Modify: `src/net/handler/tcp/mod.rs:1323-1406` (process_established ACK processing)

**Context:** When receiving ACKs with SACK blocks, the sender should parse them and update `sack_scoreboard` (BTreeMap<u32, u32>). On cumulative ACK advance, prune entries below snd_una. On RTO, clear the scoreboard entirely.

**Step 1: Write failing test for scoreboard update**

```rust
#[test]
fn sack_blocks_update_scoreboard() {
    let (mut handler, idx) = make_established_handler();
    let tcb = &mut handler.connections[idx];
    tcb.sack_enabled = true;

    // Simulate receiving an ACK with SACK blocks.
    // After processing, sack_scoreboard should contain the reported ranges.
    // (Build inbound ACK frame with SACK options and process it.)
    // Verify: handler.connections[idx].sack_scoreboard contains expected entries.
    assert!(tcb.sack_scoreboard.is_empty()); // initially empty
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test sack_blocks_update_scoreboard`
Expected: FAIL (or trivially passes since scoreboard is empty — adjust test to send actual SACK-bearing ACK)

**Step 3: Implement SACK block parsing in process_established ACK path**

In `process_established`, inside the valid new ACK branch (around line 1329-1396), after the window update (line 1396), add:

```rust
// Parse and merge SACK blocks into scoreboard.
if tcb.sack_enabled {
    let (blocks, count) = crate::net::wire::tcp::parse_sack_blocks(options);
    for i in 0..count {
        if let Some((left, right)) = blocks[i] {
            tcb.sack_scoreboard.insert(left, right.wrapping_sub(left));
        }
    }
    // Prune scoreboard entries below snd_una.
    let snd_una = tcb.snd_una;
    tcb.sack_scoreboard.retain(|&start, _| seq_le(snd_una, start));
}
```

Also add SACK parsing in the **duplicate ACK** branch (around line 1397-1406):

```rust
} else if seg_ack == snd_una && payload_len == 0 {
    // Duplicate ACK.
    let tcb = &mut self.connections[idx];
    tcb.dup_ack_count += 1;

    // Parse SACK blocks on duplicate ACKs too.
    if tcb.sack_enabled {
        let (blocks, count) = crate::net::wire::tcp::parse_sack_blocks(options);
        for i in 0..count {
            if let Some((left, right)) = blocks[i] {
                tcb.sack_scoreboard.insert(left, right.wrapping_sub(left));
            }
        }
    }

    // Keep-alive probe responses arrive as duplicate ACKs — reset timer.
    if tcb.keep_alive_enabled && tcb.keep_alive_probes_sent > 0 {
        tcb.last_activity = now;
        tcb.keep_alive_probes_sent = 0;
    }
}
```

**Step 4: Clear scoreboard on RTO retransmit**

In `poll_timers`, in the RTO retransmit path for `TcpState::Established` (around line 1822-1856), add after the cwnd reset:

```rust
// Clear SACK scoreboard on RTO — fall back to full retransmit.
tcb.sack_scoreboard.clear();
```

**Step 5: Run tests**

Run: `cargo test sack`
Expected: All PASS

**Step 6: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): parse received SACK blocks and maintain sender scoreboard"
```

---

## Task 4: Selective Retransmit Using SACK Scoreboard

**Files:**
- Modify: `src/net/handler/tcp/mod.rs:1681-1728` (fast retransmit in poll_timers)

**Context:** Currently fast retransmit always retransmits from `snd_una`. With SACK scoreboard, we can find the first gap (un-SACKed range) and retransmit only that, avoiding redundant retransmission of data the peer already has.

**Step 1: Write failing test for selective retransmit**

```rust
#[test]
fn fast_retransmit_uses_sack_scoreboard() {
    let (mut handler, idx) = make_established_handler();
    let tcb = &mut handler.connections[idx];
    tcb.sack_enabled = true;
    tcb.dup_ack_count = 3; // trigger fast retransmit

    // Write 3 MSS worth of data to send buffer.
    let mss = tcb.eff_snd_mss as usize;
    let data = vec![0xAA; mss * 3];
    tcb.send_buffer.write(&data);
    tcb.snd_nxt = tcb.snd_una.wrapping_add((mss * 3) as u32);

    // Peer has SACKed the 2nd MSS-worth of data.
    // Gap is: [snd_una, snd_una + mss) — this is what should be retransmitted.
    let sack_start = tcb.snd_una.wrapping_add(mss as u32);
    tcb.sack_scoreboard.insert(sack_start, mss as u32);

    let now = Instant::recent();
    let mut free = make_frame_buffer(4);
    let mut tx = make_frame_buffer(0);
    handler.poll_timers(now, SRC_MAC, &make_neighbor_handler(), &mut free, &mut tx);

    // Should retransmit 1 MSS from snd_una (the gap).
    assert_eq!(tx.len(), 1, "should retransmit one segment");
    let tcb = &handler.connections[idx];
    assert_eq!(tcb.dup_ack_count, 0, "dup_ack_count should be reset");
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test fast_retransmit_uses_sack_scoreboard`
Expected: FAIL (retransmits from offset 0, not using scoreboard)

**Step 3: Implement selective retransmit in fast retransmit path**

Replace the fast retransmit logic in `poll_timers` (lines 1681-1728) with:

```rust
// Fast retransmit pass — triggered by 3 duplicate ACKs.
for tcb in &mut self.connections {
    if tcb.state != TcpState::Established || tcb.dup_ack_count < 3 {
        continue;
    }

    // Determine what to retransmit.
    let (retransmit_offset, retransmit_len) = if tcb.sack_enabled && !tcb.sack_scoreboard.is_empty()
    {
        // Find first gap in scoreboard between snd_una and snd_nxt.
        let mut gap_start = tcb.snd_una;
        let mut found_gap = None;

        for (&sack_start, &sack_len) in &tcb.sack_scoreboard {
            if seq_lt(gap_start, sack_start) {
                // Gap: [gap_start, sack_start)
                let gap_len = sack_start.wrapping_sub(gap_start) as usize;
                let len = gap_len.min(tcb.eff_snd_mss as usize);
                let offset = gap_start.wrapping_sub(tcb.snd_una) as usize;
                found_gap = Some((offset, len));
                break;
            }
            // Move past this SACKed range.
            let sack_end = sack_start.wrapping_add(sack_len);
            if seq_lt(gap_start, sack_end) {
                gap_start = sack_end;
            }
        }

        found_gap.unwrap_or_else(|| {
            // No gap found before scoreboard — retransmit from snd_una.
            let len = tcb.send_buffer.available().min(tcb.eff_snd_mss as usize);
            (0, len)
        })
    } else {
        // No SACK — retransmit from snd_una.
        let len = tcb.send_buffer.available().min(tcb.eff_snd_mss as usize);
        (0, len)
    };

    if retransmit_len == 0 {
        continue;
    }

    let id = tcb.id;
    let dst_mac = neighbor_handler
        .lookup(now, &id.remote_addr)
        .unwrap_or(crate::net::wire::ethernet::MacAddress::broadcast());

    let mut payload = vec![0u8; retransmit_len];
    tcb.send_buffer.peek_at(retransmit_offset, &mut payload);

    let seq = tcb.snd_una.wrapping_add(retransmit_offset as u32);

    let ts = if tcb.ts_enabled {
        let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
        Some((tsval, tcb.ts_recent))
    } else {
        None
    };
    SegmentBuilder::build_data(
        id.local_addr,
        id.remote_addr,
        id.local_port,
        id.remote_port,
        seq,
        tcb.rcv_nxt,
        tcb.advertised_window(),
        &payload,
        ts,
        src_mac,
        dst_mac,
        self.tx_offload,
        free_frames,
        tx_return,
    );

    // Fast recovery: halve cwnd.
    tcb.ssthresh = (tcb.cwnd / 2).max(2 * tcb.eff_snd_mss as u32);
    tcb.cwnd = tcb.ssthresh;
    tcb.dup_ack_count = 0;
}
```

Note: `seq_lt` and `seq_le` are already imported at the top of `process_established`; ensure they are accessible in `poll_timers` scope (they're module-level functions in `wire::tcp`).

**Step 4: Run tests**

Run: `cargo test fast_retransmit`
Expected: All PASS (both old and new tests)

**Step 5: Commit**

```bash
git add src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): selective retransmit using SACK scoreboard"
```

---

## Task 5: Zero-Copy Send Path

**Files:**
- Modify: `src/net/handler/tcp/ring_buffer.rs` (add peek_slices)
- Modify: `src/net/handler/tcp/segment.rs` (add build_data_from_slices)
- Modify: `src/net/handler/tcp/mod.rs` (update poll_send and poll_timers call sites)

### Step 1: Write failing test for peek_slices

In `src/net/handler/tcp/ring_buffer.rs`, add to tests:

```rust
#[test]
fn peek_slices_no_wrap() {
    let mut rb = RingBuffer::new(64);
    rb.write(b"hello world");
    let (a, b) = rb.peek_slices(0, 5);
    assert_eq!(a, b"hello");
    assert!(b.is_empty());
    assert_eq!(rb.available(), 11); // unchanged
}

#[test]
fn peek_slices_with_wrap() {
    let mut rb = RingBuffer::new(16);
    // Move head near the end.
    rb.write(&[0xAA; 12]);
    let mut discard = [0u8; 12];
    rb.read(&mut discard);
    // head=12. Write 8 bytes: 4 at end [12..16], 4 wrap [0..4].
    rb.write(&[0xBB; 8]);

    let (a, b) = rb.peek_slices(0, 8);
    assert_eq!(a, &[0xBB; 4]); // [12..16]
    assert_eq!(b, &[0xBB; 4]); // [0..4]
}

#[test]
fn peek_slices_with_offset() {
    let mut rb = RingBuffer::new(64);
    rb.write(b"hello world");
    let (a, b) = rb.peek_slices(6, 5);
    assert_eq!(a, b"world");
    assert!(b.is_empty());
}
```

### Step 2: Run test to verify it fails

Run: `cargo test peek_slices`
Expected: FAIL — method doesn't exist.

### Step 3: Implement peek_slices

In `src/net/handler/tcp/ring_buffer.rs`, add to `impl RingBuffer` (after `peek_at`):

```rust
/// Return two slices covering `len` bytes starting at `offset` from `head`,
/// without advancing `head`. The first slice covers data up to the end of
/// the backing buffer; the second covers the wrap-around portion (empty if
/// no wrap occurs). Used for zero-copy segment building.
#[inline]
pub fn peek_slices(&self, offset: usize, len: usize) -> (&[u8], &[u8]) {
    debug_assert!(offset + len <= self.len);
    let pos = (self.head.wrapping_add(offset)) & self.mask;
    let first = len.min(self.buf.len() - pos);
    if first >= len {
        (&self.buf[pos..pos + len], &[])
    } else {
        (&self.buf[pos..], &self.buf[..len - first])
    }
}
```

### Step 4: Run test to verify it passes

Run: `cargo test peek_slices`
Expected: PASS

### Step 5: Write failing test for build_data_from_slices

In `src/net/handler/tcp/segment.rs` tests:

```rust
#[test]
fn build_data_from_slices_two_parts() {
    let mut free = make_test_frames(2);
    let mut tx = Vec::new();

    let part1 = b"hel";
    let part2 = b"lo";

    SegmentBuilder::build_data_from_slices(
        IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])),
        IpAddress::V4(Ipv4Address::new([10, 0, 0, 2])),
        1234,
        80,
        100,
        200,
        65535,
        (part1.as_slice(), part2.as_slice()),
        None,
        MacAddress::broadcast(),
        MacAddress::broadcast(),
        false,
        &mut free,
        &mut tx,
    );

    assert_eq!(tx.len(), 1, "should produce one frame");
}
```

### Step 6: Run test to verify it fails

Run: `cargo test build_data_from_slices`
Expected: FAIL — method doesn't exist.

### Step 7: Implement build_data_from_slices

In `segment.rs`, add two new internal helpers `build_ipv4_data_segment_slices` and `build_ipv6_data_segment_slices` that accept `(&[u8], &[u8])` instead of `&[u8]`. These are copies of the existing `build_ipv4_data_segment`/`build_ipv6_data_segment` but write two payload slices contiguously:

First, add the public method after `build_data`:

```rust
/// Build a data segment from two contiguous slices (zero-copy from ring buffer).
/// The two slices represent data that may wrap in the ring buffer.
#[inline]
pub fn build_data_from_slices<'umem>(
    local_addr: IpAddress,
    remote_addr: IpAddress,
    local_port: u16,
    remote_port: u16,
    seq: u32,
    ack: u32,
    window: u16,
    payload: (&[u8], &[u8]),
    timestamp: Option<(u32, u32)>,
    src_mac: MacAddress,
    dst_mac: MacAddress,
    tx_offload: bool,
    free_frames: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) {
    let mut ts_buf = [0u8; 12];
    let tcp_options: &[u8] = if let Some((tsval, tsecr)) = timestamp {
        ts_buf[0] = options::NOP;
        ts_buf[1] = options::NOP;
        write_timestamp_option(&mut ts_buf[2..], tsval, tsecr);
        &ts_buf
    } else {
        &[]
    };

    match (local_addr, remote_addr) {
        (IpAddress::V4(local_ip), IpAddress::V4(remote_ip)) => {
            Self::build_ipv4_data_segment_slices(
                local_ip, remote_ip, local_port, remote_port,
                seq, ack, flags::ACK, window, payload,
                tcp_options, src_mac, dst_mac, tx_offload,
                free_frames, tx_return,
            );
        }
        (IpAddress::V6(local_ip), IpAddress::V6(remote_ip)) => {
            Self::build_ipv6_data_segment_slices(
                local_ip, remote_ip, local_port, remote_port,
                seq, ack, flags::ACK, window, payload,
                tcp_options, src_mac, dst_mac, tx_offload,
                free_frames, tx_return,
            );
        }
        _ => {}
    }
}
```

Then add the internal helpers. These follow the same pattern as existing `build_ipv4_data_segment` / `build_ipv6_data_segment` but accept `payload: (&[u8], &[u8])` and compute `payload_len = payload.0.len() + payload.1.len()`. When writing the payload to the frame, write both slices sequentially:

```rust
// In the frame writing section, replace:
//   frame[payload_start..payload_start + payload.len()].copy_from_slice(payload);
// With:
//   frame[payload_start..payload_start + payload.0.len()].copy_from_slice(payload.0);
//   if !payload.1.is_empty() {
//       let p2_start = payload_start + payload.0.len();
//       frame[p2_start..p2_start + payload.1.len()].copy_from_slice(payload.1);
//   }
```

The implementer should copy `build_ipv4_data_segment` (find it by searching for `fn build_ipv4_data_segment`) and modify the payload parameter and copy logic. Same for the IPv6 variant. The checksum functions already work on byte ranges within the frame, so they need no changes.

### Step 8: Run test to verify it passes

Run: `cargo test build_data_from_slices`
Expected: PASS

### Step 9: Update poll_send to use zero-copy path

In `src/net/handler/tcp/mod.rs`, in `poll_send` (around lines 1924-1953), replace:

```rust
// OLD:
let mut payload = vec![0u8; to_send];
tcb.send_buffer.peek_at(bytes_in_flight, &mut payload);
// ... build_data(..., &payload, ...)
```

With:

```rust
// NEW: zero-copy from ring buffer.
let payload = tcb.send_buffer.peek_slices(bytes_in_flight, to_send);
// ... build_data_from_slices(..., payload, ...)
```

Update the `SegmentBuilder::build_data` call to `SegmentBuilder::build_data_from_slices` and pass the tuple directly.

### Step 10: Update poll_timers fast retransmit to use zero-copy path

In `poll_timers`, in the fast retransmit path, replace:

```rust
let mut payload = vec![0u8; retransmit_len];
tcb.send_buffer.peek_at(retransmit_offset, &mut payload);
// ... build_data(..., &payload, ...)
```

With:

```rust
let payload = tcb.send_buffer.peek_slices(retransmit_offset, retransmit_len);
// ... build_data_from_slices(..., payload, ...)
```

### Step 11: Update poll_timers RTO retransmit to use zero-copy path

In `poll_timers`, in the RTO retransmit path for `TcpState::Established` (around line 1822-1848), replace:

```rust
let mut payload = vec![0u8; retransmit_len];
tcb.send_buffer.peek_at(0, &mut payload);
// ... build_data(..., &payload, ...)
```

With:

```rust
let payload = tcb.send_buffer.peek_slices(0, retransmit_len);
// ... build_data_from_slices(..., payload, ...)
```

### Step 12: Run all tests

Run: `cargo test`
Expected: All PASS

### Step 13: Commit

```bash
git add src/net/handler/tcp/ring_buffer.rs src/net/handler/tcp/segment.rs src/net/handler/tcp/mod.rs
git commit -m "feat(tcp): zero-copy send path with peek_slices and build_data_from_slices"
```

---

## Summary

| Task | Feature | Key Files |
|------|---------|-----------|
| 1 | Zero-window probing (persist timer) | mod.rs (poll_send, process_established) |
| 2 | SACK block sending (receiver) | segment.rs (build_ack_with_sack), mod.rs (OOO path) |
| 3 | SACK block receiving (sender) | mod.rs (ACK processing, RTO path) |
| 4 | Selective retransmit | mod.rs (fast retransmit in poll_timers) |
| 5 | Zero-copy send path | ring_buffer.rs, segment.rs, mod.rs |

**Dependencies:** Task 1 is independent. Tasks 2 → 3 → 4 build on each other. Task 5 is independent but should be done last since Tasks 1-4 modify the same call sites.
