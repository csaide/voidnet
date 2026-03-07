# TCP RFC 9293 Compliance Fixes — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix the 10 highest-priority RFC 9293 compliance issues: data corruption, security vulnerabilities, and protocol violations in the TCP handler.

**Architecture:** All changes are in the TCP handler module (`mod.rs`, `tcb.rs`). Each task is independent after Task 1 (foundational). Test-first approach using the existing `build_tcp_frame` test infrastructure in `mod.rs`.

**Tech Stack:** Rust, coarsetime, existing TCP handler + wire module infrastructure.

---

### Task 1: Fix recv_buffer.write() return value — data corruption

**Files:**
- Modify: `src/net/handler/tcp/mod.rs:1531-1532` (in-order data write)
- Modify: `src/net/handler/tcp/mod.rs:2563-2564` (FinWait1 data write)
- Modify: `src/net/handler/tcp/mod.rs:2629-2630` (FinWait2 data write)
- Test: `src/net/handler/tcp/mod.rs` (add test in `mod tests`)

**Step 1: Write the failing test**

Add a unit test in `mod.rs` tests that establishes a connection, fills the recv buffer nearly full, sends a segment larger than remaining space, and verifies `rcv_nxt` only advances by the amount actually written.

```rust
#[test]
fn recv_buffer_partial_write_advances_rcv_nxt_correctly() {
    // Setup: create handler, connect, fill recv buffer to near capacity.
    // Send a data segment larger than remaining free space.
    // Verify rcv_nxt advanced by bytes_written (not payload_len).
}
```

The test should construct a scenario where `recv_buffer.free_space() < payload_len` and verify `rcv_nxt` advances by the written amount only.

**Step 2: Run test to verify it fails**

Run: `cargo test --test sync recv_buffer_partial_write` or unit test via `cargo test -p voidnet recv_buffer_partial_write`
Expected: FAIL — `rcv_nxt` advances by full `payload_len`

**Step 3: Fix the three data write sites**

In `process_established` (~line 1531):
```rust
// Before:
tcb.recv_buffer.write(payload);
tcb.rcv_nxt = rcv_nxt.wrapping_add(payload_len as u32);

// After:
let written = tcb.recv_buffer.write(payload);
tcb.rcv_nxt = rcv_nxt.wrapping_add(written as u32);
```

Apply the same fix in `process_teardown` FinWait1 (~line 2563) and FinWait2 (~line 2629):
```rust
let written = tcb.recv_buffer.write(payload);
tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(written as u32);
```

**Step 4: Run test to verify it passes**

Run: `cargo test`
Expected: PASS

**Step 5: Commit**

```
fix(tcp): use recv_buffer.write() return value for rcv_nxt advancement

rcv_nxt was advanced by the full payload length even when the recv buffer
was nearly full and only a partial write occurred. This caused sequence
number desynchronization and silent data loss (RFC 9293 §3.10.7.4 Step 7).
```

---

### Task 2: Fix out-of-order FIN processing — data loss

**Files:**
- Modify: `src/net/handler/tcp/mod.rs:1665-1698` (FIN check in process_established)
- Test: `src/net/handler/tcp/mod.rs`

**Step 1: Write the failing test**

Test that sends a FIN segment with `seg_seq > rcv_nxt` (out-of-order). Verify the connection does NOT transition to CloseWait — it should remain Established until the gap is filled.

**Step 2: Run test to verify it fails**

Expected: FAIL — connection transitions to CloseWait prematurely

**Step 3: Guard FIN processing with in-order check**

Replace the FIN check at ~line 1665:
```rust
// Before:
if seg_flags & flags::FIN != 0 {

// After:
if seg_flags & flags::FIN != 0 && seg_seq.wrapping_add(payload_len as u32) == self.connections[idx].rcv_nxt {
```

This ensures FIN is only processed when all preceding data has been received (the FIN's sequence position matches `rcv_nxt` after data processing).

Note: this means if FIN arrives out-of-order, the peer will retransmit it. We could add a `pending_remote_fin` flag for optimization later, but for correctness the simple guard is sufficient — the peer's retransmission will deliver the FIN once the gap is filled.

**Step 4: Run tests**

Run: `cargo test`
Expected: PASS

**Step 5: Commit**

```
fix(tcp): only process FIN when all preceding data received

Out-of-order segments with FIN set would transition to CloseWait before
all prior data arrived, causing data loss. Now FIN is only processed when
seg_seq + payload_len == rcv_nxt (RFC 9293 §3.10.7.4 Step 8).
```

---

### Task 3: Fix RST processing order + RFC 5961 challenge ACK

**Files:**
- Modify: `src/net/handler/tcp/mod.rs:1291-1375` (reorder process_established steps)
- Modify: `src/net/handler/tcp/mod.rs:2446-2527` (reorder process_teardown steps)
- Test: `src/net/handler/tcp/mod.rs`

**Step 1: Write two failing tests**

1. `rst_outside_window_is_silently_dropped` — send RST with `seg_seq` outside receive window. Verify connection is NOT reset.
2. `rst_in_window_but_not_exact_sends_challenge_ack` — send RST with `seg_seq` in window but != `rcv_nxt`. Verify connection survives and an ACK is sent.

**Step 2: Run tests to verify they fail**

Expected: FAIL — connection is reset in both cases

**Step 3: Reorder process_established**

Move RST check AFTER PAWS + segment acceptability. Then add RFC 5961 logic:

```rust
// After segment acceptability check passes:

// Step 2: RST check (RFC 5961).
if seg_flags & flags::RST != 0 {
    if seg_seq == self.connections[idx].rcv_nxt {
        // Exact match: reset connection.
        self.connections[idx].event_queue.push(TcpEvent::Reset);
        let id = self.connections[idx].id;
        self.decrement_syn_received(&id);
        self.connections.remove(idx);
        rx_return.push(frame);
        return;
    }
    // In-window but not exact: send challenge ACK, drop segment.
    let tcb = &self.connections[idx];
    // ... build_ack (challenge ACK) ...
    rx_return.push(frame);
    return;
}
```

Apply similar reordering in `process_teardown` — move RST check after acceptability, add RFC 5961 challenge ACK for non-exact in-window RST. Keep the TIME-WAIT RST ignore behavior.

**Step 4: Run tests**

Run: `cargo test`
Expected: PASS

**Step 5: Commit**

```
fix(tcp): reorder RST check after sequence validation, add RFC 5961 challenge ACK

RST was checked before segment acceptability, allowing out-of-window RST
to reset connections (blind RST attack). Now: (1) out-of-window RST is
dropped by acceptability check, (2) in-window non-exact RST gets challenge
ACK, (3) only exact SEG.SEQ == RCV.NXT resets (RFC 5961 §3.2).
```

---

### Task 4: Add SYN check in synchronized states (RFC 5961)

**Files:**
- Modify: `src/net/handler/tcp/mod.rs` (process_established, after RST check)
- Modify: `src/net/handler/tcp/mod.rs` (process_teardown, after RST check)
- Test: `src/net/handler/tcp/mod.rs`

**Step 1: Write failing test**

`syn_in_established_sends_challenge_ack` — send a segment with SYN flag set in Established state. Verify: (1) connection is NOT reset, (2) a challenge ACK is sent, (3) segment data is NOT processed.

**Step 2: Run test to verify it fails**

Expected: FAIL — SYN is silently ignored, data is processed

**Step 3: Add SYN check after RST check**

In `process_established`, after the RST check block and before ACK processing:

```rust
// Step 4: SYN check (RFC 5961 — challenge ACK for SYN in synchronized state).
if seg_flags & flags::SYN != 0 {
    let tcb = &self.connections[idx];
    // Send challenge ACK.
    let ts = if tcb.ts_enabled {
        let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
        Some((tsval, tcb.ts_recent))
    } else {
        None
    };
    SegmentBuilder::build_ack(
        tcb.id.local_addr, tcb.id.remote_addr,
        tcb.id.local_port, tcb.id.remote_port,
        tcb.snd_nxt, tcb.rcv_nxt,
        tcb.advertised_window(), ack_flags, ts,
        src_mac, dst_mac, self.tx_offload,
        free_frames, tx_return,
    );
    rx_return.push(frame);
    return;
}
```

Add the same check in `process_teardown`, after the RST check and before the state match.

**Step 4: Run tests**

Run: `cargo test`
Expected: PASS

**Step 5: Commit**

```
fix(tcp): send challenge ACK for SYN in synchronized states (RFC 5961)

SYN flag was not checked in ESTABLISHED or teardown states, allowing
blind SYN attacks. Now sends challenge ACK and drops the segment per
RFC 5961 §4.
```

---

### Task 5: Add FIN retransmission for teardown states

**Files:**
- Modify: `src/net/handler/tcp/mod.rs:2040` (`poll_timers` RTO match)
- Test: `src/net/handler/tcp/mod.rs`

**Step 1: Write failing test**

`fin_retransmitted_in_fin_wait1` — put a connection into FinWait1 with a retransmit deadline in the past. Call `poll_timers`. Verify a FIN-ACK segment is sent and the retransmit deadline is rescheduled.

**Step 2: Run test to verify it fails**

Expected: FAIL — `poll_timers` skips FinWait1 (`_ => continue`)

**Step 3: Add FIN retransmission cases**

In the `poll_timers` RTO match (~line 2040), before `_ => continue`:

```rust
TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck => {
    // Retransmit FIN-ACK.
    let ts = if tcb.ts_enabled {
        let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
        Some((tsval, tcb.ts_recent))
    } else {
        None
    };
    if let Some(fin_seq) = tcb.fin_seq {
        SegmentBuilder::build_fin_ack(
            id.local_addr, id.remote_addr,
            id.local_port, id.remote_port,
            fin_seq, tcb.rcv_nxt,
            tcb.advertised_window(), ts,
            src_mac, dst_mac,
            self.tx_offload, free_frames, tx_return,
        );
    }
    tcb.rto_backoff += 1;
    tcb.retransmit_deadline =
        Some(now + coarsetime::Duration::from_millis(tcb.rto << tcb.rto_backoff));
}
```

**Step 4: Run tests**

Run: `cargo test`
Expected: PASS

**Step 5: Commit**

```
feat(tcp): retransmit FIN in FinWait1, Closing, and LastAck states

Lost FIN segments were never retransmitted because poll_timers only
handled SynSent, SynReceived, and Established. Connections would hang
in teardown states until the R2 timeout (RFC 9293 §3.10.8).
```

---

### Task 6: Drop segments without ACK flag

**Files:**
- Modify: `src/net/handler/tcp/mod.rs` (process_established, before ACK processing)
- Modify: `src/net/handler/tcp/mod.rs` (process_teardown, after SYN check)
- Test: `src/net/handler/tcp/mod.rs`

**Step 1: Write failing test**

`segment_without_ack_is_dropped` — send a data segment with ACK flag cleared in Established state. Verify: no data is written to recv_buffer, segment is dropped.

**Step 2: Run test to verify it fails**

Expected: FAIL — data is processed despite missing ACK

**Step 3: Add ACK-off guard**

In `process_established`, after the SYN check (Task 4) and before ACK processing:

```rust
// Step 5 preamble: if ACK bit is off, drop segment and return.
if seg_flags & flags::ACK == 0 {
    rx_return.push(frame);
    return;
}
```

In `process_teardown`, add the same check after the SYN check and before the state match block.

**Step 4: Run tests**

Run: `cargo test`
Expected: PASS

**Step 5: Commit**

```
fix(tcp): drop segments without ACK flag in synchronized states

Segments without ACK were falling through to data/FIN processing
instead of being dropped (RFC 9293 §3.10.7.4 Step 5).
```

---

### Task 7: Handle SEG.ACK > SND.NXT

**Files:**
- Modify: `src/net/handler/tcp/mod.rs:1394` (ACK processing in process_established)
- Test: `src/net/handler/tcp/mod.rs`

**Step 1: Write failing test**

`ack_beyond_snd_nxt_sends_ack_and_drops` — send a segment with `seg_ack > snd_nxt`. Verify: (1) an ACK is sent in response, (2) no state changes occur, (3) segment data is not processed.

**Step 2: Run test to verify it fails**

Expected: FAIL — segment falls through silently

**Step 3: Add future-ACK check**

In `process_established` ACK processing, after checking `seq_lt(snd_una, seg_ack) && seq_le(seg_ack, snd_nxt)`, add an else-if before the duplicate ACK branch:

```rust
} else if seq_lt(snd_nxt, seg_ack) {
    // ACK for unsent data — send ACK and drop (RFC 9293 §3.10.7.4 Step 5).
    let tcb = &self.connections[idx];
    let ts = if tcb.ts_enabled {
        let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
        Some((tsval, tcb.ts_recent))
    } else {
        None
    };
    SegmentBuilder::build_ack(
        tcb.id.local_addr, tcb.id.remote_addr,
        tcb.id.local_port, tcb.id.remote_port,
        tcb.snd_nxt, tcb.rcv_nxt,
        tcb.advertised_window(), ack_flags, ts,
        src_mac, dst_mac, self.tx_offload,
        free_frames, tx_return,
    );
    rx_return.push(frame);
    return;
} else if seg_ack == snd_una && payload_len == 0 {
```

**Step 4: Run tests**

Run: `cargo test`
Expected: PASS

**Step 5: Commit**

```
fix(tcp): send ACK and drop segment when SEG.ACK > SND.NXT

ACKs acknowledging data not yet sent were silently ignored. Now sends
an ACK and drops the segment per RFC 9293 §3.10.7.4 Step 5.
```

---

### Task 8: Add window update WL1/WL2 guard

**Files:**
- Modify: `src/net/handler/tcp/mod.rs:1459-1461` (new-ACK window update)
- Modify: `src/net/handler/tcp/mod.rs:1500-1503` (dup-ACK window update)
- Test: `src/net/handler/tcp/mod.rs`

**Step 1: Write failing test**

`stale_segment_does_not_regress_window` — process two ACK segments out of order (segment B with higher seq first, then segment A with lower seq but different window). Verify the window is NOT overwritten by the stale segment A.

**Step 2: Run test to verify it fails**

Expected: FAIL — window is unconditionally updated

**Step 3: Add WL1/WL2 guard**

Replace the unconditional window update at ~line 1459:

```rust
// Before:
tcb.snd_wnd = tcb.scale_incoming_window(seg_wnd);
tcb.snd_wl1 = seg_seq;
tcb.snd_wl2 = seg_ack;

// After:
if seq_lt(tcb.snd_wl1, seg_seq)
    || (tcb.snd_wl1 == seg_seq && seq_le(tcb.snd_wl2, seg_ack))
{
    tcb.snd_wnd = tcb.scale_incoming_window(seg_wnd);
    tcb.snd_wl1 = seg_seq;
    tcb.snd_wl2 = seg_ack;
}
```

For the duplicate ACK window update (~line 1500), apply the same guard:

```rust
// Before:
if new_wnd != tcb.snd_wnd {
    tcb.snd_wnd = new_wnd;
    tcb.snd_wl1 = seg_seq;
    tcb.snd_wl2 = seg_ack;
}

// After:
if seq_lt(tcb.snd_wl1, seg_seq)
    || (tcb.snd_wl1 == seg_seq && seq_le(tcb.snd_wl2, seg_ack))
{
    tcb.snd_wnd = new_wnd;
    tcb.snd_wl1 = seg_seq;
    tcb.snd_wl2 = seg_ack;
}
```

**Step 4: Run tests**

Run: `cargo test`
Expected: PASS

**Step 5: Commit**

```
fix(tcp): guard window updates with SND.WL1/WL2 ordering check

Send window was unconditionally updated on every ACK. Stale out-of-order
segments could regress the window. Now uses the RFC 9293 §3.10.7.4 Step 5
guard: SND.WL1 < SEG.SEQ || (SND.WL1 == SEG.SEQ && SND.WL2 <= SEG.ACK).
```

---

### Task 9: Add ACK processing in CLOSE-WAIT

**Files:**
- Modify: `src/net/handler/tcp/mod.rs:2740-2744` (CloseWait branch in process_teardown)
- Test: `src/net/handler/tcp/mod.rs`

**Step 1: Write failing test**

`close_wait_processes_ack_for_sent_data` — put a connection in CloseWait with unacknowledged data in the send buffer. Send an ACK for that data. Verify `snd_una` advances and `send_buffer` is drained.

**Step 2: Run test to verify it fails**

Expected: FAIL — CloseWait does nothing with ACKs

**Step 3: Add ACK processing to CloseWait**

Replace the CloseWait handler:

```rust
TcpState::CloseWait => {
    // Process ACKs — local side can still send data.
    if seg_flags & flags::ACK != 0 {
        let tcb = &mut self.connections[idx];
        let snd_una = tcb.snd_una;
        let snd_nxt = tcb.snd_nxt;

        if crate::net::wire::tcp::seq_lt(snd_una, seg_ack)
            && crate::net::wire::tcp::seq_le(seg_ack, snd_nxt)
        {
            let bytes_acked = seg_ack.wrapping_sub(snd_una) as usize;
            tcb.snd_una = seg_ack;
            let buf_advance = bytes_acked.min(tcb.send_buffer.available());
            tcb.send_buffer.advance(buf_advance);

            // Window update with WL1/WL2 guard.
            if crate::net::wire::tcp::seq_lt(tcb.snd_wl1, seg_seq)
                || (tcb.snd_wl1 == seg_seq
                    && crate::net::wire::tcp::seq_le(tcb.snd_wl2, seg_ack))
            {
                tcb.snd_wnd = tcb.scale_incoming_window(seg_wnd);
                tcb.snd_wl1 = seg_seq;
                tcb.snd_wl2 = seg_ack;
            }
        }
    }
    rx_return.push(frame);
}
```

**Step 4: Run tests**

Run: `cargo test`
Expected: PASS

**Step 5: Commit**

```
fix(tcp): process ACKs in CLOSE-WAIT for half-close data transfer

CLOSE-WAIT ignored all ACKs, breaking half-close scenarios where the
local side sends data after the remote closes. Now advances snd_una and
updates the send window (RFC 9293 §3.10.7.4 Step 5 — "Do the same
processing as for the ESTABLISHED state").
```

---

### Task 10: Implement SWS avoidance (sender + receiver)

**Files:**
- Modify: `src/net/handler/tcp/tcb.rs` (add `max_snd_wnd` and `last_advertised_right_edge` fields)
- Modify: `src/net/handler/tcp/tcb.rs:297-304` (`advertised_window()`)
- Modify: `src/net/handler/tcp/mod.rs` (update `max_snd_wnd` on window updates, sender SWS check in `poll_send`)
- Test: `src/net/handler/tcp/tcb.rs`, `src/net/handler/tcp/mod.rs`

**Step 1: Add new TCB fields**

In `tcb.rs`, add to the `Tcb` struct:

```rust
/// Largest send window ever advertised by peer (for sender SWS avoidance).
pub max_snd_wnd: u32,
/// Right edge of last advertised receive window: rcv_nxt + wnd at ACK send time.
pub last_advertised_right_edge: u32,
```

Initialize both to 0 in `make_tcb()` test helper and all TCB construction sites.

**Step 2: Write failing test for receiver SWS**

Test that `advertised_window()` returns 0 when free space is less than `min(eff_snd_mss, capacity/2)` and the right edge would shrink.

**Step 3: Implement receiver SWS avoidance**

In `tcb.rs`, modify `advertised_window()`:

```rust
pub fn advertised_window(&self) -> u16 {
    let free = self.recv_buffer.free_space();
    let threshold = (self.rcv_mss as usize).min(self.recv_buffer.capacity() / 2);

    // SWS avoidance (MUST-39): don't open the window until we can
    // advertise at least min(MSS, buffer/2) of new space.
    let right_edge = self.rcv_nxt.wrapping_add(free as u32);
    let prev_right_edge = self.last_advertised_right_edge;
    let new_space = right_edge.wrapping_sub(prev_right_edge) as usize;

    let effective_free = if new_space < threshold && prev_right_edge != 0 {
        // Clamp to previous right edge to avoid shrinking.
        prev_right_edge.wrapping_sub(self.rcv_nxt).max(0) as usize
    } else {
        free
    };

    if self.wscale_enabled {
        (effective_free >> self.rcv_wscale as usize).min(u16::MAX as usize) as u16
    } else {
        effective_free.min(u16::MAX as usize) as u16
    }
}
```

Update `last_advertised_right_edge` wherever an ACK is sent (after calling `advertised_window()`). This requires setting it in `process_established` and `poll_timers` after every ACK build call.

**Step 4: Write failing test for sender SWS**

Test that `poll_send` does NOT send a sub-MSS segment when the usable window is less than `eff_snd_mss` and less than `max_snd_wnd / 2`.

**Step 5: Implement sender SWS avoidance**

In `poll_send`, after computing `can_send`:

```rust
// Sender SWS avoidance (MUST-38): don't use a small window unless
// we can send a full segment or at least half the max window.
let sws_threshold = (tcb.eff_snd_mss as usize).max(tcb.max_snd_wnd as usize / 2);
if can_send < sws_threshold && can_send < data_available {
    // Usable window too small — wait.
    // (Still allow if all remaining data fits in the window.)
} else if can_send > 0 && data_available > 0 {
    // ... existing send logic ...
}
```

Update `max_snd_wnd` wherever `snd_wnd` is updated in ACK processing:

```rust
tcb.max_snd_wnd = tcb.max_snd_wnd.max(tcb.snd_wnd);
```

**Step 6: Run all tests**

Run: `cargo test`
Expected: PASS

**Step 7: Commit**

```
feat(tcp): implement SWS avoidance for sender and receiver (MUST-38, MUST-39)

Sender: don't send sub-MSS data unless usable window >= eff_snd_mss or
>= max_snd_wnd/2. Receiver: don't open window until free space >=
min(MSS, buffer/2), preventing right edge from shrinking (also fixes
MUST-34). Tracks max_snd_wnd and last_advertised_right_edge in the TCB.
```

---

## Execution Order and Dependencies

Tasks 1-9 are independent of each other and can be implemented in any order. However, the recommended order follows the priority ranking from the design doc.

Task 10 (SWS) depends on Task 8 (WL1/WL2 guard) being done first since SWS also touches window update code.

After all 10 tasks: run `cargo test` to verify no regressions.
