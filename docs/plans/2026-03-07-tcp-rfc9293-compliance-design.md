# TCP RFC 9293 Compliance Fixes — Design

**Goal:** Fix the 10 highest-priority RFC 9293 compliance issues found during a full audit of the TCP implementation against the RFC and referenced standards (RFC 5961, 6298, 5681).

**Architecture:** All fixes are localized to the TCP handler (`mod.rs`), TCB (`tcb.rs`), and segment builder (`segment.rs`). No new files needed. Most fixes are small, surgical changes to existing processing logic.

---

## 1. recv_buffer.write() return value — data corruption fix

### Problem
`mod.rs:~1535`: `rcv_nxt` advances by full `payload.len()` even when `recv_buffer.write()` returns fewer bytes (buffer nearly full). This desynchronizes `rcv_nxt` from actual buffered data, causing silent data loss.

### Fix
Capture the return value of `recv_buffer.write(payload)`. Only advance `rcv_nxt` by the number of bytes actually written. If partial write occurs, the unwritten portion will be retransmitted by the peer (since we won't ACK past what we buffered).

```rust
let written = tcb.recv_buffer.write(payload);
tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(written as u32);
```

Also audit `write_at()` for OOO data — ensure offset + data doesn't exceed buffer capacity.

---

## 2. Out-of-order FIN processing — data loss fix

### Problem
`mod.rs:~1665`: FIN is processed whenever the flag is set, regardless of whether all preceding data has been received. An out-of-order segment with FIN transitions to CLOSE-WAIT before prior data arrives.

### Fix
Only process FIN when the segment's data ends exactly at `rcv_nxt`. After data processing (Step 7), check: `seg_seq + payload_len == rcv_nxt` (accounting for wrapping). If FIN is set but this condition is false, defer FIN processing — store a flag (`pending_remote_fin: bool`) and re-check when OOO gaps are filled.

---

## 3. RST ordering + challenge ACK (RFC 5961) — security fix

### Problem
Two issues combined:
1. RST is checked before sequence number validation (`mod.rs:~1296`), accepting out-of-window RSTs.
2. No challenge ACK for in-window but non-exact RST (RFC 5961 MUST).

### Fix
Reorder `process_established` to match RFC §3.10.7.4 step order:
1. **Step 1:** PAWS check, then segment acceptability check (already exists, just move before RST)
2. **Step 2:** RST check — only AFTER acceptability. Add RFC 5961 logic:
   - `SEG.SEQ == RCV.NXT` → reset connection
   - In-window but not exact → send challenge ACK, drop segment
   - Out-of-window → already rejected by Step 1

Apply the same reordering to `process_teardown`.

---

## 4. SYN check in synchronized states (RFC 5961) — security fix

### Problem
Neither `process_established` nor `process_teardown` check for the SYN flag. SYN in ESTABLISHED should trigger a challenge ACK.

### Fix
After Step 3 (security/precedence — skipped) and before Step 5 (ACK), add Step 4: if `seg_flags & SYN != 0`, send a challenge ACK and drop the segment. This applies to all synchronized states: ESTABLISHED, FIN-WAIT-1/2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT.

---

## 5. FIN retransmission in teardown states

### Problem
`poll_timers` RTO match only handles SynSent, SynReceived, Established. FIN-WAIT-1, Closing, and LAST-ACK hit `_ => continue`. Lost FINs are never retransmitted.

### Fix
Add cases for `FinWait1`, `Closing`, and `LastAck` in the `poll_timers` retransmit match. These should retransmit the FIN segment (rebuild from TCB state: `build_fin_ack` with `seq = snd_nxt - 1`, `ack = rcv_nxt`). Apply the same exponential backoff and R2 threshold logic.

---

## 6. "ACK bit off" drop

### Problem
Segments without ACK flag in ESTABLISHED/teardown states fall through to data/FIN processing instead of being dropped.

### Fix
In `process_established`, after the RST check (Step 2) and SYN check (Step 4), add Step 5 preamble:
```rust
if seg_flags & flags::ACK == 0 {
    return; // drop segment
}
```

Same check needed at the top of `process_teardown` ACK-dependent processing.

---

## 7. SEG.ACK > SND.NXT handling

### Problem
ACKs acknowledging data not yet sent are silently ignored. RFC requires: send ACK, drop segment, return.

### Fix
In the ACK processing section of `process_established`, after the `snd_una < seg_ack <= snd_nxt` check, add:
```rust
if seq_lt(tcb.snd_nxt, seg_ack) {
    // ACK for unsent data — send ACK and drop
    tcb.ack_pending = true;
    tcb.ack_delay_count = u8::MAX; // force immediate
    return;
}
```

---

## 8. Window update WL1/WL2 guard

### Problem
`snd_wnd`/`snd_wl1`/`snd_wl2` are unconditionally updated on every new ACK. Stale out-of-order segments can regress the send window.

### Fix
Guard the window update with the RFC condition:
```rust
if seq_lt(tcb.snd_wl1, seg_seq)
    || (tcb.snd_wl1 == seg_seq && seq_le(tcb.snd_wl2, seg_ack))
{
    tcb.snd_wnd = tcb.scale_incoming_window(seg_wnd as u32);
    tcb.snd_wl1 = seg_seq;
    tcb.snd_wl2 = seg_ack;
}
```

Apply to both new-ACK and duplicate-ACK window update paths.

---

## 9. CLOSE-WAIT ACK processing

### Problem
CLOSE-WAIT does nothing with ACKs. The local side can still send data in CLOSE-WAIT, but ACKs for that data are never processed. This breaks half-close.

### Fix
Add ESTABLISHED-equivalent ACK processing for CLOSE-WAIT in `process_teardown`:
- Advance `snd_una` when `snd_una < seg_ack <= snd_nxt`
- Update send window (with WL1/WL2 guard)
- Handle `seg_ack > snd_nxt` (send ACK, drop)
- Process congestion control (cwnd updates)

This can share code with `process_established` by extracting common ACK processing into a helper, or by inlining the logic.

---

## 10. SWS avoidance (sender + receiver)

### Problem
**Sender:** `poll_send` sends whenever `can_send > 0`. No check for usable window size.
**Receiver:** `advertised_window()` returns raw free space. Even 1 freed byte opens the window.

### Fix

**Sender (MUST-38):** In `poll_send`, add SWS check before sending sub-MSS data:
```rust
let usable_window = can_send;
if usable_window < eff_snd_mss && usable_window < max_snd_wnd / 2 && data_available > usable_window {
    // SWS: don't send unless Nagle allows it
    continue;
}
```
Where `max_snd_wnd` tracks the largest window ever advertised by the peer (new TCB field).

**Receiver (MUST-39):** In `advertised_window()`, only increase the window when free space >= `min(eff_rcv_mss, recv_buffer.capacity() / 2)`. Track `last_advertised_wnd_edge` to prevent shrinkage (also fixes MUST-34, window right edge moving left).

New TCB fields:
- `max_snd_wnd: u32` — largest send window seen from peer
- `last_advertised_right_edge: u32` — `rcv_nxt + advertised_wnd` at time of last ACK sent

---

## Scope

**Modified files:**
- `src/net/handler/tcp/mod.rs` — fixes 1-9 (reorder steps, add checks, FIN retransmit)
- `src/net/handler/tcp/tcb.rs` — fix 10 (new SWS fields), fix 2 (`pending_remote_fin`)
- `src/net/handler/tcp/segment.rs` — no changes expected

**No new files.**

**Testing:** Each fix gets a unit test exercising the specific scenario (out-of-order FIN, blind RST, ACK > SND.NXT, etc.). Existing tests must continue to pass.
