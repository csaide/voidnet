# TCP Reliability & Performance Design

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix window scaling bugs, add segment validation, timestamps, zero-window probing, full SACK, and zero-copy send path.

**Architecture:** Six features ordered by dependency: window scaling fix first (everything depends on correct windows), then segment acceptability, timestamps (PAWS gates acceptability), zero-window probing, full SACK, and zero-copy send path.

**Tech Stack:** Rust, coarsetime for timers, existing TCP handler infrastructure.

---

## 1. Window Scaling Fix

### Problem

`snd_wscale` is negotiated during the handshake but never applied. `seg_wnd` from the wire is stored raw into `tcb.snd_wnd`. With `snd_wscale=7`, a peer advertising window=512 means 65536 bytes, but we treat it as 512. Advertised `rcv_wnd` in outgoing segments is also never downscaled by `rcv_wscale`.

### Design

**Receiving (apply snd_wscale to incoming window):**
- After SYN exchange completes (Established state onward), apply shift: `tcb.snd_wnd = (seg_wnd as u32) << tcb.snd_wscale`
- During SYN/SYN-ACK processing, window is unscaled per RFC 7323 section 2.2 -- no change there
- Affected sites in `process_established`: line ~1176 (`tcb.snd_wnd = seg_wnd`)
- Affected sites in `process_teardown` FinWait1: line ~1939 (`tcb.snd_wnd = seg_wnd`)

**Sending (downscale rcv_wnd in outgoing segments):**
- When advertising our window in ACKs/data/FIN-ACK segments, compute: `(recv_buffer.free_space() >> rcv_wscale).min(u16::MAX as usize) as u16`
- Only apply scaling after handshake (when `wscale_enabled == true`). During SYN/SYN-ACK, continue using unscaled `DEFAULT_RCV_WND`
- Affected: all `SegmentBuilder::build_ack`, `build_data`, `build_fin_ack` calls in `process_established`, `process_teardown`, `poll_timers`, and `poll_send`

**Helper:** Add `fn advertised_window(&self) -> u16` on Tcb to centralize the computation.

---

## 2. Segment Acceptability Checks

### Problem

No validation that incoming segments fall within the receive window. Segments with bogus sequence numbers are processed, which is a correctness and security issue.

### Design (RFC 9293 section 3.10.7.4)

Four cases based on SEG.LEN and RCV.WND:

| SEG.LEN | RCV.WND | Acceptable if |
|---------|---------|---------------|
| 0 | 0 | `SEG.SEQ == RCV.NXT` |
| 0 | > 0 | `RCV.NXT <= SEG.SEQ < RCV.NXT + RCV.WND` |
| > 0 | 0 | Not acceptable |
| > 0 | > 0 | `RCV.NXT <= SEG.SEQ < RCV.NXT + RCV.WND` OR `RCV.NXT <= SEG.SEQ + SEG.LEN - 1 < RCV.NXT + RCV.WND` |

**Implementation:**
- Add `fn is_segment_acceptable(seg_seq: u32, seg_len: u32, rcv_nxt: u32, rcv_wnd: u32) -> bool` helper function
- Call at top of `process_established` and `process_teardown` before any processing
- If not acceptable and not RST: send ACK and drop segment
- If not acceptable and RST: drop silently
- `seg_len` computed as payload_len + SYN/FIN contribution (using existing `Tcb::seg_len`)

---

## 3. Timestamps (RFC 7323)

### Wire Format

Option Kind=8, Length=10. Contains TSval (4 bytes, sender's timestamp) and TSecr (4 bytes, echo of received TSval).

### Negotiation

Both sides must include TS option in SYN. If either omits it, timestamps are disabled. We always offer if `TcpConfig::timestamps` is true; disable if peer doesn't reciprocate.

### New Constants and Wire Functions

In `src/net/wire/tcp.rs`:
- `options::TIMESTAMP = 8`
- `options::SACK_PERMITTED = 4` (added here, used later by SACK)
- `options::SACK = 5` (added here, used later by SACK)
- `parse_timestamp(options: &[u8]) -> Option<(u32, u32)>` -- returns (TSval, TSecr)
- `write_timestamp_option(buf: &mut [u8], tsval: u32, tsecr: u32) -> usize` -- writes 10 bytes

### New TCB Fields

- `ts_enabled: bool` -- negotiated during handshake
- `ts_recent: u32` -- most recent TSval received from peer
- `ts_recent_age: Instant` -- when ts_recent was updated
- `ts_offset: Instant` -- base instant for deriving our monotonic u32 clock

### New TcpConfig Field

- `timestamps: bool` (default `true`)

### Timestamp Clock

Derive u32 millisecond counter from the `now: Instant` parameter already passed through the call chain: `now.duration_since(ts_offset).as_millis() as u32`. Wraps every ~49 days, which is fine per RFC 7323. Never calls `Instant::now()`.

### RTTM (RFC 7323 section 4.1)

On every valid ACK received with TSecr != 0, compute RTT: `rtt = our_current_ts - TSecr`. This replaces the single-sample `last_send_time` approach with per-ACK measurement. The existing SRTT/RTTVAR/RTO computation (RFC 6298) remains unchanged -- just fed more samples.

### PAWS (RFC 7323 section 5)

Before segment acceptability check in `process_established` and `process_teardown`, if `ts_enabled`:
- If `SEG.TSval < ts_recent` and segment is not RST: drop segment, send ACK
- Exception: if `ts_recent_age > 24 days`, accept anyway (stale timestamp invalidation)
- On acceptable segment with data or SYN: update `ts_recent = SEG.TSval`, `ts_recent_age = now`

### Segment Size Impact

Every non-SYN segment grows by 12 bytes (NOP + NOP + 10-byte TS option for alignment). `build_ack`, `build_data`, `build_fin_ack` all accept optional `ts: Option<(u32, u32)>` parameter. SYN/SYN-ACK option buffers grow to accommodate TS.

**SYN option layout (when all options enabled):**
MSS(4) + NOP(1) + WSCALE(3) + NOP(1) + NOP(1) + TS(10) + SACK_PERMITTED(2) = 22 bytes, padded to 24.

---

## 4. Zero-Window Probing (Persist Timer)

### Problem

When the peer advertises `window=0`, the sender stops. If the peer's window update ACK is lost, the connection deadlocks.

### New TCB Fields

- `persist_deadline: Option<Instant>` -- when to send next zero-window probe
- `persist_backoff: u8` -- exponential backoff counter (caps at 6, max ~64s)

### Logic (in `poll_send`)

**Detection:** When `send_window == 0` and there's data to send, set `persist_deadline` if not already set. Initial deadline: `now + rto`.

**Probing:** When `persist_deadline` is set and `now >= persist_deadline`:
- Send 1-byte probe segment: peek 1 byte from send buffer at `bytes_in_flight` offset
- Advance `snd_nxt` by 1
- Set next deadline: `now + rto << persist_backoff` (capped at 60s)
- Increment `persist_backoff` (cap at 6)

**Recovery:** When any ACK arrives with `snd_wnd > 0` (in `process_established` ACK handling): clear `persist_deadline`, reset `persist_backoff = 0`.

**Why poll_send:** The persist timer is tightly coupled with the send path -- it needs send buffer state, flight tracking, and segment building. Keeping it in `poll_send` avoids duplicating context.

---

## 5. Full SACK (RFC 2018 / RFC 6675)

### 5a. Negotiation

**SACK Permitted option** (Kind=4, Length=2) sent in SYN and SYN-ACK. Both sides must include it. We always offer if `TcpConfig::sack` is true; disable if peer doesn't reciprocate.

**New TCB field:** `sack_enabled: bool`

**New TcpConfig field:** `sack: bool` (default `true`)

**New wire functions:**
- `parse_sack_permitted(options: &[u8]) -> bool`
- `write_sack_permitted_option(buf: &mut [u8]) -> usize` -- 2 bytes
- `parse_sack_blocks(options: &[u8]) -> ([Option<(u32, u32)>; 4], usize)` -- fixed-size array, returns count to avoid allocation
- `write_sack_option(buf: &mut [u8], blocks: &[(u32, u32)]) -> usize` -- variable length

### 5b. Sending SACK Blocks (Receiver Side)

When OOO data arrives, report our `ooo_ranges` as SACK blocks in the duplicate ACK.

**Option space budget (40 bytes max):**
- Timestamps enabled: 12 bytes used, 28 remaining -> 3 SACK blocks max (2 + 8*3 = 26)
- Timestamps disabled: 40 bytes -> 4 SACK blocks max (2 + 8*4 = 34)

**Block ordering:** Most recently received range first (per RFC 2018 section 3).

**Implementation:** Convert `ooo_ranges` entries to SACK blocks in the OOO data path of `process_established` (line ~1257). Build a new `SegmentBuilder::build_ack_with_options` or extend `build_ack` to accept optional SACK blocks and timestamp.

### 5c. Using Received SACK Blocks (Sender Side)

**New TCB field:**
- `sack_scoreboard: BTreeMap<u32, u32>` -- byte ranges peer has confirmed (left_edge -> right_edge)

**On receiving ACK with SACK blocks:**
1. Parse SACK blocks from options
2. Insert/merge ranges into scoreboard
3. On cumulative ACK advance (`snd_una` moves forward), remove scoreboard entries below `snd_una`

**Selective retransmission (in `poll_timers` fast retransmit path):**
- When `dup_ack_count >= 3` and `sack_enabled`:
  - Find first gap in scoreboard between `snd_una` and `snd_nxt`
  - Retransmit data from that gap (1 MSS)
  - Track retransmitted ranges to avoid re-sending same gap in one recovery episode

**On RTO retransmit:** Clear scoreboard entirely -- fall back to full retransmit per RFC 6675.

---

## 6. Zero-Copy Send Path

### Problem

`poll_send` and `poll_timers` allocate `vec![0u8; to_send]` for every data segment, copying from the ring buffer into a temporary buffer before passing to `build_data`. Unnecessary when ring buffer data doesn't wrap, and avoidable even when it does.

### Design

**Ring buffer change:** Add `peek_slices(offset: usize, len: usize) -> (&[u8], &[u8])` to `RingBuffer`. Returns two slices -- first covers head-to-end-of-buffer, second covers wrap-around portion. Second slice is empty if data doesn't wrap.

**SegmentBuilder change:** `build_data` takes `payload: (&[u8], &[u8])` instead of `&[u8]`. Writes both slices contiguously into the frame. Checksum computation handles two slices (already works over arbitrary byte ranges).

**Affected call sites:** `poll_send` data path, `poll_timers` fast retransmit, `poll_timers` RTO retransmit -- all three drop the heap allocation and pass two slices directly.

---

## Test Plan

### Window Scaling Tests
1. Incoming `seg_wnd` is scaled by `snd_wscale` in Established state
2. Outgoing window is downscaled by `rcv_wscale`
3. SYN/SYN-ACK windows remain unscaled
4. Window scaling disabled when peer doesn't negotiate

### Segment Acceptability Tests
5. In-window segment accepted
6. Out-of-window segment dropped with ACK sent
7. Zero-length segment with zero window: only exact match accepted
8. RST outside window dropped silently

### Timestamp Tests
9. TS option negotiated when both sides offer
10. TS disabled when peer doesn't offer
11. RTTM: RTT computed from TSecr on each ACK
12. PAWS: segment with old TSval dropped
13. PAWS: stale ts_recent (>24 days) allows segment through

### Zero-Window Probing Tests
14. Persist probe sent when peer window is 0
15. Backoff increases between probes
16. Probing stops when window reopens

### SACK Tests
17. SACK Permitted negotiated in SYN exchange
18. SACK blocks sent in duplicate ACKs for OOO data
19. SACK blocks parsed and scoreboard updated
20. Selective retransmit: only gap data resent, not already-SACKed data
21. Scoreboard cleared on RTO

### Zero-Copy Send Tests
22. `peek_slices` returns single slice when data doesn't wrap
23. `peek_slices` returns two slices when data wraps
24. `build_data` with two-slice payload produces correct frame

## Scope

**Modified files:**
- `src/net/wire/tcp.rs` -- new option constants, parse/write functions for timestamps, SACK permitted, SACK blocks
- `src/net/handler/tcp/tcb.rs` -- new fields on Tcb and TcpConfig
- `src/net/handler/tcp/mod.rs` -- window scaling fix, segment acceptability, PAWS, timestamps in established/teardown, persist timer, SACK block generation/processing, selective retransmit
- `src/net/handler/tcp/segment.rs` -- build_data signature change (two slices), timestamp option in ACK/data/FIN-ACK builders
- `src/net/handler/tcp/ring_buffer.rs` -- peek_slices method

**No new files.**
