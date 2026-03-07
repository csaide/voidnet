# TCP Delayed ACK + Nagle Algorithm Design

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reduce per-segment overhead with delayed ACKs and prevent small-packet floods with the Nagle algorithm.

**Architecture:** Two complementary optimizations in the TCP handler. Delayed ACK defers ACKs up to 40ms or 2 segments, allowing piggybacking on data. Nagle gates small sends when data is in flight, coalescing into MSS-sized segments.

**Tech Stack:** Rust, coarsetime for timers, existing TCP handler infrastructure.

---

## Delayed ACK

### Current Behavior

Every in-order data segment in `process_established` triggers an immediate `SegmentBuilder::build_ack`. This sends one ACK per received segment — correct but wasteful when data is flowing bidirectionally (the ACK could piggyback on the next outbound data segment).

### Design

**New TCB fields:**
- `ack_pending: bool` (default `false`) — set when an ACK is owed but deferred
- `delayed_ack_deadline: Option<Instant>` — when the deferred ACK must be sent
- `ack_delay_count: u8` (default `0`) — counts consecutive unACKed segments; flush at 2

**New TcpConfig field:**
- `delayed_ack_ms: u64` (default `40`) — max delay before flushing

**Receive path (`process_established`):**
- In-order data: instead of `build_ack`, set `ack_pending = true`, set deadline if not already set, increment `ack_delay_count`. If `ack_delay_count >= 2`, send ACK immediately and reset.
- Out-of-order data: immediate ACK (needed for fast retransmit signaling)
- Duplicate data: immediate ACK
- FIN: immediate ACK

**Send path (`poll_send`):**
- Data segments already carry the ACK flag with current `rcv_nxt`. After sending data, clear `ack_pending` and reset `ack_delay_count` (piggyback).

**Timer path (`poll_timers`):**
- If `ack_pending && now >= delayed_ack_deadline`: send ACK, clear `ack_pending`, reset `ack_delay_count`.

**Constants:**
- `DEFAULT_DELAYED_ACK_MS: u64 = 40`
- `MAX_DELAYED_ACK_COUNT: u8 = 2`

### RFC Compliance

RFC 9293 §4.2: "A TCP implementation SHOULD implement a delayed ACK" and "An ACK SHOULD NOT be excessively delayed; in particular, the delay MUST be less than 0.5 seconds." The 40ms default is well within bounds and matches common implementations (Linux uses 40ms).

RFC 5681 §4.2: "An ACK SHOULD be generated for at least every second full-sized segment." The `ack_delay_count >= 2` flush satisfies this.

## Nagle Algorithm

### Current Behavior

`poll_send` sends any available data immediately regardless of size. A 1-byte `TcpStream::write` produces a 1-byte TCP segment.

### Design

**New TCB field:**
- `nagle_enabled: bool` (default `true`)

**New TcpConfig field:**
- `tcp_no_delay: bool` (default `false`) — when true, disables Nagle

**Send gate in `poll_send`:**

Before sending, check Nagle:
```
if nagle_enabled && bytes_in_flight > 0 && to_send < eff_snd_mss:
    skip sending (wait for outstanding ACK)
```

This means:
- First segment (nothing in flight): always send, any size
- Full MSS available: always send (no small-packet concern)
- Small data with outstanding segments: hold and coalesce
- `!nagle_enabled` (TCP_NODELAY): always send immediately

**Socket API:**
- `TcpStream::set_nodelay(&self, nodelay: bool)` — flips `nagle_enabled` on the TCB

### Nagle + Delayed ACK Interaction

These features interact: if both sides use Nagle + delayed ACK, a write-write-read pattern can stall (sender waits for ACK, receiver delays ACK). This is the well-known "Nagle-delayed-ACK problem" and is standard TCP behavior. Applications that need low latency on small writes use `TCP_NODELAY`. The echo example works fine because the server echoes immediately, piggybacking the ACK.

## Test Plan

**Delayed ACK tests:**
1. In-order data does NOT produce immediate ACK (verify no segment in tx_return after process_established)
2. Timer expiry sends ACK (call poll_timers after deadline)
3. Second consecutive segment flushes ACK immediately (ack_delay_count >= 2)
4. Data send piggybacks ACK (poll_send clears ack_pending)
5. Out-of-order data still sends immediate ACK
6. FIN still sends immediate ACK

**Nagle tests:**
7. Small data with bytes_in_flight > 0 is held (no segment built)
8. Full MSS-sized data always sends regardless of bytes_in_flight
9. bytes_in_flight == 0 always sends regardless of size
10. TCP_NODELAY: small data sends immediately even with bytes_in_flight > 0

## Scope

**Modified files:**
- `src/net/handler/tcp/tcb.rs` — new fields on Tcb and TcpConfig
- `src/net/handler/tcp/mod.rs` — process_established, poll_send, poll_timers changes
- `src/net/socket/tcp.rs` — `set_nodelay` method on TcpStream

**No new files.** No changes to segment builder, state machine, or ring buffer.
