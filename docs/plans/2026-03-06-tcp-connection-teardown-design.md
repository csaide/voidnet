# TCP Connection Teardown Design

## Context

VoidNet's TCP implementation has full handshake, data transfer, retransmission, and congestion control. Connection close currently sends RST immediately — no graceful FIN sequence, no TIME-WAIT. This design covers RFC 9293-compliant connection teardown.

Target use case: high-performance HTTP/2 servers on both datacenter and internet traffic. The implementation must handle all teardown paths correctly while maintaining the frame safety invariant and zero hot-path allocations.

## Frame Safety Invariant

Same as data transfer: every `Frame<'umem>` popped from `free_frames` MUST be pushed to `tx_return` or `rx_return`. FIN segments are built the same way as data segments via `poll_send` — no new frame concerns. Incoming frames in teardown states are returned to `rx_return` immediately.

## State Machine Transitions

### Active Close (we initiate)

```
Established → FinWait1 (send FIN via poll_send)
FinWait1 + recv ACK of FIN → FinWait2
FinWait2 + recv FIN → TimeWait (send ACK, start timer)
TimeWait + timer expires → remove connection
```

### Passive Close (remote initiates)

```
Established + recv FIN → CloseWait (send ACK, signal EOF)
CloseWait + send buffer drained → LastAck (send FIN via poll_send)
LastAck + recv ACK of FIN → remove connection
```

### Simultaneous Close (both FIN at same time)

```
FinWait1 + recv FIN (without ACK of our FIN) → Closing (send ACK)
Closing + recv ACK of our FIN → TimeWait (start timer)
```

## FIN Sending Mechanism

Lazy FIN via `pending_fin` flag on the TCB. `TcpStream::close()` sets the flag. `poll_send` checks the flag each tick:

- If send buffer has unsent data: send data as normal, FIN waits.
- If send buffer fully sent (`snd_nxt` caught up to all buffered data):
  - Build segment with FIN+ACK flags, no payload.
  - `fin_seq = snd_nxt`, `snd_nxt += 1` (FIN consumes one sequence number).
  - `pending_fin = false`.
  - Transition: Established → FinWait1, CloseWait → LastAck.

FIN segments reuse `SegmentBuilder` — just ACK+FIN flags with empty payload. Same frame allocation path as data segments.

### FIN ACK Tracking

`fin_seq: Option<u32>` stores the sequence number of our FIN. Our FIN is ACKed when `snd_una > fin_seq`. This triggers FinWait1 → FinWait2 and LastAck → Closed transitions.

## Receiving FIN in Established State

In `process_established`, after processing any data payload (FIN can piggyback on data):

1. `rcv_nxt += 1` (FIN consumes one sequence number).
2. Send ACK.
3. Transition to CloseWait.
4. Push `TcpEvent::RemoteClose` to event queue.

## Teardown State Processing

Each teardown state handles incoming segments. Common pattern: RST check first, then ACK/FIN processing.

### FinWait1

- RST → abort (remove connection).
- ACK covers `fin_seq + 1` → transition to FinWait2.
- FIN received → send ACK, `rcv_nxt += 1`.
  - If ACK also covers our FIN → TimeWait (start timer).
  - Else → Closing.
- Data payload → process same as Established (remote hasn't closed yet).

### FinWait2

- RST → abort.
- FIN received → send ACK, `rcv_nxt += 1`, transition to TimeWait (start timer).
- Data payload → process same as Established (remote still sending).

### CloseWait

- RST → abort.
- No new data expected from remote.
- `poll_send` handles draining send buffer and sending FIN → LastAck.

### Closing

- RST → abort.
- ACK covers `fin_seq + 1` → transition to TimeWait (start timer).

### LastAck

- RST → abort.
- ACK covers `fin_seq + 1` → remove connection.

### TimeWait

- RST → **ignore** (not abort — prevents RST attacks from killing TIME-WAIT).
- FIN retransmit → re-send ACK, restart timer.
- Everything else → ignore.
- Timer expires → remove connection.

## EOF Signaling

`TcpEvent::RemoteClose` is a new variant on the `TcpEvent` enum.

`TcpStream::read()` behavior:
- If `recv_buffer` has data → `Ready(n)` as today.
- If `recv_buffer` empty AND connection state is CloseWait, LastAck, TimeWait, or gone → `Ready(0)` (EOF).
- Else → `Pending`.

This lets the user drain remaining buffered data after remote FINs, then see EOF. Standard socket semantics.

## TIME-WAIT Cleanup

`evict_stale` is called every ~65536 iterations in the runtime loop. Currently empty. Fill it in:

```
For each connection in TimeWait state:
  If now >= time_wait_deadline → remove connection
```

Cheap iteration — no frame allocation. TIME-WAIT connections only send ACKs in response to FIN retransmits (handled in `process_teardown`).

## TcpStream::close() Rewrite

Replace the current RST hack (dummy frame buffers, `MacAddress::zero()`):

```
close():
  If already closed → return
  Set closed = true
  Get handler, find connection by conn_id
  If connection exists and state is Established or CloseWait:
    Set pending_fin = true
  Else:
    Leave it (already tearing down, or already gone)
```

No frame buffers needed. No MAC addresses needed. `poll_send` handles everything on the next tick.

## TCB Additions

```
pending_fin: bool,                    // Set by close(), consumed by poll_send
fin_seq: Option<u32>,                 // Sequence number of our FIN
time_wait_deadline: Option<Instant>,  // When to remove TIME-WAIT connection
time_wait_duration: u64,              // Configurable, from TcpConfig, in ms
```

## TcpConfig Addition

```rust
pub struct TcpConfig {
    pub send_buffer_size: usize,       // existing, default 256KB
    pub recv_buffer_size: usize,       // existing, default 256KB
    pub backlog: usize,                // existing, default 128
    pub time_wait_duration_ms: u64,    // new, default 60_000
}
```

Flows through `listen_with_config` / `connect_with_config` into the TCB at connection creation, same pattern as buffer sizes.

## New/Modified Methods

| Method | Change |
|---|---|
| `poll_send` | Extended: FIN sending for Established (pending_fin) and CloseWait |
| `process_established` | Extended: FIN flag → CloseWait transition |
| `process_teardown` | New: dispatches FinWait1/FinWait2/CloseWait/Closing/LastAck/TimeWait |
| `evict_stale` | Filled in: TIME-WAIT deadline checks |
| `TcpStream::close()` | Rewritten: sets pending_fin flag only |
| `TcpStream::read()` | Extended: returns Ready(0) on EOF |
| `TcpEvent` | New variant: RemoteClose |

## Decisions Summary

| Decision | Choice |
|---|---|
| Scope | Full RFC 9293 — all 6 teardown states + simultaneous close |
| TIME-WAIT duration | Configurable via TcpConfig, default 60s |
| Half-open (CloseWait) | Drain send buffer, auto-FIN, read() returns 0 on EOF |
| FIN mechanism | Lazy — pending_fin flag, poll_send sends next tick |
| RST in teardown | Aborts all states except TIME-WAIT |
| FIN tracking | fin_seq on TCB, ACKed when snd_una > fin_seq |
| EOF signaling | TcpEvent::RemoteClose + read() checks connection state |
| TIME-WAIT cleanup | evict_stale checks time_wait_deadline |
| close() rewrite | Sets flag only, no frame buffers or MACs needed |
| Frame safety | No new concerns — FIN uses same path as data segments |

## Deferred

- Linger option (SO_LINGER — force RST on close with timeout)
- TCP keep-alive probes
- Half-close API (`shutdown(SHUT_WR)` vs full `close()`)
