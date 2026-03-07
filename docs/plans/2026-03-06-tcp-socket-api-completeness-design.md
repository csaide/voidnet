# TCP Socket API Completeness Design

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Complete the TCP socket API with half-close, keep-alive probes, and SO_LINGER support.

**Architecture:** Three independent features added to the existing TCP handler and socket layer. Half-close adds a write-side shutdown without closing reads. Keep-alive adds periodic probes for idle connection liveness detection. Linger controls close behavior (graceful vs RST abort).

**Tech Stack:** Rust, coarsetime for timers, existing TCP handler infrastructure.

---

## Half-Close (`shutdown`)

### Current Behavior

`TcpStream::close()` sets `pending_fin = true` and `self.closed = true`. Once closed, both reads and writes stop. `Drop` calls `close()`. There is no way to send FIN while continuing to read.

### Design

**New TcpStream field:**
- `write_closed: bool` (default `false`) — tracks whether the write side is shut down

**New method: `TcpStream::shutdown()`**
- Sets `write_closed = true`
- Calls `handler.initiate_close(&self.conn_id)` — triggers `pending_fin`, which sends FIN via `poll_send`
- Does NOT set `self.closed = true` — the stream stays alive for reads

**TcpWrite::poll() change:**
- If the stream's write side is closed, return `Ready(0)` immediately (no more writes)
- Requires passing `write_closed` state to the future

**TcpRead::poll() unchanged:**
- Reads continue working until remote sends FIN (returns 0 = EOF) or connection is removed

**close() unchanged:**
- Full close on both sides. If `shutdown()` was already called, `initiate_close` is a no-op (pending_fin already set).

**Drop unchanged:**
- Calls `close()`. If shutdown was already called, it's a no-op for the FIN.

**State machine interaction:**
- `shutdown()` triggers Established → FinWait1 (same as close)
- Stream stays alive for reads through FinWait1 → FinWait2 → TimeWait
- When remote FINs back, TcpRead returns 0 (EOF)

## TCP Keep-Alive

### Current Behavior

Idle connections have no liveness probing. A silently dead peer (power failure, network partition) leaves the connection in Established forever.

### Design

**New TCB fields:**
- `keep_alive_enabled: bool` (default `false`)
- `keep_alive_idle_ms: u64` (default `7_200_000` = 2 hours per RFC 9293)
- `keep_alive_interval_ms: u64` (default `75_000` = 75 seconds)
- `keep_alive_count: u8` (default `9` probes before abort)
- `last_activity: Instant` — updated on every data send/receive
- `keep_alive_probes_sent: u8` (default `0`) — current probe counter

**New TcpConfig fields:**
- `keep_alive: bool` (default `false`)
- `keep_alive_idle_ms: u64` (default `7_200_000`)
- `keep_alive_interval_ms: u64` (default `75_000`)
- `keep_alive_count: u8` (default `9`)

**Keep-alive probe format (RFC 9293 §3.8.4):**
- Segment with `seq = snd_una - 1`, no data, ACK flag
- Peer responds with ACK containing its current `rcv_nxt`

**Timer logic in `poll_timers`:**
- For Established connections with `keep_alive_enabled`:
  - Compute idle time: `now - last_activity`
  - If no probes sent yet and `idle >= keep_alive_idle_ms`: send first probe
  - If probes already sent and `idle >= idle + interval * probes_sent`: send next probe
  - If `keep_alive_probes_sent > keep_alive_count`: push `TcpEvent::Timeout`, mark for removal
- On receiving any data or ACK in `process_established`: reset `last_activity = now`, `keep_alive_probes_sent = 0`
- On sending data in `poll_send`: reset `last_activity = now`

**Socket API:**
- `TcpStream::set_keepalive(&self, enabled: bool)`
- `TcpStream::keepalive(&self) -> bool`

## SO_LINGER

### Current Behavior

`close()` always initiates graceful close — sets `pending_fin`, data drains asynchronously, FIN sent by `poll_send`. Non-blocking.

### Design

SO_LINGER has two useful modes for our cooperative executor:

**Linger off (`None`, default):** Current behavior — graceful close, data drains in background.

**Linger(0):** Hard reset — `initiate_close` sends RST immediately, discards send buffer, removes connection. Used for abort semantics.

**Linger(timeout > 0):** Graceful close with deadline — `initiate_close` sets `pending_fin` and `linger_deadline`. If `poll_send` hasn't completed the FIN by the deadline, it sends RST and removes the connection.

**New TCB fields:**
- `linger: Option<u64>` (None = off, Some(0) = RST, Some(ms) = timeout)
- `linger_deadline: Option<Instant>` — set when linger timeout close is initiated

**New TcpConfig field:**
- `linger: Option<u64>` (default `None`)

**Handler changes:**
- `initiate_close`: if `linger == Some(0)`, send RST immediately via existing `remove_connection` (which sends RST for synchronized states), skip setting `pending_fin`. If `linger == Some(ms)`, set `pending_fin = true` and `linger_deadline = Some(now + ms)`.
- `poll_send`: after checking `pending_fin`, also check `linger_deadline`. If deadline expired and data still not drained, mark connection for RST removal instead of continuing to wait.

**Socket API:**
- `TcpStream::set_linger(&self, linger: Option<u64>)`
- `TcpStream::linger(&self) -> Option<u64>`

## Test Plan

**Half-close tests:**
1. `shutdown()` sets `pending_fin` and `write_closed`
2. Writes return 0 after shutdown
3. Reads still work after shutdown (data received before remote FIN)
4. Full lifecycle: shutdown → remote FIN → read returns 0

**Keep-alive tests:**
5. Probe sent after idle timeout expires
6. Activity resets probe timer
7. Connection killed after max probes exceeded
8. No probes when keep_alive_enabled is false

**Linger tests:**
9. Linger(0): RST sent immediately, connection removed
10. Linger(timeout): FIN sent normally if data drains in time
11. Linger(timeout) expired: RST sent, connection removed

## Scope

**Modified files:**
- `src/net/handler/tcp/tcb.rs` — new fields on Tcb and TcpConfig
- `src/net/handler/tcp/mod.rs` — process_established, poll_send, poll_timers, initiate_close changes
- `src/net/socket/tcp.rs` — shutdown(), set_keepalive(), set_linger(), write_closed tracking

**No new files.**
