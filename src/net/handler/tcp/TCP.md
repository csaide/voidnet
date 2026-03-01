# TCP Handler Module (`src/net/handler/tcp/`)

Implements a userspace TCP stack (RFC 9293) operating on zero-copy AF_XDP frames. All processing is single-threaded and driven by the `LocalRuntime` event loop.

## File Layout

| File | Role |
|------|------|
| `mod.rs` | Module declaration, public re-exports |
| `types.rs` | Core types: `ConnectionId`, `TcpState`, `TcpEvent`, `TcpCommand`, `ParsedTcpHeader`, `AcceptedConnection` |
| `tcb.rs` | Per-connection state (`Tcb`), congestion/RTO state, send buffer, listener state, retransmit entry |
| `handler.rs` | `TcpHandler` struct: connection/listener management, `connect()`, `listen()`, `tick()`, `evict_stale()` |
| `input.rs` | Inbound segment processing: `process_ipv4()`, `process_ipv6()`, state machine dispatch |
| `output.rs` | Outbound processing: `tick()` drives commands, send buffer drain, retransmission, zero-window probes, delayed ACKs |
| `segment.rs` | Segment building helpers: `build_tcp_segment()`, `send_segment()`, `send_and_queue_retransmit()`, `send_rst_stateless()`, ISN generation |
| `tests.rs` | Unit tests including pnet cross-validation of checksums |

## Architecture Overview

```
                     LocalRuntime
                          |
              +-----------+-----------+
              |                       |
         process_ipv4/ipv6()      tick() (each event loop iteration)
              |                       |
        [input.rs]               [output.rs]
              |                       |
     process_segment()         drain_send_buffer_direct()
              |                 retransmit check
     process_for_connection    delayed ACK flush
         _inplace()            zero-window probe
              |                 command processing
     process_established       evict_stale()
         _segment()
```

## Core Data Structures

### `TcpHandler<'umem>` (handler.rs)

Top-level struct owning all TCP state. Fields:

- `connections: HashMap<ConnectionId, Tcb<'umem>>` -- all active connections keyed by 4-tuple
- `listeners: Vec<ListenerState<'umem>>` -- registered listening sockets
- `dirty_conn_ids: Vec<ConnectionId>` -- connections needing processing in the next `tick()`
- `time_wait_duration: Duration` -- configurable TIME-WAIT timeout (default 120s)

### `ConnectionId` (types.rs)

4-tuple identifying a connection: `{local_addr, local_port, remote_addr, remote_port}`. Implements `Hash`, `Eq`, `Ord`. Uses `IpAddress` which is an enum over `V4`/`V6`.

### `Tcb<'umem>` (tcb.rs)

Transmission Control Block -- per-connection state per RFC 9293 section 3.3.1.

**Send-side variables:**
- `snd_una: u32` -- oldest unacknowledged sequence number
- `snd_nxt: u32` -- next sequence number to send
- `snd_wnd: u32` -- peer's receive window (already scaled)
- `snd_wl1: u32` / `snd_wl2: u32` -- window update tracking
- `iss: u32` -- initial send sequence number
- `snd_mss: u16` -- peer's MSS (from their SYN options)
- `snd_wnd_scale: u8` -- peer's window scale factor

**Receive-side variables:**
- `rcv_nxt: u32` -- next expected receive sequence number
- `rcv_wnd: u32` -- our receive window (default 262144, constant `DEFAULT_RCV_WND`)
- `irs: u32` -- initial receive sequence number
- `rcv_mss: u16` -- our MSS (default 1460)
- `rcv_wnd_scale: u8` -- our window scale factor (default 7, allows up to 8MB)

**Connection state:**
- `state: TcpState` -- current state in the TCP state machine
- `conn_id: ConnectionId` -- this connection's 4-tuple
- `from_listener: bool` -- true for passive opens (needed for listener pending count management)
- `local_mac` / `remote_mac: MacAddress` -- L2 addresses for segment construction

**Communication channels (shared with socket layer via `Rc`):**
- `rx_queue: LocalQueue<TcpEvent<'umem>>` -- handler pushes events, socket layer pops
- `cmd_queue: LocalQueue<TcpCommand>` -- socket layer pushes commands, handler pops
- `send_buffer: SharedSendBuffer` -- socket layer pushes bytes, handler drains during tick

**Receive reordering:**
- `recv_reorder: BTreeMap<u32, (Frame<'umem>, usize, usize)>` -- out-of-order segments keyed by seq number, value is (frame, payload_offset, payload_len)

**Retransmission:**
- `retransmit_queue: VecDeque<RetransmitEntry>` -- lightweight metadata entries (no frame copies)
- `rto_state: RtoState` -- Jacobson/Karels RTO estimation (RFC 6298), uses fixed-point u64 microseconds
- `congestion: CongestionState` -- cwnd/ssthresh tracking (RFC 5681)

**Delayed ACK (RFC 1122):**
- `delayed_ack_pending: u8` -- count of unacked data segments since last ACK sent
- `delayed_ack_at: Option<Instant>` -- timestamp of first unacked segment for 40ms timeout

**Fast retransmit (RFC 5681):**
- `dup_ack_count: u8` -- duplicate ACK counter
- `in_fast_recovery: bool` -- whether in fast recovery mode
- `recovery_point: u32` -- snd_nxt at time of entering fast recovery

**Scheduling:**
- `needs_tick: bool` -- marks connection as dirty for next tick() call
- `last_activity: Instant` -- last segment received/sent time
- `time_wait_start: Option<Instant>` -- when TIME-WAIT was entered

**Key methods on `Tcb`:**
- `effective_window()` -- `min(snd_wnd, cwnd)`
- `wire_rcv_wnd()` -- computes scaled 16-bit window value, proportional to rx_queue fill level
- `is_seq_acceptable()` -- RFC 9293 sequence number acceptability check
- `ack_retransmit_queue()` -- removes acked entries, advances send buffer, updates RTO from RTT samples (skips retransmitted segments per Karn's algorithm)

### `SendByteBuffer` / `SharedSendBuffer` (tcb.rs)

Byte-level send buffer. `SharedSendBuffer` wraps `Rc<UnsafeCell<SendByteBuffer>>` for shared access between the handler and socket layer. Operations:
- `push(data)` -- append bytes (called by `TcpStream::write`)
- `peek(offset, len)` -- read bytes without consuming (for retransmit)
- `advance(len)` -- consume bytes from head (on ACK). Compacts when head > 32KB and > half allocation.
- `len()` -- total available bytes (unacked + unsent)

### `RetransmitEntry` (tcb.rs)

Lightweight metadata for retransmission. **Does not store frame data** -- payload is rebuilt from `SendByteBuffer` using `peek()`. Fields: seq, len, seg_flags, ack, window, options (up to 8 bytes), sent_at, retransmit_count, is_retransmit, first_retransmit_time.

### `ListenerState<'umem>` (tcb.rs)

Per-listener state: addr, port, accept_queue (`LocalQueue<AcceptedConnection>`), backlog limit, current pending count.

### `RtoState` (tcb.rs)

Jacobson/Karels algorithm (RFC 6298) for retransmission timeout estimation. Uses fixed-point u64 microseconds for srtt/rttvar. Minimum RTO = 1 second. `backoff()` doubles RTO up to 60s max.

### `CongestionState` (tcb.rs)

Tracks `cwnd` and `ssthresh`. Initial window = 10 * MSS (RFC 6928). `ssthresh` starts at `u32::MAX`.

## Constants (segment.rs)

| Constant | Value | Source |
|----------|-------|--------|
| `DEFAULT_RCV_WND` | 262144 (256 KB) | Our advertised receive window |
| `DEFAULT_RCV_MSS` | 1460 | Standard Ethernet MSS |
| `DEFAULT_TIME_WAIT_DURATION` | 120s | 2MSL |
| `MAX_RETRANSMIT_TIME` | 100s | Give up retransmitting after this |
| `DELAYED_ACK_TIMEOUT` | 40ms | RFC 1122 delayed ACK timer |
| `DEFAULT_RCV_WND_SCALE` | 7 | Shift count, allows up to 8MB window |
| `ETH_HEADER_LEN` | 14 | Ethernet frame header size |

## Inbound Path (input.rs)

### Entry Points

- `process_ipv4(frame, now, free_frames, rx_return, tx_return)` -- validates IPv4 TCP header + checksum, extracts `ParsedTcpHeader`, calls `process_segment()`
- `process_ipv6(frame, tcp_offset, now, free_frames, rx_return, tx_return)` -- same for IPv6. Note: `tcp_offset` is passed in (may include extension headers)

### Segment Dispatch (`process_segment`)

1. Build `ConnectionId` from the segment's 4-tuple (note: local = dst, remote = src)
2. **Existing connection?** Calls `process_for_connection_inplace()` via `HashMap::get_mut()` to avoid remove/reinsert overhead. Returns bool for removal.
3. **No connection -- RST received?** Silently dropped (RFC: RST in LISTEN state).
4. **No connection -- ACK without SYN?** Send RST with `seq = seg_ack`.
5. **SYN to listener?** Creates new `Tcb` in `SynReceived`, sends SYN-ACK with MSS + optional Window Scale options, increments listener pending count.
6. **No match?** Sends RST per RFC rules (different for ACK vs non-ACK segments).

### Per-State Processing (`process_for_connection_inplace`)

**SynSent** (active open, expecting SYN-ACK):
- Validates ACK against ISS range
- RST+ACK: connection refused, emit `TcpEvent::Reset`
- SYN+ACK: complete handshake, parse MSS/WS options, transition to `Established`, send ACK, emit `TcpEvent::Connected`
- SYN only (no ACK): simultaneous open, transition to `SynReceived`, send SYN-ACK

**SynReceived** (passive open, expecting ACK):
- Sequence acceptability check
- RST: if from_listener, decrement pending; otherwise emit Reset. Remove connection.
- SYN: error -- if from_listener, decrement pending; otherwise send RST. Remove connection.
- ACK with valid range (`SND.UNA < SEG.ACK <= SND.NXT`): transition to `Established`, push `AcceptedConnection` to listener's accept_queue, emit Connected. If segment has data/FIN, immediately process via `process_established_segment()`.
- ACK out of range: send RST.

**Established / FinWait1 / FinWait2 / CloseWait / Closing / LastAck**:
- Delegates to `process_established_segment()`
- If state becomes `Closed` after processing, returns true for removal

**TimeWait**:
- Sequence check, RST closes connection, SYN sends RST+closes
- FIN restarts TIME-WAIT timer and re-ACKs

### Established Segment Processing (`process_established_segment`)

Sequential checks per RFC 9293:

1. **Sequence acceptability** -- not acceptable? Send ACK (unless RST). Drop.
2. **RST** -- Reset event, transition to Closed.
3. **SYN in synchronized state** -- Error, send RST, transition to Closed.
4. **No ACK flag** -- Drop.
5. **ACK processing:**
   - **New ACK** (`SND.UNA < SEG.ACK <= SND.NXT`): advance `snd_una`, drain retransmit queue, update congestion window (slow start if cwnd < ssthresh, congestion avoidance otherwise). Exit fast recovery if ACK >= recovery_point.
   - **Duplicate ACK** (same ack, no data, retransmit queue non-empty): increment dup_ack_count. At 3: enter fast recovery (RFC 5681), retransmit first unacked segment. Beyond 3: inflate cwnd.
   - **ACK for unsent data** (`SEG.ACK > SND.NXT`): send ACK, drop.
   - **Window update**: update `snd_wnd` using SWL1/SWL2 tracking.
6. **State transitions from ACK:**
   - `FinWait1` + our FIN acked → `FinWait2`
   - `Closing` + our FIN acked → `TimeWait`
   - `LastAck` + our FIN acked → `Closed`, emit `TcpEvent::Closed`
7. **Data delivery** (Established/FinWait1/FinWait2):
   - In-order (`seg_seq == rcv_nxt`): deliver to rx_queue, advance rcv_nxt, drain reorder buffer for consecutive segments. Delayed ACK: ACK every 2nd segment immediately, otherwise start 40ms timer.
   - Out-of-order (`seg_seq > rcv_nxt`): buffer in `recv_reorder` BTreeMap, send immediate ACK.
   - Old data (`seg_seq < rcv_nxt`): drop.
8. **FIN processing** (`process_fin`):
   - Established → CloseWait (emit PeerClosed)
   - FinWait1 → Closing (emit PeerClosed)
   - FinWait2 → TimeWait (emit PeerClosed)
   - Always sends ACK

## Outbound Path (output.rs)

### `tick(now, free_frames, rx_return, tx_return)`

Called once per event loop iteration. Processes only dirty connections (`dirty_conn_ids`):
1. Dedup and sort dirty IDs
2. For each: call `tick_connection()`, remove if it returns true, otherwise re-add to dirty list if still needs_tick

### `tick_connection()` per-connection logic:

1. **Command processing** (from socket layer):
   - `Close`: Established → send FIN+ACK, transition to FinWait1. CloseWait → send FIN+ACK, transition to LastAck.
   - `Abort`: Send RST, emit Reset event, remove connection.
2. **Send buffer drain** (`drain_send_buffer_direct`): Segments data while `effective_window()` allows. Segment size = `min(available_data, MSS, available_window)`. Sets PSH on last segment. Enqueues retransmit entries. Piggybacks ACK (clears delayed ACK state).
3. **Retransmission**: If front of retransmit queue has expired (elapsed >= RTO), retransmit it. Backoff RTO. Reset cwnd to 1*MSS, ssthresh to cwnd/2. If first retransmit > `MAX_RETRANSMIT_TIME` (100s), give up: emit Reset, remove.
4. **Zero-window probing**: If `snd_wnd == 0` and data pending, send probe ACK at RTO intervals.
5. **Delayed ACK flush**: If pending ACKs exceed 40ms timeout, send ACK.
6. **Clear needs_tick**: If no commands, no send data, no retransmits, no delayed ACKs, and window > 0.

### `evict_stale(now, rx_return)`

Iterates connections, removes those in TimeWait past `time_wait_duration`. Emits `TcpEvent::Closed`.

## Segment Construction (segment.rs)

### `build_tcp_segment()`

Builds a complete Ethernet + IP + TCP + options + payload frame. Dual-stack: IPv4 or IPv6 based on `IpAddress` variant. Sets DF flag on IPv4. TTL/Hop Limit = 64. Computes IP checksum (v4) and TCP checksum (v4/v6 pseudo-header).

### `send_segment()`

Convenience: pops a free frame, calls `build_tcp_segment()`, pushes to tx_return. Uses TCB for addressing.

### `send_and_queue_retransmit()`

Like `send_segment()` but also enqueues a `RetransmitEntry`. Used for SYN, SYN-ACK, and FIN.

### `send_rst_stateless()`

Sends RST without a TCB. Used for responding to segments on closed ports or invalid connections.

### `generate_isn()`

RFC 6528 ISN generation: time component (microseconds since epoch) + SipHash of 4-tuple with per-process random key (`LazyLock<RandomState>`).

## Communication with Socket Layer

The handler and socket layer communicate through three shared channels per connection, all using `Rc`-based single-threaded sharing:

| Channel | Type | Direction | Purpose |
|---------|------|-----------|---------|
| `rx_queue` | `LocalQueue<TcpEvent<'umem>>` | Handler → Socket | Data frames, connection events |
| `cmd_queue` | `LocalQueue<TcpCommand>` | Socket → Handler | Close/Abort commands |
| `send_buffer` | `SharedSendBuffer` | Socket → Handler | Write data (bytes) |

### TcpEvent variants:
- `Connected` -- handshake complete
- `Data { frame, payload_offset, payload_len }` -- received data (zero-copy frame reference)
- `PeerClosed` -- FIN received
- `Reset` -- RST received or connection timed out
- `Closed` -- connection fully closed (TIME-WAIT expired)

### TcpCommand variants:
- `Close` -- initiate graceful shutdown (FIN)
- `Abort` -- immediate teardown (RST)

## Socket Layer Integration (socket/tcp.rs)

- `TcpListener` -- wraps accept_queue, provides `accept()` future returning `TcpStream`
- `TcpStream` -- wraps rx_queue/cmd_queue/send_buffer, provides:
  - `write(data)` future -- copies into SharedSendBuffer (always Ready)
  - `read(buf)` future -- copies from rx_queue data frames
  - `read_zero_copy()` future -- returns `TcpFrameRef` with RAII frame return
  - `close()` / `abort()` -- push commands
  - `discard_frame()` -- manual frame return

## Frame Buffer Management

Three `FrameBuffer` pools flow through all processing:

| Buffer | Purpose |
|--------|---------|
| `free_frames` | Source of fresh frames for building outbound segments |
| `rx_return` | Return pool for consumed/dropped inbound frames |
| `tx_return` | Outbound frames ready for transmission |

Frames from `recv_reorder` are returned to `rx_return` on connection removal. The `TcpFrameRef` RAII guard returns data frames to `SharedFrameBuffer` (rx_return) on drop.

## Window Scaling (RFC 7323)

- We always offer window scale in our SYN/SYN-ACK (scale factor 7 = up to 8MB)
- If peer doesn't offer WS, both directions disabled (scale factors set to 0)
- `snd_wnd` is stored already-scaled: `(wire_window as u32) << snd_wnd_scale`
- `wire_rcv_wnd()` reverse-scales our window for the wire: `(wnd >> rcv_wnd_scale).min(65535)`

## Congestion Control (RFC 5681)

- **Initial window**: 10 * MSS (RFC 6928)
- **Slow start**: cwnd += MSS per new ACK (when cwnd < ssthresh)
- **Congestion avoidance**: cwnd += MSS^2/cwnd per new ACK (additive increase)
- **Fast retransmit**: on 3 duplicate ACKs, retransmit first unacked, ssthresh = cwnd/2, cwnd = ssthresh + 3*MSS
- **Fast recovery**: inflate cwnd by MSS per additional dup ACK; exit on new ACK past recovery_point, set cwnd = ssthresh
- **Timeout**: ssthresh = cwnd/2, cwnd = 1*MSS, exponential backoff on RTO

## TCP State Machine

```
                    connect()           SYN received
                  +-----------+       +-------------+
                  |           v       v             |
    CLOSED --> SYN_SENT --> ESTABLISHED <-- SYN_RECEIVED
                                |    |
                    close()     |    |  FIN received
                  +-------------+    +---------------+
                  v                                  v
              FIN_WAIT_1                         CLOSE_WAIT
                  |     \                            |
    FIN acked     |      \ FIN received    close()   |
                  v       v                          v
              FIN_WAIT_2  CLOSING                LAST_ACK
                  |          |                       |
    FIN received  |   ACK    |              ACK      |
                  v          v                       v
              TIME_WAIT -----+--> CLOSED <-----------+
                  |
            2MSL timeout
                  v
                CLOSED
```

## Dirty Connection Optimization

Not every connection needs processing every tick. The `dirty_conn_ids: Vec<ConnectionId>` tracks which connections need attention. A connection becomes dirty when:
- A segment is received for it (`process_segment` adds to dirty list)
- It has pending work (`needs_tick = true` when created/modified)

`tick()` only iterates dirty connections, sorts/dedups the list, and re-adds connections that still need ticking. This avoids O(n) iteration over all connections.

## Tests (tests.rs)

Unit tests cover:
- SYN to listening port creates SynReceived state
- SYN to closed port generates RST
- Bad checksum drops frame
- IPv6 SYN acceptance
- Full passive three-way handshake (SYN → SYN-ACK → ACK → Established, accept_queue populated)
- RST handling in LISTEN state
- MSS option parsing from SYN
- pnet cross-validation: checksums computed by our code match pnet's reference implementation for IPv4, IPv6, and odd-length payloads
- pnet-generated frames accepted by our process_ipv4/process_ipv6

## Key Dependencies

- `crate::net::wire::tcp` -- TCP header parsing, checksum computation, flag constants, MSS/WS option parsing, sequence number comparison functions (`seq_lt`, `seq_le`)
- `crate::net::wire::ip` -- IP address types, header parsing, IPv4 checksum
- `crate::net::wire::ethernet` -- Ethernet frame parsing, MAC address type
- `crate::net::socket::LocalQueue` -- single-threaded shared queue (`Rc<UnsafeCell<VecDeque>>`)
- `crate::xdp::frame::{Frame, FrameBuffer}` -- zero-copy frame types
- `pnet` (dev dependency) -- used only in tests for checksum cross-validation
