# TCP Data Transfer Design

## Context

VoidNet is a zero-copy AF_XDP networking library. TCP handshake (3-way SYN/SYN-ACK/ACK), RST handling, ISN generation, and socket abstractions (TcpListener, TcpStream) are already implemented. This design covers the data transfer phase for established TCP connections.

Target use case: high-performance HTTP/2 servers. The implementation must minimize copies, avoid hot-path allocations, and never hold `Frame<'umem>` references across ticks.

## Frame Safety Invariant

Every `Frame<'umem>` popped from `free_frames` MUST be pushed to either `tx_return` or `rx_return` — never dropped. Frames from incoming packets go to `rx_return`. Frames written for transmission go to `tx_return`. If any operation fails partway, the frame must be returned to its source. No `Frame<'umem>` is ever stored in TCP data structures across ticks — ring buffers hold copied bytes, not frames.

## Ring Buffer

A single ring buffer structure used for both send and receive sides.

### Structure

- Pre-allocated `Vec<u8>` sized at connection creation, never resized.
- `head: usize` — read position (oldest unread/unACKed byte).
- `tail: usize` — write position (next byte to write).
- `len: usize` — bytes currently in the buffer.
- Capacity is always a power of two. Index wrapping uses bitwise AND (`pos & (capacity - 1)`) instead of modulo.

### Operations (all O(1), no allocation)

- `write_at(offset, &[u8])` — write at an arbitrary offset from `head`. Used by receive side for out-of-order segments. Wraps around the ring with at most two memcpy calls.
- `write(&[u8])` — append bytes at `tail`. Used by send side when user writes data.
- `read(&mut [u8]) -> usize` — read contiguous bytes from `head`. Used by `TcpStream::read()` and send side when building segments.
- `peek_at(offset, &mut [u8])` — read without advancing `head`. Used by send side for retransmission.
- `advance(n)` — move `head` forward. Used when bytes are ACKed (send) or consumed (receive).
- `available() -> usize` — bytes available to read (`len`).
- `free_space() -> usize` — bytes available to write (`capacity - len`).

### Default Sizes

- Send buffer: 256KB
- Receive buffer: 256KB
- Configurable per-connection via `TcpConfig` at listen/connect time.

## Send Path

### Copy Budget

Two copies per segment, both `memcpy` of at most MSS bytes into pre-allocated memory:
1. User data into send ring buffer.
2. Ring buffer into `Frame<'umem>` for kernel handoff.

### Flow

1. User calls `TcpStream::write(data)` — returns a future. Copies data into the send ring buffer. Returns `Poll::Pending` if the buffer is full (backpressure).

2. `TcpHandler::poll_send(now)` — called each runtime tick. For each established connection with data in the send ring buffer:
   - Compute effective send window: `min(snd_wnd, cwnd) - bytes_in_flight`.
   - If window allows, read up to `eff_snd_mss` bytes from the ring buffer.
   - Build segment via `SegmentBuilder::build_data()`.
   - Set sequence number to `snd_nxt`, advance `snd_nxt` by payload length.
   - Push frame to `tx_return`.
   - Record segment sequence range and send timestamp (using the `now` parameter) for RTO tracking.

3. Retransmission (RTO fires or 3 duplicate ACKs):
   - Re-read from oldest unACKed position in the ring buffer via `peek_at`.
   - Build segment into a fresh `Frame<'umem>` from `free_frames`.
   - On RTO: `ssthresh = cwnd / 2`, `cwnd = eff_snd_mss`.
   - On fast retransmit: `ssthresh = cwnd / 2`, `cwnd = ssthresh`.

4. ACK processing (valid ACK advances `snd_una`):
   - Advance `head` in the send ring buffer (frees space for new writes).
   - Update RTT estimate (RFC 6298) using the `now` parameter if this ACK covers a timed segment.
   - Slow start: if `cwnd < ssthresh`, `cwnd += eff_snd_mss`.
   - Congestion avoidance: if `cwnd >= ssthresh`, `cwnd += eff_snd_mss * eff_snd_mss / cwnd`.
   - Reset `dup_ack_count`.

## Receive Path

### Copy Budget

One copy per segment: frame payload into receive ring buffer. Frame returned to `rx_return` immediately.

### Flow

1. `TcpHandler::process_established()` — on receiving a data segment:
   - Sequence check: is `seg_seq` within the receive window (`rcv_nxt` to `rcv_nxt + rcv_wnd`)?
     - Outside window: send duplicate ACK, return frame to `rx_return`.
   - In-order (`seg_seq == rcv_nxt`):
     - Copy payload from frame into receive ring buffer.
     - Return frame to `rx_return` immediately.
     - Advance `rcv_nxt` by payload length.
     - Check out-of-order metadata for now-contiguous ranges, advance `rcv_nxt` for each.
     - Send ACK.
   - Out-of-order (`seg_seq > rcv_nxt`):
     - Copy payload into receive ring buffer at correct offset (`seg_seq - rcv_nxt` ahead of write cursor) via `write_at`.
     - Return frame to `rx_return` immediately.
     - Record range in `BTreeMap<u32, u32>` (seq -> length) — metadata only, no frames held.
     - Send duplicate ACK.
   - Duplicate (`seg_seq < rcv_nxt`):
     - Return frame to `rx_return`, send ACK.

2. `TcpStream::read(&mut [u8])` — read contiguous bytes from the receive ring buffer. Returns a future, `Poll::Pending` when no data available.

### Out-of-Order Tracking

`BTreeMap<u32, u32>` maps sequence number to byte length. Stores metadata only — the actual bytes are already in the ring buffer via `write_at`. When an in-order segment arrives and fills a gap, contiguous ranges are merged and `rcv_nxt` is advanced. This structure is bounded by the receive window size.

## TCB Additions

Per-connection state added to `Tcb`:

```
// Send ring buffer
send_buffer: RingBuffer,

// Receive ring buffer
recv_buffer: RingBuffer,

// Out-of-order receive tracking (metadata only)
ooo_ranges: BTreeMap<u32, u32>,

// Congestion control
cwnd: u32,          // Initialized to 10 * eff_snd_mss
ssthresh: u32,      // Initialized to u32::MAX
dup_ack_count: u8,  // Fast retransmit at 3

// RTT estimation (RFC 6298)
srtt: Option<u64>,  // Smoothed RTT in microseconds
rttvar: u64,        // RTT variance
rto: u64,           // Retransmission timeout in milliseconds
```

## Runtime Integration

Per-tick additions to the `LocalRuntime` loop:

1. `tcp_handler.process_established()` — already dispatched via `process_ipv4`/`process_ipv6`. Established branch filled in with receive logic.
2. `tcp_handler.poll_send(now)` — new. Builds and sends data segments from send ring buffers. Called after receive processing so fresh ACKs update windows before sending.
3. `tcp_handler.poll_timers(now)` — already exists. Extended to handle data retransmission RTO and fast retransmit.

All timestamp operations use the `now: Instant` parameter passed from the single `coarsetime::Instant::now()` call at the top of the runtime tick. No clock reads in handlers or socket code.

### Backpressure

- User write stalls when send ring buffer is full (`TcpStream::write()` returns `Pending`).
- Send window closed: segments stop being built, send ring buffer fills, user stalls.
- Receive ring buffer full: `rcv_wnd` advertised as 0, sender stops (TCP flow control).

## TcpStream API

```rust
// Writing
TcpStream::write(&[u8]) -> Write<'_>       // Pending if send buffer full

// Reading
TcpStream::read(&mut [u8]) -> Read<'_>     // Pending if no data available

// Info (existing)
TcpStream::conn_id() -> &ConnectionId
TcpStream::local_addr() -> IpAddress
TcpStream::local_port() -> u16
TcpStream::remote_addr() -> IpAddress
TcpStream::remote_port() -> u16

// Lifecycle (existing)
TcpStream::close()                          // Sends RST (proper FIN deferred)
```

### Configuration

```rust
pub struct TcpConfig {
    pub send_buffer_size: usize,    // Default: 256KB, must be power of two
    pub recv_buffer_size: usize,    // Default: 256KB, must be power of two
    pub backlog: usize,             // Default: 128 (listener only)
}

TcpListener::listen_with_config(addr, port, TcpConfig { .. })
TcpStream::connect_with_config(local_addr, local_port, remote_addr, remote_port, TcpConfig { .. })
```

## IP Fragmentation

TCP does not use the `FragmentWriter`/`FragmentReader` infrastructure. TCP segments are sized to `eff_snd_mss` (negotiated during handshake). IPv4 packets are sent with DF (Don't Fragment) set. PMTU discovery is handled at the TCP layer by clamping MSS.

## Decisions Summary

| Decision | Choice |
|---|---|
| Send buffer | Pre-allocated ring buffer, power-of-two, default 256KB |
| Receive buffer | Pre-allocated ring buffer, same design |
| Send copies | 2: user to ring buffer, ring buffer to frame |
| Receive copies | 1: frame to ring buffer (frame returned immediately) |
| Out-of-order tracking | `BTreeMap<u32, u32>` metadata only, no frames held |
| Retransmission | RTO + fast retransmit on 3 duplicate ACKs |
| Congestion control | Simple cwnd, slow start, halve-on-loss |
| ACKs | Cumulative only, no SACK, no delayed ACK |
| Timestamps | `now: Instant` from runtime tick, no clock reads in handlers |
| Frame safety | Never held by TCP, never dropped, returned within same tick |
| Configuration | Per-connection via `TcpConfig` |
| RTT estimation | RFC 6298 smoothed RTT + RTTVAR |
| API | `write`/`read` futures with backpressure |

## Deferred

- SACK (selective acknowledgment)
- Delayed ACKs
- Proper FIN teardown / TIME-WAIT
- Congestion control algorithms (Reno/Cubic/BBR)
- Nagle algorithm
- `split()` into read/write halves
