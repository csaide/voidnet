# Socket Module

User-facing socket API. Provides async futures for UDP and TCP I/O, backed by lock-free shared queues that bridge the handler layer and user code. All futures use busy-poll semantics with no-op wakers — designed for the LocalRuntime event loop.

## SharedQueue\<T\>

Lock-free fixed-capacity MPMC queue backed by `crossbeam::ArrayQueue` wrapped in `Arc`.

```rust
pub fn new(capacity: usize) -> Self
pub fn push(&self, item: T) -> Option<T>    // force_push: evicts oldest if full
pub fn pop(&self) -> Option<T>
pub fn len(&self) -> usize
pub fn is_empty(&self) -> bool
pub fn capacity(&self) -> usize
```

`Clone` shares the same underlying `Arc<ArrayQueue<T>>`. No mutexes or per-item allocations.

Used throughout the stack: `SharedQueue<ReceivedUdpPacket>` for UDP RX, `SharedQueue<TcpEvent>` for TCP data delivery, `SharedQueue<TcpCommand>` for socket-to-handler commands, `SharedQueue<AcceptedConnection>` for TCP accept.

## UdpSocket

```rust
pub fn local_addr(&self) -> IpAddress
pub fn local_port(&self) -> u16
pub fn recv_from(&self) -> UdpRecvFromFuture
pub fn send_to(&mut self, dst_addr, dst_port, payload) -> UdpSendToFuture
pub fn discard_packet(&mut self, packet: ReceivedUdpPacket)
```

**Internal state:** `rx_queue`, `free_frames`, `tx_return`, `rx_return`, `Rc<PmtuCache>`, `Rc<NeighborHandler>`.

### UdpRecvFromFuture

```rust
type Output = ReceivedUdpPacket<'umem>;
```

Polls `rx_queue.pop()`. Returns `Pending` if empty, `Ready(packet)` when data arrives. The handler pushes `ReceivedUdpPacket`s into the queue after reassembly and checksum validation.

### UdpSendToFuture

```rust
type Output = u32;  // payload bytes sent
```

Multi-step state machine:
1. **MAC resolution:** `neighbor_handler.lookup(&dst_addr)`. If miss, calls `resolve_v4()`/`resolve_v6()` to initiate ARP/NDP, returns `Pending`.
2. **Address validation:** Ensures src/dst address families match.
3. **Checksum:** Computes UDP checksum from parts via `compute_udp_checksum_from_parts()` / `compute_udp_checksum_v6_from_parts()`.
4. **Fragmentation:** Calls `FragmentWriter::fragment_ipv4()`/`fragment_ipv6()` with TTL=64 and PMTU from `pmtu.get(&dst_addr)` (default 1500).
5. **Backpressure:** Checks `tx_return` capacity. Returns `Pending` if insufficient space.
6. **Transmit:** Drains `Packet` frames to `tx_return`.

Tracks initialization via `self.pkt` field (`Packet::Empty` = first poll).

## TcpListener

```rust
pub fn local_addr(&self) -> IpAddress
pub fn local_port(&self) -> u16
pub fn accept(&self) -> TcpAcceptFuture
```

**Internal state:** `accept_queue: SharedQueue<AcceptedConnection>`, `free_frames`, `rx_return`.

### TcpAcceptFuture

```rust
type Output = TcpStream<'umem>;
```

Polls `accept_queue.pop()`. Returns `Pending` until a connection completes the three-way handshake. The handler pushes `AcceptedConnection` containing the stream's event queue, command queue, and send buffer.

## TcpStream

```rust
pub fn local_addr(&self) -> IpAddress
pub fn local_port(&self) -> u16
pub fn remote_addr(&self) -> IpAddress
pub fn remote_port(&self) -> u16
pub fn read<'buf>(&mut self, buf: &'buf mut [u8]) -> TcpReadFuture
pub fn write<'buf>(&mut self, data: &'buf [u8]) -> TcpWriteFuture
pub fn close(&self)
pub fn abort(&self)
pub fn discard_frame(&mut self, frame: Frame)
```

**Internal state:** `rx_queue: SharedQueue<TcpEvent>`, `cmd_queue: SharedQueue<TcpCommand>`, `send_buffer: SharedFrameBuffer`, `free_frames`, `rx_return`.

### TcpReadFuture

```rust
type Output = TcpReadResult;
```

Polls `rx_queue.pop()` and maps `TcpEvent` variants:
| TcpEvent | TcpReadResult |
|----------|---------------|
| `Data { frame, payload_offset, payload_len }` | Copies payload to user buffer, returns frame to `rx_return`. `Data(bytes_copied)` |
| `Connected` | `Connected` |
| `PeerClosed` | `PeerClosed` |
| `Reset` | `Reset` |
| `Closed` | `Closed` |

Empty queue returns `Pending`.

### TcpWriteFuture

```rust
type Output = usize;  // bytes written
```

1. Pops a free frame from `free_frames`. Returns `Pending` if none available.
2. Copies payload data to the frame (limited by frame capacity).
3. Pushes frame to `send_buffer` for the handler to drain during `tick()`.
4. Returns `Ready(bytes_written)`.

### TcpReadResult

```rust
pub enum TcpReadResult {
    Data(usize),    // bytes copied to user buffer
    Connected,      // three-way handshake completed (active open)
    PeerClosed,     // FIN received
    Reset,          // RST received
    Closed,         // connection fully closed
}
```

### close() / abort()

- `close()` pushes `TcpCommand::Close` — initiates graceful FIN sequence.
- `abort()` pushes `TcpCommand::Abort` — sends RST immediately.

Commands are processed by `TcpHandler::tick()` on the next event loop iteration.

## Consumer Context

**Socket creation** (in `LocalRuntime`):
```rust
// UDP
let rx_queue = udp_handler.bind(addr, port, capacity)?;
UdpSocket::new(addr, port, rx_queue, free_frames, rx_return, tx_return, pmtu, neighbor_handler)

// TCP listen
let accept_queue = tcp_handler.listen(addr, port, backlog);
TcpListener::new(addr, port, accept_queue, free_frames, rx_return)

// TCP connect
let (rx_queue, cmd_queue, send_buffer) = tcp_handler.connect(...)?;
TcpStream::new(local_addr, local_port, remote_addr, remote_port, rx_queue, cmd_queue, send_buffer, free_frames, rx_return)
```

**Example usage** (in user future passed to `runtime.run()`):
```rust
// UDP echo
let mut socket = runtime.bind_udp(addr, 8080)?;
loop {
    let pkt = socket.recv_from().await;
    socket.send_to(pkt.src_addr, pkt.src_port, &payload).await;
    socket.discard_packet(pkt);
}

// TCP echo
let listener = runtime.listen_tcp(addr, 8080, 1024);
loop {
    let mut stream = listener.accept().await;
    loop {
        match stream.read(&mut buf).await {
            TcpReadResult::Data(n) => { stream.write(&buf[..n]).await; }
            TcpReadResult::PeerClosed | TcpReadResult::Reset => { stream.close(); break; }
            _ => {}
        }
    }
}
```

All futures are polled by the LocalRuntime's busy-poll loop. The no-op waker means `cx.waker().wake()` is never called — progress is driven by the continuous polling loop.

## File Layout

| File | Contents |
|------|----------|
| `mod.rs` | Re-exports: `SharedQueue`, `TcpListener`, `TcpReadResult`, `TcpStream`, `UdpSocket` |
| `queue.rs` | `SharedQueue<T>` — `Arc<ArrayQueue<T>>` wrapper |
| `tcp.rs` | `TcpListener`, `TcpAcceptFuture`, `TcpStream`, `TcpReadFuture`, `TcpWriteFuture`, `TcpReadResult` |
| `udp.rs` | `UdpSocket`, `UdpRecvFromFuture`, `UdpSendToFuture` |
