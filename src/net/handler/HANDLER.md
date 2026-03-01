# Handler Module

Protocol dispatch layer. Receives raw frames from the LocalRuntime event loop and routes them through L3 (IPv4/IPv6) to L4 (ICMP, UDP, TCP) handlers. Every frame is consumed — pushed to exactly one of `rx_return` (received data / errors) or `tx_return` (protocol responses).

## IPv4Handler

```rust
pub fn handle(frame, udp_handler, tcp_handler, pmtu, free_frames, rx_return, tx_return)
```

**Validation:** frame length >= 34, version == 4, IHL >= 5, total_length >= header_len, valid IPv4 checksum.

**Dispatch by `protocol` field:**
| Protocol | Action |
|----------|--------|
| ICMP (1) | `icmpv4::handle_icmpv4()` |
| TCP (6) | `tcp_handler.process_ipv4()` |
| UDP (17) | `udp_handler.process_ipv4()` |
| Other | `icmpv4::send_destination_unreachable()` (code: ProtocolUnreachable) |

## IPv6Handler

```rust
pub fn handle(frame, neighbor_handler, udp_handler, tcp_handler, pmtu, free_frames, rx_return, tx_return)
```

**Validation:** frame length >= 54, version == 6, payload_length consistent.

**Extension Header Walking** (`walk_extension_headers`):
Walks the chain transparently skipping Hop-by-Hop (0), Routing (43), Destination Options (60), and AH (51). Stops at Fragment (44), ESP (50), No Next Header (59), or upper-layer protocol. Limit: 16 extension headers max (detects loops/attacks).

Returns `NextHeaderResult`:
- `Protocol { protocol, payload_offset, next_header_offset }` — upper-layer protocol found
- `Fragment { offset }` — Fragment Extension Header encountered
- `Malformed` / `NoPayload`

**Dispatch by final protocol:**
| Protocol | Action |
|----------|--------|
| ICMPv6 (58) NDP types 133-137 | `neighbor_handler.handle_ndp()` |
| ICMPv6 (58) other types | `icmpv6::handle_icmpv6()` |
| TCP (6) | `tcp_handler.process_ipv6()` |
| UDP (17) | `udp_handler.process_ipv6()` |
| Fragment → UDP | `udp_handler.process_ipv6()` with `frag_ext_offset` |
| Other | `icmpv6::send_icmpv6_error()` (ParameterProblem, code: UnrecognizedNextHeader, pointer to NH field) |

## ICMPv4 Handling

```rust
pub fn handle_icmpv4(frame, pmtu, rx_return, tx_return)
pub fn send_destination_unreachable(frame, code, next_hop_mtu, rx_return, tx_return)
```

| Type | Action |
|------|--------|
| Echo Request (8) | Swap MACs/IPs, TTL=64, recompute checksums → Echo Reply (0) to `tx_return`. Rejects broadcast/multicast dst. |
| Dest Unreachable / Frag Needed (3/4) | Extract next-hop MTU and embedded dst IP → update `PmtuCache` → `rx_return` |
| All others | `rx_return` |

**send_destination_unreachable** per RFC 792/1122: includes original IPv4 header (up to 60 bytes) + first 8 bytes of original datagram. MUST NOT send for broadcast/multicast dst, non-unicast src, or ICMP error messages. Sets DF flag.

## ICMPv6 Handling

```rust
pub fn handle_icmpv6(frame, icmpv6_offset, icmpv6_len, neighbor_handler, pmtu, rx_return, tx_return)
pub fn send_icmpv6_error(frame, icmpv6_type, code, body, orig_upper_protocol, orig_upper_offset, rx_return, tx_return)
```

| Type | Action |
|------|--------|
| Echo Request (128) | Swap MACs/IPs, hop_limit=64 → Echo Reply (129) to `tx_return`. Rejects multicast dst. |
| Packet Too Big (2) | Extract MTU (u32) and embedded dst IPv6 → update `PmtuCache` |
| NDP (133-135) | `neighbor_handler.handle_ndp()` |
| All others | `rx_return` |

**send_icmpv6_error** per RFC 4443 s2.4: MUST NOT send for multicast/unspecified src. Multicast dst allowed only for PacketTooBig and ParameterProblem code BeyondScope. Payload capped at 1232 bytes (1280 min MTU - 40 IPv6 - 8 ICMPv6).

## UdpHandler

```rust
pub fn new(max_reassembly_entries: usize) -> Self
pub fn bind(addr, port, rx_capacity) -> Result<SharedQueue<ReceivedUdpPacket>, BindError>
pub fn process_ipv4(frame, rx_return)
pub fn process_ipv6(frame, frag_ext_offset, udp_offset, rx_return)
pub fn evict_stale(timeout, rx_return)
pub fn pending_reassembly() -> usize
```

**Socket Binding:**
- Stores `Vec<(u16, PortBindings)>` where `PortBindings` has explicit `(IpAddress, binding)` entries and an optional wildcard (unspecified addr).
- Explicit IP match takes priority over wildcard.
- Returns `BindError::AddressInUse` on duplicate.

**Routing:** Matches dst_port → explicit IP → wildcard fallback. Full queue evicts oldest. No match → frames to `rx_return`.

**Fragment Reassembly:** Owns a `FragmentReader`. IPv4 packets always pass through it. IPv6 packets with `frag_ext_offset: Some(_)` pass through it; unfragmented IPv6 takes a hot path bypassing reassembly.

**Checksum:** IPv4 zero checksum = "no checksum" (valid). IPv6 zero checksum = invalid (RFC 2460). Multi-fragment packets accumulate checksum across frames via `sum_words_carry()`.

**ReceivedUdpPacket:**
```rust
pub struct ReceivedUdpPacket<'umem> {
    pub src_addr: IpAddress,
    pub dst_addr: IpAddress,
    pub src_port: u16,
    pub dst_port: u16,
    pub packet: Packet<'umem>,
}
```

## TcpHandler

```rust
pub fn new(max_connections: usize) -> Self
pub fn set_time_wait_duration(duration: Duration)
pub fn listen(addr, port, backlog) -> SharedQueue<AcceptedConnection>
pub fn connect(local_addr, local_port, remote_addr, remote_port, local_mac, remote_mac, free_frames, tx_return)
    -> Option<(SharedQueue<TcpEvent>, SharedQueue<TcpCommand>, SharedFrameBuffer)>
pub fn num_connections() -> usize
pub fn process_ipv4(frame, free_frames, rx_return, tx_return)
pub fn process_ipv6(frame, tcp_offset, free_frames, rx_return, tx_return)
pub fn tick(free_frames, rx_return, tx_return)
```

### Connection State Machine (RFC 9293)

States: `Closed`, `Listen`, `SynSent`, `SynReceived`, `Established`, `FinWait1`, `FinWait2`, `CloseWait`, `Closing`, `LastAck`, `TimeWait`.

**Passive open:** `listen()` registers a `ListenerState`. Incoming SYN creates TCB in `SynReceived`, sends SYN-ACK. On ACK, transitions to `Established` and pushes `AcceptedConnection` to the accept queue.

**Active open:** `connect()` creates TCB in `SynSent`, generates ISS via hash of 4-tuple, sends SYN with MSS option. Returns event/command/send-buffer queues immediately.

### Transmission Control Block (TCB)

Per-connection state per RFC 9293 s3.3.1:
- **Send:** `snd_una`, `snd_nxt`, `snd_wnd`, `snd_wl1`, `snd_wl2`, `iss`
- **Receive:** `rcv_nxt`, `rcv_wnd`, `irs`
- **MSS:** `snd_mss`, `rcv_mss` (negotiated via SYN options, default 1460)
- **Reorder:** `recv_reorder: BTreeMap<u32, (Frame, offset, len)>` for out-of-order segment caching
- **Retransmit:** `retransmit_queue: VecDeque<RetransmitEntry>`, `rto_state: RtoState`, `congestion: CongestionState`
- **MAC addresses:** `local_mac`, `remote_mac`
- `effective_window() -> u32` = min(snd_wnd, cwnd)

### Retransmission (RFC 6298)

`RtoState`: Jacobson/Karels algorithm. Initial RTO = 1s. `update(rtt)` maintains SRTT and RTTVAR, computes `RTO = SRTT + 4*RTTVAR` (min 1s). `backoff()` doubles RTO (max 60s). RTT sampled only on non-retransmitted segments.

`RetransmitEntry`: `{ seq, len, frame, sent_at, retransmit_count, is_retransmit, first_retransmit_time }`. Max retransmit time: 100s.

### Congestion Control (RFC 5681)

`CongestionState`: `cwnd` and `ssthresh`. Initial window = 2-4 MSS per RFC 5681 s3.1.

### Socket Layer Communication

| Direction | Type | Purpose |
|-----------|------|---------|
| Handler → Socket | `TcpEvent::Connected` | Three-way handshake completed |
| Handler → Socket | `TcpEvent::Data { frame, payload_offset, payload_len }` | Inbound data |
| Handler → Socket | `TcpEvent::PeerClosed` | FIN received |
| Handler → Socket | `TcpEvent::Reset` | RST received |
| Handler → Socket | `TcpEvent::Closed` | Connection fully closed |
| Socket → Handler | `TcpCommand::Close` | Initiate graceful close (FIN) |
| Socket → Handler | `TcpCommand::Abort` | Abort connection (RST) |
| Socket → Handler | Frames via `SharedFrameBuffer` | Outbound data for transmission |

### tick()

Called each event loop iteration. Processes socket commands (Close/Abort), drains send buffers, checks retransmission timers, handles zero-window probing, cleans TIME-WAIT connections (default 120s, configurable via `set_time_wait_duration`).

## Consumer Context

**LocalRuntime event loop:**
1. `socket.recv()` → batch of frames
2. `EthernetFrame.ether_type` dispatch → `Ipv4Handler.handle()` / `Ipv6Handler.handle()` / `neighbor_handler.handle_arp()`
3. IPv4/IPv6 handlers validate, walk headers, dispatch to ICMP/UDP/TCP handlers
4. User future polled (busy-poll, no-op waker)
5. `tcp_handler.tick()` drives retransmission and outbound data
6. `udp_handler.evict_stale()` + neighbor/PMTU eviction
7. `socket.send()` transmits all `tx_return` frames

## File Layout

| File | Contents |
|------|----------|
| `mod.rs` | Module re-exports |
| `ipv4.rs` | `Ipv4Handler` — validation, protocol dispatch |
| `ipv6.rs` | `Ipv6Handler` — extension header walking, protocol dispatch |
| `icmpv4.rs` | Echo reply, Destination Unreachable, PMTU updates |
| `icmpv6.rs` | Echo reply, Packet Too Big, NDP dispatch, error generation |
| `udp.rs` | `UdpHandler` — binding, routing, fragment reassembly |
| `tcp/handler.rs` | `TcpHandler` — listener/connection management |
| `tcp/tcb.rs` | `Tcb`, `RtoState`, `CongestionState`, `RetransmitEntry` |
| `tcp/types.rs` | `ConnectionId`, `TcpState`, `TcpEvent`, `TcpCommand` |
| `tcp/segment.rs` | `build_tcp_segment`, `send_and_queue_retransmit`, constants |
| `tcp/input.rs` | Inbound segment processing, state transitions |
| `tcp/output.rs` | Outbound operations, retransmission, send buffer draining |
