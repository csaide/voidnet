# Fragment Module

IP fragmentation (outbound) and reassembly (inbound) engine, generic across IPv4 and IPv6. Protocol-agnostic — delegates transport-layer interpretation to callers.

## Public API

### Packet\<'umem\> (enum)

Zero-alloc container for frames forming a single IP datagram.

| Variant | Description |
|---------|-------------|
| `Empty` | Default/sentinel state |
| `Single(Frame<'umem>)` | Unfragmented — no heap allocation |
| `Multi(Vec<Frame<'umem>>)` | Fragmented — Vec-backed, sorted by offset |

**Methods:**
- `num_frames() -> usize`
- `len() -> usize` — total byte length across all frames
- `frames() -> PacketFrameIter` — borrowing iterator
- `into_frames() -> PacketIntoIter` — consuming iterator
- `drain_to(&mut impl FrameBuffer)` — push all frames to a buffer
- `From<T: Iterator<Item=Frame> + ExactSizeIterator>` — collect frames into appropriate variant

### ReassembledPacket\<'umem\>

```rust
pub struct ReassembledPacket<'umem> {
    pub packet: Packet<'umem>,
    pub protocol: u8,  // IP protocol number (6=TCP, 17=UDP)
}
```

Returned by `FragmentReader` when all fragments arrive. Caller interprets transport layer based on `protocol`.

### FragmentReader\<'umem\>

Reassembly engine maintaining separate `HashMap`s for IPv4 and IPv6 keyed by fragment identity.

```rust
pub fn new(max_entries: usize) -> Self
pub fn process_ipv4(frame, rx_return) -> Option<ReassembledPacket>
pub fn process_ipv6(frame, frag_ext_offset, rx_return) -> Option<ReassembledPacket>
pub fn evict_stale(timeout: Duration, rx_return)
pub fn pending_entries() -> usize
```

**Internals:**
- `ReassemblyEntry` uses `BTreeMap<usize, Frame>` keyed by **byte offset** for automatic sort order, enabling out-of-order fragment arrival.
- Tracks `total_len` (set when MF=0 fragment arrives) and `received_len`. Complete when `received_len == total_len`.
- Capacity shared across IPv4+IPv6. At capacity, new flows are dropped (frames returned to `rx_return`).
- `evict_stale()` removes entries older than `timeout`, returning held frames.

**Fragment Keys:**
- IPv4: `(src_addr, dst_addr, protocol, identification: u16)`
- IPv6: `(src_addr, dst_addr, identification: u32)` — no protocol field needed (in Fragment Extension Header)

### FragmentWriter (stateless)

Outbound fragmentation engine. All methods are static.

```rust
pub fn fragment_ipv4(src_mac, dst_mac, src_ip, dst_ip, ttl, transport, payload, mtu, free_frames) -> NonBlocking<Packet>
pub fn fragment_ipv6(src_mac, dst_mac, src_ip, dst_ip, hop_limit, transport, payload, mtu, free_frames) -> NonBlocking<Packet>
```

**Behavior:**
- Fits in MTU: returns `Packet::Single` (IPv4 sets DF flag; IPv6 omits Fragment Extension Header)
- Exceeds MTU: computes `FragmentPlan`, returns `Packet::Multi` with 8-byte-aligned non-last fragments
- Insufficient free frames: returns `Err(WouldBlock)`
- Fragment IDs from atomic counters (`AtomicU16` for IPv4, `AtomicU32` for IPv6) with `Relaxed` ordering

### TransportHeader (trait)

Protocol-agnostic header abstraction used by `FragmentWriter` to prepend transport headers to the first fragment.

```rust
pub trait TransportHeader {
    fn protocol(&self) -> u8;       // IP protocol number
    fn header_len(&self) -> usize;  // Serialized byte length
    fn write_to(&self, buf: &mut [u8]);
}
```

**Implementors:**
| Type | protocol() | header_len() |
|------|-----------|-------------|
| `UdpHeader` | 17 | 8 |
| `TcpHeader` | 6 | 20 |

Both use unsafe `ptr as *const u8` memcpy in `write_to()` (relies on `#[repr(C, packed)]` layout).

### FragmentPlan (pub(crate))

Pre-computed fragmentation sizing to avoid runtime calculations in the packet loop.

```rust
pub(crate) struct FragmentPlan {
    pub max_frag_data: usize,  // (mtu - ip_overhead) & !7  (8-byte aligned)
    pub first_chunk: usize,    // max_frag_data - transport_header_len
    pub num_frames: usize,
}
```

**Example** (IPv4, UDP, 1500 MTU, 3000-byte payload):
- `max_frag_data = (1500 - 20) & !7 = 1480`
- `first_chunk = 1480 - 8 = 1472` (after 8-byte UDP header)
- `num_frames = 1 + ceil((3000 - 1472) / 1480) = 3`

Fragment 0: 8B UDP + 1472B payload. Fragment 1: 1480B payload. Fragment 2: 48B payload (remainder, not aligned).

## Consumer Context

- **UdpHandler** owns a `FragmentReader` and calls `process_ipv4()`/`process_ipv6()` on every inbound UDP frame. On reassembly completion, extracts UDP header and routes to bound socket.
- **UdpSocket.send_to()** calls `FragmentWriter::fragment_ipv4()`/`fragment_ipv6()` with a `UdpHeader` as the `TransportHeader`, then drains the resulting `Packet` to `tx_return`.
- **TcpHandler** does not use fragmentation — TCP segments are sized to MSS.
- **LocalRuntime** event loop calls `udp_handler.evict_stale()` each iteration to clean timed-out reassembly entries.

## File Layout

| File | Contents |
|------|----------|
| `mod.rs` | Re-exports: `Packet`, `FragmentReader`, `ReassembledPacket`, `TransportHeader`, `FragmentWriter` |
| `pkt.rs` | `Packet` enum, `PacketFrameIter`, `PacketIntoIter` |
| `reader.rs` | `FragmentReader`, `ReassemblyEntry`, fragment keys |
| `writer.rs` | `FragmentWriter` (IPv4/IPv6 fragmentation) |
| `transport.rs` | `TransportHeader` trait + `UdpHeader`/`TcpHeader` impls |
| `plan.rs` | `FragmentPlan` pre-computation |
| `id.rs` | Atomic fragment ID counters |
