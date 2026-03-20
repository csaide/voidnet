# Custom QUIC Implementation with rustls

**Date:** 2026-03-20
**Status:** Draft
**Motivation:** Primary transport protocol for KV store and future applications. Full ownership of QUIC state machine, using rustls for TLS 1.3 crypto only.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| QUIC implementation | Full custom from scratch | Same philosophy as TCP — maximum control over state machine, loss recovery, congestion |
| TLS 1.3 | rustls as library | Crypto is too dangerous to roll your own. rustls has a clean QUIC-mode API |
| Handler integration | Dedicated `QuicHandler` at Layer 4 | Dispatched from IPv4/IPv6 handlers on UDP protocol, bypasses `UdpHandler` entirely |
| Congestion control | Pluggable trait, CUBIC first | Extract shared `CongestionController` trait from TCP, monomorphized — no dynamic dispatch |
| Socket API | Connection + Stream model | `QuicConnection` for control/config, `QuicStream` as primary data workhorse |
| Dynamic dispatch | rustls `Box<dyn>` only | Accepted at packet-level crypto operations (~0.5ns vtable vs ~100-200ns AEAD). Zero dynamic dispatch everywhere else |

## Architecture: Layered

Four distinct layers with clear interfaces, each testable in isolation:

1. **Crypto layer** — rustls integration, packet protection
2. **Transport layer** — packets, frames, loss detection, congestion control, flow control
3. **Stream layer** — stream multiplexing, per-stream flow control, buffering
4. **Handler + Socket** — runtime integration, user-facing async API

## Module Structure

```
src/net/handler/quic/
├── mod.rs                  # QuicHandler — dispatch, connection table, timer handling
├── connection.rs           # QuicConnectionState (analogous to Tcb)
├── connection_id.rs        # ConnectionId type, CID routing table
├── crypto/
│   ├── mod.rs              # Crypto layer public interface
│   ├── tls.rs              # rustls integration — ServerConfig/ClientConfig, handshake driving
│   ├── keys.rs             # Key schedule, key update logic
│   └── packet_protection.rs # Encrypt/decrypt in-place on XDP frame buffers
├── transport/
│   ├── mod.rs              # Transport layer public interface
│   ├── packet.rs           # Packet parsing/building (Initial, Handshake, 0-RTT, 1-RTT)
│   ├── frame.rs            # QuicFrame parsing/building (STREAM, ACK, CRYPTO, etc.)
│   ├── loss.rs             # Loss detection & recovery (RFC 9002)
│   ├── congestion.rs       # Pluggable congestion control trait + CUBIC impl
│   └── flow_control.rs     # Connection-level flow control
├── stream/
│   ├── mod.rs              # Stream layer public interface
│   ├── state.rs            # Stream state machine (bidi, uni, send/recv states)
│   ├── flow_control.rs     # Per-stream flow control
│   └── buffer.rs           # Stream send/recv ring buffers (shared with TCP)
└── timer.rs                # QUIC-specific timer kinds

src/net/socket/
├── quic.rs                 # QuicListener, QuicConnection, QuicStream

src/net/congestion/
├── mod.rs                  # Shared CongestionController trait + CUBIC (used by TCP and QUIC)
```

## Handler Integration

### Dispatch Chain Change

`Ipv4Handler`/`Ipv6Handler` currently dispatch UDP protocol → `UdpHandler`. The change: if the destination port is registered with `QuicHandler`, route there instead. `UdpHandler` only sees non-QUIC UDP traffic.

### Connection Table

```rust
pub struct QuicHandler {
    connections: Slab<QuicConnectionState>,
    cid_map: FxHashMap<ConnectionId, usize>,  // many CIDs → one slab index
    listeners: FxHashMap<u16, ListenerState>,  // port → listener
    stream_pool: StreamPool,
}
```

QUIC connections have multiple CIDs (peer can issue new ones for path migration/privacy). The `cid_map` maps all active CIDs to the same slab index.

### Timer Integration

Reuse existing `TimerWheel`. QUIC timers encode `(connection_key, timer_kind)` into `TimerId` u64, same pattern as TCP:

```rust
pub enum QuicTimerKind {
    LossDetection,  // RFC 9002 loss detection timer
    Idle,           // connection idle timeout
    Ack,            // delayed ACK
    Handshake,      // handshake completion deadline
    Draining,       // post-close draining period
    KeyDiscard,     // discard old keys after update
}
```

## Crypto Layer

### Design Principle

rustls handles TLS 1.3 handshake and key derivation. The `Box<dyn PacketKey>` / `Box<dyn HeaderProtectionKey>` dynamic dispatch from rustls is accepted — it operates per-packet, and the AEAD computation (~100-200ns) dwarfs the vtable lookup (~0.5ns).

### Key Types

```rust
pub struct CryptoState {
    tls: rustls::quic::Connection,
    keys: PacketKeys,
}

pub struct PacketKeys {
    initial: Option<DirectionalKeys>,
    handshake: Option<DirectionalKeys>,
    one_rtt: Option<DirectionalKeys>,
    zero_rtt: Option<DirectionalKeys>,
}

pub struct DirectionalKeys {
    seal: Box<dyn rustls::quic::PacketKey>,
    open: Box<dyn rustls::quic::PacketKey>,
    header: Box<dyn rustls::quic::HeaderProtectionKey>,
}
```

### Handshake Flow

1. Transport receives Initial packet → decrypts with Initial keys (derived deterministically from connection ID)
2. Extracts CRYPTO frames → feeds to `CryptoState::process_crypto_data()`
3. rustls produces response CRYPTO data + possibly new keys
4. Transport builds outbound CRYPTO frames + installs new `DirectionalKeys`
5. Repeat until handshake completes, 1-RTT keys installed

### Zero-Copy Constraint

All encrypt/decrypt operates in-place on XDP frame buffers. No intermediate allocations. AEAD tag appended/verified in-place.

## Transport Layer

### Packet Types

QUIC has four packet types in three packet number spaces, each with independent loss detection:

```rust
pub enum PacketType {
    Initial,    // connection setup
    Handshake,  // handshake completion
    ZeroRtt,    // early data
    OneRtt,     // application data (short header, most traffic)
}

pub struct PacketHeader {
    packet_type: PacketType,
    dcid: ConnectionIdRef<'_>,  // borrows from frame buffer — no allocation
    scid: ConnectionIdRef<'_>,  // long header only
    packet_number: u64,
    payload_offset: usize,
    payload_len: usize,
}
```

`ConnectionIdRef<'_>` borrows directly from the frame buffer for zero-copy CID routing lookups.

### Frame Types

```rust
pub enum QuicFrame<'a> {
    Padding,
    Ping,
    Ack(AckFrame<'a>),
    Crypto(CryptoFrame<'a>),
    Stream(StreamFrame<'a>),
    ResetStream(ResetStreamFrame),
    StopSending(StopSendingFrame),
    NewConnectionId(NewConnectionIdFrame<'a>),
    RetireConnectionId(RetireConnectionIdFrame),
    MaxData(u64),
    MaxStreamData(MaxStreamDataFrame),
    MaxStreams(MaxStreamsFrame),
    DataBlocked(u64),
    StreamDataBlocked(StreamDataBlockedFrame),
    NewToken(NewTokenFrame<'a>),
    ConnectionClose(ConnectionCloseFrame<'a>),
    HandshakeDone,
}
```

Named `QuicFrame` to avoid collision with XDP `Frame`. All data-carrying variants borrow from the packet buffer — `StreamFrame<'a>` points directly at payload bytes in the XDP frame.

### Loss Detection (RFC 9002)

```rust
pub struct LossDetector {
    spaces: [PacketNumberSpace; 3],  // Initial, Handshake, OneRtt
    smoothed_rtt: Duration,
    rttvar: Duration,
    min_rtt: Duration,
    pto_count: u32,
}

pub struct PacketNumberSpace {
    largest_acked: Option<u64>,
    sent_packets: BTreeMap<u64, SentPacket>,
    loss_time: Option<Instant>,
    ack_eliciting_in_flight: u32,
}

pub struct SentPacket {
    time_sent: Instant,
    size: u16,
    ack_eliciting: bool,
    frames: SmallVec<[SentFrame; 4]>,
}
```

### Congestion Control — Shared Pluggable Trait

Extract CUBIC from TCP into a shared module. Monomorphized via generics — no dynamic dispatch:

```rust
// src/net/congestion/mod.rs
pub trait CongestionController {
    fn on_packet_sent(&mut self, bytes: usize, now: Instant);
    fn on_ack(&mut self, bytes: usize, rtt: Duration, now: Instant);
    fn on_loss(&mut self, bytes: usize, now: Instant);
    fn window(&self) -> usize;
    fn bytes_in_flight(&self) -> usize;
    fn can_send(&self) -> bool;
}

pub struct Cubic { /* existing fields */ }
impl CongestionController for Cubic { /* existing logic */ }
```

TCP's `congestion.rs` becomes a thin wrapper. QUIC uses the same `Cubic`. BBRv2 or others can be added later. `QuicConnectionState<C: CongestionController>` monomorphizes per algorithm.

### Connection-Level Flow Control

```rust
pub struct FlowControl {
    max_data_send: u64,    // peer's limit on our sending
    data_sent: u64,
    max_data_recv: u64,    // our limit on peer's sending
    data_received: u64,
    auto_tune: bool,
}
```

## Stream Layer

### Stream ID Encoding

Low 2 bits of stream ID encode initiator + direction. Direct Vec indexing, no hashing:

```rust
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct StreamId(u64);

pub enum Initiator { Client, Server }
pub enum Direction { Bidi, Uni }

pub struct StreamMap {
    client_bidi: Vec<Option<StreamState>>,
    server_bidi: Vec<Option<StreamState>>,
    client_uni: Vec<Option<StreamState>>,
    server_uni: Vec<Option<StreamState>>,

    local_max_bidi: u64,
    local_max_uni: u64,
    peer_max_bidi: u64,
    peer_max_uni: u64,

    accept_queue: LocalQueue<StreamId>,
}

impl StreamMap {
    #[inline(always)]
    fn get(&self, id: StreamId) -> Option<&StreamState> {
        let idx = (id.0 >> 2) as usize;
        match id.0 & 0x03 {
            0 => self.client_bidi.get(idx)?.as_ref(),
            1 => self.server_bidi.get(idx)?.as_ref(),
            2 => self.client_uni.get(idx)?.as_ref(),
            3 => self.server_uni.get(idx)?.as_ref(),
            _ => unreachable!(),
        }
    }
}
```

### Stream State Machine

```rust
pub enum StreamState {
    Bidi { send: SendHalf, recv: RecvHalf },
    SendOnly { send: SendHalf },
    RecvOnly { recv: RecvHalf },
}

pub enum SendState { Ready, Send, DataSent, DataRecvd, ResetSent, ResetRecvd }
pub enum RecvState { Recv, SizeKnown, DataRecvd, DataRead, ResetRecvd }
```

Enum variants instead of `Option<SendHalf>` / `Option<RecvHalf>` — no discriminant overhead on every access for the common bidi case.

### Send/Recv Halves — Cache-Line Aligned

```rust
#[repr(C)]
pub struct RecvHalf {
    // Hot — touched every incoming StreamFrame
    buffer: RingBuffer,
    received: u64,
    max_stream_data: u64,
    state: RecvState,
    fin_received: bool,
    _pad: [u8; 6],

    // Cold — only on OOO or app read
    ooo: OooRanges,
    waker: Option<Waker>,
}

#[repr(C)]
pub struct SendHalf {
    // Hot — touched every outgoing write
    buffer: RingBuffer,
    sent: u64,
    max_stream_data: u64,
    state: SendState,
    fin_sent: bool,
    _pad: [u8; 6],

    // Cold
    waker: Option<Waker>,
}
```

### Out-of-Order Ranges — Inline Small

```rust
pub struct OooRanges {
    inline: [(u64, usize); 4],  // covers 99% of cases in one cache line
    len: u8,
    overflow: Option<Box<BTreeMap<u64, usize>>>,
}
```

Linear scan over 4 inline entries. `BTreeMap` only allocated in pathological reordering.

### Stream Pooling

KV store workload = millions of short-lived streams. Pool stream objects to avoid allocator pressure:

```rust
pub struct StreamPool {
    send_halves: Vec<SendHalf>,
    recv_halves: Vec<RecvHalf>,
}

impl StreamPool {
    fn alloc_send(&mut self) -> SendHalf {
        self.send_halves.pop().unwrap_or_else(SendHalf::new)
    }
    fn release_send(&mut self, mut half: SendHalf) {
        half.reset();  // clear state, keep ring buffer allocation
        self.send_halves.push(half);
    }
}
```

Ring buffer backing memory survives recycling — only head/tail/state reset.

### Shared RingBuffer

TCP's `ring_buffer.rs` is extracted to a shared location (or `pub(crate)`) for use by both TCP send/recv buffers and QUIC stream buffers.

## Connection State

```rust
#[repr(C)]
pub struct QuicConnectionState {
    // Hot — every packet
    dcid: ConnectionId,
    keys: PacketKeys,
    loss: LossDetector,
    congestion: Cubic,
    flow: FlowControl,

    // Warm — most packets
    streams: StreamMap,
    stream_pool: StreamPool,

    // Connection management
    scid_set: SmallVec<[ConnectionId; 4]>,
    dcid_seq: u64,
    state: ConnectionState,
    side: Side,

    // Handshake
    crypto: CryptoState,

    // Config / cold
    idle_timeout: Duration,
    max_udp_payload: u16,
    events: LocalQueue<QuicEvent>,
}

pub enum ConnectionState { Handshaking, Established, Draining, Closing, Closed }
pub enum Side { Client, Server }

pub struct ConnectionId {
    bytes: [u8; 20],  // max CID length per RFC 9000
    len: u8,
}
```

### Inbound Packet Dispatch (Hot Path)

1. Parse first byte → long header or short header
2. Extract DCID (borrows from frame buffer)
3. `cid_map.get(dcid)` → slab index
4. Not found + Initial → check listeners → new connection
5. Not found + other → drop
6. Decrypt in-place with appropriate packet space keys
7. Parse `QuicFrame`s, dispatch to connection state machine

### Connection Lifecycle

**Client connect:** Generate initial CID → derive Initial keys → send Initial packet with CRYPTO (ClientHello) → Handshaking

**Server accept:** Receive Initial → derive Initial keys from DCID → decrypt → feed CRYPTO to rustls → get ServerHello + keys → send Initial + Handshake → Handshaking

**Handshake complete:** 1-RTT keys installed → Established → notify socket layer via `LocalQueue<QuicEvent>`

**Shutdown:** Send CONNECTION_CLOSE → Closing → drain timer → Closed → return streams to pool → remove CIDs from `cid_map` → release slab slot

## Socket API

```rust
// Listener
pub struct QuicListener {
    port: u16,
    accept_queue: LocalQueue<usize>,
    handler: Rc<UnsafeCell<QuicHandler>>,
}

impl QuicListener {
    pub fn listen(addr: IpAddress, port: u16, tls_config: ServerConfig) -> Result<Self, BindError>;
    pub fn accept(&self) -> Accept<'_>;
}

// Connection
pub struct QuicConnection {
    conn_key: usize,
    handler: Rc<UnsafeCell<QuicHandler>>,
    wheel: Rc<UnsafeCell<TimerWheel>>,
    event_queue: LocalQueue<QuicEvent>,
}

impl QuicConnection {
    pub fn connect(addr: IpAddress, port: u16, server_name: &str, tls_config: ClientConfig) -> Connect;
    pub fn connect_0rtt(addr: IpAddress, port: u16, server_name: &str, tls_config: ClientConfig) -> (Connect, Option<QuicSendStream>);
    pub fn open_bidi_stream(&self) -> Result<QuicStream, StreamError>;
    pub fn open_uni_stream(&self) -> Result<QuicSendStream, StreamError>;
    pub fn accept_stream(&self) -> AcceptStream<'_>;
    pub fn max_concurrent_bidi_streams(&self) -> u64;
    pub fn max_concurrent_uni_streams(&self) -> u64;
    pub fn rtt(&self) -> Duration;
    pub fn close(&self, error_code: u64, reason: &[u8]);
}

// Streams
pub struct QuicStream {
    conn_key: usize,
    stream_id: StreamId,
    handler: Rc<UnsafeCell<QuicHandler>>,
}

impl QuicStream {
    pub fn read(&self, buf: &mut [u8]) -> StreamRead<'_>;
    pub fn write(&self, buf: &[u8]) -> StreamWrite<'_>;
    pub fn finish(&self);
    pub fn reset(&self, error_code: u64);
    pub fn id(&self) -> StreamId;
    pub fn split(self) -> (QuicRecvStream, QuicSendStream);
}
```

### Events

```rust
pub enum QuicEvent {
    HandshakeComplete,
    NewStream(StreamId),
    StreamReadable(StreamId),
    StreamWritable(StreamId),
    StreamFinished(StreamId),
    StreamReset(StreamId, u64),
    ConnectionClosed(u64, Vec<u8>),
}
```

### 0-RTT Support

Critical for KV store — repeat clients send first request in the very first packet:

```rust
impl QuicConnection {
    pub fn connect_0rtt(
        addr: IpAddress,
        port: u16,
        server_name: &str,
        tls_config: ClientConfig,
    ) -> (Connect, Option<QuicSendStream>);
}
```

Returns a send stream immediately if 0-RTT keys are available from a cached session. Stream usable before handshake completes. Server may reject — caller must handle.

## Performance Constraints

- **Zero-copy:** Encrypt/decrypt in-place on XDP frame buffers. No intermediate allocations on data path.
- **No dynamic dispatch** except rustls `Box<dyn PacketKey>` (per-packet, AEAD cost dominates).
- **No heap allocation** on hot path — stream pooling, inline OOO ranges, fixed-size ConnectionId.
- **Cache-line aligned** hot fields on `RecvHalf`/`SendHalf`.
- **Direct index** stream lookup via `StreamId >> 2` — no hashing.
- **Monomorphized** congestion control via generics.

## Key RFCs

- **RFC 9000** — QUIC Transport Protocol
- **RFC 9001** — Using TLS to Secure QUIC
- **RFC 9002** — QUIC Loss Detection and Congestion Control
- **RFC 9369** — QUIC Version 2 (future consideration)
