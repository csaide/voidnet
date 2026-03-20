# Custom QUIC Implementation with rustls

**Date:** 2026-03-20
**Status:** Draft (rev 3 — post RFC 9000/9001/9002/8999/9369 cross-reference)
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
| Congestion refactoring | QUIC gets own `QuicCubic` first | TCP's `CubicState` is tightly coupled to TCP semantics (`u32` sequence space, `receiver_window`, RTO methods). Extract shared trait later once both are stable. Avoids risking 1107 passing TCP tests. |

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
├── connection_id.rs        # ConnectionId type, CID routing table, stateless reset tokens
├── crypto/
│   ├── mod.rs              # Crypto layer public interface
│   ├── tls.rs              # rustls integration — ServerConfig/ClientConfig, handshake driving
│   ├── keys.rs             # Key schedule, key update logic
│   └── packet_protection.rs # Encrypt/decrypt in-place on XDP frame buffers
├── transport/
│   ├── mod.rs              # Transport layer public interface
│   ├── packet.rs           # Packet parsing/building (Initial, Handshake, 0-RTT, 1-RTT, Retry, VersionNeg)
│   ├── frame.rs            # QuicFrame parsing/building (all RFC 9000 §19 frame types)
│   ├── loss.rs             # Loss detection & recovery (RFC 9002)
│   ├── congestion.rs       # Pluggable congestion control trait + QuicCubic
│   ├── flow_control.rs     # Connection-level flow control
│   ├── params.rs           # Transport parameter negotiation (RFC 9000 §18)
│   └── packet_number.rs    # Variable-length encoding/decoding, full PN reconstruction
├── stream/
│   ├── mod.rs              # Stream layer public interface
│   ├── state.rs            # Stream state machine (bidi, uni, send/recv states per RFC 9000 §3)
│   ├── flow_control.rs     # Per-stream flow control with final size accounting
│   └── buffer.rs           # Stream send/recv buffers (slim — no embedded wakers)
├── path.rs                 # Path state, validation (PATH_CHALLENGE/RESPONSE), migration
├── token.rs                # Retry token + NEW_TOKEN generation/validation
├── error.rs                # Transport error codes (RFC 9000 §20)
└── timer.rs                # QUIC-specific timer kinds

src/net/socket/
├── quic.rs                 # QuicListener, QuicConnection, QuicStream

src/net/congestion/
├── mod.rs                  # Shared CongestionController trait
├── cubic.rs                # QuicCubic (standalone, not extracted from TCP yet)
```

## Handler Integration

### Dispatch Chain — Precise Mechanism

`Ipv4Handler`/`Ipv6Handler` currently dispatch on `IpProtocols::Udp` → `UdpHandler`. QUIC runs over UDP (IP protocol 17) — there is no separate IP protocol number. The dispatch must differentiate by destination port.

**Change to IP handler `handle()` signatures:**

```rust
// Before:
fn handle(&self, frame: Frame, ..., udp_handler: &mut UdpHandler, ...) -> ...

// After:
fn handle(&self, frame: Frame, ..., udp_handler: &mut UdpHandler, quic_handler: &mut QuicHandler, ...) -> ...
```

In the UDP match arm, before forwarding to `UdpHandler`, check destination port:

```rust
IpProtocols::Udp => {
    let dst_port = /* parse from UDP header */;
    if quic_handler.is_quic_port(dst_port) {
        quic_handler.process(frame, ...)
    } else {
        udp_handler.process(frame, ...)
    }
}
```

**Blast radius:** This changes `Ipv4Handler::handle()` and `Ipv6Handler::handle()` signatures, which propagate through `LocalRuntime`'s event loop in `rt/local.rs`. All existing call sites must be updated. This is a necessary breaking change but is contained to the dispatch path.

### Connection Table

```rust
pub struct QuicHandler {
    connections: Slab<QuicConnectionState>,
    cid_map: FxHashMap<ConnectionId, usize>,  // many CIDs → one slab index
    listeners: FxHashMap<u16, ListenerState>,  // port → listener
    // StreamPool lives per-connection, not here (avoids shared mutable state)
}
```

QUIC connections have multiple CIDs (peer can issue new ones for path migration/privacy). The `cid_map` maps all active CIDs to the same slab index.

### Timer Integration

Reuse existing `TimerWheel`. QUIC timers encode `(connection_key, timer_kind)` into `TimerId` u64, same pattern as TCP:

```rust
pub enum QuicTimerKind {
    LossDetection,  // RFC 9002 loss detection timer
    Idle,           // connection idle timeout (RFC 9000 §10.1)
    Ack,            // delayed ACK generation
    Handshake,      // handshake completion deadline
    Draining,       // post-close draining period (≥3× PTO, RFC 9000 §10.2)
    KeyDiscard,     // discard old keys after update
    PathValidation, // PATH_CHALLENGE timeout
    PmtuProbe,      // DPLPMTUD probe timer
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
    // Per-space CRYPTO frame reassembly (RFC 9000 §7.5)
    crypto_buffers: [CryptoBuffer; 3],  // Initial, Handshake, OneRtt
}

/// Reassembly buffer for out-of-order CRYPTO frames per packet space
pub struct CryptoBuffer {
    data: Vec<u8>,
    received: u64,      // contiguous frontier
    ooo: OooRanges,     // reuse stream OOO tracking
    max_offset: u64,    // limit buffering to prevent abuse (RFC 9000 §21.7)
}

pub struct PacketKeys {
    initial: Option<KeyPair>,
    handshake: Option<KeyPair>,
    one_rtt: Option<KeyPair>,
    zero_rtt: Option<ZeroRttKeys>,
}

/// One direction of packet protection — each packet space has a local and remote pair
pub struct KeyPair {
    local: DirectionalKey,   // encrypt outgoing (seal + header protect)
    remote: DirectionalKey,  // decrypt incoming (open + header unprotect)
}

pub struct DirectionalKey {
    packet_key: Box<dyn rustls::quic::PacketKey>,
    header_key: Box<dyn rustls::quic::HeaderProtectionKey>,
}

pub struct ZeroRttKeys {
    seal: Box<dyn rustls::quic::PacketKey>,
    seal_header: Box<dyn rustls::quic::HeaderProtectionKey>,
    open: Box<dyn rustls::quic::PacketKey>,
    open_header: Box<dyn rustls::quic::HeaderProtectionKey>,
}
```

### Initial Key Derivation (RFC 9001 §5.2)

Initial keys are deterministic — derived from the client's initial DCID, not from TLS:

- **Salt (v1):** `0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a`
- **Hash:** SHA-256 (always, before cipher suite negotiation)
- **Process:** `initial_secret = HKDF-Extract(salt, client_dcid)` → derive `client_initial_secret` and `server_initial_secret` via HKDF-Expand-Label
- **Labels:** `"quic key"`, `"quic iv"`, `"quic hp"` with zero-length Context
- **Note:** If server sends Retry, Initial keys are re-derived from the *new* DCID in the Retry packet

### Header Protection (RFC 9001 §5.4)

Header protection masks packet number length and bits using a sample from the encrypted payload:

- **Sample:** 16 bytes starting at `pn_offset + 4` (assumes max 4-byte PN)
- **AES suites:** `mask = AES-ECB(hp_key, sample)`
- **ChaCha20 suite:** counter + nonce from sample, `mask = ChaCha20(key, counter, nonce, 5_zero_bytes)`
- **Long header:** XOR first byte with `mask[0] & 0x0f` (4 LSBs)
- **Short header:** XOR first byte with `mask[0] & 0x1f` (5 LSBs)
- **PN bytes:** XOR with `mask[1..1+pn_length]`

Applied after encryption on send, removed before decryption on receive.

### TLS Integration Requirements (RFC 9001)

- **TLS version:** MUST NOT offer TLS < 1.3. Terminate if < 1.3 negotiated (§4.2)
- **ALPN:** MUST use ALPN to negotiate application protocol. Close with `0x0178` (no_application_protocol) if negotiation fails (§8.1)
- **Transport parameters:** MUST send `quic_transport_parameters` TLS extension in ClientHello and EncryptedExtensions. Close with `0x016d` (missing_extension) if absent (§8.2). Parameters are in handshake transcript — tampering causes handshake failure.
- **CRYPTO frames:** Carry ONLY TLS handshake messages (not alerts, not application data). TLS alerts MUST be converted to CONNECTION_CLOSE frames (§4.8).
- **CRYPTO ordering:** Out-of-order data from same encryption level must not extend past previously received data (PROTOCOL_VIOLATION). Data from new encryption levels buffered until TLS advances.
- **0-RTT constraints:** `max_early_data_size` MUST be `0xffffffff` (§4.6.1). Server MUST reject 0-RTT if HelloRetryRequest sent. Anti-replay is application protocol's responsibility — QUIC frame processing is idempotent, but application data may not be (§9.2).

### Handshake Flow (RFC 9000 §7, RFC 9001)

1. **Client Initial:** Generate unpredictable DCID (≥8 bytes, RFC 9000 §7.2). Derive Initial keys from DCID using v1 salt + SHA-256. Send Initial packet with CRYPTO (ClientHello + ALPN). Pad datagram to ≥1200 bytes.
2. **Server receives Initial:** Validate datagram ≥1200 bytes (discard if smaller, RFC 9000 §14.1). Derive Initial keys from client's DCID. Decrypt. Feed CRYPTO data to `CryptoState`. Optionally send Retry for address validation (re-derives Initial keys from new DCID).
3. **CRYPTO exchange:** Extract CRYPTO frames, reassemble in `CryptoBuffer` (may arrive out-of-order). Feed complete data to rustls. rustls produces response CRYPTO data + new keys at each stage.
4. **Key installation:** As rustls produces Handshake/1-RTT keys, install in `PacketKeys`. Key labels: `"quic key"`, `"quic iv"`, `"quic hp"` with zero-length Context.
5. **Handshake complete vs confirmed (RFC 9001 §4.1.1-4.1.2):**
   - **Complete:** TLS has sent Finished AND verified peer's Finished. Timing differs for client/server.
   - **Confirmed (server):** When handshake completes — sends HANDSHAKE_DONE.
   - **Confirmed (client):** When receives HANDSHAKE_DONE OR receives ACK for 1-RTT packet.
   - Key update, key discard, migration all depend on *confirmation*, not just completion.
6. **CID authentication:** Both endpoints validate transport parameters: `initial_source_connection_id`, `original_destination_connection_id`, `retry_source_connection_id` (RFC 9000 §7.3).

### Key Discard Schedule (RFC 9001 §4.9)

- **Initial keys:** Discard when first sending Handshake (client) or first successfully processing Handshake (server)
- **Handshake keys:** Discard when handshake is *confirmed* (not just complete)
- **0-RTT keys:** May discard immediately after installing 1-RTT keys, or retain up to 3× PTO for reordered packets
- **On discard:** Clear `sent_packets` for that space, remove from `bytes_in_flight`, reset `pto_count`, reset loss timer (RFC 9002 Appendix A.11)

### Key Update (RFC 9001 §6)

- **Initiation:** Use label `"quic ku"` via HKDF-Expand-Label. MUST NOT initiate before handshake confirmed. MUST NOT initiate next update without ACK for packet sent with current key phase.
- **Detection:** Changed Key Phase bit in received packet header
- **Timing:** MUST NOT generate new keys during packet processing (timing side-channel). Defer next receive key generation up to PTO after update.
- **Header protection keys DO NOT update** — stay same for connection lifetime
- **Old keys:** Retain old read keys ≤3× PTO after receiving new-key packet. Distinguish previous/current/next using packet numbers.

### AEAD Usage Limits (RFC 9001 §6.6)

Track encrypted packets per key set and failed decryption attempts per connection:

| Cipher Suite | Confidentiality Limit | Integrity Limit |
|---|---|---|
| AES-128-GCM / AES-256-GCM | 2^23 packets per key | 2^52 failed decryptions |
| ChaCha20-Poly1305 | No practical limit | 2^36 failed decryptions |

MUST initiate key update before exceeding confidentiality limit. If key update not possible → close with `AEAD_LIMIT_REACHED`. Track `failed_decryptions: u64` per connection.

### Retry Integrity Tag (RFC 9001 §5.8)

Retry packets carry an integrity tag computed with a fixed AES-128-GCM key:

- **Key (v1):** `0xbe0c690b9f66575a1d766b54e368c84e`
- **Nonce (v1):** `0x461599d35d632bf2239825bb`
- **AAD:** Retry Pseudo-Packet = ODCID length + ODCID + Retry header + token (no tag)
- Server computes tag on send. Client verifies on receive — reject if invalid.

### TLS Error Mapping (RFC 9001 §4.8)

TLS alerts map to QUIC transport errors: `error_code = AlertDescription + 0x0100` (range 0x0100-0x01ff). ALL TLS alerts are fatal in QUIC (even "warning" level). CONNECTION_CLOSE type MUST be 0x1c for handshake errors.

### Zero-Copy Constraint

All encrypt/decrypt operates in-place on XDP frame buffers. No intermediate allocations. AEAD tag appended/verified in-place.

**Safety invariant:** `Rc<UnsafeCell<QuicHandler>>` in socket types follows the same single-threaded interior mutability pattern as TCP. No re-entrant borrows — the `LocalRuntime` event loop ensures exclusive access at each phase.

## Transport Layer

### Packet Types

QUIC has four data packet types plus two special packets:

```rust
pub enum PacketType {
    Initial,        // connection setup (packet number space: Initial)
    Handshake,      // handshake completion (packet number space: Handshake)
    ZeroRtt,        // early data (packet number space: Application)
    OneRtt,         // application data, short header (packet number space: Application)
}

// Special packets (not encrypted, no packet number)
pub enum SpecialPacket {
    Retry,            // address validation (RFC 9000 §8.1.2)
    VersionNegotiation, // version mismatch response (RFC 9000 §6)
}

pub struct PacketHeader {
    packet_type: PacketType,
    version: u32,                // 0x00000001 for QUIC v1
    dcid: ConnectionIdRef<'_>,   // borrows from frame buffer — no allocation
    scid: ConnectionIdRef<'_>,   // long header only
    packet_number: u64,          // reconstructed full PN
    payload_offset: usize,
    payload_len: usize,
}
```

`ConnectionIdRef<'_>` borrows directly from the frame buffer for zero-copy CID routing lookups.

### Packet Number Encoding/Decoding (RFC 9000 §17.1)

Packet numbers are variable-length encoded (1-4 bytes). The receiver reconstructs the full 62-bit PN from the truncated value using the largest acknowledged PN as reference:

```rust
/// Decode truncated packet number to full value
fn decode_packet_number(largest_acked: u64, truncated: u64, nbits: u32) -> u64;

/// Encode packet number, choosing minimal byte length
fn encode_packet_number(full_pn: u64, largest_acked: u64) -> (u64, u8); // (truncated, num_bytes)
```

Per-space tracking prevents reuse. Connection MUST close (without CONNECTION_CLOSE) if 2^62-1 is reached.

### Packet Coalescing (RFC 9000 §12.2)

Multiple QUIC packets can be coalesced into a single UDP datagram. This is the normal case during handshake (Initial + Handshake in one datagram).

**Sending:** Coalesce in order of increasing encryption level: Initial → 0-RTT → Handshake → 1-RTT. Short-header (1-RTT) packet MUST be last.

**Receiving:** Parse multiple packets from a single datagram. All coalesced packets MUST share the same DCID as the first packet — discard subsequent packets with different DCIDs. Process each packet independently through decrypt → frame dispatch.

### Datagram Size (RFC 9000 §14)

- Client MUST pad Initial datagrams to ≥1200 bytes
- Server MUST discard Initial in datagram <1200 bytes
- Server MUST pad ack-eliciting Initial responses to ≥1200 bytes
- IPv4: DF bit MUST be set (no IP fragmentation)
- DPLPMTUD/PMTUD integration for path MTU discovery (RFC 9000 §14.3-14.4)

### Frame Types (RFC 9000 §19 — Complete)

```rust
pub enum QuicFrame<'a> {
    // §19.1
    Padding,
    // §19.2
    Ping,
    // §19.3 (type 0x02 without ECN, 0x03 with ECN counts)
    Ack(AckFrame<'a>),
    // §19.4
    ResetStream(ResetStreamFrame),
    // §19.5
    StopSending(StopSendingFrame),
    // §19.6
    Crypto(CryptoFrame<'a>),
    // §19.7
    NewToken(NewTokenFrame<'a>),
    // §19.8
    Stream(StreamFrame<'a>),
    // §19.9
    MaxData(u64),
    // §19.10
    MaxStreamData(MaxStreamDataFrame),
    // §19.11 (type 0x12 bidi, 0x13 uni)
    MaxStreams(MaxStreamsFrame),
    // §19.12
    DataBlocked(u64),
    // §19.13
    StreamDataBlocked(StreamDataBlockedFrame),
    // §19.14 (type 0x16 bidi, 0x17 uni)
    StreamsBlocked(StreamsBlockedFrame),
    // §19.15
    NewConnectionId(NewConnectionIdFrame<'a>),
    // §19.16
    RetireConnectionId(RetireConnectionIdFrame),
    // §19.17
    PathChallenge(PathChallengeFrame),
    // §19.18
    PathResponse(PathResponseFrame),
    // §19.19 (type 0x1c application, 0x1d QUIC layer)
    ConnectionClose(ConnectionCloseFrame<'a>),
    // §19.20
    HandshakeDone,
}

/// ACK frame with optional ECN counts (RFC 9000 §19.3, §13.4)
pub struct AckFrame<'a> {
    largest_acked: u64,
    ack_delay: u64,
    ranges: &'a [u8],         // borrowed range encoding from frame buffer
    ecn_counts: Option<EcnCounts>,  // present if frame type 0x03
}

pub struct EcnCounts {
    ect0: u64,
    ect1: u64,
    ecn_ce: u64,
}

pub struct PathChallengeFrame {
    data: [u8; 8],  // opaque, echoed in PathResponse
}

pub struct PathResponseFrame {
    data: [u8; 8],  // must match PathChallenge
}

pub struct StreamsBlockedFrame {
    max_streams: u64,
    direction: Direction,  // Bidi or Uni
}
```

Named `QuicFrame` to avoid collision with XDP `Frame`. All data-carrying variants borrow from the packet buffer — `StreamFrame<'a>` points directly at payload bytes in the XDP frame.

### ACK Generation (RFC 9000 §13.2)

- Every ack-eliciting packet SHOULD be acknowledged at least once
- Initial and Handshake ack-eliciting packets MUST be acknowledged immediately
- Application-data ack-eliciting packets acknowledged within `max_ack_delay`
- ACK frames MUST be in the same packet number space as the packet being acknowledged
- 0-RTT packets are acknowledged by 1-RTT ACK frames (both use Application space)
- MUST NOT send more than one ACK-only packet in response to an ack-eliciting packet

### Frame-Level Retransmission (RFC 9000 §13.3)

QUIC does NOT retransmit lost packets whole. Instead, the *information* in lost frames is re-sent in new packets:

- Lost CRYPTO frames → re-send CRYPTO data in new packet
- Lost STREAM frames → re-send stream data from send buffer
- Lost ACK frames → regenerate from current ACK state
- Lost flow control frames (MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS) → re-send current values
- Lost NEW_CONNECTION_ID → re-send

`SentPacket::frames` tracks which frames were in each packet so the right information can be re-sent on loss.

### Loss Detection (RFC 9002)

#### Constants (RFC 9002 §6, Appendix A.2, B.1)

```rust
// Loss detection
const K_PACKET_THRESHOLD: u32 = 3;           // packets before loss declaration
const K_TIME_THRESHOLD: f64 = 9.0 / 8.0;     // RTT multiplier for time-based loss
const K_GRANULARITY: Duration = Duration::from_millis(1);  // timer granularity floor
const K_INITIAL_RTT: Duration = Duration::from_millis(333); // before first sample

// Congestion control
const K_INITIAL_WINDOW_PACKETS: usize = 10;  // min(10*mds, max(14720, 2*mds))
const K_MINIMUM_WINDOW_PACKETS: usize = 2;   // 2 * max_datagram_size
const K_LOSS_REDUCTION_FACTOR: f64 = 0.5;    // ssthresh = cwnd * 0.5
const K_PERSISTENT_CONGESTION_THRESHOLD: u32 = 3;  // PTO multiplier
```

#### State (RFC 9002 Appendix A.3)

```rust
pub struct LossDetector {
    spaces: [PacketNumberSpace; 3],  // Initial, Handshake, Application
    // Per-space packet number counters (MUST NOT reuse)
    next_pn: [u64; 3],

    // RTT estimation
    latest_rtt: Duration,
    smoothed_rtt: Duration,
    rttvar: Duration,
    min_rtt: Duration,
    first_rtt_sample: Option<Instant>,  // gates persistent congestion

    // PTO
    pto_count: u32,
    time_of_last_ack_eliciting_pkt: [Option<Instant>; 3],  // per space

    // Handshake state (affects PTO behavior)
    handshake_confirmed: bool,
    peer_completed_address_validation: bool,
}

pub struct PacketNumberSpace {
    largest_acked: Option<u64>,
    sent_packets: BTreeMap<u64, SentPacket>,
    loss_time: Option<Instant>,         // earliest time-threshold loss eligible
    ack_eliciting_in_flight: u32,
    // ECN tracking per space
    ecn_ce_counter: u64,
}

pub struct SentPacket {
    time_sent: Instant,
    size: u16,
    ack_eliciting: bool,
    in_flight: bool,                     // counted in bytes_in_flight
    frames: SmallVec<[SentFrame; 4]>,    // for frame-level retransmission
}
```

#### PTO Computation (RFC 9002 §6.2.1)

```
PTO = smoothed_rtt + max(4 * rttvar, K_GRANULARITY) + max_ack_delay
```

- `max_ack_delay` = 0 for Initial/Handshake spaces (no delayed ACK before handshake)
- `max_ack_delay` = peer's `max_ack_delay` transport parameter for Application space
- Backoff: `PTO * 2^pto_count` on each expiry
- Client does NOT reset `pto_count` on Initial ACKs while server hasn't validated address
- Application data PTO MUST NOT be set until handshake confirmed

#### PTO Expiry Behavior (RFC 9002 §6.2.4)

- MUST send ≥1 ack-eliciting packet (probe)
- MAY send up to 2 full-sized datagrams
- SHOULD coalesce across packet number spaces
- MAY skip packet number to elicit faster ACK
- Anti-deadlock (§6.2.2.1): Server MUST NOT arm PTO when at amplification limit. Client MUST arm PTO even with 0 in-flight if handshake not confirmed.

#### Loss Declaration (RFC 9002 §6.1)

Two thresholds, both checked:
1. **Packet threshold:** Packet is lost if `K_PACKET_THRESHOLD` (3) later packets have been acknowledged
2. **Time threshold:** Packet is lost if `K_TIME_THRESHOLD * max(smoothed_rtt, latest_rtt)` has elapsed since sent

`loss_time` per space tracks when the next time-threshold loss can be declared — used to set the loss detection timer.

#### Persistent Congestion (RFC 9002 §7.6)

Detected when two ack-eliciting packets span a duration exceeding:
```
(smoothed_rtt + max(4*rttvar, K_GRANULARITY) + max_ack_delay) * K_PERSISTENT_CONGESTION_THRESHOLD
```

Requirements:
- MUST NOT establish before `first_rtt_sample` exists
- Both packets must be ack-eliciting
- None of the packets sent between them may be acknowledged
- On persistent congestion: `congestion_window = K_MINIMUM_WINDOW`

#### Packet Space Discard (RFC 9002 Appendix A.11)

When Initial/Handshake keys discarded or 0-RTT rejected:
- Clear `sent_packets` for that space
- Remove all those packets from `bytes_in_flight`
- Reset `pto_count = 0`
- Reset loss detection timer

#### Retry Handling (RFC 9002 §6.3)

Client receiving Retry resets:
- `congestion_window = K_INITIAL_WINDOW`
- `ssthresh = infinity`
- `bytes_in_flight = 0`
- `pto_count = 0`
- Clears `sent_packets` (marks as no longer in-flight)
- Does NOT reset RTT estimates

### Congestion Control — Pluggable Trait

```rust
// src/net/congestion/mod.rs
pub trait CongestionController {
    fn on_packets_sent(&mut self, bytes: usize, now: Instant);
    fn on_ack(&mut self, acked_bytes: usize, rtt: Duration, min_rtt: Duration, now: Instant);
    fn on_congestion_event(&mut self, lost_bytes: usize, now: Instant);
    fn on_ecn_ce(&mut self, now: Instant);  // ECN Congestion Experienced
    fn window(&self) -> usize;
    fn bytes_in_flight(&self) -> usize;
    fn can_send(&self) -> bool;
    fn on_mtu_update(&mut self, new_mtu: usize);
    /// Reset for path migration (RFC 9000 §9.4)
    fn reset(&mut self);
}
```

QUIC gets its own `QuicCubic` struct implementing this trait. TCP keeps its existing `CubicState` unchanged. Shared trait extraction happens later once both implementations are stable. Monomorphized via `QuicConnectionState<C: CongestionController>`.

### Congestion Window Algorithms (RFC 9002 §7, Appendix B)

**Initial window:** `min(10 * max_datagram_size, max(14720, 2 * max_datagram_size))`

**Slow start (cwnd < ssthresh):**
```
congestion_window += acked_bytes
```

**Congestion avoidance (cwnd ≥ ssthresh):**
```
congestion_window += max_datagram_size * acked_bytes / congestion_window
```

**On congestion event (loss or ECN-CE):**
```
ssthresh = congestion_window * K_LOSS_REDUCTION_FACTOR  // 0.5
congestion_window = max(ssthresh, K_MINIMUM_WINDOW)
congestion_recovery_start_time = now
```

Only one congestion event per recovery period — ignore subsequent losses/ECN within the same recovery period (packets sent before `congestion_recovery_start_time`).

**On persistent congestion:** `congestion_window = K_MINIMUM_WINDOW` (no ssthresh change).

**PMTU probes:** Loss of PMTU probe packets MUST NOT trigger congestion control reaction.

### Pacing (RFC 9002 §7.7)

MUST either pace or limit bursts to initial congestion window:

```
rate = N * congestion_window / smoothed_rtt    // N ≥ 1, recommended 1.25
interval = smoothed_rtt * packet_size / (N * congestion_window)
```

- ACK-only packets SHOULD NOT be paced
- Burst limit without pacing: `K_INITIAL_WINDOW` bytes
- Implementation: timer-based or token-bucket

### Application-Limited Behavior (RFC 9002 §7.8)

SHOULD NOT increase congestion window when application is not sending enough to fill it:

- Underutilized when `bytes_in_flight < congestion_window` and not pacing-limited
- Paced sender SHOULD NOT consider itself app-limited if pacing delay is the constraint
- Track `app_limited: bool` per connection

### ECN Support (RFC 9000 §13.4, RFC 9002 §8, Appendix A.4)

**Validation algorithm:**
1. During handshake, send packets marked with ECT(0)
2. Track `ecn_ce_counter` per packet number space
3. On ACK with ECN counts: if `ack.ecn_ce > ecn_ce_counter`, signal `on_ecn_ce()` to congestion controller
4. ECN validation: if ECT(0)-marked packets not reported correctly (e.g., CE decrease or all marks stripped), disable ECN for this path
5. Re-validate ECN on path migration

**Per-space tracking:**
```rust
pub struct EcnState {
    capable: bool,              // ECN validated for this path
    ect0_sent: u64,             // packets sent with ECT(0) mark
    ce_counter: u64,            // last known CE count from peer's ACK
    validation_pending: bool,   // waiting for ACK of ECT-marked packet
}
```

### Connection-Level Flow Control (RFC 9000 §4)

```rust
pub struct FlowControl {
    // Sending
    max_data_send: u64,         // peer's MAX_DATA limit
    data_sent: u64,
    blocked_at: Option<u64>,    // send DATA_BLOCKED when blocked

    // Receiving
    max_data_recv: u64,         // our limit, advertised via MAX_DATA
    data_received: u64,
    auto_tune_rtt: Option<Duration>,  // for BDP-based autotuning
}
```

**Final size accounting (RFC 9000 §4.5):** When a stream enters a terminal state (DataRecvd, ResetRecvd), its final byte count MUST be accounted against the connection-level flow control budget. A RESET_STREAM frame declares the final size — the bytes count against flow control even though the data isn't delivered.

### Transport Parameters (RFC 9000 §18)

Negotiated during handshake via TLS extension. Both endpoints send their parameters:

```rust
pub struct TransportParams {
    // Connection limits
    max_idle_timeout: Duration,          // §18.2 — negotiated as min of both
    max_udp_payload_size: u16,           // §18.2 — default 65527
    active_connection_id_limit: u64,     // §18.2 — default 2

    // Flow control initial values
    initial_max_data: u64,               // connection-level
    initial_max_stream_data_bidi_local: u64,
    initial_max_stream_data_bidi_remote: u64,
    initial_max_stream_data_uni: u64,
    initial_max_streams_bidi: u64,
    initial_max_streams_uni: u64,

    // Features
    max_ack_delay: Duration,             // default 25ms
    ack_delay_exponent: u8,              // default 3
    disable_active_migration: bool,

    // CID authentication (RFC 9000 §7.3)
    initial_source_connection_id: Option<ConnectionId>,
    original_destination_connection_id: Option<ConnectionId>,  // server only
    retry_source_connection_id: Option<ConnectionId>,          // server only, if Retry sent

    // Tokens
    stateless_reset_token: Option<[u8; 16]>,  // server only, for initial CID
    preferred_address: Option<PreferredAddress>,  // server only (RFC 9000 §9.6)
}
```

## Path Management (RFC 9000 §8, §9)

### Address Validation & Anti-Amplification (RFC 9000 §8)

**Anti-amplification (CRITICAL):** Before address is validated, endpoint MUST NOT send more than 3× bytes received from that address. Tracked per-connection during handshake:

```rust
pub struct AmplificationLimit {
    bytes_received: usize,
    bytes_sent: usize,
    validated: bool,  // address validated → limit removed
}
```

Validation completes when: handshake is confirmed, or a valid Retry token was processed, or PATH_RESPONSE matches a PATH_CHALLENGE we sent.

### Retry Tokens (RFC 9000 §8.1.2)

Server can respond to Initial with a Retry packet for cheap address validation before expensive crypto:

```rust
pub struct RetryToken {
    // Integrity-protected (HMAC or AEAD), contains:
    original_dcid: ConnectionId,
    client_addr: SocketAddr,
    timestamp: Instant,          // for expiration
}
```

Token is opaque to client — included in subsequent Initial packet. Server validates token, extracts original DCID for transport parameter authentication.

### NEW_TOKEN Tokens (RFC 9000 §8.1.3)

Server issues tokens via NEW_TOKEN frame for future connections (enables 0-RTT address validation). Client stores per server_name, presents in future Initial packets. Tokens expire — server validates timestamp.

### Path Validation (RFC 9000 §8.2, §9)

```rust
pub struct PathState {
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
    validated: bool,
    challenge_pending: Option<[u8; 8]>,  // awaiting PATH_RESPONSE
    challenge_sent_at: Option<Instant>,
    amplification: AmplificationLimit,
    // Per-path congestion state (reset on migration, §9.4)
    // Per-path ECN validation state
}
```

**Migration response (RFC 9000 §9.3):**
- On receiving packet from new address: apply anti-amplification limit, initiate path validation
- If validation fails: revert to last validated address
- CID rotation: MUST use different CID on different paths to prevent linkability (§9.5)

### Scope: Connection Migration

Connection migration (client changes address) is supported via CID routing and path validation. Server preferred address (§9.6) is deferred to a future revision — the transport parameter is parsed but not acted upon.

## Error Handling (RFC 9000 §11, §20)

### Transport Error Codes

```rust
pub enum TransportError {
    NoError = 0x00,
    InternalError = 0x01,
    ConnectionRefused = 0x02,
    FlowControlError = 0x03,
    StreamLimitError = 0x04,
    StreamStateError = 0x05,
    FinalSizeError = 0x06,
    FrameEncodingError = 0x07,
    TransportParameterError = 0x08,
    ConnectionIdLimitError = 0x09,
    ProtocolViolation = 0x0a,
    InvalidToken = 0x0b,
    ApplicationError = 0x0c,
    CryptoBufferExceeded = 0x0d,
    KeyUpdateError = 0x0e,
    AeadLimitReached = 0x0f,
    NoViablePath = 0x10,
    // 0x0100-0x01ff: crypto errors (TLS alert mapped)
}
```

**Connection errors** → send CONNECTION_CLOSE frame (type 0x1c for QUIC-level, 0x1d for application-level), enter Closing state.

**Stream errors** → send RESET_STREAM or STOP_SENDING frames. Do NOT close the connection.

**Handshake errors:** Before handshake confirmation, CONNECTION_CLOSE in Initial/Handshake packets MUST use type 0x1c (not 0x1d). Send in both Handshake and 1-RTT if possible (RFC 9000 §10.2.3).

Errors propagated to socket layer via `QuicEvent::ConnectionError` and `QuicEvent::StreamReset`.

## Version Negotiation (RFC 9000 §6, RFC 8999)

### RFC 8999 Invariants (MUST hold across all QUIC versions)

- Long header: form bit = 1, version field (32 bits), DCID length + DCID, SCID length + SCID
- Short header: form bit = 0, no version field, no CID length prefix
- Version `0x00000000` reserved exclusively for Version Negotiation packets
- VN packets: echo both CIDs (DCID ← receiver's SCID, SCID ← receiver's DCID), no integrity protection

### Version-Aware Packet Parsing

Packet type bits (byte 0, bits [7:6] for long headers) are **version-specific** per RFC 8999. The parser MUST read the version field before interpreting packet type bits:

```rust
fn parse_long_header(buf: &[u8]) -> Result<PacketHeader> {
    let version = u32::from_be_bytes(buf[1..5]);
    let packet_type = match version {
        0x00000001 => decode_v1_packet_type(buf[0]),
        0x6b3343cf => decode_v2_packet_type(buf[0]),  // future
        0x00000000 => return Ok(VersionNegotiation),
        _ => return Err(UnknownVersion(version)),
    };
    // ...
}
```

This ensures v2 can be added by extending the match arm without restructuring the parser.

### Negotiation Logic

- Server responds with Version Negotiation packet if client's version is unacceptable
- Client discards Version Negotiation if it has already successfully processed any other packet on this connection (prevents downgrade, RFC 9000 §6.2)
- Reserved versions matching pattern `0x?a?a?a?a` used for testing version negotiation
- Initial implementation targets QUIC v1 (`0x00000001`) only. VN packet generation/handling is required for interop.

## Stateless Reset (RFC 9000 §10.3)

- 16-byte stateless reset tokens, issued via NEW_CONNECTION_ID frame or `stateless_reset_token` transport parameter
- Tokens MUST be unpredictable (derived from CID via HMAC with server secret)
- Invalidated when associated CID is retired
- Used to recover from lost connection state (server restart, etc.)
- Detection: packet that fails decryption → check last 16 bytes against known tokens

## Stream Layer

### Stream ID Encoding (RFC 9000 §2.1)

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

    // Track opened count to validate incoming stream IDs don't exceed limits
    peer_opened_bidi: u64,
    peer_opened_uni: u64,

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

**Vec growth bound:** `MAX_STREAMS` transport parameters limit how many streams a peer can open. The Vec size is bounded by `peer_max_bidi` / `peer_max_uni` — a peer that tries to open a stream ID beyond its limit gets a `STREAM_LIMIT_ERROR`.

### Stream State Machine (RFC 9000 §3 — Complete)

```rust
pub enum StreamState {
    Bidi { send: SendHalf, recv: RecvHalf },
    SendOnly { send: SendHalf },
    RecvOnly { recv: RecvHalf },
}

/// RFC 9000 §3.1 — Sending states
pub enum SendState {
    Ready,       // created, no data sent
    Send,        // actively sending
    DataSent,    // all data sent (FIN), awaiting ACKs
    DataRecvd,   // all data ACKed — terminal
    ResetSent,   // RESET_STREAM sent, awaiting ACK
    ResetRecvd,  // RESET_STREAM ACKed — terminal
}

/// RFC 9000 §3.2 — Receiving states
pub enum RecvState {
    Recv,        // accepting data, final size unknown
    SizeKnown,   // got FIN, know total size, may still have gaps
    DataRecvd,   // all data received contiguously — ready for app
    DataRead,    // application consumed all data — terminal
    ResetRecvd,  // got RESET_STREAM — terminal
}
```

**Transition validation:** State machine enforces valid transitions. Cannot send on `ResetSent`/`ResetRecvd` stream. Cannot receive after `DataRead`. STOP_SENDING triggers RESET_STREAM in response. Bidi stream halves transition independently (RFC 9000 §3.4).

**Half-closed flow control (RFC 9000 §4.4):** When one direction of a bidi stream is reset, the other direction's flow control state MUST be maintained until that direction also reaches a terminal state.

### Send/Recv Halves — Cache-Line Optimized

```rust
#[repr(C)]
pub struct RecvHalf {
    // Hot — touched every incoming StreamFrame
    received: u64,              // contiguous data frontier
    max_stream_data: u64,       // our flow control limit for this stream
    final_size: Option<u64>,    // set when FIN or RESET_STREAM received
    state: RecvState,
    fin_received: bool,

    // Buffer — slim version without wakers (wakers live in socket layer)
    buffer: StreamRingBuffer,

    // Cold — only on OOO or app read
    ooo: OooRanges,
}

#[repr(C)]
pub struct SendHalf {
    // Hot — touched every outgoing write
    sent: u64,                  // total bytes sent (for flow control)
    acked: u64,                 // total bytes ACKed (for buffer release)
    max_stream_data: u64,       // peer's limit for this stream
    state: SendState,
    fin_sent: bool,
    blocked_at: Option<u64>,    // send STREAM_DATA_BLOCKED when blocked

    // Buffer
    buffer: StreamRingBuffer,
}
```

**`StreamRingBuffer` vs TCP's `RingBuffer`:** TCP's `RingBuffer` embeds `Option<Waker>` fields (`read_waker`, `write_waker`). QUIC stream wakers live in the socket layer (same as TCP sockets), NOT in the buffer. `StreamRingBuffer` is a slim version: just `Vec<u8>` + head + tail + mask. No waker duplication.

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

KV store workload = millions of short-lived streams. Pool stream objects per-connection to avoid allocator pressure:

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

Ring buffer backing memory survives recycling — only head/tail/state/counters reset.

## Connection State

```rust
#[repr(C)]
pub struct QuicConnectionState {
    // Hot — every packet
    dcid: ConnectionId,
    keys: PacketKeys,
    loss: LossDetector,
    congestion: QuicCubic,
    flow: FlowControl,

    // Warm — most packets
    streams: StreamMap,
    stream_pool: StreamPool,

    // Path state
    path: PathState,

    // Connection management
    scid_set: SmallVec<[ConnectionId; 4]>,
    dcid_seq: u64,
    state: ConnectionState,
    side: Side,

    // Transport parameters (negotiated)
    local_params: TransportParams,
    peer_params: TransportParams,

    // Handshake
    crypto: CryptoState,

    // AEAD limits (RFC 9001 §6.6)
    packets_encrypted: u64,       // per current key set — trigger key update before limit
    failed_decryptions: u64,      // per connection lifetime — close if integrity limit hit

    // ECN
    ecn: EcnState,

    // Pacing
    pacing_rate: u64,             // bytes/sec, derived from cwnd/srtt
    next_send_time: Option<Instant>,

    // Config / cold
    idle_timeout: Duration,
    max_udp_payload: u16,
    events: LocalQueue<QuicEvent>,
}

pub enum ConnectionState {
    Handshaking,
    HandshakeComplete,  // TLS done but not yet confirmed (RFC 9001 §4.1.1)
    Established,        // handshake confirmed (RFC 9001 §4.1.2) — full operation
    Draining,           // received CONNECTION_CLOSE; MUST NOT send any packets
    Closing,            // sent CONNECTION_CLOSE; may re-send on incoming packets
    Closed,
}
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
4. Not found + Initial → check listeners → validate datagram ≥1200 bytes → new connection (with anti-amplification)
5. Not found + valid stateless reset token in last 16 bytes → handle reset
6. Not found + other → drop
7. **Coalescing:** Parse remaining bytes in datagram for additional packets (same DCID required)
8. Decrypt in-place with appropriate packet space keys
9. Parse `QuicFrame`s, dispatch to connection state machine

### Connection Lifecycle

**Client connect:** Generate unpredictable DCID ≥8 bytes → derive Initial keys → send Initial (padded to ≥1200 bytes) with CRYPTO (ClientHello) → Handshaking

**Server accept:** Receive Initial → validate datagram size → optionally send Retry for address validation → derive Initial keys from DCID → decrypt → feed CRYPTO to rustls → authenticate CID via transport parameters → Handshaking

**Handshake complete:** 1-RTT keys installed → server sends HANDSHAKE_DONE → Established → discard Initial/Handshake keys → notify socket layer via `LocalQueue<QuicEvent>`

**Idle timeout (RFC 9000 §10.1):** Negotiated as `min(local, peer)` from transport parameters. Must be ≥3× current PTO. Reset on receiving any processed packet or sending ack-eliciting packet.

**Shutdown:** Send CONNECTION_CLOSE → Closing → timer ≥3× PTO → Closed → return streams to pool → remove CIDs from `cid_map` → release slab slot. If CONNECTION_CLOSE received while Closing → transition to Draining (MUST NOT send).

## Packet Building

Outbound packets follow the `SegmentBuilder` pattern from TCP — write directly into TX frame buffers:

```rust
pub struct PacketBuilder<'a> {
    frame: &'a mut Frame,
    offset: usize,
    packet_type: PacketType,
    // Tracks frames written for loss detection
    frames: SmallVec<[SentFrame; 4]>,
}

impl<'a> PacketBuilder<'a> {
    /// Reserve space for header (long or short) + AEAD tag
    fn begin(frame: &'a mut Frame, ptype: PacketType, cid: &ConnectionId) -> Self;

    /// Write frames into the packet
    fn write_crypto(&mut self, data: &[u8], offset: u64) -> usize;
    fn write_stream(&mut self, id: StreamId, data: &[u8], offset: u64, fin: bool) -> usize;
    fn write_ack(&mut self, ranges: &AckRanges, ecn: Option<&EcnCounts>);
    fn write_max_data(&mut self, max: u64);
    fn write_max_stream_data(&mut self, id: StreamId, max: u64);
    // ... etc for all frame types

    /// Pad to minimum size if needed (Initial ≥1200 bytes)
    fn pad_to(&mut self, min_size: usize);

    /// Finalize: encode packet number, encrypt payload, apply header protection
    fn finish(self, keys: &DirectionalKey) -> SentPacket;
}
```

**Coalescing on TX:** For handshake, build Initial packet then append Handshake packet in the same datagram frame. 1-RTT (short header) always last.

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
    ConnectionError(TransportError),
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
- **Cache-line aware** layout — hot scalars before buffer pointers in `RecvHalf`/`SendHalf`.
- **Direct index** stream lookup via `StreamId >> 2` — no hashing.
- **Monomorphized** congestion control via generics.
- **`StreamRingBuffer`** — slim ring buffer without embedded wakers (avoids duplication with socket-layer wakers).

## Testing Strategy

- **Crypto layer:** Test against known test vectors (RFC 9001 Appendix A). Verify handshake with rustls client↔server.
- **Transport layer:** Unit tests per component — packet encoding/decoding, frame parsing, loss detection state machine, PN reconstruction. Use existing test harness patterns.
- **Stream layer:** State machine transition tests (all valid/invalid transitions per RFC 9000 §3). Flow control limit enforcement. OOO reassembly.
- **Integration:** Full handshake test through the handler chain. Multi-stream data transfer. 0-RTT flow. Connection migration. Reuse existing `LocalRuntime` test infrastructure.
- **Interop:** Test against quinn/s2n-quic clients to verify wire compatibility.

## Implementation Order

1. **Transport parameters + error codes** — foundational types used everywhere
2. **Crypto layer** — rustls integration, packet protection, CRYPTO frame reassembly
3. **Transport layer** — packet parsing/building, frame codec, packet number encoding
4. **Loss detection + congestion** — QuicCubic standalone, loss detector
5. **Stream layer** — state machine, flow control, stream buffers
6. **Handler integration** — QuicHandler, dispatch chain changes, timer integration
7. **Socket API** — QuicListener, QuicConnection, QuicStream
8. **Path management** — address validation, Retry, path validation, migration
9. **Advanced** — 0-RTT, ECN, DPLPMTUD, stateless reset
10. **Congestion refactoring** — extract shared trait from TCP + QUIC (only after both stable)

## Key RFCs

- **RFC 9000** — QUIC Transport Protocol
- **RFC 9001** — Using TLS to Secure QUIC
- **RFC 9002** — QUIC Loss Detection and Congestion Control
- **RFC 9369** — QUIC Version 2 (future consideration)

## Deferred / Out of Scope

- **Server preferred address (RFC 9000 §9.6):** Transport parameter parsed but not acted upon. Future work.
- **Shared congestion control extraction:** QUIC gets standalone `QuicCubic`. TCP keeps existing `CubicState`. Shared trait extraction deferred until both are stable to avoid regressing TCP's 1107 passing tests.
- **DATAGRAM extension (RFC 9221):** Unreliable datagrams over QUIC. Not needed for KV store. Can be added later.

### QUIC Version 2 Compatibility (RFC 9369)

Design is v1-only but architecturally compatible with v2. Assessment:

**Constant swaps only (<100 LOC):**
- Initial salt: v1 `0x38762cf7...` → v2 `0x0dede3def7...`
- HKDF labels: `"quic key"` → `"quicv2 key"`, etc.
- Retry integrity key/nonce (different fixed values)

**Moderate changes (300-500 LOC):**
- Packet type bit interpretation is version-specific (v1: Initial=0b00, v2: Initial=0b01). Parser is already version-aware (see Version Negotiation section).
- Compatible negotiation (RFC 9368): dual-version state during handshake — `original_version` + `negotiated_version` tracked in `QuicConnectionState`. Server keeps original-version Initial receive keys until processing negotiated-version Handshake.
- `version_information` transport parameter (RFC 9368) added to `TransportParams`.

**No architectural changes required.** The version is threaded through `CryptoState` for constant selection and through the packet parser for type bit interpretation. Adding v2 is a feature addition, not a restructure.
