# QUIC Server-Side State Machine Design

**Date:** 2026-03-20
**Status:** Draft
**Depends on:** `docs/superpowers/specs/2026-03-20-quic-rustls-design.md` (rev 4)
**Scope:** Server-only. Client `connect()` deferred to a future spec.

## Goal

Wire all existing QUIC building blocks into a working server-side protocol engine. A quinn client should be able to connect, complete TLS 1.3 handshake, and exchange stream data with a VoidNet QUIC server.

## Phases

### Phase A: Fix 8 RFC FAIL items

Targeted corrections to existing algorithms before building on top of them:

1. **loss.rs** — `update_rtt()`: only clamp `ack_delay` to `max_ack_delay` when `handshake_confirmed` is true. Pass `handshake_confirmed` as parameter.
2. **congestion.rs** — `on_congestion_event()`: accept `sent_time: Instant` parameter. Check `sent_time <= congestion_recovery_start_time` instead of boolean flag. Remove `in_congestion_recovery` field.
3. **congestion.rs** — `on_ack()`: accept `in_flight: bool` parameter. Return early if `!in_flight`.
4. **congestion.rs** — `on_congestion_event()`: store `congestion_recovery_start_time = now`. The `on_ack` method checks if the acked packet was sent after recovery start to clear recovery.
5. **congestion.rs** — `in_persistent_congestion()`: ensure the PTO passed always includes `max_ack_delay` regardless of space.
6. **loss.rs** — `discard_space()`: reset `pto_count = 0` per RFC 9002 Appendix A.11.
7. **loss.rs** — Add `reset_min_rtt()` method. Called after persistent congestion established.
8. **wire/quic.rs** — `parse_long_header()`: accept CID lengths 0..255 for version-independent parsing. Keep the 20-byte limit as a separate validation step in the QUIC handler (v1-specific).

### Phase B: Server-Side State Machine

#### Architecture

```
handler.rs (routing layer — thin)
  ├── process_ipv4() → parse IP/UDP → extract QUIC payload → route to processor
  ├── process_ipv6() → same for IPv6
  ├── handle_timer() → look up connection → call processor
  └── poll_send() → iterate connections → call processor

processor.rs (per-connection protocol engine)
  ├── process_packet() → decrypt → parse frames → dispatch → queue responses
  ├── generate_packets() → build outgoing packets from pending state
  └── handle_timeout() → loss detection, idle, ACK timers
```

**Separation rationale:** `handler.rs` owns the connection table (`Slab` + `FxHashMap`). `processor.rs` operates on `&mut QuicConnectionState` — no borrow conflicts. Same pattern as TCP's handler vs inbound modules.

#### New Files

| File | Purpose |
|------|---------|
| `src/net/handler/quic/processor.rs` | Per-connection packet processing, frame dispatch, packet generation |
| `src/net/handler/quic/packet_parser.rs` | Initial packet token/length parsing, PN space mapping, duplicate PN detection |

#### Modified Files

| File | Change |
|------|--------|
| `handler.rs` | Wire `process_ipv4`/`ipv6`/`handle_timer`/`poll_send` to call processor |
| `connection.rs` | Add fields: `pending_crypto`, `pending_ack`, `pending_frames`, `frame_log`, `scid`, `local_port`, `remote_port`, address tracking |
| `wire/quic.rs` | CID length validation change (Phase A item 8) |

#### Inbound Packet Processing (`process_packet`)

```rust
pub fn process_packet(
    conn: &mut QuicConnectionState,
    quic_payload: &[u8],       // raw QUIC bytes (after UDP header)
    src_addr: IpAddress,
    now: coarsetime::Instant,
    free_frames: &mut impl FrameBuffer<'_>,
    tx_return: &mut impl FrameBuffer<'_>,
) -> ProcessResult
```

Steps:

1. **Parse outer header** — `parse_header()` from `wire/quic.rs`
2. **Determine packet space** — Initial=0, Handshake=1, 0-RTT/1-RTT=2
3. **Select keys** — `conn.keys.{initial,handshake,one_rtt}` remote key for decrypt. If keys not yet available for this space, drop packet.
4. **For long headers (Initial):** parse token + Length field using varint decoder to find PN offset. Use `packet_parser::parse_initial_fields()`.
5. **Decrypt:**
   - `unprotect_header()` → removes header protection, decodes truncated PN
   - `decode_pn(largest_acked, truncated, nbits)` → full PN
   - Check duplicate PN (new bitset tracker per space)
   - `decrypt_payload()` → plaintext
   - On failure: `conn.failed_decryptions += 1`, check AEAD integrity limit
6. **Parse frames** — loop `parse_frame()` over plaintext. For each frame:
   - Validate frame type is allowed in this packet space (RFC 9000 §12.4)
   - Track whether any ack-eliciting frame was seen
   - Dispatch to handler (see Frame Dispatch below)
7. **Post-processing:**
   - `conn.ack[space].on_packet_received(pn, now)`
   - If ack-eliciting: `conn.ack[space].set_ack_eliciting()`
   - Update idle timeout timer
   - `conn.path.amplification.on_bytes_received(datagram_len)`
   - Key discard: if handshake keys just installed → discard initial keys. If 1-RTT keys just installed → discard handshake keys.

#### Frame Dispatch

| Frame | Action |
|-------|--------|
| CRYPTO | Accumulate in `CryptoBuffer`. When contiguous data available, feed to `CryptoState.process_crypto_data()`. Install any new keys. Queue response CRYPTO data in `conn.pending_crypto[space]`. |
| ACK | `AckState::decode_ack_ranges()` → `LossDetector.on_ack_received()` → feed acked/lost to congestion controller → build retransmit queue for lost packets |
| STREAM | Validate stream ID direction. `StreamMap.get_or_create()`. `RecvHalf.receive()`. Update `FlowControl.on_data_received()`. Push `QuicEvent::StreamReadable`. |
| MAX_DATA | `FlowControl.update_max_data_send()` |
| MAX_STREAM_DATA | Update per-stream `SendHalf.max_stream_data` |
| MAX_STREAMS | Update `StreamMap.peer_max_bidi/uni` |
| CONNECTION_CLOSE | Transition to `ConnectionState::Draining`. Push `QuicEvent::ConnectionClosed`. |
| PATH_CHALLENGE | Queue `PATH_RESPONSE` with same 8 bytes in `conn.pending_frames` |
| HANDSHAKE_DONE | Transition to `Established` (client-side only, future) |
| PING | No action (implicitly ack-eliciting) |
| PADDING | No action |
| NEW_CONNECTION_ID | Process via `CidManager` |
| RETIRE_CONNECTION_ID | Remove CID from handler's `cid_map` (needs callback or deferred action) |

#### Outbound Packet Generation (`generate_packets`)

```rust
pub fn generate_packets<'umem>(
    conn: &mut QuicConnectionState,
    now: coarsetime::Instant,
    wheel: &mut TimerWheel,
    conn_key: usize,
    neighbor_handler: &NeighborHandler,
    free_frames: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
)
```

**Priority order for frame packing:**
1. CRYPTO data (handshake completion is highest priority)
2. ACKs for spaces that `needs_ack()`
3. Retransmit queue entries
4. HANDSHAKE_DONE (server, once after handshake confirmed)
5. Control frames: MAX_DATA, MAX_STREAM_DATA, PATH_RESPONSE
6. Stream data from `SendHalf` buffers
7. PING (for PTO probes)

**Gate checks before sending:**
- `conn.path.amplification.can_send(estimated_size)` — anti-amplification
- `conn.congestion.can_send()` — congestion window
- Pacing: if `conn.pacing.can_send(now)` is false, arm pacing timer and return

**Packet construction follows TCP's SegmentBuilder pattern:**
1. Pop a `Frame` from `free_frames`
2. Write Ethernet + IP + UDP headers using connection's address info + `NeighborHandler` for MAC resolution (same as TCP's `SegmentBuilder::build_*` methods)
3. Start QUIC payload with `PacketBuilder::begin_long()` or `begin_short()`
4. Write frames in priority order until packet full or nothing left
5. For Initial packets: `pad_to(1200)`
6. `PacketBuilder::finish()` writes Length field for long headers
7. `protect_packet()` encrypts in-place
8. Record in `LossDetector::on_packet_sent()`
9. Update `conn.path.amplification.on_bytes_sent()`, `conn.packets_encrypted += 1`
10. Push frame to `tx_return`

**Coalescing:** During handshake, build Initial packet, then if space remains in the same `Frame` buffer, build Handshake packet immediately after. Track the boundary so each packet is independently encrypted. 1-RTT (short header) always last.

**IPv4 + IPv6:** The connection stores `IpAddress` (enum with V4/V6 variants). Packet building dispatches on this — IPv4 gets a 20-byte header, IPv6 gets a 40-byte header. UDP header is the same for both. This mirrors how TCP's `SegmentBuilder` handles both protocols.

#### Timer Handling (`handle_timeout`)

```rust
pub fn handle_timeout(
    conn: &mut QuicConnectionState,
    kind: QuicTimerKind,
    now: coarsetime::Instant,
    wheel: &mut TimerWheel,
    conn_key: usize,
    // ... frame buffers for sending probes
) -> TimerResult
```

| Timer | Action |
|-------|--------|
| LossDetection | `conn.loss.on_loss_detection_timeout(now)` → if lost packets: retransmit. If PTO: send probe. Re-arm timer. |
| Idle | Return `TimerResult::Close` — handler removes connection |
| Ack | Generate ACK-only packet for pending space |
| Draining | Return `TimerResult::Close` — draining period elapsed |
| KeyDiscard | Drop `prev_remote_key` from `KeyUpdateState` |
| PathValidation | If timed out, revert to previous path |
| Handshake | If not complete, close with timeout error |

Timer arming: after `generate_packets()` or `handle_timeout()`, compute next deadline from `LossDetector.loss_detection_timer()` and re-arm via `wheel.arm(quic_timer_id(key, kind), deadline)`. Cancel stale timers first via `QuicTimerHandles`.

#### New Connection (Server)

When `process_ipv4` sees an Initial packet for an unknown DCID with a listener on that port:

1. Validate datagram ≥ 1200 bytes
2. Validate version supported (or send Version Negotiation)
3. `derive_initial_keys(client_dcid, Side::Server)` → install as `conn.keys.initial`
4. Generate random 8-byte SCID
5. Create `QuicConnectionState::new(...)` with `Side::Server`
6. `CryptoState::new_server(listener.tls_config, encoded_local_params)` → install in `conn.crypto`
7. `handler.insert_connection(conn)` → maps DCID + SCID
8. Process the Initial packet through normal `process_packet()` path
9. The CRYPTO frame processing produces ServerHello + handshake data
10. `generate_packets()` builds the Initial+Handshake response

#### Pending State on QuicConnectionState

New fields needed:

```rust
// Outbound CRYPTO data per space [Initial, Handshake, 1-RTT]
pub pending_crypto: [Vec<u8>; 3],
// Offset of next byte to send per space
pub crypto_offset: [u64; 3],
// Offset of next byte acked per space
pub crypto_acked: [u64; 3],

// Control frames queued for sending
pub pending_path_response: Option<[u8; 8]>,
pub send_handshake_done: bool,

// Per-connection frame log for loss tracking
pub frame_log: FrameLog,

// Duplicate PN detection per space
pub recv_pn_seen: [PnBitset; 3],

// Network addressing (for building response packets)
pub local_addr: IpAddress,
pub remote_addr: IpAddress,
pub local_port: u16,
pub remote_port: u16,
pub local_mac: MacAddress,
pub remote_mac: MacAddress,
```

`PnBitset` — simple duplicate PN tracker. A window of 256 bits around the largest received PN. Bit set = PN already seen. Shifts as largest advances.

```rust
pub struct PnBitset {
    bits: [u64; 4],  // 256 bits
    base: u64,       // lowest PN tracked
}
```

#### ProcessResult / TimerResult

```rust
pub enum ProcessResult {
    Ok,
    ConnectionClosed,
    VersionNegotiation,  // handler sends VN packet
    StatelessReset,      // handler sends reset
}

pub enum TimerResult {
    Ok,
    Close,  // handler should remove connection
}
```

### Phase C: Tests

**Unit test: handshake** — construct a valid QUIC Initial packet (ClientHello via rustls client), feed to `process_packet()`, verify:
- Response contains Initial + Handshake packets
- Initial has CRYPTO frame with ServerHello
- Connection state transitions to `Handshaking` → eventually `Established`
- Keys are installed at each stage

**Unit test: stream data** — after handshake completes, feed a 1-RTT packet with STREAM frame, verify:
- Data delivered to `RecvHalf`
- ACK is generated
- Can send stream data back

**Quinn interop test** — requires full runtime:
- Start `LocalRuntime` with QUIC listener on port 4433
- Quinn client connects over veth pair
- Handshake completes
- Client sends "hello", server echoes back
- Client receives "hello"

## Timestamp Discipline

**All time operations use the `now: coarsetime::Instant` passed from the runtime event loop.** No `Instant::now()`, `Instant::recent()`, or `elapsed()` calls anywhere in QUIC handler or processor code.

## Performance Constraints

- Zero heap allocation on the per-packet hot path (post-handshake steady state)
- Frame buffers borrowed from `free_frames` and returned via `tx_return` — same lifecycle as TCP
- `pending_crypto` uses `Vec<u8>` which is acceptable (handshake path only, amortized)
- `PnBitset` is 32 bytes inline, no heap
- Follow TCP patterns for `#[inline]`, frame buffer management, MAC resolution
