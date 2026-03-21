# QUIC Server-Side State Machine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire all QUIC building blocks into a working server-side protocol engine — quinn client can connect, handshake, and exchange stream data.

**Architecture:** `processor.rs` handles per-connection packet processing/generation, called by `handler.rs` which owns the connection table. Follows TCP's handler→inbound/transmit pattern. IPv4+IPv6 from day one.

**Tech Stack:** Rust, rustls (QUIC mode), coarsetime, existing VoidNet AF_XDP frame buffer system.

**Spec:** `docs/superpowers/specs/2026-03-20-quic-state-machine-design.md`

---

## Phase A: Fix 8 RFC FAIL Items

### Task 1: Fix CongestionController trait + QuicCubic

**Files:**
- Modify: `src/net/congestion/mod.rs`
- Modify: `src/net/handler/quic/transport/congestion.rs`
- Modify: `src/net/handler/quic/tests/congestion_test.rs`

- [ ] **Step 1: Update CongestionController trait signature**

In `src/net/congestion/mod.rs`, change:
- `on_ack`: add `in_flight: bool` and `sent_time: coarsetime::Instant` parameters
- `on_congestion_event`: add `sent_time: coarsetime::Instant` parameter after `lost_bytes`

Note: This trait is QUIC-only. TCP uses its own `CubicState` directly without this trait.

- [ ] **Step 2: Update QuicCubic implementation**

In `congestion.rs`:
- Remove `in_congestion_recovery` field
- `on_ack`: return early if `!in_flight`. If `sent_time > congestion_recovery_start_time` → recovery is over, allow window growth.
- `on_congestion_event`: use `sent_time <= congestion_recovery_start_time` to skip duplicate congestion events. Store `congestion_recovery_start_time = now`.
- `in_persistent_congestion()`: document that caller MUST pass PTO including `max_ack_delay`.

- [ ] **Step 3: Fix tests**

Update all test calls to match new signatures. Add:
- `test_recovery_ignores_old_losses` — loss with sent_time before recovery start is ignored
- `test_recovery_exits_on_new_ack` — ack for packet sent after recovery exits recovery
- `test_non_in_flight_no_growth` — on_ack with in_flight=false doesn't grow window

- [ ] **Step 4: Run tests**

Run: `cargo test --lib net::handler::quic::tests::congestion_test`
Expected: All pass

- [ ] **Step 5: Commit**

```
fix(quic): congestion controller uses sent_time for recovery (RFC 9002 §7.3.2)
```

---

### Task 2: Fix loss detection RTT + PTO + discard

**Files:**
- Modify: `src/net/handler/quic/transport/loss.rs`
- Modify: `src/net/handler/quic/tests/loss_test.rs`

- [ ] **Step 1: Fix update_rtt — handshake_confirmed parameter**

Add `handshake_confirmed: bool` param. Only clamp `ack_delay` to `max_ack_delay` when `handshake_confirmed == true`. Otherwise use raw ack_delay.

- [ ] **Step 2: Fix discard_space — reset pto_count**

In `discard_space()`, add `self.pto_count = 0;`. Remove the contradicting comment.

- [ ] **Step 3: Add reset_min_rtt method**

```rust
pub fn reset_min_rtt(&mut self, latest_rtt: coarsetime::Duration) {
    self.min_rtt = latest_rtt;
}
```

- [ ] **Step 4: Update tests**

- `test_rtt_unclamped_before_handshake` — pass handshake_confirmed=false, verify ack_delay used as-is
- `test_discard_space_resets_pto_count` — verify pto_count=0 after discard
- Update existing test calls for new signature

- [ ] **Step 5: Run tests, commit**

```
fix(quic): loss detection RTT clamping, pto_count reset (RFC 9002)
```

---

### Task 3: Fix wire parser CID length

**Files:**
- Modify: `src/net/wire/quic.rs`
- Modify: `src/net/handler/quic/tests/` (any wire tests referencing CID length)

- [ ] **Step 1: Change parse_long_header CID length check from 20 to 255**

The 20-byte limit is v1-specific. The wire parser is version-independent per RFC 8999.

- [ ] **Step 2: Add v1 CID length validation in handler**

In `handler.rs` (or `packet_parser.rs` when created), validate `dcid.len() <= 20` for QUIC v1 after parsing.

- [ ] **Step 3: Test — CID length 21 now parses successfully at wire level**

- [ ] **Step 4: Commit**

```
fix(quic): accept CID length 0..255 per RFC 8999 invariants
```

---

## Phase B: State Machine

### Task 4: CryptoRecvBuffer + PnBitset types

**Files:**
- Create: `src/net/handler/quic/packet_parser.rs`
- Test: `src/net/handler/quic/tests/packet_parser_test.rs`

- [ ] **Step 1: Write failing tests**

```rust
// CryptoRecvBuffer tests
#[test] fn crypto_recv_sequential() { /* write at offset 0,100,200 → received advances */ }
#[test] fn crypto_recv_out_of_order() { /* write at 100 first, then 0 → both delivered */ }
#[test] fn crypto_recv_overflow() { /* exceed 8192 → error */ }
#[test] fn crypto_recv_duplicate() { /* write same offset twice → no double count */ }

// PnBitset tests
#[test] fn pn_bitset_mark_and_check() { /* mark PN 5, check is_duplicate(5)=true, is_duplicate(6)=false */ }
#[test] fn pn_bitset_window_advance() { /* mark PNs 0..100, then 1100 → old PNs below window are not duplicate */ }
#[test] fn pn_bitset_reorder_within_window() { /* mark 100, then 50 → 50 detected as non-dup within 1024 window */ }

// parse_initial_fields test
#[test] fn parse_initial_fields_extracts_token_and_length() {
    // Build bytes: token_len(varint=0) + length(varint) → returns (token_slice, pn_offset)
}
```

- [ ] **Step 2: Implement CryptoRecvBuffer, PnBitset, parse_initial_fields**

`CryptoRecvBuffer`: fixed `[u8; 8192]`, `received: u64`, contiguous write logic.
`PnBitset`: `[u64; 16]` (1024 bits), `base: u64`, mark/check/advance.
`parse_initial_fields(buf, offset)`: parse token_len + token + length varint, return `(token, payload_length, pn_offset)`.

Also add `packet_space_from_type(PacketType) -> usize` helper (Initial→0, Handshake→1, others→2).

Add `pub(crate) mod packet_parser;` to `src/net/handler/quic/mod.rs`.

**PnBitset below-window semantics:** PNs below the window base are treated as duplicates (rejected). This is conservative — once we've advanced past a PN, we assume it was seen.

- [ ] **Step 3: Run tests, commit**

```
feat(quic): CryptoRecvBuffer, PnBitset, Initial packet field parser
```

---

### Task 5: Update QuicConnectionState with new fields

**Files:**
- Modify: `src/net/handler/quic/connection.rs`
- Modify: `src/net/handler/quic/path.rs`
- Modify: `src/net/handler/quic/transport/packet_builder.rs`

- [ ] **Step 1: Add new fields to QuicConnectionState**

Add all fields from the spec: `crypto_recv`, `pending_crypto`, `crypto_offset`, `crypto_acked`, `pacing`, `retransmit`, `pending_path_response`, `send_handshake_done`, `frame_log`, `recv_pn_seen`, network addressing fields (`local_addr`, `remote_addr`, `local_port`, `remote_port`, `local_mac`, `remote_mac`).

- [ ] **Step 2: Remove SocketAddr from PathState**

Replace `remote_addr: Option<SocketAddr>` and `local_addr: Option<SocketAddr>` with simple validation flags. Address storage is now on `QuicConnectionState`. Update `on_peer_address_change()` to accept `IpAddress` + `u16` port instead of `SocketAddr` — it compares against the connection's `remote_addr`/`remote_port` (passed as params since PathState doesn't own them). Similarly update `needs_cid_rotation()`.

- [ ] **Step 3: Fix PathState tests**

Update `path_test.rs` to use `IpAddress` + port instead of SocketAddr. Add a primary `scid: ConnectionId` field to `QuicConnectionState` (the SCID used in outgoing packet headers — first entry from `scid_set`).

- [ ] **Step 4: Fix PacketBuilder::write_crypto — accept space parameter**

Change `write_crypto` to accept `space: u8` and pass it to `SentFrame::Crypto { space, ... }`.

- [ ] **Step 5: Update QuicConnectionState::new() constructor**

Initialize all new fields with defaults. `frame_log: FrameLog::new(1024)`.

- [ ] **Step 6: Verify compilation + tests pass**

Run: `cargo test --lib net::handler::quic`

- [ ] **Step 7: Commit**

```
feat(quic): expand QuicConnectionState with pending state fields
```

---

### Task 6: Processor — process_packet (decrypt + frame parse)

**Files:**
- Create: `src/net/handler/quic/processor.rs`
- Modify: `src/net/handler/quic/mod.rs`
- Test: `src/net/handler/quic/tests/processor_test.rs`

This is the core inbound path. Build it incrementally:

- [ ] **Step 1: Write test — process Initial packet with CRYPTO frame**

Create a test that:
1. Creates a `QuicConnectionState` with Initial keys (server side)
2. Constructs a valid Initial packet: long header + token(0) + length + PN + encrypted CRYPTO frame
3. Calls `process_packet()`
4. Verifies CRYPTO data was fed to `CryptoState` and response CRYPTO data is queued

Use rustls client to generate the ClientHello CRYPTO data:
```rust
let (mut client_crypto, client_hello) = CryptoState::new_client(...);
// Build Initial packet containing client_hello as CRYPTO frame
// Encrypt with client Initial keys
// Feed to process_packet on server connection
```

- [ ] **Step 2: Implement process_packet skeleton**

Use the full final signature from the start (some params unused initially):

```rust
pub fn process_packet(
    conn: &mut QuicConnectionState,
    quic_payload: &mut [u8],  // mutable for in-place decrypt
    datagram_len: usize,
    src_addr: IpAddress,
    now: coarsetime::Instant,
) -> ProcessResult {
    // 1. Parse header
    // 2. Determine space
    // 3. Select keys (return if unavailable)
    // 4. For Initial: parse_initial_fields
    // 5. unprotect_header → decode_pn → check duplicate → decrypt_payload
    // 6. Parse frames loop
    // 7. Post-processing
}
```

Implement steps 1-5 (decrypt pipeline) first. Frame dispatch in next task.

- [ ] **Step 3: Run test — verify decrypt succeeds and CRYPTO extracted**

- [ ] **Step 4: Commit**

```
feat(quic): process_packet — decrypt pipeline
```

---

### Task 7: Processor — frame dispatch

**Files:**
- Modify: `src/net/handler/quic/processor.rs`
- Modify: `src/net/handler/quic/tests/processor_test.rs`

- [ ] **Step 1: Add frame dispatch logic to process_packet**

After decrypt + frame parse, dispatch each `QuicFrame`:
- CRYPTO → `CryptoRecvBuffer.write()`, if contiguous data ready → `CryptoState.process_crypto_data()`, install keys, queue response, apply transport params
- ACK → `AckState::decode_ack_ranges()` → `LossDetector.on_ack_received()` → congestion updates
- STREAM → validate direction, `StreamMap.get_or_create()`, `RecvHalf.receive()`, flow control
- MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS → update limits
- CONNECTION_CLOSE → transition to Draining
- PATH_CHALLENGE → queue response
- PING, PADDING → no-op (PING is ack-eliciting)

Include frame-type-per-space validation (RFC 9000 §12.4).

- [ ] **Step 2: Write test — full handshake via process_packet**

Feed ClientHello Initial → verify ServerHello queued in `pending_crypto`. Then feed the client's Handshake CRYPTO → verify 1-RTT keys installed and `send_handshake_done` set.

- [ ] **Step 3: Write test — ACK processing updates loss detector**

- [ ] **Step 4: Write test — STREAM frame delivered to RecvHalf**

- [ ] **Step 5: Commit**

```
feat(quic): process_packet — frame dispatch
```

---

### Task 8: Processor — generate_packets (outbound)

**Files:**
- Modify: `src/net/handler/quic/processor.rs`
- Modify: `src/net/handler/quic/tests/processor_test.rs`

This builds outgoing packets from pending state. Follows TCP's `SegmentBuilder` pattern — read `src/net/handler/tcp/segment.rs` to understand how it builds Ethernet+IP+UDP+payload into a `Frame<'umem>`.

- [ ] **Step 1: Add write_ack to PacketBuilder**

Before implementing generate_packets, add a `write_ack` method to `PacketBuilder` in `packet_builder.rs`:
```rust
pub fn write_ack(&mut self, ack_state: &AckState, ack_delay: u64, frame_log: &mut FrameLog) -> bool
```
Uses `AckState.largest_received()`, `first_ack_range()`, `ack_range_count()`, `encoded_ranges()` to write the ACK frame. Returns true if written.

Also add `write_max_data`, `write_handshake_done`, `write_path_response` wrappers.

- [ ] **Step 2: Implement generate_packets**

```rust
pub fn generate_packets<'umem>(
    conn: &mut QuicConnectionState,
    conn_key: usize,
    now: coarsetime::Instant,
    wheel: &mut TimerWheel,
    neighbor_handler: &NeighborHandler,
    free_frames: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
)
```

Logic:
1. Check gates (amplification, congestion, pacing)
2. For each space with pending data (Initial, Handshake, 1-RTT):
   - Pop frame from `free_frames`
   - Write Ethernet + IP + UDP headers (dispatch on `conn.local_addr` for v4/v6). Follow TCP's `SegmentBuilder` pattern: match on `(local_addr, remote_addr)` for V4/V6 dispatch.
   - `PacketBuilder::begin_long()` or `begin_short()`
   - Write frames in priority order (CRYPTO, ACK, retransmit, control, stream, PING)
   - For Initial: `pad_to(1200)`
   - `finish()` → `protect_packet()` → push to `tx_return`
   - `LossDetector.on_packet_sent()`
3. Coalesce: if building handshake response, try Initial+Handshake in same Frame
4. Arm loss detection timer via `wheel`

**Coalescing detail:** For handshake response, allocate ONE frame from `free_frames`. Write Ethernet+IP+UDP headers. Build Initial packet (with CRYPTO + padding to 1200). Track the byte offset where Initial ends. Build Handshake packet starting at that offset (same frame buffer, new PacketBuilder). Each packet is independently encrypted. Set the frame's total length to cover both. 1-RTT always last if included.

- [ ] **Step 2: Write test — generates Initial+Handshake response after ClientHello**

Process a ClientHello via `process_packet`, then call `generate_packets`. Verify:
- At least one frame produced in `tx_return`
- Frame contains valid Ethernet+IP+UDP headers
- QUIC payload is encrypted (first byte has header form bit set)

- [ ] **Step 3: Write test — generates ACK for received packet**

- [ ] **Step 4: Write test — respects anti-amplification limit**

- [ ] **Step 5: Commit**

```
feat(quic): generate_packets — outbound packet construction
```

---

### Task 9: Processor — handle_timeout

**Files:**
- Modify: `src/net/handler/quic/processor.rs`
- Modify: `src/net/handler/quic/tests/processor_test.rs`

- [ ] **Step 1: Implement handle_timeout**

**Key design:** `handle_timeout` only marks pending state — it does NOT generate packets directly. Packet generation happens in `poll_send` → `generate_packets`, which has access to `NeighborHandler` and frame buffers. This matches TCP's pattern where timers mark state and `poll_send` does the actual sending.

Dispatch on `QuicTimerKind`:
- `LossDetection`: call `loss.on_loss_detection_timeout()`. If lost packets → build retransmit queue, store in `conn.retransmit`. If PTO → mark `conn.needs_probe = true`.
- `Idle`: return `TimerResult::Close`
- `Ack`: mark `conn.ack[space].set_ack_eliciting()` (forces ACK in next poll_send)
- `Draining`: return `TimerResult::Close`
- Others: stub for now

The handler's `poll_send` will then pick up the pending state and generate packets.

- [ ] **Step 2: Write test — idle timeout closes connection**

- [ ] **Step 3: Write test — loss detection timeout triggers probe**

- [ ] **Step 4: Commit**

```
feat(quic): handle_timeout — timer dispatch
```

---

### Task 10: Wire handler to processor

**Files:**
- Modify: `src/net/handler/quic/handler.rs`
- Modify: `src/rt/local.rs`

This replaces all the stubs with real calls to the processor.

- [ ] **Step 1: Implement handler.process_ipv4**

Parse IP header → extract payload offset → parse UDP header → extract dst_port + QUIC payload. Extract src/dst addresses and MACs from the frame. For new connections (Initial + listener): create connection via `create_server_connection()`. For existing: look up by DCID, call `processor::process_packet()`. Then call `processor::generate_packets()` if the connection has pending responses.

- [ ] **Step 2: Implement handler.process_ipv6**

Same logic but for IPv6 header. Extract addresses from IPv6 header.

- [ ] **Step 3: Implement handler.handle_timer**

Look up connection by key, call `processor::handle_timeout()`. If `TimerResult::Close`, remove connection.

- [ ] **Step 4: Implement handler.poll_send**

Iterate connections that have pending data (need a `send_tracker` set or iterate all). Call `processor::generate_packets()` for each. Update `poll_send` signature to accept `neighbor_handler` and `local_mac`.

- [ ] **Step 5: Update local.rs poll_send call to pass neighbor_handler**

- [ ] **Step 6: Implement handler.evict_stale**

Check connections where `now > created_at + idle_timeout`. Remove stale ones.

- [ ] **Step 7: Implement create_server_connection**

Steps from spec: validate datagram size, derive initial keys, generate SCID, create connection state, insert, process Initial packet.

- [ ] **Step 8: Run ALL tests (cargo test) — zero regressions**

- [ ] **Step 9: Commit**

```
feat(quic): wire handler to processor — packets flow end-to-end
```

---

## Phase C: Tests

### Task 11: Unit test — full handshake

**Files:**
- Create: `src/net/handler/quic/tests/handshake_integration_test.rs`

- [ ] **Step 1: Write handshake test**

1. Create `QuicHandler` with a listener on port 4433 (self-signed cert via rcgen)
2. Use rustls `ClientConnection` to generate ClientHello CRYPTO data
3. Build a complete Initial packet (Ethernet+IP+UDP+QUIC) with the ClientHello
4. Feed through `handler.process_ipv4()`
5. Capture response from `tx_return`
6. Parse response — verify Initial+Handshake QUIC packets with CRYPTO frames
7. Feed response CRYPTO back to client rustls
8. Client produces Handshake CRYPTO → build Handshake packet → feed to handler
9. Verify connection reaches `Established` state
10. Verify `send_handshake_done` is true

- [ ] **Step 2: Run test, debug, iterate**

- [ ] **Step 3: Commit**

```
test(quic): full handshake integration test
```

---

### Task 12: Unit test — stream data transfer

**Files:**
- Modify: `src/net/handler/quic/tests/handshake_integration_test.rs`

- [ ] **Step 1: After handshake, send STREAM frame**

Build a 1-RTT packet with STREAM frame (stream_id=0, "hello"), encrypt with 1-RTT keys, feed to handler. Verify:
- Data arrives in `RecvHalf` for stream 0
- ACK is generated in response
- Can write data to `SendHalf` and call `poll_send` to get it out

- [ ] **Step 2: Commit**

```
test(quic): stream data transfer after handshake
```

---

### Task 13: Quinn interop test

**Files:**
- Create: `tests/quic_interop.rs` (integration test)

- [ ] **Step 1: Write integration test using quinn client**

Add `quinn` as a dev-dependency. Create a test that:
1. Starts `LocalRuntime` with QUIC listener on port 4433 over a veth pair
2. Spawns a quinn client task that connects and sends "hello"
3. Server echoes back "hello"
4. Client receives and verifies

This requires the full runtime stack including XDP sockets, so it must run as root.

- [ ] **Step 2: Run test, debug, iterate**

Run: `cargo test --test quic_interop`

- [ ] **Step 3: Commit**

```
test(quic): quinn interop — handshake + echo over loopback
```

---

## Post-Implementation

After all tasks complete:

1. `cargo test` — all existing + new tests pass
2. `cargo clippy` — no warnings on QUIC code
3. Verify timestamp discipline: `grep -rn "Instant::now\|Instant::recent\|\.elapsed()" src/net/handler/quic/` should return zero hits
