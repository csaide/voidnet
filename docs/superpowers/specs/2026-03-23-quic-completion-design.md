# QUIC Implementation Completion — Design Spec

**Date:** 2026-03-23
**Branch:** quic-rustls
**RFCs:** 9000, 9001, 9002, 9369 (includes compatible VN requirements from §4.1), 8999, 9221

## Overview

This spec covers completing the QUIC implementation to production readiness. The existing codebase has ~34k lines implementing RFC 9000/9001/9002 core transport with 1406 passing tests. This work adds missing RFC features, end-to-end integration tests, adversarial tests, benchmarks, and merge cleanup.

Four phases, ordered to build confidence before adding complexity:

1. **Stabilize** — E2E integration tests, debug artifact cleanup, API consistency review
2. **Variable-Length CIDs** — Complete the existing variable-length CID type with configurable length, zero-length CID 5-tuple fallback; done early since it's structural
3. **Feature Additions** — NEW_TOKEN, compatible version negotiation (RFC 9369 §4.1), preferred address, DATAGRAM (RFC 9221)
4. **Harden** — Adversarial/edge case tests, criterion benchmarks

---

## Phase 1: Stabilize

### 1.1 End-to-End Integration Tests

New test file within `src/net/handler/quic/tests/` (consistent with existing test location). All tests use loopback with self-signed certs via `rcgen`.

**Test cases:**

1. **Full lifecycle** — Client connect → open bidi stream → client sends data → server reads → server responds → client reads → client FIN → server FIN → graceful shutdown. Validates the entire happy path end-to-end.

2. **Unidirectional streams** — Client opens uni stream, sends data + FIN. Server opens uni stream back, sends data + FIN. Validates uni stream creation in both directions.

3. **Multiple concurrent streams** — Open 8+ bidi streams, send data on all concurrently, verify all complete. Exercises stream map, flow control, and fairness.

4. **Large transfer** — Send ~1MB over a single stream (exceeds 8192-byte send buffer). Validates flow control window updates, backpressure (`DataAcked` events), and multi-packet reassembly.

5. **0-RTT reconnect** — First connection with session ticket issuance, second connection using 0-RTT early data. Validates the 0-RTT key extraction and acceptance path end-to-end.

6. **Connection close by each side** — Client initiates close, verify server sees `ConnectionClosed` event and futures wake. Repeat with server initiating. Verify draining timer behavior.

7. **Stream reset** — Client sends RESET_STREAM mid-transfer, server observes `StreamReset` error. Server sends STOP_SENDING, client observes reset. Validates both directions of RFC 9000 §3.5.

8. **Idle timeout** — Connect, exchange data, then go idle. Verify connection closes after `max_idle_timeout` expires. Also verify PING keep-alive resets the idle timer. Tests RFC 9000 §10.1 including the rule that the effective timeout is the minimum of both peers' values.

### 1.2 Debug Artifact Cleanup

Audit the codebase for artifacts from the debugging commits (`debug:` prefixed commits in history):

- Remove stale `debug_assert!` calls added for frame accounting instrumentation that are not permanent invariant checks
- Remove any `eprintln!`/`println!` debug output in non-test code
- Remove commented-out code from debugging sessions (e.g., residue from the `disable QUIC poll_send` commit)
- Audit `#[allow(dead_code)]` annotations — items should either be used or removed

### 1.3 API Consistency Review

Compare QUIC socket API against TCP and UDP for consistency. Observed differences to resolve:

**Naming:**
- TCP uses `TcpListener::listen(addr, port)`, QUIC uses `QuicListener::listen(addr, port, tls_config)` — the TLS config is an inherent difference, this is fine
- TCP config variant is `listen_with_config(addr, port, config)` where config bundles backlog + buffer sizes. QUIC uses `listen_with_config(addr, port, tls_config, params)` with separate TLS and transport args. Consider: should QUIC have a unified `QuicConfig` that bundles both?
- TCP `accept()` returns `Accept<'_>`, QUIC `accept()` returns `Accept<'_>` — consistent, good
- TCP has `TcpStream` with `read()`/`write()`, QUIC has `QuicStream` with `read()`/`write()` — consistent

**Error types:**
- TCP uses `TcpError` (internal) with socket methods returning `Result<T, BindError>` for listen
- QUIC uses `QuicError` for everything including listen failures (`QuicError::NotConnected` for bind failure is semantically wrong)
- Fix: QUIC listen should return `Result<Self, BindError>` for consistency, keep `QuicError` for connection/stream operations

**Exports:**
- TCP re-exports as `Accept`, `Connect`, `TcpStream`, etc.
- QUIC re-exports with `QuicAccept`, `QuicConnect` aliases to avoid name collision — this is fine
- Verify all public types that should be exported are exported from `socket/mod.rs`

**Missing patterns:**
- TCP has `TcpStream::connect()` returning `Connect` future. QUIC has `QuicConnection::connect()` returning `Connect` future — consistent
- UDP has `close()` method. TCP stream has implicit close on drop. QUIC should have explicit `close()` on `QuicConnection` if not already present, plus `Drop` impl that initiates graceful close

---

## Phase 2: Variable-Length Connection IDs

RFC 9000 §5.1 allows CIDs from 0 to 20 bytes. The variable-length `ConnectionId` type already exists in `connection_id.rs` with the stack-allocated `[u8; 20]` + `len: u8` layout, and `handler.rs` already has `local_cid_len: usize` (default 8). Short header parsing already uses the stored CID length.

**What remains:**

### 2.1 Configurable CID Length in API

- Expose `cid_length` as a field in `TransportParams` / `QuicConfig` so users can set it (0–20, default 8)
- Wire the configured length through to `handler.rs` CID generation
- Validate at config time that `cid_length <= 20`

### 2.2 Zero-Length CID Support

When DCID length is 0 (RFC 9000 §5.1):
- Short header packets have no CID field
- Demux cannot use CID lookup — fall back to 5-tuple `(src_ip, src_port, dst_ip, dst_port, proto)` lookup
- Add `FxHashMap<FiveTuple, usize>` as secondary lookup in handler, used only when a connection has zero-length CIDs
- Connection migration is not supported with zero-length CIDs (RFC 9000 §5.1)

### 2.3 Tests

- Configurable CID length: create listener/connection with 0, 4, 8, 20 byte CID lengths
- Packet parse/serialize round-trip with different CID lengths
- Integration test: client with zero-length CID connecting to server (5-tuple demux)
- Integration test: NEW_CONNECTION_ID with different CID lengths in the exchange
- Reject CID length > 20 at config time

---

## Phase 3: Feature Additions

### 3.1 NEW_TOKEN / Session Resumption

RFC 9000 §8.1, §19.7. Server issues tokens for address validation on future connections.

**Server side:**
- After handshake, server generates an encrypted token containing:
  - **Type discriminator** (1 byte): distinguishes Retry tokens from NEW_TOKEN tokens (RFC 9000 §8.1.1 MUST: "constructed in a way that allows the server to identify how it was provided")
  - Client IP, timestamp, original DCID, QUIC version (for RFC 9369 §5 compliance)
- Token encryption: AES-256-GCM with a server-secret key (configurable via `QuicConfig`, randomly generated if not provided). Nonce derived from timestamp. **Encryption is MUST, not optional** — RFC 9000 §8.1.3 requires that NEW_TOKEN tokens not leak linkable information; the encrypted DCID satisfies this only because it's encrypted.
- Server sends NEW_TOKEN frame to client
- On future Initial packets with a token, server validates: decrypts, checks type discriminator, checks IP match (configurable strictness), checks expiry (default 24 hours), checks version matches connection version (RFC 9369 §5), extracts metadata
- Valid NEW_TOKEN token lifts amplification limit and skips Retry (RFC 9000 §8.1.2)
- Valid Retry token validates the retry exchange (different code path — already implemented)

**Client side:**
- Client stores received tokens keyed by `(server_name, version)` — RFC 9369 §5: "Clients MUST NOT use a session ticket or token from a QUIC version 1 connection to initiate a QUIC version 2 connection, and vice versa"
- Token store uses `&self` (interior mutability) for ergonomics in async contexts:

```rust
pub trait TokenStore {
    fn get(&self, server_name: &str, version: u32) -> Option<Vec<u8>>;
    fn put(&self, server_name: &str, version: u32, token: Vec<u8>);
}
```

- Default in-memory `RefCell<HashMap>`-based implementation provided
- `QuicConnection::connect()` accepts optional `&dyn TokenStore` in config
- Client attaches stored token (matching server name + version) in Initial packet's Token field

**Tests:**
- Round-trip: server issues token → client reconnects with token → server validates → no Retry sent
- Token expiry: token with old timestamp → rejected → Retry or amplification limit enforced
- Token with wrong IP → rejected
- Token with wrong version → rejected (v1 token used on v2 connection)
- Token type discriminator: Retry token vs NEW_TOKEN token handled differently
- Token store trait: custom implementation works

### 3.2 Compatible Version Negotiation (RFC 9369 §4.1)

MUST for endpoints supporting QUIC v2 (RFC 9369 §4). The compatible negotiation requirements between v1 and v2 are specified in RFC 9369 §4.1. Allows v1↔v2 switch mid-handshake without extra round trip.

**Note:** NEW_TOKEN (§3.1) must be implemented with version tagging from the start, since RFC 9369 §5 creates a hard dependency between token validity and QUIC version.

**Transport parameter:** `version_information` (type 0x11):
- `chosen_version` (32 bits): version used for this connection's handshake
- `available_versions` (32 bits each): all versions the endpoint supports

Both client and server MUST send this. Partially implemented in `params.rs` — complete the encode/decode and wire into handshake processing.

**Server-side negotiation:**
- After receiving client transport params, server checks if it prefers a different compatible version from client's `available_versions`
- If so, server switches: sends Handshake and 1-RTT packets using the negotiated version
- Server MUST use original version for Retry and Initial responses before reading transport params
- HKDF labels switch based on negotiated version (`"quic "` for v1, `"quicv2 "` for v2)

**Client-side detection:**
- Client observes first long header with a different Version field → that's the negotiated version
- Client switches subsequent Initial packets to negotiated version
- Client MUST NOT send 0-RTT using negotiated version (use original only)

**Downgrade prevention:**
- Both sides validate `version_information` presence and consistency
- If chosen version not in peer's `available_versions` → CONNECTION_CLOSE with TRANSPORT_PARAMETER_ERROR
- If `version_information` missing when peer claims v2 support → CONNECTION_CLOSE

**Key interactions:**
- Handshake and 1-RTT keys use negotiated version's HKDF labels
- Initial keys use original version's salt (already version-aware in `initial_keys.rs`)
- Retry uses original version (already handled)

**Tests:**
- Client (v1+v2) connects to server (prefers v2) → negotiates to v2 → handshake completes
- Downgrade detection: server lies about available versions → client closes
- Retry + compatible negotiation combined
- `version_information` transport parameter encode/decode round-trip
- Both endpoints v1-only → no negotiation, normal handshake

### 3.3 Preferred Address (RFC 9000 §9.6, §18.2)

Server advertises an alternate address for post-handshake client migration.

**Transport parameter encoding** (`preferred_address`, type 0x0d):
```
ipv4_address (32), ipv4_port (16),
ipv6_address (128), ipv6_port (16),
connection_id_length (8), connection_id (..),
stateless_reset_token (128)
```

**Server side:**
- Optional `preferred_address` in server config / transport params
- Encoded and sent during handshake
- Server accepts packets on both original and preferred addresses
- Server provides a new CID + stateless reset token for the preferred path
- **The CID in preferred_address MUST have sequence number 1** (RFC 9000 §5.1.1). The next NEW_CONNECTION_ID frame issued uses sequence number 2+.

**Client side:**
- After handshake, if `preferred_address` received:
  - Client initiates migration to preferred address using existing migration machinery (PATH_CHALLENGE/PATH_RESPONSE, CID rotation)
  - Uses the CID provided in the preferred_address parameter (sequence number 1)
- If path validation fails, client stays on original path (no error)
- **`disable_active_migration` does NOT prevent preferred address migration** — RFC 9000 §9.6: preferred address is a server-initiated suggestion, independent of the `disable_active_migration` transport parameter. Only general client-initiated migration to arbitrary addresses is blocked by `disable_active_migration`.

**Tests:**
- Server advertises preferred address → client migrates → data flows on new path
- Path validation to preferred address fails → client stays on original, connection continues
- `disable_active_migration` set → client STILL migrates to preferred address (RFC 9000 §9.6)
- `disable_active_migration` set → client does NOT migrate to other arbitrary addresses
- IPv4-only and IPv6-only preferred address variants
- Preferred address CID has sequence number 1, subsequent NEW_CONNECTION_ID uses 2+
- Preferred address transport param encode/decode round-trip

### 3.4 DATAGRAM Extension (RFC 9221)

Unreliable, unordered datagrams over QUIC. Independent of streams.

**Negotiation:**
- Transport parameter `max_datagram_frame_size` (type 0x20)
- Both sides advertise max size they're willing to receive. 0 or absent = datagrams not supported.
- Value includes frame overhead (varint type + optional varint length)

**Frame types:**
- `DATAGRAM` (0x30) — payload extends to end of packet (no length field)
- `DATAGRAM_WITH_LENGTH` (0x31) — varint length prefix before payload

**Internal implementation:**
- **Frame parser must be extended** to handle 0x30/0x31 frame types. The current catch-all in `frame.rs` treats unknown frame types as zero-length padding, which would silently eat DATAGRAM frames. Add explicit DATAGRAM/DATAGRAM_WITH_LENGTH variants to the frame parser before enabling the extension.
- Datagram send queue per connection: bounded ring buffer (configurable capacity, default 64 entries)
- If send queue full, oldest datagram dropped (RFC 9221 §5 guidance)
- Datagram recv queue per connection: bounded, delivered via `QuicEvent::DatagramReceived`
- Packet builder emits DATAGRAM frames after control and stream data (lower priority)
- No retransmission, no flow control, no ordering
- DATAGRAM frames are ack-eliciting (RFC 9221 §4)

**Socket API additions:**

```rust
impl QuicConnection {
    /// Send an unreliable datagram. Returns error if datagrams not negotiated
    /// or data exceeds max_datagram_frame_size.
    pub fn send_datagram(&self, data: &[u8]) -> Result<(), QuicError>;

    /// Receive the next datagram. Returns a future that resolves when available.
    pub fn recv_datagram(&self) -> RecvDatagram<'_>;

    /// Maximum datagram payload size negotiated with peer, or None if not supported.
    pub fn max_datagram_size(&self) -> Option<usize>;
}
```

**Tests:**
- Send/recv datagrams bidirectionally
- Oversized datagram → error
- Datagram when peer doesn't advertise support → error
- Interleaved datagram + stream data in same connection
- Send queue overflow → oldest dropped, newest delivered

---

## Phase 4: Adversarial Tests + Benchmarks

### 4.1 Adversarial / Edge Case Tests

New test module for malformed input and protocol edge cases.

**Packet-level:**
- Truncated packet (header claims more bytes than available)
- Invalid version in long header (unknown, not 0x00000000)
- DCID/SCID length field > 20
- Corrupted header protection bytes
- Coalesced packets where second packet has wrong DCID
- Short header before handshake completes

**Frame-level:**
- Unknown frame type → packet discarded (RFC 9000 §19.21: frames are not self-describing, so remaining bytes are unparsable; the current catch-all treating unknowns as zero-length padding is fragile and should be verified/hardened)
- Frame extends beyond packet boundary
- STREAM frame offset exceeds flow control limit → FLOW_CONTROL_ERROR
- MAX_STREAM_DATA for a locally-initiated send-only stream → STREAM_STATE_ERROR
- RESET_STREAM for unknown stream ID — two sub-cases: (a) stream ID within limits but not yet created → implicitly open it and all lower-numbered streams of same type (RFC 9000 §2.1), then apply the reset; (b) stream ID exceeds MAX_STREAMS → STREAM_LIMIT_ERROR
- ACK ranges that overlap or reference unsent packet numbers
- CONNECTION_CLOSE with unknown error code → accept gracefully
- NEW_CONNECTION_ID with `retire_prior_to > sequence_number` → FRAME_ENCODING_ERROR

**Protocol-level:**
- Amplification limit: server sends ≤3x received bytes before validation (measure precisely)
- Client Initial < 1200 bytes → server drops (RFC 9000 §14.1)
- Duplicate packet numbers → discarded silently
- Packet during draining → cached CONNECTION_CLOSE retransmit (rate-limited to PTO interval)
- Stream ID exceeds MAX_STREAMS → STREAM_LIMIT_ERROR
- Data on stream 0 from server (wrong initiator) → STREAM_STATE_ERROR
- Stream ID gap → implicit open of intermediate streams (RFC 9000 §2.1)

### 4.2 Benchmarks

Using `criterion`. File: `benches/quic.rs`.

**Micro-benchmarks:**
- `packet_protect` / `packet_unprotect` — AEAD encrypt/decrypt throughput
- `frame_encode` / `frame_decode` — frame serialization round-trip
- `varint_encode` / `varint_decode` — variable-length integer performance
- `connection_id_hash` — CID hashing throughput (hot path for packet demux)

**Macro-benchmarks:**
- `handshake_latency` — full client+server handshake to Established (wall-clock)
- `stream_throughput` — 1MB over single bidi stream (bytes/sec)
- `multi_stream_throughput` — 1MB across 8 concurrent streams
- `datagram_throughput` — 10k datagrams send/recv rate
- `migration_latency` — time from address change detection to validated-path data flow (regression tracking for the migration machinery)

---

## Success Criteria

- All existing 1406 tests continue to pass
- New E2E integration tests cover the full connection lifecycle
- Variable-length CIDs work with 0, 4, 8, and 20 byte lengths
- NEW_TOKEN round-trip works (issue → store → reconnect → validate)
- Compatible version negotiation switches v1↔v2 cleanly
- Preferred address migration succeeds and fails gracefully
- DATAGRAM send/recv works with proper negotiation
- Adversarial tests confirm RFC-mandated error handling
- No debug artifacts remain in non-test code
- QUIC socket API is consistent with TCP/UDP socket patterns
- `cargo test` passes with zero failures
