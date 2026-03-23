# QUIC Implementation Completion Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the QUIC implementation to production readiness with missing RFC features, E2E tests, adversarial tests, benchmarks, and merge cleanup.

**Architecture:** Four phases — stabilize the existing ~34k-line implementation with E2E tests and cleanup, then add structural changes (variable CIDs), then features (NEW_TOKEN, compatible VN, preferred address, DATAGRAM), then harden with adversarial tests and benchmarks.

**Tech Stack:** Rust, rustls 0.23, ring 0.17, rcgen (test certs), criterion (benchmarks), coarsetime

**Spec:** `docs/superpowers/specs/2026-03-23-quic-completion-design.md`

---

## File Structure

### New Files
- `src/net/handler/quic/tests/e2e_test.rs` — End-to-end integration tests (Phase 1)
- `src/net/handler/quic/tests/adversarial_test.rs` — Malformed input / edge case tests (Phase 4)
- `src/net/handler/quic/token_crypto.rs` — NEW_TOKEN encryption/decryption (Phase 3)
- `src/net/handler/quic/datagram.rs` — DATAGRAM send/recv queues (Phase 3)
- `src/net/handler/quic/tests/new_token_test.rs` — NEW_TOKEN unit tests (Phase 3)
- `src/net/handler/quic/tests/compat_vn_test.rs` — Compatible VN tests (Phase 3)
- `src/net/handler/quic/tests/preferred_addr_test.rs` — Preferred address tests (Phase 3)
- `src/net/handler/quic/tests/datagram_test.rs` — DATAGRAM extension tests (Phase 3)
- `benches/quic.rs` — Criterion benchmarks (Phase 4)

### Modified Files
- `src/net/handler/quic/mod.rs` — Register new modules
- `src/net/handler/quic/tests/mod.rs` — Register new test modules
- `src/net/handler/quic/transport/params.rs` — Add `preferred_address`, `max_datagram_frame_size`, `version_information` params, `cid_length` config
- `src/net/handler/quic/transport/frame.rs` — Add DATAGRAM frame variants (0x30/0x31), fix unknown frame catch-all
- `src/net/handler/quic/event.rs` — Add `DatagramReceived` event variant
- `src/net/handler/quic/connection.rs` — Add datagram queues, token_secret, preferred_address fields
- `src/net/handler/quic/handler.rs` — 5-tuple fallback map, configurable CID length, token generation, preferred address server support
- `src/net/handler/quic/processor.rs` — DATAGRAM frame dispatch, NEW_TOKEN frame emission, compatible VN handshake processing, preferred address migration trigger
- `src/net/socket/quic.rs` — `BindError` for listen, `send_datagram()`/`recv_datagram()`/`max_datagram_size()`, `TokenStore` trait, verify existing `close()`/`Drop`
- `src/net/socket/mod.rs` — Export new types
- `src/net/handler/quic/transport/version.rs` — Add `compatible_versions()`, `hkdf_labels_for_version()`
- `src/net/handler/quic/crypto/tls.rs` — Version-aware HKDF label selection for compatible VN

**Design note:** NEW_TOKEN encryption/decryption lives in new `token_crypto.rs` (wire-format crypto), separate from existing `token.rs` (in-memory `RetryToken` struct). This keeps crypto logic isolated.

---

## Phase 1: Stabilize

### Task 1: E2E Test Infrastructure

Extract shared test helpers from `handshake_integration_test.rs` into reusable form for all E2E tests.

**Files:**
- Create: `src/net/handler/quic/tests/e2e_test.rs`
- Modify: `src/net/handler/quic/tests/mod.rs`

- [ ] **Step 1: Create e2e_test.rs with shared helpers**

Create the new test file with helpers extracted from `handshake_integration_test.rs` (lines 28-240). These helpers are needed by all subsequent E2E tests:

```rust
// src/net/handler/quic/tests/e2e_test.rs
//
// Reuse the same patterns from handshake_integration_test.rs:
// - NoVerifier, make_test_cert(), make_client_config(), make_server_config()
// - encode_test_transport_params()
// - build_initial_packet(), wrap_in_eth_ipv4_udp()
//
// Add new helpers:
// - setup_client_server() -> (QuicHandler, QuicHandler) with completed handshake
// - drive_handshake(client, server) -> exchanges packets until both Established
// - pump_packets(src, dst, wheel, free, tx) -> forward all pending TX from src to dst
```

The key new helper is `drive_handshake()` which loops: client generates → feed to server → server generates → feed to client, until both reach `Established` state. This is the foundation for all E2E tests.

- [ ] **Step 2: Register module in tests/mod.rs**

Add `mod e2e_test;` to `src/net/handler/quic/tests/mod.rs`.

- [ ] **Step 3: Write first E2E test — full lifecycle**

```rust
#[test]
fn e2e_full_lifecycle() {
    // 1. Set up client + server handlers with listeners
    // 2. Client: initiate_connection()
    // 3. drive_handshake() until both Established
    // 4. Client: open bidi stream (stream_id 0x00)
    // 5. Client: write "hello" to stream via SendHalf
    // 6. pump_packets(client → server)
    // 7. Server: read from RecvHalf, assert "hello"
    // 8. Server: write "world" to same stream
    // 9. pump_packets(server → client)
    // 10. Client: read from RecvHalf, assert "world"
    // 11. Client: close stream (FIN)
    // 12. pump_packets(client → server)
    // 13. Server: observe FIN, close stream
    // 14. pump_packets(server → client)
    // 15. Verify both sides: stream complete, connection Established
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test e2e_full_lifecycle -- --nocapture`

- [ ] **Step 5: Commit**

```bash
git add src/net/handler/quic/tests/e2e_test.rs src/net/handler/quic/tests/mod.rs
git commit -m "test(quic): add E2E test infrastructure and full lifecycle test"
```

### Task 2: E2E Unidirectional Streams + Concurrent Streams

**Files:**
- Modify: `src/net/handler/quic/tests/e2e_test.rs`

- [ ] **Step 1: Write unidirectional stream test**

```rust
#[test]
fn e2e_unidirectional_streams() {
    // 1. Set up + handshake
    // 2. Client opens uni stream (type 0x02), sends data + FIN
    // 3. pump_packets, server reads
    // 4. Server opens uni stream (type 0x03), sends data + FIN
    // 5. pump_packets, client reads
    // 6. Verify both received correctly
}
```

- [ ] **Step 2: Write concurrent streams test**

```rust
#[test]
fn e2e_concurrent_streams() {
    // 1. Set up + handshake
    // 2. Client opens 8 bidi streams (IDs 0x00, 0x04, 0x08, ..., 0x1c)
    // 3. Client writes distinct data to each
    // 4. pump_packets back and forth until all acked
    // 5. Server reads from each, verifies data matches
    // 6. Server responds on each stream
    // 7. pump_packets
    // 8. Client reads all responses
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test e2e_unidirectional e2e_concurrent -- --nocapture`

- [ ] **Step 4: Commit**

```bash
git add src/net/handler/quic/tests/e2e_test.rs
git commit -m "test(quic): add E2E tests for unidirectional and concurrent streams"
```

### Task 3: E2E Large Transfer + 0-RTT

**Files:**
- Modify: `src/net/handler/quic/tests/e2e_test.rs`

- [ ] **Step 1: Write large transfer test**

```rust
#[test]
fn e2e_large_transfer() {
    // 1. Set up + handshake
    // 2. Generate 1MB of test data (repeating pattern for verification)
    // 3. Client writes in chunks to bidi stream
    // 4. Loop: pump_packets, drive flow control updates (MAX_DATA, MAX_STREAM_DATA)
    //    until all data acked
    // 5. Server reassembles, verifies full 1MB matches
    // NOTE: send buffer is 8192 bytes, so this exercises backpressure heavily
}
```

- [ ] **Step 2: Write 0-RTT reconnect test**

```rust
#[test]
fn e2e_zero_rtt_reconnect() {
    // 1. First connection: handshake, exchange data, obtain session ticket
    //    (requires server config with max_early_data_size > 0)
    // 2. Close first connection gracefully
    // 3. Second connection: use stored session ticket for 0-RTT
    // 4. Verify: client sends 0-RTT data before handshake completes
    // 5. Verify: server accepts 0-RTT data (zero_rtt_accepted counter > 0)
    // 6. Complete handshake, verify connection works normally
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test e2e_large_transfer e2e_zero_rtt -- --nocapture`

- [ ] **Step 4: Commit**

```bash
git add src/net/handler/quic/tests/e2e_test.rs
git commit -m "test(quic): add E2E tests for large transfer and 0-RTT reconnect"
```

### Task 4: E2E Connection Close + Stream Reset + Idle Timeout

**Files:**
- Modify: `src/net/handler/quic/tests/e2e_test.rs`

- [ ] **Step 1: Write connection close tests**

```rust
#[test]
fn e2e_client_initiated_close() {
    // 1. Set up + handshake
    // 2. Client sends CONNECTION_CLOSE (app error code 0x42)
    // 3. pump_packets to server
    // 4. Verify server connection enters Draining/Closing
    // 5. Verify server event_queue has ConnectionClosed(0x42)
}

#[test]
fn e2e_server_initiated_close() {
    // Same but server initiates close
}
```

- [ ] **Step 2: Write stream reset test**

```rust
#[test]
fn e2e_stream_reset() {
    // 1. Set up + handshake, open bidi stream
    // 2. Client sends partial data, then RESET_STREAM
    // 3. pump_packets
    // 4. Server observes StreamReset event
    // 5. Server sends STOP_SENDING on another stream
    // 6. pump_packets
    // 7. Client observes reset
}
```

- [ ] **Step 3: Write idle timeout test**

```rust
#[test]
fn e2e_idle_timeout() {
    // 1. Set up with max_idle_timeout_ms = 5000 (both sides)
    // 2. Handshake, exchange data
    // 3. Advance time past idle timeout
    // 4. Trigger handle_timeout() for idle timer
    // 5. Verify connection transitions to Closed/Draining
    // 6. Second test: send PING before timeout, verify it resets timer
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test e2e_client_initiated e2e_server_initiated e2e_stream_reset e2e_idle -- --nocapture`

- [ ] **Step 5: Commit**

```bash
git add src/net/handler/quic/tests/e2e_test.rs
git commit -m "test(quic): add E2E tests for connection close, stream reset, idle timeout"
```

### Task 5: Debug Artifact Cleanup

**Files:**
- Modify: Various files in `src/net/handler/quic/`

- [ ] **Step 1: Audit for debug prints**

Search all non-test QUIC source files for `eprintln!`, `println!`, `dbg!`:

```bash
grep -rn 'eprintln!\|println!\|dbg!' src/net/handler/quic/ --include='*.rs' | grep -v '/tests/'
```

Remove any found. These were likely left from the `debug:` commits.

- [ ] **Step 2: Audit for stale debug_assert! calls**

Check `debug_assert!` calls added in the frame accounting debugging commits. Review each — keep permanent invariant checks, remove instrumentation-specific ones. Look especially in:
- `src/net/handler/quic/processor.rs` (frame accounting assertions)
- `src/net/handler/quic/handler.rs` (tx_return assertions)

```bash
grep -rn 'debug_assert' src/net/handler/quic/ --include='*.rs' | grep -v '/tests/'
```

- [ ] **Step 3: Audit for commented-out code**

```bash
grep -rn '// *fn \|// *let \|// *pub \|// *if ' src/net/handler/quic/ --include='*.rs' | grep -v '/tests/'
```

Remove dead commented-out code. Particular areas: residue from the `disable QUIC poll_send` commit.

- [ ] **Step 4: Audit #[allow(dead_code)]**

```bash
grep -rn 'allow(dead_code)' src/net/handler/quic/ --include='*.rs'
```

For each: either use the item or remove both the item and the annotation. Known instance: `VersionInformation` in `params.rs:11` has `#[allow(dead_code)]` — this will be used in Phase 3 (compatible VN), so leave it.

- [ ] **Step 5: Run all tests to verify nothing broke**

Run: `cargo test`
Expected: All 1406+ tests pass.

- [ ] **Step 6: Commit**

```bash
git status  # Review changes before staging
git add src/net/handler/quic/  # Stage only QUIC handler changes
git commit -m "chore(quic): remove debug artifacts and dead code"
```

### Task 6: API Consistency Review

**Files:**
- Modify: `src/net/socket/quic.rs`
- Modify: `src/net/socket/mod.rs`

- [ ] **Step 1: Create QuicConfig struct**

Bundle TLS config + transport params into a unified config, matching TCP's pattern:

```rust
// src/net/socket/quic.rs

/// Configuration for a QUIC listener or connection.
pub struct QuicConfig {
    pub tls: Arc<ServerConfig>,  // or ClientConfig for connect
    pub transport: TransportParams,
}
```

Alternatively, keep separate since TLS config type differs (ServerConfig vs ClientConfig). Decision: keep `listen()` taking `tls_config` + optional params (current API is fine), but add `QuicServerConfig` and `QuicClientConfig` convenience types if warranted. Review existing TCP pattern at `src/net/socket/tcp.rs:20-21` (`TcpConfig` bundles backlog + buffer sizes).

**Minimum change:** Keep current API shape but fix the error type.

- [ ] **Step 2: Fix listen error type**

Change `QuicListener::listen()` and `listen_with_config()` from returning `Result<Self, QuicError>` to `Result<Self, BindError>` for consistency with TCP (`src/net/socket/tcp.rs:41`):

```rust
// Before (quic.rs:48-54):
pub fn listen(...) -> Result<Self, QuicError> {

// After:
pub fn listen(...) -> Result<Self, BindError> {
```

Update `listen_with_config()` similarly. The internal `handler.listen_with_queue()` returns `Option<LocalQueue<usize>>` — map `None` to `BindError::PortInUse` or a new `BindError` variant.

- [ ] **Step 3: Verify close() and Drop on QuicConnection**

Both already exist: `close()` at `quic.rs:281-296` and `Drop` at `quic.rs:304+`. Verify `close()` sends CONNECTION_CLOSE and `Drop` calls `close(0)`. This is a verification step, not implementation — just read and confirm correctness.

- [ ] **Step 4: Verify exports in socket/mod.rs**

Check `src/net/socket/mod.rs:7-10` — ensure all public QUIC types are re-exported. Will need to add new types as they're created in later phases (TokenStore, RecvDatagram, etc.).

- [ ] **Step 5: Run tests**

Run: `cargo test`
Expected: All tests pass. Some existing tests may need minor adjustment if they construct `QuicListener` and check error types.

- [ ] **Step 6: Commit**

```bash
git add src/net/socket/quic.rs src/net/socket/mod.rs
git commit -m "refactor(quic): align socket API with TCP/UDP patterns (BindError, Drop)"
```

---

## Phase 2: Variable-Length CIDs

### Task 7: Configurable CID Length

**Files:**
- Modify: `src/net/handler/quic/transport/params.rs:43-71`
- Modify: `src/net/handler/quic/handler.rs:30-38, 41-50, 932-1008`
- Test: `src/net/handler/quic/tests/params_test.rs`

- [ ] **Step 1: Write failing test for configurable CID length**

```rust
// In params_test.rs or a new cid_config_test section in e2e_test.rs
#[test]
fn cid_length_configurable() {
    let params = TransportParams {
        cid_length: Some(4),
        ..Default::default()
    };
    assert_eq!(params.cid_length, Some(4));

    // CID length > 20 should be rejected
    let invalid = TransportParams {
        cid_length: Some(21),
        ..Default::default()
    };
    assert!(invalid.validate_cid_length().is_err());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test cid_length_configurable`
Expected: Compile error — `cid_length` field doesn't exist yet.

- [ ] **Step 3: Add cid_length field to TransportParams**

Add to `src/net/handler/quic/transport/params.rs` `TransportParams` struct:

```rust
/// Local CID length (0-20, default 8). Not a wire parameter — local config only.
pub cid_length: Option<u8>,
```

Default to `None` (meaning use handler's default of 8). Add validation method:

```rust
pub fn validate_cid_length(&self) -> Result<(), TransportError> {
    if let Some(len) = self.cid_length {
        if len > 20 {
            return Err(TransportError::transport_parameter_error(
                "CID length must be 0-20",
            ));
        }
    }
    Ok(())
}
```

- [ ] **Step 4: Wire cid_length into handler**

In `handler.rs`, modify `listen_with_queue()` and `initiate_connection()` to read `params.cid_length` and use it instead of the hardcoded `local_cid_len: 8`:

```rust
// In initiate_connection(), around line 940-945:
let cid_len = transport_params.cid_length.unwrap_or(self.local_cid_len as u8) as usize;
// Generate DCID and SCID with cid_len bytes
```

- [ ] **Step 5: Run tests**

Run: `cargo test`

- [ ] **Step 6: Commit**

```bash
git add src/net/handler/quic/transport/params.rs src/net/handler/quic/handler.rs
git commit -m "feat(quic): add configurable CID length to TransportParams"
```

### Task 8: Zero-Length CID 5-Tuple Fallback

**Files:**
- Modify: `src/net/handler/quic/handler.rs:30-38`
- Create test in: `src/net/handler/quic/tests/e2e_test.rs`

- [ ] **Step 1: Write failing test**

```rust
#[test]
fn e2e_zero_length_cid() {
    // 1. Set up client with cid_length = 0
    // 2. Client initiates connection (generates zero-length SCID)
    // 3. Server receives Initial with zero-length SCID
    // 4. drive_handshake()
    // 5. Client sends short header packet (no DCID field)
    // 6. Server demuxes via 5-tuple fallback
    // 7. Verify data received correctly
}
```

- [ ] **Step 2: Define FiveTuple type and add fallback map to handler**

```rust
// In handler.rs:
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FiveTuple {
    local_addr: IpAddress,
    local_port: u16,
    remote_addr: IpAddress,
    remote_port: u16,
}

pub struct QuicHandler {
    connections: Slab<QuicConnectionState>,
    cid_map: FxHashMap<ConnectionId, usize>,
    five_tuple_map: FxHashMap<FiveTuple, usize>,  // NEW: fallback for zero-length CIDs
    listeners: FxHashMap<u16, ListenerState>,
    // ...
}
```

- [ ] **Step 3: Wire 5-tuple fallback into packet demux**

In `process_ipv4()`/`process_ipv6()`, when short header DCID lookup fails in `cid_map`, try `five_tuple_map`:

```rust
// After CID lookup fails:
let conn_key = self.cid_map.get(&dcid)
    .or_else(|| {
        let tuple = FiveTuple { local_addr, local_port, remote_addr, remote_port };
        self.five_tuple_map.get(&tuple)
    })
    .copied();
```

- [ ] **Step 4: Register 5-tuple on connection creation when CID is zero-length**

In `initiate_connection()` and server connection creation, if CID length is 0:

```rust
if conn.scid.is_empty() {
    let tuple = FiveTuple { local_addr, local_port, remote_addr, remote_port };
    self.five_tuple_map.insert(tuple, conn_key);
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test e2e_zero_length_cid`

- [ ] **Step 6: Commit**

```bash
git add src/net/handler/quic/handler.rs src/net/handler/quic/tests/e2e_test.rs
git commit -m "feat(quic): add 5-tuple fallback demux for zero-length CIDs"
```

### Task 9: CID Length Integration Tests

**Files:**
- Modify: `src/net/handler/quic/tests/e2e_test.rs`

- [ ] **Step 1: Write CID length variant tests**

```rust
#[test]
fn e2e_cid_length_4_bytes() {
    // Same as full lifecycle but with cid_length = 4
    // Verify packet parsing works with 4-byte CIDs
}

#[test]
fn e2e_cid_length_20_bytes() {
    // Same with cid_length = 20 (max)
}

#[test]
fn cid_length_21_rejected() {
    let params = TransportParams {
        cid_length: Some(21),
        ..Default::default()
    };
    assert!(params.validate_cid_length().is_err());
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test e2e_cid_length cid_length_21`

- [ ] **Step 3: Commit**

```bash
git add src/net/handler/quic/tests/e2e_test.rs
git commit -m "test(quic): add integration tests for various CID lengths"
```

---

## Phase 3: Feature Additions

### Task 10: TokenStore Trait + In-Memory Implementation

**Files:**
- Modify: `src/net/socket/quic.rs`
- Modify: `src/net/socket/mod.rs`

- [ ] **Step 1: Write failing test**

```rust
#[test]
fn token_store_in_memory() {
    let store = InMemoryTokenStore::new();
    assert!(store.get("example.com", QUIC_VERSION_1).is_none());

    store.put("example.com", QUIC_VERSION_1, vec![1, 2, 3]);
    assert_eq!(store.get("example.com", QUIC_VERSION_1), Some(vec![1, 2, 3]));

    // Different version should not match
    assert!(store.get("example.com", QUIC_VERSION_2).is_none());

    // Different server should not match
    assert!(store.get("other.com", QUIC_VERSION_1).is_none());
}
```

- [ ] **Step 2: Implement TokenStore trait and InMemoryTokenStore**

```rust
// In src/net/socket/quic.rs:

use std::cell::RefCell;
use std::collections::HashMap;

/// Store for QUIC address validation tokens (RFC 9000 §8.1).
/// Keyed by (server_name, version) per RFC 9369 §5.
pub trait TokenStore {
    fn get(&self, server_name: &str, version: u32) -> Option<Vec<u8>>;
    fn put(&self, server_name: &str, version: u32, token: Vec<u8>);
}

/// In-memory token store using RefCell for interior mutability.
pub struct InMemoryTokenStore {
    tokens: RefCell<HashMap<(String, u32), Vec<u8>>>,
}

impl InMemoryTokenStore {
    pub fn new() -> Self {
        Self { tokens: RefCell::new(HashMap::new()) }
    }
}

impl TokenStore for InMemoryTokenStore {
    fn get(&self, server_name: &str, version: u32) -> Option<Vec<u8>> {
        self.tokens.borrow().get(&(server_name.to_string(), version)).cloned()
    }
    fn put(&self, server_name: &str, version: u32, token: Vec<u8>) {
        self.tokens.borrow_mut().insert((server_name.to_string(), version), token);
    }
}
```

- [ ] **Step 3: Export from socket/mod.rs**

Add `InMemoryTokenStore, TokenStore` to the QUIC re-exports.

- [ ] **Step 4: Run test**

Run: `cargo test token_store_in_memory`

- [ ] **Step 5: Commit**

```bash
git add src/net/socket/quic.rs src/net/socket/mod.rs
git commit -m "feat(quic): add TokenStore trait and InMemoryTokenStore"
```

### Task 10b: NEW_TOKEN Frame Wire Format

The `QuicFrame::NewToken` variant already exists in `frame.rs:35` but we need to verify it parses correctly and add serialization support for the server to emit NEW_TOKEN frames.

**Files:**
- Modify: `src/net/handler/quic/transport/frame.rs`
- Modify: `src/net/handler/quic/tests/frame_test.rs`

- [ ] **Step 1: Write test for NEW_TOKEN frame round-trip**

```rust
#[test]
fn parse_new_token_frame() {
    let token = vec![0x01, 0x02, 0x03, 0x04];
    let mut buf = vec![0x07]; // NEW_TOKEN type
    let mut varint_buf = [0u8; 8];
    let n = encode_varint(token.len() as u64, &mut varint_buf);
    buf.extend_from_slice(&varint_buf[..n]);
    buf.extend_from_slice(&token);

    let (frame, consumed) = parse_frame(&buf).unwrap();
    match frame {
        QuicFrame::NewToken(ntf) => assert_eq!(ntf.token, token),
        _ => panic!("expected NewToken frame"),
    }
    assert_eq!(consumed, buf.len());
}
```

- [ ] **Step 2: Add NEW_TOKEN frame serialization to frame_writer**

Add `write_new_token(token: &[u8])` to the frame writer in `transport/frame_writer.rs` so `generate_packets()` can emit NEW_TOKEN frames:

```rust
pub fn write_new_token(buf: &mut [u8], offset: &mut usize, token: &[u8]) {
    buf[*offset] = 0x07; // NEW_TOKEN type
    *offset += 1;
    *offset += encode_varint(token.len() as u64, &mut buf[*offset..]);
    buf[*offset..*offset + token.len()].copy_from_slice(token);
    *offset += token.len();
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test parse_new_token`

- [ ] **Step 4: Commit**

```bash
git add src/net/handler/quic/transport/frame.rs src/net/handler/quic/transport/frame_writer.rs \
        src/net/handler/quic/tests/frame_test.rs
git commit -m "feat(quic): add NEW_TOKEN frame serialization (RFC 9000 §19.7)"
```

### Task 11: NEW_TOKEN Server-Side Token Generation

**Files:**
- Create: `src/net/handler/quic/token_crypto.rs`
- Modify: `src/net/handler/quic/mod.rs`
- Create: `src/net/handler/quic/tests/new_token_test.rs`
- Modify: `src/net/handler/quic/tests/mod.rs`

- [ ] **Step 1: Write failing test for token encrypt/decrypt**

```rust
// src/net/handler/quic/tests/new_token_test.rs
#[test]
fn token_encrypt_decrypt_roundtrip() {
    let secret = [0xABu8; 32]; // server secret key
    let token_data = NewTokenData {
        token_type: TokenType::NewToken,
        client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        timestamp_secs: 1000,
        original_dcid: ConnectionId::from_slice(&[1,2,3,4,5,6,7,8]),
        version: QUIC_VERSION_1,
    };

    let encrypted = encrypt_new_token(&secret, &token_data).unwrap();
    let decrypted = decrypt_new_token(&secret, &encrypted).unwrap();

    assert_eq!(decrypted.token_type, TokenType::NewToken);
    assert_eq!(decrypted.version, QUIC_VERSION_1);
}
```

- [ ] **Step 2: Implement token_crypto.rs**

```rust
// src/net/handler/quic/token_crypto.rs

use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

/// Discriminates Retry tokens from NEW_TOKEN tokens (RFC 9000 §8.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TokenType {
    Retry = 0x00,
    NewToken = 0x01,
}

pub struct NewTokenData {
    pub token_type: TokenType,
    pub client_ip: IpAddr,
    pub timestamp_secs: u64,
    pub original_dcid: ConnectionId,
    pub version: u32,
}

/// Encrypt token data with AES-256-GCM. Nonce derived from timestamp.
pub fn encrypt_new_token(secret: &[u8; 32], data: &NewTokenData) -> Result<Vec<u8>, ()> {
    // Serialize: type(1) + ip(4 or 16) + timestamp(8) + dcid_len(1) + dcid + version(4)
    // Encrypt with AES-256-GCM, nonce = timestamp bytes zero-padded to 12
    // Return: nonce_prefix(4 bytes of timestamp) + ciphertext + tag
    todo!() // Implement
}

/// Decrypt and validate token.
pub fn decrypt_new_token(secret: &[u8; 32], token: &[u8]) -> Result<NewTokenData, ()> {
    // Reverse of encrypt
    todo!() // Implement
}
```

- [ ] **Step 3: Register module**

Add `pub(crate) mod token_crypto;` to `src/net/handler/quic/mod.rs`.
Add `mod new_token_test;` to `src/net/handler/quic/tests/mod.rs`.

- [ ] **Step 4: Implement encrypt/decrypt**

Replace the `todo!()` stubs with actual AES-256-GCM encryption using `ring`. The nonce is derived from the timestamp (8 bytes) + 4 zero bytes = 12-byte nonce.

- [ ] **Step 5: Run test**

Run: `cargo test token_encrypt_decrypt`

- [ ] **Step 6: Add token expiry and IP validation tests**

```rust
#[test]
fn token_expired() {
    // Create token with old timestamp, verify is_expired() returns true
}

#[test]
fn token_type_discriminator() {
    // Create Retry token, verify decrypt identifies it as Retry
    // Create NewToken, verify decrypt identifies it as NewToken
}
```

- [ ] **Step 7: Commit**

```bash
git add src/net/handler/quic/token_crypto.rs src/net/handler/quic/mod.rs \
        src/net/handler/quic/tests/new_token_test.rs src/net/handler/quic/tests/mod.rs
git commit -m "feat(quic): implement NEW_TOKEN encryption/decryption (RFC 9000 §8.1)"
```

### Task 12: NEW_TOKEN Server Emission + Client Validation

**Files:**
- Modify: `src/net/handler/quic/processor.rs`
- Modify: `src/net/handler/quic/connection.rs`
- Modify: `src/net/handler/quic/handler.rs`
- Modify: `src/net/handler/quic/tests/new_token_test.rs`

- [ ] **Step 1: Add token_secret to connection state**

In `connection.rs`, add to `QuicConnectionState`:

```rust
/// Server secret for token encryption (32 bytes, randomly generated or configured)
pub token_secret: Option<[u8; 32]>,
/// Pending NEW_TOKEN frame to send
pub pending_new_token: Option<Vec<u8>>,
```

- [ ] **Step 2: Generate NEW_TOKEN after handshake**

In `processor.rs`, after handshake completes (when state transitions to `Established`), if server side and `token_secret` is set:

```rust
// After setting state = Established:
if conn.side == Side::Server {
    if let Some(ref secret) = conn.token_secret {
        let token_data = NewTokenData {
            token_type: TokenType::NewToken,
            client_ip: conn.remote_addr.into(),
            timestamp_secs: now.as_secs(),
            original_dcid: conn.dcid,
            version: conn.version,
        };
        if let Ok(encrypted) = encrypt_new_token(secret, &token_data) {
            conn.pending_new_token = Some(encrypted);
        }
    }
}
```

- [ ] **Step 3: Emit NEW_TOKEN frame in generate_packets()**

In `processor.rs` `generate_packets()`, after control frames and before stream data, check `conn.pending_new_token` and emit a NEW_TOKEN frame (type 0x07, varint length, token bytes).

- [ ] **Step 4: Handle incoming token in server Initial processing**

In `handler.rs`, when receiving a client Initial with a non-empty token field: call `decrypt_new_token()`, validate type (must be NewToken, not Retry), check IP, check expiry, check version. If valid, mark address as validated (skip Retry, lift amplification limit).

- [ ] **Step 5: Write integration test**

```rust
#[test]
fn new_token_round_trip() {
    // 1. Set up server with token_secret
    // 2. Complete handshake
    // 3. Server generates NEW_TOKEN frame
    // 4. pump_packets to client
    // 5. Client extracts token from NEW_TOKEN frame
    // 6. New connection: client attaches token in Initial
    // 7. Server validates token, skips Retry
    // 8. Verify: amplification limit lifted
}
```

- [ ] **Step 6: Run tests**

Run: `cargo test new_token`

- [ ] **Step 7: Commit**

```bash
git add src/net/handler/quic/processor.rs src/net/handler/quic/connection.rs \
        src/net/handler/quic/handler.rs src/net/handler/quic/tests/new_token_test.rs
git commit -m "feat(quic): implement NEW_TOKEN emission and validation (RFC 9000 §8.1)"
```

### Task 12b: Client-Side NEW_TOKEN Reception + Token Secret Plumbing

**Files:**
- Modify: `src/net/handler/quic/processor.rs`
- Modify: `src/net/handler/quic/handler.rs`
- Modify: `src/net/socket/quic.rs`
- Modify: `src/net/handler/quic/tests/new_token_test.rs`

- [ ] **Step 1: Add NEW_TOKEN dispatch arm for client**

In `processor.rs` `dispatch_frames()`, handle `QuicFrame::NewToken` on the client side:

```rust
QuicFrame::NewToken(ntf) => {
    if conn.side == Side::Client {
        // Store the token for future connections
        conn.received_new_token = Some(ntf.token);
        conn.event_queue.push(QuicEvent::NewTokenReceived);
    }
    // Server receiving NEW_TOKEN is a protocol error (RFC 9000 §19.7)
}
```

Add `received_new_token: Option<Vec<u8>>` and `NewTokenReceived` event to connection/event.

- [ ] **Step 2: Wire token_secret from listener config to connection state**

In `handler.rs`, when creating a server connection from a listener:
- Add `token_secret: Option<[u8; 32]>` to `ListenerState` (populated from config, or randomly generated via `ring::rand::SystemRandom`)
- Copy `token_secret` from `ListenerState` to `QuicConnectionState` on connection creation

In `socket/quic.rs`, add `token_secret` as optional field in `listen_with_config()` params or as a separate setter.

- [ ] **Step 3: Wire TokenStore into client connect path**

In `socket/quic.rs`, update `QuicConnection::connect()` to accept `token_store: Option<&dyn TokenStore>`:

```rust
pub fn connect(
    addr: IpAddress, port: u16,
    server_name: &str, tls_config: Arc<ClientConfig>,
    token_store: Option<&dyn TokenStore>,
) -> Result<Connect, QuicError> {
    // If token_store provided, look up token for (server_name, version)
    // Pass token to handler.initiate_connection() for Initial packet
}
```

In `handler.rs` `initiate_connection()`, accept `initial_token: Option<Vec<u8>>` and store it in connection state so the packet builder includes it in the Initial packet's Token field.

- [ ] **Step 4: Write test for client token reception and reuse**

```rust
#[test]
fn client_receives_and_reuses_token() {
    // 1. Set up server with token_secret, client with InMemoryTokenStore
    // 2. Handshake, server emits NEW_TOKEN
    // 3. Client receives token, stores in TokenStore
    // 4. Second connection: client retrieves token from store
    // 5. Client sends Initial with token attached
    // 6. Server validates token successfully
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test new_token`

- [ ] **Step 6: Commit**

```bash
git add src/net/handler/quic/processor.rs src/net/handler/quic/handler.rs \
        src/net/socket/quic.rs src/net/handler/quic/connection.rs \
        src/net/handler/quic/event.rs src/net/handler/quic/tests/new_token_test.rs
git commit -m "feat(quic): implement client-side NEW_TOKEN reception and token reuse"
```

### Task 13: Compatible Version Negotiation — Transport Param + Validation

Split into two tasks: 13 (param encoding + validation) and 13b (negotiation logic + HKDF).

**Files:**
- Modify: `src/net/handler/quic/transport/params.rs`
- Modify: `src/net/handler/quic/transport/version.rs`
- Create: `src/net/handler/quic/tests/compat_vn_test.rs`
- Modify: `src/net/handler/quic/tests/mod.rs`

- [ ] **Step 1: Write failing test for version_information encode/decode**

```rust
// src/net/handler/quic/tests/compat_vn_test.rs
#[test]
fn version_information_encode_decode() {
    let mut params = TransportParams::default();
    params.version_information = Some(VersionInformation {
        chosen_version: QUIC_VERSION_1,
        other_versions: vec![QUIC_VERSION_1, QUIC_VERSION_2],
    });
    let mut buf = [0u8; 512];
    let len = params.encode(&mut buf);
    let decoded = TransportParams::decode(&buf[..len]).unwrap();
    let vi = decoded.version_information.unwrap();
    assert_eq!(vi.chosen_version, QUIC_VERSION_1);
    assert!(vi.other_versions.contains(&QUIC_VERSION_2));
}
```

- [ ] **Step 2: Add version_information field to TransportParams**

In `params.rs`, add to the struct (around line 70):

```rust
pub version_information: Option<VersionInformation>,
```

Add the parameter ID constant:

```rust
const VERSION_INFORMATION: u64 = 0x11;
```

Implement encode/decode for the new parameter in the existing `encode()` and `decode()` methods.

- [ ] **Step 3: Run version_information test**

Run: `cargo test version_information_encode_decode`

- [ ] **Step 4: Implement server-side compatible negotiation**

In `processor.rs`, after transport params are decoded from the client (in the handshake processing path):

```rust
// Check if server prefers a different compatible version
if let Some(ref vi) = peer_params.version_information {
    if vi.other_versions.contains(&QUIC_VERSION_2) && conn.version == QUIC_VERSION_1 {
        // Server prefers v2, switch
        conn.negotiated_version = Some(QUIC_VERSION_2);
        // Handshake and 1-RTT packets use v2 HKDF labels from here
    }
}
```

Add `negotiated_version: Option<u32>` to `QuicConnectionState`.

- [ ] **Step 5: Implement downgrade prevention validation**

Both sides validate after transport params exchange:

```rust
// If we sent version_information, peer MUST also send it
// Peer's chosen_version must be in our available_versions
// Our chosen_version must be in peer's available_versions
// Otherwise: CONNECTION_CLOSE with TRANSPORT_PARAMETER_ERROR
```

- [ ] **Step 6: Write integration test for v1→v2 negotiation**

```rust
#[test]
fn compat_vn_v1_to_v2() {
    // Client supports v1+v2, connects with v1
    // Server prefers v2
    // Server switches Handshake/1-RTT to v2
    // Client detects version switch, uses v2 for subsequent packets
    // Handshake completes successfully
}

#[test]
fn compat_vn_downgrade_detection() {
    // Server claims to support only v1 in version_information
    // but sends v2 packets
    // Client detects mismatch → CONNECTION_CLOSE
}
```

- [ ] **Step 7: Run tests**

Run: `cargo test compat_vn`

- [ ] **Step 8: Commit**

```bash
git add src/net/handler/quic/transport/params.rs src/net/handler/quic/transport/version.rs \
        src/net/handler/quic/tests/compat_vn_test.rs src/net/handler/quic/tests/mod.rs
git commit -m "feat(quic): add version_information transport param and validation (RFC 9369 §4.1)"
```

### Task 13b: Compatible VN — Negotiation Logic + HKDF Label Switching

**Files:**
- Modify: `src/net/handler/quic/processor.rs`
- Modify: `src/net/handler/quic/connection.rs`
- Modify: `src/net/handler/quic/crypto/tls.rs`
- Modify: `src/net/handler/quic/transport/version.rs`
- Modify: `src/net/handler/quic/tests/compat_vn_test.rs`

- [ ] **Step 1: Add HKDF label helpers to version.rs**

```rust
/// Returns the HKDF labels for a given QUIC version.
/// V1: "quic key", "quic iv", "quic hp", "quic ku"
/// V2: "quicv2 key", "quicv2 iv", "quicv2 hp", "quicv2 ku"
pub fn hkdf_label_prefix(version: u32) -> &'static str {
    match version {
        QUIC_VERSION_2 => "quicv2",
        _ => "quic",
    }
}
```

- [ ] **Step 2: Wire HKDF labels into crypto/tls.rs**

In `CryptoState::new_client()` and `CryptoState::new_server()`, pass the QUIC version to rustls so it uses the correct labels. Rustls handles this via `rustls::quic::Version::V1` vs `V2` — ensure we map our `version` constant to the correct rustls enum:

```rust
let rustls_version = match version {
    QUIC_VERSION_2 => rustls::quic::Version::V2,
    _ => rustls::quic::Version::V1,
};
```

Verify this is already correct in the existing code, or fix it.

- [ ] **Step 3: Implement server-side version switching in processor.rs**

After transport params are decoded from client, if server prefers a different compatible version:

```rust
if let Some(ref vi) = peer_params.version_information {
    let negotiated = select_compatible_version(&vi.other_versions, &our_versions);
    if negotiated != conn.version {
        conn.negotiated_version = Some(negotiated);
        // Handshake and 1-RTT packets will use negotiated version's headers
    }
}
```

Add `negotiated_version: Option<u32>` to `QuicConnectionState` in `connection.rs`.

- [ ] **Step 4: Update generate_packets() to use negotiated version**

In the packet builder, when writing Handshake and 1-RTT long headers, use `conn.negotiated_version.unwrap_or(conn.version)` for the Version field.

- [ ] **Step 5: Implement client-side version detection**

In `process_packet()`, when client receives a long header with a different Version field than `conn.version`:

```rust
if conn.side == Side::Client && header_version != conn.version {
    conn.negotiated_version = Some(header_version);
    // Switch subsequent Initial packets to negotiated version
}
```

- [ ] **Step 6: Write and run integration tests**

Use the tests already outlined in Task 13 Step 6 (`compat_vn_v1_to_v2`, `compat_vn_downgrade_detection`).

Run: `cargo test compat_vn`

- [ ] **Step 7: Commit**

```bash
git add src/net/handler/quic/processor.rs src/net/handler/quic/connection.rs \
        src/net/handler/quic/crypto/tls.rs src/net/handler/quic/transport/version.rs \
        src/net/handler/quic/tests/compat_vn_test.rs
git commit -m "feat(quic): implement compatible VN negotiation logic and HKDF switching"
```

### Task 14: Preferred Address Transport Parameter

**Files:**
- Modify: `src/net/handler/quic/transport/params.rs`
- Modify: `src/net/handler/quic/connection.rs`
- Create: `src/net/handler/quic/tests/preferred_addr_test.rs`
- Modify: `src/net/handler/quic/tests/mod.rs`

- [ ] **Step 1: Write failing test for preferred_address encode/decode**

```rust
#[test]
fn preferred_address_encode_decode() {
    let pa = PreferredAddress {
        ipv4_addr: Some((Ipv4Addr::new(192, 168, 1, 1), 4433)),
        ipv6_addr: None,
        connection_id: ConnectionId::from_slice(&[0x01, 0x02, 0x03, 0x04]),
        stateless_reset_token: [0xAA; 16],
    };
    let mut params = TransportParams::default();
    params.preferred_address = Some(pa);
    let mut buf = [0u8; 512];
    let len = params.encode(&mut buf);
    let decoded = TransportParams::decode(&buf[..len]).unwrap();
    let dpa = decoded.preferred_address.unwrap();
    assert_eq!(dpa.ipv4_addr, Some((Ipv4Addr::new(192, 168, 1, 1), 4433)));
    assert_eq!(dpa.connection_id.len(), 4);
}
```

- [ ] **Step 2: Define PreferredAddress struct and add to TransportParams**

```rust
// In params.rs:
const PREFERRED_ADDRESS: u64 = 0x0d;

pub struct PreferredAddress {
    pub ipv4_addr: Option<(Ipv4Addr, u16)>,
    pub ipv6_addr: Option<(Ipv6Addr, u16)>,
    pub connection_id: ConnectionId,
    pub stateless_reset_token: [u8; 16],
}

// In TransportParams:
pub preferred_address: Option<PreferredAddress>,
```

Implement encode/decode per the wire format in the spec (§18.2).

- [ ] **Step 3: Run test**

Run: `cargo test preferred_address_encode_decode`

- [ ] **Step 4: Commit**

```bash
git add src/net/handler/quic/transport/params.rs \
        src/net/handler/quic/tests/preferred_addr_test.rs src/net/handler/quic/tests/mod.rs
git commit -m "feat(quic): add preferred_address transport parameter (RFC 9000 §18.2)"
```

### Task 15: Preferred Address Client Migration

**Files:**
- Modify: `src/net/handler/quic/processor.rs`
- Modify: `src/net/handler/quic/handler.rs`
- Modify: `src/net/handler/quic/tests/preferred_addr_test.rs`

- [ ] **Step 1: Write failing test for preferred address migration**

```rust
#[test]
fn preferred_address_client_migrates() {
    // 1. Server config includes preferred_address (different IP)
    // 2. Client handshakes, receives preferred_address in transport params
    // 3. After Established, client initiates path validation to preferred address
    //    using the CID from preferred_address (sequence number 1)
    // 4. PATH_CHALLENGE sent to preferred address
    // 5. Server responds with PATH_RESPONSE
    // 6. Client completes migration
    // 7. Subsequent data flows on new path
}

#[test]
fn preferred_address_with_disable_active_migration() {
    // Server sets both preferred_address AND disable_active_migration
    // Client STILL migrates to preferred address (RFC 9000 §9.6)
}

#[test]
fn preferred_address_cid_sequence_number() {
    // Verify the CID from preferred_address has sequence number 1
    // Verify subsequent NEW_CONNECTION_ID frames start at sequence 2
}

#[test]
fn preferred_address_path_validation_failure() {
    // Server advertises preferred address
    // Path validation to preferred address times out (no PATH_RESPONSE)
    // Client stays on original path, connection continues normally
}

#[test]
fn preferred_address_ipv4_only() {
    // Server advertises only IPv4 preferred address (IPv6 zeroed)
    // Client migrates to IPv4 address
}
```

- [ ] **Step 2: Implement client-side migration trigger**

In `processor.rs`, after handshake completes on client side, check for `peer_params.preferred_address`:

```rust
if conn.side == Side::Client {
    if let Some(ref pa) = conn.peer_params.preferred_address {
        // Register the preferred address CID with sequence number 1
        conn.scid_set.push_with_seq(pa.connection_id, 1);
        // Initiate path validation to preferred address
        conn.pending_preferred_migration = Some(PreferredMigration {
            addr: pa.best_addr_for(conn.remote_addr), // pick IPv4 or IPv6
            port: pa.port_for(conn.remote_addr),
            cid: pa.connection_id,
        });
    }
}
```

- [ ] **Step 3: Handle preferred address in handler's packet generation**

When `pending_preferred_migration` is set, generate PATH_CHALLENGE to the preferred address. Use existing migration machinery from `handler.rs`.

- [ ] **Step 4: Run tests**

Run: `cargo test preferred_address`

- [ ] **Step 5: Commit**

```bash
git add src/net/handler/quic/processor.rs src/net/handler/quic/handler.rs \
        src/net/handler/quic/tests/preferred_addr_test.rs
git commit -m "feat(quic): implement preferred address client migration (RFC 9000 §9.6)"
```

### Task 16: DATAGRAM Frame Parser

**Files:**
- Modify: `src/net/handler/quic/transport/frame.rs`
- Modify: `src/net/handler/quic/tests/frame_test.rs`

- [ ] **Step 1: Write failing test for DATAGRAM frame parsing**

```rust
#[test]
fn parse_datagram_frame() {
    // DATAGRAM (0x30) — no length, extends to end of packet
    let payload = b"hello datagram";
    let mut buf = vec![0x30]; // type
    buf.extend_from_slice(payload);

    let (frame, consumed) = parse_frame(&buf).unwrap();
    assert!(matches!(frame, QuicFrame::Datagram { .. }));
    assert_eq!(consumed, buf.len()); // consumes entire remaining buffer
}

#[test]
fn parse_datagram_with_length_frame() {
    // DATAGRAM_WITH_LENGTH (0x31) — varint length prefix
    let payload = b"hello datagram";
    let mut buf = vec![0x31];
    let mut varint_buf = [0u8; 8];
    let n = encode_varint(payload.len() as u64, &mut varint_buf);
    buf.extend_from_slice(&varint_buf[..n]);
    buf.extend_from_slice(payload);

    let (frame, consumed) = parse_frame(&buf).unwrap();
    assert!(matches!(frame, QuicFrame::Datagram { .. }));
}
```

- [ ] **Step 2: Add Datagram variant to QuicFrame enum**

In `frame.rs`, add to the enum (after HandshakeDone):

```rust
/// DATAGRAM frame (RFC 9221). data is the payload.
Datagram { data: Vec<u8> },
```

- [ ] **Step 3: Add parse arms for 0x30 and 0x31**

In `parse_frame()`, before the catch-all `_` arm (line 502):

```rust
// DATAGRAM (0x30) — extends to end of packet
0x30 => {
    let data = buf[type_len..].to_vec();
    Ok((QuicFrame::Datagram { data }, buf.len()))
}

// DATAGRAM_WITH_LENGTH (0x31)
0x31 => {
    let (length, len_size) = decode_varint(&buf[type_len..])?;
    let start = type_len + len_size;
    let end = start + length as usize;
    if end > buf.len() { return Err(FrameParseError::BufferTooShort); }
    let data = buf[start..end].to_vec();
    Ok((QuicFrame::Datagram { data }, end))
}
```

- [ ] **Step 4: Fix the unknown frame catch-all**

Change the catch-all from returning Padding to returning an error, since unknown frames make remaining data unparsable (RFC 9000 §19.21):

```rust
_ => {
    // RFC 9000 §19.21: frames are not self-describing. Unknown frame types
    // make the remainder of the packet unparsable.
    Err(FrameParseError::UnknownFrameType(frame_type))
}
```

Add `UnknownFrameType(u64)` variant to `FrameParseError`. Update callers to handle this — `dispatch_frames()` in `processor.rs` should stop processing the current packet but not close the connection (the packet is already authenticated).

- [ ] **Step 5: Run tests**

Run: `cargo test parse_datagram`

- [ ] **Step 6: Commit**

```bash
git add src/net/handler/quic/transport/frame.rs src/net/handler/quic/tests/frame_test.rs
git commit -m "feat(quic): add DATAGRAM frame parsing (RFC 9221) and fix unknown frame handling"
```

### Task 17: DATAGRAM Negotiation + Queues

**Files:**
- Create: `src/net/handler/quic/datagram.rs`
- Modify: `src/net/handler/quic/mod.rs`
- Modify: `src/net/handler/quic/transport/params.rs`
- Modify: `src/net/handler/quic/connection.rs`
- Modify: `src/net/handler/quic/event.rs`
- Create: `src/net/handler/quic/tests/datagram_test.rs`
- Modify: `src/net/handler/quic/tests/mod.rs`

- [ ] **Step 1: Add max_datagram_frame_size to TransportParams**

```rust
const MAX_DATAGRAM_FRAME_SIZE: u64 = 0x20;

// In TransportParams struct:
pub max_datagram_frame_size: Option<u64>,
```

Add encode/decode support.

- [ ] **Step 2: Create datagram.rs with send/recv queues**

```rust
// src/net/handler/quic/datagram.rs

use std::collections::VecDeque;

const DEFAULT_DATAGRAM_QUEUE_CAPACITY: usize = 64;

pub struct DatagramQueue {
    send: VecDeque<Vec<u8>>,
    recv: VecDeque<Vec<u8>>,
    capacity: usize,
    max_send_size: Option<u64>,  // peer's max_datagram_frame_size
    max_recv_size: Option<u64>,  // our max_datagram_frame_size
}

impl DatagramQueue {
    pub fn new(capacity: usize) -> Self { ... }

    /// Queue a datagram for sending. Drops oldest if full.
    pub fn send(&mut self, data: Vec<u8>) -> Result<(), DatagramError> {
        if let Some(max) = self.max_send_size {
            if data.len() as u64 > max { return Err(DatagramError::TooLarge); }
        } else {
            return Err(DatagramError::NotNegotiated);
        }
        if self.send.len() >= self.capacity {
            self.send.pop_front(); // drop oldest
        }
        self.send.push_back(data);
        Ok(())
    }

    /// Pop next datagram to send (for packet builder).
    pub fn pop_send(&mut self) -> Option<Vec<u8>> { self.send.pop_front() }

    /// Deliver received datagram.
    pub fn deliver(&mut self, data: Vec<u8>) {
        if self.recv.len() < self.capacity {
            self.recv.push_back(data);
        }
    }

    /// Read next received datagram.
    pub fn recv(&mut self) -> Option<Vec<u8>> { self.recv.pop_front() }

    pub fn has_pending_send(&self) -> bool { !self.send.is_empty() }
}
```

- [ ] **Step 3: Add DatagramReceived to QuicEvent**

In `event.rs`:

```rust
DatagramReceived,
```

- [ ] **Step 4: Add datagram queue to connection state**

In `connection.rs`:

```rust
pub datagrams: DatagramQueue,
```

Initialize in `QuicConnectionState::new()`.

- [ ] **Step 5: Write tests**

```rust
#[test]
fn datagram_queue_send_recv() {
    let mut q = DatagramQueue::new(4);
    q.max_send_size = Some(1200);
    q.max_recv_size = Some(1200);

    q.send(vec![1, 2, 3]).unwrap();
    assert_eq!(q.pop_send(), Some(vec![1, 2, 3]));
}

#[test]
fn datagram_queue_overflow_drops_oldest() {
    let mut q = DatagramQueue::new(2);
    q.max_send_size = Some(1200);
    q.send(vec![1]).unwrap();
    q.send(vec![2]).unwrap();
    q.send(vec![3]).unwrap(); // drops vec![1]
    assert_eq!(q.pop_send(), Some(vec![2]));
    assert_eq!(q.pop_send(), Some(vec![3]));
}

#[test]
fn datagram_too_large_rejected() {
    let mut q = DatagramQueue::new(4);
    q.max_send_size = Some(10);
    assert!(q.send(vec![0; 20]).is_err());
}

#[test]
fn datagram_not_negotiated_rejected() {
    let mut q = DatagramQueue::new(4);
    // max_send_size is None (peer didn't advertise)
    assert!(q.send(vec![1]).is_err());
}
```

- [ ] **Step 6: Run tests**

Run: `cargo test datagram_queue`

- [ ] **Step 7: Commit**

```bash
git add src/net/handler/quic/datagram.rs src/net/handler/quic/mod.rs \
        src/net/handler/quic/transport/params.rs src/net/handler/quic/connection.rs \
        src/net/handler/quic/event.rs \
        src/net/handler/quic/tests/datagram_test.rs src/net/handler/quic/tests/mod.rs
git commit -m "feat(quic): add DATAGRAM queues and negotiation (RFC 9221)"
```

### Task 18: DATAGRAM Processor Integration + Socket API

**Files:**
- Modify: `src/net/handler/quic/processor.rs`
- Modify: `src/net/socket/quic.rs`
- Modify: `src/net/socket/mod.rs`
- Modify: `src/net/handler/quic/tests/datagram_test.rs`

- [ ] **Step 1: Add DATAGRAM dispatch in processor**

In `dispatch_frames()` (around line 616), add arm for `QuicFrame::Datagram`:

```rust
QuicFrame::Datagram { data } => {
    if conn.datagrams.max_recv_size.is_some() {
        conn.datagrams.deliver(data);
        conn.event_queue.push(QuicEvent::DatagramReceived);
    }
    // DATAGRAM frames are ack-eliciting (RFC 9221 §4)
    ack_eliciting = true;
}
```

- [ ] **Step 2: Emit DATAGRAM frames in generate_packets()**

In the packet builder section of `generate_packets()`, after stream data:

```rust
// Emit DATAGRAM frames (lower priority than streams)
while let Some(data) = conn.datagrams.pop_send() {
    let frame_len = 1 + varint_len(data.len() as u64) + data.len();
    if builder.remaining() < frame_len {
        // Put it back — doesn't fit in this packet
        conn.datagrams.send_queue_push_front(data);
        break;
    }
    builder.write_datagram_with_length(&data);
}
```

- [ ] **Step 3: Add socket API methods**

In `src/net/socket/quic.rs`, add to `QuicConnection`:

```rust
pub fn send_datagram(&self, data: &[u8]) -> Result<(), QuicError> {
    with_runtime_context(|ctx| {
        let handler = unsafe { &mut *ctx.quic_handler.get() };
        let conn = &mut handler.connections[self.conn_key];
        conn.datagrams.send(data.to_vec())
            .map_err(|_| QuicError::WouldBlock)
    })
}

pub fn recv_datagram(&self) -> RecvDatagram<'_> {
    RecvDatagram { conn: self }
}

pub fn max_datagram_size(&self) -> Option<usize> {
    with_runtime_context(|ctx| {
        let handler = unsafe { &*ctx.quic_handler.get() };
        let conn = &handler.connections[self.conn_key];
        conn.datagrams.max_send_size.map(|s| s as usize)
    })
}
```

Add `RecvDatagram` future that polls the datagram recv queue.

- [ ] **Step 4: Write integration test**

```rust
#[test]
fn e2e_datagram_bidirectional() {
    // 1. Both sides advertise max_datagram_frame_size = 1200
    // 2. Handshake
    // 3. Client sends datagram "ping"
    // 4. pump_packets
    // 5. Server receives "ping"
    // 6. Server sends datagram "pong"
    // 7. pump_packets
    // 8. Client receives "pong"
}

#[test]
fn e2e_datagram_not_negotiated() {
    // Server does NOT advertise max_datagram_frame_size
    // Client tries send_datagram() → error
}

#[test]
fn e2e_datagram_interleaved_with_streams() {
    // Send datagrams and stream data on the same connection concurrently
    // Verify both arrive correctly and don't interfere
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test datagram`

- [ ] **Step 6: Commit**

```bash
git add src/net/handler/quic/processor.rs src/net/socket/quic.rs src/net/socket/mod.rs \
        src/net/handler/quic/tests/datagram_test.rs
git commit -m "feat(quic): wire DATAGRAM frames into processor and socket API (RFC 9221)"
```

---

## Phase 4: Harden

### Task 19: Adversarial Packet-Level Tests

**Files:**
- Create: `src/net/handler/quic/tests/adversarial_test.rs`
- Modify: `src/net/handler/quic/tests/mod.rs`

- [ ] **Step 1: Write packet-level adversarial tests**

```rust
// src/net/handler/quic/tests/adversarial_test.rs

#[test]
fn truncated_packet() {
    // Build valid Initial packet, then truncate to half length
    // Feed to process_ipv4() → should not crash, packet silently dropped
}

#[test]
fn invalid_version_long_header() {
    // Long header with version 0xDEADBEEF (unknown)
    // Feed to handler → should trigger Version Negotiation response or drop
}

#[test]
fn dcid_length_exceeds_20() {
    // Long header with DCID length byte = 25
    // Feed to handler → drop, no crash
}

#[test]
fn corrupted_header_protection() {
    // Valid Initial packet but corrupt header protection bytes
    // Decryption should fail gracefully
}

#[test]
fn coalesced_packet_wrong_dcid() {
    // First packet: valid Initial with correct DCID
    // Second packet (coalesced): Handshake with wrong DCID
    // First should process, second should be dropped
}

#[test]
fn short_header_before_handshake() {
    // Send short header (1-RTT) to a connection still in Handshaking
    // Should be dropped (no 1-RTT keys yet)
}
```

- [ ] **Step 2: Register module**

Add `mod adversarial_test;` to `tests/mod.rs`.

- [ ] **Step 3: Run tests**

Run: `cargo test adversarial`

- [ ] **Step 4: Commit**

```bash
git add src/net/handler/quic/tests/adversarial_test.rs src/net/handler/quic/tests/mod.rs
git commit -m "test(quic): add adversarial packet-level tests"
```

### Task 20: Adversarial Frame-Level + Protocol-Level Tests

**Files:**
- Modify: `src/net/handler/quic/tests/adversarial_test.rs`

- [ ] **Step 1: Write frame-level adversarial tests**

```rust
#[test]
fn unknown_frame_type_discards_packet() {
    // Inject a frame with type 0xFF into a 1-RTT packet
    // Remaining frames in packet should not be processed
    // Connection should NOT be closed
}

#[test]
fn frame_beyond_packet_boundary() {
    // STREAM frame claiming length exceeds remaining packet bytes
    // Should be dropped, no crash
}

#[test]
fn stream_offset_exceeds_flow_control() {
    // STREAM frame with offset > MAX_STREAM_DATA
    // Should trigger FLOW_CONTROL_ERROR
}

#[test]
fn reset_stream_unknown_id_within_limits() {
    // RESET_STREAM for stream ID not yet created but within MAX_STREAMS
    // Should implicitly open the stream and all lower-numbered ones
}

#[test]
fn reset_stream_exceeds_max_streams() {
    // RESET_STREAM for stream ID beyond MAX_STREAMS
    // Should trigger STREAM_LIMIT_ERROR
}

#[test]
fn new_connection_id_retire_exceeds_sequence() {
    // NEW_CONNECTION_ID with retire_prior_to > sequence_number
    // Should trigger FRAME_ENCODING_ERROR
}

#[test]
fn ack_ranges_reference_unsent_packets() {
    // ACK frame with ranges referencing packet numbers we never sent
    // Should be ignored (no crash, no state corruption)
}

#[test]
fn connection_close_unknown_error_code() {
    // CONNECTION_CLOSE with error code 0xFFFF (unknown)
    // Should still be accepted gracefully, connection enters Draining
}

#[test]
fn max_stream_data_on_send_only_stream() {
    // MAX_STREAM_DATA for a locally-initiated send-only stream
    // Should trigger STREAM_STATE_ERROR
}
```

- [ ] **Step 2: Write protocol-level tests**

```rust
#[test]
fn amplification_limit_enforced() {
    // Server receives 1200-byte Initial
    // Server should send at most 3600 bytes before address validation
    // Count bytes in TX output, assert <= 3 * 1200
}

#[test]
fn client_initial_below_1200_dropped() {
    // Build Initial packet smaller than 1200 bytes
    // Server should drop it
}

#[test]
fn duplicate_packet_number_discarded() {
    // Send same packet twice (same PN)
    // Second should be silently dropped
    // Data should not be double-delivered
}

#[test]
fn stream_id_exceeds_max_streams() {
    // Open stream with ID beyond peer's MAX_STREAMS
    // Should trigger STREAM_LIMIT_ERROR close
}

#[test]
fn stream_id_gap_implicit_open() {
    // Open stream 0x08 (bidi #2) without opening 0x04 (bidi #1)
    // Stream 0x04 should be implicitly opened (RFC 9000 §2.1)
}

#[test]
fn data_on_wrong_initiator_stream() {
    // Server sends STREAM data on stream 0 (client-initiated)
    // as if server initiated it — should trigger STREAM_STATE_ERROR
}

#[test]
fn packet_during_draining_retransmits_close() {
    // Connection in Draining state receives a packet
    // Should retransmit cached CONNECTION_CLOSE (rate-limited to PTO interval)
    // Should NOT crash or process frames
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test adversarial`

- [ ] **Step 4: Commit**

```bash
git add src/net/handler/quic/tests/adversarial_test.rs
git commit -m "test(quic): add adversarial frame-level and protocol-level tests"
```

### Task 21: Criterion Benchmarks

**Files:**
- Create: `benches/quic.rs`
- Modify: `Cargo.toml` (add `[[bench]]` section if not present)

- [ ] **Step 1: Verify criterion setup in Cargo.toml**

Check that `Cargo.toml` has criterion in dev-dependencies and a `[[bench]]` section:

```toml
[[bench]]
name = "quic"
harness = false
```

- [ ] **Step 2: Write micro-benchmarks**

```rust
// benches/quic.rs
use criterion::{criterion_group, criterion_main, Criterion, black_box};

fn bench_varint_encode(c: &mut Criterion) {
    c.bench_function("varint_encode", |b| {
        let mut buf = [0u8; 8];
        b.iter(|| {
            black_box(encode_varint(black_box(16383), &mut buf));
        });
    });
}

fn bench_varint_decode(c: &mut Criterion) {
    let encoded = [0x7F, 0xFF]; // 16383 in 2-byte varint
    c.bench_function("varint_decode", |b| {
        b.iter(|| {
            black_box(decode_varint(black_box(&encoded)));
        });
    });
}

fn bench_frame_encode_decode(c: &mut Criterion) {
    // Encode/decode a STREAM frame
    c.bench_function("frame_encode_stream", |b| { ... });
    c.bench_function("frame_decode_stream", |b| { ... });
}

fn bench_connection_id_hash(c: &mut Criterion) {
    use std::hash::{Hash, Hasher};
    use rustc_hash::FxHasher;
    let cid = ConnectionId::from_slice(&[1,2,3,4,5,6,7,8]);
    c.bench_function("connection_id_hash", |b| {
        b.iter(|| {
            let mut h = FxHasher::default();
            black_box(&cid).hash(&mut h);
            black_box(h.finish());
        });
    });
}

fn bench_packet_protect(c: &mut Criterion) {
    // Set up Initial keys, protect a 1200-byte packet
    c.bench_function("packet_protect", |b| { ... });
}

fn bench_packet_unprotect(c: &mut Criterion) {
    c.bench_function("packet_unprotect", |b| { ... });
}
```

- [ ] **Step 3: Write macro-benchmarks**

```rust
fn bench_handshake_latency(c: &mut Criterion) {
    // Full client+server handshake via CryptoState (no packet framing)
    c.bench_function("handshake_latency", |b| {
        b.iter(|| {
            let client_config = make_client_config();
            let server_config = make_server_config();
            // ClientHello → Server → Client → Server (TLS 1.3 1-RTT)
            // Measure time to reach 1-RTT keys on both sides
        });
    });
}

fn bench_stream_throughput(c: &mut Criterion) {
    // Pre-establish connection, measure 1MB write+read throughput
    c.bench_function("stream_1mb_throughput", |b| { ... });
}
```

- [ ] **Step 4: Run benchmarks**

Run: `cargo bench --bench quic`

- [ ] **Step 5: Commit**

```bash
git add benches/quic.rs Cargo.toml
git commit -m "perf(quic): add criterion benchmarks for QUIC hot paths"
```

### Task 22: Final Integration Verification

**Files:** None (verification only)

- [ ] **Step 1: Run full test suite**

Run: `cargo test`
Expected: All tests pass (original 1406 + all new tests).

- [ ] **Step 2: Run clippy**

Run: `cargo clippy -- -D warnings`
Fix any warnings.

- [ ] **Step 3: Verify no debug artifacts remain**

```bash
grep -rn 'eprintln!\|println!\|dbg!' src/net/handler/quic/ --include='*.rs' | grep -v '/tests/' | grep -v '// '
```

Expected: No output.

- [ ] **Step 4: Run benchmarks (smoke test)**

Run: `cargo bench --bench quic -- --quick`
Expected: All benchmarks run without error.

- [ ] **Step 5: Commit any final fixes**

```bash
git add -A
git commit -m "chore(quic): final cleanup for merge readiness"
```
