# QUIC Hardening, Optimization & Integration Polish — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the feature-complete QUIC implementation to production quality with zero warnings, latency benchmarks, and a working client example.

**Architecture:** Three phases executed as two tracks: (1) hardening + optimization interleaved, (2) integration polish. Hardening removes dead code and adds edge case tests; optimization adds criterion benchmarks then investigates hot paths; integration ensures API parity and adds a client example.

**Tech Stack:** Rust, criterion (benchmarks), rcgen (TLS certs), rustls, ring, clap

**Spec:** `docs/superpowers/specs/2026-03-23-quic-harden-optimize-polish-design.md`

**Testing:** Always use plain `cargo test` (no `--features` or `--all-features`). Tests require root (configured via `.cargo/config.toml` with `sudo -E`).

---

## File Map

**Modified files (hardening):**
- `src/net/handler/quic/token_crypto.rs` — remove unused import
- `src/net/handler/quic/handler.rs` — remove dead fields
- `src/net/handler/quic/transport/packet_builder.rs` — remove dead field + methods
- `src/net/handler/quic/token.rs` — remove dead `RetryToken` struct
- `src/net/handler/quic/crypto/retry.rs` — annotate unused function
- `src/net/handler/quic/crypto/stateless_reset.rs` — annotate unused functions
- `src/net/handler/quic/processor.rs` — annotate unused function, remove dead variant + pattern
- `src/net/handler/quic/transport/frame_writer.rs` — annotate unused functions
- `src/net/handler/quic/transport/version.rs` — annotate unused functions
- `src/net/handler/quic/tests/adversarial_test.rs` — fix unused imports + variable
- `src/net/handler/quic/tests/new_token_test.rs` — fix unused import, variable, mutability
- `src/net/handler/quic/tests/pmtu_test.rs` — fix unused variable

**New files (hardening):**
- `src/net/handler/quic/tests/hardening_test.rs` — structured edge case tests

**Modified files (benchmarks):**
- `benches/quic.rs` — add latency benchmark groups
- `src/net/handler/quic/mod.rs` — extend `bench` module with new exports

**New files (integration):**
- `examples/quic-client.rs` — QUIC echo client example

**Modified files (integration):**
- `src/net/handler/quic/tests/mod.rs` — add `hardening_test` module

---

### Task 1: Remove Dead Code — Imports, Fields, Struct

**Files:**
- Modify: `src/net/handler/quic/token_crypto.rs:15`
- Modify: `src/net/handler/quic/handler.rs:49-50`
- Modify: `src/net/handler/quic/transport/packet_builder.rs:16,557-559,577-579`
- Modify: `src/net/handler/quic/token.rs:9-27` (entire `RetryToken` struct + impl)

- [ ] **Step 1: Remove unused `self` import in token_crypto.rs**

In `src/net/handler/quic/token_crypto.rs:15`, change:
```rust
use ring::aead::{self, AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
```
to:
```rust
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
```

- [ ] **Step 2: Remove dead fields in handler.rs**

In `src/net/handler/quic/handler.rs`, remove lines 49-50 (`rx_offload` and `tx_offload` fields) from the `QuicHandler` struct. Also remove any initialization of these fields in `QuicHandler::new()` or similar constructors.

- [ ] **Step 3: Remove dead field and methods in packet_builder.rs**

In `src/net/handler/quic/transport/packet_builder.rs`:
- Remove the `packet_number: u64` field (line 16) from `PacketBuilder`
- Remove the `packet_number()` method (lines 557-559)
- Remove the `written()` method (lines 577-579)
- Remove any initialization of `packet_number` in `PacketBuilder::new()` or similar

- [ ] **Step 4: Remove dead `RetryToken` struct in token.rs**

In `src/net/handler/quic/token.rs`, remove the entire `RetryToken` struct and its `impl` block (lines 9-27). Check for any imports of `RetryToken` elsewhere and remove them.

- [ ] **Step 5: Run `cargo check` to verify warning count decreased**

Run: `cargo check 2>&1 | grep "generated"`
Expected: Warning count should drop from 22 to ~14.

- [ ] **Step 6: Commit**

```bash
git add src/net/handler/quic/token_crypto.rs src/net/handler/quic/handler.rs \
        src/net/handler/quic/transport/packet_builder.rs src/net/handler/quic/token.rs
git commit -m "fix(quic): remove dead imports, fields, and RetryToken struct"
```

---

### Task 2: Annotate Intentionally-Unused Infrastructure Functions

These functions are parsed-but-not-yet-emitted infrastructure. They'll be wired into the packet builder as the implementation matures. Annotate with `#[allow(dead_code)]` rather than removing.

**Files:**
- Modify: `src/net/handler/quic/crypto/retry.rs:58`
- Modify: `src/net/handler/quic/crypto/stateless_reset.rs:5,14`
- Modify: `src/net/handler/quic/processor.rs:37,976,2918`
- Modify: `src/net/handler/quic/transport/frame_writer.rs:11,17,126,132,139,204,213,223`
- Modify: `src/net/handler/quic/transport/version.rs:45,97`

- [ ] **Step 1: Annotate crypto/retry.rs**

Add above `verify_retry_integrity_tag` (line 58):
```rust
#[allow(dead_code)] // Client-side retry validation — wired when client handles Retry packets
```

- [ ] **Step 2: Annotate crypto/stateless_reset.rs**

Add above `generate_reset_token` (line 5):
```rust
#[allow(dead_code)] // Wired when handler emits stateless reset packets
```

Add above `detect_stateless_reset` (line 14):
```rust
#[allow(dead_code)] // Wired when handler detects incoming stateless resets
```

- [ ] **Step 3: Annotate processor.rs — handle_retry_packet**

Add above `handle_retry_packet` (line 2918):
```rust
#[allow(dead_code)] // Wired when client processes incoming Retry packets
```

- [ ] **Step 4: Remove dead variant and unreachable pattern in processor.rs**

Remove the `StatelessReset` variant from `ProcessResult` enum (line 37). Remove the unreachable `_ => {}` catch-all pattern (line 976).

- [ ] **Step 5: Annotate frame_writer.rs — 8 functions**

Add `#[allow(dead_code)]` above each of the 8 unused write functions. Use a single module-level comment at the top of the function group:

```rust
// The following frame writers are infrastructure for frame types that are parsed
// but not yet emitted by the packet builder. They'll be wired as needed.
```

Then add `#[allow(dead_code)]` above each: `write_padding` (line 11), `write_ping` (line 17), `write_handshake_done` (line 126), `write_path_challenge` (line 132), `write_path_response` (line 139), `write_data_blocked` (line 204), `write_stream_data_blocked` (line 213), `write_streams_blocked` (line 223).

- [ ] **Step 6: Annotate version.rs — 2 functions**

Add above `is_reserved_version` (line 45):
```rust
#[allow(dead_code)] // Used by VN testing infrastructure
```

Add above `should_process_version_negotiation` (line 97):
```rust
#[allow(dead_code)] // Guard for client-side VN packet processing
```

- [ ] **Step 7: Run `cargo check` to verify zero lib warnings**

Run: `cargo check 2>&1 | grep "warning"`
Expected: Zero warnings (or only the "generated 0 warnings" line).

- [ ] **Step 8: Commit**

```bash
git add src/net/handler/quic/crypto/retry.rs src/net/handler/quic/crypto/stateless_reset.rs \
        src/net/handler/quic/processor.rs src/net/handler/quic/transport/frame_writer.rs \
        src/net/handler/quic/transport/version.rs
git commit -m "fix(quic): annotate infrastructure functions as intentionally unused"
```

---

### Task 3: Fix Test-Mode Warnings

**Files:**
- Modify: `src/net/handler/quic/tests/adversarial_test.rs:29,399`
- Modify: `src/net/handler/quic/tests/new_token_test.rs:275,324,338`
- Modify: `src/net/handler/quic/tests/pmtu_test.rs:48`

- [ ] **Step 1: Fix adversarial_test.rs**

Line 29 — remove `IpAddress, Ipv4Address` from the import:
```rust
use crate::net::wire::ip::{IPV4_MIN_HEADER_LEN};
```
(Keep only `IPV4_MIN_HEADER_LEN` if that's the only used import; otherwise adjust accordingly.)

Line 399 — prefix unused variable with underscore:
```rust
let (quic_packet, _dcid_bytes, _) = build_valid_initial();
```

- [ ] **Step 2: Fix new_token_test.rs**

Line 324 — remove unused `processor` import entirely.

Line 275 — remove `mut` from `frame_log`:
```rust
let frame_log = FrameLog::new(64);
```

Line 338 — prefix unused variable with underscore:
```rust
let _frame_len = frame_writer::write_new_token(&mut frame_buf, token);
```

- [ ] **Step 3: Fix pmtu_test.rs**

Line 48 — prefix unused variable with underscore:
```rust
let _result = state.on_probe_lost(STEP_THRESHOLD);
```

- [ ] **Step 4: Verify zero warnings in test mode**

Run: `cargo test --no-run 2>&1 | grep "warning:" | grep -v generated`
Expected: No output (zero warnings).

- [ ] **Step 5: Run full test suite**

Run: `cargo test`
Expected: All 435+ tests pass, 0 failures.

- [ ] **Step 6: Commit**

```bash
git add src/net/handler/quic/tests/adversarial_test.rs \
        src/net/handler/quic/tests/new_token_test.rs \
        src/net/handler/quic/tests/pmtu_test.rs
git commit -m "fix(quic): resolve all test-mode compiler warnings"
```

---

### Task 4: Structured Edge Case Tests — Malformed Packets

**Files:**
- Create: `src/net/handler/quic/tests/hardening_test.rs`
- Modify: `src/net/handler/quic/tests/mod.rs` (add `mod hardening_test;`)

- [ ] **Step 1: Register the test module**

In `src/net/handler/quic/tests/mod.rs`, add:
```rust
mod hardening_test;
```

- [ ] **Step 2: Write malformed packet tests**

Create `src/net/handler/quic/tests/hardening_test.rs` with tests for:

The header parsing API is in `src/net/wire/quic.rs`, not `packet_parser`:
- `parse_header(buf: &[u8], short_dcid_len: usize) -> Result<(PacketHeader<'_>, usize), HeaderParseError>`
- Returns `HeaderParseError::BufferTooShort` or `HeaderParseError::InvalidDcidLength(u8)`

```rust
use crate::net::wire::quic::{parse_header, HeaderParseError};
use crate::net::handler::quic::transport::frame::parse_frame;

/// Truncated long header — less than minimum 7 bytes
#[test]
fn reject_truncated_long_header() {
    let short_packet = [0xC0, 0x00, 0x00, 0x00]; // only 4 bytes
    let result = parse_header(&short_packet, 8);
    assert!(matches!(result, Err(HeaderParseError::BufferTooShort)));
}

/// CID length field exceeds remaining packet bytes
#[test]
fn reject_cid_length_overflow() {
    let mut pkt = vec![0xC3]; // long header, Initial type
    pkt.extend_from_slice(&0x00000001u32.to_be_bytes()); // version 1
    pkt.push(255); // DCID len = 255 but packet ends here
    pkt.push(0);   // SCID len
    let result = parse_header(&pkt, 8);
    assert!(result.is_err());
}

/// Zero-length payload after valid header
#[test]
fn reject_zero_payload_initial() {
    let mut pkt = vec![0xC3]; // long header, Initial
    pkt.extend_from_slice(&0x00000001u32.to_be_bytes()); // version 1
    pkt.push(8); // DCID len
    pkt.extend_from_slice(&[0x01; 8]); // DCID
    pkt.push(0); // SCID len
    // No token or payload — truncated
    let result = parse_header(&pkt, 8);
    // Should parse the header successfully (payload parsing is separate)
    // The key assertion is no panic
    let _ = result;
}
```

- [ ] **Step 3: Write short header edge case test**

Add to the same file:
```rust
/// Short header with reserved bits set — should still parse (reserved bits are encrypted)
#[test]
fn short_header_reserved_bits() {
    // Short header: form bit 0, fixed bit 1, then version-specific bits
    let pkt = [0x58, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]; // 1-byte + 8-byte CID
    // parse_header with short_dcid_len=8 for short header parsing
    let result = parse_header(&pkt, 8);
    // Just verify it doesn't panic — reserved bits checked after header protection
    let _ = result;
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test hardening`
Expected: All new tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/net/handler/quic/tests/hardening_test.rs src/net/handler/quic/tests/mod.rs
git commit -m "test(quic): add malformed packet hardening tests"
```

---

### Task 5: Structured Edge Case Tests — Frame Abuse

**Files:**
- Modify: `src/net/handler/quic/tests/hardening_test.rs`

- [ ] **Step 1: Write frame abuse tests**

Add to `hardening_test.rs`:

```rust
use crate::net::handler::quic::transport::frame::{QuicFrame, parse_frame};
use crate::net::handler::quic::transport::varint::encode_varint;

/// STREAM frame with offset + length overflowing u64
#[test]
fn reject_stream_offset_overflow() {
    // STREAM frame type 0x0F (OFF + LEN + FIN bits set)
    let mut buf = Vec::new();
    buf.push(0x0F); // STREAM with all optional bits
    // stream_id = 0
    buf.push(0x00);
    // offset = u64::MAX - 1 (8-byte varint)
    let mut offset_buf = [0u8; 8];
    encode_varint(0x3FFFFFFFFFFFFFFF, &mut offset_buf); // max varint value
    buf.extend_from_slice(&offset_buf);
    // length = large value that would overflow with offset
    let mut len_buf = [0u8; 8];
    encode_varint(0x3FFFFFFFFFFFFFFF, &mut len_buf);
    buf.extend_from_slice(&len_buf);
    // No actual data needed — the overflow check should happen during parsing
    let result = parse_frame(&buf);
    // Should either return an error or handle gracefully (no panic, no wrap)
    let _ = result;
}

/// ACK frame with range exceeding largest acknowledged
#[test]
fn reject_ack_invalid_ranges() {
    // ACK frame: type=0x02, largest=5, delay=0, range_count=1, first_range=5
    // Then gap=0, ack_range=10 (which would go below 0)
    let frame = [
        0x02, // ACK type
        0x05, // largest_acked = 5
        0x00, // ack_delay = 0
        0x01, // range_count = 1
        0x02, // first_range = 2 (acks 3,4,5)
        0x00, // gap = 0 (skip pn 2)
        0x0A, // ack_range = 10 (would need pn -9, impossible)
    ];
    let result = parse_frame(&frame);
    // Should error or handle gracefully, not underflow
    let _ = result;
}
```

Adapt these to the actual `parse_frame` return type. The goal is exercising overflow/underflow checks, not asserting specific error variants.

- [ ] **Step 2: Run tests**

Run: `cargo test hardening`
Expected: All tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/net/handler/quic/tests/hardening_test.rs
git commit -m "test(quic): add frame abuse hardening tests"
```

---

### Task 6: Structured Edge Case Tests — State Violations & Resource Pressure

**Files:**
- Modify: `src/net/handler/quic/tests/hardening_test.rs`

- [ ] **Step 1: Write state violation tests**

Add tests exercising:
- Stream creation at MAX_STREAMS boundary (one below limit, at limit, one above — verify the above-limit case is rejected)
- Connection-level flow control at MAX_DATA boundary
- HANDSHAKE_DONE from wrong side (construct a frame and verify it's rejected when received by server)

These tests should use the same test helpers as existing tests (check `e2e_test.rs` and `adversarial_test.rs` for patterns — they create `QuicConnectionState` instances with mock TLS and exercise the processor directly).

- [ ] **Step 2: Write resource pressure tests**

Add tests for:
- Per-IP rate limiting: create connections rapidly from the same IP, verify they're rate-limited after the configured threshold
- Connection table limit: verify the handler rejects new connections when the table is full

Study `adversarial_test.rs` for patterns on constructing raw packets and feeding them to the handler.

- [ ] **Step 3: Run all tests**

Run: `cargo test`
Expected: All tests pass (existing + new hardening tests).

- [ ] **Step 4: Commit**

```bash
git add src/net/handler/quic/tests/hardening_test.rs
git commit -m "test(quic): add state violation and resource pressure hardening tests"
```

---

### Task 7: Criterion Latency Benchmarks

**Files:**
- Modify: `benches/quic.rs`
- Modify: `src/net/handler/quic/mod.rs` (extend `bench` module exports)

- [ ] **Step 1: Expose benchmark APIs**

In `src/net/handler/quic/mod.rs`, extend the `bench` module to export what the new benchmarks need:

```rust
pub mod bench {
    pub use super::connection_id::ConnectionId;
    pub use super::transport::frame::{StreamId, parse_frame};
    pub use super::transport::varint::{decode_varint, encode_varint};
    pub use super::crypto::packet_protection::{protect_packet, decrypt_payload};
    pub use super::crypto::initial_keys::derive_initial_keys;

    pub mod frame_writer {
        pub use crate::net::handler::quic::transport::frame_writer::{write_crypto, write_stream};
    }
}
```

Check which types/functions are actually `pub` and accessible. If some are `pub(crate)`, either make them `pub` or add a thin `pub` wrapper in the bench module. Only expose what the benchmarks actually need.

**Note:** `derive_initial_keys` takes `(client_dcid: &[u8], side: rustls::Side, version: rustls::quic::Version)` and returns `(DirectionalKeys, DirectionalKeys)`. The benchmarks must use `rustls::Side::Client`/`Server` and `rustls::quic::Version::V1`/`V2`, not raw integers.

- [ ] **Step 2: Add inbound hot path benchmark**

In `benches/quic.rs`, add a new benchmark group:

```rust
fn bench_packet_protection(c: &mut Criterion) {
    use rustls::Side;
    use rustls::quic::Version;
    use libvoid::net::handler::quic::bench::{derive_initial_keys, protect_packet, decrypt_payload};

    // Derive initial keys from the RFC 9001 test vector CID
    let cid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let (client_keys, server_keys) = derive_initial_keys(&cid, Side::Client, Version::V1);

    // Build benchmark payloads and adapt to the actual protect_packet/decrypt_payload
    // signatures from src/net/handler/quic/crypto/packet_protection.rs.
    // Read that file to understand exact buffer layout expectations.

    c.bench_function("packet_protect_initial", |b| {
        let mut buf = [0u8; 1280];
        // Fill buf with a minimal valid Initial packet structure
        // Then call protect_packet() — adapt to actual API
        b.iter(|| {
            black_box(&mut buf);
        });
    });

    c.bench_function("packet_decrypt_initial", |b| {
        // Pre-build a protected packet, then benchmark decryption
        // Use server_keys to decrypt what client_keys protected
        b.iter(|| {
            black_box(0);
        });
    });
}
```

**Important:** The protect/decrypt benchmarks require building a properly formatted packet buffer. Read `src/net/handler/quic/crypto/packet_protection.rs` (lines 31 and 170) for exact function signatures and buffer layout requirements. The benchmark should do real crypto work — the stubs above are placeholders showing the structure. Study the existing `crypto_test.rs` for test patterns that construct valid packets for encryption/decryption.

- [ ] **Step 3: Add ACK processing benchmark**

```rust
fn bench_ack_processing(c: &mut Criterion) {
    // ACK processing involves AckState and LossDetector which are complex
    // stateful types. Study src/net/handler/quic/tests/ack_test.rs and
    // src/net/handler/quic/tests/loss_test.rs for construction patterns.
    // The bench module may need additional exports — only add what's needed.

    c.bench_function("ack_process_single_range", |b| {
        // Pre-build an ACK frame with single range using frame_writer
        // Then benchmark parse_frame on the ACK
        let frame = [0x02, 0x10, 0x05, 0x00, 0x10]; // largest=16, delay=5, count=0, first=16
        b.iter(|| black_box(parse_frame(black_box(&frame))));
    });

    c.bench_function("ack_process_multi_range", |b| {
        // ACK with 3 ranges
        let frame = [
            0x02, // ACK type
            0x40, 0x64, // largest=100
            0x00, // delay=0
            0x02, // range_count=2
            0x09, // first_range=9 (acks 91-100)
            0x04, // gap=4 (skip 86-90)
            0x09, // range=9 (acks 76-85)
            0x04, // gap=4 (skip 71-75)
            0x09, // range=9 (acks 61-70)
        ];
        b.iter(|| black_box(parse_frame(black_box(&frame))));
    });
}
```

- [ ] **Step 4: Add CID lookup benchmark**

The existing `bench_cid_hash` uses `DefaultHasher`. Add an `FxHashMap` lookup benchmark that measures the actual demux path:

```rust
fn bench_cid_lookup(c: &mut Criterion) {
    use rustc_hash::FxHashMap;

    // Pre-populate a map with 1000 connections
    let mut map = FxHashMap::default();
    for i in 0u64..1000 {
        let cid = ConnectionId::from_slice(&i.to_be_bytes());
        map.insert(cid, i as usize);
    }

    let lookup_cid = ConnectionId::from_slice(&500u64.to_be_bytes());
    c.bench_function("cid_fxhashmap_lookup_1000", |b| {
        b.iter(|| black_box(map.get(black_box(&lookup_cid))));
    });
}
```

- [ ] **Step 5: Register new benchmark groups**

Update the `criterion_group!` macro:
```rust
criterion_group!(
    benches,
    bench_varint,
    bench_frames,
    bench_cid_hash,
    bench_packet_protection,
    bench_ack_processing,
    bench_cid_lookup,
);
```

- [ ] **Step 6: Verify benchmarks compile and run**

Run: `cargo bench -- --test` (quick validation run)
Expected: All benchmark groups compile and execute.

- [ ] **Step 7: Run full benchmarks to establish baseline**

Run: `cargo bench`
Expected: All benchmarks produce timing results. Record baseline numbers.

- [ ] **Step 8: Commit**

```bash
git add benches/quic.rs src/net/handler/quic/mod.rs
git commit -m "perf(quic): add criterion latency benchmarks for hot paths"
```

---

### Task 8: Latency Investigation (Conditional)

This task is conditional — only make changes if benchmarks from Task 7 reveal measurable problems.

**Files:**
- Potentially modify: `src/net/handler/quic/processor.rs`
- Potentially modify: `src/net/handler/quic/transport/ack.rs`
- Potentially modify: `src/net/handler/quic/transport/loss.rs`
- Potentially modify: `src/net/handler/quic/handler.rs`

- [ ] **Step 1: Review benchmark results from Task 7**

Identify the slowest operations. Focus on anything taking >1μs per operation (a rough threshold for per-packet hot path).

- [ ] **Step 2: Audit allocations in process_packet()**

Read `src/net/handler/quic/processor.rs:207` and trace through one full packet processing call. Look for:
- `Vec::new()` or `vec![]` allocations
- `.collect::<Vec<_>>()` patterns
- `Box::new()` or `String::from()` in the hot path
- Any `clone()` that copies data rather than sharing references

If found: replace with `SmallVec`, stack buffers, or borrowed slices.

- [ ] **Step 3: Audit allocations in generate_packets()**

Read `src/net/handler/quic/processor.rs:1614` and trace through packet generation. Same allocation patterns to look for.

- [ ] **Step 4: Check ACK range iteration complexity**

Read `src/net/handler/quic/transport/ack.rs` for the ACK processing loop. Verify:
- No nested iteration over the same data
- Early exit when past the reordering window
- No re-scanning of already-processed packet numbers

- [ ] **Step 5: Check poll_send() efficiency**

Read `src/net/handler/quic/handler.rs` `poll_send()` method. Verify it skips connections with no pending data via an early check (e.g., `pending_send_count == 0`) rather than full state inspection.

- [ ] **Step 6: If changes made, re-run benchmarks**

Run: `cargo bench`
Expected: Improved numbers on the changed paths, no regressions.

- [ ] **Step 7: Run full test suite**

Run: `cargo test`
Expected: All tests pass.

- [ ] **Step 8: Commit (if changes made)**

```bash
# Stage only the specific files that were modified
git add src/net/handler/quic/processor.rs src/net/handler/quic/handler.rs  # adjust to actual changed files
git commit -m "perf(quic): optimize hot-path allocations based on benchmark results"
```

---

### Task 9: API Parity Audit

**Files:**
- Modify: `src/net/socket/quic.rs` (if issues found)

- [ ] **Step 1: Verify BindError return type**

Confirm `QuicListener::listen()` at `src/net/socket/quic.rs:92` returns `Result<Self, BindError>`. (Already verified — this is a confirmation step.)

- [ ] **Step 2: Audit QuicError variants**

Read `src/net/socket/quic.rs:67-74`. Check:
- `NotConnected` — is it used correctly? Should not be used for bind failures (confirmed it's not).
- `ConnectionClosed(Option<u64>)` — carries error code, good.
- `WouldBlock` — used for flow control limits, good.
- `Transport(TransportError)` — wraps protocol errors, good.
- `StreamReset(u64)` — carries reset error code, good.

Compare against TCP's error handling. No changes expected unless issues found.

- [ ] **Step 3: Verify socket re-exports**

Read `src/net/socket/mod.rs` lines 7-10. Confirm all public QUIC types are re-exported:
- `QuicListener`, `QuicConnection`, `QuicStream`, `QuicRecvStream`, `QuicSendStream`
- `QuicError`, `QuicEvent`
- `Accept as QuicAccept`, `Connect as QuicConnect`, `AcceptStream`
- `TokenStore`, `InMemoryTokenStore`

- [ ] **Step 4: Verify Drop impls**

Confirm `QuicConnection::drop()` at `src/net/socket/quic.rs:380-393` initiates graceful close (sets `Closing` state with `NO_ERROR`). Already implemented.

Confirm `QuicListener::drop()` at `src/net/socket/quic.rs:143-146` calls `close()`. Already implemented.

- [ ] **Step 5: Commit (if changes made)**

Only commit if actual fixes were needed:
```bash
git add src/net/socket/quic.rs src/net/socket/mod.rs
git commit -m "fix(quic): API parity fixes for socket layer"
```

---

### Task 10: Client Example

**Files:**
- Create: `examples/quic-client.rs`

- [ ] **Step 1: Write the client example**

Create `examples/quic-client.rs` following the patterns from `examples/tcp-echo-client.rs` and `examples/quic-server.rs`:

```rust
use std::{
    ops::{Deref, DerefMut},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use clap::Parser;
use coarsetime::Duration;
use rustls::ClientConfig;
use rustls::pki_types::CertificateDer;

use libvoid::net::{
    socket::QuicConnection,
    wire::{ethernet::MacAddress, ip::SocketAddr},
};
use libvoid::rt::LocalRuntime;

mod common;
use common::BaseArgs;

#[derive(Parser)]
#[command(author, version, about = "QUIC echo client")]
struct Args {
    #[command(flatten)]
    base: BaseArgs,
    #[arg(short, long, default_value = "[fc00:dead:cafe:1::2]:4434")]
    local_addr: SocketAddr,
    #[arg(short, long, default_value = "[fc00:dead:cafe:1::1]:4433")]
    remote_addr: SocketAddr,
    #[arg(long, default_value = "localhost")]
    server_name: String,
    #[arg(long, default_value = "64")]
    message_size: usize,
    #[arg(long, help = "Path to PEM CA certificate file (uses insecure verifier if omitted)")]
    ca_cert: Option<String>,
    #[arg(long, help = "Gateway/next-hop MAC address")]
    remote_mac: MacAddress,
}

impl Deref for Args {
    type Target = BaseArgs;
    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl DerefMut for Args {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base
    }
}

fn make_insecure_config() -> Arc<ClientConfig> {
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(danger::NoCertificateVerification {}))
        .with_no_client_auth();
    let mut config = config;
    config.alpn_protocols = vec![b"hq-interop".to_vec(), b"h3".to_vec()];
    Arc::new(config)
}

fn load_ca_config(ca_path: &str) -> Arc<ClientConfig> {
    let ca_pem = std::fs::read(ca_path)
        .unwrap_or_else(|e| panic!("Failed to read CA file '{}': {}", ca_path, e));
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &ca_pem[..])
        .collect::<Result<Vec<_>, _>>()
        .expect("Failed to parse CA PEM");

    let mut root_store = rustls::RootCertStore::empty();
    for cert in certs {
        root_store.add(cert).expect("Failed to add CA cert");
    }

    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"hq-interop".to_vec(), b"h3".to_vec()];
    Arc::new(config)
}

mod danger {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    pub struct NoCertificateVerification;

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ED25519,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
            ]
        }
    }
}

fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let args = Args::parse();

    let tls_config = match &args.ca_cert {
        Some(ca) => {
            println!("Loading CA certificate from {}", ca);
            load_ca_config(ca)
        }
        None => {
            println!("No --ca-cert provided, using insecure certificate verification");
            make_insecure_config()
        }
    };

    let mut runtime = LocalRuntime::builder(&args.if_name, args.queue)
        .arp_ttl(Duration::from_secs(1200))
        .attach_mode(args.attach_mode)
        .enable_fragmentation(args.enable_fragmentation)
        .completion_ring_size(args.completion_ring_size)
        .fill_ring_size(args.fill_ring_size)
        .frame_size(args.frame_size)
        .busy_poll(args.busy_poll)
        .busy_poll_batch_size(args.busy_poll_batch_size)
        .busy_poll_timeout_us(args.busy_poll_timeout_us)
        .huge_tables(args.huge_tables)
        .unaligned(args.unaligned)
        .rx_ring_size(args.rx_ring_size)
        .tx_ring_size(args.tx_ring_size)
        .copy_mode(args.copy_mode)
        .build()
        .expect("Failed to create runtime");

    let exit = Arc::new(AtomicBool::new(false));
    ctrlc::set_handler({
        let exit = exit.clone();
        move || {
            exit.store(true, Ordering::Relaxed);
        }
    })
    .expect("Error setting Ctrl-C handler");

    let message_size = args.message_size;
    let server_name = args.server_name.clone();
    let remote_mac = args.remote_mac;

    runtime
        .run(exit, async move {
            println!(
                "Connecting from {} to {}...",
                args.local_addr, args.remote_addr
            );

            let conn = QuicConnection::connect(
                args.local_addr.ip,
                args.local_addr.port,
                // local_mac: the MAC address of the local interface
                // In production, obtain from the runtime context or ARP table.
                // For the example, the user must provide it via CLI args or
                // it could be read from the interface. For now, use a placeholder
                // that the user must replace — this is a known limitation of the
                // QUIC client API which requires L2 addressing unlike TCP.
                MacAddress([0; 6]), // Replace with actual local MAC
                args.remote_addr.ip,
                args.remote_addr.port,
                remote_mac,
                &server_name,
                tls_config,
            )
            .expect("Failed to initiate connection")
            .await
            .expect("Connection failed");

            if let (Some(addr), Some(port)) = (conn.remote_addr(), conn.remote_port()) {
                println!("Connected to {:?}:{}", addr, port);
            }

            let stream = conn.open_bidi_stream().expect("Failed to open stream");
            println!("Opened stream {}", stream.id().0);

            let payload = vec![0xABu8; message_size];
            let mut read_buf = vec![0u8; message_size];

            // Send message
            stream.write(&payload).await.expect("Write failed");
            println!("Sent {} bytes", message_size);

            // Read echo response
            let mut total_read = 0;
            while total_read < message_size {
                let n = stream.read(&mut read_buf[total_read..]).await.expect("Read failed");
                if n == 0 {
                    println!("Server closed stream");
                    break;
                }
                total_read += n;
            }
            println!("Received {} bytes", total_read);

            assert_eq!(&read_buf[..total_read], &payload[..total_read], "Echo mismatch!");
            println!("Echo verified OK");

            stream.finish();
        })
        .expect("Failed to run runtime");

    println!("Exiting...");
}
```

**Important:** The `MacAddress` handling and `local_mac` resolution need to match how the runtime provides this. Check how the TCP echo client handles this — it may use the runtime context or ARP resolution. Adapt accordingly. The `MacAddress([0; 6])` placeholder must be replaced with the correct pattern.

- [ ] **Step 2: Verify it compiles**

Run: `cargo build --example quic-client`
Expected: Compiles without errors.

- [ ] **Step 3: Commit**

```bash
git add examples/quic-client.rs
git commit -m "feat(quic): add QUIC echo client example"
```

---

### Task 11: Final Verification

- [ ] **Step 1: Verify zero warnings (lib)**

Run: `cargo check 2>&1 | grep "warning"`
Expected: Zero warnings.

- [ ] **Step 2: Verify zero warnings (test mode)**

Run: `cargo test --no-run 2>&1 | grep "warning:" | grep -v generated`
Expected: No output.

- [ ] **Step 3: Run full test suite**

Run: `cargo test`
Expected: All tests pass, 0 failures.

- [ ] **Step 4: Verify benchmarks run**

Run: `cargo bench -- --test`
Expected: All benchmark groups compile and execute.

- [ ] **Step 5: Verify both examples compile**

Run: `cargo build --example quic-server && cargo build --example quic-client`
Expected: Both compile without errors.
