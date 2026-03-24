# QUIC Production Hardening, Optimization & Integration Polish — Design Spec

**Date:** 2026-03-23
**Branch:** quic-rustls
**RFCs:** 9000, 9001, 9002, 9369, 8999

## Overview

The QUIC implementation is feature-complete (~12.7K lines, 435 tests, all 5 RFCs covered). This spec covers the final push to production readiness across three areas, executed in two phases: hardening + optimization (interleaved), then integration polish.

**Goals:**
- Zero compiler warnings, no dead code
- Structured edge case tests for adversarial inputs and state violations
- Latency-focused optimization guided by criterion benchmarks
- API parity with TCP/UDP socket patterns
- Working client example alongside the existing server example

**Acceptance Criteria:**
- Zero warnings under both `cargo check` and `cargo test --no-run`
- All existing tests pass under `cargo test`
- All new hardening tests pass
- Criterion benchmarks establish baseline latency numbers for hot paths
- Client example compiles and connects to server example

---

## Section 1: Production Hardening

### 1.1 Compiler Warnings Cleanup

29 warnings total: 22 in lib (`cargo check`) + 7 additional in test mode (`cargo test --no-run`).

For each item: decide whether the code is dead (remove it) or intentionally unused infrastructure that will be wired up soon (annotate with `#[allow(dead_code)]` and a comment explaining when it will be used). The frame_writer functions and crypto utilities are the key decision point — several are infrastructure for frame types that are parsed but not yet emitted by the packet builder.

**Lib warnings (22):**

*Unused imports:*
- `token_crypto.rs` — remove unused `self` from `use ring::aead::{self, ...}`

*Dead fields:*
- `handler.rs` — `rx_offload`, `tx_offload` fields never read
- `transport/packet_builder.rs` — `packet_number` field never read

*Dead struct:*
- `token.rs` — `RetryToken` struct never constructed; `new()` and `is_expired()` methods unused. Note: `original_dcid` and `client_addr` fields are also dead but only warned in test mode (the struct itself is the root cause)

*Unused functions (crypto):*
- `crypto/retry.rs` — `verify_retry_integrity_tag()`
- `crypto/stateless_reset.rs` — `generate_reset_token()`, `detect_stateless_reset()`
- `processor.rs` — `handle_retry_packet()`

*Unused functions (frame_writer — 8 functions):*
- `transport/frame_writer.rs` — `write_padding()`, `write_ping()`, `write_handshake_done()`, `write_path_challenge()`, `write_path_response()`, `write_data_blocked()`, `write_stream_data_blocked()`, `write_streams_blocked()`

*Unused functions (version):*
- `transport/version.rs` — `is_reserved_version()`, `should_process_version_negotiation()`

*Unused methods:*
- `transport/packet_builder.rs` — `packet_number()`, `written()`

*Dead variants/patterns:*
- `processor.rs` — never-constructed `StatelessReset` variant
- `processor.rs` — unreachable catch-all `_ => {}` pattern

**Test-mode additional warnings (7):**

*Unused imports:*
- `tests/adversarial_test.rs` — `IpAddress`, `Ipv4Address`
- `tests/new_token_test.rs` — `processor` import

*Unused variables:*
- `tests/adversarial_test.rs` — `dcid_bytes`
- `tests/new_token_test.rs` — `frame_len`
- `tests/pmtu_test.rs` — `result`

*Unnecessary mutability:*
- `tests/new_token_test.rs` — `frame_log` declared `mut` but never mutated

### 1.2 Structured Edge Case Tests

New test file `tests/hardening_test.rs` within `src/net/handler/quic/tests/`.

**Malformed packets:**
- Truncated long header (< 7 bytes)
- Invalid version field (non-zero, non-v1, non-v2)
- CID length field exceeding remaining packet bytes
- Zero-length payload after valid header
- Short header with invalid first byte (reserved bits set)

**Frame abuse:**
- CRYPTO frame exceeding 64KB buffer cap
- MAX_STREAMS beyond MAX_STREAMS_ABSOLUTE bound
- Invalid stream ID for connection role (client opening server-initiated stream IDs)
- STREAM frame with offset + length overflowing u64
- ACK frame with ranges exceeding largest acknowledged

**State violations:**
- STREAM data on a stream in Closed state
- Duplicate FIN on same stream (second FIN at different offset)
- ACK acknowledging packet numbers never sent
- CONNECTION_CLOSE received during handshake (before keys installed)
- HANDSHAKE_DONE from client (only server may send, RFC 9000 §19.20)

**Resource pressure:**
- Rapid connection open/close cycling against connection table limit
- Per-IP rate limit enforcement under burst
- Stream creation at MAX_STREAMS boundary (one below, at, one above)
- Connection-level flow control at MAX_DATA boundary

---

## Section 2: Latency Optimization

Sections 2.2–2.5 are investigation items, not guaranteed implementation. Changes are only made if benchmarks reveal a measurable problem. The benchmarks in 2.1 are the mandatory deliverable; the rest are conditional.

### 2.1 Criterion Benchmarks

Extend the existing `benches/quic.rs` with new benchmark groups for:
- **Inbound hot path:** packet decrypt + header unprotect
- **Frame parsing:** decrypted payload → parsed frames
- **ACK processing:** range walk + loss detection update
- **Outbound hot path:** packet build + encrypt + header protect
- **CID lookup:** FxHashMap probe with typical 8-byte CID

### 2.2 Allocation Audit

Profile `generate_packets()` and `process_packet()` for per-packet heap allocations:
- Replace any `Vec` allocations in frame parsing with `SmallVec` or borrowed slices
- Check `SentPacket` metadata tracking for unnecessary allocations
- Verify scratch buffers in packet builder are reused across calls (not reallocated)

### 2.3 ACK/Loss Processing

- Verify ACK range iteration doesn't exhibit quadratic behavior with many ranges
- Verify loss detection scan short-circuits past the reordering window
- Check that `on_ack_received` doesn't re-scan already-processed packet numbers

### 2.4 Timer and Poll Overhead

- Verify timer wheel dispatch is O(1) when no timers are near expiry
- Check that `poll_send()` skips connections with no pending data efficiently (early return, not full state inspection)

### 2.5 CID Lookup

- Verify FxHashMap isn't recomputing hashes unnecessarily
- Check if precomputed hash or inline CID comparison would help for the common 8-byte case

**Principle:** Measure first via benchmarks, then fix only what the numbers show is worth fixing. Benchmarks serve as regression gates afterward.

---

## Section 3: Integration Polish

### 3.1 API Parity with TCP/UDP

**Error types:**
- Confirm `QuicListener::listen()` already returns `Result<Self, BindError>` (verified — matches TCP pattern)
- Keep `QuicError` for connection/stream operations
- Audit remaining `QuicError` variants for semantic correctness

**Naming consistency audit:**
- Verify `QuicListener`, `QuicConnection`, `QuicStream`, `QuicRecvStream`, `QuicSendStream` exports from `src/net/socket/quic.rs` and re-exports in `src/net/socket/mod.rs`
- Verify future types (`Accept`, `Connect`) follow TCP patterns

**Lifecycle:**
- Verify `Drop` impl on `QuicConnection` initiates graceful close
- Verify `QuicStream` drop behavior matches `TcpStream`

### 3.2 Client Example

New file `examples/quic-client.rs`:
- Takes server address and port from CLI args
- Loads or accepts self-signed TLS certs (matching server example style)
- Calls `QuicConnection::connect()` to establish connection
- Opens a bidirectional stream
- Sends a message, reads the echo response, prints it
- Graceful shutdown
- Mirrors structure and style of existing `examples/quic-server.rs`

Together with the server example, provides a complete working demo of QUIC as a VoidNet transport.

---

## Out of Scope

- Fuzzing infrastructure (cargo-fuzz targets) — deferred to a future phase
- HTTP/3 or DNS-over-QUIC protocol implementation
- Throughput optimization (GSO coalescing, batched encryption)
- Multi-path QUIC (RFC 9443)
