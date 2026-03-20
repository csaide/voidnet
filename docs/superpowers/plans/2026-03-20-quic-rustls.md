# QUIC + rustls Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a custom QUIC transport protocol with rustls for TLS 1.3 on VoidNet's AF_XDP stack.

**Architecture:** Layered — crypto (rustls integration) → transport (packets, frames, loss detection) → stream (multiplexing, flow control) → handler+socket (runtime integration, async API). Each layer is testable in isolation. Follows existing TCP handler patterns: `Slab` connection table, `FxHashMap` CID routing, `TimerWheel` integration, `LocalQueue` waker pattern.

**Tech Stack:** Rust, rustls (QUIC mode), ring/aws-lc-rs (via rustls), slab, rustc-hash (FxHashMap), smallvec, coarsetime.

**Spec:** `docs/superpowers/specs/2026-03-20-quic-rustls-design.md`

---

## Scope Decomposition

This plan is split into **6 phases**, each producing compilable, testable code:

1. **Foundation** — Types, error codes, transport parameters, wire format
2. **Crypto** — rustls integration, packet protection, key schedule
3. **Transport** — Packet parsing/building, frame codec, loss detection, congestion
4. **Streams** — Stream state machine, flow control, buffers
5. **Handler + Runtime** — QuicHandler, dispatch chain, timer integration
6. **Socket API** — QuicListener, QuicConnection, QuicStream async futures

Each phase builds on the previous. Phases 1-4 are pure library code with unit tests. Phase 5 integrates with the runtime. Phase 6 exposes the user API.

---

## File Structure

### New files to create

```
src/net/handler/quic/
├── mod.rs                      # Module exports
├── handler.rs                  # QuicHandler — connection table, dispatch, timer handling
├── connection.rs               # QuicConnectionState — per-connection state
├── connection_id.rs            # ConnectionId, CidSet, CID routing helpers
├── error.rs                    # TransportError enum (RFC 9000 §20)
├── timer_kinds.rs              # QuicTimerKind, timer ID packing/unpacking
├── crypto/
│   ├── mod.rs                  # Crypto layer exports
│   ├── tls.rs                  # rustls QUIC-mode wrapper, handshake driving
│   ├── keys.rs                 # KeyPair, DirectionalKey, PacketKeys, key schedule
│   ├── initial_keys.rs         # Initial key derivation (deterministic from CID)
│   └── packet_protection.rs    # In-place encrypt/decrypt on frame buffers
├── transport/
│   ├── mod.rs                  # Transport layer exports
│   ├── packet.rs               # PacketHeader parsing, PacketType, coalescing
│   ├── packet_number.rs        # Variable-length PN encode/decode, full PN reconstruction
│   ├── frame.rs                # QuicFrame enum, frame parser (zero-copy borrows)
│   ├── frame_writer.rs         # Write frames into PacketBuilder
│   ├── loss.rs                 # LossDetector, InFlightRing, PTO, loss declaration
│   ├── congestion.rs           # CongestionController trait + QuicCubic
│   ├── flow_control.rs         # Connection-level FlowControl
│   ├── params.rs               # TransportParams encode/decode (RFC 9000 §18)
│   └── ack.rs                  # AckState, pre-encoded ranges, ACK generation
├── stream/
│   ├── mod.rs                  # Stream layer exports
│   ├── state.rs                # SendState, RecvState, StreamState enum
│   ├── map.rs                  # StreamMap — direct Vec indexing by StreamId
│   ├── send.rs                 # SendHalf — send buffer, flow control
│   ├── recv.rs                 # RecvHalf — recv buffer, OOO reassembly
│   ├── flow_control.rs         # Per-stream flow control, final size accounting
│   └── pool.rs                 # StreamPool — recycle stream objects
├── path.rs                     # PathState, address validation, AmplificationLimit
├── token.rs                    # Retry token + NEW_TOKEN generation/validation
└── tests/
    ├── mod.rs
    ├── connection_id_test.rs
    ├── error_test.rs
    ├── packet_number_test.rs
    ├── frame_test.rs
    ├── params_test.rs
    ├── loss_test.rs
    ├── stream_state_test.rs
    ├── flow_control_test.rs
    └── crypto_test.rs

src/net/wire/quic.rs            # QUIC long/short header wire format (zero-copy)

src/net/socket/quic.rs          # QuicListener, QuicConnection, QuicStream

src/net/congestion/
├── mod.rs                      # Shared CongestionController trait
```

### Files to modify

| File | Change |
|------|--------|
| `Cargo.toml` | Add `rustls` dependency with `quic` feature |
| `src/net/handler/mod.rs` | Add `pub mod quic;` |
| `src/net/mod.rs` | Re-export QUIC public types |
| `src/net/wire/mod.rs` | Add `pub mod quic;` |
| `src/net/handler/ipv4.rs` | Add `quic_handler` param to `handle()`, port-based dispatch |
| `src/net/handler/ipv6.rs` | Same dispatch change |
| `src/net/handler/ethernet.rs` | Thread `quic_handler` through to IP handlers |
| `src/rt/local.rs` | Add `QuicHandler` field, timer dispatch, poll_send, eviction |
| `src/rt/context.rs` | Add `quic_handler` to `RuntimeContext` |
| `src/net/socket/mod.rs` | Export QUIC socket types |

---

## Phase 1: Foundation Types

### Task 1: Add rustls dependency

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Add rustls to Cargo.toml**

Add to `[dependencies]`:
```toml
rustls = { version = "0.23", default-features = false, features = ["std", "ring", "quic"] }
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check`
Expected: Compiles with no errors. rustls `quic` feature enables `rustls::quic::*` types.

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "deps: add rustls with quic feature"
```

---

### Task 2: Transport error codes

**Files:**
- Create: `src/net/handler/quic/error.rs`
- Create: `src/net/handler/quic/mod.rs`
- Modify: `src/net/handler/mod.rs`
- Test: `src/net/handler/quic/tests/error_test.rs`

- [ ] **Step 1: Create module structure**

Create `src/net/handler/quic/mod.rs`:
```rust
pub mod error;

#[cfg(test)]
mod tests;
```

Add to `src/net/handler/mod.rs`:
```rust
pub mod quic;
```

- [ ] **Step 2: Write failing test for TransportError**

Create `src/net/handler/quic/tests/mod.rs`:
```rust
mod error_test;
```

Create `src/net/handler/quic/tests/error_test.rs`:
```rust
use super::super::error::TransportError;

#[test]
fn transport_error_codes_match_rfc() {
    assert_eq!(TransportError::NoError as u64, 0x00);
    assert_eq!(TransportError::FlowControlError as u64, 0x03);
    assert_eq!(TransportError::ProtocolViolation as u64, 0x0a);
    assert_eq!(TransportError::AeadLimitReached as u64, 0x0f);
    assert_eq!(TransportError::NoViablePath as u64, 0x10);
}

#[test]
fn tls_alert_mapping() {
    let alert: u8 = 42; // unknown_ca
    let error = TransportError::from_tls_alert(alert);
    assert_eq!(error as u64, 0x0100 + 42);
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test --lib quic::tests::error_test`
Expected: FAIL — module doesn't exist yet.

- [ ] **Step 4: Implement TransportError**

Create `src/net/handler/quic/error.rs`:
```rust
/// QUIC transport error codes (RFC 9000 §20)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
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
    /// TLS alert mapped to QUIC error (0x0100 + alert_code)
    CryptoError(u8),
}

impl TransportError {
    /// Map TLS alert to QUIC transport error (RFC 9001 §4.8)
    pub fn from_tls_alert(alert: u8) -> Self {
        TransportError::CryptoError(alert)
    }

    pub fn code(&self) -> u64 {
        match self {
            TransportError::CryptoError(alert) => 0x0100 + *alert as u64,
            other => *other as u64,
        }
    }
}
```

Note: The `CryptoError` variant breaks the `#[repr(u64)]` for the enum. Restructure as:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportError(u64);

impl TransportError {
    pub const NO_ERROR: Self = Self(0x00);
    pub const INTERNAL_ERROR: Self = Self(0x01);
    pub const CONNECTION_REFUSED: Self = Self(0x02);
    pub const FLOW_CONTROL_ERROR: Self = Self(0x03);
    pub const STREAM_LIMIT_ERROR: Self = Self(0x04);
    pub const STREAM_STATE_ERROR: Self = Self(0x05);
    pub const FINAL_SIZE_ERROR: Self = Self(0x06);
    pub const FRAME_ENCODING_ERROR: Self = Self(0x07);
    pub const TRANSPORT_PARAMETER_ERROR: Self = Self(0x08);
    pub const CONNECTION_ID_LIMIT_ERROR: Self = Self(0x09);
    pub const PROTOCOL_VIOLATION: Self = Self(0x0a);
    pub const INVALID_TOKEN: Self = Self(0x0b);
    pub const APPLICATION_ERROR: Self = Self(0x0c);
    pub const CRYPTO_BUFFER_EXCEEDED: Self = Self(0x0d);
    pub const KEY_UPDATE_ERROR: Self = Self(0x0e);
    pub const AEAD_LIMIT_REACHED: Self = Self(0x0f);
    pub const NO_VIABLE_PATH: Self = Self(0x10);

    /// Map TLS alert to QUIC transport error (RFC 9001 §4.8)
    pub fn from_tls_alert(alert: u8) -> Self {
        Self(0x0100 + alert as u64)
    }

    pub fn code(&self) -> u64 {
        self.0
    }
}
```

Update tests to use constant syntax: `TransportError::NO_ERROR.code()` etc.

- [ ] **Step 5: Run tests**

Run: `cargo test --lib quic::tests::error_test`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/net/handler/quic/ src/net/handler/mod.rs
git commit -m "feat(quic): add transport error codes (RFC 9000 §20)"
```

---

### Task 3: ConnectionId type

**Files:**
- Create: `src/net/handler/quic/connection_id.rs`
- Test: `src/net/handler/quic/tests/connection_id_test.rs`

- [ ] **Step 1: Write failing tests**

Create `src/net/handler/quic/tests/connection_id_test.rs`:
```rust
use super::super::connection_id::ConnectionId;

#[test]
fn connection_id_from_slice() {
    let bytes = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let cid = ConnectionId::from_slice(&bytes);
    assert_eq!(cid.len(), 8);
    assert_eq!(cid.as_bytes(), &bytes);
}

#[test]
fn connection_id_max_length() {
    let bytes = [0u8; 20]; // max per RFC 9000
    let cid = ConnectionId::from_slice(&bytes);
    assert_eq!(cid.len(), 20);
}

#[test]
#[should_panic]
fn connection_id_too_long() {
    let bytes = [0u8; 21];
    ConnectionId::from_slice(&bytes);
}

#[test]
fn connection_id_empty() {
    let cid = ConnectionId::empty();
    assert_eq!(cid.len(), 0);
}

#[test]
fn connection_id_eq_and_hash() {
    use std::collections::HashSet;
    let a = ConnectionId::from_slice(&[1, 2, 3]);
    let b = ConnectionId::from_slice(&[1, 2, 3]);
    let c = ConnectionId::from_slice(&[1, 2, 4]);
    assert_eq!(a, b);
    assert_ne!(a, c);
    let mut set = HashSet::new();
    set.insert(a);
    assert!(set.contains(&b));
    assert!(!set.contains(&c));
}
```

Add `mod connection_id_test;` to `tests/mod.rs`.

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test --lib quic::tests::connection_id_test`
Expected: FAIL

- [ ] **Step 3: Implement ConnectionId**

Create `src/net/handler/quic/connection_id.rs`:
```rust
/// Fixed-size QUIC Connection ID (max 20 bytes, RFC 9000 §17.2)
#[derive(Clone, Copy)]
pub struct ConnectionId {
    bytes: [u8; 20],
    len: u8,
}

impl ConnectionId {
    pub fn empty() -> Self {
        Self { bytes: [0; 20], len: 0 }
    }

    pub fn from_slice(src: &[u8]) -> Self {
        assert!(src.len() <= 20, "ConnectionId max 20 bytes");
        let mut bytes = [0u8; 20];
        bytes[..src.len()].copy_from_slice(src);
        Self { bytes, len: src.len() as u8 }
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

impl PartialEq for ConnectionId {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for ConnectionId {}

impl std::hash::Hash for ConnectionId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl std::fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CID(")?;
        for b in self.as_bytes() {
            write!(f, "{:02x}", b)?;
        }
        write!(f, ")")
    }
}

/// Borrowed reference to a CID in a packet buffer (zero-copy)
#[derive(Clone, Copy)]
pub struct ConnectionIdRef<'a> {
    bytes: &'a [u8],
}

impl<'a> ConnectionIdRef<'a> {
    pub fn from_slice(bytes: &'a [u8]) -> Self {
        debug_assert!(bytes.len() <= 20);
        Self { bytes }
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
    }

    pub fn to_owned(&self) -> ConnectionId {
        ConnectionId::from_slice(self.bytes)
    }
}

/// Fixed-size set of active CIDs (bounded by active_connection_id_limit)
pub struct CidSet {
    cids: [ConnectionId; 8],
    count: u8,
}

impl CidSet {
    pub fn new() -> Self {
        Self {
            cids: [ConnectionId::empty(); 8],
            count: 0,
        }
    }

    pub fn push(&mut self, cid: ConnectionId) -> bool {
        if (self.count as usize) < 8 {
            self.cids[self.count as usize] = cid;
            self.count += 1;
            true
        } else {
            false
        }
    }

    pub fn remove(&mut self, cid: &ConnectionId) -> bool {
        for i in 0..self.count as usize {
            if &self.cids[i] == cid {
                // Swap with last
                let last = self.count as usize - 1;
                self.cids[i] = self.cids[last];
                self.count -= 1;
                return true;
            }
        }
        false
    }

    pub fn iter(&self) -> impl Iterator<Item = &ConnectionId> {
        self.cids[..self.count as usize].iter()
    }

    pub fn len(&self) -> usize {
        self.count as usize
    }
}
```

Add `pub mod connection_id;` to `quic/mod.rs`.

- [ ] **Step 4: Run tests**

Run: `cargo test --lib quic::tests::connection_id_test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/net/handler/quic/
git commit -m "feat(quic): add ConnectionId type with zero-copy ref"
```

---

### Task 4: Timer kinds

**Files:**
- Create: `src/net/handler/quic/timer_kinds.rs`

- [ ] **Step 1: Write failing test**

Test in `tests/mod.rs` or inline:
```rust
#[test]
fn timer_id_roundtrip() {
    let key = 42usize;
    let kind = QuicTimerKind::LossDetection;
    let id = quic_timer_id(key, kind);
    let (k, kd) = unpack_quic_timer_id(id);
    assert_eq!(k, key);
    assert_eq!(kd, kind);
}
```

- [ ] **Step 2: Implement timer kinds**

Create `src/net/handler/quic/timer_kinds.rs` following the exact pattern from `src/net/handler/tcp/timer_kinds.rs`:

```rust
use crate::net::timer_wheel::{TimerId, TimerHandle};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum QuicTimerKind {
    LossDetection = 0,
    Idle = 1,
    Ack = 2,
    Handshake = 3,
    Draining = 4,
    KeyDiscard = 5,
    PathValidation = 6,
    PmtuProbe = 7,
}

impl QuicTimerKind {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::LossDetection,
            1 => Self::Idle,
            2 => Self::Ack,
            3 => Self::Handshake,
            4 => Self::Draining,
            5 => Self::KeyDiscard,
            6 => Self::PathValidation,
            7 => Self::PmtuProbe,
            _ => unreachable!("invalid QuicTimerKind: {}", v),
        }
    }
}

/// Pack connection key + timer kind into TimerId.
/// Low 8 bits = kind, bits 8+ = connection key.
pub fn quic_timer_id(key: usize, kind: QuicTimerKind) -> TimerId {
    TimerId((key as u64) << 8 | kind as u64)
}

/// Unpack TimerId back to (connection_key, timer_kind).
pub fn unpack_quic_timer_id(id: TimerId) -> (usize, QuicTimerKind) {
    let kind = QuicTimerKind::from_u8((id.0 & 0xFF) as u8);
    let key = (id.0 >> 8) as usize;
    (key, kind)
}

/// Per-connection timer handles (one per kind).
pub struct QuicTimerHandles {
    handles: [Option<TimerHandle>; 8],
}

impl QuicTimerHandles {
    pub fn new() -> Self {
        Self { handles: [None; 8] }
    }

    pub fn get(&self, kind: QuicTimerKind) -> Option<TimerHandle> {
        self.handles[kind as usize]
    }

    pub fn set(&mut self, kind: QuicTimerKind, handle: TimerHandle) {
        self.handles[kind as usize] = Some(handle);
    }

    pub fn clear(&mut self, kind: QuicTimerKind) {
        self.handles[kind as usize] = None;
    }
}
```

Add `pub mod timer_kinds;` to `quic/mod.rs`.

- [ ] **Step 3: Run tests**

Run: `cargo test --lib quic`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/net/handler/quic/
git commit -m "feat(quic): add timer kinds with ID packing"
```

---

### Task 5: Packet number encoding/decoding

**Files:**
- Create: `src/net/handler/quic/transport/mod.rs`
- Create: `src/net/handler/quic/transport/packet_number.rs`
- Test: `src/net/handler/quic/tests/packet_number_test.rs`

- [ ] **Step 1: Write failing tests (RFC 9000 Appendix A)**

Create `src/net/handler/quic/tests/packet_number_test.rs`:
```rust
use super::super::transport::packet_number::*;

#[test]
fn decode_packet_number_rfc_examples() {
    // RFC 9000 Appendix A examples
    assert_eq!(decode_pn(0xa82f30ea, 0x9b32, 16), 0xa82f9b32);
}

#[test]
fn encode_packet_number_minimal_length() {
    let (truncated, len) = encode_pn(0x01, 0x00);
    assert_eq!(len, 1); // 1 byte sufficient
}

#[test]
fn roundtrip_small() {
    for pn in 0..1000u64 {
        let (truncated, nbytes) = encode_pn(pn, if pn > 0 { pn - 1 } else { 0 });
        let nbits = nbytes as u32 * 8;
        let decoded = decode_pn(if pn > 0 { pn - 1 } else { 0 }, truncated, nbits);
        assert_eq!(decoded, pn, "roundtrip failed for pn={}", pn);
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --lib quic::tests::packet_number_test`
Expected: FAIL

- [ ] **Step 3: Implement packet number encode/decode**

Create `src/net/handler/quic/transport/mod.rs`:
```rust
pub mod packet_number;
```

Create `src/net/handler/quic/transport/packet_number.rs`:
```rust
/// Decode truncated packet number to full 62-bit value.
/// RFC 9000 Appendix A.
pub fn decode_pn(largest_acked: u64, truncated: u64, nbits: u32) -> u64 {
    let expected = largest_acked + 1;
    let win = 1u64 << nbits;
    let half_win = win / 2;
    let mask = win - 1;

    let candidate = (expected & !mask) | truncated;

    if candidate <= expected.wrapping_sub(half_win) && candidate < (1u64 << 62) - win {
        candidate + win
    } else if candidate > expected + half_win && candidate >= win {
        candidate - win
    } else {
        candidate
    }
}

/// Encode packet number to minimal truncated form.
/// Returns (truncated_value, num_bytes).
pub fn encode_pn(full_pn: u64, largest_acked: u64) -> (u64, u8) {
    let range = full_pn.saturating_sub(largest_acked);
    let num_bytes = if range < (1 << 7) {
        1
    } else if range < (1 << 15) {
        2
    } else if range < (1 << 23) {
        3
    } else {
        4
    };
    let mask = (1u64 << (num_bytes * 8)) - 1;
    (full_pn & mask, num_bytes)
}
```

Add `pub mod transport;` to `quic/mod.rs`.

- [ ] **Step 4: Run tests**

Run: `cargo test --lib quic::tests::packet_number_test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/net/handler/quic/
git commit -m "feat(quic): packet number encode/decode (RFC 9000 §17.1)"
```

---

### Task 6: Variable-length integer codec (QUIC varint)

**Files:**
- Create: `src/net/handler/quic/transport/varint.rs`

QUIC uses a variable-length integer encoding (RFC 9000 §16) for almost all frame fields. This is foundational — every frame parser and builder depends on it.

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn varint_decode_1byte() {
    let buf = [0x25]; // value 37
    let (val, consumed) = decode_varint(&buf).unwrap();
    assert_eq!(val, 37);
    assert_eq!(consumed, 1);
}

#[test]
fn varint_decode_2byte() {
    let buf = [0x7b, 0xbd]; // value 15293
    let (val, consumed) = decode_varint(&buf).unwrap();
    assert_eq!(val, 15293);
    assert_eq!(consumed, 2);
}

#[test]
fn varint_decode_4byte() {
    let buf = [0x9d, 0x7f, 0x3e, 0x7d]; // value 494878333
    let (val, consumed) = decode_varint(&buf).unwrap();
    assert_eq!(val, 494878333);
    assert_eq!(consumed, 4);
}

#[test]
fn varint_decode_8byte() {
    let buf = [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]; // value 151288809941952652
    let (val, consumed) = decode_varint(&buf).unwrap();
    assert_eq!(val, 151288809941952652);
    assert_eq!(consumed, 8);
}

#[test]
fn varint_encode_roundtrip() {
    let values = [0, 1, 63, 64, 16383, 16384, 1073741823, 1073741824, 4611686018427387903];
    for &val in &values {
        let mut buf = [0u8; 8];
        let written = encode_varint(val, &mut buf);
        let (decoded, consumed) = decode_varint(&buf[..written]).unwrap();
        assert_eq!(decoded, val);
        assert_eq!(consumed, written);
    }
}
```

- [ ] **Step 2: Implement varint codec**

Create `src/net/handler/quic/transport/varint.rs`:
```rust
/// Decode a QUIC variable-length integer (RFC 9000 §16).
/// Returns (value, bytes_consumed) or None if buffer too short.
pub fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let first = buf[0];
    let len = 1 << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let val = match len {
        1 => (first & 0x3f) as u64,
        2 => {
            let raw = u16::from_be_bytes([buf[0], buf[1]]);
            (raw & 0x3fff) as u64
        }
        4 => {
            let raw = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
            (raw & 0x3fff_ffff) as u64
        }
        8 => {
            let raw = u64::from_be_bytes([
                buf[0], buf[1], buf[2], buf[3],
                buf[4], buf[5], buf[6], buf[7],
            ]);
            raw & 0x3fff_ffff_ffff_ffff
        }
        _ => unreachable!(),
    };
    Some((val, len))
}

/// Encode a QUIC variable-length integer.
/// Returns number of bytes written.
pub fn encode_varint(val: u64, buf: &mut [u8]) -> usize {
    if val < 64 {
        buf[0] = val as u8;
        1
    } else if val < 16384 {
        let bytes = (val as u16 | 0x4000).to_be_bytes();
        buf[..2].copy_from_slice(&bytes);
        2
    } else if val < 1_073_741_824 {
        let bytes = (val as u32 | 0x8000_0000).to_be_bytes();
        buf[..4].copy_from_slice(&bytes);
        4
    } else {
        let bytes = (val | 0xc000_0000_0000_0000).to_be_bytes();
        buf[..8].copy_from_slice(&bytes);
        8
    }
}

/// Returns the encoding length for a value without writing.
pub fn varint_len(val: u64) -> usize {
    if val < 64 { 1 }
    else if val < 16384 { 2 }
    else if val < 1_073_741_824 { 4 }
    else { 8 }
}
```

Add `pub mod varint;` to `transport/mod.rs`.

- [ ] **Step 3: Run tests**

Run: `cargo test --lib quic`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/net/handler/quic/
git commit -m "feat(quic): variable-length integer codec (RFC 9000 §16)"
```

---

### Task 7: Transport parameters

**Files:**
- Create: `src/net/handler/quic/transport/params.rs`
- Test: `src/net/handler/quic/tests/params_test.rs`

- [ ] **Step 1: Write failing test for defaults + encode/decode roundtrip**

```rust
#[test]
fn transport_params_defaults() {
    let p = TransportParams::default();
    assert_eq!(p.max_idle_timeout_ms, 0); // no timeout by default
    assert_eq!(p.max_udp_payload_size, 65527);
    assert_eq!(p.active_connection_id_limit, 2);
    assert_eq!(p.ack_delay_exponent, 3);
    assert_eq!(p.max_ack_delay_ms, 25);
}

#[test]
fn transport_params_encode_decode_roundtrip() {
    let mut params = TransportParams::default();
    params.initial_max_data = 1_000_000;
    params.initial_max_stream_data_bidi_local = 65536;
    params.initial_max_streams_bidi = 100;

    let mut buf = [0u8; 512];
    let written = params.encode(&mut buf);
    let decoded = TransportParams::decode(&buf[..written]).unwrap();

    assert_eq!(decoded.initial_max_data, params.initial_max_data);
    assert_eq!(decoded.initial_max_stream_data_bidi_local, params.initial_max_stream_data_bidi_local);
    assert_eq!(decoded.initial_max_streams_bidi, params.initial_max_streams_bidi);
}
```

- [ ] **Step 2: Implement TransportParams**

Create `src/net/handler/quic/transport/params.rs` with the full parameter set from the spec (RFC 9000 §18). Uses the varint codec for encoding. Each parameter is a TLV with varint ID, varint length, value.

Key parameter IDs:
```rust
const ORIGINAL_DESTINATION_CONNECTION_ID: u64 = 0x00;
const MAX_IDLE_TIMEOUT: u64 = 0x01;
const STATELESS_RESET_TOKEN: u64 = 0x02;
const MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
const INITIAL_MAX_DATA: u64 = 0x04;
const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
const INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
const INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
const INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
const ACK_DELAY_EXPONENT: u64 = 0x0a;
const MAX_ACK_DELAY: u64 = 0x0b;
const DISABLE_ACTIVE_MIGRATION: u64 = 0x0c;
const PREFERRED_ADDRESS: u64 = 0x0d;
const ACTIVE_CONNECTION_ID_LIMIT: u64 = 0x0e;
const INITIAL_SOURCE_CONNECTION_ID: u64 = 0x0f;
const RETRY_SOURCE_CONNECTION_ID: u64 = 0x10;
```

- [ ] **Step 3: Run tests, verify pass**
- [ ] **Step 4: Commit**

```bash
git commit -m "feat(quic): transport parameter encode/decode (RFC 9000 §18)"
```

---

### Task 8: QuicFrame parser (zero-copy)

**Files:**
- Create: `src/net/handler/quic/transport/frame.rs`
- Test: `src/net/handler/quic/tests/frame_test.rs`

This is the core frame codec. All variants borrow from the packet buffer.

- [ ] **Step 1: Write failing tests for frame parsing**

Test PADDING, PING, ACK, STREAM, MAX_DATA, CONNECTION_CLOSE frames with known byte sequences.

- [ ] **Step 2: Implement QuicFrame enum and parser**

The `parse_frame()` function takes a `&[u8]` slice (the packet payload after decryption) and returns `(QuicFrame<'_>, bytes_consumed)`. Uses varint decoder for type and fields. STREAM and CRYPTO frames borrow payload directly from the buffer slice.

- [ ] **Step 3: Implement frame writer**

`write_frame()` writes a frame into a `&mut [u8]` buffer and returns bytes written. This is used by `PacketBuilder`.

- [ ] **Step 4: Run tests, verify pass**
- [ ] **Step 5: Commit**

```bash
git commit -m "feat(quic): QuicFrame parser and writer (RFC 9000 §19)"
```

---

### Task 9: QUIC wire format — long/short header parsing

**Files:**
- Create: `src/net/wire/quic.rs`
- Modify: `src/net/wire/mod.rs`

- [ ] **Step 1: Write failing tests for header parsing**

Test long header (Initial, Handshake) and short header (1-RTT) parsing from known byte sequences. Verify zero-copy — `ConnectionIdRef` borrows from input buffer.

- [ ] **Step 2: Implement header parser**

Version-aware parsing: read version field before interpreting packet type bits. Returns `PacketHeader` with borrowed `ConnectionIdRef<'a>`.

- [ ] **Step 3: Run tests, verify pass**
- [ ] **Step 4: Commit**

```bash
git commit -m "feat(quic): wire format header parsing (RFC 9000 §17)"
```

---

## Phase 2: Crypto Layer

### Task 10: Initial key derivation

**Files:**
- Create: `src/net/handler/quic/crypto/mod.rs`
- Create: `src/net/handler/quic/crypto/initial_keys.rs`

- [ ] **Step 1: Write failing test using RFC 9001 Appendix A test vectors**

The RFC provides exact byte sequences for Initial key derivation from a known DCID.

- [ ] **Step 2: Implement Initial key derivation**

Uses SHA-256 HKDF with v1 salt `0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a`. Labels: `"quic key"`, `"quic iv"`, `"quic hp"` with zero-length Context. Access via `ring` or `rustls::crypto`.

- [ ] **Step 3: Run tests against test vectors**
- [ ] **Step 4: Commit**

```bash
git commit -m "feat(quic/crypto): initial key derivation (RFC 9001 §5.2)"
```

---

### Task 11: Packet protection (encrypt/decrypt in-place)

**Files:**
- Create: `src/net/handler/quic/crypto/packet_protection.rs`
- Create: `src/net/handler/quic/crypto/keys.rs`

- [ ] **Step 1: Write failing tests**

Test encrypt→decrypt roundtrip on a known payload. Verify in-place operation (same buffer, no allocation).

- [ ] **Step 2: Implement KeyPair, DirectionalKey**

Wraps `Box<dyn rustls::quic::PacketKey>` and `Box<dyn rustls::quic::HeaderProtectionKey>`.

- [ ] **Step 3: Implement encrypt_in_place / decrypt_in_place**

Operates directly on `&mut [u8]` (the XDP frame data). Header protection applied/removed per RFC 9001 §5.4.

- [ ] **Step 4: Run tests**
- [ ] **Step 5: Commit**

```bash
git commit -m "feat(quic/crypto): in-place packet protection (RFC 9001 §5.4)"
```

---

### Task 12: rustls TLS wrapper

**Files:**
- Create: `src/net/handler/quic/crypto/tls.rs`

- [ ] **Step 1: Write test for client→server handshake via rustls**

Create `rustls::quic::ServerConnection` and `rustls::quic::ClientConnection`. Feed CRYPTO data between them. Verify handshake completes and keys are produced.

- [ ] **Step 2: Implement CryptoState**

Wraps `rustls::quic::Connection`. Methods: `process_crypto_data()`, `write_crypto_data()`, `get_keys()`. CryptoBuffer for per-space reassembly.

- [ ] **Step 3: Run tests**
- [ ] **Step 4: Commit**

```bash
git commit -m "feat(quic/crypto): rustls TLS 1.3 integration"
```

---

## Phase 3: Transport Core

### Task 13: Loss detection — InFlightRing + LossDetector

**Files:**
- Create: `src/net/handler/quic/transport/loss.rs`
- Test: `src/net/handler/quic/tests/loss_test.rs`

- [ ] **Step 1: Write failing tests**

Test InFlightRing insert/get/remove/advance. Test LossDetector RTT update with known values. Test PTO computation. Test loss declaration with packet and time thresholds.

- [ ] **Step 2: Implement InFlightRing**

256-slot ring buffer indexed by `(pn - base_pn)`. O(1) operations, no allocations.

- [ ] **Step 3: Implement LossDetector**

RTT estimation (RFC 9002 §5.3), PTO computation (§6.2.1), loss declaration (§6.1), persistent congestion (§7.6).

- [ ] **Step 4: Run tests**
- [ ] **Step 5: Commit**

```bash
git commit -m "feat(quic/transport): loss detection with InFlightRing (RFC 9002)"
```

---

### Task 14: Congestion control — QuicCubic

**Files:**
- Create: `src/net/congestion/mod.rs`
- Create: `src/net/handler/quic/transport/congestion.rs`

- [ ] **Step 1: Write failing tests**

Test initial window calculation. Test slow start growth. Test loss response (ssthresh, cwnd reduction). Test persistent congestion reset to minimum window.

- [ ] **Step 2: Implement CongestionController trait**

Create `src/net/congestion/mod.rs` with the trait. Modify `src/net/mod.rs` to export it.

- [ ] **Step 3: Implement QuicCubic**

Standalone CUBIC for QUIC. Does not touch TCP's CubicState.

- [ ] **Step 4: Run tests**
- [ ] **Step 5: Commit**

```bash
git commit -m "feat(quic/transport): QuicCubic congestion control (RFC 9002 §7)"
```

---

### Task 15: ACK state and flow control

**Files:**
- Create: `src/net/handler/quic/transport/ack.rs`
- Create: `src/net/handler/quic/transport/flow_control.rs`

- [ ] **Step 1: Test ACK range tracking and pre-encoded wire format**
- [ ] **Step 2: Implement AckState with pre-encoded ranges**
- [ ] **Step 3: Implement connection-level FlowControl**
- [ ] **Step 4: Run tests**
- [ ] **Step 5: Commit**

```bash
git commit -m "feat(quic/transport): ACK state and flow control (RFC 9000 §4, §13)"
```

---

## Phase 4: Stream Layer

### Task 16: Stream state machine

**Files:**
- Create: `src/net/handler/quic/stream/mod.rs`
- Create: `src/net/handler/quic/stream/state.rs`
- Test: `src/net/handler/quic/tests/stream_state_test.rs`

- [ ] **Step 1: Write failing tests for all valid/invalid state transitions (RFC 9000 §3)**
- [ ] **Step 2: Implement SendState, RecvState, StreamState**
- [ ] **Step 3: Run tests**
- [ ] **Step 4: Commit**

```bash
git commit -m "feat(quic/stream): stream state machine (RFC 9000 §3)"
```

---

### Task 17: StreamMap + Send/Recv halves + pool

**Files:**
- Create: `src/net/handler/quic/stream/map.rs`
- Create: `src/net/handler/quic/stream/send.rs`
- Create: `src/net/handler/quic/stream/recv.rs`
- Create: `src/net/handler/quic/stream/flow_control.rs`
- Create: `src/net/handler/quic/stream/pool.rs`
- Test: `src/net/handler/quic/tests/flow_control_test.rs`

- [ ] **Step 1: Write failing tests for StreamMap direct indexing, flow control limits, stream pooling**
- [ ] **Step 2: Implement StreamMap with Vec-based direct indexing by StreamId**
- [ ] **Step 3: Implement SendHalf, RecvHalf with StreamRingBuffer**
- [ ] **Step 4: Implement per-stream flow control with final size accounting**
- [ ] **Step 5: Implement StreamPool recycling**
- [ ] **Step 6: Run tests**
- [ ] **Step 7: Commit**

```bash
git commit -m "feat(quic/stream): StreamMap, send/recv halves, pooling"
```

---

## Phase 5: Handler + Runtime Integration

### Task 18: QuicHandler skeleton

**Files:**
- Create: `src/net/handler/quic/handler.rs`
- Create: `src/net/handler/quic/connection.rs`
- Create: `src/net/handler/quic/path.rs`
- Create: `src/net/handler/quic/token.rs`

- [ ] **Step 1: Implement QuicHandler struct**

```rust
pub struct QuicHandler {
    connections: Slab<QuicConnectionState>,
    cid_map: FxHashMap<ConnectionId, usize>,
    listeners: FxHashMap<u16, ListenerState>,
}
```

Methods: `new()`, `is_quic_port()`, `process_ipv4()`, `process_ipv6()`, `handle_timer()`, `poll_send()`.

- [ ] **Step 2: Implement QuicConnectionState**

All fields from the spec. Ties crypto, transport, stream layers together.

- [ ] **Step 3: Implement PathState, AmplificationLimit**
- [ ] **Step 4: Verify compilation**

Run: `cargo check`

- [ ] **Step 5: Commit**

```bash
git commit -m "feat(quic): QuicHandler with connection table and path state"
```

---

### Task 19: Dispatch chain integration

**Files:**
- Modify: `src/net/handler/ipv4.rs`
- Modify: `src/net/handler/ipv6.rs`
- Modify: `src/net/handler/ethernet.rs`
- Modify: `src/rt/local.rs`
- Modify: `src/rt/context.rs`

This is the highest-risk change — modifies the hot path.

- [ ] **Step 1: Add `quic_handler` parameter to Ipv4Handler::handle()**

Add `quic_handler: &mut QuicHandler` parameter. In the UDP match arm, check `quic_handler.is_quic_port(dst_port)` before forwarding to UdpHandler.

- [ ] **Step 2: Same change for Ipv6Handler::handle()**

- [ ] **Step 3: Thread quic_handler through EthernetHandler**

- [ ] **Step 4: Add QuicHandler to LocalRuntime**

Add field, initialize in `new()`, add timer dispatch in event loop, add `poll_send()` call, add eviction.

- [ ] **Step 5: Run ALL existing tests to verify no regressions**

Run: `cargo test`
Expected: All 1107 TCP tests still pass. No QUIC tests run yet (no QUIC listeners bound).

- [ ] **Step 6: Commit**

```bash
git commit -m "feat(quic): integrate QuicHandler into dispatch chain and runtime"
```

---

## Phase 6: Socket API

### Task 20: QuicListener, QuicConnection, QuicStream

**Files:**
- Create: `src/net/socket/quic.rs`
- Modify: `src/net/socket/mod.rs`
- Modify: `src/net/mod.rs`

- [ ] **Step 1: Implement QuicListener**

`listen()`, `accept()` → `Accept` future. Same pattern as `TcpListener`.

- [ ] **Step 2: Implement QuicConnection**

`connect()`, `connect_0rtt()`, `open_bidi_stream()`, `open_uni_stream()`, `accept_stream()`, `close()`.

- [ ] **Step 3: Implement QuicStream**

`read()`, `write()`, `finish()`, `reset()`, `split()`. Async futures that poll `LocalQueue<QuicEvent>`.

- [ ] **Step 4: Export from socket/mod.rs and net/mod.rs**

- [ ] **Step 5: Verify compilation**

Run: `cargo check`

- [ ] **Step 6: Commit**

```bash
git commit -m "feat(quic): socket API — QuicListener, QuicConnection, QuicStream"
```

---

### Task 21: End-to-end handshake test

**Files:**
- Test: `src/net/handler/quic/tests/handshake_test.rs`

- [ ] **Step 1: Write integration test**

Create a test that:
1. Sets up a QuicHandler with a server TLS config (self-signed cert)
2. Builds an Initial packet from a mock client
3. Feeds it through `process_ipv4()`
4. Verifies server responds with Initial + Handshake packets
5. Completes the handshake exchange
6. Verifies connection state reaches Established

- [ ] **Step 2: Run test**

Run: `cargo test --lib quic::tests::handshake_test`

- [ ] **Step 3: Debug and iterate until passing**

- [ ] **Step 4: Commit**

```bash
git commit -m "test(quic): end-to-end handshake test"
```

---

### Task 22: Stream data transfer test

- [ ] **Step 1: Write test for bidi stream data exchange over established connection**
- [ ] **Step 2: Verify stream flow control, FIN, and cleanup**
- [ ] **Step 3: Commit**

```bash
git commit -m "test(quic): stream data transfer and flow control"
```

---

## Phase 7: Packet Building & Retransmission

### Task 23: FrameLog + PacketBuilder

**Files:**
- Create: `src/net/handler/quic/transport/frame_log.rs`
- Create: `src/net/handler/quic/transport/packet_builder.rs`

FrameLog is the circular buffer that stores `SentFrame` entries. PacketBuilder constructs complete QUIC packets: header + frames + encryption + header protection.

- [ ] **Step 1: Write failing tests for FrameLog**

```rust
#[test]
fn frame_log_insert_and_range() {
    let mut log = FrameLog::new();
    let start = log.head();
    log.push(SentFrame::Ping);
    log.push(SentFrame::Stream { id: StreamId(0), offset: 0, len: 100, fin: false });
    let end = log.head();
    assert_eq!(end - start, 2);
    let frames: Vec<_> = log.range(start, end).collect();
    assert_eq!(frames.len(), 2);
}

#[test]
fn frame_log_wraps_around() {
    let mut log = FrameLog::new();
    for i in 0..1100 { // exceeds 1024 capacity
        log.push(SentFrame::Ping);
    }
    // old entries overwritten, no panic
    assert!(log.head() >= 1100);
}
```

- [ ] **Step 2: Implement FrameLog (1024-entry circular buffer)**
- [ ] **Step 3: Write failing tests for PacketBuilder**

Test: build an Initial packet with CRYPTO frame, verify header layout, verify padding to ≥1200 bytes. Build a 1-RTT packet with STREAM frame.

- [ ] **Step 4: Implement PacketBuilder**

`begin()` → write frames → `pad_to()` → `finish()` (encrypt + header protect). Coalescing support: multiple packets in one datagram.

- [ ] **Step 5: Run tests**
- [ ] **Step 6: Commit**

```bash
git commit -m "feat(quic/transport): FrameLog and PacketBuilder with coalescing"
```

---

### Task 24: Frame-level retransmission

**Files:**
- Modify: `src/net/handler/quic/transport/loss.rs`
- Create: `src/net/handler/quic/transport/retransmit.rs`

When LossDetector declares a packet lost, the *information* (not the packet) must be re-sent.

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn lost_crypto_frame_is_resent() {
    // Declare packet containing CRYPTO frame as lost
    // Verify retransmit queue contains CRYPTO data
}

#[test]
fn lost_stream_frame_is_resent_from_send_buffer() {
    // Declare packet containing STREAM frame as lost
    // Verify the stream's send buffer marks data for retransmission
}

#[test]
fn lost_max_data_resends_current_value() {
    // Lost MAX_DATA frame → re-send with current value, not old value
}
```

- [ ] **Step 2: Implement retransmission logic**

Walk `FrameLog` entries for the lost packet's `frame_range`. For each `SentFrame`, mark the corresponding data/state for re-sending. Stream data re-sent from `SendHalf` buffer. Control frames regenerated with current values.

- [ ] **Step 3: Run tests**
- [ ] **Step 4: Commit**

```bash
git commit -m "feat(quic/transport): frame-level retransmission (RFC 9000 §13.3)"
```

---

## Phase 8: Key Lifecycle & Security

### Task 25: Key update

**Files:**
- Modify: `src/net/handler/quic/crypto/keys.rs`
- Test: `src/net/handler/quic/tests/crypto_test.rs`

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn key_update_produces_new_keys() {
    // After handshake, initiate key update
    // Verify new keys differ from old
    // Verify header protection keys unchanged
}

#[test]
fn key_update_retains_old_read_keys() {
    // After update, old read keys still available for 3×PTO
}

#[test]
fn double_key_update_without_ack_is_error() {
    // Detect second key update before ACK for current phase
    // Verify KEY_UPDATE_ERROR
}
```

- [ ] **Step 2: Implement key update in CryptoState**

Track `key_phase: bool`, `lowest_pn_current_phase: u64`. Use `"quic ku"` HKDF label. Retain old read keys for 3×PTO via `KeyDiscard` timer. Header protection keys DO NOT update.

- [ ] **Step 3: Run tests**
- [ ] **Step 4: Commit**

```bash
git commit -m "feat(quic/crypto): key update with phase tracking (RFC 9001 §6)"
```

---

### Task 26: AEAD usage limits

**Files:**
- Modify: `src/net/handler/quic/connection.rs`
- Modify: `src/net/handler/quic/crypto/packet_protection.rs`

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn aead_confidentiality_limit_triggers_key_update() {
    // Encrypt 2^23 packets with AES-128-GCM keys
    // Verify key update is triggered before limit
}

#[test]
fn aead_integrity_limit_closes_connection() {
    // Simulate 2^52 failed decryptions (or 2^36 for ChaCha20)
    // Verify AEAD_LIMIT_REACHED error
}
```

- [ ] **Step 2: Add counters to QuicConnectionState**

`packets_encrypted: u64` (per key set, reset on key update), `failed_decryptions: u64` (per connection lifetime). Check after each encrypt/decrypt operation.

- [ ] **Step 3: Run tests**
- [ ] **Step 4: Commit**

```bash
git commit -m "feat(quic/crypto): AEAD usage limits (RFC 9001 §6.6)"
```

---

### Task 27: Retry integrity tag + token validation

**Files:**
- Modify: `src/net/handler/quic/token.rs`
- Modify: `src/net/handler/quic/crypto/initial_keys.rs`

- [ ] **Step 1: Write failing tests using RFC 9001 §5.8 test vectors**

Fixed key: `0xbe0c690b9f66575a1d766b54e368c84e`
Fixed nonce: `0x461599d35d632bf2239825bb`

- [ ] **Step 2: Implement Retry tag computation and validation**
- [ ] **Step 3: Implement RetryToken struct with HMAC integrity, timestamp, original DCID**
- [ ] **Step 4: Run tests**
- [ ] **Step 5: Commit**

```bash
git commit -m "feat(quic): Retry integrity tag and token validation (RFC 9001 §5.8)"
```

---

## Phase 9: Protocol Features

### Task 28: Version negotiation

**Files:**
- Modify: `src/net/handler/quic/handler.rs`
- Modify: `src/net/wire/quic.rs`

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn unknown_version_triggers_version_negotiation() {
    // Send Initial with version 0xdeadbeef
    // Verify server responds with VN packet containing 0x00000001
}

#[test]
fn client_discards_vn_after_processing_packet() {
    // After successfully processing any packet, VN packets are ignored
}
```

- [ ] **Step 2: Implement VN packet generation (echo CIDs, list supported versions)**
- [ ] **Step 3: Implement client-side VN handling with downgrade prevention**
- [ ] **Step 4: Run tests**
- [ ] **Step 5: Commit**

```bash
git commit -m "feat(quic): version negotiation (RFC 9000 §6, RFC 8999)"
```

---

### Task 29: Stateless reset

**Files:**
- Modify: `src/net/handler/quic/handler.rs`
- Modify: `src/net/handler/quic/connection_id.rs`

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn stateless_reset_token_from_cid() {
    // Derive token via HMAC with server secret
    // Verify unpredictability (different CIDs → different tokens)
}

#[test]
fn detect_stateless_reset_on_decrypt_failure() {
    // Packet fails decryption → check last 16 bytes against known tokens
}
```

- [ ] **Step 2: Implement token derivation (HMAC-SHA256 of CID with server secret)**
- [ ] **Step 3: Implement detection in inbound packet processing**
- [ ] **Step 4: Run tests**
- [ ] **Step 5: Commit**

```bash
git commit -m "feat(quic): stateless reset tokens (RFC 9000 §10.3)"
```

---

### Task 30: CID retirement

**Files:**
- Modify: `src/net/handler/quic/handler.rs`
- Modify: `src/net/handler/quic/connection_id.rs`

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn retire_prior_to_removes_old_cids() {
    // Receive NewConnectionId with retire_prior_to=3
    // Verify CIDs with seq < 3 are removed from cid_map
    // Verify RetireConnectionId frames are queued for each
}

#[test]
fn cid_count_respects_active_limit() {
    // active_connection_id_limit = 4
    // Verify we never hold more than 4 active CIDs
}
```

- [ ] **Step 2: Implement retirement protocol in handler**
- [ ] **Step 3: Run tests**
- [ ] **Step 4: Commit**

```bash
git commit -m "feat(quic): CID retirement protocol (RFC 9000 §5.1)"
```

---

### Task 31: ECN support

**Files:**
- Create: `src/net/handler/quic/transport/ecn.rs`
- Modify: `src/net/handler/quic/transport/congestion.rs`

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn ecn_validation_during_handshake() {
    // Send ECT(0)-marked packet, receive ACK with ECN counts
    // Verify ECN capability confirmed
}

#[test]
fn ecn_ce_signals_congestion() {
    // ACK reports increased ecn_ce count
    // Verify congestion controller receives on_ecn_ce()
}

#[test]
fn ecn_disabled_on_validation_failure() {
    // ECT(0) packets not reflected in ACK ECN counts
    // Verify ECN disabled for this path
}
```

- [ ] **Step 2: Implement EcnState and validation algorithm (RFC 9002 Appendix A.4)**
- [ ] **Step 3: Run tests**
- [ ] **Step 4: Commit**

```bash
git commit -m "feat(quic/transport): ECN support and validation (RFC 9000 §13.4)"
```

---

### Task 32: Pacing

**Files:**
- Modify: `src/net/handler/quic/transport/congestion.rs`
- Modify: `src/net/handler/quic/handler.rs`

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn pacing_rate_computed_from_cwnd_and_rtt() {
    let cwnd = 14720;
    let srtt = Duration::from_millis(50);
    let rate = pacing_rate(cwnd, srtt, 1.25);
    assert_eq!(rate, (1.25 * 14720.0 / 0.050) as u64); // ~368000 bytes/sec
}

#[test]
fn pacing_timer_delays_send() {
    // After sending a packet, next_send_time is set
    // Verify poll_send() does not send before next_send_time
}

#[test]
fn ack_only_packets_bypass_pacing() {
    // ACK-only packet sent immediately regardless of pacing timer
}
```

- [ ] **Step 2: Implement timer-driven pacing in poll_send()**

Compute `next_send_time` after each send. If `now < next_send_time`, arm `TimerWheel` and return. Burst limit: `K_INITIAL_WINDOW` bytes without pacing.

- [ ] **Step 3: Run tests**
- [ ] **Step 4: Commit**

```bash
git commit -m "feat(quic/transport): timer-driven pacing (RFC 9002 §7.7)"
```

---

### Task 33: Path validation + connection migration

**Files:**
- Modify: `src/net/handler/quic/path.rs`
- Modify: `src/net/handler/quic/handler.rs`

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn path_challenge_response_roundtrip() {
    // Send PATH_CHALLENGE with 8 random bytes
    // Receive PATH_RESPONSE with same bytes
    // Verify path is validated
}

#[test]
fn migration_resets_congestion_controller() {
    // Packet from new address detected
    // Verify congestion window reset, anti-amplification applied
}

#[test]
fn different_cid_per_path() {
    // On migration, verify new CID is used (linkability prevention)
}
```

- [ ] **Step 2: Implement PATH_CHALLENGE/RESPONSE in handler**
- [ ] **Step 3: Implement migration detection and congestion reset**
- [ ] **Step 4: Run tests**
- [ ] **Step 5: Commit**

```bash
git commit -m "feat(quic): path validation and connection migration (RFC 9000 §8-9)"
```

---

### Task 34: QuicEvent enum

**Files:**
- Create: `src/net/handler/quic/event.rs`

- [ ] **Step 1: Define QuicEvent**

```rust
pub enum QuicEvent {
    HandshakeComplete,
    NewStream(StreamId),
    StreamReadable(StreamId),
    StreamWritable(StreamId),
    StreamFinished(StreamId),
    StreamReset(StreamId, u64),
    ConnectionError(TransportError),
    ConnectionClosed(u64),
}
```

- [ ] **Step 2: Commit**

```bash
git commit -m "feat(quic): QuicEvent enum for socket layer notifications"
```

---

## Important Notes for Task 19 (Dispatch Chain Integration)

**This task MUST be implemented as a single atomic change:**

1. Create `QuicHandler::new()` returning a no-op handler (`is_quic_port()` returns `false`)
2. Update ALL handler signatures (`EthernetHandler::handle()`, `Ipv4Handler::handle()`, `Ipv6Handler::handle()`) in one pass
3. Update ALL test helpers that construct handlers (e.g., `new_handlers()` in `ethernet.rs` tests, similar helpers in `ipv4.rs`, `ipv6.rs` tests)
4. Update `LocalRuntime` constructor and event loop
5. The QUIC dispatch logic (port check) can be wired in a follow-up commit

This ensures the first commit is a pure mechanical signature change that preserves all existing behavior. Run `cargo test` after the signature change to verify zero regressions before adding any QUIC logic.

**Socket API (Task 20):** Follow the `Rc<UnsafeCell<QuicHandler>>` interior mutability pattern from TCP socket types. Reference `src/net/socket/tcp.rs` as the template — same waker registration, same `LocalQueue<QuicEvent>` polling pattern.

---

## Post-Implementation

After all tasks complete:

1. Run `cargo test` — all existing + new tests must pass
2. Run `cargo clippy` — no warnings
3. Create PR from `quic-rustls` branch to `main`
