# QUIC Functional Transport Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the QUIC implementation as a functional bidirectional transport — client+server data path, graceful shutdown, connection migration, key rotation, and version negotiation.

**Architecture:** End-to-end first (Approach B). Complete SendHalf and client connect to get a working bidirectional transport, then add graceful shutdown, connection migration, key update wire protocol, and version negotiation. Each task is independently testable.

**Tech Stack:** Rust, rustls (TLS 1.3), ring (crypto), smallvec, coarsetime

**Spec:** `docs/superpowers/specs/2026-03-23-quic-functional-transport-design.md`

**Testing:** Always use `cargo test` (no `--features` or `--all-features`). Tests require root (configured via `.cargo/config.toml`).

---

## File Structure

### New files:
- `src/net/handler/quic/tests/send_half_test.rs` — SendHalf unit tests
- `src/net/handler/quic/tests/client_connect_test.rs` — Client connect integration tests
- `src/net/handler/quic/tests/shutdown_test.rs` — Graceful shutdown tests
- `src/net/handler/quic/tests/migration_test.rs` — Connection migration tests
- `src/net/handler/quic/tests/key_update_wire_test.rs` — Key update wire protocol tests
- `src/net/handler/quic/tests/version_negotiation_test.rs` — Version negotiation client tests

### Modified files:
- `src/net/handler/quic/stream/send.rs` — retransmit ranges, acked ranges, ack processing
- `src/net/handler/quic/stream/recv.rs` — (already has `peek_at`, no changes needed)
- `src/net/handler/quic/processor.rs` — loss→retransmit ranges, ACK→acked ranges, migration signals, key phase detection, VN handling, CONNECTION_CLOSE event push
- `src/net/handler/quic/transport/packet_builder.rs` — retransmit range emit, client Initial padding, key update initiation
- `src/net/handler/quic/handler.rs` — `initiate_connection()`, wake-all on removal, migration CID map update, VN routing
- `src/net/handler/quic/connection.rs` — `PreviousPath`, `pending_migration`, `needs_key_update`, `original_version`, `client_config`/`server_name` fields
- `src/net/handler/quic/path.rs` — migration helper methods
- `src/net/handler/quic/connection_id.rs` — `pick_unused_cid()` for migration
- `src/net/handler/quic/event.rs` — add `DataAcked` event variant
- `src/net/socket/quic.rs` — `Connect` future, `ConnectionClosed(Option<u64>)`, backpressure waking
- `src/net/socket/queue.rs` — add `wake()` method to `LocalQueue` (fires registered waker without pushing)
- `src/net/handler/quic/crypto/keys.rs` — `derive_next_keys()` wrapper
- `src/net/handler/quic/transport/params.rs` — `version_information` parsing
- `src/net/handler/quic/tests/mod.rs` — register new test modules

---

## Task 1: SendHalf Retransmit Ranges and Acked Ranges

**Files:**
- Modify: `src/net/handler/quic/stream/send.rs`
- Create: `src/net/handler/quic/tests/send_half_test.rs`
- Modify: `src/net/handler/quic/tests/mod.rs`

- [ ] **Step 1: Write failing test for retransmit range insertion and merging**

```rust
// src/net/handler/quic/tests/send_half_test.rs
use crate::net::handler::quic::stream::send::SendHalf;

#[test]
fn test_add_retransmit_range_basic() {
    let mut send = SendHalf::new(65535);
    send.add_retransmit_range(100, 200);
    assert_eq!(send.retransmit_ranges(), &[(100, 200)]);
}

#[test]
fn test_retransmit_ranges_merge_adjacent() {
    let mut send = SendHalf::new(65535);
    send.add_retransmit_range(100, 200);
    send.add_retransmit_range(200, 300);
    assert_eq!(send.retransmit_ranges(), &[(100, 300)]);
}

#[test]
fn test_retransmit_ranges_merge_overlapping() {
    let mut send = SendHalf::new(65535);
    send.add_retransmit_range(100, 300);
    send.add_retransmit_range(200, 400);
    assert_eq!(send.retransmit_ranges(), &[(100, 400)]);
}

#[test]
fn test_retransmit_ranges_kept_sorted() {
    let mut send = SendHalf::new(65535);
    send.add_retransmit_range(500, 600);
    send.add_retransmit_range(100, 200);
    send.add_retransmit_range(300, 400);
    assert_eq!(send.retransmit_ranges(), &[(100, 200), (300, 400), (500, 600)]);
}
```

- [ ] **Step 2: Register test module in mod.rs**

Add to `src/net/handler/quic/tests/mod.rs`:
```rust
mod send_half_test;
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test send_half_test -- --nocapture 2>&1 | tail -20`
Expected: compilation error — `add_retransmit_range` and `retransmit_ranges` don't exist.

- [ ] **Step 4: Implement retransmit range tracking in SendHalf**

In `src/net/handler/quic/stream/send.rs`, add `retransmit_ranges` field and methods:

```rust
use smallvec::SmallVec;
use super::recv::StreamRingBuffer;

pub struct SendHalf {
    pub buffer: StreamRingBuffer,
    pub sent: u64,
    pub acked: u64,
    pub max_stream_data: u64,
    pub fin_sent: bool,
    pub blocked_at: Option<u64>,
    pub reset_requested: bool,
    pub reset_error_code: u64,
    pub(crate) retransmit: SmallVec<[(u64, u64); 4]>,
    acked_ooo: SmallVec<[(u64, u64); 4]>,
}
```

Initialize both to `SmallVec::new()` in `new()` and clear in `reset()`.

Add methods:

```rust
/// Insert a lost byte range for retransmission. Maintains sorted, merged list.
pub fn add_retransmit_range(&mut self, start: u64, end: u64) {
    // Find insertion point
    let mut i = 0;
    while i < self.retransmit.len() && self.retransmit[i].1 < start {
        i += 1;
    }
    // Merge with overlapping/adjacent ranges
    let mut new_start = start;
    let mut new_end = end;
    let mut remove_from = i;
    let mut remove_to = i;
    while remove_to < self.retransmit.len() && self.retransmit[remove_to].0 <= new_end {
        new_start = new_start.min(self.retransmit[remove_to].0);
        new_end = new_end.max(self.retransmit[remove_to].1);
        remove_to += 1;
    }
    // Replace merged ranges with single range
    if remove_from < remove_to {
        self.retransmit.drain(remove_from..remove_to);
    }
    self.retransmit.insert(remove_from, (new_start, new_end));
}

/// Read-only access to retransmit ranges for testing and packet builder.
pub fn retransmit_ranges(&self) -> &[(u64, u64)] {
    &self.retransmit
}

/// Remove the first retransmit range (after it's been sent). Returns it.
pub fn pop_retransmit_range(&mut self) -> Option<(u64, u64)> {
    if self.retransmit.is_empty() {
        None
    } else {
        Some(self.retransmit.remove(0))
    }
}

/// Trim retransmit ranges: remove bytes that have been acked.
/// Builds a new list to avoid borrow conflicts from splits.
pub fn trim_retransmit_for_ack(&mut self, ack_start: u64, ack_end: u64) {
    let mut result: SmallVec<[(u64, u64); 4]> = SmallVec::new();
    for &(s, e) in &self.retransmit {
        if ack_start <= s && ack_end >= e {
            continue; // fully acked — remove
        }
        if ack_start > s && ack_end < e {
            // Split: acked range punches a hole
            result.push((s, ack_start));
            result.push((ack_end, e));
            continue;
        }
        let mut ns = s;
        let mut ne = e;
        if ack_start <= ns && ack_end > ns {
            ns = ack_end; // trim front
        }
        if ack_end >= ne && ack_start < ne {
            ne = ack_start; // trim back
        }
        if ns < ne {
            result.push((ns, ne));
        }
    }
    self.retransmit = result;
}

/// Whether there is any pending data to send (new or retransmit).
pub fn has_pending_data(&self) -> bool {
    !self.retransmit.is_empty() || self.can_send() || (self.fin_sent && self.sent == self.acked + self.buffer.len() as u64)
}
```

Note: the `trim_retransmit_for_ack` split case is tricky — use retain_mut carefully. An alternative is to rebuild the list. Implementer should choose whichever is cleaner.

- [ ] **Step 5: Write tests for `trim_retransmit_for_ack`**

```rust
#[test]
fn test_trim_retransmit_fully_acked() {
    let mut send = SendHalf::new(65535);
    send.add_retransmit_range(100, 200);
    send.trim_retransmit_for_ack(100, 200);
    assert!(send.retransmit_ranges().is_empty());
}

#[test]
fn test_trim_retransmit_partial_front() {
    let mut send = SendHalf::new(65535);
    send.add_retransmit_range(100, 300);
    send.trim_retransmit_for_ack(100, 200);
    assert_eq!(send.retransmit_ranges(), &[(200, 300)]);
}

#[test]
fn test_trim_retransmit_split() {
    let mut send = SendHalf::new(65535);
    send.add_retransmit_range(100, 400);
    send.trim_retransmit_for_ack(200, 300); // punch a hole
    assert_eq!(send.retransmit_ranges(), &[(100, 200), (300, 400)]);
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test send_half_test -- --nocapture 2>&1 | tail -20`
Expected: all 7 tests PASS.

- [ ] **Step 7: Commit**

```bash
git add src/net/handler/quic/stream/send.rs src/net/handler/quic/tests/send_half_test.rs src/net/handler/quic/tests/mod.rs
git commit -m "feat(quic): add retransmit range tracking to SendHalf"
```

---

## Task 2: SendHalf Acked Ranges and Buffer Reclaim

**Files:**
- Modify: `src/net/handler/quic/stream/send.rs`
- Modify: `src/net/handler/quic/tests/send_half_test.rs`

- [ ] **Step 1: Write failing tests for acked range tracking and coalescing**

```rust
#[test]
fn test_on_ack_contiguous_advances_acked() {
    let mut send = SendHalf::new(65535);
    send.write(b"hello world"); // 11 bytes
    send.sent = 11;
    send.on_ack(0, 5); // ack bytes 0-5
    assert_eq!(send.acked, 5);
    assert_eq!(send.buffer.len(), 6); // 6 bytes remain (bytes 5-10)
}

#[test]
fn test_on_ack_out_of_order_stores_range() {
    let mut send = SendHalf::new(65535);
    send.write(b"hello world"); // 11 bytes
    send.sent = 11;
    send.on_ack(5, 8); // ack bytes 5-8 (gap: 0-5 not acked)
    assert_eq!(send.acked, 0); // can't advance past gap
    assert_eq!(send.acked_ooo_ranges(), &[(5, 8)]);
}

#[test]
fn test_on_ack_coalesces_gap_fill() {
    let mut send = SendHalf::new(65535);
    send.write(b"hello world"); // 11 bytes
    send.sent = 11;
    send.on_ack(5, 11); // ack 5-11
    assert_eq!(send.acked, 0); // gap at 0-5
    send.on_ack(0, 5); // fill gap
    assert_eq!(send.acked, 11); // coalesced!
    assert!(send.acked_ooo_ranges().is_empty());
    assert!(send.buffer.is_empty()); // all data freed
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test send_half_test -- --nocapture 2>&1 | tail -20`
Expected: `on_ack` and `acked_ooo_ranges` don't exist.

- [ ] **Step 3: Implement acked range tracking and buffer reclaim**

Add to `SendHalf`:

```rust
/// Record that bytes [start, end) have been acknowledged.
/// Advances `acked` and frees buffer space when contiguous.
/// Returns the number of bytes newly freed from the buffer.
pub fn on_ack(&mut self, start: u64, end: u64) -> usize {
    if end <= self.acked {
        return 0; // already acked
    }

    let freed_before = self.acked;

    if start <= self.acked {
        // Extends contiguous acked region
        self.acked = end;
    } else {
        // Out of order — store for later coalescing
        self.add_acked_ooo(start, end);
    }

    // Coalesce: check if any OOO ranges are now contiguous with acked
    loop {
        let mut merged = false;
        self.acked_ooo.retain_mut(|(s, e)| {
            if *s <= self.acked {
                if *e > self.acked {
                    self.acked = *e;
                }
                merged = true;
                false // remove — now contiguous
            } else {
                true
            }
        });
        if !merged {
            break;
        }
    }

    // Free buffer space: advance head by the amount acked advanced.
    // Use consume() — O(1), no allocation, just advances head pointer.
    let to_free = (self.acked - freed_before) as usize;
    if to_free > 0 {
        self.buffer.consume(to_free);
    }

    to_free
}

fn add_acked_ooo(&mut self, start: u64, end: u64) {
    // Same merge logic as retransmit ranges
    let mut i = 0;
    while i < self.acked_ooo.len() && self.acked_ooo[i].1 < start {
        i += 1;
    }
    let mut new_start = start;
    let mut new_end = end;
    let mut remove_from = i;
    let mut remove_to = i;
    while remove_to < self.acked_ooo.len() && self.acked_ooo[remove_to].0 <= new_end {
        new_start = new_start.min(self.acked_ooo[remove_to].0);
        new_end = new_end.max(self.acked_ooo[remove_to].1);
        remove_to += 1;
    }
    if remove_from < remove_to {
        self.acked_ooo.drain(remove_from..remove_to);
    }
    self.acked_ooo.insert(remove_from, (new_start, new_end));
}

pub fn acked_ooo_ranges(&self) -> &[(u64, u64)] {
    &self.acked_ooo
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test send_half_test -- --nocapture 2>&1 | tail -20`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/net/handler/quic/stream/send.rs src/net/handler/quic/tests/send_half_test.rs
git commit -m "feat(quic): add acked range tracking and buffer reclaim to SendHalf"
```

---

## Task 3: Wire SendHalf into Processor (Loss → Retransmit Ranges)

**Files:**
- Modify: `src/net/handler/quic/processor.rs:77-83` (loss handler)
- Modify: `src/net/handler/quic/processor.rs:936-943` (ACK loss handler)
- Modify: `src/net/handler/quic/event.rs`

- [ ] **Step 1: Add DataAcked event variant**

In `src/net/handler/quic/event.rs`, add:
```rust
/// Stream send data was acknowledged, buffer space freed (backpressure release)
DataAcked,
```

- [ ] **Step 2: Change loss handler to insert retransmit ranges instead of rewinding `sent`**

In `processor.rs`, replace both occurrences of `send.sent = send.sent.min(retx_offset)` (lines 81 and 941) with:

```rust
let retx_end = retx_offset + retx_len as u64;
send.add_retransmit_range(retx_offset, retx_end);
```

The `retransmit.streams` entries already contain `(stream_id, offset, len, fin)` — use `offset` and `len` to compute the range.

At line 77, the loop is:
```rust
for &(stream_id, retx_offset, _, _) in &retransmit.streams {
```
Change to:
```rust
for &(stream_id, retx_offset, retx_len, _) in &retransmit.streams {
```
And replace the body.

Same change for the equivalent loop near line 936.

- [ ] **Step 3: Run existing tests to verify nothing breaks**

Run: `cargo test -- --nocapture 2>&1 | tail -30`
Expected: all existing tests still pass.

- [ ] **Step 4: Commit**

```bash
git add src/net/handler/quic/processor.rs src/net/handler/quic/event.rs
git commit -m "feat(quic): wire loss detection to SendHalf retransmit ranges"
```

---

## Task 4: Packet Builder — Emit Retransmit Ranges Before New Data

**Files:**
- Modify: `src/net/handler/quic/transport/packet_builder.rs`
- Modify: `src/net/handler/quic/processor.rs:1698-1731` (stream data emit loop)

- [ ] **Step 1: Update the stream data emit loop in processor.rs**

The current loop at `processor.rs:1698-1731` sends new data using `peek_slices`. Change it to first emit retransmit ranges, then new data.

Replace the body of the `for stream_id in pending_streams` loop (lines 1703-1731) with:

```rust
if let Some(entry) = conn.streams.get_mut(stream_id)
    && let Some(ref mut send) = entry.send
{
    // Priority 1: retransmit lost data
    while let Some((range_start, range_end)) = send.retransmit_ranges().first().copied() {
        if builder.remaining() < 20 {
            break;
        }
        let range_len = (range_end - range_start) as usize;
        let offset_from_head = (range_start - send.acked) as usize;
        let max_len = builder.remaining().saturating_sub(20).min(range_len);
        let mut retx_buf = vec![0u8; max_len];
        let n = send.buffer.peek_at(offset_from_head, &mut retx_buf);
        if n == 0 {
            send.pop_retransmit_range();
            continue;
        }
        let fin = send.fin_sent && range_start + n as u64 >= send.final_size();
        let written = builder.write_stream(
            stream_id,
            range_start,
            &retx_buf[..n],
            fin,
            &mut conn.frame_log,
        );
        if written == range_len {
            send.pop_retransmit_range();
        } else if written > 0 {
            // Partially sent — trim the range
            send.retransmit[0].0 = range_start + written as u64;
        }
        if written > 0 {
            wrote_ack_eliciting = true;
        }
        break; // one range per iteration to be fair to other streams
    }

    // Priority 2: new data
    if builder.remaining() >= 20 {
        let unsent_off = (send.sent - send.acked) as usize;
        let max_len = builder.remaining().saturating_sub(20);
        let (part1, part2) = send.buffer.peek_slices(unsent_off, max_len);
        let total = part1.len() + part2.len();
        let all_sent = unsent_off + total >= send.buffer.len();
        let fin = send.fin_sent && all_sent;
        if total > 0 || fin {
            let written = builder.write_stream_parts(
                stream_id,
                send.sent,
                part1,
                part2,
                fin,
                &mut conn.frame_log,
            );
            send.sent += written as u64;
            if written > 0 || fin {
                wrote_ack_eliciting = true;
            }
        }
    }
}
```

Note: the implementer should check whether `write_stream` exists on the packet builder or if only `write_stream_parts` is available. If only `write_stream_parts`, pass the retransmit buffer as `(part1, &[])`.

- [ ] **Step 2: Run existing tests**

Run: `cargo test -- --nocapture 2>&1 | tail -30`
Expected: all tests PASS.

- [ ] **Step 3: Commit**

```bash
git add src/net/handler/quic/processor.rs
git commit -m "feat(quic): emit retransmit ranges before new data in packet builder"
```

---

## Task 5: Backpressure — Wake Writers on ACK

**Files:**
- Modify: `src/net/handler/quic/processor.rs` (ACK handler)
- Modify: `src/net/handler/quic/stream/map.rs` (pending_send_count)

- [ ] **Step 1: Replace existing ACK processing with `send.on_ack()`**

**Important:** The existing code at `processor.rs:963-1001` already processes stream ACKs — it advances `send.acked`, calls `send.buffer.consume()`, and decrements `pending_send_count`. This existing code must be **replaced**, not duplicated. Find where `SentFrame::Stream` ACK ranges are resolved and replace the manual `acked`/`consume` logic with:

```rust
let freed = send.on_ack(ack_offset, ack_offset + ack_len as u64);
if freed > 0 {
    conn.event_queue.push(QuicEvent::DataAcked);
}
// Also trim retransmit ranges for the acked region
send.trim_retransmit_for_ack(ack_offset, ack_offset + ack_len as u64);
```

Remove the old manual `send.acked += advance`, `send.buffer.consume(advance)`, and `pending_send_count -= 1` code — `on_ack()` handles all of that now.

- [ ] **Step 2: Update `pending_send_count` to account for retransmit ranges**

In `src/net/handler/quic/stream/map.rs`, wherever `pending_send_count` is checked or decremented, also check `send.has_pending_data()` which now includes retransmit ranges.

The `iter_send_mut()` method should yield streams that have retransmit ranges even if their buffer is empty.

- [ ] **Step 3: Run existing tests**

Run: `cargo test -- --nocapture 2>&1 | tail -30`
Expected: all tests PASS.

- [ ] **Step 4: Commit**

```bash
git add src/net/handler/quic/processor.rs src/net/handler/quic/stream/map.rs
git commit -m "feat(quic): wake blocked writers on ACK, track retransmit in pending_send_count"
```

---

## Task 6: Client-Side Connect — Connection State Fields

**Files:**
- Modify: `src/net/handler/quic/connection.rs`

- [ ] **Step 1: Add client config and server name fields to QuicConnectionState**

Add these optional fields for client connections (needed for VN retry in Task 12):

```rust
// In QuicConnectionState struct:
/// Client TLS config (retained for version negotiation retry)
pub client_config: Option<Arc<ClientConfig>>,
/// Server name for TLS SNI (retained for version negotiation retry)
pub server_name: Option<String>,
/// Original QUIC version before any version negotiation
pub original_version: Option<u32>,
/// Pending migration action for handler to process after process_packet()
pub pending_migration: Option<MigrationAction>,
/// Previous path state for migration revert
pub prev_path: Option<PreviousPath>,
/// Whether a key update should be initiated
pub needs_key_update: bool,
```

Add the supporting types:

```rust
/// Previous path state, saved when migration is detected for potential revert.
pub struct PreviousPath {
    pub remote_addr: IpAddress,
    pub remote_port: u16,
    pub remote_mac: MacAddress,
    pub path: PathState,
}

/// Migration action signal from processor to handler.
pub struct MigrationAction {
    pub old_cid: ConnectionId,
    pub new_cid: ConnectionId,
}
```

Add `use` for `Arc` and `ClientConfig` at the top. Initialize all new fields to `None`/`false` in `QuicConnectionState::new()`.

- [ ] **Step 2: Run existing tests to verify no breakage**

Run: `cargo test -- --nocapture 2>&1 | tail -30`
Expected: all tests PASS.

- [ ] **Step 3: Commit**

```bash
git add src/net/handler/quic/connection.rs
git commit -m "feat(quic): add client config, migration, and key update fields to connection state"
```

---

## Task 7: Client-Side Connect — Handler initiate_connection()

**Files:**
- Modify: `src/net/handler/quic/handler.rs`

- [ ] **Step 1: Implement `initiate_connection()` on QuicHandler**

Model it on the existing `create_server_connection()` (handler.rs:737-818) but for the client side:

```rust
/// Create a client-side connection to a remote server.
/// Returns the slab key on success.
pub fn initiate_connection(
    &mut self,
    remote_addr: IpAddress,
    remote_port: u16,
    local_addr: IpAddress,
    local_port: u16,
    local_mac: MacAddress,
    remote_mac: MacAddress,
    server_name: &str,
    tls_config: Arc<ClientConfig>,
    transport_params: TransportParams,
    now: Instant,
) -> Option<usize> {
    use crate::net::handler::quic::connection::Side;
    use crate::net::handler::quic::crypto::initial_keys::derive_initial_keys;
    use crate::net::handler::quic::crypto::keys::{DirectionalKey, KeyPair};
    use crate::net::handler::quic::crypto::tls::CryptoState;
    use ring::rand::SecureRandom;

    let rng = ring::rand::SystemRandom::new();

    // Generate random DCID (server will use this for initial key derivation)
    let mut dcid_bytes = [0u8; 8];
    rng.fill(&mut dcid_bytes).ok()?;
    let dcid = ConnectionId::from_slice(&dcid_bytes);

    // Generate our SCID
    let mut scid_bytes = [0u8; 8];
    rng.fill(&mut scid_bytes).ok()?;
    let scid = ConnectionId::from_slice(&scid_bytes);

    let rustls_version = rustls::quic::Version::V1;

    // Derive initial keys from DCID (RFC 9001 §5.2) — client side
    let (local_dk, remote_dk) = derive_initial_keys(
        dcid.as_bytes(),
        rustls::Side::Client,
        rustls_version,
    );
    let initial_keys = KeyPair {
        local: DirectionalKey::from_rustls(local_dk),
        remote: DirectionalKey::from_rustls(remote_dk),
    };

    // Set initial_source_connection_id in transport params
    let mut client_params = transport_params.clone();
    client_params.initial_source_connection_id = Some(scid);

    let mut params_buf = [0u8; 512];
    let params_len = client_params.encode(&mut params_buf);

    // Create rustls client connection and get ClientHello
    let (crypto, initial_data) = CryptoState::new_client(
        tls_config.clone(),
        server_name,
        &params_buf[..params_len],
        rustls_version,
    ).ok()?;

    let mut conn = QuicConnectionState::new(
        dcid,
        Side::Client,
        transport_params,
        1200,
        now,
    );
    conn.keys.initial = Some(initial_keys);
    conn.crypto = Some(crypto);
    conn.scid = scid;
    conn.scid_set.push(scid);
    conn.local_addr = local_addr;
    conn.remote_addr = remote_addr;
    conn.local_port = local_port;
    conn.remote_port = remote_port;
    conn.local_mac = local_mac;
    conn.remote_mac = remote_mac;
    conn.client_config = Some(tls_config);
    conn.server_name = Some(server_name.to_string());

    // Buffer the ClientHello as pending CRYPTO data in Initial space
    if !initial_data.is_empty() {
        conn.pending_crypto[0] = initial_data;
    }

    let key = self.insert_connection(conn);
    Some(key)
}
```

- [ ] **Step 2: Run existing tests**

Run: `cargo test -- --nocapture 2>&1 | tail -30`
Expected: all tests PASS.

- [ ] **Step 3: Commit**

```bash
git add src/net/handler/quic/handler.rs
git commit -m "feat(quic): implement client-side initiate_connection() in handler"
```

---

## Task 8: Client-Side Connect — Connect Future and Socket API

**Files:**
- Modify: `src/net/socket/quic.rs`
- Create: `src/net/handler/quic/tests/client_connect_test.rs`
- Modify: `src/net/handler/quic/tests/mod.rs`

- [ ] **Step 1: Implement the Connect future**

Replace the stub `Connect` struct and its `Future` impl in `socket/quic.rs` (lines 292-303):

```rust
pub struct Connect {
    conn_key: usize,
    handler: Rc<UnsafeCell<QuicHandler>>,
}

impl Future for Connect {
    type Output = Result<QuicConnection, QuicError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let handler = unsafe { &*self.handler.get() };
        let conn = match handler.connections.get(self.conn_key) {
            Some(c) => c,
            None => return Poll::Ready(Err(QuicError::NotConnected)),
        };
        match conn.state {
            ConnectionState::Established | ConnectionState::HandshakeComplete => {
                Poll::Ready(Ok(QuicConnection {
                    conn_key: self.conn_key,
                    handler: self.handler.clone(),
                }))
            }
            ConnectionState::Closing | ConnectionState::Draining | ConnectionState::Closed => {
                Poll::Ready(Err(QuicError::ConnectionClosed))
            }
            ConnectionState::Handshaking => {
                conn.event_queue.register_waker(cx.waker());
                Poll::Pending
            }
        }
    }
}
```

- [ ] **Step 2: Update `QuicConnection::connect()` to eagerly create the connection**

Replace the static `connect()` method (lines 146-153).

**Important:** `RuntimeContext` (in `src/rt/context.rs`) does NOT have `local_addr`, `local_mac`, or `gateway_mac` fields — it only has handler references, frame buffers, and timers. The addressing must be passed as arguments to `connect()`:

```rust
/// Connect to a remote QUIC server.
///
/// `local_addr`/`local_mac` identify this endpoint.
/// `remote_mac` is the gateway/next-hop MAC (from ARP/ND resolution).
pub fn connect(
    local_addr: IpAddress,
    local_port: u16,
    local_mac: MacAddress,
    remote_addr: IpAddress,
    remote_port: u16,
    remote_mac: MacAddress,
    server_name: &str,
    tls_config: Arc<ClientConfig>,
) -> Result<Connect, QuicError> {
    with_runtime_context(|ctx| {
        let handler = unsafe { &mut *ctx.quic_handler.get() };

        let conn_key = handler
            .initiate_connection(
                remote_addr,
                remote_port,
                local_addr,
                local_port,
                local_mac,
                remote_mac,
                server_name,
                tls_config,
                TransportParams::default(),
                coarsetime::Instant::now(),
            )
            .ok_or(QuicError::NotConnected)?;

        Ok(Connect {
            conn_key,
            handler: ctx.quic_handler.clone(),
        })
    })
}
```

This follows the same pattern as the echo server example which already has local/remote addressing available at the call site.

- [ ] **Step 3: Register test module**

Add to `src/net/handler/quic/tests/mod.rs`:
```rust
mod client_connect_test;
```

- [ ] **Step 4: Write integration test for client connect**

The integration test should follow the pattern in `handshake_integration_test.rs` — create a server listener and client connect within the runtime context. The implementer should study that test file for the exact setup pattern.

```rust
// src/net/handler/quic/tests/client_connect_test.rs
// Test that a client can initiate a connection and complete the handshake.
// Follow the pattern from handshake_integration_test.rs for runtime setup.
```

- [ ] **Step 5: Run tests**

Run: `cargo test client_connect_test -- --nocapture 2>&1 | tail -30`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/net/socket/quic.rs src/net/handler/quic/tests/client_connect_test.rs src/net/handler/quic/tests/mod.rs
git commit -m "feat(quic): implement client-side Connect future and socket API"
```

---

## Task 9: Client Initial Padding

**Files:**
- Modify: `src/net/handler/quic/processor.rs` (around line 1743-1747)

- [ ] **Step 1: Ensure Initial padding applies to client connections**

Check the existing padding at `processor.rs:1743-1747`:
```rust
if space == 0 {
    builder.pad_to(1200);
}
```

This already pads all Initial packets (space 0) to 1200 bytes regardless of side. Verify this is correct for client-initiated Initials (RFC 9000 §14.1). If it only applies server-side, add the client condition. If it already covers both, this step is a verification-only.

- [ ] **Step 2: Run existing handshake and packet builder tests**

Run: `cargo test packet_builder_test -- --nocapture 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 3: Commit if any changes made**

```bash
git add src/net/handler/quic/processor.rs
git commit -m "feat(quic): verify client Initial padding to 1200 bytes"
```

---

## Task 10: Graceful Shutdown — Event Propagation

**Files:**
- Modify: `src/net/socket/quic.rs`
- Modify: `src/net/handler/quic/processor.rs`
- Modify: `src/net/handler/quic/handler.rs`
- Create: `src/net/handler/quic/tests/shutdown_test.rs`
- Modify: `src/net/handler/quic/tests/mod.rs`

- [ ] **Step 1: Extend QuicError::ConnectionClosed to carry error code**

In `src/net/socket/quic.rs`, change:
```rust
ConnectionClosed,
```
to:
```rust
ConnectionClosed(Option<u64>),
```

Update all existing match sites that reference `QuicError::ConnectionClosed` to use `QuicError::ConnectionClosed(None)` or the appropriate error code. There are matches in the stream read/write futures and the close method. Use `grep -r "ConnectionClosed"` within the quic module to find them all.

- [ ] **Step 2: Push ConnectionClosed event on CONNECTION_CLOSE receipt**

In `processor.rs`, find where `QuicFrame::ConnectionClose` is handled (around line 595-597):
```rust
QuicFrame::ConnectionClose(_) => {
    conn.state = ConnectionState::Draining;
    return ProcessResult::ConnectionClosed;
}
```

Add before the return:
```rust
QuicFrame::ConnectionClose(cc) => {
    conn.event_queue.push(QuicEvent::ConnectionClosed(cc.error_code));
    conn.state = ConnectionState::Draining;
    return ProcessResult::ConnectionClosed;
}
```

Check the `ConnectionClose` struct definition in `transport/frame.rs` for the exact field name (`error_code` or similar).

- [ ] **Step 3: Add `wake()` method to LocalQueue and wake futures before connection removal**

`LocalQueue` (in `src/net/socket/queue.rs`) stores a single `Option<Waker>` — there's no `wake_all()`. Add a `wake()` method that fires the registered waker without pushing an item:

```rust
// In LocalQueue<T> impl block (src/net/socket/queue.rs):
/// Wake the registered waker (if any) without pushing an item.
/// Used for shutdown/error signaling.
pub fn wake(&self) {
    let waker_slot = unsafe { &mut *self.waker.get() };
    if let Some(waker) = waker_slot.take() {
        waker.wake();
    }
}
```

Then in `handler.rs`, find `remove_connection_by_key()` (line 718). Before removing the connection, wake both queues:

```rust
pub fn remove_connection_by_key(&mut self, key: usize) -> Option<QuicConnectionState> {
    if self.connections.contains(key) {
        let conn = &self.connections[key];
        conn.event_queue.wake();
        conn.stream_accept_queue.wake();
        let conn = self.connections.remove(key);
        // ... existing CID cleanup ...
```

- [ ] **Step 4: Register test module and write shutdown test**

Add to `src/net/handler/quic/tests/mod.rs`:
```rust
mod shutdown_test;
```

Write a test that verifies stream futures return `ConnectionClosed` when the peer sends CONNECTION_CLOSE. Follow the handshake_integration_test.rs pattern for setup.

- [ ] **Step 5: Run tests**

Run: `cargo test shutdown_test -- --nocapture 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/net/socket/quic.rs src/net/handler/quic/processor.rs src/net/handler/quic/handler.rs src/net/handler/quic/tests/shutdown_test.rs src/net/handler/quic/tests/mod.rs
git commit -m "feat(quic): graceful shutdown with event propagation and wake-all"
```

---

## Task 11: Connection Migration

**Files:**
- Modify: `src/net/handler/quic/connection_id.rs`
- Modify: `src/net/handler/quic/processor.rs`
- Modify: `src/net/handler/quic/handler.rs`
- Modify: `src/net/handler/quic/path.rs`
- Create: `src/net/handler/quic/tests/migration_test.rs`
- Modify: `src/net/handler/quic/tests/mod.rs`

This is the largest task. Break it into sub-steps.

- [ ] **Step 1: Add `pick_unused_cid()` to CidSet**

In `src/net/handler/quic/connection_id.rs`, add:

```rust
/// Pick an unused CID from the set (one that isn't the current active CID).
/// Returns (cid, sequence) or None if no spares.
pub fn pick_unused(&self, active: &ConnectionId) -> Option<(ConnectionId, u64)> {
    for i in 0..self.count as usize {
        if &self.cids[i] != active {
            return Some((self.cids[i], self.seqs[i]));
        }
    }
    None
}
```

- [ ] **Step 2: Implement migration detection in processor**

In `processor.rs`, find where incoming packets update `last_activity` (search for `conn.last_activity = now`). Before or after that point, add address change detection. The handler already knows the source address from the incoming packet.

The detection should be in the handler (which has access to the packet's source address), not the processor. In `handler.rs`, in the `process_ipv4` / `process_ipv6` methods, after routing to a connection and calling `process_packet()`:

```rust
// After process_packet(), check if source address changed
if src_addr != conn.remote_addr || src_port != conn.remote_port {
    // Determine if NAT rebinding or intentional migration
    let is_nat_rebinding = /* only port changed, same DCID as before */;
    if is_nat_rebinding {
        conn.remote_port = src_port;
    } else {
        // Full migration flow
        conn.prev_path = Some(PreviousPath {
            remote_addr: conn.remote_addr,
            remote_port: conn.remote_port,
            remote_mac: conn.remote_mac,
            path: std::mem::replace(&mut conn.path, PathState::new()),
        });
        conn.remote_addr = src_addr;
        conn.remote_port = src_port;
        conn.remote_mac = src_mac;
        conn.path.initiate_validation(now);
        // Signal CID rotation
        if let Some((new_cid, _seq)) = conn.scid_set.pick_unused(&conn.scid) {
            let old_cid = conn.scid;
            conn.scid = new_cid;
            conn.pending_migration = Some(MigrationAction { old_cid, new_cid });
        }
    }
}
```

Then, after the connection processing, handle the `pending_migration`:

```rust
if let Some(migration) = conn.pending_migration.take() {
    self.cid_map.remove(&migration.old_cid);
    self.cid_map.insert(migration.new_cid, conn_key);
}
```

- [ ] **Step 3: Implement path validation timeout revert**

In `processor.rs`, fix the `QuicTimerKind::PathValidation` handler (line 117-120):

```rust
QuicTimerKind::PathValidation => {
    if !conn.path.validated {
        if let Some(prev) = conn.prev_path.take() {
            conn.remote_addr = prev.remote_addr;
            conn.remote_port = prev.remote_port;
            conn.remote_mac = prev.remote_mac;
            conn.path = prev.path;
        } else {
            conn.close_error = Some(TransportError::INTERNAL_ERROR);
            conn.state = ConnectionState::Closing;
            conn.needs_draining_timer = true;
            return TimerResult::Ok;
        }
    }
    TimerResult::Ok
}
```

- [ ] **Step 4: Register test module and write migration tests**

Add to `src/net/handler/quic/tests/mod.rs`:
```rust
mod migration_test;
```

Write tests for:
- NAT rebinding (port change only → remote_port updated, no path validation)
- Full migration (address change → prev_path saved, PATH_CHALLENGE sent)
- Path validation timeout → revert to previous path

- [ ] **Step 5: Run tests**

Run: `cargo test migration_test -- --nocapture 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/net/handler/quic/connection_id.rs src/net/handler/quic/processor.rs src/net/handler/quic/handler.rs src/net/handler/quic/path.rs src/net/handler/quic/tests/migration_test.rs src/net/handler/quic/tests/mod.rs
git commit -m "feat(quic): implement connection migration with CID rotation and path revert"
```

---

## Task 12: Key Update Wire Protocol

**Files:**
- Modify: `src/net/handler/quic/crypto/keys.rs`
- Modify: `src/net/handler/quic/processor.rs`
- Create: `src/net/handler/quic/tests/key_update_wire_test.rs`
- Modify: `src/net/handler/quic/tests/mod.rs`

- [ ] **Step 1: Add key derivation helper to crypto/keys.rs**

```rust
/// Derive the next set of packet keys from rustls Secrets.
/// Returns (local_key, remote_key, next_secrets).
pub fn derive_next_keys(
    secrets: &rustls::quic::Secrets,
) -> (
    Box<dyn rustls::quic::PacketKey>,
    Box<dyn rustls::quic::PacketKey>,
    rustls::quic::Secrets,
) {
    let key_set = secrets.next_packet_keys();
    (key_set.local, key_set.remote, /* next secrets from ... */)
}
```

Note: `Secrets::next_packet_keys(&self)` takes `&self` (not consuming), so the same `Secrets` object can be reused for subsequent key updates — each call advances the key material internally. The `PacketKeySet` returned has `.local` and `.remote` fields (both `Box<dyn PacketKey>`). No need to track "next secrets" separately.

- [ ] **Step 2: Implement peer key update detection in processor**

In the 1-RTT packet decryption path in `processor.rs`, after decrypting with the current key, check the key phase bit. The key phase is bit 2 of the first byte for short headers. Find where 1-RTT packets are decrypted and add:

```rust
// After successful decryption of a 1-RTT packet:
let received_key_phase = (first_byte & 0x04) != 0;
if conn.key_update.is_peer_update(received_key_phase) {
    // Peer initiated key update.
    // Note: `DirectionalKey` has no `take_packet_key()`. The implementer needs to either:
    // (a) Add a `take_packet_key()` method that uses `mem::replace` on the inner `Box<dyn PacketKey>`, or
    // (b) Store the previous key by swapping the entire `DirectionalKey` via `mem::replace`.
    // Option (b) is simpler — save the old remote DirectionalKey whole:
    if let Some(ref mut one_rtt) = conn.keys.one_rtt {
        // Save old remote key for decrypting reordered packets
        let old_remote = std::mem::replace(
            &mut one_rtt.remote,
            DirectionalKey::placeholder(), // temporary, replaced below
        );
        conn.key_update.prev_remote_packet_key = Some(old_remote.into_packet_key());
    }
    // Derive new keys
    if let Some(ref secrets) = conn.key_update_secrets {
        let next_keys = secrets.next_packet_keys();
        // Install new remote key
        if let Some(ref mut one_rtt) = conn.keys.one_rtt {
            one_rtt.remote = DirectionalKey::from_packet_key(next_keys.remote);
            one_rtt.local = DirectionalKey::from_packet_key(next_keys.local);
        }
        // Advance secrets for next update
        // (check rustls API for how to get next secrets)
    }
    conn.key_update.on_update_initiated(); // flip phase
    conn.needs_key_discard_timer = true;
    conn.packets_encrypted[2] = 0; // reset AEAD counter
}
```

The exact API will depend on how `DirectionalKey` wraps the rustls key. The implementer should check `crypto/keys.rs` for the available constructors.

- [ ] **Step 3: Implement key update initiation in packet builder**

In the generate_packets function, before writing 1-RTT frames, check:

```rust
if conn.needs_key_update && conn.key_update.can_initiate_update() {
    // Same key rotation logic as peer update, but we initiate
    // ... derive new keys, flip phase, arm timer ...
    conn.needs_key_update = false;
}
```

- [ ] **Step 4: Add AEAD limit trigger**

After encrypting a 1-RTT packet (where `packets_encrypted[2]` is incremented), check:

```rust
if conn.packets_encrypted[2] >= conn.aead_limits.confidentiality_limit() / 2 {
    conn.needs_key_update = true;
}
```

Check `aead_limits.rs` for the actual method name for the confidentiality limit.

- [ ] **Step 5: ACK tracking for current key phase**

In the ACK handler, when processing ACKs for 1-RTT space:

```rust
if space == 2 {
    if let Some(lowest) = conn.key_update.lowest_pn_current_phase {
        if acked_pn >= lowest {
            conn.key_update.on_ack_for_current_phase();
        }
    }
}
```

- [ ] **Step 6: Register test module and write tests**

Add to `src/net/handler/quic/tests/mod.rs`:
```rust
mod key_update_wire_test;
```

Write tests for:
- Peer key phase flip triggers key rotation
- AEAD limit triggers `needs_key_update`
- `packets_encrypted[2]` resets to 0 after key update
- Cannot initiate update before ACK for current phase

- [ ] **Step 7: Run tests**

Run: `cargo test key_update_wire_test -- --nocapture 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/net/handler/quic/crypto/keys.rs src/net/handler/quic/processor.rs src/net/handler/quic/tests/key_update_wire_test.rs src/net/handler/quic/tests/mod.rs
git commit -m "feat(quic): implement key update wire protocol with AEAD limit trigger"
```

---

## Task 13: Version Negotiation Client Retry

**Files:**
- Modify: `src/net/handler/quic/handler.rs`
- Modify: `src/net/handler/quic/processor.rs`
- Modify: `src/net/handler/quic/transport/params.rs`
- Create: `src/net/handler/quic/tests/version_negotiation_test.rs`
- Modify: `src/net/handler/quic/tests/mod.rs`

- [ ] **Step 1: Add VN packet handling in handler**

In `handler.rs`, in the IPv4/IPv6 packet processing, when a long header packet with version 0 is received and routed to a client connection, call a new processor function:

```rust
if version == 0 && conn.side == Side::Client {
    handle_version_negotiation(conn, vn_payload);
}
```

- [ ] **Step 2: Implement handle_version_negotiation in processor**

```rust
pub fn handle_version_negotiation(
    conn: &mut QuicConnectionState,
    payload: &[u8], // after DCID/SCID fields, the supported version list
) -> ProcessResult {
    use crate::net::handler::quic::transport::version::{QUIC_VERSION_1, QUIC_VERSION_2};

    if conn.state != ConnectionState::Handshaking {
        return ProcessResult::Ok; // ignore if handshake complete
    }

    // Parse supported version list (4 bytes each)
    let mut best_version = None;
    let mut offset = 0;
    while offset + 4 <= payload.len() {
        let v = u32::from_be_bytes(payload[offset..offset + 4].try_into().unwrap());
        offset += 4;
        match v {
            QUIC_VERSION_2 => best_version = Some(QUIC_VERSION_2), // prefer v2
            QUIC_VERSION_1 if best_version.is_none() => best_version = Some(QUIC_VERSION_1),
            _ => {}
        }
    }

    let negotiated = match best_version {
        Some(v) if v != conn.version => v,
        _ => {
            // No compatible version or same version — close
            conn.close_error = Some(TransportError::INTERNAL_ERROR);
            conn.state = ConnectionState::Closing;
            conn.needs_draining_timer = true;
            return ProcessResult::ConnectionClosed;
        }
    };

    // Store original version for downgrade prevention
    conn.original_version = Some(conn.version);
    conn.version = negotiated;

    // Create fresh rustls ClientConnection with stored config
    let rustls_version = if negotiated == QUIC_VERSION_2 {
        rustls::quic::Version::V2
    } else {
        rustls::quic::Version::V1
    };

    if let (Some(config), Some(ref server_name)) = (&conn.client_config, &conn.server_name) {
        // Re-encode transport params
        let mut params_buf = [0u8; 512];
        let params_len = conn.local_params.encode(&mut params_buf);

        match CryptoState::new_client(
            config.clone(),
            server_name,
            &params_buf[..params_len],
            rustls_version,
        ) {
            Ok((crypto, initial_data)) => {
                conn.crypto = Some(crypto);
                // Re-derive initial keys with new version
                let (local_dk, remote_dk) = derive_initial_keys(
                    conn.dcid.as_bytes(),
                    rustls::Side::Client,
                    rustls_version,
                );
                conn.keys.initial = Some(KeyPair {
                    local: DirectionalKey::from_rustls(local_dk),
                    remote: DirectionalKey::from_rustls(remote_dk),
                });
                // Reset state
                conn.pending_crypto = [initial_data, Vec::new(), Vec::new()];
                conn.crypto_offset = [0; 3];
                conn.crypto_acked = [0; 3];
                conn.ack = [AckState::new(), AckState::new(), AckState::new()];
                conn.loss = LossDetector::new();
            }
            Err(_) => {
                conn.close_error = Some(TransportError::INTERNAL_ERROR);
                conn.state = ConnectionState::Closing;
                conn.needs_draining_timer = true;
                return ProcessResult::ConnectionClosed;
            }
        }
    }

    ProcessResult::Ok
}
```

- [ ] **Step 3: Add version_information transport parameter parsing**

In `src/net/handler/quic/transport/params.rs`, add parsing for the `version_information` transport parameter (type 0x11, per RFC 9368 section 3). Add a field:

```rust
pub version_information: Option<VersionInformation>,

pub struct VersionInformation {
    pub chosen_version: u32,
    pub other_versions: Vec<u32>,
}
```

Parse it in the `decode` method and add post-handshake validation:

```rust
pub fn validate_version_info(
    &self,
    negotiated_version: u32,
    original_version: Option<u32>,
) -> Result<(), TransportError> {
    if let Some(ref vi) = self.version_information {
        if vi.chosen_version != negotiated_version {
            return Err(TransportError::TRANSPORT_PARAMETER_ERROR);
        }
        if let Some(orig) = original_version {
            if !vi.other_versions.contains(&orig) {
                return Err(TransportError::TRANSPORT_PARAMETER_ERROR);
            }
        }
    }
    Ok(())
}
```

- [ ] **Step 4: Register test module and write tests**

Add to `src/net/handler/quic/tests/mod.rs`:
```rust
mod version_negotiation_test;
```

Write tests for:
- VN packet with supported version triggers retry
- VN packet with no compatible version closes connection
- VN packet after handshake complete is ignored
- Downgrade prevention: version_information mismatch → TRANSPORT_PARAMETER_ERROR

- [ ] **Step 5: Run tests**

Run: `cargo test version_negotiation_test -- --nocapture 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/net/handler/quic/handler.rs src/net/handler/quic/processor.rs src/net/handler/quic/transport/params.rs src/net/handler/quic/tests/version_negotiation_test.rs src/net/handler/quic/tests/mod.rs
git commit -m "feat(quic): implement version negotiation client retry with downgrade prevention"
```

---

## Task 14: Final Integration Test

**Files:**
- Modify: `src/net/handler/quic/tests/handshake_integration_test.rs` or create new integration test

- [ ] **Step 1: Write end-to-end test exercising the full transport**

Write a test that:
1. Server listens
2. Client connects
3. Client opens bidi stream, writes data
4. Server accepts stream, reads data, writes response
5. Client reads response
6. Client finishes stream
7. Client closes connection
8. Server sees ConnectionClosed error on read

This exercises SendHalf (with real data), client connect, stream I/O, FIN, and graceful shutdown.

- [ ] **Step 2: Run the full test suite**

Run: `cargo test -- --nocapture 2>&1 | tail -30`
Expected: all tests PASS.

- [ ] **Step 3: Commit**

```bash
git add src/net/handler/quic/tests/
git commit -m "test(quic): add end-to-end functional transport integration test"
```
