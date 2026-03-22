# QUIC RFC Compliance Fix Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the critical and medium RFC compliance issues identified in the audit of the QUIC implementation against RFCs 9000, 9001, 9002, 8999, and 9369. Findings #25 (InFlightRing 256-slot cap), #29 (coarsetime pacing precision) are deferred as they require architectural changes. Finding #26 (has_pending_send O(n)) is deferred as a future optimization. Finding #22 (key update full implementation) is scaffolded but full key derivation requires further rustls API investigation.

**Architecture:** Fixes are grouped by file/subsystem to minimize conflicts. Each task targets one or a few closely related findings. Tests use the existing pattern of direct state manipulation with `cargo test` (no feature flags).

**Tech Stack:** Rust, coarsetime, ring (AEAD), rustls (TLS 1.3), smallvec

---

## File Map

| File | Changes |
|------|---------|
| `src/net/handler/quic/processor.rs` | Findings #1-5, #12-15 — frame dispatch errors, flow control, CONNECTION_CLOSE, padding, crypto drain, IPv6 checksum |
| `src/net/handler/quic/transport/frame.rs` | Finding #13 — NEW_CONNECTION_ID, NEW_TOKEN, MAX_STREAMS validation |
| `src/net/handler/quic/transport/params.rs` | Finding #11 — max_ack_delay boundary, side-aware validation |
| `src/net/handler/quic/transport/loss.rs` | Findings #10, #24 — pto_count conditional reset, loss delay precision |
| `src/net/handler/quic/transport/congestion.rs` | Findings #17-19 — persistent congestion fixes |
| `src/net/handler/quic/transport/ecn.rs` | Finding #20 — ECN validation improvements |
| `src/net/handler/quic/crypto/retry.rs` | Finding #8 — version-aware retry integrity |
| `src/net/handler/quic/crypto/key_update.rs` | Finding #6 — actual key derivation |
| `src/net/handler/quic/crypto/aead_limits.rs` | Finding #7 — enforce limits in processor |
| `src/net/wire/quic.rs` | Finding #9 — unknown version handling, VN truncation check |
| `src/net/handler/quic/connection.rs` | New fields for close reason, address validation state |
| `src/net/handler/quic/error.rs` | No changes needed |
| `src/net/handler/quic/stream/map.rs` | Finding #26 — pending send dirty flag |
| `src/net/handler/quic/transport/packet_builder.rs` | Finding #28 — remove 1500 cap (handled in processor) |
| `src/net/handler/quic/transport/frame_writer.rs` | CONNECTION_CLOSE frame writer |
| `src/net/socket/quic.rs` | Finding #23 — AcceptStream on dead connection |

---

### Task 1: Frame Parse Error Returns Connection Error (Finding #3)

**Files:**
- Modify: `src/net/handler/quic/processor.rs:278-283`
- Test: `src/net/handler/quic/tests/processor_test.rs`

- [ ] **Step 1: Write the failing test**

In `processor_test.rs`, add a test that verifies frame parse errors produce a connection error rather than silently breaking:

```rust
#[test]
fn frame_parse_error_closes_connection() {
    // A buffer with an invalid frame type (0xff repeated) after a valid PING
    // should trigger FRAME_ENCODING_ERROR, not silent truncation.
    // We test this through dispatch_frames returning ConnectionClosed
    // when it encounters an unparseable frame.
    //
    // Since dispatch_frames is private, we test via process_packet behavior:
    // construct an encrypted Initial containing [PING(0x01), INVALID(0xff, 0xff)]
    // and verify the connection transitions to Closing.
}
```

Actually — `dispatch_frames` is a private function. We'll test the behavioral change through the connection state after processing a malformed payload. For now, write the fix and verify existing tests pass.

- [ ] **Step 2: Add `close_error` field to QuicConnectionState**

In `connection.rs`, add the field (must exist before processor references it):

```rust
pub close_error: Option<TransportError>,
```

Initialize to `None` in `new()`. Add the import: `use super::error::TransportError;`

- [ ] **Step 3: Fix dispatch_frames to return FRAME_ENCODING_ERROR**

In `processor.rs`, change the frame parse error handling:

```rust
// Line 280-283: Replace
Err(_) => break,
// With:
Err(_) => {
    conn.close_error = Some(TransportError::FRAME_ENCODING_ERROR);
    conn.state = ConnectionState::Closing;
    return ProcessResult::ConnectionClosed;
}
```

Add import at top of processor.rs: `use crate::net::handler::quic::error::TransportError;`

- [ ] **Step 4: Run tests**

Run: `cargo test`
Expected: All existing tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/net/handler/quic/processor.rs src/net/handler/quic/connection.rs
git commit -m "fix(quic): return FRAME_ENCODING_ERROR on parse failure (RFC 9000 §12.4)"
```

---

### Task 2: STREAM_LIMIT_ERROR and FLOW_CONTROL_ERROR Close Connection (Findings #4, #2)

**Files:**
- Modify: `src/net/handler/quic/processor.rs:582-614`
- Modify: `src/net/handler/quic/stream/recv.rs` (return new bytes count)
- Test: `src/net/handler/quic/tests/flow_control_test.rs`

- [ ] **Step 1: Write failing test for STREAM_LIMIT_ERROR**

In `flow_control_test.rs`:

```rust
#[test]
fn stream_limit_error_should_be_returned() {
    // Verify that exceeding stream limits produces an error, not silent drop
    let mut map = StreamMap::new(false); // server side
    map.peer_max_bidi = 1;
    // First stream should succeed
    assert!(map.get_or_create(StreamId(0)).is_ok());
    // Second stream should fail
    assert!(map.get_or_create(StreamId(4)).is_err());
}
```

- [ ] **Step 2: Run test to confirm it passes (this tests existing behavior)**

Run: `cargo test flow_control`

- [ ] **Step 3: Update RecvHalf::receive to return new byte count alongside errors**

In `stream/recv.rs`, change `receive()` return type from `Result<(), RecvError>` to `Result<usize, RecvError>`. The return value is the number of NEW (non-duplicate) bytes received:

```rust
pub fn receive(&mut self, offset: u64, data: &[u8], fin: bool) -> Result<usize, RecvError> {
    let end = offset + data.len() as u64;

    // Check flow control
    if end > self.max_stream_data {
        return Err(RecvError::FlowControlExceeded);
    }

    // Check final size consistency
    if fin {
        if let Some(fs) = self.final_size {
            if fs != end { return Err(RecvError::FinalSizeMismatch); }
        }
        self.final_size = Some(end);
        self.fin_received = true;
    } else if let Some(fs) = self.final_size {
        if end > fs { return Err(RecvError::FinalSizeMismatch); }
    }

    // Handle overlap with already-received contiguous data
    if offset < self.received {
        let overlap = (self.received - offset) as usize;
        if overlap >= data.len() {
            return Ok(0); // fully duplicate
        }
        // Partially overlapping — trim prefix, recurse on new tail
        return self.receive(self.received, &data[overlap..], fin);
    }

    // Write to buffer and track new bytes
    let buf_offset = (offset - self.read_offset) as usize;
    let written = self.buffer.write_at(buf_offset, data);

    if offset == self.received {
        self.received = end;
        if !self.ooo.is_empty() {
            self.drain_contiguous();
        }
    } else {
        self.ooo.insert(offset, data.len());
    }

    Ok(written)
}
```

Key: duplicates return `Ok(0)`, new data returns `Ok(written)`, errors still return `Err(RecvError)`.

- [ ] **Step 4: Fix handle_stream_frame to close connection on errors**

In `processor.rs`, replace `handle_stream_frame`:

```rust
fn handle_stream_frame(
    conn: &mut QuicConnectionState,
    stream_id: StreamId,
    offset: u64,
    data: &[u8],
    fin: bool,
) -> Option<TransportError> {
    let is_new = conn.streams.get(stream_id).is_none();

    let entry = match conn.streams.get_or_create(stream_id) {
        Ok(e) => e,
        Err(_) => return Some(TransportError::STREAM_LIMIT_ERROR),
    };

    if let Some(ref mut recv) = entry.recv {
        match recv.receive(offset, data, fin) {
            Ok(new_bytes) => {
                // Only count NEW data against connection-level flow control
                if new_bytes > 0 {
                    if conn.flow.on_data_received(new_bytes as u64).is_err() {
                        return Some(TransportError::FLOW_CONTROL_ERROR);
                    }
                }
            }
            Err(_) => {
                return Some(TransportError::FLOW_CONTROL_ERROR);
            }
        }
    }

    if is_new {
        conn.stream_accept_queue.push(stream_id);
    }
    conn.event_queue
        .push(crate::net::handler::quic::event::QuicEvent::StreamReadable(stream_id));
    None
}
```

- [ ] **Step 5: Update dispatch_frames to handle the return value**

In the `QuicFrame::Stream` match arm:

```rust
QuicFrame::Stream(stream) => {
    if let Some(err) = handle_stream_frame(conn, stream.stream_id, stream.offset, stream.data, stream.fin) {
        conn.close_error = Some(err);
        conn.state = ConnectionState::Closing;
        return ProcessResult::ConnectionClosed;
    }
}
```

- [ ] **Step 6: Run tests**

Run: `cargo test`

- [ ] **Step 7: Commit**

```bash
git add src/net/handler/quic/processor.rs src/net/handler/quic/stream/recv.rs
git commit -m "fix(quic): close connection on STREAM_LIMIT_ERROR and FLOW_CONTROL_ERROR (RFC 9000 §4.6, §19.9)"
```

---

### Task 3: HANDSHAKE_DONE from Client = PROTOCOL_VIOLATION (Finding #12)

**Files:**
- Modify: `src/net/handler/quic/processor.rs:360-365`
- Test: `src/net/handler/quic/tests/frame_test.rs`

- [ ] **Step 1: Fix the HANDSHAKE_DONE dispatch**

```rust
QuicFrame::HandshakeDone => {
    if conn.side == Side::Client {
        conn.state = ConnectionState::Established;
    } else {
        // Server MUST NOT receive HANDSHAKE_DONE (RFC 9000 §19.20)
        conn.close_error = Some(TransportError::PROTOCOL_VIOLATION);
        conn.state = ConnectionState::Closing;
        return ProcessResult::ConnectionClosed;
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test`

- [ ] **Step 3: Commit**

```bash
git add src/net/handler/quic/processor.rs
git commit -m "fix(quic): reject HANDSHAKE_DONE from client as PROTOCOL_VIOLATION (RFC 9000 §19.20)"
```

---

### Task 4: Frame-Level Validations (Finding #13)

**Files:**
- Modify: `src/net/handler/quic/transport/frame.rs:255-266, 388-422`
- Modify: `src/net/handler/quic/processor.rs:343-349`
- Test: `src/net/handler/quic/tests/frame_test.rs`

- [ ] **Step 1: Write failing tests**

In `frame_test.rs`:

```rust
#[test]
fn parse_new_connection_id_cid_len_zero_fails() {
    // NEW_CONNECTION_ID with cid_len=0 must be FRAME_ENCODING_ERROR
    let mut buf = Vec::new();
    encode_varint(0x18, &mut buf); // type
    encode_varint(1, &mut buf);    // sequence
    encode_varint(0, &mut buf);    // retire_prior_to
    buf.push(0);                   // cid_len = 0 (INVALID per RFC)
    buf.extend_from_slice(&[0u8; 16]); // stateless_reset_token
    assert!(parse_frame(&buf).is_err());
}

#[test]
fn parse_new_connection_id_cid_len_21_fails() {
    let mut buf = Vec::new();
    encode_varint(0x18, &mut buf);
    encode_varint(1, &mut buf);
    encode_varint(0, &mut buf);
    buf.push(21);                  // cid_len = 21 (INVALID, max is 20)
    buf.extend_from_slice(&[0u8; 21 + 16]);
    assert!(parse_frame(&buf).is_err());
}

#[test]
fn parse_new_connection_id_retire_gt_sequence_fails() {
    let mut buf = Vec::new();
    encode_varint(0x18, &mut buf);
    encode_varint(5, &mut buf);    // sequence = 5
    encode_varint(6, &mut buf);    // retire_prior_to = 6 > 5 (INVALID)
    buf.push(4);                   // cid_len = 4
    buf.extend_from_slice(&[1, 2, 3, 4]); // cid
    buf.extend_from_slice(&[0u8; 16]); // stateless_reset_token
    assert!(parse_frame(&buf).is_err());
}

#[test]
fn parse_new_token_empty_fails() {
    let mut buf = Vec::new();
    encode_varint(0x07, &mut buf); // NEW_TOKEN type
    encode_varint(0, &mut buf);    // length = 0 (INVALID)
    assert!(parse_frame(&buf).is_err());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test frame_test`
Expected: 4 new tests FAIL.

- [ ] **Step 3: Add validations to frame.rs**

For NEW_CONNECTION_ID (around line 401):
```rust
let cid_len = rest[pos] as usize;
pos += 1;
// RFC 9000 §19.15: CID length must be 1..=20
if cid_len == 0 || cid_len > 20 {
    return Err(FrameParseError::InvalidFrame);
}
// RFC 9000 §19.15: retire_prior_to must not exceed sequence
if retire_prior_to > sequence {
    return Err(FrameParseError::InvalidFrame);
}
```

For NEW_TOKEN (around line 258):
```rust
let length = length as usize;
// RFC 9000 §19.7: token MUST NOT be empty
if length == 0 {
    return Err(FrameParseError::InvalidFrame);
}
```

- [ ] **Step 4: Add MAX_STREAMS validation in processor.rs**

In the `MaxStreams` handler (line 343):
```rust
QuicFrame::MaxStreams { max, bidi } => {
    // RFC 9000 §19.11: value cannot exceed 2^60
    if max > (1u64 << 60) {
        conn.close_error = Some(TransportError::FRAME_ENCODING_ERROR);
        conn.state = ConnectionState::Closing;
        return ProcessResult::ConnectionClosed;
    }
    if bidi {
        conn.streams.peer_max_bidi = conn.streams.peer_max_bidi.max(max);
    } else {
        conn.streams.peer_max_uni = conn.streams.peer_max_uni.max(max);
    }
}
```

- [ ] **Step 5: Add `InvalidFrame` variant to FrameParseError if needed**

Check if `FrameParseError` has an appropriate variant. If not, add one.

- [ ] **Step 6: Run tests**

Run: `cargo test`
Expected: All tests pass including 4 new ones.

- [ ] **Step 7: Commit**

```bash
git add src/net/handler/quic/transport/frame.rs src/net/handler/quic/processor.rs
git commit -m "fix(quic): validate NEW_CONNECTION_ID, NEW_TOKEN, MAX_STREAMS (RFC 9000 §19.7, §19.11, §19.15)"
```

---

### Task 5: Transport Parameter Validation (Finding #11)

**Files:**
- Modify: `src/net/handler/quic/transport/params.rs:221-373`
- Modify: `src/net/handler/quic/processor.rs:456-480`
- Test: `src/net/handler/quic/tests/params_test.rs`

- [ ] **Step 1: Write failing tests**

In `params_test.rs`:

```rust
#[test]
fn max_ack_delay_exactly_16384_is_invalid() {
    // RFC 9000 §18.2: "Values of 2^14 or greater are invalid"
    let mut params = TransportParams::default();
    params.max_ack_delay_ms = 16384;
    let mut buf = [0u8; 512];
    let len = params.encode(&mut buf);
    let result = TransportParams::decode(&buf[..len]);
    assert!(result.is_err());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test max_ack_delay_exactly`
Expected: FAIL (current code uses `>` not `>=`).

- [ ] **Step 3: Fix max_ack_delay boundary**

In `params.rs` line 356:
```rust
// Change from:
if params.max_ack_delay_ms > 16384 {
// To:
if params.max_ack_delay_ms >= 16384 {
```

- [ ] **Step 4: Add side-aware parameter validation**

Add a new method to `TransportParams`:

```rust
/// Validate transport parameters based on which side sent them (RFC 9000 §18.2).
pub fn validate_for_side(&self, peer_side: Side) -> Result<(), TransportError> {
    // Server-only parameters MUST NOT be sent by a client
    if peer_side == Side::Client {
        if self.original_destination_connection_id.is_some()
            || self.stateless_reset_token.is_some()
            || self.retry_source_connection_id.is_some()
        {
            return Err(TransportError::TRANSPORT_PARAMETER_ERROR);
        }
    }
    // Client MUST validate server sends original_destination_connection_id
    if peer_side == Side::Server {
        if self.original_destination_connection_id.is_none() {
            return Err(TransportError::TRANSPORT_PARAMETER_ERROR);
        }
    }
    Ok(())
}
```

- [ ] **Step 5: Call validate_for_side in processor.rs after decode**

In `processor.rs` around line 464, after successful decode:
```rust
let peer_side = if conn.side == Side::Client { Side::Server } else { Side::Client };
if let Err(err) = params.validate_for_side(peer_side) {
    conn.close_error = Some(err);
    conn.state = ConnectionState::Closing;
    return;
}
```

Note: also add `initial_source_connection_id` presence check if the parameter exists in the struct.

- [ ] **Step 6: Run tests**

Run: `cargo test`

- [ ] **Step 7: Commit**

```bash
git add src/net/handler/quic/transport/params.rs src/net/handler/quic/processor.rs
git commit -m "fix(quic): side-aware transport parameter validation (RFC 9000 §7.3, §18.2)"
```

---

### Task 6: STOP_SENDING and RESET_STREAM Handling (Finding #5)

**Files:**
- Modify: `src/net/handler/quic/processor.rs:371-375`
- Test: `src/net/handler/quic/tests/processor_test.rs`

- [ ] **Step 1: Add STOP_SENDING and RESET_STREAM handlers**

In `dispatch_frames`, replace the catch-all with explicit handlers:

```rust
QuicFrame::StopSending(stop) => {
    // RFC 9000 §3.5: Receipt of STOP_SENDING means peer no longer reads.
    // We MUST send RESET_STREAM if in Ready or Send state.
    if let Some(entry) = conn.streams.get_mut(stop.stream_id) {
        if let Some(ref mut send) = entry.send {
            // Queue RESET_STREAM
            send.reset_requested = true;
            send.reset_error_code = stop.error_code;
        }
    }
}

QuicFrame::ResetStream(reset) => {
    // RFC 9000 §3.5: Peer is abandoning the stream.
    if let Some(entry) = conn.streams.get_mut(reset.stream_id) {
        if let Some(ref mut recv) = entry.recv {
            recv.on_reset(reset.final_size);
        }
        // Account for final_size in connection flow control (RFC 9000 §4.5)
        conn.flow.on_stream_final_size(reset.final_size);
    }
}

QuicFrame::PathResponse(data) => {
    conn.path.on_path_response(data);
}

QuicFrame::DataBlocked(_) | QuicFrame::StreamDataBlocked { .. } | QuicFrame::StreamsBlocked { .. } => {
    // Informational — no action required, peer is blocked
}

_ => {} // truly unknown frames caught by parse_frame
```

- [ ] **Step 2: Add `reset_requested` and `reset_error_code` to SendHalf**

In `stream/send.rs`:
```rust
pub reset_requested: bool,
pub reset_error_code: u64,
```

- [ ] **Step 3: Add `on_reset` to RecvHalf**

In `stream/recv.rs`:
```rust
pub fn on_reset(&mut self, _final_size: u64) {
    self.is_reset = true;
}
```

And add `pub is_reset: bool` field, initialized to `false`.

- [ ] **Step 4: Run tests**

Run: `cargo test`

- [ ] **Step 5: Commit**

```bash
git add src/net/handler/quic/processor.rs src/net/handler/quic/stream/send.rs src/net/handler/quic/stream/recv.rs
git commit -m "fix(quic): handle STOP_SENDING, RESET_STREAM, PathResponse (RFC 9000 §3.5, §19.18)"
```

---

### Task 7: CONNECTION_CLOSE Actually Sent (Finding #1)

**Files:**
- Modify: `src/net/handler/quic/processor.rs:659-665`
- Modify: `src/net/handler/quic/transport/frame_writer.rs`
- Modify: `src/net/handler/quic/transport/packet_builder.rs`
- Test: `src/net/handler/quic/tests/processor_test.rs`

- [ ] **Step 1: Add `write_connection_close` to frame_writer.rs**

```rust
/// Write a CONNECTION_CLOSE frame (type 0x1c for transport errors).
pub fn write_connection_close(buf: &mut [u8], error_code: u64, frame_type: u64, reason: &[u8]) -> usize {
    let mut pos = 0;
    pos += encode_varint(0x1c, &mut buf[pos..]); // type
    pos += encode_varint(error_code, &mut buf[pos..]);
    pos += encode_varint(frame_type, &mut buf[pos..]);
    pos += encode_varint(reason.len() as u64, &mut buf[pos..]);
    buf[pos..pos + reason.len()].copy_from_slice(reason);
    pos + reason.len()
}
```

- [ ] **Step 2: Add `write_connection_close` to PacketBuilder**

```rust
pub fn write_connection_close(&mut self, error_code: u64, frame_log: &mut FrameLog) -> bool {
    let needed = 1 + 8 + 1 + 1; // type + error_code + frame_type(0) + reason_len(0)
    if self.remaining() < needed {
        return false;
    }
    let written = frame_writer::write_connection_close(
        &mut self.buf[self.offset..], error_code, 0, &[]
    );
    self.offset += written;
    true
}
```

- [ ] **Step 3: Implement Closing state packet generation**

In `processor.rs`, replace the Closing TODO block:

```rust
if conn.state == ConnectionState::Closing {
    // Build CONNECTION_CLOSE packet (RFC 9000 §10.2)
    let error_code = conn.close_error.map(|e| e.code()).unwrap_or(0);

    // Try to send in the highest available space
    for space in (0..3u8).rev() {
        let has_key = match space {
            0 => conn.keys.initial.is_some(),
            1 => conn.keys.handshake.is_some(),
            2 => conn.keys.one_rtt.is_some(),
            _ => false,
        };
        if !has_key { continue; }

        if let Some(mut frame) = free_frames.pop() {
            let capacity = frame.capacity();
            if capacity < quic_offset + 64 {
                free_frames.push(frame);
                continue;
            }
            unsafe { frame.set_len(capacity) };

            let pn = conn.loss.next_pn(space as usize);
            let largest_acked = conn.ack[space as usize].largest_received().unwrap_or(0);

            let mut builder = if space <= 1 {
                let packet_type_bits = if space == 0 { 0x00 } else { 0x02 };
                match PacketBuilder::begin_long(
                    &mut frame[quic_offset..], packet_type_bits, conn.version,
                    conn.dcid.as_bytes(), conn.scid.as_bytes(), pn, largest_acked, &conn.frame_log,
                ) {
                    Some(b) => b,
                    None => { free_frames.push(frame); continue; }
                }
            } else {
                match PacketBuilder::begin_short(
                    &mut frame[quic_offset..], conn.dcid.as_bytes(), pn, largest_acked,
                    false, &conn.frame_log,
                ) {
                    Some(b) => b,
                    None => { free_frames.push(frame); continue; }
                }
            };

            builder.write_connection_close(error_code, &mut conn.frame_log);

            let pn_offset = builder.pn_offset();
            let pn_length = builder.pn_length();
            let quic_len = builder.finish();

            let local_key = match space {
                0 => conn.keys.initial.as_ref().map(|kp| &kp.local),
                1 => conn.keys.handshake.as_ref().map(|kp| &kp.local),
                2 => conn.keys.one_rtt.as_ref().map(|kp| &kp.local),
                _ => None,
            };
            if let Some(local_key) = local_key {
                let quic_buf = &mut frame[quic_offset..quic_offset + quic_len];
                if let Ok(protected_len) = protect_packet(local_key, quic_buf, pn_offset, pn_length, pn) {
                    let total_len = write_transport_headers(conn, &mut frame, quic_offset, protected_len);
                    if total_len > 0 {
                        unsafe { frame.set_len(total_len) };
                        tx_return.push(frame);
                    } else {
                        free_frames.push(frame);
                    }
                } else {
                    free_frames.push(frame);
                }
            } else {
                free_frames.push(frame);
            }
            break; // only send one CONNECTION_CLOSE
        }
    }

    conn.state = ConnectionState::Draining;
    return;
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test`

- [ ] **Step 5: Commit**

```bash
git add src/net/handler/quic/processor.rs src/net/handler/quic/transport/frame_writer.rs src/net/handler/quic/transport/packet_builder.rs
git commit -m "fix(quic): send CONNECTION_CLOSE frame when closing (RFC 9000 §10.2)"
```

---

### Task 8: Drain Pending CRYPTO After Write (Finding #14)

**Files:**
- Modify: `src/net/handler/quic/processor.rs:791-800`

- [ ] **Step 1: Fix crypto drain**

In `processor.rs`, after writing CRYPTO data (around line 796-800):

```rust
if !conn.pending_crypto[space as usize].is_empty() {
    let offset_val = conn.crypto_offset[space as usize];
    let data = &conn.pending_crypto[space as usize];
    let written = builder.write_crypto(offset_val, data, space, &mut conn.frame_log);
    if written > 0 {
        conn.crypto_offset[space as usize] += written as u64;
        // Drain the written bytes from the pending buffer
        conn.pending_crypto[space as usize].drain(..written);
        wrote_ack_eliciting = true;
    }
}
```

The key change is adding `conn.pending_crypto[space as usize].drain(..written);`.

- [ ] **Step 2: Run tests**

Run: `cargo test`

- [ ] **Step 3: Commit**

```bash
git add src/net/handler/quic/processor.rs
git commit -m "fix(quic): drain pending CRYPTO buffer after write to prevent infinite retransmission"
```

---

### Task 9: Initial Padding Fix (Finding #15)

**Files:**
- Modify: `src/net/handler/quic/processor.rs:895-900`

- [ ] **Step 1: Fix padding calculation**

RFC 9000 §14 defines "datagram" as the UDP payload (not including UDP header). The QUIC packet IS the UDP payload for non-coalesced packets. So pad to 1200, not 1200-8.

```rust
// Line 897-899: Replace
if space == 0 {
    let min_quic_size = 1200usize.saturating_sub(UDP_HEADER_LEN);
    builder.pad_to(min_quic_size);
}
// With:
if space == 0 {
    // RFC 9000 §14: "datagram size" = UDP payload = QUIC packet bytes
    builder.pad_to(1200);
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test`

- [ ] **Step 3: Commit**

```bash
git add src/net/handler/quic/processor.rs
git commit -m "fix(quic): pad Initial packets to 1200 bytes (RFC 9000 §14 datagram = UDP payload)"
```

---

### Task 10: IPv6 UDP Checksum (Finding #16)

**Files:**
- Modify: `src/net/handler/quic/processor.rs:1010-1017`

- [ ] **Step 1: Implement proper IPv6 UDP checksum**

Replace the placeholder with a proper computation:

```rust
if matches!(conn.local_addr, IpAddress::V6(_)) {
    // Compute UDP checksum over IPv6 pseudo-header + UDP segment
    let (src, dst) = match (conn.local_addr, conn.remote_addr) {
        (IpAddress::V6(s), IpAddress::V6(d)) => {
            let s: [u8; 16] = s.into();
            let d: [u8; 16] = d.into();
            (s, d)
        }
        _ => unreachable!(),
    };
    let udp_segment = &frame[udp_offset..udp_offset + udp_len];
    let checksum = ipv6_udp_checksum(&src, &dst, udp_segment);
    let udp_mut = unsafe { UdpHeader::from_bytes_at_mut(frame, udp_offset) };
    udp_mut.checksum = checksum.to_be_bytes();
}
```

Add helper function:

```rust
/// Compute UDP checksum over IPv6 pseudo-header + UDP segment.
fn ipv6_udp_checksum(src: &[u8; 16], dst: &[u8; 16], udp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    // Pseudo-header: src(16) + dst(16) + udp_length(4) + next_header(4)
    for chunk in src.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for chunk in dst.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    let udp_len = udp_segment.len() as u32;
    sum += (udp_len >> 16) as u32;
    sum += (udp_len & 0xFFFF) as u32;
    sum += 17u32; // Next Header = UDP
    // UDP segment (with checksum field = 0)
    let mut i = 0;
    while i + 1 < udp_segment.len() {
        // Skip checksum field at bytes 6-7
        if i == 6 {
            i += 2;
            continue;
        }
        sum += u16::from_be_bytes([udp_segment[i], udp_segment[i + 1]]) as u32;
        i += 2;
    }
    if i < udp_segment.len() {
        sum += (udp_segment[i] as u32) << 8;
    }
    // Fold
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let result = !(sum as u16);
    if result == 0 { 0xFFFF } else { result }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test`

- [ ] **Step 3: Commit**

```bash
git add src/net/handler/quic/processor.rs
git commit -m "fix(quic): compute proper IPv6 UDP checksum (RFC 8200 §8.1)"
```

---

### Task 11: pto_count Conditional Reset (Finding #10)

**Files:**
- Modify: `src/net/handler/quic/transport/loss.rs:294-295`
- Modify: `src/net/handler/quic/connection.rs` (add `peer_completed_address_validation` if not present)
- Test: `src/net/handler/quic/tests/loss_test.rs`

- [ ] **Step 1: Write failing test**

In `loss_test.rs`:

```rust
#[test]
fn pto_count_not_reset_before_address_validation() {
    let mut loss = LossDetector::new();
    loss.pto_count = 2;
    loss.peer_completed_address_validation = false;

    // Send and ACK a packet
    let now = Instant::now();
    loss.on_packet_sent(0, 0, make_sent_packet_at(now));
    let (_, _) = loss.on_ack_received(0, 0, Duration::from_millis(0), &[(0, 0)],
        Duration::from_millis(25), false, now + Duration::from_millis(50));

    // pto_count should NOT be reset
    assert_eq!(loss.pto_count, 2);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test pto_count_not_reset`
Expected: FAIL (pto_count unconditionally reset to 0).

- [ ] **Step 3: Fix conditional reset**

In `loss.rs` line 294-295, replace:
```rust
self.pto_count = 0;
```
With:
```rust
// RFC 9002 §A.7: Only reset pto_count if peer has completed address validation
if self.peer_completed_address_validation {
    self.pto_count = 0;
}
```

The `peer_completed_address_validation` field already exists in `LossDetector` (seen in line 458).

- [ ] **Step 4: Run tests**

Run: `cargo test`

- [ ] **Step 5: Commit**

```bash
git add src/net/handler/quic/transport/loss.rs
git commit -m "fix(quic): only reset pto_count when peer completed address validation (RFC 9002 §A.7)"
```

---

### Task 12: Persistent Congestion Fixes (Findings #17-19)

**Files:**
- Modify: `src/net/handler/quic/transport/congestion.rs:50-56`
- Modify: `src/net/handler/quic/processor.rs:548-563`
- Test: `src/net/handler/quic/tests/congestion_test.rs`

- [ ] **Step 1: Write failing test for recovery_start_time reset**

In `congestion_test.rs`:

```rust
#[test]
fn persistent_congestion_resets_recovery_time() {
    let mut cc = QuicCubic::new(1200);
    let now = Instant::now();
    // Trigger a normal congestion event to set congestion_recovery_start_time
    cc.on_congestion_event(1200, now, now);
    assert!(cc.congestion_recovery_start_time.is_some());

    // Persistent congestion should reset it
    cc.on_persistent_congestion();
    assert!(cc.congestion_recovery_start_time.is_none());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test persistent_congestion_resets_recovery`
Expected: FAIL.

- [ ] **Step 3: Fix on_persistent_congestion**

In `congestion.rs`:
```rust
pub fn on_persistent_congestion(&mut self) {
    self.cwnd = self.minimum_window();
    self.congestion_recovery_start_time = None; // RFC 9002 §B.8
    self.ssthresh = self.cwnd;
}
```

- [ ] **Step 4: Fix persistent congestion PTO to always include max_ack_delay**

In `congestion.rs`, add a dedicated method:
```rust
/// Compute persistent congestion duration threshold (RFC 9002 §7.6.1).
/// Unlike PTO, this ALWAYS includes max_ack_delay regardless of space.
pub fn persistent_congestion_threshold(
    smoothed_rtt: Duration,
    rttvar: Duration,
    max_ack_delay: Duration,
) -> Duration {
    let granularity = Duration::from_millis(1);
    let var4 = rttvar * 4;
    let var_component = if var4 > granularity { var4 } else { granularity };
    (smoothed_rtt + var_component + max_ack_delay) * K_PERSISTENT_CONGESTION_THRESHOLD
}
```

- [ ] **Step 5: Update processor.rs to use the new threshold**

In `processor.rs`, replace the persistent congestion check (around line 548-563):
```rust
if conn.loss.first_rtt_sample.is_some() && lost.len() >= 2 {
    let max_ack_delay_pc = conn.peer_params.as_ref()
        .map(|p| coarsetime::Duration::from_millis(p.max_ack_delay_ms))
        .unwrap_or(coarsetime::Duration::from_millis(25));
    let pc_threshold = QuicCubic::persistent_congestion_threshold(
        conn.loss.smoothed_rtt, conn.loss.rttvar, max_ack_delay_pc,
    );
    let earliest = lost.first().unwrap().1.time_sent;
    let latest = lost.last().unwrap().1.time_sent;
    let duration = latest.duration_since(earliest);
    if duration > pc_threshold {
        conn.congestion.on_persistent_congestion();
        conn.loss.reset_min_rtt(conn.loss.latest_rtt);
    }
}
```

- [ ] **Step 6: Run tests**

Run: `cargo test`

- [ ] **Step 7: Commit**

```bash
git add src/net/handler/quic/transport/congestion.rs src/net/handler/quic/processor.rs
git commit -m "fix(quic): persistent congestion always includes max_ack_delay, resets recovery (RFC 9002 §7.6)"
```

---

### Task 13: ECN Validation Improvements (Finding #20)

**Files:**
- Modify: `src/net/handler/quic/transport/ecn.rs`
- Test: `src/net/handler/quic/tests/ecn_test.rs`

- [ ] **Step 1: Write failing tests**

In `ecn_test.rs`:

```rust
#[test]
fn ecn_counts_must_not_decrease() {
    let mut ecn = EcnState::new();
    ecn.begin_validation();
    ecn.on_ect0_sent();
    // First ACK: ect0=1
    ecn.on_ack_ecn(1, 0, 0);
    assert!(ecn.capable);
    // Second ACK: ect0=0 (decreased!) → must disable
    ecn.on_ack_ecn(0, 0, 0);
    assert!(ecn.disabled);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test ecn_counts_must_not`
Expected: FAIL.

- [ ] **Step 3: Improve ECN validation**

Replace `on_ack_ecn` in `ecn.rs`:

```rust
pub fn on_ack_ecn(&mut self, ect0: u64, ect1: u64, ecn_ce: u64) -> bool {
    if self.disabled {
        return false;
    }

    // RFC 9000 §13.4.2.1: ECN counts MUST NOT decrease
    if ect0 < self.prev_ect0 || ect1 < self.prev_ect1 || ecn_ce < self.ce_counter {
        self.disabled = true;
        self.capable = false;
        self.validation_pending = false;
        return false;
    }

    // Validation: if we sent ECT(0) but none reflected, disable ECN
    if self.validation_pending && ect0 == 0 && self.ect0_sent > 0 {
        self.disabled = true;
        self.capable = false;
        self.validation_pending = false;
        return false;
    }

    if ect0 > 0 {
        self.capable = true;
        self.validation_pending = false;
    }

    // Update tracked counters
    let ce_increased = ecn_ce > self.ce_counter;
    self.prev_ect0 = ect0;
    self.prev_ect1 = ect1;
    self.ce_counter = ecn_ce;
    ce_increased
}
```

Add fields `prev_ect0: u64` and `prev_ect1: u64` to `EcnState`, initialized to 0.

- [ ] **Step 4: Run tests**

Run: `cargo test`

- [ ] **Step 5: Commit**

```bash
git add src/net/handler/quic/transport/ecn.rs
git commit -m "fix(quic): ECN validation checks for count decreases (RFC 9000 §13.4.2.1)"
```

---

### Task 14: Version-Aware Retry Integrity (Finding #8)

**Files:**
- Modify: `src/net/handler/quic/crypto/retry.rs`
- Test: `src/net/handler/quic/tests/retry_test.rs`

- [ ] **Step 1: Write failing test**

In `retry_test.rs`:

```rust
#[test]
fn retry_tag_v2_uses_v2_key() {
    let odcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let retry_packet = [0xcf, 0x6b, 0x33, 0x43, 0xcf]; // minimal v2 retry
    let tag_v1 = compute_retry_integrity_tag(&odcid, &retry_packet, QUIC_VERSION_1);
    let tag_v2 = compute_retry_integrity_tag(&odcid, &retry_packet, QUIC_VERSION_2);
    assert_ne!(tag_v1, tag_v2);
}
```

- [ ] **Step 2: Run test to verify it fails (signature mismatch)**

Run: `cargo test retry_tag_v2`
Expected: Compilation error — function doesn't take version param.

- [ ] **Step 3: Add version parameter**

```rust
pub fn compute_retry_integrity_tag(odcid: &[u8], retry_packet: &[u8], version: u32) -> [u8; 16] {
    use ring::aead;
    use super::super::transport::version::{QUIC_VERSION_1, QUIC_VERSION_2};

    let (key_bytes, nonce_bytes) = match version {
        QUIC_VERSION_2 => (&RETRY_KEY_V2, &RETRY_NONCE_V2),
        _ => (&RETRY_KEY_V1, &RETRY_NONCE_V1), // v1 is default
    };

    let mut aad = Vec::with_capacity(1 + odcid.len() + retry_packet.len());
    aad.push(odcid.len() as u8);
    aad.extend_from_slice(odcid);
    aad.extend_from_slice(retry_packet);

    let key = aead::UnboundKey::new(&aead::AES_128_GCM, key_bytes).unwrap();
    let nonce = aead::Nonce::assume_unique_for_key(*nonce_bytes);
    let key = aead::LessSafeKey::new(key);

    let mut in_out = Vec::new();
    let tag = key.seal_in_place_separate_tag(nonce, aead::Aad::from(&aad), &mut in_out).unwrap();

    let mut result = [0u8; 16];
    result.copy_from_slice(tag.as_ref());
    result
}

pub fn verify_retry_integrity_tag(odcid: &[u8], retry_packet_with_tag: &[u8], version: u32) -> bool {
    if retry_packet_with_tag.len() < 16 {
        return false;
    }
    let (packet, tag) = retry_packet_with_tag.split_at(retry_packet_with_tag.len() - 16);
    let expected = compute_retry_integrity_tag(odcid, packet, version);
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(tag.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}
```

- [ ] **Step 4: Update all call sites to pass version**

Search for calls to these functions and add the version parameter. Remove `#[allow(dead_code)]` from v2 constants.

- [ ] **Step 5: Run tests**

Run: `cargo test`

- [ ] **Step 6: Commit**

```bash
git add src/net/handler/quic/crypto/retry.rs src/net/handler/quic/tests/retry_test.rs
git commit -m "fix(quic): version-aware retry integrity tags (RFC 9369 §3.3.3)"
```

---

### Task 15: Wire Parser Handles Unknown Versions (Finding #9)

**Files:**
- Modify: `src/net/wire/quic.rs:211-231`
- Test: `src/net/wire/quic.rs` (inline tests)

- [ ] **Step 1: Write failing test**

In `wire/quic.rs` inline tests:

```rust
#[test]
fn unknown_version_parses_as_long_header() {
    // Future QUIC v3 should parse invariant fields, not error
    let mut buf = vec![0xC0]; // long header
    buf.extend_from_slice(&0xDEADBEEFu32.to_be_bytes()); // unknown version
    buf.push(4); // dcid_len
    buf.extend_from_slice(&[1, 2, 3, 4]); // dcid
    buf.push(4); // scid_len
    buf.extend_from_slice(&[5, 6, 7, 8]); // scid
    let result = parse_header(&buf, 0);
    assert!(result.is_ok());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test unknown_version_parses`
Expected: FAIL (UnknownVersion error).

- [ ] **Step 3: Fix decode_long_packet_type**

Change the unknown version case to return a generic type instead of error:

```rust
fn decode_long_packet_type(first_byte: u8, version: u32) -> Result<PacketType, HeaderParseError> {
    match version {
        QUIC_VERSION_1 => match (first_byte & 0x30) >> 4 {
            0 => Ok(PacketType::Initial),
            1 => Ok(PacketType::ZeroRtt),
            2 => Ok(PacketType::Handshake),
            3 => Ok(PacketType::Retry),
            _ => unreachable!(),
        },
        QUIC_VERSION_2 => match (first_byte & 0x30) >> 4 {
            0 => Ok(PacketType::Retry),
            1 => Ok(PacketType::Initial),
            2 => Ok(PacketType::ZeroRtt),
            3 => Ok(PacketType::Handshake),
            _ => unreachable!(),
        },
        0x00000000 => Ok(PacketType::Initial), // Version Negotiation handled separately
        _ => Ok(PacketType::Unknown), // Unknown version — parse invariant fields only
    }
}
```

Add `Unknown` variant to `PacketType`:
```rust
pub enum PacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    OneRtt,
    Unknown, // For unknown versions (RFC 8999 — can still parse invariant fields)
}
```

- [ ] **Step 4: Add VN truncation check**

In `parse_long_header`, after the VN packet parse (line 157-168):
```rust
if version == 0x00000000 {
    let versions = &buf[scid_end..];
    // RFC 8999 §6: ignore if no versions or truncated
    if versions.is_empty() || versions.len() % 4 != 0 {
        return Err(HeaderParseError::BufferTooShort);
    }
    // ...
}
```

- [ ] **Step 5: Handle `PacketType::Unknown` in packet_space and process_packet**

In `packet_parser.rs`, update `packet_space()` to handle the new variant:
```rust
PacketType::Unknown => return None, // Unknown version — cannot determine space
```

Change `packet_space` return type to `Option<usize>` if currently `usize`.

In `processor.rs` `process_packet()`, add an early return for unknown types:
```rust
if header.packet_type == PacketType::Unknown {
    return ProcessResult::VersionNegotiation;
}
```

- [ ] **Step 6: Handler sends VN for unknown versions**

In `handler.rs`, when `ProcessResult::VersionNegotiation` is returned, build and send a Version Negotiation packet using the existing `build_version_negotiation` function. The invariant header fields (DCID, SCID) are already parsed correctly for unknown versions.

- [ ] **Step 6: Run tests**

Run: `cargo test`

- [ ] **Step 7: Commit**

```bash
git add src/net/wire/quic.rs src/net/handler/quic/handler.rs
git commit -m "fix(quic): parse unknown versions for VN response (RFC 8999 §5.4, §6)"
```

---

### Task 16: AEAD Limits Enforcement (Finding #7)

**Files:**
- Modify: `src/net/handler/quic/processor.rs` (add checks after encrypt/decrypt)
- Modify: `src/net/handler/quic/crypto/aead_limits.rs` (fix fence-post)
- Test: `src/net/handler/quic/tests/aead_limits_test.rs`

- [ ] **Step 1: Fix fence-post in needs_key_update**

In `aead_limits.rs`:
```rust
// Trigger BEFORE reaching the limit (RFC 9001 §6.6)
pub fn needs_key_update(&self, packets_encrypted: u64) -> bool {
    packets_encrypted + 1 >= self.confidentiality_limit
}
```

- [ ] **Step 2: Add AEAD limit checks in processor.rs**

After `conn.packets_encrypted += 1;` (around line 935):
```rust
conn.packets_encrypted += 1;
// RFC 9001 §6.6: Check AEAD limits
let limits = AeadLimits::AES_GCM; // TODO: select based on negotiated cipher
if limits.must_close(conn.failed_decryptions) {
    conn.close_error = Some(TransportError::AEAD_LIMIT_REACHED);
    conn.state = ConnectionState::Closing;
}
```

After failed decryptions (in `decrypt_and_process`, on decrypt failure):
```rust
conn.failed_decryptions += 1;
```

- [ ] **Step 3: Run tests**

Run: `cargo test`

- [ ] **Step 4: Commit**

```bash
git add src/net/handler/quic/processor.rs src/net/handler/quic/crypto/aead_limits.rs
git commit -m "fix(quic): enforce AEAD confidentiality and integrity limits (RFC 9001 §6.6)"
```

---

### Task 17: Loss Delay Precision (Finding #24)

**Files:**
- Modify: `src/net/handler/quic/transport/loss.rs:376-384`

- [ ] **Step 1: Fix loss delay to use microsecond precision**

```rust
// Replace lines 376-384:
let loss_delay_us =
    (K_TIME_THRESHOLD_NUM as u64 * max_rtt.as_micros()) / K_TIME_THRESHOLD_DEN as u64;
let loss_delay_us = if loss_delay_us < K_GRANULARITY_MS * 1000 {
    K_GRANULARITY_MS * 1000
} else {
    loss_delay_us
};
// Use from_micros for sub-ms precision
let loss_delay = Duration::from_micros(loss_delay_us);
```

If `coarsetime::Duration` lacks `from_micros`, use: `Duration::new(loss_delay_us / 1_000_000, ((loss_delay_us % 1_000_000) * 1000) as u32)`. Or fall back to `Duration::from_millis((loss_delay_us + 999) / 1000)` (round up to avoid under-estimating the delay, which is conservative — better to wait slightly longer than to declare loss too early).

- [ ] **Step 2: Run tests**

Run: `cargo test`

- [ ] **Step 3: Commit**

```bash
git add src/net/handler/quic/transport/loss.rs
git commit -m "fix(quic): use microsecond precision for loss delay (RFC 9002 §6.1)"
```

---

### Task 18: Pending Send Dirty Flag (Finding #26)

**Files:**
- Modify: `src/net/handler/quic/stream/map.rs:173-190`
- Modify: `src/net/handler/quic/stream/send.rs`

- [ ] **Step 1: Add dirty tracking to StreamMap**

Add a field:
```rust
pub send_pending_count: usize,
```

Increment when data is written to a SendHalf, decrement when fully sent. Use this in `has_pending_send`:

```rust
pub fn has_pending_send(&self) -> bool {
    self.send_pending_count > 0
}
```

- [ ] **Step 2: Update write/send paths to maintain the counter**

This requires incrementing `send_pending_count` when `SendHalf::buffer.write()` is called, and decrementing when the buffer becomes empty after sending. Given the architecture (SendHalf is separate from StreamMap), the simplest approach is to add a `pending_send_dirty: bool` field to `StreamMap` that gets set to `true` on any write and cleared after a full send scan.

Actually, the simpler fix: just keep the O(n) scan for now — it's only called once per packet generation cycle, and with typical stream counts (< 100) it's not a bottleneck. Mark this as a future optimization.

- [ ] **Step 3: Skip this task — defer to future optimization**

The O(n) scan is not a correctness issue. Skip.

---

### Task 19: Stream Data Cap Removed (Finding #28)

**Files:**
- Modify: `src/net/handler/quic/processor.rs:873`

- [ ] **Step 1: Remove the 1500 cap, use available packet space**

Simply remove the `.min(1500)` cap and increase the stack buffer to match max QUIC packet size. Since max_udp_payload is typically 1200-1500 and the builder already limits via `remaining()`, a 4096 stack buffer covers all realistic cases without heap allocation:

```rust
let max_data = builder.remaining().saturating_sub(20);
let data_len = send.buffer.len().min(max_data);
let mut temp = [0u8; 4096]; // covers max realistic QUIC packet payload
let data_len = data_len.min(temp.len());
let read = send.buffer.read(&mut temp[..data_len]);
let fin = send.fin_sent && send.buffer.is_empty();
if read > 0 || fin {
    let written = builder.write_stream(stream_id, send.sent, &temp[..read], fin, &mut conn.frame_log);
    send.sent += written as u64;
    if written > 0 || fin { wrote_ack_eliciting = true; }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test`

- [ ] **Step 3: Commit**

```bash
git add src/net/handler/quic/processor.rs
git commit -m "fix(quic): remove 1500-byte stream data cap, use available packet space"
```

---

### Task 20: AcceptStream on Dead Connection (Finding #23)

**Files:**
- Modify: `src/net/socket/quic.rs`

- [ ] **Step 1: Fix AcceptStream to return error on dead connection**

Find the `AcceptStream::poll` implementation and change `Poll::Pending` to `Poll::Ready(Err(...))` when the connection is gone.

```rust
// When connection is gone:
Poll::Ready(Err(QuicError::ConnectionClosed))
```

- [ ] **Step 2: Run tests**

Run: `cargo test`

- [ ] **Step 3: Commit**

```bash
git add src/net/socket/quic.rs
git commit -m "fix(quic): AcceptStream returns error on dead connection instead of hanging"
```

---

### Task 21: ACK Encoding Allocation Removed (Finding #27)

**Files:**
- Modify: `src/net/handler/quic/processor.rs:817`

- [ ] **Step 1: Remove the .to_vec() allocation**

The `encoded_ranges()` returns a `&[u8]`. The `to_vec()` is needed because `builder.write_ack` borrows `conn` mutably. Restructure to avoid the borrow conflict:

```rust
// Extract all ACK data before the mutable borrow
let largest = conn.ack[space as usize].largest_received().unwrap();
let ack_delay = /* ... computed above ... */;
let first_ack_range = conn.ack[space as usize].first_ack_range();
let ack_range_count = conn.ack[space as usize].ack_range_count();

// Copy encoded ranges to stack buffer to avoid allocation
let ranges_slice = conn.ack[space as usize].encoded_ranges();
let mut ranges_buf = [0u8; 256];
let ranges_len = ranges_slice.len().min(256);
ranges_buf[..ranges_len].copy_from_slice(&ranges_slice[..ranges_len]);

builder.write_ack(
    largest, ack_delay, first_ack_range, ack_range_count,
    &ranges_buf[..ranges_len], &mut conn.frame_log, space,
);
conn.ack[space as usize].ack_sent();
```

- [ ] **Step 2: Run tests**

Run: `cargo test`

- [ ] **Step 3: Commit**

```bash
git add src/net/handler/quic/processor.rs
git commit -m "perf(quic): stack-buffer ACK ranges instead of heap allocation"
```

---

### Task 22: Key Update Scaffolding (Finding #6)

**Files:**
- Modify: `src/net/handler/quic/crypto/key_update.rs`
- Modify: `src/net/handler/quic/connection.rs`

- [ ] **Step 1: Add key derivation to KeyUpdateState**

The actual HKDF-Expand-Label for key updates is done by rustls via `Secrets::next_packet_keys()`. The `key_update_secrets` field in `QuicConnectionState` stores the `rustls::quic::Secrets` from the initial 1-RTT key exchange.

Add a method:

```rust
/// Perform a key update using the stored secrets.
/// Returns the new PacketKeySet and updated Secrets for the next update.
pub fn derive_next_keys(secrets: &rustls::quic::Secrets) -> (rustls::quic::PacketKeySet, rustls::quic::Secrets) {
    let next_keys = secrets.next_packet_keys();
    // The next_packet_keys() call returns both the keys and implicitly
    // advances the secret. We need the new secrets for the next update.
    // Actually, rustls::quic::Secrets has extract_keys() which gives us PacketKeySet.
    // We need to check the rustls API.
    todo!("wire up rustls key update API")
}
```

This task requires understanding the exact rustls quic API. The key insight: `rustls::quic::Secrets` has a `next_packet_keys()` method that returns new keys. The `Secrets` object is consumed/mutated to advance the secret material.

- [ ] **Step 2: Wire key update into the processor**

When `AeadLimits::needs_key_update()` triggers, call the key derivation and swap keys:

```rust
// In generate_packets, after checking packets_encrypted:
if limits.needs_key_update(conn.packets_encrypted) {
    if let Some(ref mut secrets) = conn.key_update_secrets {
        if conn.key_update.can_initiate_update() {
            let new_keys = secrets.next_packet_keys();
            // Store prev remote key for reorder window
            conn.key_update.prev_remote_key = conn.keys.one_rtt.as_ref()
                .map(|kp| kp.remote.clone());
            // Install new keys
            // ... (requires creating DirectionalKey from rustls PacketKey)
            conn.key_update.on_update_initiated();
            conn.packets_encrypted = 0; // reset counter for new keys
        }
    }
}
```

This is complex and depends heavily on rustls API details. Implement the scaffolding and mark the actual key swap as a follow-up if the rustls API doesn't match expectations.

- [ ] **Step 3: Run tests**

Run: `cargo test`

- [ ] **Step 4: Commit**

```bash
git add src/net/handler/quic/crypto/key_update.rs src/net/handler/quic/processor.rs src/net/handler/quic/connection.rs
git commit -m "feat(quic): key update scaffolding with AEAD limit trigger (RFC 9001 §6)"
```

---

### Task 23: Final Verification

- [ ] **Step 1: Run full test suite**

Run: `cargo test`
Expected: All tests pass.

- [ ] **Step 2: Run cargo check for warnings**

Run: `cargo check 2>&1 | grep warning`
Fix any new warnings.

- [ ] **Step 3: Final commit if any cleanup needed**

```bash
git add -A
git commit -m "fix(quic): cleanup warnings from RFC compliance fixes"
```
