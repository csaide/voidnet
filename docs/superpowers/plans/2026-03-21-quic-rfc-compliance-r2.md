# QUIC RFC Compliance Fix Plan — Round 2

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all remaining RFC compliance issues found in the second audit of the QUIC implementation.

**Architecture:** Fixes grouped by subsystem. Tasks are ordered by dependency. Key update full implementation (C4/C5/H2) and v2 support (H3) are deferred as known scaffolding gaps — everything else is fixed.

**Tech Stack:** Rust, coarsetime, rustls, smallvec

---

## File Map

| File | Changes |
|------|---------|
| `src/net/handler/quic/processor.rs` | C1, C6, H1, H4, H5, H6, H7, H8, H9, M1, M2, M3 |
| `src/net/handler/quic/stream/map.rs` | C7, C8 |
| `src/net/handler/quic/stream/recv.rs` | H8 (final_size validation in on_reset) |
| `src/net/handler/quic/transport/loss.rs` | C2, M3 |
| `src/net/handler/quic/transport/flow_control.rs` | H8 (on_stream_final_size check) |
| `src/net/handler/quic/connection.rs` | H6 (add EcnState field) |

---

### Task 1: Fix HANDSHAKE_DONE rejection + client handshake_confirmed + key discard (C1, H1)

**Files:**
- Modify: `src/net/handler/quic/processor.rs:378-383`

- [ ] **Step 1: Fix the HandshakeDone handler**

Replace lines 378-383:
```rust
QuicFrame::HandshakeDone => {
    if conn.side == Side::Client {
        conn.state = ConnectionState::Established;
        // RFC 9001 §4.9.2: discard Handshake keys when handshake confirmed
        conn.keys.handshake = None;
        conn.loss.handshake_confirmed = true;
        conn.loss.peer_completed_address_validation = true;
        // Discard Handshake space packets from loss tracking
        conn.loss.discard_space(1);
    } else {
        // RFC 9000 §19.20: server MUST reject HANDSHAKE_DONE
        conn.close_error = Some(TransportError::PROTOCOL_VIOLATION);
        conn.state = ConnectionState::Closing;
        return ProcessResult::ConnectionClosed;
    }
}
```

- [ ] **Step 2: Run `cargo test`**
- [ ] **Step 3: Commit**
```
git commit -am "fix(quic): reject HANDSHAKE_DONE on server, discard handshake keys on client (RFC 9000 §19.20, RFC 9001 §4.9.2)"
```

---

### Task 2: Initialize local_max_bidi/uni from transport params (C7)

**Files:**
- Modify: `src/net/handler/quic/processor.rs` (where peer params are applied, ~line 520)
- Modify: `src/net/handler/quic/connection.rs` (in new(), after StreamMap creation)

- [ ] **Step 1: Set local stream limits from local_params in connection.rs**

After `streams: StreamMap::new(is_client)` in `new()`, add:
```rust
let mut streams = StreamMap::new(is_client);
streams.local_max_bidi = local_params.initial_max_streams_bidi;
streams.local_max_uni = local_params.initial_max_streams_uni;
```

- [ ] **Step 2: Run `cargo test`**
- [ ] **Step 3: Commit**
```
git commit -am "fix(quic): initialize local stream limits from transport params (RFC 9000 §4.6)"
```

---

### Task 3: Open intermediate streams on gap (C8)

**Files:**
- Modify: `src/net/handler/quic/stream/map.rs:91-164`

- [ ] **Step 1: Fix get_or_create to open all intermediate streams**

In `get_or_create`, when `is_new && !we_initiated`, the opened count should be based on the stream index (which implies all lower IDs exist), not incremented by 1. Replace the increment logic:

```rust
if is_new {
    if !we_initiated {
        // RFC 9000 §2.1: opening stream N implicitly opens all lower-numbered
        // streams of the same type. Count = index + 1 (0-indexed).
        let required_count = (idx as u64) + 1;
        if is_bidi {
            if required_count > self.local_max_bidi {
                return Err(StreamLimitError);
            }
            if required_count > self.peer_opened_bidi {
                self.peer_opened_bidi = required_count;
            }
        } else {
            if required_count > self.local_max_uni {
                return Err(StreamLimitError);
            }
            if required_count > self.peer_opened_uni {
                self.peer_opened_uni = required_count;
            }
        }
    } else {
        if is_bidi && self.local_opened_bidi >= self.peer_max_bidi {
            return Err(StreamLimitError);
        }
        if !is_bidi && self.local_opened_uni >= self.peer_max_uni {
            return Err(StreamLimitError);
        }
        if is_bidi {
            self.local_opened_bidi += 1;
        } else {
            self.local_opened_uni += 1;
        }
    }
}
```

Also create intermediate stream entries for peer-initiated streams:
```rust
// After resizing the vec, create any missing intermediate entries
if !we_initiated && is_new {
    for i in 0..=idx {
        if vec[i].is_none() {
            let (state, has_send, has_recv) = if is_bidi {
                (StreamState::new_bidi(), true, true)
            } else {
                (StreamState::new_recv_only(), false, true)
            };
            vec[i] = Some(StreamEntry {
                state,
                send: if has_send { Some(SendHalf::new(65536)) } else { None },
                recv: if has_recv { Some(RecvHalf::new(65536)) } else { None },
            });
        }
    }
}
```

- [ ] **Step 2: Run `cargo test` — fix stream_map tests if needed**
- [ ] **Step 3: Commit**
```
git commit -am "fix(quic): open intermediate streams on gap (RFC 9000 §2.1)"
```

---

### Task 4: Frame restriction sets close_error to PROTOCOL_VIOLATION (H9)

**Files:**
- Modify: `src/net/handler/quic/processor.rs:304-307`

- [ ] **Step 1: Add close_error before entering Closing**

```rust
_ => {
    conn.close_error = Some(TransportError::PROTOCOL_VIOLATION);
    conn.state = ConnectionState::Closing;
    return ProcessResult::ConnectionClosed;
}
```

- [ ] **Step 2: Run `cargo test`**
- [ ] **Step 3: Commit**
```
git commit -am "fix(quic): set PROTOCOL_VIOLATION on frame restriction violation (RFC 9000 §12.4)"
```

---

### Task 5: Stream direction validation (H7)

**Files:**
- Modify: `src/net/handler/quic/processor.rs` (handle_stream_frame, StopSending, ResetStream handlers)

- [ ] **Step 1: Add direction check in handle_stream_frame**

At the start of `handle_stream_frame`, before `get_or_create`:
```rust
// Check stream direction: receiving data on a send-only stream is STREAM_STATE_ERROR
let we_initiated = stream_id.initiator_is_client() == (conn.side == Side::Client);
let is_bidi = stream_id.is_bidi();
if !is_bidi && we_initiated {
    // We initiated a unidirectional stream — we can only send, not receive
    return Some(TransportError::STREAM_STATE_ERROR);
}
```

- [ ] **Step 2: Add direction check in StopSending handler**

STOP_SENDING on a receive-only stream (peer-initiated uni) is invalid:
```rust
QuicFrame::StopSending(stop) => {
    let we_initiated = stop.stream_id.initiator_is_client() == (conn.side == Side::Client);
    if !stop.stream_id.is_bidi() && !we_initiated {
        // Peer sent STOP_SENDING on their own uni stream (we only receive)
        conn.close_error = Some(TransportError::STREAM_STATE_ERROR);
        conn.state = ConnectionState::Closing;
        return ProcessResult::ConnectionClosed;
    }
    if let Some(entry) = conn.streams.get_mut(stop.stream_id) {
        if let Some(ref mut send) = entry.send {
            send.reset_requested = true;
            send.reset_error_code = stop.error_code;
        }
    }
}
```

- [ ] **Step 3: Add direction check in ResetStream handler**

RESET_STREAM on a send-only stream (we initiated uni) is invalid:
```rust
QuicFrame::ResetStream(reset) => {
    let we_initiated = reset.stream_id.initiator_is_client() == (conn.side == Side::Client);
    if !reset.stream_id.is_bidi() && we_initiated {
        // Peer sent RESET_STREAM on our uni stream (we only send)
        conn.close_error = Some(TransportError::STREAM_STATE_ERROR);
        conn.state = ConnectionState::Closing;
        return ProcessResult::ConnectionClosed;
    }
    if let Some(entry) = conn.streams.get_mut(reset.stream_id) {
        if let Some(ref mut recv) = entry.recv {
            recv.on_reset(reset.final_size);
        }
        conn.flow.on_stream_final_size(reset.final_size);
    }
}
```

- [ ] **Step 4: Run `cargo test`**
- [ ] **Step 5: Commit**
```
git commit -am "fix(quic): validate stream direction for STREAM, STOP_SENDING, RESET_STREAM (RFC 9000 §19.4, §19.5, §19.8)"
```

---

### Task 6: RESET_STREAM final_size validation (H8)

**Files:**
- Modify: `src/net/handler/quic/stream/recv.rs:335-337`
- Modify: `src/net/handler/quic/transport/flow_control.rs:142-148`
- Modify: `src/net/handler/quic/processor.rs:402-409`

- [ ] **Step 1: Validate final_size in on_reset**

Replace `on_reset`:
```rust
pub fn on_reset(&mut self, final_size: u64) -> Result<(), RecvError> {
    // final_size must not be less than data already received
    if final_size < self.received {
        return Err(RecvError::FinalSizeMismatch);
    }
    // Check consistency with previously known final_size
    if let Some(fs) = self.final_size {
        if fs != final_size {
            return Err(RecvError::FinalSizeMismatch);
        }
    }
    // Check stream-level flow control
    if final_size > self.max_stream_data {
        return Err(RecvError::FlowControlExceeded);
    }
    self.final_size = Some(final_size);
    self.is_reset = true;
    Ok(())
}
```

- [ ] **Step 2: Add flow control check in on_stream_final_size**

In `flow_control.rs`, change `on_stream_final_size` to return an error if limit exceeded:
```rust
pub fn on_stream_final_size(&mut self, final_size: u64) -> Result<(), ()> {
    if final_size > self.data_received {
        self.data_received = final_size;
    }
    if self.data_received > self.max_data_recv {
        return Err(());
    }
    Ok(())
}
```

- [ ] **Step 3: Update processor RESET_STREAM handler to check errors**

```rust
QuicFrame::ResetStream(reset) => {
    let we_initiated = reset.stream_id.initiator_is_client() == (conn.side == Side::Client);
    if !reset.stream_id.is_bidi() && we_initiated {
        conn.close_error = Some(TransportError::STREAM_STATE_ERROR);
        conn.state = ConnectionState::Closing;
        return ProcessResult::ConnectionClosed;
    }
    if let Some(entry) = conn.streams.get_mut(reset.stream_id) {
        if let Some(ref mut recv) = entry.recv {
            if recv.on_reset(reset.final_size).is_err() {
                conn.close_error = Some(TransportError::FINAL_SIZE_ERROR);
                conn.state = ConnectionState::Closing;
                return ProcessResult::ConnectionClosed;
            }
        }
    }
    if conn.flow.on_stream_final_size(reset.final_size).is_err() {
        conn.close_error = Some(TransportError::FLOW_CONTROL_ERROR);
        conn.state = ConnectionState::Closing;
        return ProcessResult::ConnectionClosed;
    }
}
```

- [ ] **Step 4: Run `cargo test`**
- [ ] **Step 5: Commit**
```
git commit -am "fix(quic): validate RESET_STREAM final_size and flow control (RFC 9000 §4.5)"
```

---

### Task 7: Anti-deadlock PTO for client before address validation (C2)

**Files:**
- Modify: `src/net/handler/quic/transport/loss.rs:462-527`

- [ ] **Step 1: Fix loss_detection_timer to handle anti-deadlock PTO**

Replace lines 462-491:
```rust
// Anti-deadlock: if peer hasn't validated our address and nothing in flight,
// we still need a PTO to prevent deadlock (RFC 9002 §A.8)
if !self.peer_completed_address_validation
    && self.spaces.iter().all(|s| s.ack_eliciting_in_flight == 0)
{
    // Arm PTO from now
    let pto_duration = self.pto(0, max_ack_delay); // Use Initial space
    let backoff = 1u32 << self.pto_count;
    return Some(Instant::now() + pto_duration * backoff);
}

if self.peer_completed_address_validation
    && self.spaces.iter().all(|s| s.ack_eliciting_in_flight == 0)
{
    return None;
}
```

- [ ] **Step 2: Fix on_loss_detection_timeout probe space selection**

Replace lines 519-527:
```rust
// PTO expired with nothing in flight — choose correct space for probe
// Prefer Initial if keys exist, then Handshake, then Application
if !self.handshake_confirmed {
    if self.spaces[0].ack_eliciting_in_flight > 0 || !self.peer_completed_address_validation {
        return LossDetectionResult::SendProbe { space: 0 };
    }
    return LossDetectionResult::SendProbe { space: 1 };
}
LossDetectionResult::SendProbe { space: 2 }
```

- [ ] **Step 3: Run `cargo test`**
- [ ] **Step 4: Commit**
```
git commit -am "fix(quic): anti-deadlock PTO for client before address validation (RFC 9002 §A.8)"
```

---

### Task 8: Coalesced packet processing (C6)

**Files:**
- Modify: `src/net/handler/quic/processor.rs:126-175`

- [ ] **Step 1: Wrap process_packet in a loop**

Replace `process_packet`:
```rust
pub fn process_packet(
    conn: &mut QuicConnectionState,
    quic_payload: &mut [u8],
    datagram_len: usize,
    now: Instant,
) -> ProcessResult {
    let mut offset = 0;
    let mut result = ProcessResult::Ok;

    while offset < quic_payload.len() {
        let remaining = &mut quic_payload[offset..];
        if remaining.is_empty() {
            break;
        }

        let short_dcid_len = conn.scid.len();
        let (space, pn_offset, packet_len) = {
            let (header, header_len) = match wire_quic::parse_header(remaining, short_dcid_len) {
                Ok(h) => h,
                Err(_) => break, // unparseable remainder, stop
            };

            match header {
                PacketHeader::Long(long) => {
                    let space = match packet_space(long.packet_type) {
                        Some(s) => s,
                        None => break,
                    };
                    let pn_offset = if long.packet_type == PacketType::Initial {
                        match packet_parser::parse_initial_fields(&remaining[long.payload_offset..]) {
                            Some((_token, payload_length, relative_pn_offset)) => {
                                // Compute total packet length: header + payload (includes PN + encrypted data + tag)
                                let packet_len = long.payload_offset + relative_pn_offset + payload_length as usize;
                                (space, long.payload_offset + relative_pn_offset, packet_len)
                            }
                            None => break,
                        }
                    } else if long.packet_type == PacketType::Handshake {
                        match crate::net::handler::quic::transport::varint::decode_varint(
                            &remaining[long.payload_offset..],
                        ) {
                            Some((length, consumed)) => {
                                let pn_off = long.payload_offset + consumed;
                                let packet_len = pn_off + length as usize;
                                (space, pn_off, packet_len)
                            }
                            None => break,
                        }
                    } else {
                        break; // 0-RTT not supported
                    };
                    pn_offset
                }
                PacketHeader::Short(short) => {
                    // Short header: rest of datagram is one packet
                    (2, short.pn_offset, remaining.len())
                }
                PacketHeader::VersionNegotiation(_) => break,
            }
        };

        let packet_result = decrypt_and_process(conn, &mut quic_payload[offset..offset + packet_len], space, pn_offset, datagram_len, now);
        match packet_result {
            ProcessResult::ConnectionClosed => return ProcessResult::ConnectionClosed,
            _ => {}
        }
        result = packet_result;
        offset += packet_len;
    }

    result
}
```

Note: The `parse_initial_fields` function needs to return `payload_length` so we know the total packet size. Read the current function to check if it already does. If not, we need the Length field from the Initial packet header to determine where the next coalesced packet starts.

- [ ] **Step 2: Run `cargo test`**
- [ ] **Step 3: Commit**
```
git commit -am "fix(quic): process coalesced packets in a single UDP datagram (RFC 9000 §12.2)"
```

---

### Task 9: Early return on empty ACK + ack_delay precision (M2, M3)

**Files:**
- Modify: `src/net/handler/quic/transport/loss.rs:259-302`
- Modify: `src/net/handler/quic/processor.rs:561`

- [ ] **Step 1: Add early return in on_ack_received when nothing newly acked**

After the acked packet removal loop (line 274), add:
```rust
if acked.is_empty() {
    return (acked, SmallVec::new());
}
```

- [ ] **Step 2: Fix ack_delay precision in processor.rs:561**

Change:
```rust
let ack_delay = coarsetime::Duration::from_millis(ack_delay_us / 1000);
```
To:
```rust
let ack_delay = coarsetime::Duration::new(
    ack_delay_us / 1_000_000,
    ((ack_delay_us % 1_000_000) * 1000) as u32,
);
```

- [ ] **Step 3: Run `cargo test`**
- [ ] **Step 4: Commit**
```
git commit -am "fix(quic): early return on empty ACK, microsecond ack_delay precision (RFC 9002 §A.7, §5.3)"
```

---

### Task 10: Loss/ACK ordering + persistent congestion filtering (M1, H4, H5)

**Files:**
- Modify: `src/net/handler/quic/processor.rs:580-625`

- [ ] **Step 1: Reorder handle_ack_frame to process losses before acks**

Move the congestion ack processing AFTER loss handling (RFC 9002 §A.7 says OnPacketsLost before OnPacketsAcked):

```rust
// Handle lost packets FIRST (RFC 9002 §A.7)
if !lost.is_empty() {
    // ... existing loss handling ...
}

// THEN update congestion for acked packets
for pkt in &acked {
    conn.congestion.on_ack(/* ... */);
}
```

- [ ] **Step 2: Fix persistent congestion to filter by first_rtt_sample and ack-eliciting**

```rust
if conn.loss.first_rtt_sample.is_some() && lost.len() >= 2 {
    // RFC 9002 §7.6.2: only consider ack-eliciting packets sent after first RTT sample
    let first_rtt = conn.loss.first_rtt_sample.unwrap();
    let eligible: smallvec::SmallVec<[&SentPacket; 8]> = lost.iter()
        .map(|(_, pkt)| pkt)
        .filter(|pkt| pkt.ack_eliciting && pkt.time_sent > first_rtt)
        .collect();
    if eligible.len() >= 2 {
        let max_ack_delay_pc = conn.peer_params.as_ref()
            .map(|p| coarsetime::Duration::from_millis(p.max_ack_delay_ms))
            .unwrap_or(coarsetime::Duration::from_millis(25));
        let pc_threshold = QuicCubic::persistent_congestion_threshold(
            conn.loss.smoothed_rtt, conn.loss.rttvar, max_ack_delay_pc,
        );
        let earliest = eligible.first().unwrap().time_sent;
        let latest = eligible.last().unwrap().time_sent;
        let duration = latest.duration_since(earliest);
        if duration > pc_threshold {
            conn.congestion.on_persistent_congestion();
            conn.loss.reset_min_rtt(conn.loss.latest_rtt);
        }
    }
}
```

- [ ] **Step 3: Run `cargo test`**
- [ ] **Step 4: Commit**
```
git commit -am "fix(quic): loss before ack ordering, persistent congestion filters (RFC 9002 §A.7, §7.6.2)"
```

---

### Task 11: Wire ECN into ACK processing (H6)

**Files:**
- Modify: `src/net/handler/quic/connection.rs` (add ecn field)
- Modify: `src/net/handler/quic/processor.rs` (handle_ack_frame)

- [ ] **Step 1: Add EcnState to QuicConnectionState**

In `connection.rs`, add:
```rust
use super::transport::ecn::EcnState;
```
And field:
```rust
pub ecn: EcnState,
```
Initialize in `new()`: `ecn: EcnState::new(),`

- [ ] **Step 2: Process ECN counts in handle_ack_frame**

After loss handling in `handle_ack_frame`, add:
```rust
// Process ECN counts if present (RFC 9002 §A.7)
if let Some(ref ecn_counts) = ack.ecn {
    let ce_signaled = conn.ecn.on_ack_ecn(ecn_counts.ect0, ecn_counts.ect1, ecn_counts.ecn_ce);
    if ce_signaled {
        // Use sent_time of largest newly acked for congestion event
        if let Some(largest_pkt) = acked.iter().last() {
            conn.congestion.on_ecn_ce(largest_pkt.time_sent, now);
        }
    }
}
```

Check the `AckFrame` struct to see how `ecn` is stored (likely `ecn: Option<EcnCounts>`).

- [ ] **Step 3: Run `cargo test`**
- [ ] **Step 4: Commit**
```
git commit -am "fix(quic): wire ECN processing into ACK handling (RFC 9002 §A.7)"
```

---

### Task 12: AEAD integrity limit enforcement (C3)

**Files:**
- Modify: `src/net/handler/quic/processor.rs:202,229`

- [ ] **Step 1: Add integrity limit check after failed decryptions**

After `conn.failed_decryptions += 1;` at lines 202 and 229, add:
```rust
let limits = crate::net::handler::quic::crypto::aead_limits::AeadLimits::AES_GCM;
if limits.must_close(conn.failed_decryptions) {
    conn.close_error = Some(TransportError::AEAD_LIMIT_REACHED);
    conn.state = ConnectionState::Closing;
    return ProcessResult::ConnectionClosed;
}
```

- [ ] **Step 2: Run `cargo test`**
- [ ] **Step 3: Commit**
```
git commit -am "fix(quic): enforce AEAD integrity limit on failed decryptions (RFC 9001 §6.6)"
```

---

### Task 13: Idle timeout from transport params (M6)

**Files:**
- Modify: `src/net/handler/quic/connection.rs:176`
- Modify: `src/net/handler/quic/processor.rs:524-529`

- [ ] **Step 1: Initialize idle_timeout from local_params**

In `connection.rs`, change:
```rust
idle_timeout: Duration::from_secs(30),
```
To:
```rust
idle_timeout: if local_params.max_idle_timeout_ms > 0 {
    Duration::from_millis(local_params.max_idle_timeout_ms)
} else {
    Duration::from_millis(0) // 0 means disabled
},
```

- [ ] **Step 2: Fix idle timeout negotiation in processor.rs**

Replace the idle timeout logic:
```rust
if params.max_idle_timeout_ms > 0 {
    let peer_timeout = coarsetime::Duration::from_millis(params.max_idle_timeout_ms);
    if conn.idle_timeout.as_millis() == 0 {
        // Our timeout disabled, use peer's
        conn.idle_timeout = peer_timeout;
    } else {
        // Both non-zero: use minimum
        conn.idle_timeout = if conn.idle_timeout < peer_timeout {
            conn.idle_timeout
        } else {
            peer_timeout
        };
    }
}
// If both are 0, idle timeout stays disabled (0)
```

- [ ] **Step 3: Run `cargo test`**
- [ ] **Step 4: Commit**
```
git commit -am "fix(quic): idle timeout uses transport params, min(local, peer) (RFC 9000 §10.1)"
```

---

### Task 14: Key phase bit from key_update state

**Files:**
- Modify: `src/net/handler/quic/processor.rs:937`

- [ ] **Step 1: Use actual key phase**

Change:
```rust
false, // key_phase
```
To:
```rust
conn.key_update.key_phase, // key_phase
```

- [ ] **Step 2: Run `cargo test`**
- [ ] **Step 3: Commit**
```
git commit -am "fix(quic): use actual key_phase bit from key update state (RFC 9001 §6)"
```

---

### Task 15: Final verification

- [ ] **Step 1: Run `cargo test`** — all pass
- [ ] **Step 2: Run `cargo check`** — no errors
- [ ] **Step 3: Commit any cleanup**
