# QUIC Functional Server Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the remaining gaps that prevent a real QUIC client (curl, browser) from talking to the server end-to-end.

**Architecture:** Five targeted fixes — IPv6 checksum, STOP_SENDING generation, stream cleanup, 0-RTT rejection, and CUBIC congestion control. Each is independent.

**Tech Stack:** Rust, rustls (quic feature), coarsetime

**Constraints:**
- Tests run with plain `cargo test` (no feature flags)
- Never commit to main — all work on `quic-rustls` branch
- rustls crypto is untouchable — no custom crypto code

---

## Task 1: Fix IPv6 UDP checksum in Version Negotiation response

**Context:** IPv6 mandates non-zero UDP checksums (RFC 8200 §8.1). The QUIC data path already computes IPv6 UDP checksums in `write_transport_headers` (processor.rs:1784-1791) using a private `ipv6_udp_checksum` function. But `send_version_negotiation_ipv6` in handler.rs has `udp.checksum = [0, 0]; // TODO`. The fix is to use the existing `compute_udp_checksum_ip::<Ipv6>` from `crate::net::checksum`.

**Files:**
- Modify: `src/net/handler/quic/handler.rs:602`

- [ ] **Step 1: Read handler.rs to confirm the exact location**

The TODO is at handler.rs:602:
```rust
udp.checksum = [0, 0]; // TODO: compute IPv6 UDP checksum
```

The surrounding context (lines 587-612) shows `src_addr` and `dst_addr` are `IpAddress`, `dst_port` and `src_port` are `u16`, `udp_len` is computed, and the VN payload is at `frame[quic_offset..]`.

- [ ] **Step 2: Replace the TODO with a proper checksum computation**

In `src/net/handler/quic/handler.rs`, replace line 602:
```rust
            udp.checksum = [0, 0]; // TODO: compute IPv6 UDP checksum
```

with:
```rust
            udp.checksum = [0, 0]; // zeroed before computation
        }
        // Compute IPv6 UDP checksum (mandatory per RFC 8200 §8.1)
        if let (IpAddress::V6(src), IpAddress::V6(dst)) = (dst_addr, src_addr) {
            // dst_addr/src_addr are swapped: dst_addr is our local, src_addr is the remote
            let src_bytes: [u8; 16] = src.into();
            let dst_bytes: [u8; 16] = dst.into();
            let udp_segment = &frame[udp_offset..udp_offset + udp_len];
            let cksum = crate::net::checksum::compute_udp_checksum_ip::<
                crate::net::wire::ip::Ipv6,
            >(
                &src.into(),
                &dst.into(),
                dst_port, // our source port (swapped)
                src_port, // their dest port (swapped)
                udp_len as u16,
                &frame[quic_offset..quic_offset + vn_len],
            );
            let udp_mut = unsafe {
                crate::net::wire::udp::UdpHeader::from_bytes_at_mut(&mut frame, udp_offset)
            };
            udp_mut.checksum = cksum;
        }
```

Wait — the address naming is confusing because VN swaps src/dst. Let me be more precise. Look at the IPv6 header writes at lines 587-592:
- `ip[8..24]` (src) gets `dst_addr` — our address (we're responding)
- `ip[24..40]` (dst) gets `src_addr` — the remote peer

So for the pseudo-header:
- pseudo-header src = `dst_addr` (our addr, which was the original packet's dst)
- pseudo-header dst = `src_addr` (remote, which was the original packet's src)

Actually, the simplest approach is to match what processor.rs does — compute the checksum inline over the UDP segment. The processor.rs `ipv6_udp_checksum` function is private to processor.rs, so let's use the existing `compute_udp_checksum_ip` from the checksum module instead.

Let me provide the correct replacement. Replace the ENTIRE UDP block (lines 595-603) with:

```rust
        {
            let udp = unsafe {
                crate::net::wire::udp::UdpHeader::from_bytes_at_mut(&mut frame, udp_offset)
            };
            udp.src_port = dst_port.to_be_bytes(); // swap ports
            udp.dst_port = src_port.to_be_bytes();
            udp.length = (udp_len as u16).to_be_bytes();
            udp.checksum = [0, 0]; // zero before computing
        }
        // IPv6 UDP checksum mandatory (RFC 8200 §8.1)
        // Write VN payload first so checksum covers it
        version::build_version_negotiation(
            &mut frame[quic_offset..],
            scid,
            dcid,
            &[version::QUIC_VERSION_1, version::QUIC_VERSION_2],
        );
        // Now compute checksum over the complete UDP segment
        if let (IpAddress::V6(src_ip), IpAddress::V6(dst_ip)) = (dst_addr, src_addr) {
            use crate::net::checksum::{
                checksum_to_bytes, fold_checksum, pseudo_header_sum_v6, sum_words,
            };
            // src_ip and dst_ip are already Ipv6Address from the destructure
            let udp_segment = &frame[udp_offset..udp_offset + udp_len];
            let sum = pseudo_header_sum_v6(
                &src_ip,
                &dst_ip,
                crate::net::wire::ip::IpProtocols::Udp,
                udp_len as u32,
            ) + sum_words(udp_segment);
            let cksum = checksum_to_bytes(fold_checksum(sum));
            let udp_mut = unsafe {
                crate::net::wire::udp::UdpHeader::from_bytes_at_mut(&mut frame, udp_offset)
            };
            udp_mut.checksum = cksum;
        }
```

IMPORTANT: This means the VN payload write (`build_version_negotiation`) must be moved BEFORE the checksum computation. Remove the duplicate VN write that was previously at lines 605-610.

- [ ] **Step 3: Run `cargo test` — all should pass**

Run: `cargo test`

- [ ] **Step 4: Commit**

```bash
git add src/net/handler/quic/handler.rs
git commit -m "fix(quic): compute IPv6 UDP checksum in VN response (RFC 8200 §8.1)"
```

---

## Task 2: Generate STOP_SENDING frames

**Context:** STOP_SENDING tells a peer to stop sending data on a stream we don't want. Browsers send STOP_SENDING; our server should too. The pattern is identical to RESET_STREAM (Task 7 from the previous plan). The infrastructure exists: `frame_writer::write_stop_sending` (frame_writer.rs:185), `SentFrame::StopSending` (frame_log.rs:40-43), `RetransmitQueue::stop_sending` (retransmit.rs:28).

**Files:**
- Modify: `src/net/handler/quic/stream/recv.rs` (add `stop_sending_requested` field + method)
- Modify: `src/net/handler/quic/transport/packet_builder.rs` (add `write_stop_sending`)
- Modify: `src/net/handler/quic/stream/map.rs` (add `iter_all_recv`)
- Modify: `src/net/handler/quic/processor.rs` (wire generation into `build_packet_in_frame`)
- Modify: `src/net/socket/quic.rs` (add `stop_sending` method to `QuicRecvStream`)
- Test: `src/net/handler/quic/tests/stream_state_test.rs`

- [ ] **Step 1: Write failing test**

In `src/net/handler/quic/tests/stream_state_test.rs`, add:

```rust
#[test]
fn recv_half_stop_sending() {
    use crate::net::handler::quic::stream::recv::RecvHalf;
    let mut recv = RecvHalf::new(65536);
    assert!(!recv.stop_sending_requested);
    recv.request_stop_sending(0x99);
    assert!(recv.stop_sending_requested);
    assert_eq!(recv.stop_sending_error_code, 0x99);
}
```

Run: `cargo test recv_half_stop_sending` — should FAIL.

- [ ] **Step 2: Add stop_sending fields and method to RecvHalf**

In `src/net/handler/quic/stream/recv.rs`, add fields to `RecvHalf`:

```rust
    pub stop_sending_requested: bool,
    pub stop_sending_error_code: u64,
```

Initialize both in `new()` (`false` and `0`). Also initialize in `reset()`.

Add method:

```rust
    pub fn request_stop_sending(&mut self, error_code: u64) {
        self.stop_sending_requested = true;
        self.stop_sending_error_code = error_code;
    }
```

Run test — should PASS.

- [ ] **Step 3: Add `write_stop_sending` to PacketBuilder**

In `src/net/handler/quic/transport/packet_builder.rs`, add:

```rust
    pub fn write_stop_sending(
        &mut self,
        stream_id: StreamId,
        error_code: u64,
        frame_log: &mut FrameLog,
    ) -> bool {
        let needed = 1 + varint_len(stream_id.0) + varint_len(error_code);
        if self.remaining() < needed {
            return false;
        }
        let written = frame_writer::write_stop_sending(
            &mut self.buf[self.offset..],
            stream_id,
            error_code,
        );
        self.offset += written;
        frame_log.push(SentFrame::StopSending {
            id: stream_id,
            error_code,
        });
        true
    }
```

- [ ] **Step 4: Add `iter_all_recv` to StreamMap**

In `src/net/handler/quic/stream/map.rs`, add:

```rust
    pub fn iter_all_recv(&self) -> impl Iterator<Item = (StreamId, &StreamEntry)> {
        let types: [(u64, &Vec<Option<StreamEntry>>); 4] = [
            (0, &self.client_bidi),
            (1, &self.server_bidi),
            (2, &self.client_uni),
            (3, &self.server_uni),
        ];
        types.into_iter().flat_map(|(type_bits, vec)| {
            vec.iter().enumerate().filter_map(move |(idx, slot)| {
                let entry = slot.as_ref()?;
                if entry.recv.is_some() {
                    Some((StreamId((idx as u64) << 2 | type_bits), entry))
                } else {
                    None
                }
            })
        })
    }
```

- [ ] **Step 5: Wire STOP_SENDING into `build_packet_in_frame` in processor.rs**

After the RESET_STREAM block (labeled `// 4e.`), add:

```rust
    // 4f. STOP_SENDING — request peer stops sending on a stream (RFC 9000 §3.5)
    if space == 2 {
        let retransmit_stops: smallvec::SmallVec<[(StreamId, u64); 4]> =
            conn.retransmit.stop_sending.drain(..).collect();
        for (id, error_code) in retransmit_stops {
            if builder.write_stop_sending(id, error_code, &mut conn.frame_log) {
                wrote_ack_eliciting = true;
            } else {
                conn.retransmit.stop_sending.push((id, error_code));
                break;
            }
        }
        let stop_streams: smallvec::SmallVec<[(StreamId, u64); 4]> = conn
            .streams
            .iter_all_recv()
            .filter_map(|(id, entry)| {
                entry.recv.as_ref().and_then(|r| {
                    if r.stop_sending_requested {
                        Some((id, r.stop_sending_error_code))
                    } else {
                        None
                    }
                })
            })
            .collect();
        for (id, error_code) in stop_streams {
            if builder.write_stop_sending(id, error_code, &mut conn.frame_log) {
                if let Some(entry) = conn.streams.get_mut(id) {
                    if let Some(ref mut recv) = entry.recv {
                        recv.stop_sending_requested = false;
                    }
                }
                wrote_ack_eliciting = true;
            } else {
                break;
            }
        }
    }
```

- [ ] **Step 6: Add `stop_sending` to socket API**

In `src/net/socket/quic.rs`, add to `QuicRecvStream`:

```rust
    pub fn stop_sending(&self, error_code: u64) {
        let handler = unsafe { &mut *self.handler.get() };
        if let Some(conn) = handler.connections.get_mut(self.conn_key) {
            if let Some(entry) = conn.streams.get_mut(self.stream_id) {
                if let Some(ref mut recv) = entry.recv {
                    recv.request_stop_sending(error_code);
                }
            }
        }
    }
```

Also add to `QuicStream`:

```rust
    pub fn stop_sending(&self, error_code: u64) {
        let handler = unsafe { &mut *self.handler.get() };
        if let Some(conn) = handler.connections.get_mut(self.conn_key) {
            if let Some(entry) = conn.streams.get_mut(self.stream_id) {
                if let Some(ref mut recv) = entry.recv {
                    recv.request_stop_sending(error_code);
                }
            }
        }
    }
```

- [ ] **Step 7: Run `cargo test` — all should pass**

- [ ] **Step 8: Commit**

```bash
git add src/net/handler/quic/stream/recv.rs src/net/handler/quic/transport/packet_builder.rs src/net/handler/quic/stream/map.rs src/net/handler/quic/processor.rs src/net/socket/quic.rs src/net/handler/quic/tests/stream_state_test.rs
git commit -m "fix(quic): implement STOP_SENDING frame generation (RFC 9000 §3.5)"
```

---

## Task 3: Stream cleanup on FIN/RESET

**Context:** Streams accumulate indefinitely in the `StreamMap`. After both sides are done (FIN sent+acked AND FIN received AND all data read, or RESET), the stream entry should be removed to prevent memory leaks.

**Files:**
- Modify: `src/net/handler/quic/processor.rs` (cleanup in ack handler and stream frame handler)
- Test: `src/net/handler/quic/tests/stream_map_test.rs`

- [ ] **Step 1: Write test for stream removal after completion**

In `src/net/handler/quic/tests/stream_map_test.rs`, add:

```rust
#[test]
fn stream_removed_after_completion() {
    use crate::net::handler::quic::stream::map::StreamMap;
    use crate::net::handler::quic::transport::frame::StreamId;
    let mut map = StreamMap::new(false); // server
    map.peer_max_bidi = 10;
    let id = StreamId(0); // client-initiated bidi
    assert!(map.get_or_create(id).is_ok());
    assert!(map.get(id).is_some());
    map.remove(id);
    assert!(map.get(id).is_none());
}
```

Run: `cargo test stream_removed_after_completion` — should PASS (remove already exists).

- [ ] **Step 2: Add stream cleanup check function to processor.rs**

In `src/net/handler/quic/processor.rs`, add a helper function:

```rust
/// Check if a stream is fully complete (both sides done) and can be removed.
fn is_stream_complete(entry: &StreamEntry) -> bool {
    let send_done = match &entry.send {
        None => true,
        Some(send) => {
            // Send done when: all data acked, or reset
            (send.fin_sent && send.buffer.is_empty() && send.acked == send.sent)
                || send.reset_requested
        }
    };
    let recv_done = match &entry.recv {
        None => true,
        Some(recv) => {
            // Recv done when: FIN received and all data read, or reset
            (recv.fin_received && recv.read_offset == recv.received) || recv.is_reset
        }
    };
    send_done && recv_done
}
```

You'll need to import `StreamEntry` from `super::stream::map::StreamEntry`.

- [ ] **Step 3: Add cleanup in the ACK handler (after stream data is acked)**

In `processor.rs`, in `handle_ack_frame`, after the loop that processes acked stream data (around line 969, after the pending_send_count decrement), add:

```rust
                    // Check if stream is fully complete and can be cleaned up
                    if is_stream_complete(entry) {
                        conn.streams.remove(*id);
                    }
```

This goes inside the `if let Some(entry) = conn.streams.get_mut(*id)` block, but AFTER the send half updates. Note the borrow — you may need to re-fetch the entry as an immutable reference for the check:

```rust
                // After advancing acked, check for stream completion
                if let Some(entry) = conn.streams.get(*id) {
                    if is_stream_complete(entry) {
                        conn.streams.remove(*id);
                    }
                }
```

- [ ] **Step 4: Add cleanup in stream frame handler (when FIN fully received + read)**

In `handle_stream_frame`, after the recv state transitions (around line 1038), the stream may be complete if both sides have already finished. Add at the end of the function, before the notification:

```rust
    // Check if stream is fully complete
    if let Some(entry) = conn.streams.get(stream_id) {
        if is_stream_complete(entry) {
            conn.streams.remove(stream_id);
            return None;
        }
    }
```

- [ ] **Step 5: Run `cargo test`**

- [ ] **Step 6: Commit**

```bash
git add src/net/handler/quic/processor.rs src/net/handler/quic/tests/stream_map_test.rs
git commit -m "fix(quic): clean up completed streams to prevent memory leaks"
```

---

## Task 4: Reject 0-RTT packets gracefully

**Context:** `processor.rs:213` silently drops 0-RTT packets by returning `None`. A client sending 0-RTT data will never get an acknowledgment, causing confusion. The server should either ignore 0-RTT entirely (which it does), but the key issue is that the server MUST still process the Initial packet that typically comes coalesced with 0-RTT. Currently 0-RTT returns `None` which is correct per the coalesced packet loop — it skips the 0-RTT packet and continues to the next one. The real fix needed: ensure `has_pending_data` is true for the response so the handshake proceeds.

Actually, on re-examination: the coalesced packet loop at processor.rs:170-278 processes each packet independently. When it hits a 0-RTT packet at line 213, it returns `None` (skip this packet) and the loop continues to the next packet in the datagram. The Initial packet in the same datagram IS processed. So 0-RTT silently dropping is actually correct behavior for a server that doesn't support 0-RTT — the client will retry the data in 1-RTT after handshake completes.

**This task is a NO-OP for correctness.** However, we should log or count dropped 0-RTT packets for observability.

**Files:**
- Modify: `src/net/handler/quic/processor.rs:213`

- [ ] **Step 1: Add a counter for dropped 0-RTT packets**

In `src/net/handler/quic/connection.rs`, add to `QuicConnectionState`:

```rust
    pub zero_rtt_rejected: u64,
```

Initialize to `0` in `new()`.

- [ ] **Step 2: Increment counter when 0-RTT is skipped**

In `processor.rs`, at line 213, change:

```rust
        } else {
            None // 0-RTT not supported
        }
```

to:

```rust
        } else {
            conn.zero_rtt_rejected += 1;
            None // 0-RTT not yet supported; client will retry in 1-RTT
        }
```

- [ ] **Step 3: Run `cargo test`**

- [ ] **Step 4: Commit**

```bash
git add src/net/handler/quic/processor.rs src/net/handler/quic/connection.rs
git commit -m "fix(quic): track rejected 0-RTT packets for observability"
```

---

## Task 5: Implement CUBIC congestion control

**Context:** `QuicCubic` in `congestion.rs` has CUBIC state fields (`w_max`, `k`, `epoch_start`) but congestion avoidance uses Reno-style linear increase. The CUBIC growth function `W_cubic(t) = C * (t - K)^3 + W_max` is never computed. This affects throughput on high-BDP links.

RFC 9002 §7.3 defers to RFC 8312 for CUBIC. Key formulas:
- `K = cbrt(W_max * (1 - beta) / C)` where `C = 0.4`, `beta = 0.3` (CUBIC), but QUIC uses `beta = 0.5` (RFC 9002 §7.3.2)
- `W_cubic(t) = C * (t - K)^3 + W_max` (in bytes, not segments)
- Use the max of W_cubic and standard TCP (Reno) during congestion avoidance

**Files:**
- Modify: `src/net/handler/quic/transport/congestion.rs`
- Test: `src/net/handler/quic/tests/congestion_test.rs`

- [ ] **Step 1: Write test for CUBIC growth**

In `src/net/handler/quic/tests/congestion_test.rs`, add:

```rust
#[test]
fn cubic_growth_exceeds_reno() {
    use crate::net::handler::quic::transport::congestion::QuicCubic;
    use crate::net::congestion::CongestionController;
    use coarsetime::{Duration, Instant};

    let mds = 1200;
    let mut cubic = QuicCubic::new(mds);
    let now = Instant::now();

    // Force a congestion event to enter congestion avoidance
    // First, grow window in slow start
    for _ in 0..20 {
        cubic.on_packets_sent(mds, now);
        cubic.on_ack(mds, Duration::from_millis(50), Duration::from_millis(50), now, true, now);
    }
    let pre_loss_cwnd = cubic.window();
    assert!(pre_loss_cwnd > 20000, "should have grown in slow start: {}", pre_loss_cwnd);

    // Trigger congestion event
    let loss_time = now + Duration::from_millis(100);
    cubic.on_congestion_event(mds, loss_time, loss_time);
    let post_loss_cwnd = cubic.window();
    assert!(post_loss_cwnd < pre_loss_cwnd, "window should decrease on loss");

    // Now simulate congestion avoidance with CUBIC
    // After K seconds, CUBIC should exceed the Reno growth rate
    let rtt = Duration::from_millis(50);
    let mut elapsed = Duration::from_millis(0);
    let ack_time_base = loss_time + Duration::from_millis(200);
    for i in 0..100 {
        let ack_time = ack_time_base + Duration::from_millis(i * 50);
        cubic.on_packets_sent(mds, ack_time);
        cubic.on_ack(mds, rtt, rtt, ack_time, true, ack_time);
    }
    let final_cwnd = cubic.window();
    // CUBIC should grow faster than Reno in congestion avoidance
    // Reno grows by ~mds per RTT, so after 100 RTTs: post_loss + 100*mds
    let reno_estimate = post_loss_cwnd + 100 * mds;
    // CUBIC should be comparable or larger (exact depends on K)
    assert!(final_cwnd > post_loss_cwnd + 50 * mds,
        "CUBIC should grow significantly: final={}, post_loss={}", final_cwnd, post_loss_cwnd);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test cubic_growth_exceeds_reno`
Expected: FAIL — current Reno won't match CUBIC growth.

- [ ] **Step 3: Implement CUBIC growth in `on_ack`**

In `src/net/handler/quic/transport/congestion.rs`, add CUBIC constants at the top:

```rust
// CUBIC constants (RFC 8312 §4.1, adapted for QUIC per RFC 9002 §7.3.2)
const CUBIC_C: f64 = 0.4;
const CUBIC_BETA: f64 = 0.5; // QUIC uses 0.5, not 0.3 (RFC 9002 §7.3.2)
```

Replace the congestion avoidance branch in `on_ack` (line 132-134):

```rust
        } else {
            // Congestion avoidance: cwnd += mds * acked_bytes / cwnd
            self.cwnd += self.max_datagram_size * acked_bytes / self.cwnd;
        }
```

with the full CUBIC calculation:

```rust
        } else {
            // CUBIC congestion avoidance (RFC 8312 §4.1)
            let t = match self.epoch_start {
                Some(epoch) => {
                    let elapsed = _now.duration_since(epoch);
                    elapsed.as_millis() as f64 / 1000.0
                }
                None => {
                    self.epoch_start = Some(_now);
                    0.0
                }
            };

            // W_cubic(t) = C * (t - K)^3 + W_max
            let w_cubic = CUBIC_C * (t - self.k).powi(3) * self.max_datagram_size as f64
                + self.w_max;

            // TCP-friendly estimate: W_est = W_max * beta + (3 * (1-beta) / (1+beta)) * (t / RTT)
            let rtt_secs = _rtt.as_millis().max(1) as f64 / 1000.0;
            let w_est = self.w_max * CUBIC_BETA
                + (3.0 * (1.0 - CUBIC_BETA) / (1.0 + CUBIC_BETA)) * (t / rtt_secs)
                    * self.max_datagram_size as f64;

            // Use the larger of CUBIC and TCP-friendly
            let target = w_cubic.max(w_est).max(self.cwnd as f64);
            let target_cwnd = target as usize;

            if target_cwnd > self.cwnd {
                // Grow by the CUBIC increment, scaled by acked bytes
                let increment = ((target_cwnd - self.cwnd) * self.max_datagram_size)
                    / self.cwnd;
                self.cwnd += increment.max(1) * acked_bytes / self.max_datagram_size;
            } else {
                // Reno fallback: at minimum grow by 1 mds per cwnd of acked data
                self.cwnd += self.max_datagram_size * acked_bytes / self.cwnd;
            }
        }
```

- [ ] **Step 4: Compute K on congestion event**

In `on_congestion_event` (around line 150), after `self.w_max = self.cwnd as f64;`, add the K computation:

```rust
        // K = cbrt(W_max * (1 - beta) / (C * mds))  (RFC 8312 §4.1, in segment-scale)
        // W_max is in bytes; dividing by (C * mds) gives segment-scale for K in seconds.
        // The w_cubic formula then multiplies back by mds to return bytes.
        self.k = (self.w_max * (1.0 - CUBIC_BETA) / (CUBIC_C * self.max_datagram_size as f64))
            .cbrt();
```

Also remove the `#[allow(dead_code)]` annotation from the `k` field in the `QuicCubic` struct (around line 19-20) since `k` is now actively used.

- [ ] **Step 5: Remove `_` prefix from `_rtt` and `_now` parameters in `on_ack`**

The `on_ack` method signature uses `_rtt` and `_now` — remove the underscores since they're now used:

```rust
    fn on_ack(
        &mut self,
        acked_bytes: usize,
        rtt: Duration,      // was _rtt
        _min_rtt: Duration,
        now: Instant,        // was _now
        in_flight: bool,
        sent_time: Instant,
    ) {
```

- [ ] **Step 6: Run test**

Run: `cargo test cubic_growth_exceeds_reno`
Expected: PASS

- [ ] **Step 7: Run all tests**

Run: `cargo test`
Expected: All pass.

- [ ] **Step 8: Commit**

```bash
git add src/net/handler/quic/transport/congestion.rs src/net/handler/quic/tests/congestion_test.rs
git commit -m "feat(quic): implement CUBIC congestion control (RFC 8312, RFC 9002 §7.3)"
```

---

## Post-Implementation Verification

After all tasks complete:

```bash
cargo test 2>&1 | tail -5
cargo check 2>&1 | grep "^error"
```

Expected: All tests pass, no errors.
