# QUIC Retry Packet Generation & PMTU Discovery

**Date:** 2026-03-23
**Branch:** quic-rustls
**RFCs:** RFC 9000 §8.1/§14.3/§17.2.5, RFC 9001 §5.8, RFC 8899, RFC 9369 §5

## Overview

Two features to complete the VoidNet QUIC implementation:

1. **Retry packet generation** — server sends Retry packets for address validation under load, with client-side handling
2. **DPLPMTUD with ICMP integration** — active path MTU probing using PADDING+PING frames, supplemented by the existing PmtuCache/ICMP pipeline

## Feature 1: Retry Packet Generation

### Protocol Flow

```
Client                          Server
  |                               |
  |--- Initial (no token) ------>|  (connections >= retry_threshold)
  |                               |  (connections < connection_limit)
  |<----- Retry (token) ---------|  Server generates encrypted token + integrity tag
  |                               |
  |--- Initial (with token) ---->|  Client resends with token, new DCID = Retry's SCID
  |                               |  Server validates token, creates connection
  |<---- Handshake continues ---->|
```

When `connections.len() >= connection_limit`: drop silently (existing behavior).

### Tiered Load Response

| Connection Count | Behavior |
|---|---|
| < `retry_threshold` (default 5000) | Accept Initial directly, no Retry |
| >= `retry_threshold` AND < `connection_limit` (default 10000) | Send Retry for address validation |
| >= `connection_limit` | Drop silently |

### Retry Packet Wire Format (RFC 9000 §17.2.5)

```
Retry Packet {
  Header Form (1) = 1,
  Fixed Bit (1) = 1,
  Long Packet Type (2),        // v1: 0b11, v2: 0b00
  Unused (4),
  Version (32),
  DCID Length (8),
  DCID (0..160),               // echoed from client's SCID
  SCID Length (8),
  SCID (0..160),               // new server-chosen CID
  Retry Token (..),            // encrypted address validation token
  Retry Integrity Tag (128),   // AES-128-GCM tag (RFC 9001 §5.8)
}
```

Key differences from other long-header packets: no Length field, no Packet Number field.

### Server-Side: Retry Generation

#### `build_retry_packet()` — standalone function

Location: `src/net/handler/quic/transport/packet_builder.rs` (as a free function, NOT a method on `PacketBuilder` — Retry packets lack the Length and Packet Number fields that `PacketBuilder::begin_long()` assumes)

Inputs:
- `version: u32` — QUIC version (for packet type bits and integrity tag key selection)
- `dcid: &[u8]` — client's Source CID (becomes Retry's DCID)
- `scid: &[u8]` — new server-chosen CID (becomes Retry's SCID)
- `odcid: &[u8]` — original Destination CID from client's Initial (for integrity tag AAD)
- `token: &[u8]` — encrypted retry token

Output: `Vec<u8>` — complete Retry packet ready to send

Construction:
1. Write first byte: form=1, fixed=1, packet type bits (v1: 0b11, v2: 0b00), unused lower 4 bits (SHOULD be random per RFC 9000 §17.2.5). Note: these bits become part of the integrity tag AAD — the verifier must use the bits as received, not regenerate them.
2. Write version (4 bytes, big-endian)
3. Write DCID length (1 byte) + DCID
4. Write SCID length (1 byte) + SCID
5. Write token bytes directly (no length prefix — token extends to end of packet minus 16-byte tag)
6. Compute integrity tag via `compute_retry_integrity_tag(odcid, packet_so_far, version)`
7. Append 16-byte integrity tag

Anti-amplification: the Retry packet is sent before address validation. It counts toward the 3× amplification limit (RFC 9000 §8.1). In practice, a Retry packet is ~100 bytes vs a 1200-byte Initial, so the limit is never reached.

#### Handler Integration

Location: `src/net/handler/quic/handler.rs`, in `create_server_connection()` path

Replace the current `return None` at retry_threshold:

```
if connections.len() >= retry_threshold && connections.len() < connection_limit {
    // Generate Retry
    1. Generate new server CID (8 bytes, random)
    2. Encrypt token: encrypt_token(token_secret, TokenType::Retry, client_ip, now_secs, odcid, version)
    3. Build Retry packet: build_retry_packet(version, client_scid, new_server_cid, odcid, encrypted_token)
    4. Queue for TX (via tx_return buffer or equivalent)
    return None  // Don't create connection state yet
}
```

#### Token Validation on Subsequent Initial

Token validation runs AFTER the `connection_limit` check. If the server is now at capacity when the client's Initial-with-token arrives, the packet is dropped silently — the client will timeout and retry the full handshake.

When an Initial packet arrives with a non-empty token (and server is below `connection_limit`):

1. Decrypt token via `decrypt_token(token_secret, token_bytes)`
2. On decryption failure → treat as no-token Initial (fall through to normal path)
3. Validate token type is `Retry` (0x00)
4. Validate client IP matches token's stored address
5. Validate timestamp: `now - token_timestamp <= retry_token_max_age`
6. Validate version matches
7. Extract ODCID from token
8. Create connection, store ODCID in connection state for transport parameter validation (RFC 9000 §7.3: server MUST include `original_destination_connection_id` and `retry_source_connection_id` transport params)

#### Token Nonce Safety

The existing `encrypt_token()` derives its 12-byte nonce from only the top 4 bytes of the timestamp (remaining 8 bytes zeroed). Under high Retry volume, this risks AES-GCM nonce reuse within the same second. Fix: replace the nonce derivation to use 4 bytes of timestamp + 8 bytes of random, ensuring uniqueness even under burst Retry generation. This fix applies to both Retry and NEW_TOKEN token paths.

### Client-Side: Retry Handling

Location: `src/net/handler/quic/processor.rs`

When client receives a packet parsed as `PacketType::Retry`:

1. Check: has client already processed a Retry for this connection? If yes → discard (RFC 9000 §17.2.5.2)
2. Verify integrity tag via `verify_retry_integrity_tag(odcid, retry_packet, version)` where `odcid` is the DCID the client originally sent
3. On failure → discard silently (possibly spoofed)
4. Extract token and new server CID (Retry's SCID)
5. Store token and new DCID (Retry's SCID) in connection state
6. Set `retry_received = true` flag to prevent accepting another Retry
7. Reset Initial packet number space to 0
8. Regenerate Initial keys using the new DCID (Retry's SCID) as the key derivation input
9. Resend Initial packet with:
   - DCID = Retry's SCID (the new server CID)
   - Token field = token from Retry packet
   - Same SCID as before
10. If 0-RTT was attempted, 0-RTT packets continue using original DCID's keys (RFC 9001 §4.9.2: "0-RTT keys are not re-generated")

### Configuration

Add to listener/handler config:
- `retry_token_max_age: Duration` — default 30 seconds, configurable

### Transport Parameter Obligations (RFC 9000 §7.3)

After a Retry, the server MUST include in its transport parameters:
- `original_destination_connection_id` — the ODCID extracted from the validated token
- `retry_source_connection_id` — the SCID the server used in the Retry packet

The client MUST validate these match what it observed. Mismatch → TRANSPORT_PARAMETER_ERROR.

### Error Handling

- Token decryption failure → treat as no-token Initial (normal processing path)
- Token expired → same as decryption failure
- Token address mismatch (NAT rebinding) → same
- Client receives Retry with bad integrity tag → discard silently
- Client receives second Retry → discard (one Retry per connection attempt)
- Coalesced Initial+0-RTT with token → server processes Initial first, validates token, then accepts 0-RTT if keys available

### Files Touched

| File | Change |
|---|---|
| `transport/packet_builder.rs` | Add `build_retry_packet()` |
| `handler.rs` | Retry generation in tiered load path, token validation on Initial-with-token |
| `processor.rs` | Client-side Retry handling |
| `connection.rs` | Add `retry_received: bool`, `original_dcid: Option<ConnectionId>`, `retry_scid: Option<ConnectionId>` fields |
| `transport/params.rs` | Emit `original_destination_connection_id` and `retry_source_connection_id` after Retry |

### Tests

1. **`build_retry_packet` round-trip** — build → parse header → verify type is Retry → verify integrity tag
2. **Tiered threshold behavior** — below threshold: no Retry; between thresholds: Retry sent; above limit: drop
3. **Client Retry handling** — feed Retry to client processor → verify Initial resent with token and new DCID
4. **Token validation (valid)** — encrypted token round-trips, address/version/expiry all match
5. **Token validation (expired)** — token older than max_age rejected gracefully
6. **Token validation (wrong address)** — NAT rebinding scenario, treated as no-token
7. **Double-Retry rejection** — client discards second Retry
8. **Bad integrity tag** — client discards Retry with tampered tag
9. **Full e2e with Retry** — client Initial → server Retry → client Initial+token → handshake completes → data flows
10. **Transport parameter validation** — server includes ODCID/retry_scid params, client validates
11. **Retry with coalesced 0-RTT** — Initial+0-RTT with token in one datagram, server validates then accepts 0-RTT
12. **Version mismatch in token** — client retries with different version than token was issued for, validation rejects gracefully

---

## Feature 2: DPLPMTUD with ICMP Integration

### Search Parameters

| Parameter | Value |
|---|---|
| Floor (BASE_PLPMTU) | 1200 bytes (QUIC minimum, RFC 9000 §14.1) |
| Ceiling (MAX_PLPMTU) | 1452 bytes (default, configurable via `pmtu_ceiling`) |
| Step threshold | 20 bytes (stop searching when ceiling - floor < 20) |
| Probe timeout | 3 × PTO (consistent with loss detection) |
| Max probe attempts per size | 3 (declare lost after 3 unanswered probes at same size) |
| Re-probe interval | 600 seconds (10 minutes, matches PmtuCache TTL) |
| Probing start | After connection reaches Established state |

### State Machine

```
         connection established
                |
                v
          +-----------+
          | Disabled  |  MTU = 1200
          +-----------+
                |
                | (auto-start after handshake)
                v
          +-----------+     probe ACKed (floor < ceiling - step)
          | Searching |------------------------------------------+
          +-----------+                                          |
           |    |    ^                                           |
           |    |    | ICMP reduces MTU below current            |
           |    |    +-------------------------------------------+
           |    |
           |    | converged (ceiling - floor < step)
           |    | OR 3 consecutive probe losses at same size
           |    v
          +----------------+
          | SearchComplete |  MTU = floor (last confirmed size)
          +----------------+
                |       ^
                |       | re-probe timer (10 min)
                +-------+
                |
                | path migration
                v
          +-----------+
          | Disabled  |  reset to 1200, restart
          +-----------+
```

### PmtuState Struct

Location: new struct in `src/net/handler/quic/path.rs` (co-located with PathState)

```rust
pub(crate) struct PmtuState {
    phase: PmtuPhase,          // Disabled, Searching, SearchComplete
    floor: u16,                // lowest confirmed working MTU (starts 1200)
    ceiling: u16,              // highest unconfirmed MTU (starts 1452)
    probe_size: u16,           // current probe target: (floor + ceiling) / 2
    probe_pn: Option<u64>,     // packet number of outstanding probe (one at a time, always 1-RTT space)
    probe_count: u8,           // consecutive failed probes at current size
    last_probe_time: Instant,  // for timeout detection
}
```

### Probe Generation

Location: `src/net/handler/quic/processor.rs`, in packet building path

When PmtuProbe timer fires and state is Searching:
1. Compute probe_size = (floor + ceiling) / 2
2. Build a 1-RTT packet containing PING frame
3. Pad with PADDING frames so total UDP payload (= QUIC packet on wire) equals probe_size. PADDING length = `probe_size - header_len - 1(PING) - 16(AEAD tag)`. The `probe_size` is in the same units as `max_udp_payload` — total QUIC packet size, not including IP/UDP headers.
4. Tag the sent packet as a PMTU probe in the loss detector (new `is_pmtu_probe: bool` field on SentPacket)
5. Record `probe_pn` and `last_probe_time`
6. Arm PmtuProbe timer for 3 × PTO

### Probe ACK Handling

In ACK processing (processor.rs), when an ACKed packet has `is_pmtu_probe = true`:
1. `floor = probe_size` (this size works)
2. Update `connection.max_udp_payload = floor`
3. Call `congestion.on_mtu_update(floor)` to adjust CWND
4. If `ceiling - floor >= step_threshold`: compute new probe_size, arm timer for next probe
5. If `ceiling - floor < step_threshold`: transition to SearchComplete, arm re-probe timer (10 min)

### Probe Loss Handling

In loss detection, when a lost packet has `is_pmtu_probe = true`:
1. Do NOT invoke congestion controller (probe loss is not congestion signal)
2. Increment `probe_count`
3. If `probe_count < 3`: retry same size, arm timer
4. If `probe_count >= 3`: `ceiling = probe_size`, reset `probe_count = 0`
5. If `ceiling - floor < step_threshold`: transition to SearchComplete with MTU = floor

### ICMP Integration

The existing pipeline: ICMP Packet-Too-Big → `handler/icmpv4.rs` / `handler/icmpv6.rs` → `PmtuCache::update()`

New integration point in `handler.rs`:
- When `PmtuCache` is updated for an IP that has active QUIC connections, notify those connections
- Connection receives notification with new MTU value
- If new MTU < current `floor`: set `floor = max(new_mtu, 1200)`, set `max_udp_payload = floor`, notify congestion controller, enter Searching
- If new MTU < current `ceiling` but >= `floor`: set `ceiling = new_mtu`, continue or restart search
- If new MTU >= `ceiling`: ignore (current search already bounded lower)

Implementation: after `PmtuCache::update()` in ICMP handlers, iterate connections for that peer IP via the connection table's address index. This is O(connections per IP) which is bounded by `per_ip_limit` (100).

### Re-probing (SearchComplete)

When re-probe timer fires (10 minutes):
- Reset `ceiling` to configured `pmtu_ceiling` (default 1452), keep `floor` at last confirmed MTU
- Transition to Searching
- This detects path changes that increase available MTU

### Path Migration Reset

When `PathState::on_peer_address_change()` is called:
- Reset PmtuState to Disabled (floor = 1200, ceiling = 1452)
- Set `max_udp_payload = 1200`
- Update congestion controller
- PMTU search restarts automatically after path validation completes

### Configuration

- `pmtu_probing_enabled: bool` — default true
- `pmtu_ceiling: u16` — default 1452, override for specific deployments

### Error Handling

- Probe loss is not a congestion event — excluded from congestion controller
- All probes lost at floor → stay at 1200, SearchComplete (path doesn't support larger)
- ICMP reports MTU below 1200 → clamp to 1200 (QUIC minimum), log warning
- `on_mtu_update()` with smaller MTU mid-flight → in-flight large packets may be lost, loss detector retransmits normally
- Probing during congestion window exhaustion → probe counts against bytes_in_flight, respects CWND

### Files Touched

| File | Change |
|---|---|
| `path.rs` | Add `PmtuState` struct and methods |
| `processor.rs` | PmtuProbe timer handler, probe generation, probe ACK/loss special handling |
| `transport/packet_builder.rs` | Probe packet construction (PING + PADDING to target size) |
| `connection.rs` | Add `PmtuState` field, update `max_udp_payload` on MTU changes |
| `transport/loss.rs` | Add `is_pmtu_probe` flag to SentPacket, exclude probe loss from congestion |
| `transport/congestion.rs` | Enhance `on_mtu_update()` to scale CWND proportionally (`cwnd = cwnd * new_mtu / old_mtu`) in addition to updating `max_datagram_size`. Ensures effective window in packets stays constant across MTU changes. |
| `handler.rs` | ICMP→connection notification path, PmtuCache lookup |

### Tests

1. **PmtuState transitions** — Disabled → Searching → SearchComplete, verify state fields at each step
2. **Binary search convergence** — simulate probe ACK/loss sequence, verify floor/ceiling converge within expected iterations (ceil(log2(252/20)) = 4 iterations for 1200→1452 range)
3. **Probe packet format** — verify PING + PADDING at exact target size
4. **Probe ACK raises floor** — ACK probe at 1326 → floor = 1326, new probe at 1389
5. **Probe loss lowers ceiling** — lose probe at 1326 → ceiling = 1326, new probe at 1263
6. **3 consecutive losses** — 3 failures at same size → ceiling drops, search continues or completes
7. **Probe loss excluded from congestion** — verify congestion window unchanged on probe loss
8. **ICMP lowers MTU** — cache update → connection MTU reduced → re-enters Searching
9. **ICMP below 1200** — clamped to 1200
10. **Path migration resets** — new path → Disabled → restart search
11. **Re-probe timer** — SearchComplete → 10 min → Searching again
12. **`on_mtu_update()` propagation** — congestion controller CWND adjusts to new MTU
13. **No probing during handshake** — verify probes only sent after Established

---

## Implementation Order

1. **Retry packet generation** (server-side build + handler integration)
2. **Retry client handling** (processor Retry detection + Initial resend)
3. **Retry token validation** (server validates token on Initial-with-token)
4. **Retry e2e test** (full handshake through Retry)
5. **PMTU state machine** (PmtuState struct + transitions)
6. **PMTU probe generation** (timer handler + packet building)
7. **PMTU probe ACK/loss handling** (floor/ceiling adjustment + congestion integration)
8. **PMTU ICMP integration** (PmtuCache → connection notification)
9. **PMTU re-probing + path migration reset**
10. **PMTU e2e test** (probe sequence → MTU convergence)
