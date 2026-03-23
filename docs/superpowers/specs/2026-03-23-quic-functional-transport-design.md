# QUIC Functional Transport — Design Spec

**Date:** 2026-03-23
**Branch:** quic-rustls
**Goal:** Complete the QUIC implementation as a functional bidirectional transport for VoidNet internal use, with an API clean enough for general-purpose use.

**Approach:** End-to-end first — get a complete client+server data path working, then harden with migration, key rotation, and version negotiation.

**RFCs:** RFC 9000 (QUIC v1), RFC 9001 (QUIC-TLS), RFC 9002 (Loss/CC), RFC 9369 (QUIC v2), RFC 8999 (VN Invariants)

---

## Current State

The branch has ~31k lines of QUIC implementation across 96 files. What works:

- **Handshake:** Full rustls integration, Initial/Handshake/1-RTT key installation
- **0-RTT:** Key extraction, packet acceptance, counter tracking
- **Packet processing:** Coalesced packet parsing, multi-space decryption, header protection
- **Frames:** 15/17 frame types handled (missing: KEY_UPDATE wire protocol, NEW_TOKEN processing)
- **ACK/Loss:** RFC 9002 compliant loss detection, PTO, congestion events
- **Congestion:** CUBIC with pacing
- **Streams:** Full recv side (ring buffer, OOO reassembly, 552 lines). Skeletal send side (53 lines)
- **Flow control:** Per-stream and connection-level, blocking detection
- **CID lifecycle:** Sequence tracking, retirement, active limit enforcement
- **Path:** Detection of address changes, PATH_CHALLENGE/RESPONSE primitives, amplification limits
- **Stateless reset, retry:** Complete

What's missing or incomplete is addressed in the six sections below.

---

## Section 1: Complete SendHalf

**Problem:** `SendHalf` (53 lines) lacks retransmit gap tracking. Loss recovery rewinds `sent` backward, which can re-send already-acked data when there are gaps.

**Design:**

Add `retransmit_ranges: SmallVec<[(u64, u64); 4]>` to `SendHalf`. Each entry is a `(start_offset, end_offset)` byte range that was lost and needs retransmission.

Packet builder priority order:
1. Retransmit ranges (lost data first)
2. New data from `sent..buffer_end` (subject to flow control)

When ACKs arrive and advance `acked`:
- Remove fully-acked retransmit ranges
- Trim partially-acked ranges
- Free ring buffer space (advance head)
- Push `QuicEvent` to wake blocked `StreamWrite` futures (backpressure release)

Loss detection changes: instead of rewinding `sent`, insert the lost byte range into `retransmit_ranges`.

**Files modified:**
- `stream/send.rs` — add retransmit ranges, ack processing, buffer space reclaim
- `processor.rs` — loss handler inserts ranges instead of rewinding `sent`
- `transport/packet_builder.rs` — emit retransmit ranges before new data

---

## Section 2: Client-Side Connect

**Problem:** `QuicConnection::connect()` is a stub returning `Poll::Pending` forever. Only server-side connections work.

**Design:**

New method `QuicHandler::initiate_connection()`:
1. Generate random DCID (for the server) and SCID (our identifier)
2. Create `QuicConnectionState` with `Side::Client`
3. Initialize rustls `ClientConnection` with server name and config
4. Extract initial TLS ClientHello, buffer as pending CRYPTO data in Initial space
5. Derive Initial keys from the generated DCID (RFC 9001 sect 5.2)
6. Insert connection in slab, register SCID in CID map
7. Mark connection as needing to send

`Connect` future:
- Holds `conn_key` and handler reference
- Polls connection state; resolves when `Established`
- Registers waker on `event_queue`
- Processor already pushes events on handshake completion — just need to ensure it does so for client side too

Client Initial padding: RFC 9000 sect 14.1 requires >= 1200 bytes. Packet builder pads Initial packets from client side.

**Files modified:**
- `handler.rs` — add `initiate_connection()` method
- `socket/quic.rs` — implement `Connect` future, wire `connect()` to handler
- `transport/packet_builder.rs` — ensure client Initial padding to 1200 bytes

---

## Section 3: Graceful Shutdown

**Problem:** Peer-side gets no notification when a connection closes. Stream futures hang until the connection is removed from the slab.

**Design:**

1. **Connection closed event.** When CONNECTION_CLOSE is received (already parsed in processor), push `QuicEvent::ConnectionClosed` to `event_queue`. All blocked stream futures wake and check connection state.

2. **Drain wake-all.** Before the handler removes a connection (on draining timer or idle timeout), call `event_queue.wake_all()` so no futures are left hanging.

3. **Error code propagation.** Extend `QuicError::ConnectionClosed` to `ConnectionClosed(Option<u64>)` to carry the peer's error code. Stream read/write futures return this when the connection is in Closing/Draining/Closed state.

4. **Idle timeout.** Already implemented. Just add the wake-all before removal.

**Files modified:**
- `socket/quic.rs` — extend `QuicError::ConnectionClosed`, update read/write futures
- `processor.rs` — push `QuicEvent::ConnectionClosed` on CONNECTION_CLOSE receipt
- `handler.rs` — wake-all before connection removal

---

## Section 4: Connection Migration

**Problem:** Peer address change is detected but not acted on. No CID rotation, no path revert on timeout, no NAT rebinding distinction.

**Design:**

**Previous path storage.** Add to `QuicConnectionState`:
```
prev_path: Option<PreviousPath>
```
Where `PreviousPath` holds `{ remote_addr, remote_port, remote_mac, path_state }`. Snapshot before updating on address change.

**Migration flow (peer address change detected):**
1. Snapshot current path into `prev_path`
2. Update `remote_addr`/`remote_port` to new values
3. Reset `path` — unvalidated, fresh amplification limits
4. Pick unused CID from `scid_set`, update handler's DCID map
5. Retire old CID (queue RETIRE_CONNECTION_ID frame)
6. Send PATH_CHALLENGE on new path (`initiate_validation()`)
7. Arm `PathValidation` timer

**Path validation timeout revert.** `handle_timeout(PathValidation)`:
- If `prev_path` exists and current path not validated: restore previous path, drop failed path
- If no `prev_path`: close connection

**NAT rebinding.** If only port changed and DCID matches a known CID: update remote port, skip full migration (no CID rotation, no path validation).

**Amplification on new path.** `generate_packets` checks `path.amplification.can_send()` before sending on unvalidated paths. Already enforced for server Initial; extend to migration paths.

**Files modified:**
- `connection.rs` — add `PreviousPath` struct, `prev_path` field
- `path.rs` — no structural changes, possibly add helper methods
- `processor.rs` — wire migration detection into full flow (CID rotation, challenge, timer)
- `handler.rs` — update DCID map on CID rotation, handle timeout revert
- `connection_id.rs` — add method to pick next unused CID for migration

---

## Section 5: Key Update Wire Protocol

**Problem:** Key phase tracking exists but keys are never actually rotated on the wire. Long-lived connections will hit AEAD limits.

**Design:**

Key update is signaled via the key phase bit in short (1-RTT) headers, not a frame type.

**Detecting peer key update.** In 1-RTT packet processing, when `key_update.is_peer_update(received_key_phase)`:
1. Save current remote packet key as `prev_remote_packet_key`
2. Derive new keys via `key_update_secrets.next_packet_keys()` (rustls API)
3. Install new remote key, flip `key_phase`
4. Arm key discard timer (3xPTO) for old key
5. Decrypt with new key; on failure, retry with `prev_remote_packet_key`

**Initiating key update.** Add `needs_key_update: bool` to connection state. Packet builder checks this flag + `can_initiate_update()`:
1. Save current remote packet key
2. Derive new local + remote keys from secrets
3. Flip `key_phase`, reset `lowest_pn_current_phase`
4. Arm key discard timer
5. Clear flag

**Triggers:**
- AEAD limit approach: when `packets_encrypted[2]` nears confidentiality limit, set `needs_key_update = true`
- Optional: `QuicConnection::update_keys()` for app-driven rotation

**ACK tracking.** When ACK received for pn >= `lowest_pn_current_phase`, set `acked_current_phase = true` to unblock next update.

**Files modified:**
- `connection.rs` — add `needs_key_update` flag
- `processor.rs` — detect peer key update in 1-RTT decrypt path, handle phase mismatch
- `transport/packet_builder.rs` — initiate key update when flag set
- `crypto/keys.rs` — add key derivation from secrets helper

---

## Section 6: Version Negotiation Client Retry

**Problem:** Client doesn't handle Version Negotiation packets. TODO at `processor.rs:266`.

**Design:**

**VN packet handling.** When client receives long header with version 0x00000000:
1. Parse supported version list from payload
2. Validate: SCID in VN matches our DCID (anti-spoofing, RFC 8999 sect 6)
3. Only process if in `Handshaking` state (ignore if handshake complete)
4. Find highest mutually-supported version (we support v1 `0x00000001` and v2 `0x6b3343cf`)
5. If no match: close with version negotiation error

**Retry with new version:**
1. Store original version in `conn.original_version: Option<u32>`
2. Update `conn.version` to negotiated version
3. Re-derive Initial keys with version-appropriate salt (v2 uses `0x0dede3def700a6db819381be6e269dcbf9bd2ed9`)
4. Reset crypto state — fresh ClientHello from rustls
5. Reset packet number spaces and ACK state
6. Re-send Initial packet

**Downgrade prevention (RFC 9369 sect 4).** After handshake, validate `version_information` transport parameter. Mismatch → TRANSPORT_PARAMETER_ERROR.

**Scope limit:** Incompatible VN only (round-trip penalty variant). Compatible VN (RFC 9368) deferred.

**Files modified:**
- `connection.rs` — add `original_version` field
- `handler.rs` — route VN packets to client connection
- `processor.rs` — VN packet processing, version retry logic
- `crypto/initial_keys.rs` — support v2 salt for key derivation
- `transport/params.rs` — validate `version_information` after handshake

---

## Out of Scope

- **NEW_TOKEN / session resumption** — frame parsed but not processed; deferred
- **DATAGRAM extension** (RFC 9221) — not needed for transport
- **Compatible version negotiation** (RFC 9368) — incompatible VN sufficient
- **Multi-path QUIC** (RFC 9443) — separate extension
- **Preferred address** transport parameter — deferred
- **Variable-length CIDs** — 8-byte fixed is fine for now
