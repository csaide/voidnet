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

Add two tracking structures to `SendHalf`:
- `retransmit_ranges: SmallVec<[(u64, u64); 4]>` — byte ranges lost and needing retransmit. Kept sorted, merged on insert to prevent fragmentation.
- `acked_ranges: SmallVec<[(u64, u64); 4]>` — non-contiguous acknowledged byte ranges ahead of the contiguous ack frontier.

**Offset semantics:**
- `acked`: highest *contiguous* byte offset acknowledged (the ring buffer head). All bytes below this are confirmed and can be freed.
- `acked_ranges`: out-of-order ACK ranges above `acked`. When a gap fills, coalesce into `acked` and advance the ring buffer head.
- `sent`: highest byte offset transmitted (the new-data frontier).

**Example lifecycle:** Write 1000 bytes. ACK 0-400 → `acked=400`, head advances, 400 bytes freed. Lose 400-600. ACK 600-800 → `acked_ranges=[(600,800)]`, head stays at 400 (data 400-600 still in buffer for retransmit). Loss detected → `retransmit_ranges=[(400,600)]`. Retransmit 400-600. ACK 400-600 → gap fills, coalesce: `acked=800`, `acked_ranges` cleared, head advances to 800.

**Packet builder priority order:**
1. Retransmit ranges (lost data first) — read from ring buffer at arbitrary offsets via `peek_at(offset, len)` (new method on `StreamRingBuffer`)
2. New data from `sent..buffer_end` (subject to flow control) — existing `peek_slices` path

**Ring buffer change:** Add `peek_at(offset_from_head: usize, buf: &mut [u8]) -> usize` to `StreamRingBuffer` for reading at arbitrary offsets without advancing head. This lets the packet builder read retransmit data from anywhere in the buffer.

**Backpressure:** When `on_ack` advances `acked` and frees ring buffer space, push `QuicEvent::DataAcked` to wake blocked `StreamWrite` futures.

**`pending_send_count` update:** A stream has pending send data if `!buffer.is_empty() || !retransmit_ranges.is_empty()`. Update `has_pending_send()` to check both.

Loss detection changes: instead of rewinding `sent`, insert the lost byte range into `retransmit_ranges`.

**Files modified:**
- `stream/send.rs` — add retransmit ranges, acked ranges, ack processing, buffer space reclaim
- `stream/recv.rs` — add `peek_at()` method to `StreamRingBuffer`
- `processor.rs` — loss handler inserts ranges instead of rewinding `sent`; ACK handler updates `acked_ranges`
- `transport/packet_builder.rs` — emit retransmit ranges (via `peek_at`) before new data

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

**Address resolution:** The client needs `local_addr`, `local_mac`, and `remote_mac` to build outgoing frames. `local_addr` and `local_mac` come from the runtime context (already available in `QuicHandler`). `remote_mac` requires the gateway MAC from the routing table — use the same ARP/ND-resolved MAC that the UDP socket path uses. Store `remote_addr` and `remote_port` from the `connect()` call parameters. The `initiate_connection()` method takes these as arguments alongside the TLS config.

**Connect future design:** `connect()` is currently a static method returning a stub. Change it to call `initiate_connection()` first (creating the connection eagerly), then return a `Connect` future holding `conn_key: usize` and `handler: Rc<UnsafeCell<QuicHandler>>`. The future polls connection state and resolves to `QuicConnection` when `Established`. This mirrors how `Accept` works.

**Rustls config retention:** Store `Arc<ClientConfig>` and `server_name: String` in `QuicConnectionState` so they're available for version negotiation retry (Section 6 needs to create a fresh `ClientConnection`).

`Connect` future:
- Holds `conn_key` and handler reference (created eagerly by `connect()`)
- Polls connection state; resolves when `Established`
- Registers waker on `event_queue`
- Processor already pushes events on handshake completion — just need to ensure it does so for client side too

Client Initial padding: RFC 9000 sect 14.1 requires >= 1200 bytes. Packet builder pads Initial packets from client side.

**Files modified:**
- `handler.rs` — add `initiate_connection()` method with address resolution
- `connection.rs` — add optional `client_config` and `server_name` fields
- `socket/quic.rs` — implement `Connect` future with `conn_key` + handler ref, change `connect()` to eager creation
- `transport/packet_builder.rs` — ensure client Initial padding to 1200 bytes

---

## Section 3: Graceful Shutdown

**Problem:** Peer-side gets no notification when a connection closes. Stream futures hang until the connection is removed from the slab.

**Design:**

1. **Connection closed event.** When CONNECTION_CLOSE is received (already parsed in processor), push `QuicEvent::ConnectionClosed` to `event_queue`. All blocked stream futures wake and check connection state.

2. **Drain wake-all.** Before the handler removes a connection (on draining timer or idle timeout), call `wake_all()` on both `event_queue` and `stream_accept_queue` so no futures are left hanging (the `AcceptStream` future registers on `stream_accept_queue`, not `event_queue`).

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

**Cross-boundary signaling:** `process_packet()` takes `&mut QuicConnectionState` without access to `QuicHandler`, so it cannot update the DCID map directly. The processor returns migration signals via a new field `conn.pending_migration: Option<MigrationAction>` (containing old/new CID info). The handler checks this after `process_packet()` returns and performs the DCID map update. Same pattern used for other handler-level operations like connection removal.

**Path validation timeout revert.** `handle_timeout(PathValidation)`:
- If `prev_path` exists and current path not validated: restore previous path, drop failed path
- If no `prev_path`: close connection

**NAT rebinding vs intentional migration (RFC 9000 sect 9.3).** Distinguish by whether the peer used a new CID: if the packet's DCID is the *same* CID the peer was already using and only the source port changed, treat as NAT rebinding — update remote port, skip CID rotation and path validation. If the peer sent on a *new* CID (one from NEW_CONNECTION_ID that wasn't the active one), treat as intentional migration — full flow above.

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

**Counter reset.** On key update, reset `packets_encrypted[2]` to 0. The AEAD limit tracks per-key usage, not per-connection lifetime. Without this, the limit would trigger immediately after every update.

**ACK tracking.** When ACK received for pn >= `lowest_pn_current_phase`, set `acked_current_phase = true` to unblock next update.

**Key derivation.** `conn.key_update_secrets` (already stored, type `rustls::quic::Secrets`) provides `next_packet_keys()` which returns a `PacketKeySet` with both local and remote keys. No raw HKDF needed — rustls handles the derivation.

**Files modified:**
- `connection.rs` — add `needs_key_update` flag
- `processor.rs` — detect peer key update in 1-RTT decrypt path, handle phase mismatch, reset `packets_encrypted[2]`
- `transport/packet_builder.rs` — initiate key update when flag set
- `crypto/keys.rs` — wrap `Secrets::next_packet_keys()` call and install results

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
3. Re-derive Initial keys with version-appropriate salt (rustls handles v1/v2 salt selection internally via `Version` enum — no raw salt bytes needed)
4. Create a fresh rustls `ClientConnection` using the stored `client_config` and `server_name` (from Section 2). rustls connections are not resettable — must create new.
5. Reset packet number spaces and ACK state
6. Re-send Initial packet

**Downgrade prevention (RFC 9369 sect 4).** After handshake, validate `version_information` transport parameter: server's `chosen_version` must match negotiated version, and `other_versions` must include the client's originally-attempted version. Mismatch → TRANSPORT_PARAMETER_ERROR.

**Scope limit:** Incompatible VN only (round-trip penalty variant). Compatible VN (RFC 9368) deferred.

**Files modified:**
- `connection.rs` — add `original_version` field
- `handler.rs` — route VN packets to client connection
- `processor.rs` — VN packet processing, version retry logic
- `crypto/initial_keys.rs` — support v2 salt for key derivation
- `transport/params.rs` — add `version_information` transport parameter parsing (type 0x11) and post-handshake validation

---

## Out of Scope

- **NEW_TOKEN / session resumption** — frame parsed but not processed; deferred
- **DATAGRAM extension** (RFC 9221) — not needed for transport
- **Compatible version negotiation** (RFC 9368) — incompatible VN sufficient
- **Multi-path QUIC** (RFC 9443) — separate extension
- **Preferred address** transport parameter — deferred
- **Variable-length CIDs** — 8-byte fixed is fine for now
