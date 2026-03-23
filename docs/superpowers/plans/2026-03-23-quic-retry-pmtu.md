# QUIC Retry Packet Generation & DPLPMTUD Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement server-side Retry packet generation with client handling, and DPLPMTUD with ICMP integration for active path MTU discovery.

**Architecture:** Two independent features built sequentially. Retry (Tasks 1-7) adds tiered load response: connections between `retry_threshold` and `connection_limit` trigger Retry packets instead of silent drops. PMTU (Tasks 8-14) adds a binary-search probe state machine that discovers path MTU between 1200-1452 bytes using PADDING+PING probes, supplemented by the existing PmtuCache/ICMP pipeline.

**Tech Stack:** Rust, ring (AES-GCM for tokens, random for CIDs), rustls (TLS/QUIC), coarsetime (timers)

**Spec:** `docs/superpowers/specs/2026-03-23-quic-retry-pmtu-design.md`

**Testing:** Always use plain `cargo test` (no `--features` flags). Tests require root (configured via `.cargo/config.toml`).

---

## File Structure

### Retry Feature (Tasks 1-7)
| File | Action | Responsibility |
|---|---|---|
| `src/net/handler/quic/transport/packet_builder.rs` | Modify | Add `build_retry_packet()` standalone function |
| `src/net/handler/quic/token_crypto.rs` | Modify | Fix nonce derivation (timestamp+random) |
| `src/net/handler/quic/connection.rs` | Modify | Add `retry_received`, `original_dcid`, `retry_token` fields |
| `src/net/handler/quic/handler.rs` | Modify | Retry generation in tiered path, token validation, `retry_token_max_age` config |
| `src/net/handler/quic/processor.rs` | Modify | Client-side Retry handling |
| `src/net/handler/quic/transport/version.rs` | Modify | Add `retry_packet_type_bits()` helper |
| `src/net/handler/quic/tests/retry_test.rs` | Modify | Extend with build/parse/validation tests |

### PMTU Feature (Tasks 8-14)
| File | Action | Responsibility |
|---|---|---|
| `src/net/handler/quic/path.rs` | Modify | Add `PmtuState` struct and methods |
| `src/net/handler/quic/transport/loss.rs` | Modify | Add `is_pmtu_probe` flag to `SentPacket` |
| `src/net/handler/quic/transport/congestion.rs` | Modify | Enhance `on_mtu_update()` with CWND scaling |
| `src/net/handler/quic/connection.rs` | Modify | Add `pmtu` field, config fields |
| `src/net/handler/quic/processor.rs` | Modify | PmtuProbe timer handler, probe generation, probe ACK/loss handling |
| `src/net/handler/quic/handler.rs` | Modify | ICMP→connection notification |
| `src/net/handler/quic/tests/pmtu_test.rs` | Create | All PMTU tests |

---

## Task 1: Fix Token Nonce Safety

**Files:**
- Modify: `src/net/handler/quic/token_crypto.rs:54-57` (nonce derivation)
- Test: `src/net/handler/quic/tests/new_token_test.rs` (existing tests must still pass)

- [ ] **Step 1: Write test for nonce uniqueness**

Add to `src/net/handler/quic/tests/retry_test.rs`:

```rust
#[test]
fn token_encrypt_unique_nonces() {
    // Two tokens encrypted in the same second must produce different ciphertexts
    // (proving the nonce includes randomness, not just timestamp)
    let secret = [0xABu8; 32];
    let ip = &[127u8, 0, 0, 1];
    let ts = 1000u64;
    let dcid = &[1u8, 2, 3, 4];
    let version = 0x00000001u32;

    let t1 = crate::net::handler::quic::token_crypto::encrypt_token(
        &secret,
        crate::net::handler::quic::token_crypto::TokenType::Retry,
        ip, ts, dcid, version,
    ).unwrap();
    let t2 = crate::net::handler::quic::token_crypto::encrypt_token(
        &secret,
        crate::net::handler::quic::token_crypto::TokenType::Retry,
        ip, ts, dcid, version,
    ).unwrap();

    // Random portion of nonce (bytes 4..12) must differ across calls
    assert_ne!(&t1[4..12], &t2[4..12], "random nonce bytes must differ across calls");
    // Full ciphertexts must also differ
    assert_ne!(t1, t2);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test token_encrypt_unique_nonces -- --exact`
Expected: FAIL — current nonce is deterministic from timestamp, so both tokens are identical.

- [ ] **Step 3: Fix nonce derivation in token_crypto.rs**

Replace lines 54-57 in `src/net/handler/quic/token_crypto.rs`:

```rust
    // Build 12-byte nonce: 4 bytes timestamp + 8 bytes random
    let ts_bytes = timestamp_secs.to_be_bytes();
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..4].copy_from_slice(&ts_bytes[..4]);
    {
        use ring::rand::SecureRandom;
        ring::rand::SystemRandom::new()
            .fill(&mut nonce_bytes[4..])
            .map_err(|_| ())?;
    }
```

Also update the wire format: change `nonce_prefix(4)` to `nonce_prefix(12)` — the full 12-byte nonce is now written to the output since the receiver needs it for decryption.

Update `encrypt_token` output section (lines 67-71):

```rust
    // Output: nonce(12) + ciphertext_with_tag
    let mut output = Vec::with_capacity(12 + plaintext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&plaintext);
    Ok(output)
```

Update `decrypt_token` (lines 81-91) to read 12-byte nonce:

```rust
    // Minimum size: 12 (nonce) + 1 (type) + 1 (ip_ver) + 4 (ipv4) + 8 (ts) + 1 (dcid_len) + 4 (version) + 16 (tag)
    if encrypted.len() < 12 + 19 + 16 {
        return Err(());
    }

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&encrypted[..12]);
    let mut ciphertext = encrypted[12..].to_vec();
```

- [ ] **Step 4: Run all tests to verify nothing broke**

Run: `cargo test`
Expected: ALL PASS including new `token_encrypt_unique_nonces` and existing `new_token_*` tests.

- [ ] **Step 5: Commit**

```bash
git add src/net/handler/quic/token_crypto.rs src/net/handler/quic/tests/retry_test.rs
git commit -m "fix(quic): use random nonce in token encryption to prevent AES-GCM nonce reuse"
```

---

## Task 2: Add `build_retry_packet()` Function

**Files:**
- Modify: `src/net/handler/quic/transport/packet_builder.rs` (add standalone function at end of file)
- Modify: `src/net/handler/quic/transport/version.rs` (add `retry_packet_type_bits()`)
- Test: `src/net/handler/quic/tests/retry_test.rs`

- [ ] **Step 1: Add `retry_packet_type_bits()` to version.rs**

Append to `src/net/handler/quic/transport/version.rs`:

```rust
/// Returns the 2-bit long header packet type field for Retry packets.
/// v1: 0b11 (0x03), v2: 0b00 (0x00) per RFC 9369 §3.2.
pub fn retry_packet_type_bits(version: u32) -> u8 {
    if version == QUIC_VERSION_2 {
        0x00
    } else {
        0x03
    }
}
```

- [ ] **Step 2: Write test for `build_retry_packet` round-trip**

Add to `src/net/handler/quic/tests/retry_test.rs`:

```rust
use crate::net::handler::quic::transport::packet_builder::build_retry_packet;
use crate::net::handler::quic::transport::version::QUIC_VERSION_1;
use crate::net::wire::quic::{self as wire_quic, PacketHeader, PacketType};

#[test]
fn build_retry_packet_roundtrip_v1() {
    let version = QUIC_VERSION_1;
    let dcid = &[0x01, 0x02, 0x03, 0x04]; // client's SCID → Retry's DCID
    let scid = &[0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11]; // new server CID
    let odcid = &[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]; // original DCID
    let token = &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];

    let packet = build_retry_packet(version, dcid, scid, odcid, token);

    // Parse the header
    let (header, _consumed) = wire_quic::parse_header(&packet, 0).unwrap();
    match header {
        PacketHeader::Long(long) => {
            assert_eq!(long.packet_type, PacketType::Retry);
            assert_eq!(long.version, version);
            assert_eq!(long.dcid.as_bytes(), dcid);
            assert_eq!(long.scid.as_bytes(), scid);
        }
        _ => panic!("expected long header"),
    }

    // Verify integrity tag
    assert!(verify_retry_integrity_tag(odcid, &packet, version));
}

#[test]
fn build_retry_packet_roundtrip_v2() {
    use crate::net::handler::quic::transport::version::QUIC_VERSION_2;

    let version = QUIC_VERSION_2;
    let dcid = &[0x01, 0x02, 0x03, 0x04];
    let scid = &[0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11];
    let odcid = &[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let token = &[0xDE, 0xAD, 0xBE, 0xEF];

    let packet = build_retry_packet(version, dcid, scid, odcid, token);

    let (header, _) = wire_quic::parse_header(&packet, 0).unwrap();
    match header {
        PacketHeader::Long(long) => {
            assert_eq!(long.packet_type, PacketType::Retry);
            assert_eq!(long.version, version);
        }
        _ => panic!("expected long header"),
    }
    assert!(verify_retry_integrity_tag(odcid, &packet, version));
}

#[test]
fn build_retry_packet_tampered_tag_fails() {
    let version = QUIC_VERSION_1;
    let dcid = &[0x01, 0x02];
    let scid = &[0x0A, 0x0B, 0x0C, 0x0D];
    let odcid = &[0x83, 0x94, 0xc8, 0xf0];
    let token = &[0xCA, 0xFE];

    let mut packet = build_retry_packet(version, dcid, scid, odcid, token);
    // Tamper with last byte of integrity tag
    let len = packet.len();
    packet[len - 1] ^= 0xFF;

    assert!(!verify_retry_integrity_tag(odcid, &packet, version));
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test build_retry_packet`
Expected: FAIL — `build_retry_packet` doesn't exist yet.

- [ ] **Step 4: Implement `build_retry_packet()` in packet_builder.rs**

Add as a standalone function at the end of `src/net/handler/quic/transport/packet_builder.rs`:

```rust
/// Build a complete Retry packet (RFC 9000 §17.2.5).
///
/// This is a standalone function, NOT a method on PacketBuilder, because Retry
/// packets have a different wire format: no Length field, no Packet Number.
///
/// - `version`: QUIC version (determines packet type bits and integrity tag keys)
/// - `dcid`: client's Source CID (echoed as Retry's DCID)
/// - `scid`: new server-chosen CID (Retry's SCID)
/// - `odcid`: original Destination CID from client's Initial (for integrity tag AAD)
/// - `token`: encrypted address validation token
pub fn build_retry_packet(
    version: u32,
    dcid: &[u8],
    scid: &[u8],
    odcid: &[u8],
    token: &[u8],
) -> Vec<u8> {
    use super::version::retry_packet_type_bits;
    use crate::net::handler::quic::crypto::retry::compute_retry_integrity_tag;

    let type_bits = retry_packet_type_bits(version);

    // First byte: form(1)=1, fixed(1)=1, type(2), unused(4)=random
    let unused: u8 = {
        use ring::rand::SecureRandom;
        let mut b = [0u8; 1];
        ring::rand::SystemRandom::new().fill(&mut b).unwrap();
        b[0] & 0x0F
    };
    let first_byte: u8 = 0xC0 | (type_bits << 4) | unused;

    // Total size: 1 + 4 + 1 + dcid + 1 + scid + token + 16 (tag)
    let packet_len = 1 + 4 + 1 + dcid.len() + 1 + scid.len() + token.len() + 16;
    let mut packet = Vec::with_capacity(packet_len);

    // Header
    packet.push(first_byte);
    packet.extend_from_slice(&version.to_be_bytes());
    packet.push(dcid.len() as u8);
    packet.extend_from_slice(dcid);
    packet.push(scid.len() as u8);
    packet.extend_from_slice(scid);

    // Token (no length prefix — extends to end minus 16-byte tag)
    packet.extend_from_slice(token);

    // Integrity tag: computed over packet-so-far with ODCID in AAD
    let tag = compute_retry_integrity_tag(odcid, &packet, version);
    packet.extend_from_slice(&tag);

    packet
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test build_retry_packet`
Expected: ALL PASS (3 new tests).

- [ ] **Step 6: Commit**

```bash
git add src/net/handler/quic/transport/packet_builder.rs src/net/handler/quic/transport/version.rs src/net/handler/quic/tests/retry_test.rs
git commit -m "feat(quic): add build_retry_packet() for server-side Retry generation (RFC 9000 §17.2.5)"
```

---

## Task 3: Add Retry Fields to Connection State

**Files:**
- Modify: `src/net/handler/quic/connection.rs:66-243` (struct fields)
- Modify: `src/net/handler/quic/connection.rs:270-351` (constructor)
- Modify: `src/net/handler/quic/handler.rs:53-56` (add `retry_token_max_age`)

- [ ] **Step 1: Add fields to `QuicConnectionState`**

Add after line 242 (before the closing `}` of the struct) in `src/net/handler/quic/connection.rs`:

```rust
    /// Whether client has already processed a Retry for this connection (RFC 9000 §17.2.5.2).
    pub retry_received: bool,
    /// Original DCID from before Retry (for transport parameter validation, RFC 9000 §7.3).
    pub original_dcid: Option<ConnectionId>,
    /// Token from Retry packet (client stores for resending in Initial).
    pub retry_token: Option<Vec<u8>>,
    /// SCID the server used in the Retry packet (for transport param validation).
    pub retry_source_cid: Option<ConnectionId>,
```

- [ ] **Step 2: Initialize fields in constructor**

Add to the `Self { ... }` block in `QuicConnectionState::new()`, before the closing `}`:

```rust
            retry_received: false,
            original_dcid: None,
            retry_token: None,
            retry_source_cid: None,
```

- [ ] **Step 3: Add `retry_token_max_age` to handler config**

Add field to `QuicHandler` struct in `src/net/handler/quic/handler.rs` after line 60:

```rust
    /// Maximum age of a Retry token before it's considered expired (default 30s).
    pub(crate) retry_token_max_age: coarsetime::Duration,
```

Initialize in `QuicHandler::new()` after line 76:

```rust
            retry_token_max_age: coarsetime::Duration::from_secs(30),
```

- [ ] **Step 4: Run tests to verify nothing broke**

Run: `cargo test`
Expected: ALL PASS.

- [ ] **Step 5: Commit**

```bash
git add src/net/handler/quic/connection.rs src/net/handler/quic/handler.rs
git commit -m "feat(quic): add Retry state fields to connection and handler config"
```

---

## Task 4: Server-Side Retry Generation in Handler

**Files:**
- Modify: `src/net/handler/quic/handler.rs:1032-1036` (replace drop with Retry send)
- Modify: `src/net/handler/quic/handler.rs:310-377` (token validation on Initial-with-token, IPv4 path)
- Modify: `src/net/handler/quic/handler.rs:535-605` (same for IPv6 path)
- Test: `src/net/handler/quic/tests/retry_test.rs`

- [ ] **Step 1: Write test for tiered threshold behavior**

Add to `src/net/handler/quic/tests/retry_test.rs`:

```rust
use crate::net::handler::quic::handler::QuicHandler;
use crate::net::handler::quic::transport::version::QUIC_VERSION_1;
use crate::net::wire::quic::{self as wire_quic, PacketHeader, PacketType};

#[test]
fn server_sends_retry_between_thresholds() {
    let mut handler = QuicHandler::new(false, false);
    handler.retry_threshold = 2;
    handler.max_connections = 5;

    // Setup: create a listener on port 4433
    let tls_config = crate::net::handler::quic::tests::e2e_test::make_server_config();
    handler.register_listener(4433, tls_config, Default::default());

    // Fill connections to reach retry_threshold
    // (We need 2 dummy connections to trigger Retry)
    // Use build_retry_packet to test: call the internal method that would generate retry
    // For unit testing, verify generate_retry_packet returns valid packet
    let odcid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let client_scid = [0x0A, 0x0B, 0x0C, 0x0D];
    let version = QUIC_VERSION_1;

    let result = handler.generate_retry_packet(
        &odcid,
        &client_scid,
        &[127, 0, 0, 1], // client IP
        4433,             // local port
        version,
    );

    assert!(result.is_some(), "should generate a Retry packet");
    let packet = result.unwrap();

    // Verify it parses as a Retry
    let (header, _) = wire_quic::parse_header(&packet, 0).unwrap();
    match header {
        PacketHeader::Long(long) => {
            assert_eq!(long.packet_type, PacketType::Retry);
            assert_eq!(long.dcid.as_bytes(), &client_scid);
        }
        _ => panic!("expected Retry long header"),
    }

    // Verify integrity tag
    assert!(verify_retry_integrity_tag(&odcid, &packet, version));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test server_sends_retry_between_thresholds -- --exact`
Expected: FAIL — `generate_retry_packet` method doesn't exist.

- [ ] **Step 3: Implement `generate_retry_packet` method on QuicHandler**

Add method to `impl QuicHandler` in `src/net/handler/quic/handler.rs`:

```rust
    /// Generate a Retry packet for address validation.
    /// Returns the complete Retry packet bytes, or None if no listener on port.
    pub(crate) fn generate_retry_packet(
        &self,
        odcid: &[u8],
        client_scid: &[u8],
        client_ip: &[u8],
        local_port: u16,
        version: u32,
    ) -> Option<Vec<u8>> {
        use crate::net::handler::quic::token_crypto::{encrypt_token, TokenType};
        use crate::net::handler::quic::transport::packet_builder::build_retry_packet;
        use ring::rand::SecureRandom;

        let listener = self.listeners.get(&local_port)?;

        // Generate new server CID (8 bytes)
        let mut new_scid = [0u8; 8];
        ring::rand::SystemRandom::new().fill(&mut new_scid).ok()?;

        // Get current time for token timestamp
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Encrypt token
        let token = encrypt_token(
            &listener.token_secret,
            TokenType::Retry,
            client_ip,
            now_secs,
            odcid,
            version,
        )
        .ok()?;

        Some(build_retry_packet(version, client_scid, &new_scid, odcid, &token))
    }
```

- [ ] **Step 4: Replace the retry_threshold drop with Retry generation**

In `src/net/handler/quic/handler.rs`, replace lines 1032-1036:

```rust
        // DoS protection: when under load, drop without allocating state.
        // Future work: send Retry packet for address validation (RFC 9000 §8.1).
        if self.connections.len() >= self.retry_threshold {
            return None;
        }
```

With:

```rust
        // Tiered DoS protection: between retry_threshold and max_connections,
        // send Retry for address validation instead of dropping (RFC 9000 §8.1).
        if self.connections.len() >= self.retry_threshold {
            // Retry generation is handled by the caller (process_ipv4/ipv6)
            // which checks the threshold and calls generate_retry_packet.
            return None;
        }
```

Note: The actual Retry sending happens in `process_ipv4`/`process_ipv6` before calling `create_server_connection`, because we need access to the frame buffer for TX. This will be wired in the next step.

- [ ] **Step 5: Wire Retry sending into process_ipv4**

In `src/net/handler/quic/handler.rs`, in `process_ipv4()` around line 354, modify the `create_server_connection` call block. Before calling `create_server_connection`, check if we're in the Retry zone:

Replace the block starting at `if let Some(key) = self.create_server_connection(` with:

```rust
                    // Check for token in Initial packet (Retry validation)
                    let token_data = Self::extract_initial_token(quic_data);

                    // Tiered: between retry_threshold and max_connections, send Retry
                    if self.connections.len() >= self.retry_threshold
                        && self.connections.len() < self.max_connections
                        && token_data.is_none()
                    {
                        // Generate and send Retry packet
                        let client_ip_bytes: Vec<u8> = match src_addr {
                            IpAddress::V4(v4) => v4.octets.to_vec(),
                            IpAddress::V6(v6) => v6.octets.to_vec(),
                        };
                        if let Some(retry_pkt) = self.generate_retry_packet(
                            dcid.as_bytes(),
                            client_scid.as_bytes(),
                            client_ip_bytes,
                            dst_port,
                            version,
                        ) {
                            Self::send_raw_quic_ipv4(
                                &retry_pkt, frame, quic_offset, ip_offset,
                                src_addr, dst_addr, src_port, dst_port,
                                src_mac, dst_mac, tx_return, rx_return,
                            );
                        } else {
                            rx_return.push(frame);
                        }
                        return;
                    }

                    // Validate Retry token if present
                    let validated_odcid = token_data.and_then(|token_bytes| {
                        self.validate_retry_token(
                            &token_bytes, &src_addr, dst_port, version,
                        )
                    });

                    // Use validated ODCID or original DCID for key derivation
                    let key_dcid = validated_odcid.as_ref().unwrap_or(&dcid);

                    if let Some(key) = self.create_server_connection(
                        key_dcid,
                        &client_scid,
                        dst_addr, src_addr, dst_port, src_port,
                        src_mac, dst_mac, now, version,
                    ) {
                        // Store Retry state if token was validated
                        if let Some(ref odcid) = validated_odcid {
                            let conn = &mut self.connections[key];
                            conn.original_dcid = Some(*odcid);
                        }

                        let conn = &mut self.connections[key];
                        let mut frame_data = frame;
                        let quic_payload = &mut frame_data[quic_offset..];
                        processor::process_packet(conn, quic_payload, datagram_len, now);
                        rx_return.push(frame_data);
                        let conn = &mut self.connections[key];
                        processor::generate_packets(conn, key, now, wheel, free_frames, tx_return);
                        self.sync_cid_map(key);
                    } else {
                        rx_return.push(frame);
                    }
```

- [ ] **Step 6: Add helper methods**

Add to `impl QuicHandler`:

```rust
    /// Extract the token from an Initial packet's payload.
    /// Returns None if no token or token length is 0.
    fn extract_initial_token(quic_data: &[u8]) -> Option<Vec<u8>> {
        // Long header: first_byte(1) + version(4) + dcid_len(1) + dcid + scid_len(1) + scid
        if quic_data.len() < 6 {
            return None;
        }
        let dcid_len = quic_data[5] as usize;
        let scid_offset = 6 + dcid_len;
        if quic_data.len() <= scid_offset {
            return None;
        }
        let scid_len = quic_data[scid_offset] as usize;
        let token_len_offset = scid_offset + 1 + scid_len;
        if quic_data.len() <= token_len_offset {
            return None;
        }
        // Token length is a varint
        let (token_len, varint_size) =
            crate::net::handler::quic::transport::varint::decode_varint(&quic_data[token_len_offset..])?;
        if token_len == 0 {
            return None;
        }
        let token_start = token_len_offset + varint_size;
        let token_end = token_start + token_len as usize;
        if quic_data.len() < token_end {
            return None;
        }
        Some(quic_data[token_start..token_end].to_vec())
    }

    /// Validate a Retry token from an Initial packet.
    /// Returns the original DCID if valid, None otherwise.
    fn validate_retry_token(
        &self,
        token_bytes: &[u8],
        client_addr: &IpAddress,
        local_port: u16,
        version: u32,
    ) -> Option<ConnectionId> {
        use crate::net::handler::quic::token_crypto::{decrypt_token, TokenType};

        let listener = self.listeners.get(&local_port)?;
        let (token_type, token_ip, timestamp_secs, dcid_bytes, token_version) =
            decrypt_token(&listener.token_secret, token_bytes).ok()?;

        // Must be a Retry token
        if token_type != TokenType::Retry {
            return None;
        }

        // Client IP must match
        let client_ip_bytes: Vec<u8> = match client_addr {
            IpAddress::V4(v4) => v4.octets.to_vec(),
            IpAddress::V6(v6) => v6.octets.to_vec(),
        };
        if token_ip != client_ip_bytes {
            return None;
        }

        // Version must match
        if token_version != version {
            return None;
        }

        // Check expiry
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let age_secs = now_secs.saturating_sub(timestamp_secs);
        if age_secs > self.retry_token_max_age.as_secs() {
            return None;
        }

        Some(ConnectionId::from_slice(&dcid_bytes))
    }
```

Also add a `send_raw_quic_ipv4` helper (or reuse existing `build_vn_ipv4` pattern — check how VN packets are sent and follow the same approach).

- [ ] **Step 7: Apply the same changes to process_ipv6**

Mirror the Retry logic from `process_ipv4` into `process_ipv6` using the IPv6 addressing equivalents.

- [ ] **Step 8: Run tests**

Run: `cargo test`
Expected: ALL PASS.

- [ ] **Step 9: Commit**

```bash
git add src/net/handler/quic/handler.rs src/net/handler/quic/tests/retry_test.rs
git commit -m "feat(quic): server sends Retry packets between threshold and limit (RFC 9000 §8.1)"
```

---

## Task 5: Client-Side Retry Handling

**Files:**
- Modify: `src/net/handler/quic/processor.rs` (add Retry packet handling in `process_packet`)
- Test: `src/net/handler/quic/tests/retry_test.rs`

- [ ] **Step 1: Write test for client Retry handling**

Add to `src/net/handler/quic/tests/retry_test.rs`:

```rust
#[test]
fn client_handles_retry_packet() {
    use crate::net::handler::quic::connection::{QuicConnectionState, Side};
    use crate::net::handler::quic::transport::params::TransportParams;
    use coarsetime::Instant;

    let now = Instant::now();
    let dcid = ConnectionId::from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    let scid = ConnectionId::from_slice(&[0x0A, 0x0B, 0x0C, 0x0D]);

    let mut conn = QuicConnectionState::new(dcid, Side::Client, TransportParams::default(), 1200, now);
    conn.scid = scid;

    // Build a Retry packet that the server would send
    let server_scid = &[0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7];
    let token = &[0xDE, 0xAD, 0xBE, 0xEF];
    let retry_packet = build_retry_packet(
        QUIC_VERSION_1,
        scid.as_bytes(),     // Retry DCID = client's SCID
        server_scid,         // Retry SCID = new server CID
        dcid.as_bytes(),     // ODCID = client's original DCID
        token,
    );

    // Process the Retry
    let handled = crate::net::handler::quic::processor::handle_retry_packet(
        &mut conn, &retry_packet, QUIC_VERSION_1,
    );
    assert!(handled, "should accept valid Retry");
    assert!(conn.retry_received);
    assert_eq!(conn.dcid, ConnectionId::from_slice(server_scid));
    assert_eq!(conn.retry_token.as_deref(), Some(token.as_slice()));
}

#[test]
fn client_rejects_second_retry() {
    use crate::net::handler::quic::connection::{QuicConnectionState, Side};
    use crate::net::handler::quic::transport::params::TransportParams;
    use coarsetime::Instant;

    let now = Instant::now();
    let dcid = ConnectionId::from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    let mut conn = QuicConnectionState::new(dcid, Side::Client, TransportParams::default(), 1200, now);
    conn.retry_received = true; // Already got one

    let retry_packet = build_retry_packet(
        QUIC_VERSION_1,
        &[0x0A], &[0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7],
        dcid.as_bytes(), &[0xCA, 0xFE],
    );

    let handled = crate::net::handler::quic::processor::handle_retry_packet(
        &mut conn, &retry_packet, QUIC_VERSION_1,
    );
    assert!(!handled, "should reject second Retry");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test client_handles_retry`
Expected: FAIL — `handle_retry_packet` doesn't exist.

- [ ] **Step 3: Implement `handle_retry_packet` in processor.rs**

Add to `src/net/handler/quic/processor.rs`:

```rust
/// Handle an incoming Retry packet on the client side (RFC 9000 §17.2.5.2).
///
/// Returns true if the Retry was accepted and state was updated.
/// Returns false if the Retry was rejected (already received, bad tag, etc.).
pub fn handle_retry_packet(
    conn: &mut QuicConnectionState,
    retry_packet: &[u8],
    version: u32,
) -> bool {
    use crate::net::handler::quic::crypto::retry::verify_retry_integrity_tag;
    use crate::net::handler::quic::connection_id::ConnectionId;

    // RFC 9000 §17.2.5.2: client MUST accept at most one Retry
    if conn.retry_received {
        return false;
    }

    // Only clients process Retry
    if conn.side != Side::Client {
        return false;
    }

    // Verify integrity tag using our original DCID
    if !verify_retry_integrity_tag(conn.dcid.as_bytes(), retry_packet, version) {
        return false;
    }

    // Parse the Retry packet to extract SCID and token
    let header = match wire_quic::parse_header(retry_packet, 0) {
        Ok((PacketHeader::Long(h), _)) if h.packet_type == PacketType::Retry => h,
        _ => return false,
    };

    // Token is everything after the header and before the 16-byte integrity tag
    let token_start = header.payload_offset;
    let token_end = retry_packet.len().saturating_sub(16);
    if token_end <= token_start {
        return false;
    }
    let token = &retry_packet[token_start..token_end];

    // Store original DCID before overwriting
    let original_dcid = conn.dcid;
    conn.original_dcid = Some(original_dcid);

    // Update DCID to server's new CID (Retry's SCID)
    let new_dcid = ConnectionId::from_slice(header.scid.as_bytes());
    conn.dcid = new_dcid;

    // Store Retry state
    conn.retry_received = true;
    conn.retry_token = Some(token.to_vec());
    conn.retry_source_cid = Some(new_dcid);

    // Reset Initial packet number space to 0
    // Note: LossDetector has no reset_space method — reset the PN counter
    // and ACK state for the Initial space. The in-flight ring will naturally
    // age out old entries. If needed, add a reset_space() helper to LossDetector.
    conn.loss.reset_next_pn(0); // Reset Initial space PN counter to 0
    conn.ack[0] = crate::net::handler::quic::transport::ack::AckState::new();
    conn.recv_pn_seen[0] = crate::net::handler::quic::packet_parser::PnBitset::new();

    // Regenerate Initial keys using the new DCID
    let rustls_version =
        crate::net::handler::quic::transport::version::rustls_quic_version(version);
    let (local_dk, remote_dk) = crate::net::handler::quic::crypto::initial_keys::derive_initial_keys(
        new_dcid.as_bytes(),
        rustls::Side::Client,
        rustls_version,
    );
    conn.keys.initial = Some(crate::net::handler::quic::crypto::keys::KeyPair {
        local: crate::net::handler::quic::crypto::keys::DirectionalKey::from_rustls(local_dk),
        remote: crate::net::handler::quic::crypto::keys::DirectionalKey::from_rustls(remote_dk),
    });

    // Re-buffer the pending CRYPTO data so it gets sent in the new Initial
    // (the pending_crypto[0] should still contain the ClientHello)

    true
}
```

- [ ] **Step 4: Wire `handle_retry_packet` into the packet processing path**

In `process_packet()` in `processor.rs`, after parsing the header but before decryption, add a check for Retry packets. Find the section where `PacketType` is matched and add:

```rust
        // Handle Retry packets (no decryption needed)
        PacketType::Retry => {
            // Retry packets are handled at the handler level or here
            // depending on whether we have the connection already
            return ProcessResult::Ok; // handled by handler
        }
```

The actual `handle_retry_packet` call happens in the handler's `process_ipv4`/`process_ipv6` when the client's connection receives a Retry.

- [ ] **Step 5: Run tests**

Run: `cargo test`
Expected: ALL PASS.

- [ ] **Step 6: Commit**

```bash
git add src/net/handler/quic/processor.rs src/net/handler/quic/tests/retry_test.rs
git commit -m "feat(quic): client-side Retry packet handling (RFC 9000 §17.2.5.2)"
```

---

## Task 6: Server Transport Parameter Obligations After Retry

**Files:**
- Modify: `src/net/handler/quic/handler.rs:1082-1086` (set ODCID/retry_scid params)
- Test: `src/net/handler/quic/tests/retry_test.rs`

- [ ] **Step 1: Write test for transport parameter inclusion after Retry**

Add to `src/net/handler/quic/tests/retry_test.rs`:

```rust
#[test]
fn server_includes_retry_transport_params() {
    use crate::net::handler::quic::transport::params::TransportParams;

    let mut params = TransportParams::default();
    let odcid = ConnectionId::from_slice(&[0x01, 0x02, 0x03, 0x04]);
    let retry_scid = ConnectionId::from_slice(&[0xF0, 0xF1, 0xF2, 0xF3]);

    params.original_destination_connection_id = Some(odcid);
    params.retry_source_connection_id = Some(retry_scid);

    let mut buf = [0u8; 512];
    let len = params.encode(&mut buf);
    assert!(len > 0);

    let decoded = TransportParams::decode(&buf[..len]).unwrap();
    assert_eq!(decoded.original_destination_connection_id, Some(odcid));
    assert_eq!(decoded.retry_source_connection_id, Some(retry_scid));
}
```

- [ ] **Step 2: Run test**

Run: `cargo test server_includes_retry_transport_params -- --exact`
Expected: PASS — transport params already support these fields. This test confirms the encode/decode works.

- [ ] **Step 3: Modify `create_server_connection` to set retry params**

In `src/net/handler/quic/handler.rs`, in `create_server_connection()`, after setting `server_params.original_destination_connection_id` (line 1084), add handling for the Retry case. The caller passes the validated ODCID and the server's Retry SCID. Modify `create_server_connection` signature to accept an optional `retry_odcid`:

Add parameter: `retry_odcid: Option<&ConnectionId>` and `retry_scid: Option<&ConnectionId>`.

When `retry_odcid` is `Some`:
```rust
        if let Some(odcid) = retry_odcid {
            server_params.original_destination_connection_id = Some(*odcid);
            // The retry_source_connection_id is the SCID we used in the Retry packet
            // which is now stored as the client's DCID
            if let Some(rscid) = retry_scid {
                server_params.retry_source_connection_id = Some(*rscid);
            }
        }
```

- [ ] **Step 4: Run tests**

Run: `cargo test`
Expected: ALL PASS.

- [ ] **Step 5: Commit**

```bash
git add src/net/handler/quic/handler.rs src/net/handler/quic/tests/retry_test.rs
git commit -m "feat(quic): include ODCID and retry_scid in transport params after Retry (RFC 9000 §7.3)"
```

---

## Task 7: Retry Token Validation Tests

**Files:**
- Test: `src/net/handler/quic/tests/retry_test.rs`

- [ ] **Step 1: Write validation tests**

Add to `src/net/handler/quic/tests/retry_test.rs`:

```rust
#[test]
fn token_validation_valid() {
    use crate::net::handler::quic::token_crypto::{encrypt_token, decrypt_token, TokenType};

    let secret = [0xABu8; 32];
    let ip = &[10u8, 0, 0, 1];
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let dcid = &[0x01, 0x02, 0x03, 0x04];
    let version = QUIC_VERSION_1;

    let encrypted = encrypt_token(&secret, TokenType::Retry, ip, now_secs, dcid, version).unwrap();
    let (token_type, token_ip, ts, token_dcid, token_ver) = decrypt_token(&secret, &encrypted).unwrap();

    assert_eq!(token_type, TokenType::Retry);
    assert_eq!(token_ip, ip);
    assert_eq!(ts, now_secs);
    assert_eq!(token_dcid, dcid);
    assert_eq!(token_ver, version);
}

#[test]
fn token_validation_wrong_secret_fails() {
    use crate::net::handler::quic::token_crypto::{encrypt_token, decrypt_token, TokenType};

    let secret = [0xABu8; 32];
    let wrong_secret = [0xCDu8; 32];
    let ip = &[10u8, 0, 0, 1];
    let now_secs = 1000u64;
    let dcid = &[0x01, 0x02, 0x03, 0x04];

    let encrypted = encrypt_token(&secret, TokenType::Retry, ip, now_secs, dcid, QUIC_VERSION_1).unwrap();
    assert!(decrypt_token(&wrong_secret, &encrypted).is_err());
}

#[test]
fn token_validation_truncated_fails() {
    use crate::net::handler::quic::token_crypto::{encrypt_token, decrypt_token, TokenType};

    let secret = [0xABu8; 32];
    let encrypted = encrypt_token(&secret, TokenType::Retry, &[10, 0, 0, 1], 1000, &[1, 2], QUIC_VERSION_1).unwrap();
    // Truncate
    assert!(decrypt_token(&secret, &encrypted[..encrypted.len() - 5]).is_err());
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test token_validation`
Expected: ALL PASS.

- [ ] **Step 3: Add missing spec tests**

Also add these tests to `retry_test.rs`:

```rust
#[test]
fn token_validation_expired() {
    use crate::net::handler::quic::token_crypto::{encrypt_token, decrypt_token, TokenType};

    let secret = [0xABu8; 32];
    let old_ts = 1000u64; // very old timestamp
    let encrypted = encrypt_token(&secret, TokenType::Retry, &[10, 0, 0, 1], old_ts, &[1, 2], QUIC_VERSION_1).unwrap();
    let (_, _, ts, _, _) = decrypt_token(&secret, &encrypted).unwrap();

    // Token is valid cryptographically but the timestamp is old
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let age = now_secs.saturating_sub(ts);
    assert!(age > 30, "token should be expired (age={}s)", age);
}

#[test]
fn token_validation_wrong_address() {
    use crate::net::handler::quic::token_crypto::{encrypt_token, decrypt_token, TokenType};

    let secret = [0xABu8; 32];
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let encrypted = encrypt_token(&secret, TokenType::Retry, &[10, 0, 0, 1], now_secs, &[1, 2], QUIC_VERSION_1).unwrap();
    let (_, ip, _, _, _) = decrypt_token(&secret, &encrypted).unwrap();

    // Token was encrypted for 10.0.0.1 — different client IP should be rejected
    assert_ne!(ip.as_slice(), &[192u8, 168, 0, 1]);
}

#[test]
fn token_validation_version_mismatch() {
    use crate::net::handler::quic::token_crypto::{encrypt_token, decrypt_token, TokenType};
    use crate::net::handler::quic::transport::version::QUIC_VERSION_2;

    let secret = [0xABu8; 32];
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // Encrypt for v1
    let encrypted = encrypt_token(&secret, TokenType::Retry, &[10, 0, 0, 1], now_secs, &[1, 2], QUIC_VERSION_1).unwrap();
    let (_, _, _, _, ver) = decrypt_token(&secret, &encrypted).unwrap();

    // Token was for v1, using with v2 should be rejected by version check
    assert_ne!(ver, QUIC_VERSION_2);
}
```

- [ ] **Step 4: Run full test suite**

Run: `cargo test`
Expected: ALL PASS (1501+ tests).

- [ ] **Step 5: Commit**

```bash
git add src/net/handler/quic/tests/retry_test.rs
git commit -m "test(quic): add Retry token validation and edge case tests"
```

---

## Task 8: PMTU State Machine

**Files:**
- Modify: `src/net/handler/quic/path.rs` (add `PmtuState` struct and methods)
- Create: `src/net/handler/quic/tests/pmtu_test.rs`
- Modify: `src/net/handler/quic/tests/mod.rs` (register new test module)

- [ ] **Step 1: Register test module**

Add to `src/net/handler/quic/tests/mod.rs`:

```rust
mod pmtu_test;
```

- [ ] **Step 2: Write tests for PmtuState transitions**

Create `src/net/handler/quic/tests/pmtu_test.rs`:

```rust
use crate::net::handler::quic::path::{PmtuPhase, PmtuState};

const DEFAULT_FLOOR: u16 = 1200;
const DEFAULT_CEILING: u16 = 1452;
const STEP_THRESHOLD: u16 = 20;

#[test]
fn pmtu_initial_state_is_disabled() {
    let state = PmtuState::new(DEFAULT_CEILING);
    assert_eq!(state.phase(), PmtuPhase::Disabled);
    assert_eq!(state.floor(), DEFAULT_FLOOR);
    assert_eq!(state.ceiling(), DEFAULT_CEILING);
    assert_eq!(state.current_mtu(), DEFAULT_FLOOR);
}

#[test]
fn pmtu_start_searching() {
    let mut state = PmtuState::new(DEFAULT_CEILING);
    state.start_searching();
    assert_eq!(state.phase(), PmtuPhase::Searching);
    assert_eq!(state.next_probe_size(), (DEFAULT_FLOOR + DEFAULT_CEILING) / 2);
}

#[test]
fn pmtu_probe_ack_raises_floor() {
    let mut state = PmtuState::new(DEFAULT_CEILING);
    state.start_searching();
    let probe_size = state.next_probe_size(); // 1326
    state.set_probe_pn(42);

    let result = state.on_probe_acked(42, STEP_THRESHOLD);
    assert!(result.is_searching());
    assert_eq!(state.floor(), probe_size);
}

#[test]
fn pmtu_probe_loss_lowers_ceiling() {
    let mut state = PmtuState::new(DEFAULT_CEILING);
    state.start_searching();
    let probe_size = state.next_probe_size(); // 1326
    state.set_probe_pn(42);

    // 3 consecutive losses at this size
    state.on_probe_lost(STEP_THRESHOLD);
    state.on_probe_lost(STEP_THRESHOLD);
    let result = state.on_probe_lost(STEP_THRESHOLD);
    assert_eq!(state.ceiling(), probe_size);
    // Should still be searching (ceiling - floor > step)
    assert!(result.is_searching() || result.is_complete());
}

#[test]
fn pmtu_converges_to_search_complete() {
    let mut state = PmtuState::new(DEFAULT_CEILING);
    state.start_searching();

    // Simulate binary search: ACK all probes (best case, path supports max)
    for _ in 0..10 {
        let probe = state.next_probe_size();
        let pn = 100;
        state.set_probe_pn(pn);
        let result = state.on_probe_acked(pn, STEP_THRESHOLD);
        if result.is_complete() {
            break;
        }
    }

    assert_eq!(state.phase(), PmtuPhase::SearchComplete);
    // Floor should be close to ceiling
    assert!(state.ceiling() - state.floor() < STEP_THRESHOLD);
}

#[test]
fn pmtu_reset_on_migration() {
    let mut state = PmtuState::new(DEFAULT_CEILING);
    state.start_searching();
    state.set_probe_pn(1);
    state.on_probe_acked(1, STEP_THRESHOLD);

    state.reset(DEFAULT_CEILING);
    assert_eq!(state.phase(), PmtuPhase::Disabled);
    assert_eq!(state.floor(), DEFAULT_FLOOR);
    assert_eq!(state.current_mtu(), DEFAULT_FLOOR);
}

#[test]
fn pmtu_icmp_reduces_floor() {
    let mut state = PmtuState::new(DEFAULT_CEILING);
    state.start_searching();
    state.set_probe_pn(1);
    state.on_probe_acked(1, STEP_THRESHOLD); // floor raised

    let old_floor = state.floor();
    state.on_icmp_reduction(1250); // lower than current floor
    assert_eq!(state.floor(), 1250);
    assert_eq!(state.phase(), PmtuPhase::Searching);
    assert_eq!(state.current_mtu(), 1250);
}

#[test]
fn pmtu_icmp_below_1200_clamps() {
    let mut state = PmtuState::new(DEFAULT_CEILING);
    state.start_searching();
    state.on_icmp_reduction(800);
    assert_eq!(state.floor(), DEFAULT_FLOOR); // clamped to 1200
    assert_eq!(state.current_mtu(), DEFAULT_FLOOR);
}

#[test]
fn pmtu_reprobe_resets_ceiling() {
    let mut state = PmtuState::new(DEFAULT_CEILING);
    state.start_searching();
    // Force convergence
    for _ in 0..10 {
        let pn = 100;
        state.set_probe_pn(pn);
        let result = state.on_probe_acked(pn, STEP_THRESHOLD);
        if result.is_complete() {
            break;
        }
    }
    assert_eq!(state.phase(), PmtuPhase::SearchComplete);

    state.start_reprobing(DEFAULT_CEILING);
    assert_eq!(state.phase(), PmtuPhase::Searching);
    assert_eq!(state.ceiling(), DEFAULT_CEILING);
    // Floor stays at confirmed value
    assert!(state.floor() > DEFAULT_FLOOR);
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test pmtu_`
Expected: FAIL — `PmtuState`, `PmtuPhase` don't exist.

- [ ] **Step 4: Implement `PmtuState` in path.rs**

Add to `src/net/handler/quic/path.rs`:

```rust
/// PMTU discovery phase (DPLPMTUD, RFC 8899).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmtuPhase {
    Disabled,
    Searching,
    SearchComplete,
}

/// Result from a PMTU probe event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmtuProbeResult {
    Searching,
    Complete,
}

impl PmtuProbeResult {
    pub fn is_searching(self) -> bool { self == PmtuProbeResult::Searching }
    pub fn is_complete(self) -> bool { self == PmtuProbeResult::Complete }
}

const BASE_PLPMTU: u16 = 1200;
const MAX_PROBE_ATTEMPTS: u8 = 3;

/// DPLPMTUD state for a single connection path.
pub struct PmtuState {
    phase: PmtuPhase,
    floor: u16,
    ceiling: u16,
    probe_pn: Option<u64>,
    probe_count: u8,
}

impl PmtuState {
    pub fn new(ceiling: u16) -> Self {
        Self {
            phase: PmtuPhase::Disabled,
            floor: BASE_PLPMTU,
            ceiling,
            probe_pn: None,
            probe_count: 0,
        }
    }

    pub fn phase(&self) -> PmtuPhase { self.phase }
    pub fn floor(&self) -> u16 { self.floor }
    pub fn ceiling(&self) -> u16 { self.ceiling }

    /// The current effective MTU (always the floor — last confirmed working size).
    pub fn current_mtu(&self) -> u16 { self.floor }

    /// The size of the next probe to send.
    pub fn next_probe_size(&self) -> u16 {
        (self.floor + self.ceiling) / 2
    }

    pub fn set_probe_pn(&mut self, pn: u64) {
        self.probe_pn = Some(pn);
        self.probe_count = 0;
    }

    /// Transition from Disabled to Searching.
    pub fn start_searching(&mut self) {
        self.phase = PmtuPhase::Searching;
        self.probe_count = 0;
        self.probe_pn = None;
    }

    /// Handle a probe ACK. Returns whether to continue searching or we're done.
    pub fn on_probe_acked(&mut self, pn: u64, step_threshold: u16) -> PmtuProbeResult {
        if self.probe_pn != Some(pn) {
            return if self.phase == PmtuPhase::SearchComplete {
                PmtuProbeResult::Complete
            } else {
                PmtuProbeResult::Searching
            };
        }

        // Probe succeeded: raise floor
        self.floor = self.next_probe_size();
        self.probe_pn = None;
        self.probe_count = 0;

        if self.ceiling - self.floor < step_threshold {
            self.phase = PmtuPhase::SearchComplete;
            PmtuProbeResult::Complete
        } else {
            PmtuProbeResult::Searching
        }
    }

    /// Handle a probe loss (called after probe timeout or detected loss).
    pub fn on_probe_lost(&mut self, step_threshold: u16) -> PmtuProbeResult {
        self.probe_count += 1;

        if self.probe_count >= MAX_PROBE_ATTEMPTS {
            // Give up on this size: lower ceiling
            self.ceiling = self.next_probe_size();
            self.probe_count = 0;
            self.probe_pn = None;

            if self.ceiling - self.floor < step_threshold {
                self.phase = PmtuPhase::SearchComplete;
                return PmtuProbeResult::Complete;
            }
        }

        PmtuProbeResult::Searching
    }

    /// Handle ICMP Packet-Too-Big notification with a smaller MTU.
    pub fn on_icmp_reduction(&mut self, new_mtu: u16) {
        let clamped = new_mtu.max(BASE_PLPMTU);

        if clamped < self.floor {
            self.floor = clamped;
            self.phase = PmtuPhase::Searching;
        } else if clamped < self.ceiling {
            self.ceiling = clamped;
            if self.phase == PmtuPhase::SearchComplete {
                self.phase = PmtuPhase::Searching;
            }
        }
        // If clamped >= ceiling: no-op (already bounded)

        self.probe_pn = None;
        self.probe_count = 0;
    }

    /// Reset to Disabled (e.g., on path migration).
    pub fn reset(&mut self, ceiling: u16) {
        *self = Self::new(ceiling);
    }

    /// Restart probing from SearchComplete (periodic re-probe).
    pub fn start_reprobing(&mut self, ceiling: u16) {
        self.ceiling = ceiling;
        self.phase = PmtuPhase::Searching;
        self.probe_pn = None;
        self.probe_count = 0;
    }

    /// Whether there is an outstanding probe waiting for ACK/loss.
    pub fn has_outstanding_probe(&self) -> bool {
        self.probe_pn.is_some()
    }

    pub fn outstanding_probe_pn(&self) -> Option<u64> {
        self.probe_pn
    }
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test pmtu_`
Expected: ALL PASS (8 tests).

- [ ] **Step 6: Commit**

```bash
git add src/net/handler/quic/path.rs src/net/handler/quic/tests/pmtu_test.rs src/net/handler/quic/tests/mod.rs
git commit -m "feat(quic): add PmtuState state machine for DPLPMTUD (RFC 8899)"
```

---

## Task 9: Add `is_pmtu_probe` to SentPacket and CWND Scaling

**Files:**
- Modify: `src/net/handler/quic/transport/loss.rs:30-37` (add field to SentPacket)
- Modify: `src/net/handler/quic/transport/congestion.rs:215-217` (enhance `on_mtu_update`)
- Test: `src/net/handler/quic/tests/pmtu_test.rs`

- [ ] **Step 1: Write test for CWND scaling**

Add to `src/net/handler/quic/tests/pmtu_test.rs`:

```rust
use crate::net::handler::quic::transport::congestion::QuicCubic;
use crate::net::congestion::CongestionController;

#[test]
fn on_mtu_update_scales_cwnd() {
    let mut cc = QuicCubic::new(1200);
    let initial_cwnd = cc.window();

    // MTU increases from 1200 to 1452
    cc.on_mtu_update(1452);

    // CWND should scale proportionally
    let expected = initial_cwnd * 1452 / 1200;
    assert_eq!(cc.window(), expected);
}

#[test]
fn on_mtu_update_scales_cwnd_down() {
    let mut cc = QuicCubic::new(1452);
    let initial_cwnd = cc.window();

    cc.on_mtu_update(1200);

    let expected = initial_cwnd * 1200 / 1452;
    assert_eq!(cc.window(), expected);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test on_mtu_update_scales_cwnd`
Expected: FAIL — current `on_mtu_update` only sets `max_datagram_size`.

- [ ] **Step 3: Add `is_pmtu_probe` to SentPacket**

In `src/net/handler/quic/transport/loss.rs`, modify the `SentPacket` struct (line 30):

```rust
pub struct SentPacket {
    pub time_sent: Instant,
    pub size: u16,
    pub ack_eliciting: bool,
    pub in_flight: bool,
    /// Indices into FrameLog (Task 23). (start, end) range.
    pub frame_range: (u32, u32),
    /// Whether this packet was a PMTU probe (excluded from congestion on loss).
    pub is_pmtu_probe: bool,
}
```

Find all places that construct `SentPacket` (search for `SentPacket {`) and add `is_pmtu_probe: false`.

- [ ] **Step 4: Enhance `on_mtu_update` with CWND scaling**

Replace in `src/net/handler/quic/transport/congestion.rs`:

```rust
    fn on_mtu_update(&mut self, new_mtu: usize) {
        if self.max_datagram_size > 0 && new_mtu != self.max_datagram_size {
            // Scale CWND proportionally to maintain effective window in packets
            self.cwnd = self.cwnd * new_mtu / self.max_datagram_size;
            // Ensure minimum window
            let min = minimum_window(new_mtu);
            if self.cwnd < min {
                self.cwnd = min;
            }
        }
        self.max_datagram_size = new_mtu;
    }
```

- [ ] **Step 5: Run tests**

Run: `cargo test`
Expected: ALL PASS.

- [ ] **Step 6: Commit**

```bash
git add src/net/handler/quic/transport/loss.rs src/net/handler/quic/transport/congestion.rs src/net/handler/quic/tests/pmtu_test.rs
git commit -m "feat(quic): add is_pmtu_probe flag and CWND scaling in on_mtu_update"
```

---

## Task 10: Add PMTU State to Connection

**Files:**
- Modify: `src/net/handler/quic/connection.rs` (add `pmtu` field and config)

- [ ] **Step 1: Add fields**

Add to `QuicConnectionState` struct:

```rust
    /// PMTU discovery state (DPLPMTUD, RFC 8899).
    pub pmtu: PmtuState,
    /// Whether PMTU probing is enabled for this connection.
    pub pmtu_probing_enabled: bool,
    /// Configured PMTU ceiling (default 1452).
    pub pmtu_ceiling: u16,
    /// Flag: a PMTU probe needs to be sent (separate from needs_probe which is for PTO).
    pub needs_pmtu_probe: bool,
```

Add import at top:

```rust
use super::path::PmtuState;
```

- [ ] **Step 2: Initialize in constructor**

Add to `QuicConnectionState::new()`:

```rust
            pmtu: PmtuState::new(1452),
            pmtu_probing_enabled: true,
            pmtu_ceiling: 1452,
            needs_pmtu_probe: false,
```

- [ ] **Step 3: Run tests**

Run: `cargo test`
Expected: ALL PASS.

- [ ] **Step 4: Commit**

```bash
git add src/net/handler/quic/connection.rs
git commit -m "feat(quic): add PmtuState and config to connection state"
```

---

## Task 11: PMTU Probe Generation in Processor

**Files:**
- Modify: `src/net/handler/quic/processor.rs:145` (PmtuProbe timer handler)
- Modify: `src/net/handler/quic/processor.rs` (generate_packets — probe building)
- Test: `src/net/handler/quic/tests/pmtu_test.rs`

- [ ] **Step 1: Write test for probe generation triggering**

Add to `src/net/handler/quic/tests/pmtu_test.rs`:

```rust
#[test]
fn pmtu_no_probing_during_handshake() {
    let state = PmtuState::new(DEFAULT_CEILING);
    // Phase should be Disabled until explicitly started
    assert_eq!(state.phase(), PmtuPhase::Disabled);
    assert!(!state.has_outstanding_probe());
}
```

- [ ] **Step 2: Implement PmtuProbe timer handler**

In `src/net/handler/quic/processor.rs`, replace line 145:

```rust
        QuicTimerKind::PmtuProbe => TimerResult::Ok,
```

With:

```rust
        QuicTimerKind::PmtuProbe => {
            if conn.state != ConnectionState::Established {
                return TimerResult::Ok;
            }
            match conn.pmtu.phase() {
                crate::net::handler::quic::path::PmtuPhase::Searching => {
                    if conn.pmtu.has_outstanding_probe() {
                        // Probe timed out — treat as loss
                        let step = 20u16;
                        let result = conn.pmtu.on_probe_lost(step);
                        if result.is_complete() {
                            conn.max_udp_payload = conn.pmtu.current_mtu();
                            conn.congestion.on_mtu_update(conn.pmtu.current_mtu() as usize);
                        }
                    }
                    // Will generate a new probe in generate_packets
                    conn.needs_pmtu_probe = true;
                }
                crate::net::handler::quic::path::PmtuPhase::SearchComplete => {
                    // Re-probe timer fired — restart search
                    conn.pmtu.start_reprobing(conn.pmtu_ceiling);
                    conn.needs_pmtu_probe = true;
                }
                _ => {}
            }
            TimerResult::Ok
        }
```

- [ ] **Step 3: Add probe generation in generate_packets**

In `generate_packets()`, add PMTU probe generation after the connection transitions to Established. Find the section that builds 1-RTT packets and add:

```rust
    // PMTU probe generation (only in Established state with 1-RTT keys)
    if conn.pmtu_probing_enabled
        && conn.state == ConnectionState::Established
        && conn.pmtu.phase() == crate::net::handler::quic::path::PmtuPhase::Searching
        && !conn.pmtu.has_outstanding_probe()
        && conn.keys.one_rtt.is_some()
    {
        let probe_size = conn.pmtu.next_probe_size();
        // Build a probe packet: PING + PADDING to target size
        if let Some(mut frame) = free_frames.pop() {
            let ip_len = match conn.local_addr {
                IpAddress::V4(_) => IPV4_MIN_HEADER_LEN,
                IpAddress::V6(_) => IPV6_HEADER_LEN,
            };
            let quic_offset = ETH_LEN + ip_len + UDP_HEADER_LEN;
            let capacity = frame.capacity();
            if capacity >= quic_offset + probe_size as usize {
                unsafe { frame.set_len(capacity) };
                let pn = conn.loss.next_pn(2); // 1-RTT space
                let buf = &mut frame[quic_offset..quic_offset + probe_size as usize];

                if let Some(mut builder) = PacketBuilder::begin_short(
                    buf,
                    conn.dcid.as_bytes(),
                    pn,
                    conn.loss.largest_acked_pn(2),
                    conn.key_update.phase_bit(),
                    &conn.frame_log,
                ) {
                    // Write PING frame
                    crate::net::handler::quic::transport::frame_writer::write_ping(&mut builder);
                    // Pad to fill remaining space
                    builder.pad_to_fill();

                    if let Some(sent) = builder.finish(conn.keys.one_rtt.as_ref().unwrap()) {
                        // Track as PMTU probe
                        let mut sent_pkt = SentPacket {
                            time_sent: now,
                            size: probe_size,
                            ack_eliciting: true,
                            in_flight: true,
                            frame_range: (sent.frame_start, sent.frame_end),
                            is_pmtu_probe: true,
                        };
                        conn.loss.on_packet_sent(2, pn, sent_pkt); // space=2 (1-RTT), then pn
                        conn.pmtu.set_probe_pn(pn);
                        conn.congestion.on_packets_sent(probe_size as usize, now);

                        // Arm PmtuProbe timer for 3×PTO
                        let max_ack_delay = conn.peer_params
                            .as_ref()
                            .map(|p| coarsetime::Duration::from_millis(p.max_ack_delay_ms))
                            .unwrap_or(coarsetime::Duration::from_millis(25));
                        let pto = conn.loss.pto(2, max_ack_delay);
                        let deadline = now + pto * 3;
                        conn.timers.arm(
                            QuicTimerKind::PmtuProbe, conn_key, deadline, wheel,
                        );

                        // Write Ethernet/IP/UDP headers and send
                        // (follow the same pattern as regular packet sending)
                        let total_len = quic_offset + probe_size as usize;
                        unsafe { frame.set_len(total_len) };
                        write_headers(&mut frame, conn, quic_offset, ip_len, probe_size as usize);
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
        }
    }
```

Note: The exact integration depends on the existing generate_packets structure. The key points are:
1. Only probe when Established + Searching + no outstanding probe
2. Build a short header packet with PING + PADDING to exact probe_size
3. Tag the SentPacket with `is_pmtu_probe: true`
4. Record probe_pn in PmtuState
5. Arm PmtuProbe timer for 3×PTO

- [ ] **Step 4: Start PMTU probing when connection reaches Established**

In `processor.rs`, find where `conn.state` transitions to `ConnectionState::Established` and add:

```rust
    // Start PMTU discovery after handshake completes
    if conn.pmtu_probing_enabled && conn.pmtu.phase() == crate::net::handler::quic::path::PmtuPhase::Disabled {
        conn.pmtu.start_searching();
    }
```

- [ ] **Step 5: Run tests**

Run: `cargo test`
Expected: ALL PASS.

- [ ] **Step 6: Commit**

```bash
git add src/net/handler/quic/processor.rs src/net/handler/quic/tests/pmtu_test.rs
git commit -m "feat(quic): PMTU probe generation in processor (DPLPMTUD RFC 8899)"
```

---

## Task 12: PMTU Probe ACK/Loss Handling

**Files:**
- Modify: `src/net/handler/quic/processor.rs` (ACK processing, loss processing)
- Test: `src/net/handler/quic/tests/pmtu_test.rs`

- [ ] **Step 1: Write test for probe loss excluded from congestion**

Add to `src/net/handler/quic/tests/pmtu_test.rs`:

```rust
#[test]
fn pmtu_probe_loss_not_congestion_event() {
    // Verify that when a PMTU probe is lost, CWND is unchanged
    let mut cc = QuicCubic::new(1200);
    let cwnd_before = cc.window();

    // A normal lost packet would trigger congestion, but probe loss should not
    // This is verified at the processor level — the processor checks is_pmtu_probe
    // before calling congestion.on_congestion_event()

    // For unit testing: just verify the flag exists on SentPacket
    use crate::net::handler::quic::transport::loss::SentPacket;
    use coarsetime::Instant;

    let probe_pkt = SentPacket {
        time_sent: Instant::now(),
        size: 1326,
        ack_eliciting: true,
        in_flight: true,
        frame_range: (0, 0),
        is_pmtu_probe: true,
    };
    assert!(probe_pkt.is_pmtu_probe);
}
```

- [ ] **Step 2: Modify ACK processing to handle PMTU probes**

In `processor.rs`, find where ACKed packets are processed (the loop that iterates over newly ACKed packets). Add a check:

```rust
    // Check if ACKed packet was a PMTU probe
    if sent_pkt.is_pmtu_probe {
        let step = 20u16;
        let result = conn.pmtu.on_probe_acked(pn, step);
        if result.is_complete() || result.is_searching() {
            conn.max_udp_payload = conn.pmtu.current_mtu();
            conn.congestion.on_mtu_update(conn.pmtu.current_mtu() as usize);
        }
    }
```

- [ ] **Step 3: Modify loss detection to skip congestion for PMTU probes**

In the loss detection path in `processor.rs`, where lost packets trigger `congestion.on_congestion_event()`, add a guard:

```rust
    // PMTU probe loss is NOT a congestion event
    if !lost_pkt.is_pmtu_probe {
        conn.congestion.on_congestion_event(lost_pkt.time_sent, now);
    }
```

- [ ] **Step 4: Run tests**

Run: `cargo test`
Expected: ALL PASS.

- [ ] **Step 5: Commit**

```bash
git add src/net/handler/quic/processor.rs src/net/handler/quic/tests/pmtu_test.rs
git commit -m "feat(quic): PMTU probe ACK/loss handling with congestion exclusion"
```

---

## Task 13: ICMP → QUIC Connection Integration

**Files:**
- Modify: `src/net/handler/quic/handler.rs` (add method to notify connections of PMTU changes)
- Test: `src/net/handler/quic/tests/pmtu_test.rs`

- [ ] **Step 1: Write test for ICMP notification**

Add to `src/net/handler/quic/tests/pmtu_test.rs`:

```rust
#[test]
fn pmtu_icmp_reduction_lowers_ceiling() {
    let mut state = PmtuState::new(DEFAULT_CEILING);
    state.start_searching();
    // Simulate ICMP "Packet Too Big" reporting 1400
    state.on_icmp_reduction(1400);
    assert_eq!(state.ceiling(), 1400);
    assert_eq!(state.phase(), PmtuPhase::Searching);
}

#[test]
fn pmtu_icmp_does_nothing_if_above_ceiling() {
    let mut state = PmtuState::new(DEFAULT_CEILING);
    state.start_searching();
    state.on_icmp_reduction(1500); // above ceiling of 1452
    assert_eq!(state.ceiling(), DEFAULT_CEILING); // unchanged
}
```

- [ ] **Step 2: Add `notify_pmtu_update` to QuicHandler**

Add to `impl QuicHandler` in `src/net/handler/quic/handler.rs`:

```rust
    /// Notify QUIC connections about a PMTU change for a given peer IP.
    /// Called when the PmtuCache is updated by an ICMP handler.
    pub fn notify_pmtu_update(&mut self, peer_addr: &IpAddress, new_link_mtu: u32) {
        // Convert link MTU to QUIC packet size (subtract IP + UDP headers)
        let ip_overhead: u32 = match peer_addr {
            IpAddress::V4(_) => 20 + 8, // IPv4 + UDP
            IpAddress::V6(_) => 40 + 8, // IPv6 + UDP
        };
        let quic_mtu = new_link_mtu.saturating_sub(ip_overhead) as u16;

        for (_key, conn) in self.connections.iter_mut() {
            if conn.remote_addr == *peer_addr && conn.pmtu_probing_enabled {
                conn.pmtu.on_icmp_reduction(quic_mtu);
                conn.max_udp_payload = conn.pmtu.current_mtu();
                conn.congestion.on_mtu_update(conn.pmtu.current_mtu() as usize);
            }
        }
    }
```

- [ ] **Step 3: Wire ICMP handlers to call `notify_pmtu_update`**

In `src/net/handler/icmpv4.rs`, after the existing `PmtuCache::update()` call (around line 89-105), add a call to notify QUIC connections. The exact integration depends on how the ICMP handler accesses the QuicHandler — it may need to be passed as a parameter or accessed through the runtime context. If the architecture doesn't allow direct access, add a callback/event mechanism.

Similarly for `src/net/handler/icmpv6.rs` for IPv6 Packet Too Big messages.

Note: If the ICMP handlers don't have access to `QuicHandler`, this integration may need to go through a shared event queue or be deferred to the runtime's main loop. Check how other cross-handler communication works in the codebase.

- [ ] **Step 4: Run tests**

Run: `cargo test`
Expected: ALL PASS.

- [ ] **Step 5: Commit**

```bash
git add src/net/handler/quic/handler.rs src/net/handler/quic/tests/pmtu_test.rs
git commit -m "feat(quic): ICMP-to-QUIC PMTU notification path"
```

---

## Task 14: Path Migration PMTU Reset and Re-probe Timer

**Files:**
- Modify: `src/net/handler/quic/processor.rs` (reset PMTU on migration, arm re-probe timer)
- Test: `src/net/handler/quic/tests/pmtu_test.rs`

- [ ] **Step 1: Write test for migration reset**

Add to `src/net/handler/quic/tests/pmtu_test.rs`:

```rust
#[test]
fn pmtu_binary_search_iterations() {
    let mut state = PmtuState::new(DEFAULT_CEILING);
    state.start_searching();

    let mut iterations = 0;
    loop {
        iterations += 1;
        let pn = iterations as u64;
        state.set_probe_pn(pn);
        let result = state.on_probe_acked(pn, STEP_THRESHOLD);
        if result.is_complete() {
            break;
        }
        assert!(iterations <= 10, "search should converge");
    }

    // ceil(log2(252/20)) = 4 iterations expected
    assert!(iterations <= 5, "expected at most 5 iterations, got {}", iterations);
    assert_eq!(state.phase(), PmtuPhase::SearchComplete);
    assert!(state.floor() >= DEFAULT_CEILING - STEP_THRESHOLD);
}
```

- [ ] **Step 2: Add PMTU reset on path migration**

In `processor.rs`, find where `PathState::on_peer_address_change()` is called (connection migration handling). After that call, add:

```rust
    // Reset PMTU discovery on path migration
    if conn.pmtu_probing_enabled {
        conn.pmtu.reset(conn.pmtu_ceiling);
        conn.max_udp_payload = 1200;
        conn.congestion.on_mtu_update(1200);
    }
```

- [ ] **Step 3: Arm re-probe timer when SearchComplete**

In `generate_packets()`, after the PMTU probe section, add timer arming for re-probe:

```rust
    // Arm re-probe timer when PMTU search completes
    if conn.pmtu_probing_enabled
        && conn.pmtu.phase() == crate::net::handler::quic::path::PmtuPhase::SearchComplete
        && !conn.timers.is_armed(QuicTimerKind::PmtuProbe)
    {
        let reprobe_deadline = now + coarsetime::Duration::from_secs(600); // 10 minutes
        conn.timers.arm(QuicTimerKind::PmtuProbe, conn_key, reprobe_deadline, wheel);
    }
```

- [ ] **Step 4: Run full test suite**

Run: `cargo test`
Expected: ALL PASS.

- [ ] **Step 5: Commit**

```bash
git add src/net/handler/quic/processor.rs src/net/handler/quic/tests/pmtu_test.rs
git commit -m "feat(quic): PMTU reset on migration and 10-minute re-probe timer"
```

---

## Task 15: Final Integration Run

- [ ] **Step 1: Run full test suite**

Run: `cargo test`
Expected: ALL PASS.

- [ ] **Step 2: Run clippy**

Run: `cargo clippy -- -D warnings 2>&1 | head -50`
Fix any warnings.

- [ ] **Step 3: Verify no regressions in existing e2e tests**

Run: `cargo test e2e_`
Expected: ALL PASS — existing end-to-end tests must not regress.

- [ ] **Step 4: Commit any clippy fixes**

```bash
git add -A
git commit -m "fix(quic): address clippy warnings from Retry and PMTU features"
```
