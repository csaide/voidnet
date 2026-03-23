use coarsetime::Instant;

use crate::net::congestion::CongestionController;
use crate::net::handler::quic::connection::{ConnectionState, QuicConnectionState, Side};
use crate::net::handler::quic::crypto::packet_protection::{
    decrypt_payload, protect_packet, unprotect_header,
};
use crate::net::handler::quic::error::TransportError;
use crate::net::handler::quic::packet_parser::{self, packet_space};
use crate::net::handler::quic::timer_kinds::QuicTimerKind;
use crate::net::handler::quic::transport::ack::AckState;
use crate::net::handler::quic::transport::congestion::QuicCubic;
use crate::net::handler::quic::transport::frame::{self, QuicFrame, StreamId};
use crate::net::handler::quic::transport::loss::SentPacket;
use crate::net::handler::quic::transport::packet_builder::PacketBuilder;
use crate::net::handler::quic::transport::packet_number::decode_pn;
use crate::net::handler::quic::transport::retransmit::build_retransmit_queue;
use crate::net::timer_wheel::TimerWheel;
use crate::net::wire::ethernet::{EtherTypes, EthernetFrame, write_ethernet_header};
use crate::net::wire::ip::{
    IPV4_MIN_HEADER_LEN, IPV6_HEADER_LEN, IpAddress, IpProtocols, Ipv4Header,
};
use crate::net::wire::quic::{self as wire_quic, PacketHeader, PacketType};
use crate::net::wire::udp::{UDP_HEADER_LEN, UdpHeader};
use crate::xdp::frame::{Frame, FrameBuffer};

pub enum ProcessResult {
    Ok,
    ConnectionClosed,
    VersionNegotiation,
    StatelessReset,
}

/// Result returned by `handle_timeout`.
pub enum TimerResult {
    /// Connection should continue.
    Ok,
    /// Handler should remove the connection.
    Close,
}

/// Handle a timer expiry. Marks pending state — does NOT generate packets directly.
/// Packet generation happens in poll_send → generate_packets.
pub fn handle_timeout(
    conn: &mut QuicConnectionState,
    kind: QuicTimerKind,
    now: Instant,
) -> TimerResult {
    match kind {
        QuicTimerKind::LossDetection => {
            let max_ack_delay = conn
                .peer_params
                .as_ref()
                .map(|p| coarsetime::Duration::from_millis(p.max_ack_delay_ms))
                .unwrap_or(coarsetime::Duration::from_millis(25));
            let result = conn.loss.on_loss_detection_timeout(now, max_ack_delay);
            match result {
                crate::net::handler::quic::transport::loss::LossDetectionResult::LostPackets(
                    lost,
                ) => {
                    let frame_ranges: smallvec::SmallVec<[(u32, u32); 8]> =
                        lost.iter().map(|(_, pkt)| pkt.frame_range).collect();
                    // Single congestion event per loss round (Fix 10)
                    if let Some(max_sent_time) = lost.iter().map(|(_, pkt)| pkt.time_sent).max() {
                        let total_lost_bytes: usize =
                            lost.iter().map(|(_, pkt)| pkt.size as usize).sum();
                        conn.congestion
                            .on_congestion_event(total_lost_bytes, now, max_sent_time);
                    }
                    let retransmit = build_retransmit_queue(&conn.frame_log, &frame_ranges);
                    // Rewind crypto_offset for CRYPTO retransmission
                    for &(retx_space, retx_offset, _) in &retransmit.crypto {
                        conn.crypto_offset[retx_space as usize] =
                            conn.crypto_offset[retx_space as usize].min(retx_offset);
                    }
                    // Insert retransmit ranges for lost stream data
                    for &(stream_id, retx_offset, retx_len, _) in &retransmit.streams {
                        if let Some(entry) = conn.streams.get_mut(stream_id)
                            && let Some(ref mut send) = entry.send
                        {
                            send.add_retransmit_range(retx_offset, retx_offset + retx_len as u64);
                        }
                    }
                    if retransmit.handshake_done {
                        conn.retransmit.handshake_done = true;
                    }
                    if retransmit.max_data {
                        conn.retransmit.max_data = true;
                    }
                }
                crate::net::handler::quic::transport::loss::LossDetectionResult::SendProbe {
                    space: _,
                } => {
                    conn.needs_probe = true;
                }
                crate::net::handler::quic::transport::loss::LossDetectionResult::None => {}
            }
            conn.timer_needs_rearm = true;
            TimerResult::Ok
        }
        QuicTimerKind::Idle => TimerResult::Close,
        QuicTimerKind::Ack => {
            // Force ACK in next poll_send
            for ack in &mut conn.ack {
                if ack.needs_ack() {
                    ack.set_ack_eliciting();
                }
            }
            TimerResult::Ok
        }
        QuicTimerKind::Draining => TimerResult::Close,
        QuicTimerKind::KeyDiscard => {
            // Discard previous remote packet key after 3×PTO (RFC 9001 §6.5)
            conn.key_update.prev_remote_packet_key = None;
            TimerResult::Ok
        }
        QuicTimerKind::PathValidation => {
            if !conn.path.validated {
                if let Some(prev) = conn.prev_path.take() {
                    conn.remote_addr = prev.remote_addr;
                    conn.remote_port = prev.remote_port;
                    conn.remote_mac = prev.remote_mac;
                    conn.path = prev.path;
                } else {
                    // No previous path to revert to — close
                    conn.close_error = Some(TransportError::INTERNAL_ERROR);
                    conn.state = ConnectionState::Closing;
                    conn.needs_draining_timer = true;
                }
            }
            TimerResult::Ok
        }
        QuicTimerKind::Handshake => {
            if conn.state == ConnectionState::Handshaking {
                // RFC 9000 §10: transition through Closing→Draining, not directly to Closed.
                // If we have no keys to send CONNECTION_CLOSE, the draining timer
                // will eventually close the connection.
                conn.close_error = Some(TransportError::INTERNAL_ERROR);
                conn.state = ConnectionState::Closing;
                conn.needs_draining_timer = true;
                return TimerResult::Ok;
            }
            TimerResult::Ok
        }
        QuicTimerKind::PmtuProbe => TimerResult::Ok,
    }
}

/// Process QUIC packets from a UDP datagram (RFC 9000 §12.2: coalesced packets).
/// `quic_payload` is the raw QUIC bytes AFTER the UDP header. MUTABLE for in-place decrypt.
/// `datagram_len` is the total UDP datagram size (for amplification tracking).
pub fn process_packet(
    conn: &mut QuicConnectionState,
    quic_payload: &mut [u8],
    datagram_len: usize,
    now: Instant,
) -> ProcessResult {
    // RFC 9000 §10.2.1: In Closing state, retransmit CONNECTION_CLOSE on incoming packets.
    // Rate-limit to at most once per PTO (RFC 9000 §10.2.1 SHOULD limit rate).
    if conn.state == ConnectionState::Closing {
        let should_retransmit = match conn.last_close_sent {
            None => true,
            Some(last) => {
                let max_ack_delay = conn
                    .peer_params
                    .as_ref()
                    .map(|p| coarsetime::Duration::from_millis(p.max_ack_delay_ms))
                    .unwrap_or(coarsetime::Duration::from_millis(25));
                let pto = conn.loss.pto(2, max_ack_delay);
                now.duration_since(last) >= pto
            }
        };
        if should_retransmit {
            conn.closing_frame_sent = false; // trigger re-send in generate_packets
        }
        return ProcessResult::Ok;
    }

    let mut offset = 0;
    let mut last_result = ProcessResult::Ok;

    while offset < quic_payload.len() {
        let remaining = &quic_payload[offset..];
        if remaining.is_empty() {
            break;
        }

        // For short headers, the DCID in the incoming packet is OUR SCID
        let short_dcid_len = conn.scid.len();

        let parse_result = {
            let (header, _header_len) = match wire_quic::parse_header(remaining, short_dcid_len) {
                Ok(h) => h,
                Err(_) => break, // unparseable, stop processing
            };

            match header {
                PacketHeader::Long(long) => {
                    let space = match packet_space(long.packet_type) {
                        Some(s) => s,
                        None => break,
                    };
                    if long.packet_type == PacketType::Initial {
                        match packet_parser::parse_initial_fields(&remaining[long.payload_offset..])
                        {
                            Some((_token, payload_length, relative_pn_offset)) => {
                                let pn_offset = long.payload_offset + relative_pn_offset;
                                // Total packet = everything up to pn_offset + payload_length
                                let packet_len = pn_offset + payload_length;
                                Some((space, pn_offset, packet_len))
                            }
                            None => None,
                        }
                    } else if long.packet_type == PacketType::Handshake {
                        match crate::net::handler::quic::transport::varint::decode_varint(
                            &remaining[long.payload_offset..],
                        ) {
                            Some((length, consumed)) => {
                                let pn_offset = long.payload_offset + consumed;
                                let packet_len = pn_offset + length as usize;
                                Some((space, pn_offset, packet_len))
                            }
                            None => None,
                        }
                    } else if long.packet_type == PacketType::ZeroRtt {
                        // 0-RTT: same length-prefixed format as Handshake (RFC 9000 §17.2)
                        match crate::net::handler::quic::transport::varint::decode_varint(
                            &remaining[long.payload_offset..],
                        ) {
                            Some((length, consumed)) => {
                                let pn_offset = long.payload_offset + consumed;
                                let packet_len = pn_offset + length as usize;
                                if conn.keys.zero_rtt_open.is_some() {
                                    Some((space, pn_offset, packet_len))
                                } else {
                                    conn.zero_rtt_rejected += 1;
                                    None
                                }
                            }
                            None => None,
                        }
                    } else {
                        conn.zero_rtt_rejected += 1;
                        None
                    }
                }
                PacketHeader::Short(short) => {
                    // Short header is always the last packet in a datagram
                    Some((2, short.pn_offset, remaining.len()))
                }
                PacketHeader::VersionNegotiation(vn) => {
                    // RFC 9000 §6.2: client processes VN from server
                    if conn.side == Side::Client && conn.state == ConnectionState::Handshaking {
                        // Find a supported version different from current
                        let mut negotiated_version: Option<u32> = None;
                        let mut i = 0;
                        while i + 4 <= vn.versions.len() {
                            let v = u32::from_be_bytes([
                                vn.versions[i],
                                vn.versions[i + 1],
                                vn.versions[i + 2],
                                vn.versions[i + 3],
                            ]);
                            if crate::net::handler::quic::transport::version::is_supported_version(
                                v,
                            ) && v != conn.version
                            {
                                negotiated_version = Some(v);
                                break;
                            }
                            i += 4;
                        }

                        match negotiated_version {
                            None => {
                                // No compatible version — close
                                conn.state = ConnectionState::Closed;
                                last_result = ProcessResult::VersionNegotiation;
                            }
                            Some(new_version) => {
                                use crate::net::handler::quic::crypto::initial_keys::derive_initial_keys;
                                use crate::net::handler::quic::crypto::keys::{
                                    DirectionalKey, KeyPair,
                                };
                                use crate::net::handler::quic::crypto::tls::CryptoState;
                                use crate::net::handler::quic::transport::ack::AckState;
                                use crate::net::handler::quic::transport::loss::LossDetector;
                                use crate::net::handler::quic::transport::version::QUIC_VERSION_2;

                                // Store original version and switch to negotiated
                                conn.original_version = Some(conn.version);
                                conn.version = new_version;

                                let rustls_version = if new_version == QUIC_VERSION_2 {
                                    rustls::quic::Version::V2
                                } else {
                                    rustls::quic::Version::V1
                                };

                                // Create fresh TLS client connection with negotiated version
                                if let (Some(config), Some(server_name)) =
                                    (conn.client_config.as_ref(), conn.server_name.as_ref())
                                {
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
                                            // Re-derive initial keys for negotiated version
                                            let (local_dk, remote_dk) = derive_initial_keys(
                                                conn.dcid.as_bytes(),
                                                rustls::Side::Client,
                                                rustls_version,
                                            );
                                            conn.keys.initial = Some(KeyPair {
                                                local: DirectionalKey::from_rustls(local_dk),
                                                remote: DirectionalKey::from_rustls(remote_dk),
                                            });
                                            // Reset crypto and ack state for fresh handshake
                                            conn.pending_crypto =
                                                [initial_data, Vec::new(), Vec::new()];
                                            conn.crypto_offset = [0; 3];
                                            conn.crypto_acked = [0; 3];
                                            conn.ack =
                                                [AckState::new(), AckState::new(), AckState::new()];
                                            conn.loss = LossDetector::new();
                                        }
                                        Err(_) => {
                                            conn.state = ConnectionState::Closed;
                                            last_result = ProcessResult::VersionNegotiation;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    None
                }
            }
        };

        let (space, pn_offset, packet_len) = match parse_result {
            Some(r) => r,
            None => break,
        };

        // Ensure packet_len doesn't exceed remaining data
        let packet_len = packet_len.min(quic_payload.len() - offset);

        let result = decrypt_and_process(
            conn,
            &mut quic_payload[offset..offset + packet_len],
            space,
            pn_offset,
            datagram_len,
            now,
        );

        match result {
            ProcessResult::ConnectionClosed => return ProcessResult::ConnectionClosed,
            _ => last_result = result,
        }

        offset += packet_len;
    }

    last_result
}

fn decrypt_and_process(
    conn: &mut QuicConnectionState,
    quic_payload: &mut [u8],
    space: usize,
    pn_offset: usize,
    datagram_len: usize,
    now: Instant,
) -> ProcessResult {
    // Select decrypt key for the space
    let remote_key = match space {
        0 => conn.keys.initial.as_ref().map(|kp| &kp.remote),
        1 => conn.keys.handshake.as_ref().map(|kp| &kp.remote),
        2 => conn
            .keys
            .one_rtt
            .as_ref()
            .map(|kp| &kp.remote)
            .or(conn.keys.zero_rtt_open.as_ref()),
        _ => None,
    };
    let remote_key = match remote_key {
        Some(k) => k,
        None => {
            return ProcessResult::Ok;
        }
    };

    // Unprotect header (removes header protection, decodes truncated PN)
    let (truncated_pn, pn_length, payload_offset) =
        match unprotect_header(remote_key, quic_payload, pn_offset) {
            Ok(r) => r,
            Err(_) => {
                return ProcessResult::Ok;
            }
        };

    // Reconstruct full PN
    let largest_acked = conn.ack[space].largest_received().unwrap_or(0);
    let pn = decode_pn(largest_acked, truncated_pn, (pn_length * 8) as u32);

    // NOTE: Duplicate PN check is intentionally AFTER decryption (see below)
    // to avoid timing side channels per RFC 9001 §9.5.

    // Decrypt payload — need copy for AAD (header bytes before payload).
    // Max QUIC header: 1 + 4 + 1 + 20(DCID) + 1 + 20(SCID) + varint + token(≤255) + varint + 4(PN) ≈ 310.
    // 256 covers all practical cases; Initial with max-length token could exceed,
    // but tokens >200 bytes are pathological.
    let mut header_buf = [0u8; 256];
    let header_len = payload_offset.min(256);
    header_buf[..header_len].copy_from_slice(&quic_payload[..header_len]);

    // For 1-RTT packets, save encrypted payload in case we need to retry with previous key
    // after a key update (RFC 9001 §6.1: retain old keys for reordered packets).
    let payload_slice = &quic_payload[payload_offset..];
    let saved_payload = if space == 2 && conn.key_update.prev_remote_packet_key.is_some() {
        Some(payload_slice.to_vec())
    } else {
        None
    };

    let plaintext_len = match decrypt_payload(
        remote_key,
        pn,
        &header_buf[..header_len],
        &mut quic_payload[payload_offset..],
    ) {
        Ok(len) => len,
        Err(_) => {
            // Current key failed. For 1-RTT, try previous key if available (RFC 9001 §6.5).
            if let Some(ref saved) = saved_payload {
                if let Some(ref prev_key) = conn.key_update.prev_remote_packet_key {
                    // Restore the encrypted payload for retry
                    quic_payload[payload_offset..payload_offset + saved.len()]
                        .copy_from_slice(saved);
                    match prev_key.decrypt_in_place(
                        pn,
                        &header_buf[..header_len],
                        &mut quic_payload[payload_offset..payload_offset + saved.len()],
                    ) {
                        Ok(plaintext) => plaintext.len(),
                        Err(_) => {
                            // Both keys failed — genuine authentication failure
                            conn.failed_decryptions += 1;
                            let limits = conn.aead_limits;
                            if limits.must_close(conn.failed_decryptions) {
                                conn.close_error = Some(TransportError::AEAD_LIMIT_REACHED);
                                conn.state = ConnectionState::Closing;
                                conn.needs_draining_timer = true;
                                return ProcessResult::ConnectionClosed;
                            }
                            return ProcessResult::Ok;
                        }
                    }
                } else {
                    conn.failed_decryptions += 1;
                    let limits = conn.aead_limits;
                    if limits.must_close(conn.failed_decryptions) {
                        conn.close_error = Some(TransportError::AEAD_LIMIT_REACHED);
                        conn.state = ConnectionState::Closing;
                        conn.needs_draining_timer = true;
                        return ProcessResult::ConnectionClosed;
                    }
                    return ProcessResult::Ok;
                }
            } else {
                conn.failed_decryptions += 1;
                let limits = conn.aead_limits;
                if limits.must_close(conn.failed_decryptions) {
                    conn.close_error = Some(TransportError::AEAD_LIMIT_REACHED);
                    conn.state = ConnectionState::Closing;
                    conn.needs_draining_timer = true;
                    return ProcessResult::ConnectionClosed;
                }
                return ProcessResult::Ok;
            }
        }
    };

    // Track 0-RTT acceptance for observability
    if space == 2 && conn.keys.one_rtt.is_none() && conn.keys.zero_rtt_open.is_some() {
        conn.zero_rtt_accepted += 1;
    }

    // RFC 9001 §9.5: Duplicate PN check AFTER decryption to avoid timing side channels.
    // "the entire process of header protection removal, packet number recovery, and
    // packet protection removal MUST be applied together without timing and other side channels."
    if conn.recv_pn_seen[space].is_duplicate(pn) {
        return ProcessResult::Ok;
    }

    // Mark PN as seen
    conn.recv_pn_seen[space].mark(pn);

    // Detect peer-initiated key update (RFC 9001 §6.2)
    if space == 2 {
        // key_phase bit is bit 2 (0x04) of first byte after header protection removal
        let received_key_phase = (quic_payload[0] & 0x04) != 0;
        if conn.key_update.is_peer_update(received_key_phase) {
            // Peer initiated key update — derive new keys
            if let Some(ref mut secrets) = conn.key_update_secrets {
                let new_keys = secrets.next_packet_keys();
                // Retain old remote packet key for reordered packets (RFC 9001 §6.1).
                // Header protection keys are unchanged by key updates (RFC 9001 §5.4),
                // so we only need to save the old packet key. We swap it out via
                // update_packet_key which replaces it in-place.
                if let Some(ref mut kp) = conn.keys.one_rtt {
                    let old_remote_pkt_key =
                        std::mem::replace(&mut kp.remote.packet_key, new_keys.remote);
                    conn.key_update.prev_remote_packet_key = Some(old_remote_pkt_key);
                    kp.local.update_packet_key(new_keys.local);
                }
                conn.key_update.on_update_initiated();
                conn.packets_encrypted[2] = 0;
                conn.needs_key_discard_timer = true;
            }
        }
    }

    // Update amplification tracking (Fix 13: check if we were at limit before receiving)
    let was_at_limit = !conn.path.amplification.can_send(1);
    conn.path.amplification.on_bytes_received(datagram_len);
    if was_at_limit && conn.path.amplification.can_send(1) {
        // Unblocked from anti-amplification limit — caller will generate_packets
    }

    // Update last activity time for idle timeout tracking (Fix 8)
    conn.last_activity = now;

    // Parse and dispatch frames
    let plaintext = &quic_payload[payload_offset..payload_offset + plaintext_len];
    let mut ack_eliciting = false;

    let result = dispatch_frames(conn, plaintext, space, &mut ack_eliciting, now);

    // Post-processing
    conn.ack[space].on_packet_received(pn, now);
    if ack_eliciting {
        conn.ack[space].set_ack_eliciting();
    }

    // Key discard transitions (RFC 9001 §4.9.2).
    // Initial keys: discard after first Handshake packet processed.
    if space == 1 && conn.keys.initial.is_some() {
        conn.keys.initial = None;
        conn.loss.discard_space(0);
    }
    // Handshake keys: mark for deferred discard when we receive a 1-RTT packet
    // (confirms client got the handshake). Don't discard immediately — we may
    // still need to send a Handshake ACK for the client's Finished. The actual
    // discard happens in generate_packets after the ACK is sent.
    if space == 2 && conn.keys.handshake.is_some() {
        conn.handshake_keys_pending_discard = true;
    }

    result
}

fn dispatch_frames(
    conn: &mut QuicConnectionState,
    plaintext: &[u8],
    space: usize,
    ack_eliciting: &mut bool,
    now: Instant,
) -> ProcessResult {
    let mut offset = 0;
    while offset < plaintext.len() {
        let (frame, consumed) = match frame::parse_frame(&plaintext[offset..]) {
            Ok(r) => r,
            Err(_) => {
                conn.close_error = Some(TransportError::FRAME_ENCODING_ERROR);
                conn.state = ConnectionState::Closing;
                conn.needs_draining_timer = true;
                return ProcessResult::ConnectionClosed;
            }
        };
        offset += consumed;

        // Frame type restriction validation (RFC 9000 §12.4)
        if space <= 1 {
            // Initial or Handshake: only PADDING, PING, ACK, CRYPTO, CONNECTION_CLOSE(0x1c)
            match &frame {
                QuicFrame::Padding | QuicFrame::Ping | QuicFrame::Ack(_) | QuicFrame::Crypto(_) => {
                }
                QuicFrame::ConnectionClose(cc) if cc.frame_type.is_some() => {
                    // type 0x1c has frame_type field (transport close) — allowed
                }
                _ => {
                    conn.close_error = Some(TransportError::PROTOCOL_VIOLATION);
                    conn.state = ConnectionState::Closing;
                    conn.needs_draining_timer = true;
                    return ProcessResult::ConnectionClosed;
                }
            }
        }

        // Track ack-eliciting
        match &frame {
            QuicFrame::Padding | QuicFrame::Ack(_) => {}
            _ => *ack_eliciting = true,
        }

        match frame {
            QuicFrame::Padding => {}
            QuicFrame::Ping => {} // ack-eliciting handled above

            QuicFrame::Crypto(crypto) => {
                handle_crypto_frame(conn, space, crypto.offset, crypto.data, now);
            }

            QuicFrame::Ack(ack) => {
                handle_ack_frame(conn, space, &ack, now);
            }

            QuicFrame::Stream(stream) => {
                if let Some(err) = handle_stream_frame(
                    conn,
                    stream.stream_id,
                    stream.offset,
                    stream.data,
                    stream.fin,
                ) {
                    conn.close_error = Some(err);
                    conn.state = ConnectionState::Closing;
                    conn.needs_draining_timer = true;
                    return ProcessResult::ConnectionClosed;
                }
            }

            QuicFrame::MaxData(max) => {
                conn.flow.update_max_data_send(max);
            }

            QuicFrame::MaxStreamData { stream_id, max } => {
                if let Ok(entry) = conn.streams.get_or_create(stream_id)
                    && let Some(ref mut send) = entry.send
                {
                    send.max_stream_data = send.max_stream_data.max(max);
                }
            }

            QuicFrame::MaxStreams { max, bidi } => {
                if max > (1u64 << 60) {
                    conn.close_error = Some(TransportError::FRAME_ENCODING_ERROR);
                    conn.state = ConnectionState::Closing;
                    conn.needs_draining_timer = true;
                    return ProcessResult::ConnectionClosed;
                }
                if bidi {
                    conn.streams.peer_max_bidi = conn.streams.peer_max_bidi.max(max);
                } else {
                    conn.streams.peer_max_uni = conn.streams.peer_max_uni.max(max);
                }
            }

            QuicFrame::ConnectionClose(cc) => {
                conn.event_queue.push(
                    crate::net::handler::quic::event::QuicEvent::ConnectionClosed(cc.error_code),
                );
                conn.state = ConnectionState::Draining;
                return ProcessResult::ConnectionClosed;
            }

            QuicFrame::PathChallenge(data) => {
                conn.pending_path_response = Some(data);
            }

            QuicFrame::HandshakeDone => {
                if conn.side == Side::Client {
                    conn.state = ConnectionState::Established;
                    conn.keys.handshake = None;
                    conn.loss.handshake_confirmed = true;
                    conn.key_update.handshake_confirmed = true;
                    conn.loss.peer_completed_address_validation = true;
                    conn.loss.discard_space(1);
                } else {
                    conn.close_error = Some(TransportError::PROTOCOL_VIOLATION);
                    conn.state = ConnectionState::Closing;
                    conn.needs_draining_timer = true;
                    return ProcessResult::ConnectionClosed;
                }
            }

            QuicFrame::NewConnectionId(ncid) => {
                // RFC 9000 §19.15: retire_prior_to MUST NOT be greater than sequence
                if ncid.retire_prior_to > ncid.sequence {
                    conn.close_error = Some(TransportError::FRAME_ENCODING_ERROR);
                    conn.state = ConnectionState::Closing;
                    conn.needs_draining_timer = true;
                    return ProcessResult::ConnectionClosed;
                }

                // RFC 9000 §19.15: zero-length DCID peer MUST NOT send NEW_CONNECTION_ID
                if conn.dcid.is_empty() {
                    conn.close_error = Some(TransportError::PROTOCOL_VIOLATION);
                    conn.state = ConnectionState::Closing;
                    conn.needs_draining_timer = true;
                    return ProcessResult::ConnectionClosed;
                }

                let new_cid = crate::net::handler::quic::connection_id::ConnectionId::from_slice(
                    ncid.connection_id.as_bytes(),
                );

                // Process via CidManager — retires old CIDs and stores new one
                let _retired = conn.cid_manager.on_new_connection_id(
                    ncid.sequence,
                    ncid.retire_prior_to,
                    new_cid,
                );

                // Queue RETIRE_CONNECTION_ID frames for retired sequences
                let pending = conn.cid_manager.take_pending_retires();
                conn.retransmit.retire_connection_ids.extend(pending);

                // RFC 9000 §5.1.1: check active CID limit
                if conn.cid_manager.peer_cids.len() as u64
                    > conn.local_params.active_connection_id_limit
                {
                    conn.close_error = Some(TransportError::CONNECTION_ID_LIMIT_ERROR);
                    conn.state = ConnectionState::Closing;
                    conn.needs_draining_timer = true;
                    return ProcessResult::ConnectionClosed;
                }

                // Update active DCID to newest available peer CID
                if let Some((active_cid, _seq)) = conn.cid_manager.peer_cids.pick_unused(&conn.dcid)
                {
                    conn.dcid = active_cid;
                }
            }

            QuicFrame::RetireConnectionId { sequence } => {
                // RFC 9000 §19.16: sequence > highest issued is PROTOCOL_VIOLATION
                if sequence > conn.cid_manager.highest_issued_seq {
                    conn.close_error = Some(TransportError::PROTOCOL_VIOLATION);
                    conn.state = ConnectionState::Closing;
                    conn.needs_draining_timer = true;
                    return ProcessResult::ConnectionClosed;
                }

                // Remove the retired CID from our local set
                if let Some(_retired_cid) = conn.cid_manager.local_cids.remove_by_seq(sequence) {
                    // Mark that we need to issue a replacement CID
                    conn.cid_manager.needs_replacement_cid = true;
                }
            }

            QuicFrame::StopSending(stop) => {
                let we_initiated =
                    stop.stream_id.initiator_is_client() == (conn.side == Side::Client);
                if !stop.stream_id.is_bidi() && !we_initiated {
                    conn.close_error = Some(TransportError::STREAM_STATE_ERROR);
                    conn.state = ConnectionState::Closing;
                    conn.needs_draining_timer = true;
                    return ProcessResult::ConnectionClosed;
                }
                if let Some(entry) = conn.streams.get_mut(stop.stream_id)
                    && let Some(ref mut send) = entry.send
                {
                    send.reset_requested = true;
                    send.reset_error_code = stop.error_code;
                }
            }

            QuicFrame::ResetStream(reset) => {
                let we_initiated =
                    reset.stream_id.initiator_is_client() == (conn.side == Side::Client);
                if !reset.stream_id.is_bidi() && we_initiated {
                    conn.close_error = Some(TransportError::STREAM_STATE_ERROR);
                    conn.state = ConnectionState::Closing;
                    conn.needs_draining_timer = true;
                    return ProcessResult::ConnectionClosed;
                }
                if let Some(entry) = conn.streams.get_mut(reset.stream_id)
                    && let Some(ref mut recv) = entry.recv
                    && recv.on_reset(reset.final_size).is_err()
                {
                    conn.close_error = Some(TransportError::FINAL_SIZE_ERROR);
                    conn.state = ConnectionState::Closing;
                    conn.needs_draining_timer = true;
                    return ProcessResult::ConnectionClosed;
                }
                if conn.flow.on_stream_final_size(reset.final_size).is_err() {
                    conn.close_error = Some(TransportError::FLOW_CONTROL_ERROR);
                    conn.state = ConnectionState::Closing;
                    conn.needs_draining_timer = true;
                    return ProcessResult::ConnectionClosed;
                }
            }

            QuicFrame::PathResponse(data) => {
                conn.path.on_path_response(&data);
            }

            QuicFrame::NewToken(nt) => {
                // RFC 9000 §19.7: only clients should receive NEW_TOKEN
                if conn.side == Side::Client {
                    conn.received_new_token = Some(nt.token.to_vec());
                } else {
                    // Server receiving NEW_TOKEN is a protocol violation
                    conn.close_error = Some(TransportError::PROTOCOL_VIOLATION);
                    conn.state = ConnectionState::Closing;
                    conn.needs_draining_timer = true;
                    return ProcessResult::ConnectionClosed;
                }
            }

            QuicFrame::Datagram { data } => {
                // RFC 9221: deliver if we advertised max_datagram_frame_size
                if conn.datagrams.max_recv_size.is_some() {
                    conn.datagrams.deliver(data);
                    conn.event_queue
                        .push(crate::net::handler::quic::event::QuicEvent::DatagramReceived);
                }
                // ack_eliciting already set above (non-Padding/ACK frame)
            }

            QuicFrame::DataBlocked(_)
            | QuicFrame::StreamDataBlocked { .. }
            | QuicFrame::StreamsBlocked { .. } => {
                // Informational — no action required
            }

            _ => {}
        }
    }

    ProcessResult::Ok
}

fn handle_crypto_frame(
    conn: &mut QuicConnectionState,
    space: usize,
    offset: u64,
    data: &[u8],
    _now: Instant,
) {
    // Write to reassembly buffer
    let written = match conn.crypto_recv[space].write(offset, data) {
        Ok(n) => n,
        Err(_) => return, // buffer full
    };
    if written == 0 {
        return;
    } // gap or duplicate

    // Feed contiguous data to rustls
    let crypto_data = conn.crypto_recv[space].read_all();
    if crypto_data.is_empty() {
        return;
    }
    let data_len = crypto_data.len();

    // Take CryptoState out of the Option to break the mutable borrow
    // on conn (crypto_recv borrows conn, crypto also borrows conn).
    let mut crypto = match conn.crypto.take() {
        Some(c) => c,
        None => return,
    };

    // Determine starting space: output goes to the highest available level.
    let starting_space = if conn.keys.one_rtt.is_some() {
        2
    } else if conn.keys.handshake.is_some() {
        1
    } else {
        0
    };
    let output = match crypto.process_crypto_data(crypto_data, starting_space) {
        Ok(o) => {
            conn.crypto = Some(crypto);
            o
        }
        Err(_) => {
            conn.crypto = Some(crypto);
            conn.state = ConnectionState::Closing;
            conn.needs_draining_timer = true;
            return;
        }
    };

    conn.crypto_recv[space].drain(data_len);

    // Install new keys
    if let Some(hs_keys) = output.handshake_keys {
        conn.keys.handshake = Some(hs_keys);
    }
    if let Some(zero_rtt_key) = output.zero_rtt_keys {
        conn.keys.zero_rtt_open = Some(zero_rtt_key);
    }
    if let Some(rtt_keys) = output.one_rtt_keys {
        conn.keys.one_rtt = Some(rtt_keys);
        conn.keys.zero_rtt_open = None; // 0-RTT no longer needed (RFC 9001 §4.9.3)
        // Store key update secrets for future key rotation (Fix 7)
        if let Some(secrets) = output.next_secrets {
            conn.key_update_secrets = Some(secrets);
        }
        // Update AEAD limits based on negotiated cipher suite (RFC 9001 §6.6)
        if let Some(ref crypto) = conn.crypto
            && let Some(cs) = crypto.negotiated_cipher_suite()
        {
            conn.aead_limits =
                crate::net::handler::quic::crypto::aead_limits::AeadLimits::from_cipher_suite(cs);
        }
        if conn.side == Side::Server {
            conn.state = ConnectionState::Established;
            conn.send_handshake_done = true;
            conn.notify_established = true;
            conn.path.amplification.set_validated();
            conn.loss.handshake_confirmed = true;
            conn.key_update.handshake_confirmed = true;

            // Generate NEW_TOKEN for the client (RFC 9000 §8.1)
            if let Some(ref secret) = conn.token_secret {
                let client_ip_bytes: Vec<u8> = match conn.remote_addr {
                    IpAddress::V4(v4) => v4.octets.to_vec(),
                    IpAddress::V6(v6) => v6.octets.to_vec(),
                };
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                if let Ok(encrypted) = crate::net::handler::quic::token_crypto::encrypt_token(
                    secret,
                    crate::net::handler::quic::token_crypto::TokenType::NewToken,
                    &client_ip_bytes,
                    timestamp,
                    conn.dcid.as_bytes(),
                    conn.version,
                ) {
                    conn.pending_new_token = Some(encrypted);
                }
            }
            // Fix 6: DON'T discard handshake keys yet — wait until we
            // receive a 1-RTT packet (confirms client got the handshake).
            // Key discard happens in decrypt_and_process when space == 2.
        }
        // Notify socket layer: handshake complete
        conn.event_queue
            .push(crate::net::handler::quic::event::QuicEvent::HandshakeComplete);
    }

    // Queue per-space CRYPTO response data
    for (space, data) in output.crypto_data.iter().enumerate() {
        if !data.is_empty() {
            conn.pending_crypto[space].extend_from_slice(data);
        }
    }

    // Apply peer transport parameters if available
    if conn.peer_params.is_none()
        && let Some(crypto) = conn.crypto.as_ref()
        && let Some(params_bytes) = crypto.peer_transport_parameters()
        && let Ok(params) =
            crate::net::handler::quic::transport::params::TransportParams::decode(params_bytes)
    {
        let peer_side = if conn.side == Side::Client {
            Side::Server
        } else {
            Side::Client
        };
        if let Err(err) = params.validate_for_side(peer_side) {
            conn.close_error = Some(err);
            conn.state = ConnectionState::Closing;
            conn.needs_draining_timer = true;
            return;
        }
        conn.flow.update_max_data_send(params.initial_max_data);
        conn.streams.peer_max_bidi = params.initial_max_streams_bidi;
        conn.streams.peer_max_uni = params.initial_max_streams_uni;
        if params.max_idle_timeout_ms > 0 {
            let peer_timeout = coarsetime::Duration::from_millis(params.max_idle_timeout_ms);
            if conn.idle_timeout.as_millis() == 0 || peer_timeout < conn.idle_timeout {
                conn.idle_timeout = peer_timeout;
            }
        }
        conn.max_udp_payload = (params.max_udp_payload_size as u16).max(1200);
        // Apply per-stream flow control limits from peer's transport params
        conn.streams.peer_send_max_bidi = params.initial_max_stream_data_bidi_local;
        conn.streams.peer_send_max_bidi_remote = params.initial_max_stream_data_bidi_remote;
        conn.streams.peer_send_max_uni = params.initial_max_stream_data_uni;
        // RFC 9000 §7.3: client MUST switch DCID to server's initial_source_connection_id
        if conn.side == Side::Client {
            if let Some(ref server_scid) = params.initial_source_connection_id {
                conn.dcid = *server_scid;
            }
        }

        // RFC 9369 §4.1: Compatible Version Negotiation
        // Validate peer's version_information and detect if we can negotiate a preferred version.
        {
            use crate::net::handler::quic::transport::version::{QUIC_VERSION_1, QUIC_VERSION_2};
            let our_available = [QUIC_VERSION_1, QUIC_VERSION_2];
            if let Err(err) = params.validate_version_info(conn.version, &our_available) {
                conn.close_error = Some(err);
                conn.state = ConnectionState::Closing;
                conn.needs_draining_timer = true;
                return;
            }
            // Server-side: if both sides support v2 and we're currently on v1,
            // record the negotiated version (informational — rustls handles HKDF labels).
            if conn.side == Side::Server {
                if let Some(ref vi) = params.version_information {
                    if conn.version == QUIC_VERSION_1 && vi.other_versions.contains(&QUIC_VERSION_2)
                    {
                        conn.negotiated_version = Some(QUIC_VERSION_2);
                    }
                }
            }
        }

        // RFC 9000 §9.6: Client processes preferred_address from server.
        // Note: disable_active_migration does NOT block preferred address migration.
        if conn.side == Side::Client {
            if let Some(ref pa) = params.preferred_address {
                // Register the CID from preferred_address with sequence number 1 (RFC 9000 §5.1.1)
                conn.scid_set.push_with_seq(pa.connection_id, 1);
                conn.pending_preferred_addr_migration = true;
            }
        }

        // RFC 9221: if peer advertised max_datagram_frame_size, enable sending
        if let Some(max_size) = params.max_datagram_frame_size {
            conn.datagrams.max_send_size = Some(max_size);
        }

        // Update CidManager with peer's active_connection_id_limit
        conn.cid_manager.active_limit = params.active_connection_id_limit;

        conn.peer_params = Some(params);
    }
}

fn handle_ack_frame(
    conn: &mut QuicConnectionState,
    space: usize,
    ack: &frame::AckFrame<'_>,
    now: Instant,
) {
    // Decode ACK ranges
    let ranges = AckState::decode_ack_ranges(
        ack.largest_acked,
        ack.first_ack_range,
        ack.range_count,
        ack.ranges,
    );

    // Feed to loss detector
    // Fix 1: Apply ack_delay_exponent. The ACK delay field is in microseconds / 2^exponent.
    let ack_delay_exponent = conn
        .peer_params
        .as_ref()
        .map(|p| p.ack_delay_exponent)
        .unwrap_or(3); // default exponent is 3
    let ack_delay_us = ack.ack_delay * (1u64 << ack_delay_exponent);
    let ack_delay = coarsetime::Duration::new(
        ack_delay_us / 1_000_000,
        ((ack_delay_us % 1_000_000) * 1000) as u32,
    );
    let max_ack_delay = conn
        .peer_params
        .as_ref()
        .map(|p| coarsetime::Duration::from_millis(p.max_ack_delay_ms))
        .unwrap_or(coarsetime::Duration::from_millis(25));

    let handshake_confirmed = conn.state == ConnectionState::Established;

    let ranges_slice: smallvec::SmallVec<[(u64, u64); 32]> = ranges;
    let (acked, lost) = conn.loss.on_ack_received(
        space,
        ack.largest_acked,
        ack_delay,
        &ranges_slice,
        max_ack_delay,
        handshake_confirmed,
        now,
    );

    // Handle lost packets FIRST (RFC 9002 §A.7: loss before ack)
    if !lost.is_empty() {
        let frame_ranges: smallvec::SmallVec<[(u32, u32); 8]> =
            lost.iter().map(|(_, pkt)| pkt.frame_range).collect();

        // Fix 10: Single congestion event per loss round — use max sent_time
        let max_sent_time = lost.iter().map(|(_, pkt)| pkt.time_sent).max().unwrap();
        let total_lost_bytes: usize = lost.iter().map(|(_, pkt)| pkt.size as usize).sum();
        conn.congestion
            .on_congestion_event(total_lost_bytes, now, max_sent_time);

        // Persistent congestion (RFC 9002 §7.6.2): requires two ack-eliciting lost packets
        // spanning the threshold, with NO acknowledged packets sent between them.
        if let Some(first_rtt) = conn.loss.first_rtt_sample
            && lost.len() >= 2
        {
            let eligible: smallvec::SmallVec<
                [&crate::net::handler::quic::transport::loss::SentPacket; 8],
            > = lost
                .iter()
                .map(|(_, pkt)| pkt)
                .filter(|pkt| pkt.ack_eliciting && pkt.time_sent > first_rtt)
                .collect();
            if eligible.len() >= 2 {
                let max_ack_delay_pc = conn
                    .peer_params
                    .as_ref()
                    .map(|p| coarsetime::Duration::from_millis(p.max_ack_delay_ms))
                    .unwrap_or(coarsetime::Duration::from_millis(25));
                let pc_threshold = QuicCubic::persistent_congestion_threshold(
                    conn.loss.smoothed_rtt,
                    conn.loss.rttvar,
                    max_ack_delay_pc,
                );
                let earliest = eligible.first().unwrap().time_sent;
                let latest = eligible.last().unwrap().time_sent;
                let duration = latest.duration_since(earliest);
                if duration > pc_threshold {
                    // RFC 9002 §7.6.2: "none of the packets sent between the send times
                    // of these two packets are acknowledged"
                    let any_acked_between = acked
                        .iter()
                        .any(|pkt| pkt.time_sent > earliest && pkt.time_sent < latest);
                    if !any_acked_between {
                        conn.congestion.on_persistent_congestion();
                        conn.loss.reset_min_rtt(conn.loss.latest_rtt);
                    }
                }
            }
        }

        let retransmit = build_retransmit_queue(&conn.frame_log, &frame_ranges);
        // Rewind crypto_offset for CRYPTO retransmission
        for &(retx_space, retx_offset, _) in &retransmit.crypto {
            conn.crypto_offset[retx_space as usize] =
                conn.crypto_offset[retx_space as usize].min(retx_offset);
        }
        // Insert retransmit ranges for lost stream data
        for &(stream_id, retx_offset, retx_len, _) in &retransmit.streams {
            if let Some(entry) = conn.streams.get_mut(stream_id)
                && let Some(ref mut send) = entry.send
            {
                send.add_retransmit_range(retx_offset, retx_offset + retx_len as u64);
            }
        }
        if retransmit.handshake_done {
            conn.retransmit.handshake_done = true;
        }
        if retransmit.max_data {
            conn.retransmit.max_data = true;
        }
    }

    // Update congestion for acked packets (after loss processing per RFC 9002 §A.7)
    for pkt in &acked {
        conn.congestion.on_ack(
            pkt.size as usize,
            conn.loss.latest_rtt,
            conn.loss.min_rtt,
            now,
            pkt.in_flight,
            pkt.time_sent,
        );

        // Advance stream send.acked and consume from buffer for acked stream data
        for frame in conn.frame_log.range(pkt.frame_range.0, pkt.frame_range.1) {
            if let crate::net::handler::quic::transport::frame_log::SentFrame::Stream {
                id,
                offset,
                len,
                fin,
            } = frame
            {
                let end = *offset + *len as u64;
                if let Some(entry) = conn.streams.get_mut(*id)
                    && let Some(ref mut send) = entry.send
                {
                    let freed = send.on_ack(*offset, end);
                    send.trim_retransmit_for_ack(*offset, end);
                    if freed > 0 {
                        conn.event_queue
                            .push(crate::net::handler::quic::event::QuicEvent::DataAcked);
                    }
                    // pending_send_count: decrement when stream has no more pending data
                    if send.buffer.is_empty()
                        && send.retransmit.is_empty()
                        && send.acked == send.sent
                    {
                        conn.streams.pending_send_count =
                            conn.streams.pending_send_count.saturating_sub(1);
                    }
                    // FIN-only frame acked
                    if *fin && *len == 0 {
                        conn.streams.pending_send_count =
                            conn.streams.pending_send_count.saturating_sub(1);
                    }
                }
                // Clean up fully completed streams
                if let Some(entry) = conn.streams.get(*id)
                    && is_stream_complete(entry)
                {
                    conn.streams.remove(*id);
                }
            }
        }
    }

    // Track ACKs for key update state (RFC 9001 §6).
    // If this is a 1-RTT ACK and it acknowledges a packet sent with the current key phase,
    // mark the current phase as acknowledged so future key updates can be initiated.
    if space == 2
        && let Some(lowest_pn) = conn.key_update.lowest_pn_current_phase
        && ack.largest_acked >= lowest_pn
    {
        conn.key_update.on_ack_for_current_phase();
    }

    // Process ECN if present
    if let Some(ref ecn_counts) = ack.ecn {
        let ce_signaled = conn
            .ecn
            .on_ack_ecn(ecn_counts.ect0, ecn_counts.ect1, ecn_counts.ecn_ce);
        if ce_signaled && let Some(last_acked) = acked.last() {
            conn.congestion.on_ecn_ce(last_acked.time_sent, now);
        }
    }

    // Signal that the loss detection timer needs re-arming (RFC 9002 §A.7)
    conn.timer_needs_rearm = true;
}

fn handle_stream_frame(
    conn: &mut QuicConnectionState,
    stream_id: StreamId,
    offset: u64,
    data: &[u8],
    fin: bool,
) -> Option<TransportError> {
    use crate::net::handler::quic::stream::state::RecvState;

    // Receiving data on our own send-only unidirectional stream is STREAM_STATE_ERROR
    let we_initiated = stream_id.initiator_is_client() == (conn.side == Side::Client);
    let is_bidi = stream_id.is_bidi();
    if !is_bidi && we_initiated {
        return Some(TransportError::STREAM_STATE_ERROR);
    }

    // Check if this is a new stream (not yet in the map)
    let is_new = conn.streams.get(stream_id).is_none();

    let entry = match conn.streams.get_or_create(stream_id) {
        Ok(e) => e,
        Err(_) => return Some(TransportError::STREAM_LIMIT_ERROR),
    };

    // RFC 9000 §3.2: only Recv and SizeKnown states can accept data
    if let Some(recv_state) = entry.state.recv_state()
        && !recv_state.can_receive_data()
    {
        return Some(TransportError::STREAM_STATE_ERROR);
    }

    if let Some(ref mut recv) = entry.recv {
        match recv.receive(offset, data, fin) {
            Ok(new_bytes) => {
                // Only count genuinely new bytes against connection flow control
                if new_bytes > 0 && conn.flow.on_data_received(new_bytes as u64).is_err() {
                    return Some(TransportError::FLOW_CONTROL_ERROR);
                }
                // RFC 9000 §3.2: transition Recv → SizeKnown when FIN received
                if fin {
                    if let Some(recv_state) = entry.state.recv_state_mut()
                        && *recv_state == RecvState::Recv
                    {
                        let _ = recv_state.transition(RecvState::SizeKnown);
                    }
                    // Check if all data has been received contiguously
                    if let Some(fs) = recv.final_size
                        && recv.received >= fs
                        && let Some(recv_state) = entry.state.recv_state_mut()
                        && *recv_state == RecvState::SizeKnown
                    {
                        let _ = recv_state.transition(RecvState::DataRecvd);
                    }
                }
            }
            Err(_) => return Some(TransportError::FLOW_CONTROL_ERROR),
        }
    }

    // Notify socket layer BEFORE cleanup check — the socket must learn about
    // the stream even if it's already complete (e.g., single-frame request with FIN).
    if is_new {
        conn.stream_accept_queue.push(stream_id);
    }
    conn.event_queue
        .push(crate::net::handler::quic::event::QuicEvent::StreamReadable(
            stream_id,
        ));

    None
}

// ---------------------------------------------------------------------------
// Outbound packet generation
// ---------------------------------------------------------------------------

const ETH_LEN: usize = std::mem::size_of::<EthernetFrame>();

/// Check if any packet-number space has anything to send.
pub fn has_pending_data_any(conn: &QuicConnectionState) -> bool {
    // Closing state needs to send CONNECTION_CLOSE (RFC 9000 §10.2.1)
    if conn.state == ConnectionState::Closing && !conn.closing_frame_sent {
        return true;
    }
    (0..3u8).any(|s| has_pending_data(conn, s))
}

/// Check if a packet-number space has anything to send.
fn has_pending_data(conn: &QuicConnectionState, space: u8) -> bool {
    // Per-space: unsent CRYPTO data or ACK needed
    if (conn.crypto_offset[space as usize] as usize) < conn.pending_crypto[space as usize].len() {
        return true;
    }
    if conn.ack[space as usize].needs_ack() {
        return true;
    }
    // Probe can be sent in any space (PING is valid everywhere)
    if conn.needs_probe {
        return true;
    }
    // Everything below is 1-RTT only (space 2)
    if space != 2 {
        return false;
    }
    conn.send_handshake_done
        || conn.pending_new_token.is_some()
        || conn.pending_path_response.is_some()
        || conn.streams.has_pending_send()
        || conn.datagrams.has_pending_send()
        || conn.retransmit.max_data
        || !conn.retransmit.max_stream_data.is_empty()
        || conn.retransmit.max_streams
        || !conn.retransmit.reset_streams.is_empty()
        || !conn.retransmit.stop_sending.is_empty()
        || conn.retransmit.handshake_done
        || conn.flow.should_send_max_data().is_some()
        || !conn.retransmit.pending_retire_cids.is_empty()
        || !conn.retransmit.pending_new_cids.is_empty()
        || !conn.retransmit.retire_connection_ids.is_empty()
        || !conn.retransmit.new_connection_ids.is_empty()
}

/// Generate outbound QUIC packets from pending connection state.
///
/// Iterates over each packet-number space (Initial, Handshake, 1-RTT),
/// builds the QUIC payload using `PacketBuilder`, encrypts it via
/// `protect_packet`, wraps it in Ethernet+IP+UDP headers, and pushes
/// the resulting frame to `tx_return`.
pub fn generate_packets<'umem>(
    conn: &mut QuicConnectionState,
    conn_key: usize,
    now: Instant,
    wheel: &mut TimerWheel,
    free_frames: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) {
    // Don't send in Draining or Closed state
    if matches!(
        conn.state,
        ConnectionState::Draining | ConnectionState::Closed
    ) {
        return;
    }

    // RFC 9000 §10.2.1: Closing state — retransmit CONNECTION_CLOSE on incoming packets.
    // Stay in Closing; the idle/draining timer handles the transition to Draining/Closed.
    if conn.state == ConnectionState::Closing {
        if !conn.closing_frame_sent {
            let error_code = conn.close_error.map(|e| e.code()).unwrap_or(0);

            // Pick the highest available encryption space
            let space: u8 = if conn.keys.one_rtt.is_some() {
                2
            } else if conn.keys.handshake.is_some() {
                1
            } else if conn.keys.initial.is_some() {
                0
            } else {
                return;
            };

            if let Some(mut frame) = free_frames.pop() {
                let ip_len = match conn.local_addr {
                    IpAddress::V4(_) => IPV4_MIN_HEADER_LEN,
                    IpAddress::V6(_) => IPV6_HEADER_LEN,
                };
                let quic_offset = ETH_LEN + ip_len + UDP_HEADER_LEN;
                let capacity = frame.capacity();
                if capacity >= quic_offset + 64 {
                    unsafe { frame.set_len(capacity) };
                    let pn = conn.loss.next_pn(space as usize);
                    let largest_acked = conn.ack[space as usize].largest_received().unwrap_or(0);

                    let builder_opt = if space <= 1 {
                        let packet_type_bits = if space == 0 { 0x00 } else { 0x02 };
                        PacketBuilder::begin_long(
                            &mut frame[quic_offset..],
                            packet_type_bits,
                            conn.version,
                            conn.dcid.as_bytes(),
                            conn.scid.as_bytes(),
                            pn,
                            largest_acked,
                            &conn.frame_log,
                        )
                    } else {
                        PacketBuilder::begin_short(
                            &mut frame[quic_offset..],
                            conn.dcid.as_bytes(),
                            pn,
                            largest_acked,
                            false,
                            &conn.frame_log,
                        )
                    };

                    if let Some(mut builder) = builder_opt {
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

                        if let Some(key) = local_key {
                            let quic_buf = &mut frame[quic_offset..quic_offset + quic_len];
                            if let Ok(protected_len) =
                                protect_packet(key, quic_buf, pn_offset, pn_length, pn)
                            {
                                let total_len = write_transport_headers(
                                    conn,
                                    &mut frame,
                                    quic_offset,
                                    protected_len,
                                );
                                if total_len > 0 {
                                    debug_assert!(
                                        total_len >= 64,
                                        "QUIC CLOSE: packet too small: {} bytes",
                                        total_len
                                    );
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
                    } else {
                        free_frames.push(frame);
                    }
                } else {
                    free_frames.push(frame);
                }
            }

            conn.closing_frame_sent = true;
            conn.last_close_sent = Some(now);
        }
        // Arm draining timer for Closing state cleanup (RFC 9000 §10.2)
        if conn.needs_draining_timer {
            conn.needs_draining_timer = false;
            let max_ack_delay = conn
                .peer_params
                .as_ref()
                .map(|p| coarsetime::Duration::from_millis(p.max_ack_delay_ms))
                .unwrap_or(coarsetime::Duration::from_millis(25));
            let pto = conn.loss.pto(2, max_ack_delay);
            let draining_deadline = now + pto * 3;
            conn.timers
                .arm(QuicTimerKind::Draining, conn_key, draining_deadline, wheel);
        }

        // Stay in Closing — don't transition to Draining.
        // The draining timer will handle the transition.
        return;
    }

    // Arm key discard timer after key update (RFC 9001 §6.5: 3×PTO)
    if conn.needs_key_discard_timer {
        conn.needs_key_discard_timer = false;
        let max_ack_delay = conn
            .peer_params
            .as_ref()
            .map(|p| coarsetime::Duration::from_millis(p.max_ack_delay_ms))
            .unwrap_or(coarsetime::Duration::from_millis(25));
        let pto = conn.loss.pto(2, max_ack_delay);
        let discard_deadline = now + pto * 3;
        conn.timers
            .arm(QuicTimerKind::KeyDiscard, conn_key, discard_deadline, wheel);
    }

    // Build packets for each space that has pending data
    for space in 0..3u8 {
        if !has_pending_data(conn, space) {
            continue;
        }

        // Gate: amplification limit check
        let estimated_size = 1200;
        if !conn.path.amplification.can_send(estimated_size) {
            continue;
        }

        // Gate: congestion window (RFC 9002 §7) — only gate 1-RTT data
        if space == 2 && !conn.congestion.can_send() {
            continue;
        }

        // Gate: pacing (RFC 9002 §7.7) — only pace 1-RTT data, not handshake
        if space == 2 && !conn.pacing.can_send(now, estimated_size) {
            continue;
        }

        // Gate: must have encrypt key for this space
        let has_key = match space {
            0 => conn.keys.initial.is_some(),
            1 => conn.keys.handshake.is_some(),
            2 => conn.keys.one_rtt.is_some(),
            _ => false,
        };
        if !has_key {
            continue;
        }

        // Pop a frame from free_frames
        let Some(mut frame) = free_frames.pop() else {
            return;
        };

        // Build the packet into the frame buffer
        let total_len = build_packet_in_frame(conn, space, now, &mut frame);

        if total_len > 0 {
            // Minimum packet size varies by CID length; 21 bytes is the absolute
            // minimum (ETH+IP+UDP headers are separate, this is total frame size).
            debug_assert!(
                total_len >= 42,
                "QUIC: packet too small: {} bytes (space={}, state={:?})",
                total_len,
                space,
                conn.state
            );
            unsafe { frame.set_len(total_len) };
            conn.path.amplification.on_bytes_sent(total_len);
            conn.pacing.on_packet_sent(total_len, now);
            tx_return.push(frame);
        } else {
            free_frames.push(frame); // return unused frame
        }
    }

    // Deferred Handshake key discard: now that generate_packets has had a
    // chance to send a Handshake ACK, discard the keys (RFC 9001 §4.9.2).
    if conn.handshake_keys_pending_discard && conn.keys.handshake.is_some() {
        conn.keys.handshake = None;
        conn.loss.discard_space(1);
        conn.handshake_keys_pending_discard = false;
    }

    // Notify the accept queue if this connection just completed handshake
    if conn.notify_established {
        conn.notify_established = false;
        if let Some(ref accept_queue) = conn.accept_queue {
            accept_queue.push(conn_key);
        }
    }

    // Arm loss detection timer
    let max_ack_delay = conn
        .peer_params
        .as_ref()
        .map(|p| coarsetime::Duration::from_millis(p.max_ack_delay_ms))
        .unwrap_or(coarsetime::Duration::from_millis(25));
    if let Some(deadline) = conn.loss.loss_detection_timer(max_ack_delay) {
        conn.timers
            .arm(QuicTimerKind::LossDetection, conn_key, deadline, wheel);
    }
    conn.timer_needs_rearm = false;
}

/// Build a complete Ethernet+IP+UDP+QUIC packet into a frame buffer.
///
/// Returns the total frame length (including all headers), or 0 if the
/// packet could not be built (e.g. buffer too small, no keys).
fn build_packet_in_frame(
    conn: &mut QuicConnectionState,
    space: u8,
    now: Instant,
    frame: &mut Frame<'_>,
) -> usize {
    let ip_len = match conn.local_addr {
        IpAddress::V4(_) => IPV4_MIN_HEADER_LEN,
        IpAddress::V6(_) => IPV6_HEADER_LEN,
    };
    let udp_offset = ETH_LEN + ip_len;
    let quic_offset = udp_offset + UDP_HEADER_LEN;

    // Set frame length to capacity so we can write into the full buffer
    let capacity = frame.capacity();
    if capacity < quic_offset + 64 {
        return 0; // buffer too small for even minimal packet
    }
    unsafe { frame.set_len(capacity) };

    // Build QUIC payload starting at quic_offset
    let pn = conn.loss.next_pn(space as usize);
    let largest_acked = conn.ack[space as usize].largest_received().unwrap_or(0);

    // Choose packet builder type
    let mut builder = if space <= 1 {
        // Long header (Initial=0x00 or Handshake=0x02)
        let packet_type_bits = if space == 0 { 0x00 } else { 0x02 };
        match PacketBuilder::begin_long(
            &mut frame[quic_offset..],
            packet_type_bits,
            conn.version,
            conn.dcid.as_bytes(),
            conn.scid.as_bytes(),
            pn,
            largest_acked,
            &conn.frame_log,
        ) {
            Some(b) => b,
            None => return 0,
        }
    } else {
        // Short header (1-RTT)
        match PacketBuilder::begin_short(
            &mut frame[quic_offset..],
            conn.dcid.as_bytes(),
            pn,
            largest_acked,
            conn.key_update.key_phase, // key_phase
            &conn.frame_log,
        ) {
            Some(b) => b,
            None => return 0,
        }
    };

    let mut wrote_ack_eliciting = false;

    // Write frames in priority order:

    // 1. CRYPTO data (new + retransmissions)
    // pending_crypto is append-only; crypto_offset tracks the next byte to send.
    // On loss, crypto_offset is rewound so the data is re-sent from the buffer.
    {
        let send_start = conn.crypto_offset[space as usize] as usize;
        let buf = &conn.pending_crypto[space as usize];
        if send_start < buf.len() {
            let data = &buf[send_start..];
            let offset_val = conn.crypto_offset[space as usize];
            let written = builder.write_crypto(offset_val, data, space, &mut conn.frame_log);
            if written > 0 {
                conn.crypto_offset[space as usize] += written as u64;
                wrote_ack_eliciting = true;
            }
        }
    }

    // 2. ACK
    if conn.ack[space as usize].needs_ack()
        && let Some(largest) = conn.ack[space as usize].largest_received()
    {
        // Fix 2: Compute actual ACK delay from largest_received_time
        let ack_delay = if let Some(recv_time) = conn.ack[space as usize].largest_received_time() {
            let delay = now.duration_since(recv_time);
            let exponent = conn.local_params.ack_delay_exponent;
            // Encode: delay_us / 2^exponent
            (delay.as_millis() * 1000) / (1u64 << exponent)
        } else {
            0
        };
        let first_ack_range = conn.ack[space as usize].first_ack_range();
        let ack_range_count = conn.ack[space as usize].ack_range_count();
        let ranges_slice = conn.ack[space as usize].encoded_ranges();
        let mut ranges_buf = [0u8; 256];
        let ranges_len = ranges_slice.len().min(256);
        ranges_buf[..ranges_len].copy_from_slice(&ranges_slice[..ranges_len]);
        builder.write_ack(
            largest,
            ack_delay,
            first_ack_range,
            ack_range_count,
            &ranges_buf[..ranges_len],
            &mut conn.frame_log,
            space,
        );
        conn.ack[space as usize].ack_sent();
    }

    // 3. HANDSHAKE_DONE (server, 1-RTT space only)
    if space == 2
        && conn.send_handshake_done
        && conn.side == Side::Server
        && builder.write_handshake_done(&mut conn.frame_log)
    {
        conn.send_handshake_done = false;
        wrote_ack_eliciting = true;
    }

    // 3b. NEW_TOKEN (server, 1-RTT space only, RFC 9000 §8.1)
    if space == 2 && conn.side == Side::Server {
        if let Some(ref token) = conn.pending_new_token {
            if builder.write_new_token(token) {
                conn.pending_new_token = None;
                wrote_ack_eliciting = true;
            }
        }
    }

    // 4b. MAX_DATA — expand peer's send window (RFC 9000 §4.2)
    if space == 2 {
        if conn.retransmit.max_data {
            let current_max = conn.flow.current_max_data_recv();
            if builder.write_max_data(current_max, &mut conn.frame_log) {
                conn.retransmit.max_data = false;
                wrote_ack_eliciting = true;
            }
        } else if let Some(new_max) = conn.flow.should_send_max_data()
            && builder.write_max_data(new_max, &mut conn.frame_log)
        {
            conn.flow.commit_max_data(new_max);
            wrote_ack_eliciting = true;
        }
    }

    // 4c. MAX_STREAM_DATA — expand per-stream windows (RFC 9000 §4.2)
    if space == 2 {
        // Retransmit lost MAX_STREAM_DATA first
        let retransmit_ids: smallvec::SmallVec<[StreamId; 4]> =
            conn.retransmit.max_stream_data.drain(..).collect();
        for stream_id in retransmit_ids {
            if let Some(entry) = conn.streams.get_mut(stream_id)
                && let Some(ref recv) = entry.recv
            {
                let current = recv.max_stream_data;
                if builder.write_max_stream_data(stream_id, current, &mut conn.frame_log) {
                    wrote_ack_eliciting = true;
                } else {
                    conn.retransmit.max_stream_data.push(stream_id);
                    break;
                }
            }
        }
        // Proactively send MAX_STREAM_DATA for streams needing window expansion
        let stream_ids: smallvec::SmallVec<[StreamId; 16]> = conn
            .streams
            .iter_recv()
            .filter_map(|(id, entry)| {
                entry
                    .recv
                    .as_ref()
                    .and_then(|r| r.should_send_max_stream_data().map(|_| id))
            })
            .collect();
        for stream_id in stream_ids {
            if builder.remaining() < 20 {
                break;
            }
            if let Some(entry) = conn.streams.get_mut(stream_id)
                && let Some(ref mut recv) = entry.recv
                && let Some(new_max) = recv.should_send_max_stream_data()
                && builder.write_max_stream_data(stream_id, new_max, &mut conn.frame_log)
            {
                recv.commit_max_stream_data(new_max);
                wrote_ack_eliciting = true;
            }
        }
    }

    // 4d. MAX_STREAMS — expand peer's stream concurrency (RFC 9000 §4.6)
    if space == 2 {
        if conn.retransmit.max_streams {
            let bidi_max = conn.streams.local_max_bidi;
            let uni_max = conn.streams.local_max_uni;
            if bidi_max > 0 {
                builder.write_max_streams(bidi_max, true, &mut conn.frame_log);
            }
            if uni_max > 0 {
                builder.write_max_streams(uni_max, false, &mut conn.frame_log);
            }
            conn.retransmit.max_streams = false;
            wrote_ack_eliciting = true;
        } else {
            if let Some(new_max) = conn.streams.should_send_max_streams_bidi()
                && builder.write_max_streams(new_max, true, &mut conn.frame_log)
            {
                conn.streams.commit_max_streams_bidi(new_max);
                wrote_ack_eliciting = true;
            }
            if let Some(new_max) = conn.streams.should_send_max_streams_uni()
                && builder.write_max_streams(new_max, false, &mut conn.frame_log)
            {
                conn.streams.commit_max_streams_uni(new_max);
                wrote_ack_eliciting = true;
            }
        }
    }

    // 4e. RESET_STREAM — abort individual streams (RFC 9000 §3.1)
    if space == 2 {
        // Retransmit lost RESET_STREAMs
        let retransmit_resets: smallvec::SmallVec<[(StreamId, u64, u64); 4]> =
            conn.retransmit.reset_streams.drain(..).collect();
        for (id, error_code, final_size) in retransmit_resets {
            if builder.write_reset_stream(id, error_code, final_size, &mut conn.frame_log) {
                wrote_ack_eliciting = true;
            } else {
                conn.retransmit
                    .reset_streams
                    .push((id, error_code, final_size));
                break;
            }
        }
        // Newly requested resets
        let reset_streams: smallvec::SmallVec<[(StreamId, u64, u64); 4]> = conn
            .streams
            .iter_all_send()
            .filter_map(|(id, entry)| {
                entry.send.as_ref().and_then(|s| {
                    if s.reset_requested {
                        Some((id, s.reset_error_code, s.final_size()))
                    } else {
                        None
                    }
                })
            })
            .collect();
        for (id, error_code, final_size) in reset_streams {
            if builder.write_reset_stream(id, error_code, final_size, &mut conn.frame_log) {
                if let Some(entry) = conn.streams.get_mut(id)
                    && let Some(ref mut send) = entry.send
                {
                    send.reset_requested = false;
                }
                wrote_ack_eliciting = true;
            } else {
                break;
            }
        }
    }

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
                if let Some(entry) = conn.streams.get_mut(id)
                    && let Some(ref mut recv) = entry.recv
                {
                    recv.stop_sending_requested = false;
                }
                wrote_ack_eliciting = true;
            } else {
                break;
            }
        }
    }

    // 4. PATH_RESPONSE
    if space == 2
        && let Some(data) = conn.pending_path_response.take()
    {
        if builder.write_path_response(data) {
            wrote_ack_eliciting = true;
        } else {
            // Couldn't fit; put it back
            conn.pending_path_response = Some(data);
        }
    }

    // 4g. RETIRE_CONNECTION_ID frames (1-RTT space only, RFC 9000 §5.1.2)
    if space == 2 {
        // From CidManager pending retires (queued during NEW_CONNECTION_ID processing)
        while let Some(seq) = conn.retransmit.pending_retire_cids.pop() {
            if builder.write_retire_connection_id(seq, &mut conn.frame_log) {
                wrote_ack_eliciting = true;
            } else {
                conn.retransmit.pending_retire_cids.push(seq);
                break;
            }
        }
        // Retransmit lost RETIRE_CONNECTION_ID
        let retransmit_retire: smallvec::SmallVec<[u64; 4]> =
            conn.retransmit.retire_connection_ids.drain(..).collect();
        for seq in retransmit_retire {
            if builder.write_retire_connection_id(seq, &mut conn.frame_log) {
                wrote_ack_eliciting = true;
            } else {
                conn.retransmit.retire_connection_ids.push(seq);
                break;
            }
        }
    }

    // 4h. NEW_CONNECTION_ID frames (1-RTT space only, RFC 9000 §5.1.1)
    if space == 2 {
        while let Some((seq, retire_prior_to, cid, token)) = conn.retransmit.pending_new_cids.pop()
        {
            if builder.write_new_connection_id(
                seq,
                retire_prior_to,
                cid.as_bytes(),
                token,
                &mut conn.frame_log,
            ) {
                wrote_ack_eliciting = true;
            } else {
                conn.retransmit
                    .pending_new_cids
                    .push((seq, retire_prior_to, cid, token));
                break;
            }
        }
        // Retransmit lost NEW_CONNECTION_ID (look up CID details from cid_manager)
        let retransmit_new: smallvec::SmallVec<[u64; 4]> =
            conn.retransmit.new_connection_ids.drain(..).collect();
        for seq in retransmit_new {
            // Find the CID for this sequence in local_cids
            if let Some((cid, found_seq)) = conn
                .cid_manager
                .local_cids
                .iter()
                .zip(conn.cid_manager.local_cids.iter_seqs())
                .find(|(_, s)| *s == seq)
                .map(|(c, s)| (*c, s))
            {
                let _ = found_seq;
                let token = [0u8; 16]; // Simplified reset token for retransmit
                if builder.write_new_connection_id(
                    seq,
                    0,
                    cid.as_bytes(),
                    token,
                    &mut conn.frame_log,
                ) {
                    wrote_ack_eliciting = true;
                } else {
                    conn.retransmit.new_connection_ids.push(seq);
                    break;
                }
            }
        }
    }

    // 5. Probe: if we need a probe but haven't written anything ack-eliciting, add PING
    if conn.needs_probe && !wrote_ack_eliciting {
        builder.write_ping(&mut conn.frame_log);
        wrote_ack_eliciting = true;
        conn.needs_probe = false;
    }

    // 6. Stream data (1-RTT space only)
    if space == 2 {
        // Collect stream IDs with pending data first to avoid borrow conflicts
        let pending_streams: smallvec::SmallVec<[StreamId; 16]> =
            conn.streams.iter_send_mut().map(|(id, _)| id).collect();
        for stream_id in pending_streams {
            if builder.remaining() < 20 {
                break; // not enough space for a meaningful STREAM frame
            }
            if let Some(entry) = conn.streams.get_mut(stream_id)
                && let Some(ref mut send) = entry.send
            {
                // Priority 1: Retransmit lost data before sending new data
                if !send.retransmit.is_empty() {
                    let (range_start, range_end) = send.retransmit[0];
                    let offset_from_head = (range_start - send.acked) as usize;
                    let range_len = (range_end - range_start) as usize;
                    let max_len = builder.remaining().saturating_sub(20).min(range_len);
                    if max_len > 0 {
                        let mut temp_buf = [0u8; 1200];
                        let n = send
                            .buffer
                            .peek_at(offset_from_head, &mut temp_buf[..max_len]);
                        if n > 0 {
                            let fin = send.fin_sent
                                && range_start + n as u64 >= send.acked + send.buffer.len() as u64;
                            let written = builder.write_stream(
                                stream_id,
                                range_start,
                                &temp_buf[..n],
                                fin,
                                &mut conn.frame_log,
                            );
                            if written > 0 {
                                wrote_ack_eliciting = true;
                                if range_start + written as u64 >= range_end {
                                    send.pop_retransmit_range();
                                } else {
                                    send.retransmit[0].0 = range_start + written as u64;
                                }
                            }
                        }
                    }
                    continue; // fairness: one retransmit range per stream per packet
                }

                // Priority 2: New data
                if builder.remaining() < 20 {
                    continue;
                }
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
    }

    // 7. DATAGRAM frames (1-RTT space only, RFC 9221)
    if space == 2 {
        while let Some(data) = conn.datagrams.pop_send() {
            if !builder.write_datagram_with_length(&data) {
                // Couldn't fit; put it back at the front
                conn.datagrams.send.push_front(data);
                break;
            }
            wrote_ack_eliciting = true;
        }
    }

    // Guard: don't send a packet with no frames at all.
    // This can happen when has_pending_data() triggers for control frames
    // but the current space (0 or 1) doesn't write them (they're 1-RTT only).
    let frame_range_check = builder.frame_range(&conn.frame_log);
    if frame_range_check.0 == frame_range_check.1 && !wrote_ack_eliciting {
        // No frames written — don't finalize or send
        return 0;
    }

    // 7a. Minimum payload padding (RFC 9001 §5.4.2): the combined length of
    // encoded PN + protected payload must be at least 4 bytes longer than the
    // header protection sample (16 bytes). Equivalently, ensure offset >=
    // pn_offset + 4 so the AEAD ciphertext covers the sample window.
    {
        let min_offset = builder.pn_offset() + 4;
        builder.pad_to(min_offset);
    }

    // 7b. Initial padding — Initial packets must be at least 1200 bytes total
    // RFC 9000 §14: the 1200-byte minimum applies to the UDP payload (= QUIC packet)
    if space == 0 {
        builder.pad_to(1200);
    }

    // Finalize: get metadata before consuming builder
    let pn_offset = builder.pn_offset();
    let pn_length = builder.pn_length();
    let frame_range = builder.frame_range(&conn.frame_log);
    let quic_len = builder.finish(); // returns total including AEAD tag space

    // Encrypt the QUIC packet
    let local_key = match space {
        0 => conn.keys.initial.as_ref().map(|kp| &kp.local),
        1 => conn.keys.handshake.as_ref().map(|kp| &kp.local),
        2 => conn.keys.one_rtt.as_ref().map(|kp| &kp.local),
        _ => None,
    };
    let local_key = match local_key {
        Some(k) => k,
        None => return 0,
    };

    let quic_buf = &mut frame[quic_offset..quic_offset + quic_len];
    match protect_packet(local_key, quic_buf, pn_offset, pn_length, pn) {
        Ok(protected_len) => {
            // Record sent packet for loss detection
            conn.loss.on_packet_sent(
                space as usize,
                pn,
                SentPacket {
                    time_sent: now,
                    size: protected_len as u16,
                    ack_eliciting: wrote_ack_eliciting,
                    in_flight: wrote_ack_eliciting,
                    frame_range,
                },
            );
            conn.packets_encrypted[space as usize] += 1;

            // RFC 9001 §4.9.1: client MUST discard Initial keys when first sending Handshake
            if space == 1 && conn.side == Side::Client && conn.keys.initial.is_some() {
                conn.keys.initial = None;
                conn.loss.discard_space(0);
            }

            // Sync congestion controller with sent bytes
            if wrote_ack_eliciting {
                conn.congestion.on_packets_sent(protected_len, now);
            }

            // Track key phase for key updates
            conn.key_update.on_packet_sent(pn);

            // Check if key update is needed (AEAD confidentiality limit)
            let limits = conn.aead_limits;
            if space == 2
                && limits.needs_key_update(conn.packets_encrypted[2])
                && conn.key_update.can_initiate_update()
                && let Some(ref mut secrets) = conn.key_update_secrets
            {
                let new_keys = secrets.next_packet_keys();
                // Update packet keys while preserving header protection keys
                // (RFC 9001 §5.4: header protection keys are unchanged by key updates).
                // Retain old remote packet key for reordered packets (RFC 9001 §6.1).
                if let Some(ref mut kp) = conn.keys.one_rtt {
                    let old_remote_pkt_key =
                        std::mem::replace(&mut kp.remote.packet_key, new_keys.remote);
                    conn.key_update.prev_remote_packet_key = Some(old_remote_pkt_key);
                    kp.local.update_packet_key(new_keys.local);
                }
                conn.key_update.on_update_initiated();
                conn.packets_encrypted[2] = 0;
                conn.needs_key_discard_timer = true;
            }

            // Build Ethernet + IP + UDP headers
            write_transport_headers(conn, frame, quic_offset, protected_len)
        }
        Err(_) => 0,
    }
}

/// Check if a stream is fully complete (both sides done) and can be removed.
fn is_stream_complete(entry: &crate::net::handler::quic::stream::map::StreamEntry) -> bool {
    let send_done = match &entry.send {
        None => true,
        Some(send) => {
            (send.fin_sent && send.buffer.is_empty() && send.acked == send.sent)
                || send.reset_requested
        }
    };
    let recv_done = match &entry.recv {
        None => true,
        Some(recv) => (recv.fin_received && recv.read_offset == recv.received) || recv.is_reset,
    };
    send_done && recv_done
}

/// Write Ethernet + IP + UDP headers into the frame, returning the total
/// frame length. The QUIC payload is already in place at `quic_offset`.
fn write_transport_headers(
    conn: &QuicConnectionState,
    frame: &mut Frame<'_>,
    quic_offset: usize,
    quic_len: usize,
) -> usize {
    let udp_len = UDP_HEADER_LEN + quic_len;
    let total_frame_len = quic_offset + quic_len;

    // Ethernet header
    match conn.local_addr {
        IpAddress::V4(_) => {
            write_ethernet_header(frame, conn.remote_mac, conn.local_mac, EtherTypes::IPv4);
        }
        IpAddress::V6(_) => {
            write_ethernet_header(frame, conn.remote_mac, conn.local_mac, EtherTypes::IPv6);
        }
    }

    // IP header — must write manually because IpVersion::write_ip_header hardcodes TCP
    match (conn.local_addr, conn.remote_addr) {
        (IpAddress::V4(src), IpAddress::V4(dst)) => {
            let ip = &mut frame[ETH_LEN..ETH_LEN + IPV4_MIN_HEADER_LEN];
            ip.fill(0);
            ip[0] = 0x45; // version=4, IHL=5
            let total_ip_len = (IPV4_MIN_HEADER_LEN + udp_len) as u16;
            ip[2..4].copy_from_slice(&total_ip_len.to_be_bytes());
            ip[6] = 0x40; // Don't Fragment
            ip[8] = 64; // TTL
            ip[9] = IpProtocols::Udp; // Protocol = UDP
            let src_bytes: [u8; 4] = src.into();
            ip[12..16].copy_from_slice(&src_bytes);
            let dst_bytes: [u8; 4] = dst.into();
            ip[16..20].copy_from_slice(&dst_bytes);
            // Compute IPv4 header checksum
            let ip_header = Ipv4Header::from_bytes_mut(frame);
            ip_header.fill_checksum();
        }
        (IpAddress::V6(src), IpAddress::V6(dst)) => {
            let ip = &mut frame[ETH_LEN..ETH_LEN + IPV6_HEADER_LEN];
            ip.fill(0);
            ip[0] = 0x60; // version=6
            let payload_len = udp_len as u16;
            ip[4..6].copy_from_slice(&payload_len.to_be_bytes());
            ip[6] = IpProtocols::Udp; // Next Header = UDP
            ip[7] = 64; // Hop Limit
            let src_bytes: [u8; 16] = src.into();
            ip[8..24].copy_from_slice(&src_bytes);
            let dst_bytes: [u8; 16] = dst.into();
            ip[24..40].copy_from_slice(&dst_bytes);
        }
        _ => return 0, // mismatched address families
    }

    // UDP header
    let udp_offset = quic_offset - UDP_HEADER_LEN;
    let udp = unsafe { UdpHeader::from_bytes_at_mut(frame, udp_offset) };
    *udp = UdpHeader::new(
        conn.local_port,
        conn.remote_port,
        udp_len as u16,
        [0, 0], // checksum initially 0
    );

    // Fix 20: UDP checksum is MANDATORY for IPv6. For IPv4, checksum 0 is valid (optional).
    if let (IpAddress::V6(src), IpAddress::V6(dst)) = (conn.local_addr, conn.remote_addr) {
        let src_bytes: [u8; 16] = src.into();
        let dst_bytes: [u8; 16] = dst.into();
        let udp_segment = &frame[udp_offset..udp_offset + udp_len];
        let cksum = ipv6_udp_checksum(&src_bytes, &dst_bytes, udp_segment);
        let udp_mut = unsafe { UdpHeader::from_bytes_at_mut(frame, udp_offset) };
        udp_mut.checksum = cksum.to_be_bytes();
    }

    total_frame_len
}

/// Compute the UDP checksum over an IPv6 pseudo-header and UDP segment.
/// The UDP segment includes the UDP header and payload. The checksum field
/// at bytes 6-7 of the segment is skipped during summation.
fn ipv6_udp_checksum(src: &[u8; 16], dst: &[u8; 16], udp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    // Pseudo-header: source address
    for chunk in src.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    // Pseudo-header: destination address
    for chunk in dst.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    // Pseudo-header: UDP length (32-bit for jumbo)
    let udp_len = udp_segment.len() as u32;
    sum += udp_len >> 16;
    sum += udp_len & 0xFFFF;
    // Pseudo-header: Next Header = UDP (17)
    sum += 17u32;
    // UDP segment (skip checksum field at bytes 6-7)
    let mut i = 0;
    while i + 1 < udp_segment.len() {
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
    // Fold carry bits
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let result = !(sum as u16);
    if result == 0 { 0xFFFF } else { result }
}
