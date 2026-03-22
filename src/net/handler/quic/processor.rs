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
                    conn.retransmit
                        .crypto
                        .extend(retransmit.crypto.iter().cloned());
                    conn.retransmit
                        .streams
                        .extend(retransmit.streams.iter().cloned());
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
            // TODO: drop prev_remote_key
            TimerResult::Ok
        }
        QuicTimerKind::PathValidation => {
            // TODO: revert to previous path
            TimerResult::Ok
        }
        QuicTimerKind::Handshake => {
            if conn.state == ConnectionState::Handshaking {
                conn.state = ConnectionState::Closed;
                return TimerResult::Close;
            }
            TimerResult::Ok
        }
        QuicTimerKind::PmtuProbe => TimerResult::Ok,
    }
}

/// Process one QUIC packet (from a UDP datagram).
/// `quic_payload` is the raw QUIC bytes AFTER the UDP header. MUTABLE for in-place decrypt.
/// `datagram_len` is the total UDP datagram size (for amplification tracking).
pub fn process_packet(
    conn: &mut QuicConnectionState,
    quic_payload: &mut [u8],
    datagram_len: usize,
    now: Instant,
) -> ProcessResult {
    // For short headers, the DCID in the incoming packet is OUR SCID
    let short_dcid_len = conn.scid.len();

    // Extract (space, pn_offset) from the header using an immutable borrow,
    // then release the borrow before passing quic_payload mutably.
    let (space, pn_offset) = {
        let (header, _header_len) = match wire_quic::parse_header(quic_payload, short_dcid_len) {
            Ok(h) => h,
            Err(_) => return ProcessResult::Ok, // unparseable, drop
        };

        match header {
            PacketHeader::Long(long) => {
                let space = packet_space(long.packet_type);
                let pn_offset = if long.packet_type == PacketType::Initial {
                    match packet_parser::parse_initial_fields(&quic_payload[long.payload_offset..])
                    {
                        Some((_token, _payload_length, relative_pn_offset)) => {
                            long.payload_offset + relative_pn_offset
                        }
                        None => return ProcessResult::Ok,
                    }
                } else if long.packet_type == PacketType::Handshake {
                    match crate::net::handler::quic::transport::varint::decode_varint(
                        &quic_payload[long.payload_offset..],
                    ) {
                        Some((_length, consumed)) => long.payload_offset + consumed,
                        None => return ProcessResult::Ok,
                    }
                } else {
                    return ProcessResult::Ok; // 0-RTT not supported, Retry handled elsewhere
                };
                (space, pn_offset)
            }
            PacketHeader::Short(short) => (2, short.pn_offset),
            PacketHeader::VersionNegotiation(_) => return ProcessResult::Ok,
        }
    };

    decrypt_and_process(conn, quic_payload, space, pn_offset, datagram_len, now)
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
        2 => conn.keys.one_rtt.as_ref().map(|kp| &kp.remote),
        _ => None,
    };
    let remote_key = match remote_key {
        Some(k) => k,
        None => return ProcessResult::Ok, // no keys for this space yet, drop
    };

    // Unprotect header (removes header protection, decodes truncated PN)
    let (truncated_pn, pn_length, payload_offset) =
        match unprotect_header(remote_key, quic_payload, pn_offset) {
            Ok(r) => r,
            Err(_) => {
                conn.failed_decryptions += 1;
                return ProcessResult::Ok;
            }
        };

    // Reconstruct full PN
    let largest_acked = conn.ack[space].largest_received().unwrap_or(0);
    let pn = decode_pn(largest_acked, truncated_pn, (pn_length * 8) as u32);

    // Check duplicate
    if conn.recv_pn_seen[space].is_duplicate(pn) {
        return ProcessResult::Ok;
    }

    // Decrypt payload — need copy for AAD (header bytes before payload)
    // Use stack buffer instead of heap allocation (max long header is ~60 bytes)
    let mut header_buf = [0u8; 64];
    let header_len = payload_offset.min(64);
    header_buf[..header_len].copy_from_slice(&quic_payload[..header_len]);
    let plaintext_len = match decrypt_payload(
        remote_key,
        pn,
        &header_buf[..header_len],
        &mut quic_payload[payload_offset..],
    ) {
        Ok(len) => len,
        Err(_) => {
            conn.failed_decryptions += 1;
            return ProcessResult::Ok;
        }
    };

    // Mark PN as seen
    conn.recv_pn_seen[space].mark(pn);

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

    // Check for key discard transitions
    if space == 1 && conn.keys.initial.is_some() {
        // First Handshake packet processed -> discard Initial keys
        conn.keys.initial = None;
        conn.loss.discard_space(0);
    }

    // Fix 6: Discard handshake keys when server receives a 1-RTT packet
    // (confirms client got the handshake)
    if space == 2 && conn.keys.handshake.is_some() {
        conn.keys.handshake = None;
        conn.loss.discard_space(1);
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
                    // PROTOCOL_VIOLATION: invalid frame for Initial/Handshake space
                    conn.state = ConnectionState::Closing;
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
                    return ProcessResult::ConnectionClosed;
                }
            }

            QuicFrame::MaxData(max) => {
                conn.flow.update_max_data_send(max);
            }

            QuicFrame::MaxStreamData { stream_id, max } => {
                if let Ok(entry) = conn.streams.get_or_create(stream_id) {
                    if let Some(ref mut send) = entry.send {
                        send.max_stream_data = send.max_stream_data.max(max);
                    }
                }
            }

            QuicFrame::MaxStreams { max, bidi } => {
                if bidi {
                    conn.streams.peer_max_bidi = conn.streams.peer_max_bidi.max(max);
                } else {
                    conn.streams.peer_max_uni = conn.streams.peer_max_uni.max(max);
                }
            }

            QuicFrame::ConnectionClose(_) => {
                conn.state = ConnectionState::Draining;
                return ProcessResult::ConnectionClosed;
            }

            QuicFrame::PathChallenge(data) => {
                conn.pending_path_response = Some(data);
            }

            QuicFrame::HandshakeDone => {
                // Client-side: transition to Established
                if conn.side == Side::Client {
                    conn.state = ConnectionState::Established;
                }
            }

            QuicFrame::NewConnectionId(_) => {
                // TODO: process via CidManager
            }

            QuicFrame::RetireConnectionId { .. } => {
                // TODO: deferred action via handler
            }

            _ => {} // other frames: skip for now
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
    let crypto_data = conn.crypto_recv[space].read_all().to_vec();
    if crypto_data.is_empty() {
        return;
    }

    let crypto = match conn.crypto.as_mut() {
        Some(c) => c,
        None => return,
    };

    let output = match crypto.process_crypto_data(&crypto_data) {
        Ok(o) => o,
        Err(_) => {
            conn.state = ConnectionState::Closing;
            return;
        }
    };

    conn.crypto_recv[space].drain(crypto_data.len());

    // Install new keys
    if let Some(hs_keys) = output.handshake_keys {
        conn.keys.handshake = Some(hs_keys);
    }
    if let Some(rtt_keys) = output.one_rtt_keys {
        conn.keys.one_rtt = Some(rtt_keys);
        // Store key update secrets for future key rotation (Fix 7)
        if let Some(secrets) = output.next_secrets {
            conn.key_update_secrets = Some(secrets);
        }
        if conn.side == Side::Server {
            conn.state = ConnectionState::Established;
            conn.send_handshake_done = true;
            conn.notify_established = true;
            conn.path.amplification.set_validated();
            conn.loss.handshake_confirmed = true;
            // Fix 6: DON'T discard handshake keys yet — wait until we
            // receive a 1-RTT packet (confirms client got the handshake).
            // Key discard happens in decrypt_and_process when space == 2.
        }
        // Notify socket layer: handshake complete
        conn.event_queue
            .push(crate::net::handler::quic::event::QuicEvent::HandshakeComplete);
    }

    // Queue response CRYPTO data
    if !output.crypto_data.is_empty() {
        let response_space = if conn.keys.one_rtt.is_some() {
            2
        } else if conn.keys.handshake.is_some() {
            1
        } else {
            0
        };
        conn.pending_crypto[response_space].extend_from_slice(&output.crypto_data);
    }

    // Apply peer transport parameters if available
    if conn.peer_params.is_none() {
        if let Some(crypto) = conn.crypto.as_ref() {
            if let Some(params_bytes) = crypto.peer_transport_parameters() {
                if let Ok(params) =
                    crate::net::handler::quic::transport::params::TransportParams::decode(
                        params_bytes,
                    )
                {
                    conn.flow.update_max_data_send(params.initial_max_data);
                    conn.streams.peer_max_bidi = params.initial_max_streams_bidi;
                    conn.streams.peer_max_uni = params.initial_max_streams_uni;
                    if params.max_idle_timeout_ms > 0 {
                        let peer_timeout =
                            coarsetime::Duration::from_millis(params.max_idle_timeout_ms);
                        if conn.idle_timeout > peer_timeout || conn.idle_timeout.as_millis() == 0 {
                            conn.idle_timeout = peer_timeout;
                        }
                    }
                    conn.max_udp_payload = (params.max_udp_payload_size as u16).max(1200);
                    conn.peer_params = Some(params);
                }
            }
        }
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
    let ack_delay = coarsetime::Duration::from_millis(ack_delay_us / 1000);
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

    // Update congestion for acked packets
    for pkt in &acked {
        conn.congestion.on_ack(
            pkt.size as usize,
            conn.loss.latest_rtt,
            conn.loss.min_rtt,
            now,
            pkt.in_flight,
            pkt.time_sent,
        );
    }

    // Handle lost packets
    if !lost.is_empty() {
        let frame_ranges: smallvec::SmallVec<[(u32, u32); 8]> =
            lost.iter().map(|(_, pkt)| pkt.frame_range).collect();

        // Fix 10: Single congestion event per loss round — use max sent_time
        let max_sent_time = lost.iter().map(|(_, pkt)| pkt.time_sent).max().unwrap();
        let total_lost_bytes: usize = lost.iter().map(|(_, pkt)| pkt.size as usize).sum();
        conn.congestion
            .on_congestion_event(total_lost_bytes, now, max_sent_time);

        // Fix 12: Check persistent congestion
        if conn.loss.first_rtt_sample.is_some() && lost.len() >= 2 {
            let max_ack_delay_pc = conn
                .peer_params
                .as_ref()
                .map(|p| coarsetime::Duration::from_millis(p.max_ack_delay_ms))
                .unwrap_or(coarsetime::Duration::from_millis(25));
            let pto = conn.loss.pto(2, max_ack_delay_pc);
            let earliest = lost.first().unwrap().1.time_sent;
            let latest = lost.last().unwrap().1.time_sent;
            let duration = latest.duration_since(earliest);
            if conn.congestion.in_persistent_congestion(duration, pto) {
                conn.congestion.on_persistent_congestion();
                conn.loss.reset_min_rtt(conn.loss.latest_rtt);
            }
        }

        let retransmit = build_retransmit_queue(&conn.frame_log, &frame_ranges);
        // Merge into conn.retransmit
        conn.retransmit
            .crypto
            .extend(retransmit.crypto.iter().cloned());
        conn.retransmit
            .streams
            .extend(retransmit.streams.iter().cloned());
        if retransmit.handshake_done {
            conn.retransmit.handshake_done = true;
        }
        if retransmit.max_data {
            conn.retransmit.max_data = true;
        }
    }
}

fn handle_stream_frame(
    conn: &mut QuicConnectionState,
    stream_id: StreamId,
    offset: u64,
    data: &[u8],
    fin: bool,
) -> Option<TransportError> {
    // Check if this is a new stream (not yet in the map)
    let is_new = conn.streams.get(stream_id).is_none();

    let entry = match conn.streams.get_or_create(stream_id) {
        Ok(e) => e,
        Err(_) => return Some(TransportError::STREAM_LIMIT_ERROR),
    };

    if let Some(ref mut recv) = entry.recv {
        match recv.receive(offset, data, fin) {
            Ok(new_bytes) => {
                // Only count genuinely new bytes against connection flow control
                if new_bytes > 0 {
                    if conn.flow.on_data_received(new_bytes as u64).is_err() {
                        return Some(TransportError::FLOW_CONTROL_ERROR);
                    }
                }
            }
            Err(_) => return Some(TransportError::FLOW_CONTROL_ERROR),
        }
    }

    // Notify socket layer
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
    (0..3u8).any(|s| has_pending_data(conn, s))
}

/// Check if a packet-number space has anything to send.
fn has_pending_data(conn: &QuicConnectionState, space: u8) -> bool {
    !conn.pending_crypto[space as usize].is_empty()
        || conn.ack[space as usize].needs_ack()
        || (space == 2 && conn.send_handshake_done)
        || conn.pending_path_response.is_some()
        || conn.needs_probe
        || (space == 2 && conn.streams.has_pending_send())
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

    // Fix 9: Closing state — send CONNECTION_CLOSE then transition to Draining
    if conn.state == ConnectionState::Closing {
        // TODO: Build CONNECTION_CLOSE packet and send it.
        // For now, transition directly to Draining.
        conn.state = ConnectionState::Draining;
        return;
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
            unsafe { frame.set_len(total_len) };
            conn.path.amplification.on_bytes_sent(total_len);
            tx_return.push(frame);
        } else {
            free_frames.push(frame); // return unused frame
        }
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
            false, // key_phase
            &conn.frame_log,
        ) {
            Some(b) => b,
            None => return 0,
        }
    };

    let mut wrote_ack_eliciting = false;

    // Write frames in priority order:

    // 1. CRYPTO data
    if !conn.pending_crypto[space as usize].is_empty() {
        let offset_val = conn.crypto_offset[space as usize];
        let data = &conn.pending_crypto[space as usize];
        let written = builder.write_crypto(offset_val, data, space, &mut conn.frame_log);
        if written > 0 {
            conn.crypto_offset[space as usize] += written as u64;
            wrote_ack_eliciting = true;
        }
    }

    // 2. ACK
    if conn.ack[space as usize].needs_ack() {
        if let Some(largest) = conn.ack[space as usize].largest_received() {
            // Fix 2: Compute actual ACK delay from largest_received_time
            let ack_delay =
                if let Some(recv_time) = conn.ack[space as usize].largest_received_time() {
                    let delay = now.duration_since(recv_time);
                    let exponent = conn.local_params.ack_delay_exponent;
                    // Encode: delay_us / 2^exponent
                    (delay.as_millis() * 1000) / (1u64 << exponent)
                } else {
                    0
                };
            let first_ack_range = conn.ack[space as usize].first_ack_range();
            let ack_range_count = conn.ack[space as usize].ack_range_count();
            let encoded_ranges = conn.ack[space as usize].encoded_ranges().to_vec();
            builder.write_ack(
                largest,
                ack_delay,
                first_ack_range,
                ack_range_count,
                &encoded_ranges,
                &mut conn.frame_log,
                space,
            );
            conn.ack[space as usize].ack_sent();
        }
    }

    // 3. HANDSHAKE_DONE (server, 1-RTT space only)
    if space == 2 && conn.send_handshake_done && conn.side == Side::Server {
        if builder.write_handshake_done(&mut conn.frame_log) {
            conn.send_handshake_done = false;
            wrote_ack_eliciting = true;
        }
    }

    // 4. PATH_RESPONSE
    if space == 2 {
        if let Some(data) = conn.pending_path_response.take() {
            if builder.write_path_response(data) {
                wrote_ack_eliciting = true;
            } else {
                // Couldn't fit; put it back
                conn.pending_path_response = Some(data);
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
            if let Some(entry) = conn.streams.get_mut(stream_id) {
                if let Some(ref mut send) = entry.send {
                    let data_len = send
                        .buffer
                        .len()
                        .min(builder.remaining().saturating_sub(20))
                        .min(1500); // Fix 23: Cap to stack buffer size
                    let mut temp = [0u8; 1500];
                    let read = send.buffer.read(&mut temp[..data_len]);
                    let fin = send.fin_sent && send.buffer.is_empty();
                    if read > 0 || fin {
                        let written = builder.write_stream(
                            stream_id,
                            send.sent,
                            &temp[..read],
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
    }

    // 7. Initial padding — Initial packets must be at least 1200 bytes total
    // Fix 15: The 1200-byte minimum is for the UDP datagram (UDP header + QUIC payload)
    if space == 0 {
        let min_quic_size = 1200usize.saturating_sub(UDP_HEADER_LEN);
        builder.pad_to(min_quic_size);
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
            conn.packets_encrypted += 1;

            // Build Ethernet + IP + UDP headers
            write_transport_headers(conn, frame, quic_offset, protected_len)
        }
        Err(_) => 0,
    }
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
    if matches!(conn.local_addr, IpAddress::V6(_)) {
        // TODO: Compute proper UDP checksum over IPv6 pseudo-header + UDP payload.
        // Setting 0xFFFF as a placeholder — a proper implementation should compute
        // the full checksum over the IPv6 pseudo-header + UDP header + payload.
        let udp_mut = unsafe { UdpHeader::from_bytes_at_mut(frame, udp_offset) };
        udp_mut.checksum = [0xFF, 0xFF];
    }

    total_frame_len
}
