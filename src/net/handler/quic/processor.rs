use coarsetime::Instant;

use crate::net::congestion::CongestionController;
use crate::net::handler::quic::connection::{ConnectionState, QuicConnectionState, Side};
use crate::net::handler::quic::crypto::packet_protection::{decrypt_payload, unprotect_header};
use crate::net::handler::quic::packet_parser::{self, packet_space};
use crate::net::handler::quic::transport::ack::AckState;
use crate::net::handler::quic::transport::frame::{self, QuicFrame, StreamId};
use crate::net::handler::quic::transport::packet_number::decode_pn;
use crate::net::handler::quic::transport::retransmit::build_retransmit_queue;
use crate::net::wire::quic::{self as wire_quic, PacketHeader, PacketType};

pub enum ProcessResult {
    Ok,
    ConnectionClosed,
    VersionNegotiation,
    StatelessReset,
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
    let dcid_len = conn.dcid.len();

    // Extract (space, pn_offset) from the header using an immutable borrow,
    // then release the borrow before passing quic_payload mutably.
    let (space, pn_offset) = {
        let (header, _header_len) = match wire_quic::parse_header(quic_payload, dcid_len) {
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
    let header_bytes = quic_payload[..payload_offset].to_vec();
    let plaintext_len = match decrypt_payload(
        remote_key,
        pn,
        &header_bytes,
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

    // Update amplification tracking
    conn.path.amplification.on_bytes_received(datagram_len);

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
            Err(_) => break,
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
                _ => continue, // invalid frame for this space, skip
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
                handle_stream_frame(
                    conn,
                    stream.stream_id,
                    stream.offset,
                    stream.data,
                    stream.fin,
                );
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
        if conn.side == Side::Server {
            conn.state = ConnectionState::Established;
            conn.send_handshake_done = true;
            conn.path.amplification.set_validated();
            // Discard handshake keys after installing 1-RTT
            conn.keys.handshake = None;
            conn.loss.discard_space(1);
        }
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
    let ack_delay = coarsetime::Duration::from_millis(ack.ack_delay);
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

        for (_, pkt) in &lost {
            conn.congestion
                .on_congestion_event(pkt.size as usize, now, pkt.time_sent);
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
) {
    // For received STREAM frames, the stream is peer-initiated (not local)
    let _is_local = match conn.side {
        Side::Server => !stream_id.initiator_is_client(), // server-initiated = local
        Side::Client => stream_id.initiator_is_client(),  // client-initiated = local
    };

    let entry = match conn.streams.get_or_create(stream_id) {
        Ok(e) => e,
        Err(_) => return, // stream limit exceeded
    };

    if let Some(ref mut recv) = entry.recv {
        // Connection-level flow control check
        if conn.flow.on_data_received(data.len() as u64).is_err() {
            // FLOW_CONTROL_ERROR — should close connection
            return;
        }
        let _ = recv.receive(offset, data, fin);
    }
}
