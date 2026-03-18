use coarsetime::Instant;
use smallvec::SmallVec;

use crate::{
    net::{NeighborHandler, timer_wheel::TimerWheel, wire::tcp::flags},
    xdp::frame::FrameBuffer,
};

use super::{
    TcpHandler, segment::SegmentBuilder, send_tracker::SendReady, state::TcpState,
    tcb::MAX_DELAYED_ACK_COUNT, timer_kinds::TcpTimerKind,
};

impl TcpHandler {
    // --- Data transmission ---

    /// Poll connections with pending send work for outbound data segments.
    /// Called each tick from the runtime loop after receive processing.
    /// Only iterates connections tracked by the SendTracker.
    pub fn poll_send<'umem>(
        &mut self,
        now: Instant,
        wheel: &mut TimerWheel,
        src_mac: crate::net::wire::ethernet::MacAddress,
        neighbor_handler: &NeighborHandler,
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        self.send_tracker.swap();
        let mut closed: SmallVec<[usize; 4]> = SmallVec::new();
        while let Some(key) = self.send_tracker.pop_active() {
            let Some(tcb) = self.connections.get_mut(key) else {
                continue; // connection was removed
            };
            if tcb.state != TcpState::Established && tcb.state != TcpState::CloseWait {
                continue;
            }

            let tsval = if tcb.ts_enabled {
                now.duration_since(tcb.ts_offset).as_millis() as u32
            } else {
                0
            };

            // Send as many segments as the window allows.
            loop {
                let bytes_in_flight = tcb.snd_nxt.wrapping_sub(tcb.snd_una) as usize;
                let data_available = tcb.send_buffer.available().saturating_sub(bytes_in_flight);

                let can_send = if tcb.recovery.in_recovery {
                    tcb.recovery.set_pipe(
                        tcb.snd_una,
                        tcb.snd_nxt,
                        &tcb.sack_scoreboard,
                        tcb.eff_snd_mss,
                    );
                    let pipe = tcb.recovery.pipe as usize;
                    let cwnd = tcb.cubic.cwnd as usize;
                    if pipe < cwnd {
                        (cwnd - pipe).min(tcb.eff_snd_mss as usize)
                    } else {
                        0
                    }
                } else {
                    // Limited Transmit (RFC 3042): inflate effective cwnd by
                    // dup_ack_count * MSS on the 1st/2nd dup ACK.
                    let effective_cwnd = if tcb.recovery.dup_ack_count > 0
                        && tcb.recovery.dup_ack_count <= 2
                        && !tcb.recovery.in_recovery
                    {
                        tcb.cubic.cwnd as usize
                            + tcb.recovery.dup_ack_count as usize * tcb.eff_snd_mss as usize
                    } else {
                        tcb.cubic.cwnd as usize
                    };
                    let send_window = (tcb.snd_wnd as usize).min(effective_cwnd);
                    send_window.saturating_sub(bytes_in_flight)
                };

                if can_send == 0 || data_available == 0 {
                    break;
                }

                // Sender SWS avoidance (MUST-38): don't send sub-MSS data unless
                // the usable window is large enough or all remaining data fits.
                let sws_ok = can_send >= tcb.eff_snd_mss as usize
                    || can_send >= (tcb.max_snd_wnd as usize / 2).max(1)
                    || data_available <= can_send;
                if !sws_ok {
                    break;
                }

                let to_send = can_send.min(data_available).min(tcb.eff_snd_mss as usize);

                // Nagle algorithm: hold small segments when data is in flight.
                if tcb.nagle_enabled && bytes_in_flight > 0 && to_send < tcb.eff_snd_mss as usize {
                    break;
                }

                // Peek the data from the send buffer (don't advance — held until ACKed).
                let payload = tcb.send_buffer.peek_slices(bytes_in_flight, to_send);

                let Some(dst_mac) = neighbor_handler.lookup_or_resolve(
                    now,
                    &tcb.id.remote_addr,
                    &tcb.id.local_addr,
                    free_frames,
                    rx_return,
                    tx_return,
                ) else {
                    break; // exit inner loop — TCP retransmit will retry later
                };

                let ts = tcb.ts_option(tsval);
                let remaining_after_send = data_available.saturating_sub(to_send);
                let mut data_flags = if remaining_after_send == 0 || to_send >= can_send {
                    flags::ACK | flags::PSH
                } else {
                    flags::ACK
                };
                if tcb.ecn_ce_received {
                    data_flags |= flags::ECE;
                }
                if tcb.ecn_cwr_sent {
                    data_flags |= flags::CWR;
                }
                SegmentBuilder::build_data_from_slices(
                    tcb.id.local_addr,
                    tcb.id.remote_addr,
                    tcb.id.local_port,
                    tcb.id.remote_port,
                    tcb.snd_nxt,
                    tcb.rcv_nxt,
                    tcb.advertised_window(),
                    payload,
                    data_flags,
                    tcb.ecn_enabled,
                    ts,
                    src_mac,
                    dst_mac,
                    self.tx_offload,
                    free_frames,
                    tx_return,
                );

                tcb.snd_nxt = tcb.snd_nxt.wrapping_add(to_send as u32);
                tcb.last_send_time = Some(now);

                // Reset keep-alive timer on sent data.
                tcb.last_activity = now;
                tcb.keep_alive_probes_sent = 0;

                // Set retransmit timer if not already running.
                if !self.timer_handles[key].is_armed(TcpTimerKind::Retransmit) {
                    self.timer_handles[key].arm(
                        TcpTimerKind::Retransmit,
                        key,
                        now + coarsetime::Duration::from_millis(tcb.rto),
                        wheel,
                    );
                }

                // Clear CWR after sending (only needs to be on one segment).
                if tcb.ecn_cwr_sent {
                    tcb.ecn_cwr_sent = false;
                }

                // Piggyback: data segment carries ACK, so clear delayed ACK state.
                tcb.update_advertised_edge();
                tcb.ack_pending = false;
                tcb.ack_delay_count = 0;
                self.timer_handles[key].cancel_timer(TcpTimerKind::DelayedAck, wheel);
            }

            // Delayed ACK fallback: if the data send loop didn't piggyback an ACK
            // and enough segments have arrived to require an immediate ACK, send a
            // pure ACK now. This defers ACK generation from inbound processing to
            // give data segments a chance to piggyback the ACK first.
            if tcb.ack_pending && tcb.ack_delay_count >= MAX_DELAYED_ACK_COUNT {
                let Some(dst_mac) = neighbor_handler.lookup_or_resolve(
                    now,
                    &tcb.id.remote_addr,
                    &tcb.id.local_addr,
                    free_frames,
                    rx_return,
                    tx_return,
                ) else {
                    // Neighbor resolution pending — re-mark for next tick.
                    self.send_tracker.mark(SendReady(key));
                    continue; // skip to next connection
                };

                let ts = tcb.ts_option(tsval);
                let mut ack_flags = flags::ACK;
                if tcb.ecn_ce_received {
                    ack_flags |= flags::ECE;
                }
                SegmentBuilder::build_ack(
                    tcb.id.local_addr,
                    tcb.id.remote_addr,
                    tcb.id.local_port,
                    tcb.id.remote_port,
                    tcb.snd_nxt,
                    tcb.rcv_nxt,
                    tcb.advertised_window(),
                    ack_flags,
                    ts,
                    src_mac,
                    dst_mac,
                    self.tx_offload,
                    free_frames,
                    tx_return,
                );
                tcb.update_advertised_edge();
                tcb.ack_pending = false;
                tcb.ack_delay_count = 0;
                self.timer_handles[key].cancel_timer(TcpTimerKind::DelayedAck, wheel);
            }

            // --- Zero-window probing (persist timer) ---
            // Recompute state after the send loop for persist timer and FIN checks.
            let bytes_in_flight = tcb.snd_nxt.wrapping_sub(tcb.snd_una) as usize;
            let data_available = tcb.send_buffer.available().saturating_sub(bytes_in_flight);
            let send_window = (tcb.snd_wnd as usize).min(tcb.cubic.cwnd as usize);

            // A. Arm persist timer when peer advertises window=0 and we have data to send.
            if send_window == 0
                && data_available > 0
                && !self.timer_handles[key].is_armed(TcpTimerKind::Persist)
            {
                self.timer_handles[key].arm(
                    TcpTimerKind::Persist,
                    key,
                    now + coarsetime::Duration::from_millis(tcb.rto),
                    wheel,
                );
            }

            // After data sending: check if we should send FIN.
            if tcb.pending_fin {
                let bytes_in_flight = tcb.snd_nxt.wrapping_sub(tcb.snd_una) as usize;
                let data_available = tcb.send_buffer.available().saturating_sub(bytes_in_flight);

                // Only send FIN when all data has been sent and ACKed.
                if data_available == 0 && bytes_in_flight == 0 {
                    let id = tcb.id;
                    let Some(dst_mac) = neighbor_handler.lookup_or_resolve(
                        now,
                        &tcb.id.remote_addr,
                        &tcb.id.local_addr,
                        free_frames,
                        rx_return,
                        tx_return,
                    ) else {
                        // Neighbor resolution pending — re-mark for next tick.
                        self.send_tracker.mark(SendReady(key));
                        continue; // skip to next connection
                    };

                    let ts = tcb.ts_option(tsval);
                    SegmentBuilder::build_fin_ack(
                        id.local_addr,
                        id.remote_addr,
                        id.local_port,
                        id.remote_port,
                        tcb.snd_nxt,
                        tcb.rcv_nxt,
                        tcb.advertised_window(),
                        ts,
                        src_mac,
                        dst_mac,
                        self.tx_offload,
                        free_frames,
                        tx_return,
                    );

                    tcb.fin_seq = Some(tcb.snd_nxt);
                    tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1); // FIN consumes one sequence number

                    tcb.pending_fin = false;

                    match tcb.state {
                        TcpState::Established => tcb.state = TcpState::FinWait1,
                        TcpState::CloseWait => tcb.state = TcpState::LastAck,
                        _ => {}
                    }

                    // Set retransmit timer for FIN.
                    if !self.timer_handles[key].is_armed(TcpTimerKind::Retransmit) {
                        self.timer_handles[key].arm(
                            TcpTimerKind::Retransmit,
                            key,
                            now + coarsetime::Duration::from_millis(tcb.rto),
                            wheel,
                        );
                    }
                }
            }

            // Re-add to tracker if this connection still has pending work.
            if let Some(tcb) = self.connections.get(key) {
                let bytes_in_flight = tcb.snd_nxt.wrapping_sub(tcb.snd_una) as usize;
                let has_data = tcb.send_buffer.available().saturating_sub(bytes_in_flight) > 0;
                let has_work = has_data
                    || tcb.ack_pending
                    || tcb.pending_fin
                    || self.timer_handles[key].is_armed(TcpTimerKind::Persist)
                    || self.timer_handles[key].is_armed(TcpTimerKind::Retransmit);
                if has_work {
                    self.send_tracker.mark(SendReady(key));
                }
            }
        }

        // Remove connections aborted by linger deadline.
        for key in &closed {
            self.send_tracker.unmark(*key);
            self.timer_handles[*key].cancel_all(wheel);
            self.remove_connection_by_key(*key);
        }
    }
}
