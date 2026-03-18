use coarsetime::Instant;

use crate::{
    net::{NeighborHandler, timer_wheel::TimerWheel, wire::tcp::flags},
    xdp::frame::FrameBuffer,
};

use super::{
    TcpHandler,
    handler::{INITIAL_RTO_MS, SYN_R2_THRESHOLD_MS},
    segment::SegmentBuilder,
    send_tracker::SendReady,
    state::TcpState,
    tcb::{DEFAULT_RCV_MSS, DEFAULT_RCV_WND, DEFAULT_RCV_WSCALE, TcpEvent},
    timer_kinds::TcpTimerKind,
};

impl TcpHandler {
    // --- Individual fire_* methods for timer-wheel dispatch ---

    /// Fire a delayed ACK for a single connection identified by slab key.
    ///
    /// Sends a pure ACK if the connection has a pending ACK, then clears
    /// the delayed-ACK state. If the connection doesn't exist or has no
    /// pending ACK, this is a no-op.
    #[inline]
    pub fn fire_delayed_ack<'umem>(
        &mut self,
        key: usize,
        now: Instant,
        src_mac: crate::net::wire::ethernet::MacAddress,
        neighbor_handler: &NeighborHandler,
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        // Clear the handle — this timer has fired.
        self.timer_handles[key].clear(TcpTimerKind::DelayedAck);

        let Some(tcb) = self.connections.get_mut(key) else {
            return;
        };
        if !tcb.ack_pending {
            return;
        }

        let tsval = if tcb.ts_enabled {
            now.duration_since(tcb.ts_offset).as_millis() as u32
        } else {
            0
        };

        let id = tcb.id;
        let Some(dst_mac) = neighbor_handler.lookup_or_resolve(
            now,
            &id.remote_addr,
            &id.local_addr,
            free_frames,
            rx_return,
            tx_return,
        ) else {
            // Neighbor resolution pending — mark for poll_send to retry.
            self.send_tracker.mark(SendReady(key));
            return;
        };

        let ts = tcb.ts_option(tsval);
        let ack_flags = if tcb.ecn_ce_received {
            flags::ACK | flags::ECE
        } else {
            flags::ACK
        };
        SegmentBuilder::build_ack(
            id.local_addr,
            id.remote_addr,
            id.local_port,
            id.remote_port,
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
    }

    /// Fire an RTO retransmit for a single connection identified by slab key.
    ///
    /// Handles R2 threshold checks, SYN/SYN-ACK/Established/FIN retransmit,
    /// and exponential backoff. If the R2 threshold is exceeded, the connection
    /// is removed.
    #[inline]
    pub fn fire_retransmit<'umem>(
        &mut self,
        key: usize,
        now: Instant,
        wheel: &mut TimerWheel,
        src_mac: crate::net::wire::ethernet::MacAddress,
        neighbor_handler: &NeighborHandler,
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        // Clear the handle — this timer has fired.
        self.timer_handles[key].clear(TcpTimerKind::Retransmit);

        let Some(tcb) = self.connections.get_mut(key) else {
            return;
        };

        let tsval = if tcb.ts_enabled {
            now.duration_since(tcb.ts_offset).as_millis() as u32
        } else {
            0
        };

        // Check R2 threshold.
        let total_elapsed_ms = {
            let base_rto = INITIAL_RTO_MS;
            let mut total: u64 = 0;
            for i in 0..=tcb.rto_backoff {
                total += base_rto << i;
            }
            total
        };

        if total_elapsed_ms >= SYN_R2_THRESHOLD_MS {
            // Timeout — signal and remove.
            tcb.event_queue.push(TcpEvent::Timeout);
            if let Some(tcb) = self.connections.get(key) {
                Self::decrement_syn_received(&mut self.listeners, &tcb.id);
            }
            self.send_tracker.unmark(key);
            self.timer_handles[key].cancel_all(wheel);
            self.remove_connection_by_key(key);
            return;
        }

        // Resolve neighbor.
        let id = tcb.id;
        let Some(dst_mac) = neighbor_handler.lookup_or_resolve(
            now,
            &id.remote_addr,
            &id.local_addr,
            free_frames,
            rx_return,
            tx_return,
        ) else {
            // Re-arm retransmit timer so we retry after the solicitation completes.
            self.timer_handles[key].arm(
                TcpTimerKind::Retransmit,
                key,
                now + coarsetime::Duration::from_millis(tcb.rto),
                wheel,
            );
            return;
        };

        let mut syn_sent = false;
        match tcb.state {
            TcpState::SynSent => {
                let ts_opt = if tcb.ts_enabled {
                    Some((tsval, 0u32))
                } else {
                    None
                };
                let sent = SegmentBuilder::build_syn(
                    id.local_addr,
                    id.remote_addr,
                    id.local_port,
                    id.remote_port,
                    tcb.iss,
                    DEFAULT_RCV_WND,
                    DEFAULT_RCV_MSS,
                    DEFAULT_RCV_WSCALE,
                    ts_opt,
                    tcb.sack_enabled,
                    tcb.ecn_enabled,
                    src_mac,
                    dst_mac,
                    self.tx_offload,
                    free_frames,
                    tx_return,
                );
                if !sent {
                    self.timer_handles[key].arm(
                        TcpTimerKind::Retransmit,
                        key,
                        now + coarsetime::Duration::from_millis(INITIAL_RTO_MS),
                        wheel,
                    );
                    return;
                }
                syn_sent = true;
            }
            TcpState::SynReceived => {
                let wscale_opt = if tcb.wscale_enabled {
                    Some(tcb.rcv_wscale)
                } else {
                    None
                };
                let ts_opt = tcb.ts_option(tsval);
                let sent = SegmentBuilder::build_syn_ack(
                    id.local_addr,
                    id.remote_addr,
                    id.local_port,
                    id.remote_port,
                    tcb.iss,
                    tcb.rcv_nxt,
                    DEFAULT_RCV_WND,
                    tcb.rcv_mss,
                    wscale_opt,
                    ts_opt,
                    tcb.sack_enabled,
                    tcb.ecn_enabled,
                    src_mac,
                    dst_mac,
                    self.tx_offload,
                    free_frames,
                    tx_return,
                );
                if !sent {
                    self.timer_handles[key].arm(
                        TcpTimerKind::Retransmit,
                        key,
                        now + coarsetime::Duration::from_millis(INITIAL_RTO_MS),
                        wheel,
                    );
                    return;
                }
                syn_sent = true;
            }
            TcpState::Established => {
                let retransmit_len = tcb.send_buffer.available().min(tcb.eff_snd_mss as usize);
                if retransmit_len > 0 {
                    let payload = tcb.send_buffer.peek_slices(0, retransmit_len);
                    let ts = tcb.ts_option(tsval);
                    let sent = SegmentBuilder::build_data_from_slices(
                        id.local_addr,
                        id.remote_addr,
                        id.local_port,
                        id.remote_port,
                        tcb.snd_una,
                        tcb.rcv_nxt,
                        tcb.advertised_window(),
                        payload,
                        flags::ACK,
                        false, // retransmits don't get ECT per RFC 3168 §6.1.5
                        ts,
                        src_mac,
                        dst_mac,
                        self.tx_offload,
                        free_frames,
                        tx_return,
                    );
                    if !sent {
                        // No frame available — re-arm timer to retry without
                        // corrupting congestion state.
                        self.timer_handles[key].arm(
                            TcpTimerKind::Retransmit,
                            key,
                            now + coarsetime::Duration::from_millis(tcb.rto),
                            wheel,
                        );
                        self.send_tracker.mark(SendReady(key));
                        return;
                    }
                }
                // F-RTO + CUBIC RTO response.
                tcb.frto.enter(tcb.snd_una);
                tcb.cubic.on_rto();
                tcb.recovery.exit();
                tcb.sack_scoreboard.clear();
                tcb.rto_backoff += 1;
                self.timer_handles[key].arm(
                    TcpTimerKind::Retransmit,
                    key,
                    now + coarsetime::Duration::from_millis(tcb.rto << tcb.rto_backoff),
                    wheel,
                );
                // Mark for poll_send — may have more data to send after RTO.
                self.send_tracker.mark(SendReady(key));
            }
            TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck => {
                // Retransmit FIN-ACK.
                let ts = tcb.ts_option(tsval);
                if let Some(fin_seq) = tcb.fin_seq {
                    SegmentBuilder::build_fin_ack(
                        id.local_addr,
                        id.remote_addr,
                        id.local_port,
                        id.remote_port,
                        fin_seq,
                        tcb.rcv_nxt,
                        tcb.advertised_window(),
                        ts,
                        src_mac,
                        dst_mac,
                        self.tx_offload,
                        free_frames,
                        tx_return,
                    );
                }
                // Exponential backoff (same as Established).
                tcb.rto_backoff += 1;
                self.timer_handles[key].arm(
                    TcpTimerKind::Retransmit,
                    key,
                    now + coarsetime::Duration::from_millis(tcb.rto << tcb.rto_backoff),
                    wheel,
                );
            }
            _ => return,
        }

        // Exponential backoff for SYN/SYN-ACK states.
        if syn_sent {
            tcb.rto_backoff += 1;
            let rto = INITIAL_RTO_MS << tcb.rto_backoff;
            self.timer_handles[key].arm(
                TcpTimerKind::Retransmit,
                key,
                now + coarsetime::Duration::from_millis(rto),
                wheel,
            );
        }
    }

    /// Fire a keep-alive probe for a single connection identified by slab key.
    ///
    /// Sends a keep-alive probe (seq = snd_una - 1) if the connection has been
    /// idle long enough. If max probes are exceeded, the connection is aborted.
    #[inline]
    pub fn fire_keep_alive<'umem>(
        &mut self,
        key: usize,
        now: Instant,
        wheel: &mut TimerWheel,
        src_mac: crate::net::wire::ethernet::MacAddress,
        neighbor_handler: &NeighborHandler,
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        // Clear the handle — this timer has fired.
        self.timer_handles[key].clear(TcpTimerKind::KeepAlive);

        let Some(tcb) = self.connections.get_mut(key) else {
            return;
        };
        if tcb.state != TcpState::Established || !tcb.keep_alive_enabled {
            return;
        }

        if tcb.keep_alive_probes_sent >= tcb.keep_alive_count {
            // Max probes exceeded — abort connection.
            tcb.event_queue.push(TcpEvent::Timeout);
            if let Some(tcb) = self.connections.get(key) {
                Self::decrement_syn_received(&mut self.listeners, &tcb.id);
            }
            self.send_tracker.unmark(key);
            self.timer_handles[key].cancel_all(wheel);
            self.remove_connection_by_key(key);
            return;
        }

        let tsval = if tcb.ts_enabled {
            now.duration_since(tcb.ts_offset).as_millis() as u32
        } else {
            0
        };

        // Send keep-alive probe: seq = snd_una - 1, no data, ACK.
        let id = tcb.id;
        let Some(dst_mac) = neighbor_handler.lookup_or_resolve(
            now,
            &id.remote_addr,
            &id.local_addr,
            free_frames,
            rx_return,
            tx_return,
        ) else {
            // Re-arm for retry.
            self.timer_handles[key].arm(
                TcpTimerKind::KeepAlive,
                key,
                now + coarsetime::Duration::from_millis(tcb.keep_alive_interval_ms),
                wheel,
            );
            return;
        };
        let ts = tcb.ts_option(tsval);
        let ack_flags = if tcb.ecn_ce_received {
            flags::ACK | flags::ECE
        } else {
            flags::ACK
        };
        SegmentBuilder::build_ack(
            id.local_addr,
            id.remote_addr,
            id.local_port,
            id.remote_port,
            tcb.snd_una.wrapping_sub(1),
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

        tcb.keep_alive_probes_sent += 1;

        // Re-arm for next probe interval.
        self.timer_handles[key].arm(
            TcpTimerKind::KeepAlive,
            key,
            now + coarsetime::Duration::from_millis(tcb.keep_alive_interval_ms),
            wheel,
        );
    }

    /// Fire a zero-window (persist) probe for a single connection identified by slab key.
    ///
    /// Sends a 1-byte probe when the persist deadline has expired and the peer's
    /// advertised window is zero. Applies exponential backoff capped at 60 seconds.
    #[inline]
    pub fn fire_persist<'umem>(
        &mut self,
        key: usize,
        now: Instant,
        wheel: &mut TimerWheel,
        src_mac: crate::net::wire::ethernet::MacAddress,
        neighbor_handler: &NeighborHandler,
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        // Clear the handle — this timer has fired.
        self.timer_handles[key].clear(TcpTimerKind::Persist);

        let Some(tcb) = self.connections.get_mut(key) else {
            return;
        };

        let send_window = (tcb.snd_wnd as usize).min(tcb.cubic.cwnd as usize);
        let bytes_in_flight = tcb.snd_nxt.wrapping_sub(tcb.snd_una) as usize;
        let data_available = tcb.send_buffer.available().saturating_sub(bytes_in_flight);

        if send_window != 0 || data_available == 0 {
            return;
        }

        let tsval = if tcb.ts_enabled {
            now.duration_since(tcb.ts_offset).as_millis() as u32
        } else {
            0
        };

        let mut probe = [0u8; 1];
        tcb.send_buffer.peek_at(bytes_in_flight, &mut probe);

        let id = tcb.id;
        let Some(dst_mac) = neighbor_handler.lookup_or_resolve(
            now,
            &id.remote_addr,
            &id.local_addr,
            free_frames,
            rx_return,
            tx_return,
        ) else {
            // Neighbor resolution pending — mark for poll_send to retry.
            self.send_tracker.mark(SendReady(key));
            return;
        };

        let ts = tcb.ts_option(tsval);
        let sent = SegmentBuilder::build_data(
            id.local_addr,
            id.remote_addr,
            id.local_port,
            id.remote_port,
            tcb.snd_nxt,
            tcb.rcv_nxt,
            tcb.advertised_window(),
            &probe,
            ts,
            src_mac,
            dst_mac,
            self.tx_offload,
            free_frames,
            tx_return,
        );

        if !sent {
            // No frame available — re-arm persist at base interval to retry.
            self.timer_handles[key].arm(
                TcpTimerKind::Persist,
                key,
                now + coarsetime::Duration::from_millis(tcb.rto),
                wheel,
            );
            return;
        }

        tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);

        // Schedule next probe with exponential backoff, capped at 60s.
        let backoff_ms = (tcb.rto << tcb.persist_backoff).min(60_000);
        self.timer_handles[key].arm(
            TcpTimerKind::Persist,
            key,
            now + coarsetime::Duration::from_millis(backoff_ms),
            wheel,
        );
        tcb.persist_backoff = tcb.persist_backoff.saturating_add(1).min(6);
    }

    /// Fire linger timeout for a single connection identified by slab key.
    ///
    /// If the connection has a pending FIN and the linger deadline has expired,
    /// sends a RST to the peer and marks the connection for removal.
    #[inline]
    pub fn fire_linger<'umem>(
        &mut self,
        key: usize,
        now: Instant,
        wheel: &mut TimerWheel,
        src_mac: crate::net::wire::ethernet::MacAddress,
        neighbor_handler: &NeighborHandler,
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        // Clear the handle — this timer has fired.
        self.timer_handles[key].clear(TcpTimerKind::Linger);

        let Some(tcb) = self.connections.get_mut(key) else {
            return;
        };

        if !tcb.pending_fin {
            return;
        }

        // Send RST to peer.
        let id = tcb.id;
        let Some(dst_mac) = neighbor_handler.lookup_or_resolve(
            now,
            &id.remote_addr,
            &id.local_addr,
            free_frames,
            rx_return,
            tx_return,
        ) else {
            // Neighbor resolution pending — mark for poll_send to retry.
            self.send_tracker.mark(SendReady(key));
            return;
        };

        // Use build_rst by simulating an "incoming ACK" segment.
        // This produces: <SEQ=SEG.ACK><CTL=RST> = <SEQ=snd_nxt><CTL=RST>
        SegmentBuilder::build_rst(
            id.remote_addr,
            id.local_addr, // swapped: "incoming" from remote
            id.remote_port,
            id.local_port, // swapped
            0,
            tcb.snd_nxt, // incoming_seq=0, incoming_ack=snd_nxt
            flags::ACK,  // pretend incoming has ACK set
            0,           // seg_len doesn't matter
            src_mac,
            dst_mac,
            self.tx_offload,
            free_frames,
            tx_return,
        );

        tcb.event_queue.push(TcpEvent::Reset);
        tcb.state = TcpState::Closed;
        tcb.pending_fin = false;

        self.send_tracker.unmark(key);
        self.timer_handles[key].cancel_all(wheel);
        self.remove_connection_by_key(key);
    }

    /// Fire TIME-WAIT expiry for a single connection identified by slab key.
    ///
    /// Removes the connection if it is in TimeWait state. No packet is sent.
    #[inline]
    pub fn fire_time_wait(&mut self, key: usize, wheel: &mut TimerWheel) {
        // Clear the handle — this timer has fired.
        self.timer_handles[key].clear(TcpTimerKind::TimeWait);

        let Some(tcb) = self.connections.get(key) else {
            return;
        };
        if tcb.state != TcpState::TimeWait {
            return;
        }
        self.send_tracker.unmark(key);
        self.timer_handles[key].cancel_all(wheel);
        self.remove_connection_by_key(key);
    }

    /// Dispatch a timer firing for a single connection by kind.
    ///
    /// Routes to the appropriate `fire_*` method based on `TcpTimerKind`.
    #[inline]
    pub fn handle_timer<'umem>(
        &mut self,
        key: usize,
        kind: TcpTimerKind,
        now: Instant,
        wheel: &mut TimerWheel,
        src_mac: crate::net::wire::ethernet::MacAddress,
        neighbor_handler: &NeighborHandler,
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        // Guard: if a prior fire_* in this advance() batch already removed the
        // connection (e.g. R2 timeout), the timer_handles entry is gone. Skip.
        if !self.timer_handles.contains(key) {
            return;
        }
        match kind {
            TcpTimerKind::DelayedAck => {
                self.fire_delayed_ack(
                    key,
                    now,
                    src_mac,
                    neighbor_handler,
                    free_frames,
                    rx_return,
                    tx_return,
                );
            }
            TcpTimerKind::Retransmit => {
                self.fire_retransmit(
                    key,
                    now,
                    wheel,
                    src_mac,
                    neighbor_handler,
                    free_frames,
                    rx_return,
                    tx_return,
                );
            }
            TcpTimerKind::KeepAlive => {
                self.fire_keep_alive(
                    key,
                    now,
                    wheel,
                    src_mac,
                    neighbor_handler,
                    free_frames,
                    rx_return,
                    tx_return,
                );
            }
            TcpTimerKind::Persist => {
                self.fire_persist(
                    key,
                    now,
                    wheel,
                    src_mac,
                    neighbor_handler,
                    free_frames,
                    rx_return,
                    tx_return,
                );
            }
            TcpTimerKind::Linger => {
                self.fire_linger(
                    key,
                    now,
                    wheel,
                    src_mac,
                    neighbor_handler,
                    free_frames,
                    rx_return,
                    tx_return,
                );
            }
            TcpTimerKind::TimeWait => {
                self.fire_time_wait(key, wheel);
            }
        }
    }
}
