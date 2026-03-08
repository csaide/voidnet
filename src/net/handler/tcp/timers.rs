use coarsetime::Instant;

use crate::{
    net::{
        NeighborHandler,
        wire::tcp::flags,
    },
    xdp::frame::FrameBuffer,
};

use super::{
    segment::SegmentBuilder,
    state::TcpState,
    tcb::{DEFAULT_RCV_MSS, DEFAULT_RCV_WND, DEFAULT_RCV_WSCALE, TcpEvent},
    TcpHandler, INITIAL_RTO_MS, SYN_R2_THRESHOLD_MS,
};

impl TcpHandler {
    // --- Timer polling ---

    /// Poll retransmission timers for SYN/SYN-ACK retransmission.
    pub fn poll_timers<'umem>(
        &mut self,
        now: Instant,
        src_mac: crate::net::wire::ethernet::MacAddress,
        neighbor_handler: &NeighborHandler,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        // Delayed ACK pass — flush pending ACKs whose deadline has expired.
        for tcb in &mut self.connections {
            if !tcb.ack_pending {
                continue;
            }
            if let Some(deadline) = tcb.delayed_ack_deadline
                && now >= deadline
            {
                let id = tcb.id;
                let dst_mac = neighbor_handler
                    .lookup(now, &id.remote_addr)
                    .unwrap_or(crate::net::wire::ethernet::MacAddress::broadcast());
                let ts = if tcb.ts_enabled {
                    let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
                    Some((tsval, tcb.ts_recent))
                } else {
                    None
                };
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
                tcb.delayed_ack_deadline = None;
            }
        }

        // Keep-alive probe pass — send probes for idle established connections.
        let mut keep_alive_removals: Vec<usize> = Vec::new();
        for (i, tcb) in self.connections.iter_mut().enumerate() {
            if tcb.state != TcpState::Established || !tcb.keep_alive_enabled {
                continue;
            }

            let idle_ms = now.duration_since(tcb.last_activity).as_millis();

            let probe_threshold = if tcb.keep_alive_probes_sent == 0 {
                tcb.keep_alive_idle_ms
            } else {
                tcb.keep_alive_idle_ms
                    + tcb.keep_alive_interval_ms * tcb.keep_alive_probes_sent as u64
            };

            if idle_ms >= probe_threshold {
                if tcb.keep_alive_probes_sent >= tcb.keep_alive_count {
                    // Max probes exceeded — abort connection.
                    tcb.event_queue.push(TcpEvent::Timeout);
                    keep_alive_removals.push(i);
                    continue;
                }

                // Send keep-alive probe: seq = snd_una - 1, no data, ACK.
                let id = tcb.id;
                let dst_mac = neighbor_handler
                    .lookup(now, &id.remote_addr)
                    .unwrap_or(crate::net::wire::ethernet::MacAddress::broadcast());
                let ts = if tcb.ts_enabled {
                    let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
                    Some((tsval, tcb.ts_recent))
                } else {
                    None
                };
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
            }
        }

        // Remove connections that exceeded keep-alive probes (reverse order).
        for idx in keep_alive_removals.into_iter().rev() {
            let id = self.connections[idx].id;
            self.decrement_syn_received(&id);
            self.connections.remove(idx);
        }

        // SACK recovery pass — RFC 6675 recovery loop.
        for tcb in &mut self.connections {
            if tcb.state != TcpState::Established || !tcb.recovery.in_recovery {
                continue;
            }

            // Recompute pipe estimate.
            tcb.recovery.set_pipe(
                tcb.snd_una,
                tcb.snd_nxt,
                &tcb.sack_scoreboard,
                tcb.eff_snd_mss,
            );

            // Send while pipe < cwnd.
            while tcb.recovery.pipe < tcb.cubic.cwnd {
                // Try lost segment first.
                if let Some(lost_seq) = tcb.recovery.next_lost_segment(
                    tcb.snd_una,
                    tcb.snd_nxt,
                    &tcb.sack_scoreboard,
                    tcb.eff_snd_mss,
                ) {
                    let offset = lost_seq.wrapping_sub(tcb.snd_una) as usize;
                    let retransmit_len = tcb
                        .send_buffer
                        .available()
                        .saturating_sub(offset)
                        .min(tcb.eff_snd_mss as usize);
                    if retransmit_len == 0 {
                        break;
                    }

                    let id = tcb.id;
                    let dst_mac = neighbor_handler
                        .lookup(now, &id.remote_addr)
                        .unwrap_or(crate::net::wire::ethernet::MacAddress::broadcast());

                    let payload = tcb.send_buffer.peek_slices(offset, retransmit_len);
                    let ts = if tcb.ts_enabled {
                        let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
                        Some((tsval, tcb.ts_recent))
                    } else {
                        None
                    };
                    SegmentBuilder::build_data_from_slices(
                        id.local_addr,
                        id.remote_addr,
                        id.local_port,
                        id.remote_port,
                        lost_seq,
                        tcb.rcv_nxt,
                        tcb.advertised_window(),
                        payload,
                        flags::ACK,
                        false,
                        ts,
                        src_mac,
                        dst_mac,
                        self.tx_offload,
                        free_frames,
                        tx_return,
                    );

                    tcb.recovery.pipe += tcb.eff_snd_mss as u32;
                    tcb.prr.on_sent(retransmit_len as u32);
                } else {
                    // No more lost segments — could send new data, but that's
                    // handled by poll_send. Break here.
                    break;
                }
            }
        }

        // RTO retransmit pass — timer-based.
        let mut to_remove = Vec::new();

        for (idx, tcb) in self.connections.iter_mut().enumerate() {
            let Some(deadline) = tcb.retransmit_deadline else {
                continue;
            };

            if now < deadline {
                continue;
            }

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
                // Timeout — signal and mark for removal.
                tcb.event_queue.push(TcpEvent::Timeout);
                to_remove.push(idx);
                continue;
            }

            // Retransmit.
            let id = tcb.id;
            let dst_mac = neighbor_handler
                .lookup(now, &id.remote_addr)
                .unwrap_or(crate::net::wire::ethernet::MacAddress::broadcast());

            match tcb.state {
                TcpState::SynSent => {
                    let ts_opt = if tcb.ts_enabled {
                        let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
                        Some((tsval, 0u32))
                    } else {
                        None
                    };
                    SegmentBuilder::build_syn(
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
                }
                TcpState::SynReceived => {
                    let wscale_opt = if tcb.wscale_enabled {
                        Some(tcb.rcv_wscale)
                    } else {
                        None
                    };
                    let ts_opt = if tcb.ts_enabled {
                        let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
                        Some((tsval, tcb.ts_recent))
                    } else {
                        None
                    };
                    SegmentBuilder::build_syn_ack(
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
                }
                TcpState::Established => {
                    let retransmit_len = tcb.send_buffer.available().min(tcb.eff_snd_mss as usize);
                    if retransmit_len > 0 {
                        let payload = tcb.send_buffer.peek_slices(0, retransmit_len);
                        let ts = if tcb.ts_enabled {
                            let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
                            Some((tsval, tcb.ts_recent))
                        } else {
                            None
                        };
                        SegmentBuilder::build_data_from_slices(
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
                    }
                    // F-RTO + CUBIC RTO response.
                    tcb.frto.enter(tcb.snd_una);
                    tcb.cubic.on_rto();
                    tcb.recovery.exit();
                    tcb.sack_scoreboard.clear();
                    tcb.rto_backoff += 1;
                    tcb.retransmit_deadline =
                        Some(now + coarsetime::Duration::from_millis(tcb.rto << tcb.rto_backoff));
                }
                TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck => {
                    // Retransmit FIN-ACK.
                    let ts = if tcb.ts_enabled {
                        let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
                        Some((tsval, tcb.ts_recent))
                    } else {
                        None
                    };
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
                    tcb.retransmit_deadline =
                        Some(now + coarsetime::Duration::from_millis(tcb.rto << tcb.rto_backoff));
                }
                _ => continue,
            }

            // Exponential backoff for SYN/SYN-ACK states.
            match tcb.state {
                TcpState::SynSent | TcpState::SynReceived => {
                    tcb.rto_backoff += 1;
                    let rto = INITIAL_RTO_MS << tcb.rto_backoff;
                    tcb.retransmit_deadline = Some(now + coarsetime::Duration::from_millis(rto));
                }
                _ => {} // Established handles its own backoff above.
            }
        }

        // Remove timed-out connections (in reverse order to preserve indices).
        for idx in to_remove.into_iter().rev() {
            let id = self.connections[idx].id;
            self.decrement_syn_received(&id);
            self.connections.remove(idx);
        }
    }

    /// Evict stale connections whose TIME-WAIT deadline has passed.
    pub fn evict_stale<'umem>(&mut self, now: Instant, _rx_return: &mut impl FrameBuffer<'umem>) {
        self.connections.retain(|tcb| {
            if tcb.state == TcpState::TimeWait
                && let Some(deadline) = tcb.time_wait_deadline
                && now >= deadline
            {
                return false; // remove
            }
            true // keep
        });
    }
}
