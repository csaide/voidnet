use std::time::Instant;

use crate::net::wire::tcp::flags;
use crate::xdp::frame::FrameBuffer;

use super::TcpHandler;
use super::segment::*;
use super::tcb::*;
use super::types::*;

impl<'umem> TcpHandler<'umem> {
    /// Drives outbound processing: socket commands, send buffer drain,
    /// retransmissions, and zero-window probing.
    ///
    /// Called once per event loop iteration by `LocalRuntime::run`.
    pub fn tick(
        &mut self,
        now: Instant,
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let mut conn_ids = std::mem::take(&mut self.dirty_conn_ids);
        conn_ids.sort_unstable();
        conn_ids.dedup();

        let Self { connections, dirty_conn_ids, .. } = self;

        for &conn_id in conn_ids.iter() {
            let should_remove = if let Some(tcb) = connections.get_mut(&conn_id) {
                Self::tick_connection(tcb, now, free_frames, rx_return, tx_return)
            } else {
                continue;
            };
            if should_remove {
                if let Some(tcb) = connections.remove(&conn_id) {
                    tcb.drain_rx_queue(rx_return);
                    for (_, (frame, _, _)) in tcb.recv_reorder {
                        rx_return.push(frame);
                    }
                }
            } else if let Some(tcb) = connections.get(&conn_id) {
                if tcb.needs_tick {
                    dirty_conn_ids.push(conn_id);
                }
            }
        }

        // Merge: move new dirty entries into conn_ids for capacity reuse.
        conn_ids.clear();
        conn_ids.append(dirty_conn_ids);
        *dirty_conn_ids = conn_ids;
    }

    /// Per-connection tick logic. Returns `true` if the connection should be removed.
    fn tick_connection(
        tcb: &mut Tcb<'umem>,
        now: Instant,
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) -> bool {
        // Process commands from socket layer.
        if let Some(cmd) = tcb.cmd_queue.pop() {
            match cmd {
                TcpCommand::Close => match tcb.state {
                    TcpState::Established => {
                        let seq = tcb.snd_nxt;
                        let ack = tcb.rcv_nxt;
                        let wnd = tcb.wire_rcv_wnd() as u32;
                        send_and_queue_retransmit(
                            tcb, seq, ack,
                            flags::FIN | flags::ACK,
                            wnd, &[], 1, now,
                            free_frames, tx_return,
                        );
                        tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);
                        tcb.state = TcpState::FinWait1;
                    }
                    TcpState::CloseWait => {
                        let seq = tcb.snd_nxt;
                        let ack = tcb.rcv_nxt;
                        let wnd = tcb.wire_rcv_wnd() as u32;
                        send_and_queue_retransmit(
                            tcb, seq, ack,
                            flags::FIN | flags::ACK,
                            wnd, &[], 1, now,
                            free_frames, tx_return,
                        );
                        tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);
                        tcb.state = TcpState::LastAck;
                    }
                    _ => {}
                },
                TcpCommand::Abort => {
                    send_rst_stateless(
                        tcb.conn_id.local_addr,
                        tcb.conn_id.remote_addr,
                        tcb.conn_id.local_port,
                        tcb.conn_id.remote_port,
                        tcb.snd_nxt,
                        tcb.rcv_nxt,
                        true,
                        tcb.local_mac,
                        tcb.remote_mac,
                        free_frames,
                        tx_return,
                    );
                    tcb.push_rx_event(TcpEvent::Reset, rx_return);
                    return true; // Remove connection.
                }
            }
        }

        // Drain send buffer and transmit data.
        if (tcb.state == TcpState::Established || tcb.state == TcpState::CloseWait)
            && tcb.send_buffer.len() > 0
        {
            Self::drain_send_buffer_direct(tcb, now, free_frames, tx_return);
        }

        // Retransmission check.
        if !tcb.retransmit_queue.is_empty() {
            let rto = tcb.rto_state.rto;
            if let Some(entry) = tcb.retransmit_queue.front() {
                if now.duration_since(entry.sent_at) >= rto {
                    let entry_seq = entry.seq;
                    let entry_len = entry.len;
                    let entry_flags = entry.seg_flags;
                    let entry_ack = entry.ack;
                    let entry_wnd = entry.window;
                    let mut entry_opts = [0u8; 8];
                    let entry_opts_len = entry.options_len as usize;
                    entry_opts[..entry_opts_len]
                        .copy_from_slice(&entry.options[..entry_opts_len]);

                    let entry = tcb.retransmit_queue.front_mut().unwrap();
                    if entry.first_retransmit_time.is_none() {
                        entry.first_retransmit_time = Some(now);
                    }
                    entry.retransmit_count += 1;
                    entry.is_retransmit = true;
                    entry.sent_at = now;

                    if let Some(tx_frame) = free_frames.pop() {
                        let buf_offset = entry_seq.wrapping_sub(tcb.snd_una) as usize;
                        if entry_len > 0 {
                            let (a, b) = tcb.send_buffer.peek_slices(buf_offset, entry_len);
                            let payload: &[u8];
                            let mut scratch = [0u8; 1460];
                            if b.is_empty() {
                                payload = a;
                            } else {
                                scratch[..a.len()].copy_from_slice(a);
                                scratch[a.len()..a.len() + b.len()].copy_from_slice(b);
                                payload = &scratch[..a.len() + b.len()];
                            }
                            match build_tcp_segment(
                                tx_frame,
                                tcb.local_mac,
                                tcb.remote_mac,
                                tcb.conn_id.local_addr,
                                tcb.conn_id.remote_addr,
                                tcb.conn_id.local_port,
                                tcb.conn_id.remote_port,
                                entry_seq,
                                entry_ack,
                                entry_flags,
                                entry_wnd,
                                &entry_opts[..entry_opts_len],
                                payload,
                            ) {
                                Ok(f) => tx_return.push(f),
                                Err(f) => free_frames.push(f),
                            }
                        } else {
                            match build_tcp_segment(
                                tx_frame,
                                tcb.local_mac,
                                tcb.remote_mac,
                                tcb.conn_id.local_addr,
                                tcb.conn_id.remote_addr,
                                tcb.conn_id.local_port,
                                tcb.conn_id.remote_port,
                                entry_seq,
                                entry_ack,
                                entry_flags,
                                entry_wnd,
                                &entry_opts[..entry_opts_len],
                                &[],
                            ) {
                                Ok(f) => tx_return.push(f),
                                Err(f) => free_frames.push(f),
                            }
                        }
                    }

                    tcb.rto_state.backoff();

                    let mss = tcb.snd_mss as u32;
                    tcb.congestion.ssthresh = (tcb.congestion.cwnd / 2).max(2 * mss);
                    tcb.congestion.cwnd = mss;
                    tcb.dup_ack_count = 0;
                    tcb.in_fast_recovery = false;

                    if let Some(first_rt) =
                        tcb.retransmit_queue.front().unwrap().first_retransmit_time
                    {
                        if now.duration_since(first_rt) >= MAX_RETRANSMIT_TIME {
                            tcb.push_rx_event(TcpEvent::Reset, rx_return);
                            tcb.state = TcpState::Closed;
                            return true; // Remove connection.
                        }
                    }
                }
            }
        }

        // Zero-window probing.
        if tcb.snd_wnd == 0
            && (tcb.state == TcpState::Established || tcb.state == TcpState::CloseWait)
            && tcb.send_buffer.len() > 0
        {
            let rto = tcb.rto_state.rto;
            if now.duration_since(tcb.last_activity) >= rto {
                send_segment(
                    tcb,
                    tcb.snd_nxt,
                    tcb.rcv_nxt,
                    flags::ACK,
                    tcb.wire_rcv_wnd() as u32,
                    &[],
                    &[],
                    free_frames,
                    tx_return,
                );
                tcb.last_activity = now;
            }
        }

        // Flush delayed ACKs that have exceeded the 40ms timeout.
        if tcb.delayed_ack_pending > 0 {
            if let Some(ack_at) = tcb.delayed_ack_at {
                if now.duration_since(ack_at) >= DELAYED_ACK_TIMEOUT {
                    send_segment(
                        tcb,
                        tcb.snd_nxt,
                        tcb.rcv_nxt,
                        flags::ACK,
                        tcb.wire_rcv_wnd() as u32,
                        &[],
                        &[],
                        free_frames,
                        tx_return,
                    );
                    tcb.delayed_ack_pending = 0;
                    tcb.delayed_ack_at = None;
                }
            }
        }

        // Clear needs_tick if nothing left to do.
        if tcb.cmd_queue.is_empty()
            && tcb.send_buffer.len() == 0
            && tcb.retransmit_queue.is_empty()
            && tcb.delayed_ack_pending == 0
            && tcb.snd_wnd != 0
        {
            tcb.needs_tick = false;
        }

        false // Keep connection.
    }

    /// Drains the send buffer directly on an owned TCB, avoiding HashMap lookups.
    fn drain_send_buffer_direct(
        tcb: &mut Tcb<'umem>,
        now: Instant,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        loop {
            let eff_wnd = tcb.effective_window();
            let flight_size = tcb.snd_nxt.wrapping_sub(tcb.snd_una);
            if flight_size >= eff_wnd {
                break;
            }
            let available_wnd = eff_wnd - flight_size;

            // Bytes available beyond what's already in flight.
            let buf_offset = tcb.snd_nxt.wrapping_sub(tcb.snd_una) as usize;
            let buf_available = tcb.send_buffer.len().saturating_sub(buf_offset);
            if buf_available == 0 {
                break;
            }

            let seg_size = buf_available
                .min(tcb.snd_mss as usize)
                .min(available_wnd as usize);
            if seg_size == 0 {
                break;
            }

            let seq = tcb.snd_nxt;
            let ack = tcb.rcv_nxt;
            let wnd = tcb.wire_rcv_wnd() as u32;
            let remaining_after = buf_available - seg_size;
            let seg_flags = flags::ACK | if remaining_after == 0 { flags::PSH } else { 0 };

            let tx_frame = match free_frames.pop() {
                Some(f) => f,
                None => break,
            };

            // Peek payload bytes from the send buffer (no consume — kept for retransmit).
            let (a, b) = tcb.send_buffer.peek_slices(buf_offset, seg_size);
            let payload: &[u8];
            let mut scratch = [0u8; 1460];
            if b.is_empty() {
                // Common case: contiguous data, pass directly
                payload = a;
            } else {
                // Rare: ring wrap, use stack scratch
                scratch[..a.len()].copy_from_slice(a);
                scratch[a.len()..a.len() + b.len()].copy_from_slice(b);
                payload = &scratch[..a.len() + b.len()];
            }
            match build_tcp_segment(
                tx_frame,
                tcb.local_mac,
                tcb.remote_mac,
                tcb.conn_id.local_addr,
                tcb.conn_id.remote_addr,
                tcb.conn_id.local_port,
                tcb.conn_id.remote_port,
                seq, ack, seg_flags, wnd, &[], payload,
            ) {
                Ok(tx_f) => {
                    tx_return.push(tx_f);

                    // Data segment carries ACK — clear delayed ACK state (piggybacking).
                    tcb.delayed_ack_pending = 0;
                    tcb.delayed_ack_at = None;
                    tcb.snd_nxt = tcb.snd_nxt.wrapping_add(seg_size as u32);
                    tcb.retransmit_queue.push_back(RetransmitEntry {
                        seq,
                        len: seg_size,
                        seg_flags,
                        ack,
                        window: wnd,
                        options: [0; 8],
                        options_len: 0,
                        sent_at: now,
                        retransmit_count: 0,
                        is_retransmit: false,
                        first_retransmit_time: None,
                    });
                }
                Err(f) => { free_frames.push(f); break; }
            }
        }
    }

    /// Removes connections that have exceeded their TIME-WAIT duration.
    pub fn evict_stale(&mut self, now: Instant, rx_return: &mut impl FrameBuffer<'umem>) {
        let time_wait_duration = self.time_wait_duration;

        let mut expired: Vec<ConnectionId> = Vec::new();
        for (id, tcb) in self.connections.iter() {
            if tcb.state == TcpState::TimeWait {
                if let Some(start) = tcb.time_wait_start {
                    if now.duration_since(start) >= time_wait_duration {
                        expired.push(*id);
                    }
                }
            }
        }

        for conn_id in expired.iter() {
            if let Some(tcb) = self.connections.get(conn_id) {
                tcb.push_rx_event(TcpEvent::Closed, rx_return);
            }
            self.remove_connection(conn_id, rx_return);
        }
    }
}
