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
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let mut conn_ids = std::mem::take(&mut self.tick_conn_ids);
        conn_ids.clear();
        conn_ids.extend(self.connections.keys().copied());
        let now = Instant::now();

        for &conn_id in conn_ids.iter() {
            // Process commands from socket layer.
            if let Some(tcb) = self.connections.get(&conn_id) {
                if let Some(cmd) = tcb.cmd_queue.pop() {
                    match cmd {
                        TcpCommand::Close => {
                            let state = tcb.state;
                            match state {
                                TcpState::Established => {
                                    let tcb = self.connections.get_mut(&conn_id).unwrap();
                                    let seq = tcb.snd_nxt;
                                    let ack = tcb.rcv_nxt;
                                    let wnd = tcb.rcv_wnd;
                                    send_and_queue_retransmit(
                                        tcb,
                                        seq,
                                        ack,
                                        flags::FIN | flags::ACK,
                                        wnd,
                                        &[],
                                        1,
                                        free_frames,
                                        tx_return,
                                    );
                                    tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);
                                    tcb.state = TcpState::FinWait1;
                                }
                                TcpState::CloseWait => {
                                    let tcb = self.connections.get_mut(&conn_id).unwrap();
                                    let seq = tcb.snd_nxt;
                                    let ack = tcb.rcv_nxt;
                                    let wnd = tcb.rcv_wnd;
                                    send_and_queue_retransmit(
                                        tcb,
                                        seq,
                                        ack,
                                        flags::FIN | flags::ACK,
                                        wnd,
                                        &[],
                                        1,
                                        free_frames,
                                        tx_return,
                                    );
                                    tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);
                                    tcb.state = TcpState::LastAck;
                                }
                                _ => {}
                            }
                        }
                        TcpCommand::Abort => {
                            if let Some(tcb) = self.connections.get(&conn_id) {
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
                                tcb.rx_queue.push(TcpEvent::Reset);
                            }
                            self.remove_connection(&conn_id, rx_return);
                            continue;
                        }
                    }
                }
            }

            // Drain send buffer and transmit data.
            if let Some(tcb) = self.connections.get(&conn_id) {
                if (tcb.state == TcpState::Established || tcb.state == TcpState::CloseWait)
                    && tcb.send_buffer.num_frames() > 0
                {
                    let _ = tcb;
                    self.drain_send_buffer(&conn_id, free_frames, rx_return, tx_return);
                }
            }

            // Retransmission check.
            if let Some(tcb) = self.connections.get_mut(&conn_id) {
                if !tcb.retransmit_queue.is_empty() {
                    let rto = tcb.rto_state.rto;
                    if let Some(entry) = tcb.retransmit_queue.front() {
                        if now.duration_since(entry.sent_at) >= rto {
                            let entry = tcb.retransmit_queue.front_mut().unwrap();
                            if entry.first_retransmit_time.is_none() {
                                entry.first_retransmit_time = Some(now);
                            }
                            entry.retransmit_count += 1;
                            entry.is_retransmit = true;
                            entry.sent_at = now;

                            // Copy frame for retransmit.
                            if let Some(mut tx_frame) = free_frames.pop() {
                                let src = &entry.frame;
                                let len = src.len();
                                if len <= tx_frame.capacity() {
                                    unsafe { tx_frame.set_len(len) };
                                    tx_frame[..len].copy_from_slice(&src[..len]);
                                    tx_return.push(tx_frame);
                                } else {
                                    rx_return.push(tx_frame);
                                }
                            }

                            // Exponential backoff
                            tcb.rto_state.backoff();

                            // Congestion: timeout
                            let mss = tcb.snd_mss as u32;
                            tcb.congestion.ssthresh =
                                (tcb.congestion.cwnd / 2).max(2 * mss);
                            tcb.congestion.cwnd = mss;

                            // Connection failure check using first_retransmit_time
                            if let Some(first_rt) =
                                tcb.retransmit_queue.front().unwrap().first_retransmit_time
                            {
                                if now.duration_since(first_rt) >= MAX_RETRANSMIT_TIME {
                                    tcb.rx_queue.push(TcpEvent::Reset);
                                    tcb.state = TcpState::Closed;
                                    self.remove_connection(&conn_id, rx_return);
                                    continue;
                                }
                            }
                        }
                    }
                }
            }

            // Zero-window probing.
            if let Some(tcb) = self.connections.get_mut(&conn_id) {
                if tcb.snd_wnd == 0
                    && (tcb.state == TcpState::Established || tcb.state == TcpState::CloseWait)
                    && tcb.send_buffer.num_frames() > 0
                {
                    let rto = tcb.rto_state.rto;
                    if now.duration_since(tcb.last_activity) >= rto {
                        send_segment(
                            tcb,
                            tcb.snd_nxt,
                            tcb.rcv_nxt,
                            flags::ACK,
                            tcb.rcv_wnd,
                            &[],
                            &[],
                            free_frames,
                            tx_return,
                        );
                        tcb.last_activity = now;
                    }
                }
            }
        }

        self.tick_conn_ids = conn_ids;
    }

    pub(super) fn drain_send_buffer(
        &mut self,
        conn_id: &ConnectionId,
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        loop {
            let tcb = match self.connections.get_mut(conn_id) {
                Some(t) => t,
                None => return,
            };

            let eff_wnd = tcb.effective_window();
            let flight_size = tcb.snd_nxt.wrapping_sub(tcb.snd_una);
            if flight_size >= eff_wnd {
                break;
            }
            let available_wnd = eff_wnd - flight_size;

            let data_frame = match tcb.send_buffer.pop() {
                Some(f) => f,
                None => break,
            };

            let data_len = data_frame.len();
            let seg_size = data_len.min(tcb.snd_mss as usize).min(available_wnd as usize);
            if seg_size == 0 {
                tcb.send_buffer.push(data_frame);
                break;
            }

            let seq = tcb.snd_nxt;
            let ack = tcb.rcv_nxt;
            let wnd = tcb.rcv_wnd;
            let local_addr = tcb.conn_id.local_addr;
            let remote_addr = tcb.conn_id.remote_addr;
            let local_port = tcb.conn_id.local_port;
            let remote_port = tcb.conn_id.remote_port;
            let local_mac = tcb.local_mac;
            let remote_mac = tcb.remote_mac;
            let is_last = tcb.send_buffer.num_frames() == 0;
            let seg_flags = flags::ACK | if is_last { flags::PSH } else { 0 };

            let tx_frame = match free_frames.pop() {
                Some(f) => f,
                None => {
                    let tcb = self.connections.get_mut(conn_id).unwrap();
                    tcb.send_buffer.push(data_frame);
                    break;
                }
            };
            let retransmit_frame = match free_frames.pop() {
                Some(f) => f,
                None => {
                    free_frames.push(tx_frame);
                    let tcb = self.connections.get_mut(conn_id).unwrap();
                    tcb.send_buffer.push(data_frame);
                    break;
                }
            };

            let payload = &data_frame[..seg_size];
            let built = build_tcp_segment(
                tx_frame, local_mac, remote_mac, local_addr, remote_addr, local_port, remote_port,
                seq, ack, seg_flags, wnd, &[], payload,
            );

            match built {
                Some(tx_f) => {
                    let mut retransmit_f = retransmit_frame;
                    let len = tx_f.len();
                    unsafe { retransmit_f.set_len(len) };
                    retransmit_f[..len].copy_from_slice(&tx_f[..len]);

                    tx_return.push(tx_f);

                    let tcb = self.connections.get_mut(conn_id).unwrap();
                    tcb.snd_nxt = tcb.snd_nxt.wrapping_add(seg_size as u32);
                    tcb.retransmit_queue.push_back(RetransmitEntry {
                        seq,
                        len: seg_size,
                        frame: retransmit_f,
                        sent_at: Instant::now(),
                        retransmit_count: 0,
                        is_retransmit: false,
                        first_retransmit_time: None,
                    });
                }
                None => {
                    rx_return.push(retransmit_frame);
                }
            }

            rx_return.push(data_frame);
        }
    }

    /// Removes connections that have exceeded their TIME-WAIT duration.
    pub fn evict_stale(&mut self, rx_return: &mut impl FrameBuffer<'umem>) {
        let now = Instant::now();
        let time_wait_duration = self.time_wait_duration;

        let mut expired = std::mem::take(&mut self.tick_conn_ids);
        expired.clear();
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
                tcb.rx_queue.push(TcpEvent::Closed);
            }
            self.remove_connection(conn_id, rx_return);
        }
        expired.clear();
        self.tick_conn_ids = expired;
    }
}
