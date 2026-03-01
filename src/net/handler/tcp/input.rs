use std::collections::BTreeMap;
use std::time::Instant;

use crate::net::socket::LocalQueue;
use crate::net::wire::ethernet::{EthernetFrame, MacAddress};
use crate::net::wire::ip::{IPV6_HEADER_LEN, IpAddress, Ipv4Header, Ipv6Header};
use crate::net::wire::tcp::{
    self, TCP_HEADER_LEN, TcpHeader, flags, parse_mss, parse_window_scale, seq_le, seq_lt,
    write_mss_option, write_window_scale_option,
};
use crate::xdp::frame::{Frame, FrameBuffer};

use super::TcpHandler;
use super::segment::*;
use super::tcb::*;
use super::types::*;

impl<'umem> TcpHandler<'umem> {
    /// Processes an incoming TCP segment from an IPv4 frame.
    ///
    /// Validates the TCP header and checksum, then dispatches to
    /// the segment processing state machine. Invalid frames go to `rx_return`.
    pub fn process_ipv4(
        &mut self,
        frame: Frame<'umem>,
        now: Instant,
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let (src_mac, dst_mac) = {
            let eth = EthernetFrame::from_frame(&frame);
            (eth.src_mac, eth.dst_mac)
        };

        let (src_addr, dst_addr, tcp_offset, tcp_segment_len) = {
            let ip = Ipv4Header::from_frame(&frame);
            (
                ip.src_addr,
                ip.dst_addr,
                ip.payload_offset(),
                ip.payload_len(),
            )
        };

        if frame.len() < tcp_offset + TCP_HEADER_LEN {
            rx_return.push(frame);
            return;
        }

        let parsed = {
            let tcp = unsafe { TcpHeader::from_frame_at(&frame, tcp_offset) };
            ParsedTcpHeader {
                src_port: tcp.src_port(),
                dst_port: tcp.dst_port(),
                seq_num: tcp.seq_num(),
                ack_num: tcp.ack_num(),
                flags: tcp.flags(),
                window: tcp.window(),
                header_len: tcp.header_len(),
            }
        };

        if parsed.header_len < TCP_HEADER_LEN || frame.len() < tcp_offset + parsed.header_len {
            rx_return.push(frame);
            return;
        }

        if tcp_segment_len < TCP_HEADER_LEN || frame.len() < tcp_offset + tcp_segment_len {
            rx_return.push(frame);
            return;
        }

        if !tcp::verify_tcp_checksum(
            &src_addr,
            &dst_addr,
            &frame[tcp_offset..tcp_offset + tcp_segment_len],
        ) {
            rx_return.push(frame);
            return;
        }

        self.process_segment(
            frame,
            IpAddress::V4(src_addr),
            IpAddress::V4(dst_addr),
            parsed,
            tcp_offset,
            tcp_segment_len,
            src_mac,
            dst_mac,
            now,
            free_frames,
            rx_return,
            tx_return,
        );
    }

    /// Processes an incoming TCP segment from an IPv6 frame.
    ///
    /// Validates the TCP header and checksum, then dispatches to
    /// the segment processing state machine. Invalid frames go to `rx_return`.
    pub fn process_ipv6(
        &mut self,
        frame: Frame<'umem>,
        tcp_offset: usize,
        now: Instant,
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let (src_mac, dst_mac) = {
            let eth = EthernetFrame::from_frame(&frame);
            (eth.src_mac, eth.dst_mac)
        };

        let (src_addr, dst_addr, tcp_segment_len) = {
            let ip = Ipv6Header::from_frame(&frame);
            (
                ip.src_addr,
                ip.dst_addr,
                ip.payload_length() as usize - (tcp_offset - ETH_HEADER_LEN - IPV6_HEADER_LEN), // Subtract extension header bytes
            )
        };

        if frame.len() < tcp_offset + TCP_HEADER_LEN {
            rx_return.push(frame);
            return;
        }

        let parsed = {
            let tcp = unsafe { TcpHeader::from_frame_at(&frame, tcp_offset) };
            ParsedTcpHeader {
                src_port: tcp.src_port(),
                dst_port: tcp.dst_port(),
                seq_num: tcp.seq_num(),
                ack_num: tcp.ack_num(),
                flags: tcp.flags(),
                window: tcp.window(),
                header_len: tcp.header_len(),
            }
        };

        if parsed.header_len < TCP_HEADER_LEN
            || tcp_segment_len < TCP_HEADER_LEN
            || frame.len() < tcp_offset + tcp_segment_len
        {
            rx_return.push(frame);
            return;
        }

        if !tcp::verify_tcp_checksum_v6(
            &src_addr,
            &dst_addr,
            &frame[tcp_offset..tcp_offset + tcp_segment_len],
        ) {
            rx_return.push(frame);
            return;
        }

        self.process_segment(
            frame,
            IpAddress::V6(src_addr),
            IpAddress::V6(dst_addr),
            parsed,
            tcp_offset,
            tcp_segment_len,
            src_mac,
            dst_mac,
            now,
            free_frames,
            rx_return,
            tx_return,
        );
    }

    /// Core segment processing following RFC 9293.
    ///
    /// Routes the segment to an existing connection, a matching listener,
    /// or generates a RST for unmatched segments.
    fn process_segment(
        &mut self,
        frame: Frame<'umem>,
        src_addr: IpAddress,
        dst_addr: IpAddress,
        parsed: ParsedTcpHeader,
        tcp_offset: usize,
        tcp_segment_len: usize,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        now: Instant,
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let conn_id = ConnectionId {
            local_addr: dst_addr,
            local_port: parsed.dst_port,
            remote_addr: src_addr,
            remote_port: parsed.src_port,
        };

        // Try existing connection first -- use get_mut to avoid remove/reinsert.
        {
            let Self { connections, listeners, dirty_conn_ids, .. } = self;
            if let Some(tcb) = connections.get_mut(&conn_id) {
                let should_remove = Self::process_for_connection_inplace(
                    tcb,
                    listeners,
                    conn_id,
                    frame,
                    parsed,
                    tcp_offset,
                    tcp_segment_len,
                    now,
                    free_frames,
                    rx_return,
                    tx_return,
                );
                if should_remove {
                    if let Some(tcb) = connections.remove(&conn_id) {
                        tcb.drain_rx_queue(rx_return);
                    }
                } else {
                    dirty_conn_ids.push(conn_id);
                }
                return;
            }
        }

        // Try listener.
        let seg_flags = parsed.flags;

        if seg_flags & flags::RST != 0 {
            // RST to no connection (LISTEN state behavior): ignore.
            rx_return.push(frame);
            return;
        }

        if seg_flags & flags::ACK != 0 && seg_flags & flags::SYN == 0 {
            // ACK to no connection: send RST.
            let seq = parsed.ack_num;
            rx_return.push(frame);
            send_rst_stateless(
                dst_addr,
                src_addr,
                parsed.dst_port,
                parsed.src_port,
                seq,
                0,
                false,
                dst_mac,
                src_mac,
                free_frames,
                tx_return,
            );
            return;
        }

        if seg_flags & flags::SYN != 0 {
            // SYN -- look for a listener.
            if let Some(listener_idx) = self.find_listener(dst_addr, parsed.dst_port) {
                let listener = &self.listeners[listener_idx];
                if listener.pending >= listener.backlog {
                    rx_return.push(frame);
                    return;
                }

                // Parse MSS and Window Scale from SYN options.
                let (peer_mss, peer_wnd_scale) = if parsed.header_len > TCP_HEADER_LEN {
                    let opts_start = tcp_offset + TCP_HEADER_LEN;
                    let opts_end = tcp_offset + parsed.header_len;
                    if opts_end <= frame.len() {
                        let opts = &frame[opts_start..opts_end];
                        (
                            parse_mss(opts).unwrap_or(536),
                            parse_window_scale(opts),
                        )
                    } else {
                        (536, None)
                    }
                } else {
                    (536, None)
                };

                let seg_seq = parsed.seq_num;
                let seg_wnd = parsed.window;
                let iss = generate_isn(&conn_id);

                // RFC 7323: only use window scaling if peer offered it.
                let (snd_wnd_scale, rcv_wnd_scale) = match peer_wnd_scale {
                    Some(s) => (s, DEFAULT_RCV_WND_SCALE),
                    None => (0, 0),
                };

                let rx_queue = LocalQueue::new(256);
                let cmd_queue = LocalQueue::new(64);
                let send_buffer = SharedSendBuffer::new(DEFAULT_SEND_BUF_CAPACITY);
                let send_notify = SharedFlag::new();

                let mut tcb = Tcb {
                    state: TcpState::SynReceived,
                    conn_id,
                    snd_una: iss,
                    snd_nxt: iss.wrapping_add(1),
                    snd_wnd: (seg_wnd as u32) << snd_wnd_scale,
                    snd_wl1: seg_seq,
                    snd_wl2: iss,
                    iss,
                    rcv_nxt: seg_seq.wrapping_add(1),
                    rcv_wnd: DEFAULT_RCV_WND,
                    irs: seg_seq,
                    snd_mss: peer_mss,
                    rcv_mss: DEFAULT_RCV_MSS,
                    snd_wnd_scale,
                    rcv_wnd_scale,
                    last_activity: now,
                    time_wait_start: None,
                    rx_queue,
                    cmd_queue,
                    send_buffer,
                    send_notify,
                    recv_reorder: BTreeMap::new(),
                    retransmit_queue: RetransmitQueue::new(DEFAULT_RETRANSMIT_CAPACITY),
                    rto_state: RtoState::new(),
                    congestion: CongestionState::new(peer_mss),
                    delayed_ack_pending: 0,
                    delayed_ack_at: None,
                    dup_ack_count: 0,
                    in_fast_recovery: false,
                    recovery_point: 0,
                    needs_tick: true,
                    from_listener: true,
                    rcv_wnd_per_slot: DEFAULT_RCV_WND / 256,
                    local_mac: dst_mac,
                    remote_mac: src_mac,
                };

                // Send SYN-ACK with retransmit (include MSS + Window Scale options)
                let rcv_nxt = tcb.rcv_nxt;
                let rcv_wnd = tcb.wire_rcv_wnd() as u32;
                let mut syn_opts = [0u8; 8]; // MSS(4) + NOP(1) + WS(3)
                write_mss_option(&mut syn_opts[..4], tcb.rcv_mss);
                let opts_len = if rcv_wnd_scale > 0 {
                    syn_opts[4] = 1; // NOP for alignment
                    write_window_scale_option(&mut syn_opts[5..], rcv_wnd_scale);
                    8
                } else {
                    4
                };
                send_and_queue_retransmit(
                    &mut tcb,
                    iss,
                    rcv_nxt,
                    flags::SYN | flags::ACK,
                    rcv_wnd,
                    &syn_opts[..opts_len],
                    1,
                    now,
                    free_frames,
                    tx_return,
                );
                self.listeners[listener_idx].pending += 1;
                self.insert_connection(conn_id, tcb);
                rx_return.push(frame);
                return;
            }
        }

        // No matching connection or listener -- send RST.
        let rst_seq;
        let rst_ack;
        let rst_has_ack;
        if seg_flags & flags::ACK != 0 {
            rst_seq = parsed.ack_num;
            rst_ack = 0;
            rst_has_ack = false;
        } else {
            let data_len = if tcp_segment_len > parsed.header_len {
                tcp_segment_len - parsed.header_len
            } else {
                0
            };
            let seg_len = data_len
                + if seg_flags & flags::SYN != 0 { 1 } else { 0 }
                + if seg_flags & flags::FIN != 0 { 1 } else { 0 };
            rst_seq = 0;
            rst_ack = parsed.seq_num.wrapping_add(seg_len as u32);
            rst_has_ack = true;
        }
        rx_return.push(frame);
        send_rst_stateless(
            dst_addr,
            src_addr,
            parsed.dst_port,
            parsed.src_port,
            rst_seq,
            rst_ack,
            rst_has_ack,
            dst_mac,
            src_mac,
            free_frames,
            tx_return,
        );
    }

    /// Processes a segment for an existing connection (in-place via `get_mut`).
    ///
    /// Returns `true` if the connection should be removed from the map.
    fn process_for_connection_inplace(
        tcb: &mut Tcb<'umem>,
        listeners: &mut Vec<ListenerState<'umem>>,
        conn_id: ConnectionId,
        frame: Frame<'umem>,
        parsed: ParsedTcpHeader,
        tcp_offset: usize,
        tcp_segment_len: usize,
        now: Instant,
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) -> bool {
        let seg_seq = parsed.seq_num;
        let seg_ack = parsed.ack_num;
        let seg_flags = parsed.flags;
        let seg_wnd = parsed.window;
        let tcp_header_len = parsed.header_len;
        let payload_offset = tcp_offset + tcp_header_len;
        let payload_len = if tcp_segment_len > tcp_header_len {
            tcp_segment_len - tcp_header_len
        } else {
            0
        };

        tcb.last_activity = now;
        tcb.needs_tick = true;

        match tcb.state {
            TcpState::SynSent => {
                // Expecting SYN-ACK
                if seg_flags & flags::ACK != 0 {
                    if !seq_le(tcb.iss.wrapping_add(1), seg_ack) || !seq_le(seg_ack, tcb.snd_nxt) {
                        if seg_flags & flags::RST == 0 {
                            send_rst_stateless(
                                tcb.conn_id.local_addr,
                                tcb.conn_id.remote_addr,
                                tcb.conn_id.local_port,
                                tcb.conn_id.remote_port,
                                seg_ack,
                                0,
                                false,
                                tcb.local_mac,
                                tcb.remote_mac,
                                free_frames,
                                tx_return,
                            );
                        }
                        rx_return.push(frame);
                        return false;
                    }
                }

                if seg_flags & flags::RST != 0 {
                    if seg_flags & flags::ACK != 0 {
                        tcb.state = TcpState::Closed;
                        tcb.push_rx_event(TcpEvent::Reset, rx_return);
                        for (_, (f, _, _)) in std::mem::take(&mut tcb.recv_reorder) {
                            rx_return.push(f);
                        }
                        rx_return.push(frame);
                        return true;
                    }
                    rx_return.push(frame);
                    return false;
                }

                if seg_flags & flags::SYN != 0 {
                    // Parse MSS and Window Scale from SYN/SYN-ACK options.
                    if tcp_header_len > TCP_HEADER_LEN {
                        let opts_start = tcp_offset + TCP_HEADER_LEN;
                        let opts_end = tcp_offset + tcp_header_len;
                        if opts_end <= frame.len() {
                            let opts = &frame[opts_start..opts_end];
                            if let Some(mss) = parse_mss(opts) {
                                tcb.snd_mss = mss;
                            }
                            if let Some(ws) = parse_window_scale(opts) {
                                tcb.snd_wnd_scale = ws;
                            } else {
                                // Peer doesn't support WS — disable both directions.
                                tcb.snd_wnd_scale = 0;
                                tcb.rcv_wnd_scale = 0;
                            }
                        }
                    } else {
                        // No options at all — disable window scaling.
                        tcb.snd_wnd_scale = 0;
                        tcb.rcv_wnd_scale = 0;
                    }

                    tcb.irs = seg_seq;
                    tcb.rcv_nxt = seg_seq.wrapping_add(1);
                    tcb.snd_wnd = (seg_wnd as u32) << tcb.snd_wnd_scale;
                    tcb.snd_wl1 = seg_seq;
                    tcb.snd_wl2 = seg_ack;

                    if seg_flags & flags::ACK != 0 {
                        tcb.snd_una = seg_ack;
                        tcb.ack_retransmit_queue(seg_ack, now);
                        tcb.state = TcpState::Established;
                        send_segment(
                            &tcb,
                            tcb.snd_nxt,
                            tcb.rcv_nxt,
                            flags::ACK,
                            tcb.wire_rcv_wnd() as u32,
                            &[],
                            &[],
                            free_frames,
                            tx_return,
                        );
                        tcb.push_rx_event(TcpEvent::Connected, rx_return);
                    } else {
                        // Simultaneous open
                        tcb.state = TcpState::SynReceived;
                        let iss = tcb.iss;
                        let rcv_nxt = tcb.rcv_nxt;
                        let rcv_wnd = tcb.wire_rcv_wnd() as u32;
                        let mut syn_opts = [0u8; 8];
                        write_mss_option(&mut syn_opts[..4], tcb.rcv_mss);
                        let opts_len = if tcb.rcv_wnd_scale > 0 {
                            syn_opts[4] = 1; // NOP
                            write_window_scale_option(&mut syn_opts[5..], tcb.rcv_wnd_scale);
                            8
                        } else {
                            4
                        };
                        send_and_queue_retransmit(
                            tcb,
                            iss,
                            rcv_nxt,
                            flags::SYN | flags::ACK,
                            rcv_wnd,
                            &syn_opts[..opts_len],
                            1,
                            now,
                            free_frames,
                            tx_return,
                        );
                    }
                }
                rx_return.push(frame);
                false
            }

            TcpState::SynReceived => {
                // Sequence check (RFC SEG.LEN includes SYN/FIN)
                let seg_len = payload_len
                    + if seg_flags & flags::SYN != 0 { 1 } else { 0 }
                    + if seg_flags & flags::FIN != 0 { 1 } else { 0 };
                if !tcb.is_seq_acceptable(seg_seq, seg_len) {
                    if seg_flags & flags::RST == 0 {
                        send_segment(
                            &tcb,
                            tcb.snd_nxt,
                            tcb.rcv_nxt,
                            flags::ACK,
                            tcb.wire_rcv_wnd() as u32,
                            &[],
                            &[],
                            free_frames,
                            tx_return,
                        );
                    }
                    rx_return.push(frame);
                    return false;
                }

                if seg_flags & flags::RST != 0 {
                    if tcb.from_listener {
                        if let Some(l) = listeners.iter_mut().find(|l| {
                            l.port == conn_id.local_port
                                && (l.addr == conn_id.local_addr || l.addr.is_unspecified())
                        }) {
                            if l.pending > 0 { l.pending -= 1; }
                        }
                    } else {
                        tcb.push_rx_event(TcpEvent::Reset, rx_return);
                    }
                    for (_, (f, _, _)) in std::mem::take(&mut tcb.recv_reorder) {
                        rx_return.push(f);
                    }
                    rx_return.push(frame);
                    return true;
                }

                if seg_flags & flags::SYN != 0 {
                    if tcb.from_listener {
                        if let Some(l) = listeners.iter_mut().find(|l| {
                            l.port == conn_id.local_port
                                && (l.addr == conn_id.local_addr || l.addr.is_unspecified())
                        }) {
                            if l.pending > 0 { l.pending -= 1; }
                        }
                    } else {
                        tcb.push_rx_event(TcpEvent::Reset, rx_return);
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
                    }
                    for (_, (f, _, _)) in std::mem::take(&mut tcb.recv_reorder) {
                        rx_return.push(f);
                    }
                    rx_return.push(frame);
                    return true;
                }

                if seg_flags & flags::ACK == 0 {
                    rx_return.push(frame);
                    return false;
                }

                // RFC 9293 §3.10.7.3: SND.UNA < SEG.ACK =< SND.NXT
                if seq_lt(tcb.snd_una, seg_ack) && seq_le(seg_ack, tcb.snd_nxt) {
                    tcb.snd_una = seg_ack;
                    tcb.ack_retransmit_queue(seg_ack, now);
                    tcb.state = TcpState::Established;
                    tcb.snd_wnd = (seg_wnd as u32) << tcb.snd_wnd_scale;
                    tcb.snd_wl1 = seg_seq;
                    tcb.snd_wl2 = seg_ack;

                    if tcb.from_listener {
                        let accepted = AcceptedConnection {
                            conn_id,
                            rx_queue: tcb.rx_queue.clone(),
                            cmd_queue: tcb.cmd_queue.clone(),
                            send_buffer: tcb.send_buffer.clone(),
                            send_notify: tcb.send_notify.clone(),
                        };
                        if let Some(l) = listeners.iter_mut().find(|l| {
                            l.port == conn_id.local_port
                                && (l.addr == conn_id.local_addr || l.addr.is_unspecified())
                        }) {
                            if l.pending > 0 { l.pending -= 1; }
                            l.accept_queue.push(accepted);
                        }
                    }
                    tcb.push_rx_event(TcpEvent::Connected, rx_return);

                    if payload_len > 0 || seg_flags & flags::FIN != 0 {
                        Self::process_established_segment(
                            tcb,
                            frame,
                            seg_seq,
                            seg_ack,
                            seg_flags,
                            seg_wnd,
                            payload_offset,
                            payload_len,
                            now,
                            free_frames,
                            rx_return,
                            tx_return,
                        );
                        return false;
                    }
                } else {
                    send_rst_stateless(
                        tcb.conn_id.local_addr,
                        tcb.conn_id.remote_addr,
                        tcb.conn_id.local_port,
                        tcb.conn_id.remote_port,
                        seg_ack,
                        0,
                        false,
                        tcb.local_mac,
                        tcb.remote_mac,
                        free_frames,
                        tx_return,
                    );
                }
                rx_return.push(frame);
                false
            }

            TcpState::Established
            | TcpState::FinWait1
            | TcpState::FinWait2
            | TcpState::CloseWait
            | TcpState::Closing
            | TcpState::LastAck => {
                Self::process_established_segment(
                    tcb,
                    frame,
                    seg_seq,
                    seg_ack,
                    seg_flags,
                    seg_wnd,
                    payload_offset,
                    payload_len,
                    now,
                    free_frames,
                    rx_return,
                    tx_return,
                );
                if tcb.state == TcpState::Closed {
                    for (_, (f, _, _)) in std::mem::take(&mut tcb.recv_reorder) {
                        rx_return.push(f);
                    }
                    true
                } else {
                    false
                }
            }

            TcpState::TimeWait => {
                // Sequence check
                let seg_len = payload_len
                    + if seg_flags & flags::SYN != 0 { 1 } else { 0 }
                    + if seg_flags & flags::FIN != 0 { 1 } else { 0 };
                if !tcb.is_seq_acceptable(seg_seq, seg_len) {
                    if seg_flags & flags::RST == 0 {
                        send_segment(
                            &tcb,
                            tcb.snd_nxt,
                            tcb.rcv_nxt,
                            flags::ACK,
                            tcb.wire_rcv_wnd() as u32,
                            &[],
                            &[],
                            free_frames,
                            tx_return,
                        );
                    }
                    rx_return.push(frame);
                    return false;
                }

                // RST in TIME-WAIT: close
                if seg_flags & flags::RST != 0 {
                    tcb.state = TcpState::Closed;
                    for (_, (f, _, _)) in std::mem::take(&mut tcb.recv_reorder) {
                        rx_return.push(f);
                    }
                    rx_return.push(frame);
                    return true;
                }

                // SYN in TIME-WAIT: signal error and close
                if seg_flags & flags::SYN != 0 {
                    tcb.push_rx_event(TcpEvent::Reset, rx_return);
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
                    for (_, (f, _, _)) in std::mem::take(&mut tcb.recv_reorder) {
                        rx_return.push(f);
                    }
                    rx_return.push(frame);
                    return true;
                }

                // Restart TIME-WAIT timer; re-ACK FIN if present
                tcb.time_wait_start = Some(now);
                if seg_flags & flags::FIN != 0 {
                    send_segment(
                        &tcb,
                        tcb.snd_nxt,
                        tcb.rcv_nxt,
                        flags::ACK,
                        tcb.wire_rcv_wnd() as u32,
                        &[],
                        &[],
                        free_frames,
                        tx_return,
                    );
                }
                rx_return.push(frame);
                false
            }

            TcpState::Closed | TcpState::Listen => {
                rx_return.push(frame);
                false
            }
        }
    }

    /// Processes a segment on an established (or post-established) connection.
    ///
    /// Operates directly on a `&mut Tcb` -- no HashMap lookups.
    /// Sets `tcb.state = TcpState::Closed` when the connection should be removed.
    fn process_established_segment(
        tcb: &mut Tcb<'umem>,
        frame: Frame<'umem>,
        seg_seq: u32,
        seg_ack: u32,
        seg_flags: u8,
        seg_wnd: u16,
        payload_offset: usize,
        payload_len: usize,
        now: Instant,
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        // Sequence check (RFC SEG.LEN includes SYN/FIN)
        let seg_len = payload_len
            + if seg_flags & flags::SYN != 0 { 1 } else { 0 }
            + if seg_flags & flags::FIN != 0 { 1 } else { 0 };
        if !tcb.is_seq_acceptable(seg_seq, seg_len) {
            if seg_flags & flags::RST == 0 {
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
            }
            rx_return.push(frame);
            return;
        }

        // RST check
        if seg_flags & flags::RST != 0 {
            match tcb.state {
                TcpState::Established
                | TcpState::FinWait1
                | TcpState::FinWait2
                | TcpState::CloseWait => {
                    tcb.push_rx_event(TcpEvent::Reset, rx_return);
                    tcb.state = TcpState::Closed;
                }
                TcpState::Closing | TcpState::LastAck | TcpState::TimeWait => {
                    tcb.state = TcpState::Closed;
                }
                _ => {}
            }
            rx_return.push(frame);
            return;
        }

        // SYN in synchronized state is an error
        if seg_flags & flags::SYN != 0 {
            tcb.push_rx_event(TcpEvent::Reset, rx_return);
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
            tcb.state = TcpState::Closed;
            rx_return.push(frame);
            return;
        }

        // ACK check
        if seg_flags & flags::ACK == 0 {
            rx_return.push(frame);
            return;
        }

        // Process the ACK and update send window / congestion state
        {
            let state = tcb.state;

            match state {
                TcpState::Established
                | TcpState::FinWait1
                | TcpState::FinWait2
                | TcpState::CloseWait
                | TcpState::Closing
                | TcpState::LastAck => {
                    if seq_lt(tcb.snd_una, seg_ack) && seq_le(seg_ack, tcb.snd_nxt) {
                        tcb.snd_una = seg_ack;
                        tcb.ack_retransmit_queue(seg_ack, now);

                        // Exit fast recovery when new ACK advances past recovery_point.
                        if tcb.in_fast_recovery && seq_le(tcb.recovery_point, seg_ack) {
                            tcb.in_fast_recovery = false;
                            tcb.dup_ack_count = 0;
                            tcb.congestion.cwnd = tcb.congestion.ssthresh;
                        } else {
                            // Normal congestion control: slow start / congestion avoidance.
                            let mss = tcb.snd_mss as u32;
                            if tcb.congestion.cwnd < tcb.congestion.ssthresh {
                                tcb.congestion.cwnd += mss;
                            } else {
                                // Use u64 intermediate to prevent zero-increment at large windows.
                                let inc = ((mss as u64) * (mss as u64) / (tcb.congestion.cwnd as u64)).max(1) as u32;
                                tcb.congestion.cwnd += inc;
                            }
                        }

                        // Reset dup ACK count on new data ACK.
                        tcb.dup_ack_count = 0;
                    } else if seg_ack == tcb.snd_una && payload_len == 0 && !tcb.retransmit_queue.is_empty() {
                        // Duplicate ACK (RFC 5681 §3.2).
                        tcb.dup_ack_count = tcb.dup_ack_count.saturating_add(1);

                        if tcb.dup_ack_count == 3 && !tcb.in_fast_recovery {
                            // Enter fast recovery: retransmit first unacked segment.
                            let mss = tcb.snd_mss as u32;
                            tcb.congestion.ssthresh = (tcb.congestion.cwnd / 2).max(2 * mss);
                            tcb.congestion.cwnd = tcb.congestion.ssthresh + 3 * mss;
                            tcb.in_fast_recovery = true;
                            tcb.recovery_point = tcb.snd_nxt;

                            // Retransmit the first unacked segment.
                            if let Some(entry) = tcb.retransmit_queue.front_mut() {
                                entry.retransmit_count += 1;
                                entry.is_retransmit = true;
                                let entry_seq = entry.seq;
                                let entry_len = entry.len;
                                let entry_flags = entry.seg_flags;
                                let entry_ack = entry.ack;
                                let entry_wnd = entry.window;
                                let mut entry_opts = [0u8; 8];
                                let entry_opts_len = entry.options_len as usize;
                                entry_opts[..entry_opts_len]
                                    .copy_from_slice(&entry.options[..entry_opts_len]);

                                if let Some(tx_frame) = free_frames.pop() {
                                    let buf_offset = entry_seq.wrapping_sub(tcb.snd_una) as usize;
                                    if entry_len > 0 {
                                        let (a, b) = tcb.send_buffer.peek_slices(buf_offset, entry_len);
                                        let payload_data: &[u8];
                                        let mut scratch = [0u8; 1460];
                                        if b.is_empty() {
                                            payload_data = a;
                                        } else {
                                            scratch[..a.len()].copy_from_slice(a);
                                            scratch[a.len()..a.len() + b.len()].copy_from_slice(b);
                                            payload_data = &scratch[..a.len() + b.len()];
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
                                            payload_data,
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
                            }
                        } else if tcb.in_fast_recovery && tcb.dup_ack_count > 3 {
                            // Inflate cwnd by MSS for each additional dup ACK.
                            tcb.congestion.cwnd += tcb.snd_mss as u32;
                        }
                    } else if seq_lt(tcb.snd_nxt, seg_ack) {
                        // ACK for unsent data -- send ACK and drop.
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
                        rx_return.push(frame);
                        return;
                    }

                    // Window update — applies to both new and duplicate ACKs
                    if seq_lt(tcb.snd_wl1, seg_seq)
                        || (tcb.snd_wl1 == seg_seq && seq_le(tcb.snd_wl2, seg_ack))
                    {
                        tcb.snd_wnd = (seg_wnd as u32) << tcb.snd_wnd_scale;
                        tcb.snd_wl1 = seg_seq;
                        tcb.snd_wl2 = seg_ack;
                    }
                }
                _ => {}
            }
        }

        // State transitions driven by this ACK
        {
            match tcb.state {
                TcpState::FinWait1 => {
                    if seg_ack == tcb.snd_nxt {
                        tcb.state = TcpState::FinWait2;
                    }
                }
                TcpState::Closing => {
                    if seg_ack == tcb.snd_nxt {
                        tcb.state = TcpState::TimeWait;
                        tcb.time_wait_start = Some(now);
                        rx_return.push(frame);
                        return;
                    }
                }
                TcpState::LastAck => {
                    if seg_ack == tcb.snd_nxt {
                        tcb.state = TcpState::Closed;
                        tcb.push_rx_event(TcpEvent::Closed, rx_return);
                        rx_return.push(frame);
                        return;
                    }
                }
                _ => {}
            }
        }

        // Deliver payload data when in a receive-capable state
        {
            match tcb.state {
                TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2 => {
                    if payload_len > 0 {
                        if seg_seq == tcb.rcv_nxt {
                            // In-order data -- deliver directly.
                            tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(payload_len as u32);

                            // Deliver in-order frame first, then drain reorder buffer
                            tcb.push_rx_event(TcpEvent::Data {
                                frame,
                                payload_offset,
                                payload_len,
                            }, rx_return);
                            loop {
                                let next = tcb.rcv_nxt;
                                if let Some((f, off, len)) = tcb.recv_reorder.remove(&next) {
                                    tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(len as u32);
                                    tcb.push_rx_event(TcpEvent::Data {
                                        frame: f,
                                        payload_offset: off,
                                        payload_len: len,
                                    }, rx_return);
                                } else {
                                    break;
                                }
                            }

                            // Delayed ACK (RFC 1122 §4.2.3.2):
                            // ACK every 2nd in-order data segment immediately,
                            // or when PSH is set (sender has no more buffered data).
                            tcb.delayed_ack_pending += 1;
                            if tcb.delayed_ack_at.is_none() {
                                tcb.delayed_ack_at = Some(now);
                            }
                            if tcb.delayed_ack_pending >= 2 {
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

                            if seg_flags & flags::FIN != 0 {
                                Self::process_fin(tcb, now, free_frames, rx_return, tx_return);
                            }
                            return; // frame consumed by rx_queue
                        } else if seq_lt(tcb.rcv_nxt, seg_seq) {
                            // Out-of-order -- buffer.
                            tcb.recv_reorder
                                .insert(seg_seq, (frame, payload_offset, payload_len));
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
                            return; // frame consumed by reorder buffer
                        }
                        // else: seq < rcv_nxt means old data, drop.
                    }
                }
                _ => {}
            }
        }

        // FIN processing
        if seg_flags & flags::FIN != 0 {
            Self::process_fin(tcb, now, free_frames, rx_return, tx_return);
        }

        rx_return.push(frame);
    }

    fn process_fin(
        tcb: &mut Tcb<'umem>,
        now: Instant,
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);

        match tcb.state {
            TcpState::Established => {
                tcb.state = TcpState::CloseWait;
                tcb.push_rx_event(TcpEvent::Fin, rx_return);
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
            }
            TcpState::FinWait1 => {
                tcb.state = TcpState::Closing;
                tcb.push_rx_event(TcpEvent::Fin, rx_return);
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
            }
            TcpState::FinWait2 => {
                tcb.state = TcpState::TimeWait;
                tcb.time_wait_start = Some(now);
                tcb.push_rx_event(TcpEvent::Fin, rx_return);
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
            }
            _ => {
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
            }
        }
    }
}
