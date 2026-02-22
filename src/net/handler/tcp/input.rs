use std::collections::{BTreeMap, VecDeque};
use std::time::Instant;

use crate::net::socket::SharedQueue;
use crate::net::wire::ethernet::{EthernetFrame, MacAddress};
use crate::net::wire::ip::{IPV6_HEADER_LEN, IpAddress, Ipv4Header, Ipv6Header};
use crate::net::wire::tcp::{
    self, TCP_HEADER_LEN, TcpHeader, flags, parse_mss, seq_le, seq_lt, write_mss_option,
};
use crate::xdp::frame::{BasicFrameBuffer, Frame, FrameBuffer, SharedFrameBuffer};

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
        mut frame: Frame<'umem>,
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

        let (src_port, dst_port, tcp_header_len) = {
            let tcp = unsafe { TcpHeader::from_frame_at(&frame, tcp_offset) };
            (tcp.src_port(), tcp.dst_port(), tcp.header_len())
        };

        if tcp_header_len < TCP_HEADER_LEN || frame.len() < tcp_offset + tcp_header_len {
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
            &mut frame[tcp_offset..tcp_offset + tcp_segment_len],
        ) {
            rx_return.push(frame);
            return;
        }

        self.process_segment(
            frame,
            IpAddress::V4(src_addr),
            IpAddress::V4(dst_addr),
            src_port,
            dst_port,
            tcp_offset,
            tcp_segment_len,
            src_mac,
            dst_mac,
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
        mut frame: Frame<'umem>,
        tcp_offset: usize,
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

        let (src_port, dst_port, tcp_header_len) = {
            let tcp = unsafe { TcpHeader::from_frame_at(&frame, tcp_offset) };
            (tcp.src_port(), tcp.dst_port(), tcp.header_len())
        };

        if tcp_header_len < TCP_HEADER_LEN
            || tcp_segment_len < TCP_HEADER_LEN
            || frame.len() < tcp_offset + tcp_segment_len
        {
            rx_return.push(frame);
            return;
        }

        if !tcp::verify_tcp_checksum_v6(
            &src_addr,
            &dst_addr,
            &mut frame[tcp_offset..tcp_offset + tcp_segment_len],
        ) {
            rx_return.push(frame);
            return;
        }

        self.process_segment(
            frame,
            IpAddress::V6(src_addr),
            IpAddress::V6(dst_addr),
            src_port,
            dst_port,
            tcp_offset,
            tcp_segment_len,
            src_mac,
            dst_mac,
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
        src_port: u16,
        dst_port: u16,
        tcp_offset: usize,
        tcp_segment_len: usize,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let conn_id = ConnectionId {
            local_addr: dst_addr,
            local_port: dst_port,
            remote_addr: src_addr,
            remote_port: src_port,
        };

        // Try existing connection first.
        if self.connections.contains_key(&conn_id) {
            self.process_for_connection(
                conn_id,
                frame,
                tcp_offset,
                tcp_segment_len,
                free_frames,
                rx_return,
                tx_return,
            );
            return;
        }

        // Try listener.
        let tcp = unsafe { TcpHeader::from_frame_at(&frame, tcp_offset) };
        let seg_flags = tcp.flags();

        if seg_flags & flags::RST != 0 {
            // RST to no connection (LISTEN state behavior): ignore.
            rx_return.push(frame);
            return;
        }

        if seg_flags & flags::ACK != 0 && seg_flags & flags::SYN == 0 {
            // ACK to no connection: send RST.
            let seq = tcp.ack_num();
            rx_return.push(frame);
            send_rst_stateless(
                dst_addr,
                src_addr,
                dst_port,
                src_port,
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
            if let Some(listener_idx) = self.find_listener(dst_addr, dst_port) {
                let listener = &self.listeners[listener_idx];
                if listener.pending >= listener.backlog {
                    rx_return.push(frame);
                    return;
                }

                // Parse MSS from SYN options.
                let tcp_header_len = tcp.header_len();
                let peer_mss = if tcp_header_len > TCP_HEADER_LEN {
                    let opts_start = tcp_offset + TCP_HEADER_LEN;
                    let opts_end = tcp_offset + tcp_header_len;
                    if opts_end <= frame.len() {
                        parse_mss(&frame[opts_start..opts_end]).unwrap_or(536)
                    } else {
                        536
                    }
                } else {
                    536
                };

                let seg_seq = tcp.seq_num();
                let seg_wnd = tcp.window();
                let iss = generate_isn(&conn_id);

                let rx_queue = SharedQueue::new(256);
                let cmd_queue = SharedQueue::new(64);
                let send_buffer: SharedFrameBuffer = BasicFrameBuffer::new(256).into();

                let mut tcb = Tcb {
                    state: TcpState::SynReceived,
                    conn_id,
                    snd_una: iss,
                    snd_nxt: iss.wrapping_add(1),
                    snd_wnd: seg_wnd,
                    snd_wl1: seg_seq,
                    snd_wl2: iss,
                    iss,
                    rcv_nxt: seg_seq.wrapping_add(1),
                    rcv_wnd: DEFAULT_RCV_WND,
                    irs: seg_seq,
                    snd_mss: peer_mss,
                    rcv_mss: DEFAULT_RCV_MSS,
                    last_activity: Instant::now(),
                    time_wait_start: None,
                    rx_queue,
                    cmd_queue,
                    send_buffer,
                    recv_reorder: BTreeMap::new(),
                    retransmit_queue: VecDeque::new(),
                    rto_state: RtoState::new(),
                    congestion: CongestionState::new(peer_mss),
                    from_listener: true,
                    local_mac: dst_mac,
                    remote_mac: src_mac,
                };

                // Send SYN-ACK with retransmit
                let rcv_nxt = tcb.rcv_nxt;
                let rcv_wnd = tcb.rcv_wnd;
                let mut mss_opt = [0u8; 4];
                write_mss_option(&mut mss_opt, tcb.rcv_mss);
                send_and_queue_retransmit(
                    &mut tcb,
                    iss,
                    rcv_nxt,
                    flags::SYN | flags::ACK,
                    rcv_wnd,
                    &mss_opt,
                    1,
                    free_frames,
                    tx_return,
                );
                self.listeners[listener_idx].pending += 1;
                self.connections.insert(conn_id, tcb);
                rx_return.push(frame);
                return;
            }
        }

        // No matching connection or listener -- send RST.
        let tcp = unsafe { TcpHeader::from_frame_at(&frame, tcp_offset) };
        let rst_seq;
        let rst_ack;
        let rst_has_ack;
        if seg_flags & flags::ACK != 0 {
            rst_seq = tcp.ack_num();
            rst_ack = 0;
            rst_has_ack = false;
        } else {
            let tcp_header_len = tcp.header_len();
            let data_len = if tcp_segment_len > tcp_header_len {
                tcp_segment_len - tcp_header_len
            } else {
                0
            };
            let seg_len = data_len
                + if seg_flags & flags::SYN != 0 { 1 } else { 0 }
                + if seg_flags & flags::FIN != 0 { 1 } else { 0 };
            rst_seq = 0;
            rst_ack = tcp.seq_num().wrapping_add(seg_len as u32);
            rst_has_ack = true;
        }
        rx_return.push(frame);
        send_rst_stateless(
            dst_addr,
            src_addr,
            dst_port,
            src_port,
            rst_seq,
            rst_ack,
            rst_has_ack,
            dst_mac,
            src_mac,
            free_frames,
            tx_return,
        );
    }

    fn process_for_connection(
        &mut self,
        conn_id: ConnectionId,
        frame: Frame<'umem>,
        tcp_offset: usize,
        tcp_segment_len: usize,
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let tcp = unsafe { TcpHeader::from_frame_at(&frame, tcp_offset) };
        let seg_seq = tcp.seq_num();
        let seg_ack = tcp.ack_num();
        let seg_flags = tcp.flags();
        let seg_wnd = tcp.window();
        let tcp_header_len = tcp.header_len();
        let payload_offset = tcp_offset + tcp_header_len;
        let payload_len = if tcp_segment_len > tcp_header_len {
            tcp_segment_len - tcp_header_len
        } else {
            0
        };

        let tcb = self.connections.get_mut(&conn_id).unwrap();
        tcb.last_activity = Instant::now();

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
                        return;
                    }
                }

                if seg_flags & flags::RST != 0 {
                    if seg_flags & flags::ACK != 0 {
                        let tcb = self.connections.get_mut(&conn_id).unwrap();
                        tcb.state = TcpState::Closed;
                        tcb.rx_queue.push(TcpEvent::Reset);
                        self.remove_connection(&conn_id, rx_return);
                    }
                    rx_return.push(frame);
                    return;
                }

                if seg_flags & flags::SYN != 0 {
                    let tcb = self.connections.get_mut(&conn_id).unwrap();

                    // Parse MSS from SYN options.
                    if tcp_header_len > TCP_HEADER_LEN {
                        let opts_start = tcp_offset + TCP_HEADER_LEN;
                        let opts_end = tcp_offset + tcp_header_len;
                        if opts_end <= frame.len() {
                            if let Some(mss) = parse_mss(&frame[opts_start..opts_end]) {
                                tcb.snd_mss = mss;
                            }
                        }
                    }

                    tcb.irs = seg_seq;
                    tcb.rcv_nxt = seg_seq.wrapping_add(1);
                    tcb.snd_wnd = seg_wnd;
                    tcb.snd_wl1 = seg_seq;
                    tcb.snd_wl2 = seg_ack;

                    if seg_flags & flags::ACK != 0 {
                        tcb.snd_una = seg_ack;
                        tcb.ack_retransmit_queue(seg_ack, rx_return);
                        tcb.state = TcpState::Established;
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
                        tcb.rx_queue.push(TcpEvent::Connected);
                    } else {
                        // Simultaneous open
                        tcb.state = TcpState::SynReceived;
                        let iss = tcb.iss;
                        let rcv_nxt = tcb.rcv_nxt;
                        let rcv_wnd = tcb.rcv_wnd;
                        let mut mss_opt = [0u8; 4];
                        write_mss_option(&mut mss_opt, tcb.rcv_mss);
                        send_and_queue_retransmit(
                            tcb,
                            iss,
                            rcv_nxt,
                            flags::SYN | flags::ACK,
                            rcv_wnd,
                            &mss_opt,
                            1,
                            free_frames,
                            tx_return,
                        );
                    }
                }
                rx_return.push(frame);
            }

            TcpState::SynReceived => {
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
                            tcb.rcv_wnd,
                            &[],
                            &[],
                            free_frames,
                            tx_return,
                        );
                    }
                    rx_return.push(frame);
                    return;
                }

                if seg_flags & flags::RST != 0 {
                    if tcb.from_listener {
                        self.decrement_listener_pending(&conn_id);
                        self.remove_connection(&conn_id, rx_return);
                    } else {
                        let tcb = self.connections.get_mut(&conn_id).unwrap();
                        tcb.state = TcpState::Closed;
                        tcb.rx_queue.push(TcpEvent::Reset);
                        self.remove_connection(&conn_id, rx_return);
                    }
                    rx_return.push(frame);
                    return;
                }

                if seg_flags & flags::SYN != 0 {
                    if tcb.from_listener {
                        // RFC 9293 §3.10.7.3: passive open — return to LISTEN.
                        self.decrement_listener_pending(&conn_id);
                        self.remove_connection(&conn_id, rx_return);
                    } else {
                        // Active open — signal reset per RFC.
                        let tcb = self.connections.get(&conn_id).unwrap();
                        tcb.rx_queue.push(TcpEvent::Reset);
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
                        self.remove_connection(&conn_id, rx_return);
                    }
                    rx_return.push(frame);
                    return;
                }

                if seg_flags & flags::ACK == 0 {
                    rx_return.push(frame);
                    return;
                }

                // RFC 9293 §3.10.7.3: SND.UNA < SEG.ACK =< SND.NXT
                let tcb = self.connections.get_mut(&conn_id).unwrap();
                if seq_lt(tcb.snd_una, seg_ack) && seq_le(seg_ack, tcb.snd_nxt) {
                    tcb.snd_una = seg_ack;
                    tcb.ack_retransmit_queue(seg_ack, rx_return);
                    tcb.state = TcpState::Established;
                    tcb.snd_wnd = seg_wnd;
                    tcb.snd_wl1 = seg_seq;
                    tcb.snd_wl2 = seg_ack;

                    if tcb.from_listener {
                        // Decrement pending now that the connection is fully established.
                        self.decrement_listener_pending(&conn_id);

                        let tcb = self.connections.get(&conn_id).unwrap();
                        let accepted = AcceptedConnection {
                            local_addr: conn_id.local_addr,
                            local_port: conn_id.local_port,
                            remote_addr: conn_id.remote_addr,
                            remote_port: conn_id.remote_port,
                            rx_queue: tcb.rx_queue.clone(),
                            cmd_queue: tcb.cmd_queue.clone(),
                            send_buffer: tcb.send_buffer.clone(),
                        };
                        if let Some(idx) =
                            self.find_listener(conn_id.local_addr, conn_id.local_port)
                        {
                            self.listeners[idx].accept_queue.push(accepted);
                        }
                    }
                    let tcb = self.connections.get_mut(&conn_id).unwrap();
                    tcb.rx_queue.push(TcpEvent::Connected);

                    if payload_len > 0 || seg_flags & flags::FIN != 0 {
                        self.process_established_segment(
                            conn_id,
                            frame,
                            tcp_offset,
                            seg_seq,
                            seg_ack,
                            seg_flags,
                            seg_wnd,
                            payload_offset,
                            payload_len,
                            free_frames,
                            rx_return,
                            tx_return,
                        );
                        return;
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
            }

            TcpState::Established
            | TcpState::FinWait1
            | TcpState::FinWait2
            | TcpState::CloseWait
            | TcpState::Closing
            | TcpState::LastAck => {
                self.process_established_segment(
                    conn_id,
                    frame,
                    tcp_offset,
                    seg_seq,
                    seg_ack,
                    seg_flags,
                    seg_wnd,
                    payload_offset,
                    payload_len,
                    free_frames,
                    rx_return,
                    tx_return,
                );
            }

            TcpState::TimeWait => {
                let tcb = self.connections.get_mut(&conn_id).unwrap();

                // Sequence check
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
                            tcb.rcv_wnd,
                            &[],
                            &[],
                            free_frames,
                            tx_return,
                        );
                    }
                    rx_return.push(frame);
                    return;
                }

                // RST in TIME-WAIT: close
                if seg_flags & flags::RST != 0 {
                    tcb.state = TcpState::Closed;
                    self.remove_connection(&conn_id, rx_return);
                    rx_return.push(frame);
                    return;
                }

                // SYN in TIME-WAIT: signal error and close
                if seg_flags & flags::SYN != 0 {
                    tcb.rx_queue.push(TcpEvent::Reset);
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
                    self.remove_connection(&conn_id, rx_return);
                    rx_return.push(frame);
                    return;
                }

                // Restart TIME-WAIT timer; re-ACK FIN if present
                tcb.time_wait_start = Some(Instant::now());
                if seg_flags & flags::FIN != 0 {
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
                }
                rx_return.push(frame);
            }

            TcpState::Closed | TcpState::Listen => {
                rx_return.push(frame);
            }
        }
    }

    pub(super) fn process_established_segment(
        &mut self,
        conn_id: ConnectionId,
        frame: Frame<'umem>,
        _tcp_offset: usize,
        seg_seq: u32,
        seg_ack: u32,
        seg_flags: u8,
        seg_wnd: u16,
        payload_offset: usize,
        payload_len: usize,
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        // Sequence check (RFC SEG.LEN includes SYN/FIN)
        let seg_len = payload_len
            + if seg_flags & flags::SYN != 0 { 1 } else { 0 }
            + if seg_flags & flags::FIN != 0 { 1 } else { 0 };
        let tcb = self.connections.get_mut(&conn_id).unwrap();
        if !tcb.is_seq_acceptable(seg_seq, seg_len) {
            if seg_flags & flags::RST == 0 {
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
                    tcb.rx_queue.push(TcpEvent::Reset);
                    tcb.state = TcpState::Closed;
                    self.remove_connection(&conn_id, rx_return);
                }
                TcpState::Closing | TcpState::LastAck | TcpState::TimeWait => {
                    tcb.state = TcpState::Closed;
                    self.remove_connection(&conn_id, rx_return);
                }
                _ => {}
            }
            rx_return.push(frame);
            return;
        }

        // SYN in synchronized state is an error
        if seg_flags & flags::SYN != 0 {
            tcb.rx_queue.push(TcpEvent::Reset);
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
            self.remove_connection(&conn_id, rx_return);
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
            let tcb = self.connections.get_mut(&conn_id).unwrap();
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
                        tcb.ack_retransmit_queue(seg_ack, rx_return);

                        // Congestion: ACK processing
                        let mss = tcb.snd_mss as u32;
                        if tcb.congestion.cwnd < tcb.congestion.ssthresh {
                            tcb.congestion.cwnd += mss;
                        } else {
                            tcb.congestion.cwnd += mss * mss / tcb.congestion.cwnd;
                        }
                    } else if seq_lt(tcb.snd_nxt, seg_ack) {
                        // ACK for unsent data -- send ACK and drop.
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
                        rx_return.push(frame);
                        return;
                    }

                    // Window update — applies to both new and duplicate ACKs
                    if seq_lt(tcb.snd_wl1, seg_seq)
                        || (tcb.snd_wl1 == seg_seq && seq_le(tcb.snd_wl2, seg_ack))
                    {
                        tcb.snd_wnd = seg_wnd;
                        tcb.snd_wl1 = seg_seq;
                        tcb.snd_wl2 = seg_ack;
                    }
                }
                _ => {}
            }
        }

        // State transitions driven by this ACK
        {
            let tcb = self.connections.get_mut(&conn_id).unwrap();
            match tcb.state {
                TcpState::FinWait1 => {
                    if seg_ack == tcb.snd_nxt {
                        tcb.state = TcpState::FinWait2;
                    }
                }
                TcpState::Closing => {
                    if seg_ack == tcb.snd_nxt {
                        tcb.state = TcpState::TimeWait;
                        tcb.time_wait_start = Some(Instant::now());
                        rx_return.push(frame);
                        return;
                    }
                }
                TcpState::LastAck => {
                    if seg_ack == tcb.snd_nxt {
                        tcb.state = TcpState::Closed;
                        tcb.rx_queue.push(TcpEvent::Closed);
                        self.remove_connection(&conn_id, rx_return);
                        rx_return.push(frame);
                        return;
                    }
                }
                _ => {}
            }
        }

        // Deliver payload data when in a receive-capable state
        {
            let tcb = self.connections.get_mut(&conn_id).unwrap();
            match tcb.state {
                TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2 => {
                    if payload_len > 0 {
                        if seg_seq == tcb.rcv_nxt {
                            // In-order data -- deliver directly.
                            tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(payload_len as u32);

                            // Deliver in-order frame first, then drain reorder buffer
                            tcb.rx_queue.push(TcpEvent::Data {
                                frame,
                                payload_offset,
                                payload_len,
                            });
                            loop {
                                let next = tcb.rcv_nxt;
                                if let Some((f, off, len)) = tcb.recv_reorder.remove(&next) {
                                    tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(len as u32);
                                    tcb.rx_queue.push(TcpEvent::Data {
                                        frame: f,
                                        payload_offset: off,
                                        payload_len: len,
                                    });
                                } else {
                                    break;
                                }
                            }

                            // Send ACK
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

                            if seg_flags & flags::FIN != 0 {
                                let _ = tcb;
                                self.process_fin(conn_id, free_frames, rx_return, tx_return);
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
                                tcb.rcv_wnd,
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
            self.process_fin(conn_id, free_frames, rx_return, tx_return);
        }

        rx_return.push(frame);
    }

    fn process_fin(
        &mut self,
        conn_id: ConnectionId,
        free_frames: &mut impl FrameBuffer<'umem>,
        _rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let tcb = self.connections.get_mut(&conn_id).unwrap();
        tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);

        match tcb.state {
            TcpState::Established => {
                tcb.state = TcpState::CloseWait;
                tcb.rx_queue.push(TcpEvent::PeerClosed);
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
            }
            TcpState::FinWait1 => {
                tcb.state = TcpState::Closing;
                tcb.rx_queue.push(TcpEvent::PeerClosed);
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
            }
            TcpState::FinWait2 => {
                tcb.state = TcpState::TimeWait;
                tcb.time_wait_start = Some(Instant::now());
                tcb.rx_queue.push(TcpEvent::PeerClosed);
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
            }
            _ => {
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
            }
        }
    }
}
