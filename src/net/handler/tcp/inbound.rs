use coarsetime::Instant;

use crate::{
    net::{
        NeighborHandler,
        checksum::{verify_tcp_checksum, verify_tcp_checksum_v6},
        socket::LocalQueue,
        wire::{
            ethernet::EthernetFrame,
            ip::{IpAddress, Ipv4Header, Ipv6Header},
            tcp::{
                TCP_HEADER_LEN, TcpHeader, flags, parse_mss, parse_sack_permitted, parse_timestamp,
                parse_window_scale,
            },
        },
    },
    xdp::frame::{Frame, FrameBuffer},
};

use std::collections::BTreeMap;

use rustc_hash::FxHashMap;

use super::congestion::CubicState;
use super::handler::{INITIAL_RTO_MS, TcpHandler};
use super::listener::ListenEntry;
use super::options::ParsedOptions;
use super::recovery::{FRtoAction, FRtoState, PrrState, SackRecovery};
use super::ring_buffer::RingBuffer;
use super::segment::SegmentBuilder;
use super::state::TcpState;
use super::tcb::{
    ConnectionId, DEFAULT_RCV_MSS, DEFAULT_RCV_WND, DEFAULT_RCV_WSCALE, TS_OPTION_LEN, Tcb,
    TcpEvent,
};

use super::isn::IsnGenerator;
use super::send_tracker::SendReady;

/// Actions that must be performed after releasing the `&mut Tcb` borrow.
enum PostAction {
    None,
    RemoveConnection(ConnectionId),
    RemoveAndDecrement(ConnectionId),
}

/// Check segment acceptability per RFC 9293 §3.10.7.4.
#[inline]
pub(super) fn is_segment_acceptable(
    seg_seq: u32,
    seg_len: u32,
    rcv_nxt: u32,
    rcv_wnd: u32,
) -> bool {
    use crate::net::wire::tcp::{seq_le, seq_lt};

    if seg_len == 0 {
        if rcv_wnd == 0 {
            seg_seq == rcv_nxt
        } else {
            seq_le(rcv_nxt, seg_seq) && seq_lt(seg_seq, rcv_nxt.wrapping_add(rcv_wnd))
        }
    } else if rcv_wnd == 0 {
        false
    } else {
        let seg_end = seg_seq.wrapping_add(seg_len - 1);
        let wnd_end = rcv_nxt.wrapping_add(rcv_wnd);
        (seq_le(rcv_nxt, seg_seq) && seq_lt(seg_seq, wnd_end))
            || (seq_le(rcv_nxt, seg_end) && seq_lt(seg_end, wnd_end))
    }
}

impl TcpHandler {
    // --- Segment processing ---

    /// Process an incoming IPv4 TCP segment.
    pub fn process_ipv4<'umem>(
        &mut self,
        frame: Frame<'umem>,
        now: Instant,
        neighbor_handler: &NeighborHandler,
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let ip = Ipv4Header::from_bytes(&frame);
        let src_addr = ip.src_addr;
        let dst_addr = ip.dst_addr;
        let tcp_offset = ip.payload_offset();

        if frame.len() < tcp_offset + TCP_HEADER_LEN {
            rx_return.push(frame);
            return;
        }

        let tcp = unsafe { TcpHeader::from_bytes_at(&frame, tcp_offset) };

        // Validate data offset.
        let data_offset = tcp.data_offset();
        if data_offset < 5 || frame.len() < tcp_offset + tcp.header_len() {
            rx_return.push(frame);
            return;
        }

        // Checksum verification.
        if !self.rx_offload {
            let tcp_segment = &frame[tcp_offset..];
            if !verify_tcp_checksum(&src_addr, &dst_addr, tcp_segment) {
                rx_return.push(frame);
                return;
            }
        }

        let src_port = tcp.src_port();
        let dst_port = tcp.dst_port();
        let seg_seq = tcp.seq_num();
        let seg_ack = tcp.ack_num();
        let seg_flags = tcp.flags();
        let seg_wnd = tcp.window() as u32;
        let header_len = tcp.header_len();

        // Copy options to stack buffer before moving frame.
        let mut opt_buf = [0u8; 40];
        let opt_len = if header_len > TCP_HEADER_LEN {
            let len = header_len - TCP_HEADER_LEN;
            opt_buf[..len]
                .copy_from_slice(&frame[tcp_offset + TCP_HEADER_LEN..tcp_offset + header_len]);
            len
        } else {
            0
        };

        let seg_data_len = frame.len() - tcp_offset - header_len;
        let seg_len = Tcb::seg_len(seg_data_len, seg_flags);

        // IPv4 ToS byte is at ethernet header length + 1.
        // ECN bits are the low 2 bits of the ToS byte.
        let ecn_bits = frame[std::mem::size_of::<EthernetFrame>() + 1] & 0x03;

        let incoming_src = IpAddress::V4(src_addr);
        let incoming_dst = IpAddress::V4(dst_addr);
        let src_mac = neighbor_handler.local_mac();
        // For responses, swap MACs from incoming frame.
        let dst_mac = EthernetFrame::from_bytes(&frame).src_mac;

        self.process_segment(
            frame,
            now,
            incoming_src,
            incoming_dst,
            src_port,
            dst_port,
            seg_seq,
            seg_ack,
            seg_flags,
            seg_wnd,
            seg_len,
            &opt_buf[..opt_len],
            tcp_offset,
            header_len,
            ecn_bits,
            src_mac,
            dst_mac,
            free_frames,
            rx_return,
            tx_return,
        );
    }

    /// Process an incoming IPv6 TCP segment.
    pub fn process_ipv6<'umem>(
        &mut self,
        frame: Frame<'umem>,
        tcp_offset: usize,
        now: Instant,
        neighbor_handler: &NeighborHandler,
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let ip = Ipv6Header::from_bytes(&frame);
        let src_addr = ip.src_addr;
        let dst_addr = ip.dst_addr;

        if frame.len() < tcp_offset + TCP_HEADER_LEN {
            rx_return.push(frame);
            return;
        }

        let tcp = unsafe { TcpHeader::from_bytes_at(&frame, tcp_offset) };

        let data_offset = tcp.data_offset();
        if data_offset < 5 || frame.len() < tcp_offset + tcp.header_len() {
            rx_return.push(frame);
            return;
        }

        if !self.rx_offload {
            let tcp_segment = &frame[tcp_offset..];
            if !verify_tcp_checksum_v6(&src_addr, &dst_addr, tcp_segment) {
                rx_return.push(frame);
                return;
            }
        }

        let src_port = tcp.src_port();
        let dst_port = tcp.dst_port();
        let seg_seq = tcp.seq_num();
        let seg_ack = tcp.ack_num();
        let seg_flags = tcp.flags();
        let seg_wnd = tcp.window() as u32;
        let header_len = tcp.header_len();

        // Copy options to stack buffer before moving frame.
        let mut opt_buf = [0u8; 40];
        let opt_len = if header_len > TCP_HEADER_LEN {
            let len = header_len - TCP_HEADER_LEN;
            opt_buf[..len]
                .copy_from_slice(&frame[tcp_offset + TCP_HEADER_LEN..tcp_offset + header_len]);
            len
        } else {
            0
        };

        let seg_data_len = frame.len() - tcp_offset - header_len;
        let seg_len = Tcb::seg_len(seg_data_len, seg_flags);

        // IPv6 TC ECN bits: (frame_data[ETH_LEN + 1] >> 4) & 0x03
        let ecn_bits = (frame[std::mem::size_of::<EthernetFrame>() + 1] >> 4) & 0x03;

        let incoming_src = IpAddress::V6(src_addr);
        let incoming_dst = IpAddress::V6(dst_addr);
        let src_mac = neighbor_handler.local_mac();
        let dst_mac = EthernetFrame::from_bytes(&frame).src_mac;

        self.process_segment(
            frame,
            now,
            incoming_src,
            incoming_dst,
            src_port,
            dst_port,
            seg_seq,
            seg_ack,
            seg_flags,
            seg_wnd,
            seg_len,
            &opt_buf[..opt_len],
            tcp_offset,
            header_len,
            ecn_bits,
            src_mac,
            dst_mac,
            free_frames,
            rx_return,
            tx_return,
        );
    }

    /// Unified segment processing for both IPv4 and IPv6.
    #[inline]
    fn process_segment<'umem>(
        &mut self,
        frame: Frame<'umem>,
        now: Instant,
        incoming_src: IpAddress,
        incoming_dst: IpAddress,
        src_port: u16,
        dst_port: u16,
        seg_seq: u32,
        seg_ack: u32,
        seg_flags: u8,
        seg_wnd: u32,
        seg_len: u32,
        options: &[u8],
        tcp_offset: usize,
        tcp_header_len: usize,
        ecn_bits: u8,
        src_mac: crate::net::wire::ethernet::MacAddress,
        dst_mac: crate::net::wire::ethernet::MacAddress,
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        // Look up existing connection.
        let conn_id = ConnectionId {
            local_addr: incoming_dst,
            local_port: dst_port,
            remote_addr: incoming_src,
            remote_port: src_port,
        };

        // Destructure self for split borrows.
        let Self { connections, listeners, isn_generator, send_tracker, tx_offload, rx_offload: _, .. } = self;
        let tx_offload = *tx_offload;

        if let Some(tcb) = connections.get_mut(&conn_id) {
            let tsval = if tcb.ts_enabled {
                now.duration_since(tcb.ts_offset).as_millis() as u32
            } else {
                0
            };
            let state = tcb.state;
            let action = match state {
                TcpState::SynSent => {
                    let action = Self::process_syn_sent(
                        tcb,
                        now,
                        tsval,
                        seg_seq,
                        seg_ack,
                        seg_flags,
                        seg_wnd,
                        options,
                        src_mac,
                        dst_mac,
                        tx_offload,
                        free_frames,
                        tx_return,
                    );
                    rx_return.push(frame);
                    action
                }
                TcpState::SynReceived => {
                    let action = Self::process_syn_received(
                        tcb,
                        listeners,
                        tsval,
                        seg_seq,
                        seg_ack,
                        seg_flags,
                        seg_wnd,
                        seg_len,
                        src_mac,
                        dst_mac,
                        tx_offload,
                        free_frames,
                        tx_return,
                    );
                    rx_return.push(frame);
                    action
                }
                TcpState::Established => {
                    let payload_offset = tcp_offset + tcp_header_len;
                    let payload_len = frame.len().saturating_sub(payload_offset);
                    let opts = ParsedOptions::parse(options);
                    let action = Self::process_established(
                        tcb,
                        frame,
                        now,
                        tsval,
                        seg_seq,
                        seg_ack,
                        seg_flags,
                        seg_wnd,
                        payload_offset,
                        payload_len,
                        &opts,
                        ecn_bits,
                        src_mac,
                        dst_mac,
                        tx_offload,
                        free_frames,
                        rx_return,
                        tx_return,
                    );
                    action
                }
                TcpState::FinWait1
                | TcpState::FinWait2
                | TcpState::CloseWait
                | TcpState::Closing
                | TcpState::LastAck
                | TcpState::TimeWait => {
                    let payload_offset = tcp_offset + tcp_header_len;
                    let payload_len = frame.len().saturating_sub(payload_offset);
                    let opts = ParsedOptions::parse(options);
                    let action = Self::process_teardown(
                        tcb,
                        frame,
                        now,
                        tsval,
                        seg_seq,
                        seg_ack,
                        seg_flags,
                        seg_wnd,
                        payload_offset,
                        payload_len,
                        &opts,
                        src_mac,
                        dst_mac,
                        tx_offload,
                        free_frames,
                        rx_return,
                        tx_return,
                    );
                    action
                }
                _ => {
                    rx_return.push(frame);
                    PostAction::None
                }
            };

            // Handle deferred actions after tcb borrow is released.
            match action {
                PostAction::RemoveConnection(id) => {
                    send_tracker.unmark(&id);
                    connections.remove(&id);
                }
                PostAction::RemoveAndDecrement(id) => {
                    Self::decrement_syn_received(listeners, &id);
                    send_tracker.unmark(&id);
                    connections.remove(&id);
                }
                PostAction::None => {
                    // Mark connection for send processing if it has pending work.
                    if let Some(tcb) = connections.get(&conn_id) {
                        if tcb.ack_pending
                            || tcb.pending_fin
                            || tcb.send_buffer.available() > 0
                            || tcb.ecn_cwr_sent
                            || tcb.persist_deadline.is_some()
                            || tcb.retransmit_deadline.is_some()
                        {
                            send_tracker.mark(SendReady(conn_id));
                        }
                    }
                }
            }
            return;
        }

        // No connection found — check listeners (LISTEN state, §16.2).
        if let Some(listener_idx) = listeners
            .iter()
            .position(|l| l.port == dst_port && (l.addr.is_unspecified() || l.addr == incoming_dst))
        {
            Self::process_listen(
                connections,
                listeners,
                isn_generator,
                listener_idx,
                now,
                incoming_src,
                incoming_dst,
                src_port,
                dst_port,
                seg_seq,
                seg_ack,
                seg_flags,
                seg_wnd,
                seg_len,
                options,
                src_mac,
                dst_mac,
                tx_offload,
                free_frames,
                tx_return,
            );
            // New SynReceived connection needs retransmit timer tracking.
            let new_conn_id = ConnectionId {
                local_addr: incoming_dst,
                local_port: dst_port,
                remote_addr: incoming_src,
                remote_port: src_port,
            };
            if connections.contains_key(&new_conn_id) {
                send_tracker.mark(SendReady(new_conn_id));
            }
            rx_return.push(frame);
            return;
        }

        // CLOSED state — no connection, no listener.
        // RST segments are silently dropped (no RST for RST).
        if seg_flags & flags::RST != 0 {
            rx_return.push(frame);
            return;
        }

        // Send RST per RFC §16.1.
        SegmentBuilder::build_rst(
            incoming_src,
            incoming_dst,
            src_port,
            dst_port,
            seg_seq,
            seg_ack,
            seg_flags,
            seg_len,
            src_mac,
            dst_mac,
            tx_offload,
            free_frames,
            tx_return,
        );
        rx_return.push(frame);
    }

    // --- LISTEN state processing (RFC §16.2) ---

    fn process_listen<'umem>(
        connections: &mut FxHashMap<ConnectionId, Tcb>,
        listeners: &mut Vec<ListenEntry>,
        isn_generator: &mut IsnGenerator,
        listener_idx: usize,
        now: Instant,
        incoming_src: IpAddress,
        incoming_dst: IpAddress,
        src_port: u16,
        dst_port: u16,
        seg_seq: u32,
        seg_ack: u32,
        seg_flags: u8,
        seg_wnd: u32,
        seg_len: u32,
        options: &[u8],
        src_mac: crate::net::wire::ethernet::MacAddress,
        dst_mac: crate::net::wire::ethernet::MacAddress,
        tx_offload: bool,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        // Step 1: RST → ignore.
        if seg_flags & flags::RST != 0 {
            return;
        }

        // Step 2: ACK (no SYN) → send RST.
        if seg_flags & flags::ACK != 0 && seg_flags & flags::SYN == 0 {
            SegmentBuilder::build_rst(
                incoming_src,
                incoming_dst,
                src_port,
                dst_port,
                seg_seq,
                seg_ack,
                seg_flags,
                seg_len,
                src_mac,
                dst_mac,
                tx_offload,
                free_frames,
                tx_return,
            );
            return;
        }

        // Step 3: SYN → create new connection in SYN-RECEIVED.
        if seg_flags & flags::SYN != 0 {
            // Check backlog.
            let listener = &listeners[listener_idx];
            if listener.syn_received_count >= listener.backlog {
                return; // Drop excess SYNs.
            }

            let id = ConnectionId {
                local_addr: incoming_dst,
                local_port: dst_port,
                remote_addr: incoming_src,
                remote_port: src_port,
            };

            let iss = isn_generator.generate(&id);
            let peer_mss = parse_mss(options).unwrap_or(536);
            let peer_wscale = parse_window_scale(options);
            let peer_ts = parse_timestamp(options);
            let peer_sack = parse_sack_permitted(options);

            let wscale_enabled = peer_wscale.is_some();
            let snd_wscale = peer_wscale.unwrap_or(0);

            // Negotiate timestamps, SACK, and ECN.
            let ts_enabled = listener.timestamps && peer_ts.is_some();
            let sack_enabled = listener.sack && peer_sack;
            let ecn_enabled = listener.ecn
                && (seg_flags & (flags::ECE | flags::CWR) == (flags::ECE | flags::CWR));
            let peer_tsval = peer_ts.map(|(v, _)| v).unwrap_or(0);

            let send_buffer_size = listener.send_buffer_size;
            let recv_buffer_size = listener.recv_buffer_size;
            let time_wait_duration = listener.time_wait_duration;

            let event_queue = LocalQueue::new(16);

            let tcb = Tcb {
                id,
                state: TcpState::SynReceived,
                from_passive_open: true,
                iss,
                snd_una: iss,
                snd_nxt: iss.wrapping_add(1),
                snd_wnd: seg_wnd,
                snd_wl1: seg_seq,
                snd_wl2: seg_ack,
                irs: seg_seq,
                rcv_nxt: seg_seq.wrapping_add(1),
                rcv_wnd: DEFAULT_RCV_WND as u32,
                snd_mss: peer_mss,
                rcv_mss: DEFAULT_RCV_MSS,
                eff_snd_mss: {
                    let base = peer_mss.min(DEFAULT_RCV_MSS);
                    if ts_enabled {
                        base.saturating_sub(TS_OPTION_LEN)
                    } else {
                        base
                    }
                },
                snd_wscale,
                rcv_wscale: if wscale_enabled {
                    DEFAULT_RCV_WSCALE
                } else {
                    0
                },
                wscale_enabled,
                retransmit_deadline: Some(now + coarsetime::Duration::from_millis(INITIAL_RTO_MS)),
                rto_backoff: 0,
                event_queue,
                send_buffer: RingBuffer::new(send_buffer_size),
                recv_buffer: RingBuffer::new(recv_buffer_size),
                ooo_ranges: BTreeMap::new(),
                cubic: CubicState::new({
                    let base = peer_mss.min(DEFAULT_RCV_MSS);
                    if ts_enabled {
                        base.saturating_sub(TS_OPTION_LEN)
                    } else {
                        base
                    }
                }),
                recovery: SackRecovery::new(),
                prr: PrrState::new(),
                frto: FRtoState::new(),
                srtt: None,
                rttvar: 0,
                rto: 1000,
                last_send_time: None,
                pending_fin: false,
                fin_seq: None,
                time_wait_deadline: None,
                time_wait_duration,
                ack_pending: false,
                delayed_ack_deadline: None,
                ack_delay_count: 0,
                delayed_ack_ms: listener.delayed_ack_ms,
                nagle_enabled: !listener.tcp_no_delay,
                keep_alive_enabled: listener.keep_alive,
                keep_alive_idle_ms: listener.keep_alive_idle_ms,
                keep_alive_interval_ms: listener.keep_alive_interval_ms,
                keep_alive_count: listener.keep_alive_count,
                last_activity: now,
                keep_alive_probes_sent: 0,
                linger: listener.linger,
                linger_deadline: None,
                ts_enabled,
                ts_recent: if ts_enabled { peer_tsval } else { 0 },
                ts_recent_age: now,
                ts_offset: now,
                sack_enabled,
                sack_scoreboard: BTreeMap::new(),
                ecn_enabled,
                ecn_ce_received: false,
                ecn_cwr_sent: false,
                persist_deadline: None,
                persist_backoff: 0,
                max_snd_wnd: 0,
                last_advertised_right_edge: 0,
            };

            // Send SYN-ACK.
            let wscale_opt = if wscale_enabled {
                Some(DEFAULT_RCV_WSCALE)
            } else {
                None
            };
            let ts_opt = if ts_enabled {
                Some((0u32, peer_tsval))
            } else {
                None
            };
            SegmentBuilder::build_syn_ack(
                incoming_dst,
                incoming_src,
                dst_port,
                src_port,
                iss,
                seg_seq.wrapping_add(1),
                DEFAULT_RCV_WND,
                DEFAULT_RCV_MSS,
                wscale_opt,
                ts_opt,
                sack_enabled,
                ecn_enabled,
                src_mac,
                dst_mac,
                tx_offload,
                free_frames,
                tx_return,
            );

            connections.insert(tcb.id, tcb);
            listeners[listener_idx].syn_received_count += 1;
        }

        // Step 4: Other → drop (frame returned by caller).
    }

    // --- SYN-RECEIVED state processing (RFC §16.4) ---

    fn process_syn_received<'umem>(
        tcb: &mut Tcb,
        listeners: &mut Vec<ListenEntry>,
        tsval: u32,
        seg_seq: u32,
        seg_ack: u32,
        seg_flags: u8,
        seg_wnd: u32,
        _seg_len: u32,
        src_mac: crate::net::wire::ethernet::MacAddress,
        dst_mac: crate::net::wire::ethernet::MacAddress,
        tx_offload: bool,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) -> PostAction {
        let id = tcb.id;

        // Step 1: Check sequence number acceptability.
        let seq_ok = seg_seq == tcb.rcv_nxt
            || (seg_flags & flags::SYN != 0 && seg_seq.wrapping_add(1) == tcb.rcv_nxt);
        if !seq_ok {
            // Out of window — if not RST, send challenge ACK.
            if seg_flags & flags::RST == 0 {
                let ts = tcb.ts_option(tsval);
                SegmentBuilder::build_ack(
                    tcb.id.local_addr,
                    tcb.id.remote_addr,
                    tcb.id.local_port,
                    tcb.id.remote_port,
                    tcb.snd_nxt,
                    tcb.rcv_nxt,
                    DEFAULT_RCV_WND,
                    flags::ACK,
                    ts,
                    src_mac,
                    dst_mac,
                    tx_offload,
                    free_frames,
                    tx_return,
                );
            }
            return PostAction::None;
        }

        // Step 2: Check RST.
        if seg_flags & flags::RST != 0 {
            let from_passive = tcb.from_passive_open;
            if from_passive {
                // Return to LISTEN — remove TCB.
                return PostAction::RemoveAndDecrement(id);
            } else {
                // Active open → signal refused.
                tcb.event_queue.push(TcpEvent::ConnectionRefused);
                return PostAction::RemoveConnection(id);
            }
        }

        // Step 4: Check the SYN bit.
        if seg_flags & flags::SYN != 0 && seg_flags & flags::ACK == 0 {
            if tcb.from_passive_open {
                // Retransmit SYN-ACK so the client can complete the handshake.
                let wscale_opt = if tcb.wscale_enabled {
                    Some(tcb.rcv_wscale)
                } else {
                    None
                };
                let ts_opt = tcb.ts_option(tsval);
                SegmentBuilder::build_syn_ack(
                    tcb.id.local_addr,
                    tcb.id.remote_addr,
                    tcb.id.local_port,
                    tcb.id.remote_port,
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
                    tx_offload,
                    free_frames,
                    tx_return,
                );
            } else {
                // Active open (simultaneous): send challenge ACK per RFC 5961.
                let ts = tcb.ts_option(tsval);
                SegmentBuilder::build_ack(
                    tcb.id.local_addr,
                    tcb.id.remote_addr,
                    tcb.id.local_port,
                    tcb.id.remote_port,
                    tcb.snd_nxt,
                    tcb.rcv_nxt,
                    DEFAULT_RCV_WND,
                    flags::ACK,
                    ts,
                    src_mac,
                    dst_mac,
                    tx_offload,
                    free_frames,
                    tx_return,
                );
            }
            return PostAction::None;
        }

        // Step 5: Check ACK.
        if seg_flags & flags::ACK != 0 {
            let snd_una = tcb.snd_una;
            let snd_nxt = tcb.snd_nxt;

            if crate::net::wire::tcp::seq_lt(snd_una, seg_ack)
                && crate::net::wire::tcp::seq_le(seg_ack, snd_nxt)
            {
                // ACK is acceptable → transition to ESTABLISHED.
                tcb.state = TcpState::Established;
                tcb.snd_una = seg_ack;
                // RFC 7323 §2.2: window scaling applies to all non-SYN segments.
                tcb.snd_wnd = tcb.scale_incoming_window(seg_wnd);
                tcb.max_snd_wnd = tcb.max_snd_wnd.max(tcb.snd_wnd);
                tcb.snd_wl1 = seg_seq;
                tcb.snd_wl2 = seg_ack;
                tcb.retransmit_deadline = None;
                tcb.rto_backoff = 0;

                let from_passive = tcb.from_passive_open;
                if from_passive {
                    // Push ConnectionId to listener's accept_queue.
                    Self::push_to_accept_queue_on(listeners, &id);
                    Self::decrement_syn_received(listeners, &id);
                } else {
                    // Simultaneous open — notify the active opener.
                    tcb.event_queue.push(TcpEvent::Connected);
                }
            } else {
                // Bad ACK → send RST.
                SegmentBuilder::build_rst(
                    id.remote_addr,
                    id.local_addr,
                    id.remote_port,
                    id.local_port,
                    seg_seq,
                    seg_ack,
                    seg_flags,
                    0,
                    src_mac,
                    dst_mac,
                    tx_offload,
                    free_frames,
                    tx_return,
                );
            }
        }
        PostAction::None
    }

    // --- SYN-SENT state processing (RFC §16.3) ---

    fn process_syn_sent<'umem>(
        tcb: &mut Tcb,
        now: Instant,
        tsval: u32,
        seg_seq: u32,
        seg_ack: u32,
        seg_flags: u8,
        seg_wnd: u32,
        options: &[u8],
        src_mac: crate::net::wire::ethernet::MacAddress,
        dst_mac: crate::net::wire::ethernet::MacAddress,
        tx_offload: bool,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) -> PostAction {
        let iss = tcb.iss;

        // Step 1: Check ACK.
        if seg_flags & flags::ACK != 0
            && (crate::net::wire::tcp::seq_le(seg_ack, iss)
                || crate::net::wire::tcp::seq_lt(tcb.snd_nxt, seg_ack))
        {
            // Unacceptable ACK.
            if seg_flags & flags::RST == 0 {
                // Send RST unless RST is set.
                let id = tcb.id;
                SegmentBuilder::build_rst(
                    id.remote_addr,
                    id.local_addr,
                    id.remote_port,
                    id.local_port,
                    seg_seq,
                    seg_ack,
                    seg_flags,
                    0,
                    src_mac,
                    dst_mac,
                    tx_offload,
                    free_frames,
                    tx_return,
                );
            }
            return PostAction::None;
        }

        // Step 2: Check RST.
        if seg_flags & flags::RST != 0 {
            if seg_flags & flags::ACK != 0 {
                // ACK was acceptable (passed step 1) → connection refused.
                tcb.event_queue.push(TcpEvent::ConnectionRefused);
                return PostAction::RemoveConnection(tcb.id);
            }
            // RST without ACK → drop silently.
            return PostAction::None;
        }

        // Step 3: Check SYN.
        if seg_flags & flags::SYN != 0 {
            tcb.irs = seg_seq;
            tcb.rcv_nxt = seg_seq.wrapping_add(1);

            // Parse peer options.
            let peer_mss = parse_mss(options).unwrap_or(536);
            let peer_wscale = parse_window_scale(options);
            tcb.snd_mss = peer_mss;

            if let Some(ws) = peer_wscale {
                tcb.snd_wscale = ws;
                tcb.wscale_enabled = true;
            }

            // Timestamp negotiation.
            if tcb.ts_enabled {
                if let Some((peer_tsval, _)) = parse_timestamp(options) {
                    tcb.ts_recent = peer_tsval;
                    tcb.ts_recent_age = now;
                } else {
                    tcb.ts_enabled = false; // peer doesn't support
                }
            }

            // Set eff_snd_mss after timestamp negotiation so we know the option overhead.
            let base_mss = peer_mss.min(tcb.rcv_mss);
            tcb.eff_snd_mss = if tcb.ts_enabled {
                base_mss.saturating_sub(TS_OPTION_LEN)
            } else {
                base_mss
            };
            tcb.cubic.set_mss(tcb.eff_snd_mss);
            // SACK negotiation.
            if tcb.sack_enabled && !parse_sack_permitted(options) {
                tcb.sack_enabled = false;
            }
            // ECN negotiation: confirm only if SYN-ACK has ECE set.
            if tcb.ecn_enabled && seg_flags & flags::ECE == 0 {
                tcb.ecn_enabled = false;
            }

            if seg_flags & flags::ACK != 0 {
                // Our SYN was ACKed.
                tcb.snd_una = seg_ack;
            }

            if crate::net::wire::tcp::seq_lt(tcb.iss, tcb.snd_una) {
                // SND.UNA > ISS → ESTABLISHED.
                tcb.state = TcpState::Established;
                tcb.snd_wnd = seg_wnd;
                tcb.max_snd_wnd = tcb.max_snd_wnd.max(tcb.snd_wnd);
                tcb.snd_wl1 = seg_seq;
                tcb.snd_wl2 = seg_ack;
                tcb.retransmit_deadline = None;
                tcb.rto_backoff = 0;

                // Send ACK.
                let id = tcb.id;
                let ts = tcb.ts_option(tsval);
                SegmentBuilder::build_ack(
                    id.local_addr,
                    id.remote_addr,
                    id.local_port,
                    id.remote_port,
                    tcb.snd_nxt,
                    tcb.rcv_nxt,
                    DEFAULT_RCV_WND,
                    flags::ACK,
                    ts,
                    src_mac,
                    dst_mac,
                    tx_offload,
                    free_frames,
                    tx_return,
                );

                tcb.event_queue.push(TcpEvent::Connected);
            } else {
                // Simultaneous open → SYN-RECEIVED (MUST-10).
                tcb.state = TcpState::SynReceived;
                tcb.from_passive_open = false;
                tcb.snd_wnd = seg_wnd;
                tcb.max_snd_wnd = tcb.max_snd_wnd.max(tcb.snd_wnd);
                tcb.snd_wl1 = seg_seq;
                tcb.snd_wl2 = seg_ack;

                // Send SYN-ACK.
                let id = tcb.id;
                let wscale_opt = if tcb.wscale_enabled {
                    Some(tcb.rcv_wscale)
                } else {
                    None
                };
                let ts_opt = tcb.ts_option(tsval);
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
                    tx_offload,
                    free_frames,
                    tx_return,
                );

                // Reset retransmit timer for SYN-ACK.
                tcb.retransmit_deadline =
                    Some(now + coarsetime::Duration::from_millis(INITIAL_RTO_MS));
                tcb.rto_backoff = 0;
            }
        }

        // Step 4: Neither SYN nor RST → drop.
        PostAction::None
    }

    // --- ESTABLISHED state processing: cold-path helpers ---

    /// Handle RST in established state (RFC 5961).
    /// Returns PostAction indicating if connection should be removed.
    #[inline(never)]
    fn handle_rst_established<'umem>(
        tcb: &mut Tcb,
        seg_seq: u32,
        tsval: u32,
        ack_flags: u8,
        src_mac: crate::net::wire::ethernet::MacAddress,
        dst_mac: crate::net::wire::ethernet::MacAddress,
        tx_offload: bool,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) -> PostAction {
        if seg_seq == tcb.rcv_nxt {
            // Exact match: reset connection.
            tcb.event_queue.push(TcpEvent::Reset);
            return PostAction::RemoveAndDecrement(tcb.id);
        }
        // In-window but not exact: send challenge ACK, drop segment.
        let ts = tcb.ts_option(tsval);
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
            tx_offload,
            free_frames,
            tx_return,
        );
        PostAction::None
    }

    /// Handle SYN in established state — send challenge ACK (RFC 5961).
    #[inline(never)]
    fn handle_syn_established<'umem>(
        tcb: &mut Tcb,
        tsval: u32,
        ack_flags: u8,
        src_mac: crate::net::wire::ethernet::MacAddress,
        dst_mac: crate::net::wire::ethernet::MacAddress,
        tx_offload: bool,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let ts = tcb.ts_option(tsval);
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
            tx_offload,
            free_frames,
            tx_return,
        );
    }

    /// Handle out-of-order data — store in OOO buffer and send duplicate ACK with SACK blocks.
    #[inline(never)]
    fn handle_ooo_data<'umem>(
        tcb: &mut Tcb,
        frame: &Frame<'umem>,
        seg_seq: u32,
        tsval: u32,
        payload_offset: usize,
        payload_len: usize,
        ack_flags: u8,
        src_mac: crate::net::wire::ethernet::MacAddress,
        dst_mac: crate::net::wire::ethernet::MacAddress,
        tx_offload: bool,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let rcv_nxt = tcb.rcv_nxt;
        let offset = seg_seq.wrapping_sub(rcv_nxt) as usize;
        let payload = &frame[payload_offset..payload_offset + payload_len];
        tcb.recv_buffer.write_at(offset, payload);
        tcb.ooo_ranges.insert(seg_seq, payload_len as u32);

        // Send duplicate ACK (with current rcv_nxt) and SACK blocks.
        let ts = tcb.ts_option(tsval);

        let max_blocks = if tcb.ts_enabled { 3 } else { 4 };
        let mut sack_buf = [(0u32, 0u32); 4];
        let mut sack_count = 0usize;
        if tcb.sack_enabled {
            // Most recently received range first (per RFC 2018 §3).
            sack_buf[0] = (seg_seq, seg_seq.wrapping_add(payload_len as u32));
            sack_count = 1;
            for (&start, &len) in tcb.ooo_ranges.iter().rev() {
                if sack_count >= max_blocks {
                    break;
                }
                let end = start.wrapping_add(len);
                if start != seg_seq {
                    sack_buf[sack_count] = (start, end);
                    sack_count += 1;
                }
            }
        }
        let sack_blocks = &sack_buf[..sack_count];

        SegmentBuilder::build_ack_with_sack(
            tcb.id.local_addr,
            tcb.id.remote_addr,
            tcb.id.local_port,
            tcb.id.remote_port,
            tcb.snd_nxt,
            tcb.rcv_nxt,
            tcb.advertised_window(),
            ack_flags,
            ts,
            sack_blocks,
            src_mac,
            dst_mac,
            tx_offload,
            free_frames,
            tx_return,
        );
    }

    // --- ESTABLISHED state processing ---

    fn process_established<'umem>(
        tcb: &mut Tcb,
        frame: Frame<'umem>,
        now: Instant,
        tsval: u32,
        seg_seq: u32,
        seg_ack: u32,
        seg_flags: u8,
        seg_wnd: u32,
        payload_offset: usize,
        payload_len: usize,
        opts: &ParsedOptions,
        ecn_bits: u8,
        src_mac: crate::net::wire::ethernet::MacAddress,
        dst_mac: crate::net::wire::ethernet::MacAddress,
        tx_offload: bool,
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) -> PostAction {
        use crate::net::wire::tcp::{seq_le, seq_lt};

        // ECN CE detection: if ECN is enabled and CE codepoint (0b11) is received,
        // record it so we can signal ECE back to the sender.
        if tcb.ecn_enabled && ecn_bits == 0x03 {
            tcb.ecn_ce_received = true;
        }

        // ECN CWR processing: peer acknowledges our ECE by sending CWR.
        if tcb.ecn_enabled && seg_flags & flags::CWR != 0 {
            tcb.ecn_ce_received = false;
        }

        // Compute ACK flags: include ECE when we need to signal congestion back.
        let ack_flags = if tcb.ecn_ce_received {
            flags::ACK | flags::ECE
        } else {
            flags::ACK
        };

        // Fast-path: common case — in-order data + valid new ACK, no special flags.
        {
            let fast_path = (seg_flags & (flags::RST | flags::SYN | flags::FIN)) == 0
                && seg_flags & flags::ACK != 0
                && payload_len > 0
                && seg_seq == tcb.rcv_nxt
                && seq_lt(tcb.snd_una, seg_ack)
                && seq_le(seg_ack, tcb.snd_nxt)
                && !tcb.recovery.in_recovery
                && tcb.ooo_ranges.is_empty();

            if fast_path {
                // PAWS check — on failure, fall through to slow path.
                if tcb.ts_enabled {
                    if let Some((ts_val, _)) = opts.timestamp {
                        let ts_diff = ts_val.wrapping_sub(tcb.ts_recent) as i32;
                        if ts_diff < 0 {
                            // Possible PAWS rejection — let slow path handle it.
                        } else {
                            // PAWS OK — proceed with fast path.

                            // Segment acceptability (simplified: seg_seq == rcv_nxt, payload > 0).
                            if tcb.recv_buffer.free_space() == 0 {
                                // No window space — fall through to slow path.
                            } else {
                                // Update ts_recent.
                                tcb.ts_recent = ts_val;
                                tcb.ts_recent_age = now;

                                // ACK advancement (we know snd_una < seg_ack <= snd_nxt).
                                let bytes_acked = seg_ack.wrapping_sub(tcb.snd_una) as usize;
                                tcb.snd_una = seg_ack;
                                tcb.send_buffer.advance(bytes_acked);
                                tcb.last_activity = now;
                                tcb.keep_alive_probes_sent = 0;

                                // RFC 6298 §5.3: manage retransmit timer on new ACK.
                                tcb.rto_backoff = 0;
                                if tcb.snd_una == tcb.snd_nxt {
                                    tcb.retransmit_deadline = None;
                                } else {
                                    tcb.retransmit_deadline =
                                        Some(now + coarsetime::Duration::from_millis(tcb.rto));
                                }

                                // F-RTO check.
                                let mut frto_handled = false;
                                if tcb.frto.is_active() {
                                    let action = tcb.frto.on_ack(seg_ack);
                                    match action {
                                        FRtoAction::SpuriousRto => {
                                            tcb.cubic.restore_after_spurious_rto();
                                            frto_handled = true;
                                        }
                                        FRtoAction::SendNewData => {
                                            frto_handled = true;
                                        }
                                        FRtoAction::GenuineLoss | FRtoAction::None => {}
                                    }
                                }

                                // Congestion control (fast path is never in recovery).
                                if !frto_handled {
                                    let rtt_ms = tcb.srtt.unwrap_or(tcb.rto);
                                    tcb.cubic.on_ack(
                                        bytes_acked as u32,
                                        now,
                                        rtt_ms,
                                        tcb.max_snd_wnd,
                                    );
                                }
                                tcb.recovery.dup_ack_count = 0;

                                // RTT measurement via timestamps.
                                if let Some((_tsval, tsecr)) = opts.timestamp
                                    && tsecr != 0
                                {
                                    let our_ts = tsval;
                                    let rtt_ms = our_ts.wrapping_sub(tsecr) as u64;
                                    match tcb.srtt {
                                        None => {
                                            tcb.srtt = Some(rtt_ms);
                                            tcb.rttvar = rtt_ms / 2;
                                        }
                                        Some(srtt) => {
                                            let diff = rtt_ms.abs_diff(srtt);
                                            tcb.rttvar = (3 * tcb.rttvar + diff) / 4;
                                            tcb.srtt = Some((7 * srtt + rtt_ms) / 8);
                                        }
                                    }
                                    tcb.rto =
                                        (tcb.srtt.unwrap() + 4 * tcb.rttvar).clamp(1000, 60_000);
                                }

                                // Window update.
                                if seq_lt(tcb.snd_wl1, seg_seq)
                                    || (tcb.snd_wl1 == seg_seq && seq_le(tcb.snd_wl2, seg_ack))
                                {
                                    tcb.snd_wnd = tcb.scale_incoming_window(seg_wnd);
                                    tcb.max_snd_wnd = tcb.max_snd_wnd.max(tcb.snd_wnd);
                                    tcb.snd_wl1 = seg_seq;
                                    tcb.snd_wl2 = seg_ack;
                                }

                                // Clear persist timer when window reopens.
                                if tcb.snd_wnd > 0 && tcb.persist_deadline.is_some() {
                                    tcb.persist_deadline = None;
                                    tcb.persist_backoff = 0;
                                }

                                // SACK scoreboard.
                                if tcb.sack_enabled {
                                    let (blocks, count) = opts.sack_blocks;
                                    for (left, right) in blocks.iter().take(count).flatten() {
                                        tcb.sack_scoreboard
                                            .insert(*left, right.wrapping_sub(*left));
                                    }
                                    let snd_una = tcb.snd_una;
                                    tcb.sack_scoreboard.retain(|&start, _| {
                                        !crate::net::wire::tcp::seq_lt(start, snd_una)
                                    });
                                }

                                // ECN congestion response.
                                if tcb.ecn_enabled
                                    && seg_flags & flags::ECE != 0
                                    && !tcb.ecn_cwr_sent
                                {
                                    tcb.cubic.on_ecn();
                                    tcb.ecn_cwr_sent = true;
                                }

                                // Data write (in-order, no OOO to drain).
                                let payload = &frame[payload_offset..payload_offset + payload_len];
                                let written = tcb.recv_buffer.write(payload);
                                tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(written as u32);
                                tcb.last_activity = now;
                                tcb.keep_alive_probes_sent = 0;

                                // Delayed ACK — defer to poll_send for piggyback opportunity.
                                tcb.ack_delay_count += 1;
                                tcb.ack_pending = true;
                                if tcb.delayed_ack_deadline.is_none() {
                                    tcb.delayed_ack_deadline = Some(
                                        now + coarsetime::Duration::from_millis(tcb.delayed_ack_ms),
                                    );
                                }

                                rx_return.push(frame);
                                return PostAction::None;
                            }
                        }
                    }
                    // ts_enabled but no timestamp in packet — fall through to slow path.
                } else {
                    // Timestamps not enabled — fast path without PAWS.

                    // Segment acceptability (simplified: seg_seq == rcv_nxt, payload > 0).
                    if tcb.recv_buffer.free_space() > 0 {
                        // ACK advancement.
                        let bytes_acked = seg_ack.wrapping_sub(tcb.snd_una) as usize;
                        tcb.snd_una = seg_ack;
                        tcb.send_buffer.advance(bytes_acked);
                        tcb.last_activity = now;
                        tcb.keep_alive_probes_sent = 0;

                        // RFC 6298 §5.3: manage retransmit timer on new ACK.
                        tcb.rto_backoff = 0;
                        if tcb.snd_una == tcb.snd_nxt {
                            tcb.retransmit_deadline = None;
                        } else {
                            tcb.retransmit_deadline =
                                Some(now + coarsetime::Duration::from_millis(tcb.rto));
                        }

                        // F-RTO check.
                        let mut frto_handled = false;
                        if tcb.frto.is_active() {
                            let action = tcb.frto.on_ack(seg_ack);
                            match action {
                                FRtoAction::SpuriousRto => {
                                    tcb.cubic.restore_after_spurious_rto();
                                    frto_handled = true;
                                }
                                FRtoAction::SendNewData => {
                                    frto_handled = true;
                                }
                                FRtoAction::GenuineLoss | FRtoAction::None => {}
                            }
                        }

                        // Congestion control.
                        if !frto_handled {
                            let rtt_ms = tcb.srtt.unwrap_or(tcb.rto);
                            tcb.cubic
                                .on_ack(bytes_acked as u32, now, rtt_ms, tcb.max_snd_wnd);
                        }
                        tcb.recovery.dup_ack_count = 0;

                        // RTT measurement via last_send_time (fallback).
                        if let Some(send_time) = tcb.last_send_time {
                            let rtt_ms = now.duration_since(send_time).as_millis();
                            match tcb.srtt {
                                None => {
                                    tcb.srtt = Some(rtt_ms);
                                    tcb.rttvar = rtt_ms / 2;
                                }
                                Some(srtt) => {
                                    let diff = rtt_ms.abs_diff(srtt);
                                    tcb.rttvar = (3 * tcb.rttvar + diff) / 4;
                                    tcb.srtt = Some((7 * srtt + rtt_ms) / 8);
                                }
                            }
                            let srtt = tcb.srtt.unwrap();
                            tcb.rto = (srtt + 4 * tcb.rttvar).clamp(1000, 60_000);
                            tcb.last_send_time = None;
                        }

                        // Window update.
                        if seq_lt(tcb.snd_wl1, seg_seq)
                            || (tcb.snd_wl1 == seg_seq && seq_le(tcb.snd_wl2, seg_ack))
                        {
                            tcb.snd_wnd = tcb.scale_incoming_window(seg_wnd);
                            tcb.max_snd_wnd = tcb.max_snd_wnd.max(tcb.snd_wnd);
                            tcb.snd_wl1 = seg_seq;
                            tcb.snd_wl2 = seg_ack;
                        }

                        // Clear persist timer when window reopens.
                        if tcb.snd_wnd > 0 && tcb.persist_deadline.is_some() {
                            tcb.persist_deadline = None;
                            tcb.persist_backoff = 0;
                        }

                        // SACK scoreboard.
                        if tcb.sack_enabled {
                            let (blocks, count) = opts.sack_blocks;
                            for (left, right) in blocks.iter().take(count).flatten() {
                                tcb.sack_scoreboard.insert(*left, right.wrapping_sub(*left));
                            }
                            let snd_una = tcb.snd_una;
                            tcb.sack_scoreboard
                                .retain(|&start, _| !crate::net::wire::tcp::seq_lt(start, snd_una));
                        }

                        // ECN congestion response.
                        if tcb.ecn_enabled && seg_flags & flags::ECE != 0 && !tcb.ecn_cwr_sent {
                            tcb.cubic.on_ecn();
                            tcb.ecn_cwr_sent = true;
                        }

                        // Data write (in-order, no OOO to drain).
                        let payload = &frame[payload_offset..payload_offset + payload_len];
                        let written = tcb.recv_buffer.write(payload);
                        tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(written as u32);
                        tcb.last_activity = now;
                        tcb.keep_alive_probes_sent = 0;

                        // Delayed ACK — defer to poll_send for piggyback opportunity.
                        tcb.ack_delay_count += 1;
                        tcb.ack_pending = true;
                        if tcb.delayed_ack_deadline.is_none() {
                            tcb.delayed_ack_deadline =
                                Some(now + coarsetime::Duration::from_millis(tcb.delayed_ack_ms));
                        }

                        rx_return.push(frame);
                        return PostAction::None;
                    }
                    // No window space — fall through to slow path.
                }
            }
        }
        // Fall through to existing slow path.

        // PAWS check (RFC 7323 §5).
        if tcb.ts_enabled
            && let Some((tsval, _)) = opts.timestamp
        {
            // Check if TSval is older than ts_recent.
            // Use signed comparison for wraparound.
            let ts_diff = tsval.wrapping_sub(tcb.ts_recent) as i32;
            if ts_diff < 0 {
                // Check staleness: if ts_recent is older than 24 days, accept anyway.
                let staleness = now.duration_since(tcb.ts_recent_age).as_millis();
                if staleness < 24 * 24 * 60 * 60 * 1000 {
                    // Reject: send ACK and drop (unless RST, which is silently dropped).
                    if seg_flags & flags::RST != 0 {
                        rx_return.push(frame);
                        return PostAction::None;
                    }
                    let ts = tcb.ts_option(tsval);
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
                        tx_offload,
                        free_frames,
                        tx_return,
                    );
                    rx_return.push(frame);
                    return PostAction::None;
                }
            }
        }

        // Segment acceptability check (RFC 9293 §3.10.7.4).
        {
            let seg_len = Tcb::seg_len(payload_len, seg_flags);
            let rcv_wnd = tcb.recv_buffer.free_space() as u32;
            if !is_segment_acceptable(seg_seq, seg_len, tcb.rcv_nxt, rcv_wnd) {
                // Out-of-window: send ACK (unless RST, which is silently dropped).
                if seg_flags & flags::RST != 0 {
                    rx_return.push(frame);
                    return PostAction::None;
                }
                let ts = tcb.ts_option(tsval);
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
                    tx_offload,
                    free_frames,
                    tx_return,
                );
                rx_return.push(frame);
                return PostAction::None;
            }
        }

        // Step 2: RST check (RFC 5961).
        if seg_flags & flags::RST != 0 {
            let action = Self::handle_rst_established(
                tcb,
                seg_seq,
                tsval,
                ack_flags,
                src_mac,
                dst_mac,
                tx_offload,
                free_frames,
                tx_return,
            );
            rx_return.push(frame);
            return action;
        }

        // Step 4: SYN check (RFC 5961 — challenge ACK for SYN in synchronized state).
        if seg_flags & flags::SYN != 0 {
            Self::handle_syn_established(
                tcb,
                tsval,
                ack_flags,
                src_mac,
                dst_mac,
                tx_offload,
                free_frames,
                tx_return,
            );
            rx_return.push(frame);
            return PostAction::None;
        }

        // Step 5 preamble: if ACK bit is off, drop segment and return.
        if seg_flags & flags::ACK == 0 {
            rx_return.push(frame);
            return PostAction::None;
        }

        // Update ts_recent from incoming segment.
        {
            if tcb.ts_enabled
                && let Some((tsval, _)) = opts.timestamp
            {
                tcb.ts_recent = tsval;
                tcb.ts_recent_age = now;
            }
        }

        // Step 2: ACK processing.
        if seg_flags & flags::ACK != 0 {
            let snd_una = tcb.snd_una;
            let snd_nxt = tcb.snd_nxt;

            if seq_lt(snd_una, seg_ack) && seq_le(seg_ack, snd_nxt) {
                // Valid new ACK — advance snd_una and send buffer.
                let bytes_acked = seg_ack.wrapping_sub(snd_una) as usize;
                tcb.snd_una = seg_ack;
                tcb.send_buffer.advance(bytes_acked);

                // Reset keep-alive timer on activity.
                tcb.last_activity = now;
                tcb.keep_alive_probes_sent = 0;

                // RFC 6298 §5.3: manage retransmit timer on new ACK.
                tcb.rto_backoff = 0;
                if tcb.snd_una == tcb.snd_nxt {
                    tcb.retransmit_deadline = None;
                } else {
                    tcb.retransmit_deadline =
                        Some(now + coarsetime::Duration::from_millis(tcb.rto));
                }

                // F-RTO check — must come before recovery/congestion control.
                let mut frto_handled = false;
                if tcb.frto.is_active() {
                    let action = tcb.frto.on_ack(seg_ack);
                    match action {
                        FRtoAction::SpuriousRto => {
                            tcb.cubic.restore_after_spurious_rto();
                            frto_handled = true;
                        }
                        FRtoAction::GenuineLoss => {
                            // Keep reduced cwnd — proceed normally.
                        }
                        FRtoAction::SendNewData => {
                            // F-RTO Step1→Step2: prefer sending new data in poll_send.
                            // No cwnd changes here.
                            frto_handled = true;
                        }
                        FRtoAction::None => {}
                    }
                }

                // Recovery exit check — must come before congestion control.
                if tcb.recovery.in_recovery && tcb.recovery.on_ack(seg_ack) {
                    // Exited recovery — full ACK covers recovery_point.
                    tcb.prr.exit();
                }

                // Congestion control — only update outside recovery and F-RTO.
                if !tcb.recovery.in_recovery && !frto_handled {
                    let rtt_ms = tcb.srtt.unwrap_or(tcb.rto);
                    tcb.cubic
                        .on_ack(bytes_acked as u32, now, rtt_ms, tcb.max_snd_wnd);
                }

                tcb.recovery.dup_ack_count = 0;

                // RTT measurement.
                if tcb.ts_enabled {
                    // RTTM via timestamps (RFC 7323).
                    if let Some((_tsval, tsecr)) = opts.timestamp
                        && tsecr != 0
                    {
                        let our_ts = tsval;
                        let rtt_ms = our_ts.wrapping_sub(tsecr) as u64;
                        match tcb.srtt {
                            None => {
                                tcb.srtt = Some(rtt_ms);
                                tcb.rttvar = rtt_ms / 2;
                            }
                            Some(srtt) => {
                                let diff = rtt_ms.abs_diff(srtt);
                                tcb.rttvar = (3 * tcb.rttvar + diff) / 4;
                                tcb.srtt = Some((7 * srtt + rtt_ms) / 8);
                            }
                        }
                        tcb.rto = (tcb.srtt.unwrap() + 4 * tcb.rttvar).clamp(1000, 60_000);
                    }
                } else if let Some(send_time) = tcb.last_send_time {
                    // Fallback: RTT from last_send_time (RFC 6298).
                    let rtt_ms = now.duration_since(send_time).as_millis();

                    match tcb.srtt {
                        None => {
                            tcb.srtt = Some(rtt_ms);
                            tcb.rttvar = rtt_ms / 2;
                        }
                        Some(srtt) => {
                            let diff = rtt_ms.abs_diff(srtt);
                            tcb.rttvar = (3 * tcb.rttvar + diff) / 4;
                            tcb.srtt = Some((7 * srtt + rtt_ms) / 8);
                        }
                    }
                    let srtt = tcb.srtt.unwrap();
                    tcb.rto = (srtt + 4 * tcb.rttvar).clamp(1000, 60_000);
                    tcb.last_send_time = None; // consumed
                }

                // Update send window (RFC 9293 §3.10.7.4 Step 5).
                if seq_lt(tcb.snd_wl1, seg_seq)
                    || (tcb.snd_wl1 == seg_seq && seq_le(tcb.snd_wl2, seg_ack))
                {
                    tcb.snd_wnd = tcb.scale_incoming_window(seg_wnd);
                    tcb.max_snd_wnd = tcb.max_snd_wnd.max(tcb.snd_wnd);
                    tcb.snd_wl1 = seg_seq;
                    tcb.snd_wl2 = seg_ack;
                }

                // C. Clear persist timer when window reopens.
                if tcb.snd_wnd > 0 && tcb.persist_deadline.is_some() {
                    tcb.persist_deadline = None;
                    tcb.persist_backoff = 0;
                }

                // Parse and merge SACK blocks into scoreboard.
                if tcb.sack_enabled {
                    let (blocks, count) = opts.sack_blocks;
                    for (left, right) in blocks.iter().take(count).flatten() {
                        tcb.sack_scoreboard.insert(*left, right.wrapping_sub(*left));
                    }
                    // Prune scoreboard entries below snd_una (already ACKed cumulatively).
                    let snd_una = tcb.snd_una;
                    tcb.sack_scoreboard
                        .retain(|&start, _| !crate::net::wire::tcp::seq_lt(start, snd_una));
                }

                // ECN congestion response: if peer signals ECE, halve cwnd and
                // schedule CWR on the next data segment.
                if tcb.ecn_enabled && seg_flags & flags::ECE != 0 && !tcb.ecn_cwr_sent {
                    tcb.cubic.on_ecn();
                    tcb.ecn_cwr_sent = true;
                }
            } else if seq_lt(snd_nxt, seg_ack) {
                // ACK for unsent data — send ACK and drop (RFC 9293 §3.10.7.4 Step 5).
                let ts = tcb.ts_option(tsval);
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
                    tx_offload,
                    free_frames,
                    tx_return,
                );
                rx_return.push(frame);
                return PostAction::None;
            } else if seg_ack == snd_una && payload_len == 0 {
                // Duplicate ACK.
                tcb.recovery.dup_ack_count += 1;
                // Keep-alive probe responses arrive as duplicate ACKs — reset timer.
                if tcb.keep_alive_enabled && tcb.keep_alive_probes_sent > 0 {
                    tcb.last_activity = now;
                    tcb.keep_alive_probes_sent = 0;
                }

                // Window update may arrive as a duplicate ACK (RFC 9293 §3.10.7.4 Step 5).
                let new_wnd = tcb.scale_incoming_window(seg_wnd);
                if seq_lt(tcb.snd_wl1, seg_seq)
                    || (tcb.snd_wl1 == seg_seq && seq_le(tcb.snd_wl2, seg_ack))
                {
                    tcb.snd_wnd = new_wnd;
                    tcb.max_snd_wnd = tcb.max_snd_wnd.max(tcb.snd_wnd);
                    tcb.snd_wl1 = seg_seq;
                    tcb.snd_wl2 = seg_ack;
                }

                // Clear persist timer when window reopens via duplicate ACK.
                if tcb.snd_wnd > 0 && tcb.persist_deadline.is_some() {
                    tcb.persist_deadline = None;
                    tcb.persist_backoff = 0;
                }

                // Parse SACK blocks on duplicate ACKs too.
                if tcb.sack_enabled {
                    let (blocks, count) = opts.sack_blocks;
                    for (left, right) in blocks.iter().take(count).flatten() {
                        tcb.sack_scoreboard.insert(*left, right.wrapping_sub(*left));
                    }
                }

                // Enter SACK recovery on the 3rd duplicate ACK.
                if tcb.recovery.dup_ack_count == 3 && !tcb.recovery.in_recovery {
                    let bytes_in_flight = tcb.snd_nxt.wrapping_sub(tcb.snd_una);
                    tcb.recovery.enter(tcb.snd_nxt);
                    tcb.prr.enter(bytes_in_flight);
                    tcb.cubic.on_loss();
                }
            }
        }

        // Step 3: Data processing.
        if payload_len > 0 {
            let rcv_nxt = tcb.rcv_nxt;

            if seg_seq == rcv_nxt {
                // In-order data.
                let payload = &frame[payload_offset..payload_offset + payload_len];
                let written = tcb.recv_buffer.write(payload);
                tcb.rcv_nxt = rcv_nxt.wrapping_add(written as u32);

                // Reset keep-alive timer on received data.
                tcb.last_activity = now;
                tcb.keep_alive_probes_sent = 0;

                // Drain contiguous OOO ranges.
                loop {
                    let current_nxt = tcb.rcv_nxt;
                    if let Some(&ooo_len) = tcb.ooo_ranges.get(&current_nxt) {
                        tcb.ooo_ranges.remove(&current_nxt);
                        tcb.recv_buffer.commit(ooo_len as usize);
                        tcb.rcv_nxt = current_nxt.wrapping_add(ooo_len);
                    } else {
                        break;
                    }
                }

                // Defer ACK (delayed ACK) — defer to poll_send for piggyback opportunity.
                tcb.ack_delay_count += 1;
                tcb.ack_pending = true;
                if tcb.delayed_ack_deadline.is_none() {
                    tcb.delayed_ack_deadline =
                        Some(now + coarsetime::Duration::from_millis(tcb.delayed_ack_ms));
                }
            } else if crate::net::wire::tcp::seq_lt(rcv_nxt, seg_seq) {
                // Out-of-order data.
                Self::handle_ooo_data(
                    tcb,
                    &frame,
                    seg_seq,
                    tsval,
                    payload_offset,
                    payload_len,
                    ack_flags,
                    src_mac,
                    dst_mac,
                    tx_offload,
                    free_frames,
                    tx_return,
                );
            } else {
                // Duplicate data (seg_seq < rcv_nxt) — just ACK.
                let ts = tcb.ts_option(tsval);
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
                    tx_offload,
                    free_frames,
                    tx_return,
                );
            }
        }

        // Step 4: Process FIN flag.
        if seg_flags & flags::FIN != 0
            && seg_seq.wrapping_add(payload_len as u32) == tcb.rcv_nxt
        {
            tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1); // FIN consumes one sequence number
            tcb.state = TcpState::CloseWait;
            tcb.event_queue.push(TcpEvent::RemoteClose);

            // Send ACK for FIN.
            let id = tcb.id;
            let snd_nxt = tcb.snd_nxt;
            let new_rcv_nxt = tcb.rcv_nxt;
            let window = tcb.advertised_window();
            let ts = tcb.ts_option(tsval);
            SegmentBuilder::build_ack(
                id.local_addr,
                id.remote_addr,
                id.local_port,
                id.remote_port,
                snd_nxt,
                new_rcv_nxt,
                window,
                ack_flags,
                ts,
                src_mac,
                dst_mac,
                tx_offload,
                free_frames,
                tx_return,
            );
        }

        // Always return incoming frame to rx_return.
        rx_return.push(frame);
        PostAction::None
    }

    // --- Connection teardown ---

    // --- Teardown state processing (FinWait1, FinWait2, CloseWait, Closing, LastAck, TimeWait) ---

    fn process_teardown<'umem>(
        tcb: &mut Tcb,
        frame: Frame<'umem>,
        now: Instant,
        tsval: u32,
        seg_seq: u32,
        seg_ack: u32,
        seg_flags: u8,
        seg_wnd: u32,
        payload_offset: usize,
        payload_len: usize,
        opts: &ParsedOptions,
        src_mac: crate::net::wire::ethernet::MacAddress,
        dst_mac: crate::net::wire::ethernet::MacAddress,
        tx_offload: bool,
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) -> PostAction {
        let state = tcb.state;

        // PAWS check (RFC 7323 §5).
        if tcb.ts_enabled
            && let Some((tsval, _)) = opts.timestamp
        {
            let ts_diff = tsval.wrapping_sub(tcb.ts_recent) as i32;
            if ts_diff < 0 {
                let staleness = now.duration_since(tcb.ts_recent_age).as_millis();
                if staleness < 24 * 24 * 60 * 60 * 1000 {
                    // Reject: silently drop RST, send ACK for others.
                    if seg_flags & flags::RST != 0 {
                        rx_return.push(frame);
                        return PostAction::None;
                    }
                    let ts = tcb.ts_option(tsval);
                    SegmentBuilder::build_ack(
                        tcb.id.local_addr,
                        tcb.id.remote_addr,
                        tcb.id.local_port,
                        tcb.id.remote_port,
                        tcb.snd_nxt,
                        tcb.rcv_nxt,
                        tcb.advertised_window(),
                        flags::ACK,
                        ts,
                        src_mac,
                        dst_mac,
                        tx_offload,
                        free_frames,
                        tx_return,
                    );
                    rx_return.push(frame);
                    return PostAction::None;
                }
            }
        }

        // Segment acceptability check (RFC 9293 §3.10.7.4).
        {
            let seg_len = Tcb::seg_len(payload_len, seg_flags);
            let rcv_wnd = tcb.recv_buffer.free_space() as u32;
            if !is_segment_acceptable(seg_seq, seg_len, tcb.rcv_nxt, rcv_wnd) {
                // Out-of-window: silently drop RST, send ACK for others.
                if seg_flags & flags::RST != 0 {
                    rx_return.push(frame);
                    return PostAction::None;
                }
                let ts = tcb.ts_option(tsval);
                SegmentBuilder::build_ack(
                    tcb.id.local_addr,
                    tcb.id.remote_addr,
                    tcb.id.local_port,
                    tcb.id.remote_port,
                    tcb.snd_nxt,
                    tcb.rcv_nxt,
                    tcb.advertised_window(),
                    flags::ACK,
                    ts,
                    src_mac,
                    dst_mac,
                    tx_offload,
                    free_frames,
                    tx_return,
                );
                rx_return.push(frame);
                return PostAction::None;
            }
        }

        // RST check (RFC 5961) — after sequence validation.
        if seg_flags & flags::RST != 0 {
            if state == TcpState::TimeWait {
                // Ignore RST in TIME-WAIT (prevents RST attacks).
                rx_return.push(frame);
                return PostAction::None;
            }
            if seg_seq == tcb.rcv_nxt {
                // Exact match: reset connection.
                tcb.event_queue.push(TcpEvent::Reset);
                rx_return.push(frame);
                return PostAction::RemoveConnection(tcb.id);
            }
            // In-window but not exact: send challenge ACK, drop segment.
            let ts = tcb.ts_option(tsval);
            SegmentBuilder::build_ack(
                tcb.id.local_addr,
                tcb.id.remote_addr,
                tcb.id.local_port,
                tcb.id.remote_port,
                tcb.snd_nxt,
                tcb.rcv_nxt,
                tcb.advertised_window(),
                flags::ACK,
                ts,
                src_mac,
                dst_mac,
                tx_offload,
                free_frames,
                tx_return,
            );
            rx_return.push(frame);
            return PostAction::None;
        }

        // Step 4: SYN check (RFC 5961 — challenge ACK for SYN in synchronized state).
        if seg_flags & flags::SYN != 0 {
            let ts = tcb.ts_option(tsval);
            SegmentBuilder::build_ack(
                tcb.id.local_addr,
                tcb.id.remote_addr,
                tcb.id.local_port,
                tcb.id.remote_port,
                tcb.snd_nxt,
                tcb.rcv_nxt,
                tcb.advertised_window(),
                flags::ACK,
                ts,
                src_mac,
                dst_mac,
                tx_offload,
                free_frames,
                tx_return,
            );
            rx_return.push(frame);
            return PostAction::None;
        }

        // Step 5 preamble: if ACK bit is off, drop segment and return.
        if seg_flags & flags::ACK == 0 {
            rx_return.push(frame);
            return PostAction::None;
        }

        match state {
            TcpState::FinWait1 => {
                let fin_acked = if seg_flags & flags::ACK != 0 {
                    if let Some(fin_seq) = tcb.fin_seq {
                        crate::net::wire::tcp::seq_lt(fin_seq, seg_ack)
                    } else {
                        false
                    }
                } else {
                    false
                };

                // Process ACK (advance snd_una if valid).
                if seg_flags & flags::ACK != 0 {
                    let snd_una = tcb.snd_una;
                    let snd_nxt = tcb.snd_nxt;
                    if crate::net::wire::tcp::seq_lt(snd_una, seg_ack)
                        && crate::net::wire::tcp::seq_le(seg_ack, snd_nxt)
                    {
                        let bytes_acked = seg_ack.wrapping_sub(snd_una) as usize;
                        tcb.snd_una = seg_ack;
                        // Cap advance to actual buffer content (FIN consumes a sequence
                        // number but has no corresponding data in the send buffer).
                        let buf_advance = bytes_acked.min(tcb.send_buffer.available());
                        tcb.send_buffer.advance(buf_advance);
                        tcb.snd_wnd = tcb.scale_incoming_window(seg_wnd);
                        tcb.max_snd_wnd = tcb.max_snd_wnd.max(tcb.snd_wnd);
                    }
                }

                // Process data if present (remote may still be sending).
                if payload_len > 0 && seg_seq == tcb.rcv_nxt {
                    let payload = &frame[payload_offset..payload_offset + payload_len];
                    let written = tcb.recv_buffer.write(payload);
                    tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(written as u32);
                }

                // Check for FIN from remote.
                let remote_fin = seg_flags & flags::FIN != 0;
                if remote_fin {
                    tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);
                }

                // Determine new state.
                if fin_acked && remote_fin {
                    // Both sides FINed and our FIN is ACKed → TimeWait.
                    tcb.state = TcpState::TimeWait;
                    tcb.time_wait_deadline =
                        Some(now + coarsetime::Duration::from_millis(tcb.time_wait_duration));
                    tcb.retransmit_deadline = None;
                } else if fin_acked {
                    // Our FIN ACKed but no remote FIN yet → FinWait2.
                    tcb.state = TcpState::FinWait2;
                    tcb.retransmit_deadline = None;
                } else if remote_fin {
                    // Remote FINed but our FIN not yet ACKed → Closing.
                    tcb.state = TcpState::Closing;
                }

                // Send ACK if FIN or data received.
                if remote_fin || payload_len > 0 {
                    let id = tcb.id;
                    let snd_nxt = tcb.snd_nxt;
                    let rcv_nxt = tcb.rcv_nxt;
                    let ts = tcb.ts_option(tsval);
                    let window = tcb.advertised_window();
                    SegmentBuilder::build_ack(
                        id.local_addr,
                        id.remote_addr,
                        id.local_port,
                        id.remote_port,
                        snd_nxt,
                        rcv_nxt,
                        window,
                        flags::ACK,
                        ts,
                        src_mac,
                        dst_mac,
                        tx_offload,
                        free_frames,
                        tx_return,
                    );
                }

                rx_return.push(frame);
            }

            TcpState::FinWait2 => {
                // Process data if present (remote still sending).
                if payload_len > 0 && seg_seq == tcb.rcv_nxt {
                    let payload = &frame[payload_offset..payload_offset + payload_len];
                    let written = tcb.recv_buffer.write(payload);
                    tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(written as u32);
                }

                // Check for FIN.
                if seg_flags & flags::FIN != 0 {
                    tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);
                    tcb.state = TcpState::TimeWait;
                    tcb.time_wait_deadline =
                        Some(now + coarsetime::Duration::from_millis(tcb.time_wait_duration));
                }

                // Send ACK if FIN or data.
                if seg_flags & flags::FIN != 0 || payload_len > 0 {
                    let id = tcb.id;
                    let snd_nxt = tcb.snd_nxt;
                    let rcv_nxt = tcb.rcv_nxt;
                    let ts = tcb.ts_option(tsval);
                    SegmentBuilder::build_ack(
                        id.local_addr,
                        id.remote_addr,
                        id.local_port,
                        id.remote_port,
                        snd_nxt,
                        rcv_nxt,
                        tcb.advertised_window(),
                        flags::ACK,
                        ts,
                        src_mac,
                        dst_mac,
                        tx_offload,
                        free_frames,
                        tx_return,
                    );
                }

                rx_return.push(frame);
            }

            TcpState::Closing => {
                // Waiting for ACK of our FIN.
                if seg_flags & flags::ACK != 0
                    && let Some(fin_seq) = tcb.fin_seq
                    && crate::net::wire::tcp::seq_lt(fin_seq, seg_ack)
                {
                    tcb.snd_una = seg_ack;
                    tcb.state = TcpState::TimeWait;
                    tcb.time_wait_deadline =
                        Some(now + coarsetime::Duration::from_millis(tcb.time_wait_duration));
                    tcb.retransmit_deadline = None;
                }
                rx_return.push(frame);
            }

            TcpState::LastAck => {
                // Waiting for ACK of our FIN.
                if seg_flags & flags::ACK != 0 {
                    if let Some(fin_seq) = tcb.fin_seq
                        && crate::net::wire::tcp::seq_lt(fin_seq, seg_ack)
                    {
                        rx_return.push(frame);
                        return PostAction::RemoveConnection(tcb.id);
                    }
                }
                rx_return.push(frame);
            }

            TcpState::TimeWait => {
                // FIN retransmit → re-ACK and restart timer.
                if seg_flags & flags::FIN != 0 {
                    let id = tcb.id;
                    let snd_nxt = tcb.snd_nxt;
                    let rcv_nxt = tcb.rcv_nxt;
                    let ts = tcb.ts_option(tsval);
                    SegmentBuilder::build_ack(
                        id.local_addr,
                        id.remote_addr,
                        id.local_port,
                        id.remote_port,
                        snd_nxt,
                        rcv_nxt,
                        tcb.advertised_window(),
                        flags::ACK,
                        ts,
                        src_mac,
                        dst_mac,
                        tx_offload,
                        free_frames,
                        tx_return,
                    );
                    tcb.time_wait_deadline =
                        Some(now + coarsetime::Duration::from_millis(tcb.time_wait_duration));
                }
                // Everything else (including RST) is ignored — RST handled above.
                rx_return.push(frame);
            }

            TcpState::CloseWait => {
                // Process ACKs — local side can still send data.
                if seg_flags & flags::ACK != 0 {
                    let snd_una = tcb.snd_una;
                    let snd_nxt = tcb.snd_nxt;

                    if crate::net::wire::tcp::seq_lt(snd_una, seg_ack)
                        && crate::net::wire::tcp::seq_le(seg_ack, snd_nxt)
                    {
                        let bytes_acked = seg_ack.wrapping_sub(snd_una) as usize;
                        tcb.snd_una = seg_ack;
                        let buf_advance = bytes_acked.min(tcb.send_buffer.available());
                        tcb.send_buffer.advance(buf_advance);

                        // Window update with WL1/WL2 guard.
                        if crate::net::wire::tcp::seq_lt(tcb.snd_wl1, seg_seq)
                            || (tcb.snd_wl1 == seg_seq
                                && crate::net::wire::tcp::seq_le(tcb.snd_wl2, seg_ack))
                        {
                            tcb.snd_wnd = tcb.scale_incoming_window(seg_wnd);
                            tcb.max_snd_wnd = tcb.max_snd_wnd.max(tcb.snd_wnd);
                            tcb.snd_wl1 = seg_seq;
                            tcb.snd_wl2 = seg_ack;
                        }
                    }
                }
                rx_return.push(frame);
            }

            _ => {
                rx_return.push(frame);
            }
        }
        PostAction::None
    }
}
