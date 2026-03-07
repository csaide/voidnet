mod isn;
pub(crate) mod ring_buffer;
pub(crate) mod segment;
pub(crate) mod state;
pub(crate) mod tcb;

use coarsetime::Instant;

use crate::{
    net::{
        NeighborHandler,
        checksum::{verify_tcp_checksum, verify_tcp_checksum_v6},
        handler::udp::BindError,
        socket::LocalQueue,
        wire::{
            ethernet::EthernetFrame,
            ip::{IpAddress, Ipv4Header, Ipv6Header},
            tcp::{TcpHeader, TCP_HEADER_LEN, flags, parse_mss, parse_window_scale},
        },
    },
    xdp::frame::{Frame, FrameBuffer},
};

use std::collections::BTreeMap;

use isn::IsnGenerator;
use ring_buffer::RingBuffer;
use segment::SegmentBuilder;
use state::TcpState;
use tcb::{ConnectionId, Tcb, TcpEvent, DEFAULT_RCV_MSS, DEFAULT_RCV_WND, DEFAULT_RCV_WSCALE};

/// Initial RTO for SYN retransmission (1 second in coarsetime ticks).
const INITIAL_RTO_MS: u64 = 1000;

/// R2 threshold for SYN retransmission (~3 minutes per MUST-23).
const SYN_R2_THRESHOLD_MS: u64 = 180_000;

/// Entry for a listening socket.
pub(crate) struct ListenEntry {
    pub addr: IpAddress,
    pub port: u16,
    pub backlog: usize,
    pub accept_queue: LocalQueue<ConnectionId>,
    pub syn_received_count: usize,
}

/// TCP protocol handler.
///
/// Manages the connection table, listener table, and dispatches
/// incoming TCP segments through the appropriate state machine.
pub struct TcpHandler {
    connections: Vec<Tcb>,
    listeners: Vec<ListenEntry>,
    isn_generator: IsnGenerator,
    rx_offload: bool,
    tx_offload: bool,
}

impl TcpHandler {
    pub fn new(rx_offload: bool, tx_offload: bool) -> Self {
        Self {
            connections: Vec::new(),
            listeners: Vec::new(),
            isn_generator: IsnGenerator::new(),
            rx_offload,
            tx_offload,
        }
    }

    // --- Listener management ---

    /// Register a listening socket on (addr, port).
    pub fn listen(
        &mut self,
        addr: IpAddress,
        port: u16,
        backlog: usize,
    ) -> Result<LocalQueue<ConnectionId>, BindError> {
        // Check for duplicate listeners.
        if self.listeners.iter().any(|l| l.port == port && (l.addr == addr || l.addr.is_unspecified() || addr.is_unspecified())) {
            return Err(BindError::AddressInUse);
        }
        let accept_queue = LocalQueue::new(backlog);
        self.listeners.push(ListenEntry {
            addr,
            port,
            backlog,
            accept_queue: accept_queue.clone(),
            syn_received_count: 0,
        });
        Ok(accept_queue)
    }

    /// Remove a listener on (addr, port) and clean up associated SYN-RECEIVED connections.
    pub fn unlisten(&mut self, addr: IpAddress, port: u16) {
        self.listeners.retain(|l| !(l.port == port && l.addr == addr));
        // Remove any SYN-RECEIVED connections associated with this listener.
        self.connections.retain(|c| {
            !(c.state == TcpState::SynReceived
                && c.from_passive_open
                && c.id.local_port == port
                && (addr.is_unspecified() || c.id.local_addr == addr))
        });
    }

    // --- Active open ---

    /// Initiate an active open (connect).
    pub fn connect<'umem>(
        &mut self,
        local_addr: IpAddress,
        local_port: u16,
        remote_addr: IpAddress,
        remote_port: u16,
        src_mac: crate::net::wire::ethernet::MacAddress,
        dst_mac: crate::net::wire::ethernet::MacAddress,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) -> Result<LocalQueue<TcpEvent>, BindError> {
        let id = ConnectionId {
            local_addr,
            local_port,
            remote_addr,
            remote_port,
        };

        // Check for existing connection with same 4-tuple.
        if self.connections.iter().any(|c| c.id == id) {
            return Err(BindError::AddressInUse);
        }

        let iss = self.isn_generator.generate(&id);
        let event_queue = LocalQueue::new(16);

        let tcb = Tcb {
            id,
            state: TcpState::SynSent,
            from_passive_open: false,
            iss,
            snd_una: iss,
            snd_nxt: iss.wrapping_add(1),
            snd_wnd: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            irs: 0,
            rcv_nxt: 0,
            rcv_wnd: DEFAULT_RCV_WND as u32,
            snd_mss: DEFAULT_RCV_MSS,
            rcv_mss: DEFAULT_RCV_MSS,
            eff_snd_mss: DEFAULT_RCV_MSS,
            snd_wscale: 0,
            rcv_wscale: DEFAULT_RCV_WSCALE,
            wscale_enabled: false,
            retransmit_deadline: Some(Instant::now() + coarsetime::Duration::from_millis(INITIAL_RTO_MS)),
            rto_backoff: 0,
            event_queue: event_queue.clone(),
            send_buffer: RingBuffer::new(256 * 1024),
            recv_buffer: RingBuffer::new(256 * 1024),
            ooo_ranges: BTreeMap::new(),
            cwnd: 10 * DEFAULT_RCV_MSS as u32,
            ssthresh: u32::MAX,
            dup_ack_count: 0,
            srtt: None,
            rttvar: 0,
            rto: 1000,
            last_send_time: None,
        };

        // Send SYN.
        SegmentBuilder::build_syn(
            local_addr, remote_addr,
            local_port, remote_port,
            iss, DEFAULT_RCV_WND, DEFAULT_RCV_MSS, DEFAULT_RCV_WSCALE,
            src_mac, dst_mac,
            self.tx_offload, free_frames, tx_return,
        );

        self.connections.push(tcb);
        Ok(event_queue)
    }

    // --- Segment processing ---

    /// Process an incoming IPv4 TCP segment.
    pub fn process_ipv4<'umem>(
        &mut self,
        frame: Frame<'umem>,
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
            opt_buf[..len].copy_from_slice(&frame[tcp_offset + TCP_HEADER_LEN..tcp_offset + header_len]);
            len
        } else {
            0
        };

        let seg_data_len = frame.len() - tcp_offset - header_len;
        let seg_len = Tcb::seg_len(seg_data_len, seg_flags);

        let incoming_src = IpAddress::V4(src_addr);
        let incoming_dst = IpAddress::V4(dst_addr);
        let src_mac = neighbor_handler.local_mac();
        // For responses, swap MACs from incoming frame.
        let dst_mac = EthernetFrame::from_bytes(&frame).src_mac;

        self.process_segment(
            frame, incoming_src, incoming_dst,
            src_port, dst_port, seg_seq, seg_ack, seg_flags, seg_wnd, seg_len,
            &opt_buf[..opt_len], tcp_offset, header_len,
            src_mac, dst_mac,
            free_frames, rx_return, tx_return,
        );
    }

    /// Process an incoming IPv6 TCP segment.
    pub fn process_ipv6<'umem>(
        &mut self,
        frame: Frame<'umem>,
        tcp_offset: usize,
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
            opt_buf[..len].copy_from_slice(&frame[tcp_offset + TCP_HEADER_LEN..tcp_offset + header_len]);
            len
        } else {
            0
        };

        let seg_data_len = frame.len() - tcp_offset - header_len;
        let seg_len = Tcb::seg_len(seg_data_len, seg_flags);

        let incoming_src = IpAddress::V6(src_addr);
        let incoming_dst = IpAddress::V6(dst_addr);
        let src_mac = neighbor_handler.local_mac();
        let dst_mac = EthernetFrame::from_bytes(&frame).src_mac;

        self.process_segment(
            frame, incoming_src, incoming_dst,
            src_port, dst_port, seg_seq, seg_ack, seg_flags, seg_wnd, seg_len,
            &opt_buf[..opt_len], tcp_offset, header_len,
            src_mac, dst_mac,
            free_frames, rx_return, tx_return,
        );
    }

    /// Unified segment processing for both IPv4 and IPv6.
    #[inline]
    fn process_segment<'umem>(
        &mut self,
        frame: Frame<'umem>,
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

        if let Some(idx) = self.connections.iter().position(|c| c.id == conn_id) {
            let state = self.connections[idx].state;
            match state {
                TcpState::SynSent => {
                    self.process_syn_sent(
                        idx, seg_seq, seg_ack, seg_flags, seg_wnd, options,
                        src_mac, dst_mac, free_frames, tx_return,
                    );
                    rx_return.push(frame);
                }
                TcpState::SynReceived => {
                    self.process_syn_received(
                        idx, seg_seq, seg_ack, seg_flags, seg_wnd, seg_len,
                        src_mac, dst_mac, free_frames, tx_return,
                    );
                    rx_return.push(frame);
                }
                TcpState::Established => {
                    let payload_offset = tcp_offset + tcp_header_len;
                    let payload_len = frame.len().saturating_sub(payload_offset);
                    self.process_established(
                        idx, frame, seg_seq, seg_ack, seg_flags, seg_wnd,
                        payload_offset, payload_len,
                        src_mac, dst_mac,
                        free_frames, rx_return, tx_return,
                    );
                }
                _ => {
                    rx_return.push(frame);
                }
            }
            return;
        }

        // No connection found — check listeners (LISTEN state, §16.2).
        if let Some(listener_idx) = self.find_listener(incoming_dst, dst_port) {
            self.process_listen(
                listener_idx,
                incoming_src, incoming_dst, src_port, dst_port,
                seg_seq, seg_ack, seg_flags, seg_wnd, seg_len, options,
                src_mac, dst_mac, free_frames, tx_return,
            );
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
            incoming_src, incoming_dst,
            src_port, dst_port,
            seg_seq, seg_ack, seg_flags, seg_len,
            src_mac, dst_mac,
            self.tx_offload, free_frames, tx_return,
        );
        rx_return.push(frame);
    }

    // --- LISTEN state processing (RFC §16.2) ---

    fn process_listen<'umem>(
        &mut self,
        listener_idx: usize,
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
                incoming_src, incoming_dst,
                src_port, dst_port,
                seg_seq, seg_ack, seg_flags, seg_len,
                src_mac, dst_mac,
                self.tx_offload, free_frames, tx_return,
            );
            return;
        }

        // Step 3: SYN → create new connection in SYN-RECEIVED.
        if seg_flags & flags::SYN != 0 {
            // Check backlog.
            let listener = &self.listeners[listener_idx];
            if listener.syn_received_count >= listener.backlog {
                return; // Drop excess SYNs.
            }

            let id = ConnectionId {
                local_addr: incoming_dst,
                local_port: dst_port,
                remote_addr: incoming_src,
                remote_port: src_port,
            };

            let iss = self.isn_generator.generate(&id);
            let peer_mss = parse_mss(options).unwrap_or(536);
            let peer_wscale = parse_window_scale(options);

            let wscale_enabled = peer_wscale.is_some();
            let snd_wscale = peer_wscale.unwrap_or(0);

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
                eff_snd_mss: peer_mss.min(DEFAULT_RCV_MSS),
                snd_wscale,
                rcv_wscale: if wscale_enabled { DEFAULT_RCV_WSCALE } else { 0 },
                wscale_enabled,
                retransmit_deadline: Some(Instant::now() + coarsetime::Duration::from_millis(INITIAL_RTO_MS)),
                rto_backoff: 0,
                event_queue,
                send_buffer: RingBuffer::new(256 * 1024),
                recv_buffer: RingBuffer::new(256 * 1024),
                ooo_ranges: BTreeMap::new(),
                cwnd: 10 * peer_mss.min(DEFAULT_RCV_MSS) as u32,
                ssthresh: u32::MAX,
                dup_ack_count: 0,
                srtt: None,
                rttvar: 0,
                rto: 1000,
                last_send_time: None,
            };

            // Send SYN-ACK.
            let wscale_opt = if wscale_enabled { Some(DEFAULT_RCV_WSCALE) } else { None };
            SegmentBuilder::build_syn_ack(
                incoming_dst, incoming_src,
                dst_port, src_port,
                iss, seg_seq.wrapping_add(1),
                DEFAULT_RCV_WND, DEFAULT_RCV_MSS, wscale_opt,
                src_mac, dst_mac,
                self.tx_offload, free_frames, tx_return,
            );

            self.connections.push(tcb);
            self.listeners[listener_idx].syn_received_count += 1;
        }

        // Step 4: Other → drop (frame returned by caller).
    }

    // --- SYN-RECEIVED state processing (RFC §16.4) ---

    fn process_syn_received<'umem>(
        &mut self,
        idx: usize,
        seg_seq: u32,
        seg_ack: u32,
        seg_flags: u8,
        seg_wnd: u32,
        _seg_len: u32,
        src_mac: crate::net::wire::ethernet::MacAddress,
        dst_mac: crate::net::wire::ethernet::MacAddress,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let tcb = &self.connections[idx];
        let id = tcb.id;

        // Step 1: Check sequence number acceptability.
        // For SYN-RECEIVED with no data, we expect seg_seq == rcv_nxt.
        // Simplified check: accept if seg_seq == rcv_nxt.
        if seg_seq != tcb.rcv_nxt {
            // Out of window — if not RST, send challenge ACK.
            if seg_flags & flags::RST == 0 {
                let tcb = &self.connections[idx];
                SegmentBuilder::build_ack(
                    tcb.id.local_addr, tcb.id.remote_addr,
                    tcb.id.local_port, tcb.id.remote_port,
                    tcb.snd_nxt, tcb.rcv_nxt,
                    DEFAULT_RCV_WND,
                    src_mac, dst_mac,
                    self.tx_offload, free_frames, tx_return,
                );
            }
            return;
        }

        // Step 2: Check RST.
        if seg_flags & flags::RST != 0 {
            let from_passive = tcb.from_passive_open;
            if from_passive {
                // Return to LISTEN — remove TCB.
                self.decrement_syn_received(&id);
                self.connections.remove(idx);
            } else {
                // Active open → signal refused.
                self.connections[idx].event_queue.push(TcpEvent::ConnectionRefused);
                self.connections.remove(idx);
            }
            return;
        }

        // Step 3: Check SYN (duplicate SYN in synchronized state).
        if seg_flags & flags::SYN != 0 {
            // Send challenge ACK per RFC 5961.
            let tcb = &self.connections[idx];
            SegmentBuilder::build_ack(
                tcb.id.local_addr, tcb.id.remote_addr,
                tcb.id.local_port, tcb.id.remote_port,
                tcb.snd_nxt, tcb.rcv_nxt,
                DEFAULT_RCV_WND,
                src_mac, dst_mac,
                self.tx_offload, free_frames, tx_return,
            );
            return;
        }

        // Step 5: Check ACK.
        if seg_flags & flags::ACK != 0 {
            let tcb = &self.connections[idx];
            let snd_una = tcb.snd_una;
            let snd_nxt = tcb.snd_nxt;

            if crate::net::wire::tcp::seq_lt(snd_una, seg_ack)
                && crate::net::wire::tcp::seq_le(seg_ack, snd_nxt)
            {
                // ACK is acceptable → transition to ESTABLISHED.
                let tcb = &mut self.connections[idx];
                tcb.state = TcpState::Established;
                tcb.snd_una = seg_ack;
                tcb.snd_wnd = seg_wnd;
                tcb.snd_wl1 = seg_seq;
                tcb.snd_wl2 = seg_ack;
                tcb.retransmit_deadline = None;
                tcb.rto_backoff = 0;

                // Push ConnectionId to listener's accept_queue.
                self.push_to_accept_queue(&id);
                self.decrement_syn_received(&id);
            } else {
                // Bad ACK → send RST.
                SegmentBuilder::build_rst(
                    id.remote_addr, id.local_addr,
                    id.remote_port, id.local_port,
                    seg_seq, seg_ack, seg_flags, 0,
                    src_mac, dst_mac,
                    self.tx_offload, free_frames, tx_return,
                );
            }
        }
    }

    // --- SYN-SENT state processing (RFC §16.3) ---

    fn process_syn_sent<'umem>(
        &mut self,
        idx: usize,
        seg_seq: u32,
        seg_ack: u32,
        seg_flags: u8,
        seg_wnd: u32,
        options: &[u8],
        src_mac: crate::net::wire::ethernet::MacAddress,
        dst_mac: crate::net::wire::ethernet::MacAddress,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let tcb = &self.connections[idx];
        let iss = tcb.iss;

        // Step 1: Check ACK.
        if seg_flags & flags::ACK != 0 {
            if crate::net::wire::tcp::seq_le(seg_ack, iss) || crate::net::wire::tcp::seq_lt(tcb.snd_nxt, seg_ack) {
                // Unacceptable ACK.
                if seg_flags & flags::RST == 0 {
                    // Send RST unless RST is set.
                    let id = tcb.id;
                    SegmentBuilder::build_rst(
                        id.remote_addr, id.local_addr,
                        id.remote_port, id.local_port,
                        seg_seq, seg_ack, seg_flags, 0,
                        src_mac, dst_mac,
                        self.tx_offload, free_frames, tx_return,
                    );
                }
                return;
            }
        }

        // Step 2: Check RST.
        if seg_flags & flags::RST != 0 {
            if seg_flags & flags::ACK != 0 {
                // ACK was acceptable (passed step 1) → connection refused.
                self.connections[idx].event_queue.push(TcpEvent::ConnectionRefused);
                self.connections.remove(idx);
            }
            // RST without ACK → drop silently.
            return;
        }

        // Step 3: Check SYN.
        if seg_flags & flags::SYN != 0 {
            let tcb = &mut self.connections[idx];
            tcb.irs = seg_seq;
            tcb.rcv_nxt = seg_seq.wrapping_add(1);

            // Parse peer options.
            let peer_mss = parse_mss(options).unwrap_or(536);
            let peer_wscale = parse_window_scale(options);
            tcb.snd_mss = peer_mss;
            tcb.eff_snd_mss = peer_mss.min(tcb.rcv_mss);

            if let Some(ws) = peer_wscale {
                tcb.snd_wscale = ws;
                tcb.wscale_enabled = true;
            }

            if seg_flags & flags::ACK != 0 {
                // Our SYN was ACKed.
                tcb.snd_una = seg_ack;
            }

            if crate::net::wire::tcp::seq_lt(tcb.iss, tcb.snd_una) {
                // SND.UNA > ISS → ESTABLISHED.
                let tcb = &mut self.connections[idx];
                tcb.state = TcpState::Established;
                tcb.snd_wnd = seg_wnd;
                tcb.snd_wl1 = seg_seq;
                tcb.snd_wl2 = seg_ack;
                tcb.retransmit_deadline = None;
                tcb.rto_backoff = 0;

                // Send ACK.
                let id = tcb.id;
                SegmentBuilder::build_ack(
                    id.local_addr, id.remote_addr,
                    id.local_port, id.remote_port,
                    tcb.snd_nxt, tcb.rcv_nxt,
                    DEFAULT_RCV_WND,
                    src_mac, dst_mac,
                    self.tx_offload, free_frames, tx_return,
                );

                tcb.event_queue.push(TcpEvent::Connected);
            } else {
                // Simultaneous open → SYN-RECEIVED (MUST-10).
                let tcb = &mut self.connections[idx];
                tcb.state = TcpState::SynReceived;
                tcb.from_passive_open = false;
                tcb.snd_wnd = seg_wnd;
                tcb.snd_wl1 = seg_seq;
                tcb.snd_wl2 = seg_ack;

                // Send SYN-ACK.
                let id = tcb.id;
                let wscale_opt = if tcb.wscale_enabled { Some(tcb.rcv_wscale) } else { None };
                SegmentBuilder::build_syn_ack(
                    id.local_addr, id.remote_addr,
                    id.local_port, id.remote_port,
                    tcb.iss, tcb.rcv_nxt,
                    DEFAULT_RCV_WND, tcb.rcv_mss, wscale_opt,
                    src_mac, dst_mac,
                    self.tx_offload, free_frames, tx_return,
                );

                // Reset retransmit timer for SYN-ACK.
                tcb.retransmit_deadline = Some(Instant::now() + coarsetime::Duration::from_millis(INITIAL_RTO_MS));
                tcb.rto_backoff = 0;
            }
        }

        // Step 4: Neither SYN nor RST → drop.
    }

    // --- ESTABLISHED state processing ---

    fn process_established<'umem>(
        &mut self,
        idx: usize,
        frame: Frame<'umem>,
        seg_seq: u32,
        seg_ack: u32,
        seg_flags: u8,
        seg_wnd: u32,
        payload_offset: usize,
        payload_len: usize,
        src_mac: crate::net::wire::ethernet::MacAddress,
        dst_mac: crate::net::wire::ethernet::MacAddress,
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        use crate::net::wire::tcp::{seq_lt, seq_le};

        // Step 1: RST check.
        if seg_flags & flags::RST != 0 {
            self.connections[idx].event_queue.push(TcpEvent::Reset);
            let id = self.connections[idx].id;
            self.decrement_syn_received(&id);
            self.connections.remove(idx);
            rx_return.push(frame);
            return;
        }

        // Step 2: ACK processing.
        if seg_flags & flags::ACK != 0 {
            let tcb = &self.connections[idx];
            let snd_una = tcb.snd_una;
            let snd_nxt = tcb.snd_nxt;

            if seq_lt(snd_una, seg_ack) && seq_le(seg_ack, snd_nxt) {
                // Valid new ACK — advance snd_una and send buffer.
                let bytes_acked = seg_ack.wrapping_sub(snd_una) as usize;
                let tcb = &mut self.connections[idx];
                tcb.snd_una = seg_ack;
                tcb.send_buffer.advance(bytes_acked);

                // Congestion control.
                let eff_mss = tcb.eff_snd_mss as u32;
                if tcb.cwnd < tcb.ssthresh {
                    // Slow start.
                    tcb.cwnd += eff_mss;
                } else {
                    // Congestion avoidance.
                    tcb.cwnd += (eff_mss * eff_mss) / tcb.cwnd;
                }

                tcb.dup_ack_count = 0;

                // Update send window.
                tcb.snd_wnd = seg_wnd;
                tcb.snd_wl1 = seg_seq;
                tcb.snd_wl2 = seg_ack;
            } else if seg_ack == snd_una && payload_len == 0 {
                // Duplicate ACK.
                self.connections[idx].dup_ack_count += 1;
            }
        }

        // Step 3: Data processing.
        if payload_len > 0 {
            let tcb = &self.connections[idx];
            let rcv_nxt = tcb.rcv_nxt;

            if seg_seq == rcv_nxt {
                // In-order data.
                let payload = &frame[payload_offset..payload_offset + payload_len];
                let tcb = &mut self.connections[idx];
                tcb.recv_buffer.write(payload);
                tcb.rcv_nxt = rcv_nxt.wrapping_add(payload_len as u32);

                // Drain contiguous OOO ranges.
                loop {
                    let current_nxt = self.connections[idx].rcv_nxt;
                    if let Some(&ooo_len) = self.connections[idx].ooo_ranges.get(&current_nxt) {
                        self.connections[idx].ooo_ranges.remove(&current_nxt);
                        self.connections[idx].recv_buffer.commit(ooo_len as usize);
                        self.connections[idx].rcv_nxt = current_nxt.wrapping_add(ooo_len);
                    } else {
                        break;
                    }
                }

                // Send ACK.
                let tcb = &self.connections[idx];
                SegmentBuilder::build_ack(
                    tcb.id.local_addr, tcb.id.remote_addr,
                    tcb.id.local_port, tcb.id.remote_port,
                    tcb.snd_nxt, tcb.rcv_nxt,
                    DEFAULT_RCV_WND,
                    src_mac, dst_mac,
                    self.tx_offload, free_frames, tx_return,
                );
            } else if seq_lt(rcv_nxt, seg_seq) {
                // Out-of-order data.
                let offset = seg_seq.wrapping_sub(rcv_nxt) as usize;
                let payload = &frame[payload_offset..payload_offset + payload_len];
                let tcb = &mut self.connections[idx];
                tcb.recv_buffer.write_at(offset, payload);
                tcb.ooo_ranges.insert(seg_seq, payload_len as u32);

                // Send duplicate ACK (with current rcv_nxt).
                SegmentBuilder::build_ack(
                    tcb.id.local_addr, tcb.id.remote_addr,
                    tcb.id.local_port, tcb.id.remote_port,
                    tcb.snd_nxt, tcb.rcv_nxt,
                    DEFAULT_RCV_WND,
                    src_mac, dst_mac,
                    self.tx_offload, free_frames, tx_return,
                );
            } else {
                // Duplicate data (seg_seq < rcv_nxt) — just ACK.
                let tcb = &self.connections[idx];
                SegmentBuilder::build_ack(
                    tcb.id.local_addr, tcb.id.remote_addr,
                    tcb.id.local_port, tcb.id.remote_port,
                    tcb.snd_nxt, tcb.rcv_nxt,
                    DEFAULT_RCV_WND,
                    src_mac, dst_mac,
                    self.tx_offload, free_frames, tx_return,
                );
            }
        }

        // Always return incoming frame to rx_return.
        rx_return.push(frame);
    }

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
                    SegmentBuilder::build_syn(
                        id.local_addr, id.remote_addr,
                        id.local_port, id.remote_port,
                        tcb.iss, DEFAULT_RCV_WND, DEFAULT_RCV_MSS, DEFAULT_RCV_WSCALE,
                        src_mac, dst_mac,
                        self.tx_offload, free_frames, tx_return,
                    );
                }
                TcpState::SynReceived => {
                    let wscale_opt = if tcb.wscale_enabled { Some(tcb.rcv_wscale) } else { None };
                    SegmentBuilder::build_syn_ack(
                        id.local_addr, id.remote_addr,
                        id.local_port, id.remote_port,
                        tcb.iss, tcb.rcv_nxt,
                        DEFAULT_RCV_WND, tcb.rcv_mss, wscale_opt,
                        src_mac, dst_mac,
                        self.tx_offload, free_frames, tx_return,
                    );
                }
                _ => continue,
            }

            // Exponential backoff.
            tcb.rto_backoff += 1;
            let rto = INITIAL_RTO_MS << tcb.rto_backoff;
            tcb.retransmit_deadline = Some(now + coarsetime::Duration::from_millis(rto));
        }

        // Remove timed-out connections (in reverse order to preserve indices).
        for idx in to_remove.into_iter().rev() {
            let id = self.connections[idx].id;
            self.decrement_syn_received(&id);
            self.connections.remove(idx);
        }
    }

    /// Evict stale connections (placeholder for future timer-based cleanup).
    pub fn evict_stale<'umem>(
        &mut self,
        _now: Instant,
        _rx_return: &mut impl FrameBuffer<'umem>,
    ) {
        // Placeholder — will be used for TIME-WAIT cleanup in future phases.
    }

    // --- Helpers ---

    /// Find a matching listener for the given address and port.
    fn find_listener(&self, addr: IpAddress, port: u16) -> Option<usize> {
        self.listeners.iter().position(|l| {
            l.port == port && (l.addr.is_unspecified() || l.addr == addr)
        })
    }

    /// Push a ConnectionId to the matching listener's accept queue.
    fn push_to_accept_queue(&self, id: &ConnectionId) {
        for listener in &self.listeners {
            if listener.port == id.local_port
                && (listener.addr.is_unspecified() || listener.addr == id.local_addr)
            {
                listener.accept_queue.push(*id);
                return;
            }
        }
    }

    /// Decrement syn_received_count on the matching listener.
    fn decrement_syn_received(&mut self, id: &ConnectionId) {
        for listener in &mut self.listeners {
            if listener.port == id.local_port
                && (listener.addr.is_unspecified() || listener.addr == id.local_addr)
            {
                listener.syn_received_count = listener.syn_received_count.saturating_sub(1);
                return;
            }
        }
    }

    /// Get a reference to the connection for a given ConnectionId.
    pub fn get_connection(&self, id: &ConnectionId) -> Option<&Tcb> {
        self.connections.iter().find(|c| c.id == *id)
    }

    /// Remove a connection by ConnectionId (used by TcpStream::close).
    pub fn remove_connection<'umem>(
        &mut self,
        id: &ConnectionId,
        src_mac: crate::net::wire::ethernet::MacAddress,
        dst_mac: crate::net::wire::ethernet::MacAddress,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        if let Some(idx) = self.connections.iter().position(|c| c.id == *id) {
            let tcb = &self.connections[idx];
            // Send RST for now (proper FIN sequence deferred).
            if tcb.state.is_synchronized() || tcb.state == TcpState::SynReceived {
                SegmentBuilder::build_rst(
                    id.local_addr, id.remote_addr,
                    id.local_port, id.remote_port,
                    0, 0, flags::ACK, 0,
                    src_mac, dst_mac,
                    self.tx_offload, free_frames, tx_return,
                );
            }
            self.connections.remove(idx);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        net::{
            checksum::{compute_ipv4_checksum, compute_tcp_checksum},
            wire::{
                ip::{IPV4_MIN_HEADER_LEN, IpAddress, IpProtocols, Ipv4Address},
                tcp::{TCP_HEADER_LEN, TcpHeader, flags},
            },
        },
        xdp::frame::{BasicFrameBuffer, Frame},
    };

    use super::*;

    const LOCAL_IP: Ipv4Address = Ipv4Address::new([10, 0, 0, 1]);
    const REMOTE_IP: Ipv4Address = Ipv4Address::new([10, 0, 0, 2]);
    const ETH_HEADER_LEN: usize = 14;

    fn new_handler() -> TcpHandler {
        TcpHandler::new(false, false)
    }

    fn new_neighbor_handler() -> NeighborHandler {
        NeighborHandler::new("test0", coarsetime::Duration::from_secs(60)).unwrap()
    }

    /// Build a valid Ethernet + IPv4 + TCP frame.
    fn build_tcp_frame(
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        tcp_flags: u8,
        window: u16,
        tcp_options: &[u8],
    ) -> Vec<u8> {
        let opt_padded_len = (tcp_options.len() + 3) & !3;
        let tcp_header_len = TCP_HEADER_LEN + opt_padded_len;
        let data_offset = (tcp_header_len / 4) as u8;
        let total_ip_len = (IPV4_MIN_HEADER_LEN + tcp_header_len) as u16;
        let mut buf = vec![0u8; ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + tcp_header_len];

        // Ethernet header.
        buf[0..6].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // dst mac
        buf[6..12].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // src mac
        buf[12] = 0x08;
        buf[13] = 0x00;

        // IPv4 header.
        let ip = &mut buf[ETH_HEADER_LEN..];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&total_ip_len.to_be_bytes());
        ip[6] = 0x40;
        ip[8] = 64;
        ip[9] = IpProtocols::Tcp;
        let src_bytes: [u8; 4] = src_ip.into();
        ip[12..16].copy_from_slice(&src_bytes);
        let dst_bytes: [u8; 4] = dst_ip.into();
        ip[16..20].copy_from_slice(&dst_bytes);
        let cksum = compute_ipv4_checksum(&ip[..20]);
        ip[10] = cksum[0];
        ip[11] = cksum[1];

        // TCP header.
        let tcp_off = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        let hdr = TcpHeader::new(
            src_port, dst_port, seq, ack,
            data_offset, tcp_flags, window,
            [0, 0], 0,
        );
        let hdr_bytes = unsafe {
            std::slice::from_raw_parts(&hdr as *const TcpHeader as *const u8, TCP_HEADER_LEN)
        };
        buf[tcp_off..tcp_off + TCP_HEADER_LEN].copy_from_slice(hdr_bytes);

        // Options.
        if !tcp_options.is_empty() {
            buf[tcp_off + TCP_HEADER_LEN..tcp_off + TCP_HEADER_LEN + tcp_options.len()]
                .copy_from_slice(tcp_options);
        }

        // TCP checksum.
        let tcp_segment = &mut buf[tcp_off..];
        let cksum = compute_tcp_checksum(&src_ip, &dst_ip, tcp_segment);
        buf[tcp_off + 16] = cksum[0];
        buf[tcp_off + 17] = cksum[1];

        buf
    }

    /// Build a valid Ethernet + IPv4 + TCP frame with payload data.
    fn build_tcp_frame_with_payload(
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        tcp_flags: u8,
        window: u16,
        tcp_options: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        let opt_padded_len = (tcp_options.len() + 3) & !3;
        let tcp_header_len = TCP_HEADER_LEN + opt_padded_len;
        let data_offset = (tcp_header_len / 4) as u8;
        let total_ip_len = (IPV4_MIN_HEADER_LEN + tcp_header_len + payload.len()) as u16;
        let mut buf = vec![0u8; ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + tcp_header_len + payload.len()];

        // Ethernet header.
        buf[0..6].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // dst mac
        buf[6..12].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // src mac
        buf[12] = 0x08;
        buf[13] = 0x00;

        // IPv4 header.
        let ip = &mut buf[ETH_HEADER_LEN..];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&total_ip_len.to_be_bytes());
        ip[6] = 0x40;
        ip[8] = 64;
        ip[9] = IpProtocols::Tcp;
        let src_bytes: [u8; 4] = src_ip.into();
        ip[12..16].copy_from_slice(&src_bytes);
        let dst_bytes: [u8; 4] = dst_ip.into();
        ip[16..20].copy_from_slice(&dst_bytes);
        let cksum = compute_ipv4_checksum(&ip[..20]);
        ip[10] = cksum[0];
        ip[11] = cksum[1];

        // TCP header.
        let tcp_off = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        let hdr = TcpHeader::new(
            src_port, dst_port, seq, ack,
            data_offset, tcp_flags, window,
            [0, 0], 0,
        );
        let hdr_bytes = unsafe {
            std::slice::from_raw_parts(&hdr as *const TcpHeader as *const u8, TCP_HEADER_LEN)
        };
        buf[tcp_off..tcp_off + TCP_HEADER_LEN].copy_from_slice(hdr_bytes);

        // Options.
        if !tcp_options.is_empty() {
            buf[tcp_off + TCP_HEADER_LEN..tcp_off + TCP_HEADER_LEN + tcp_options.len()]
                .copy_from_slice(tcp_options);
        }

        // Payload.
        if !payload.is_empty() {
            buf[tcp_off + tcp_header_len..tcp_off + tcp_header_len + payload.len()]
                .copy_from_slice(payload);
        }

        // TCP checksum (covers header + payload).
        let tcp_segment = &mut buf[tcp_off..];
        let cksum = compute_tcp_checksum(&src_ip, &dst_ip, tcp_segment);
        buf[tcp_off + 16] = cksum[0];
        buf[tcp_off + 17] = cksum[1];

        buf
    }

    /// Leak data for test frames — avoids lifetime issues with frame buffers.
    fn leak(data: Vec<u8>) -> &'static mut [u8] {
        Box::leak(data.into_boxed_slice())
    }

    fn alloc_free_frame(addr: u64) -> Frame<'static> {
        Frame::new(addr, leak(vec![0u8; 256]), 256, false)
    }

    #[test]
    fn unmatched_syn_generates_rst() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(4);
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        free.push(alloc_free_frame(100));

        let data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1000, 0, flags::SYN, 65535, &[]);
        let len = data.len();
        let frame = Frame::new(0, leak(data), len, false);

        handler.process_ipv4(frame, &nh, &mut free, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1, "original frame returned to rx");
        assert_eq!(tx.num_frames(), 1, "RST generated on tx");
        assert_eq!(free.num_frames(), 0, "free frame consumed");
    }

    #[test]
    fn rst_to_unbound_port_silently_dropped() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(4);
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1000, 0, flags::RST, 0, &[]);
        let len = data.len();
        let frame = Frame::new(0, leak(data), len, false);

        handler.process_ipv4(frame, &nh, &mut free, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1, "frame returned to rx");
        assert_eq!(tx.num_frames(), 0, "no RST for RST");
    }

    #[test]
    fn invalid_checksum_dropped() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(4);
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1000, 0, flags::SYN, 65535, &[]);
        // Corrupt checksum.
        let tcp_off = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        let leaked = leak(data);
        leaked[tcp_off + 16] ^= 0xFF;
        let len = leaked.len();
        let frame = Frame::new(0, leaked, len, false);

        handler.process_ipv4(frame, &nh, &mut free, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1, "frame returned to rx");
        assert_eq!(tx.num_frames(), 0, "no RST for bad checksum");
    }

    #[test]
    fn truncated_tcp_header_dropped() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(4);
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        // Build a frame that's too short for a TCP header.
        let mut data = vec![0u8; ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + 10]; // only 10 bytes of TCP
        data[12] = 0x08;
        data[13] = 0x00;
        data[ETH_HEADER_LEN] = 0x45;
        let total = (IPV4_MIN_HEADER_LEN + 10) as u16;
        data[ETH_HEADER_LEN + 2..ETH_HEADER_LEN + 4].copy_from_slice(&total.to_be_bytes());
        data[ETH_HEADER_LEN + 8] = 64;
        data[ETH_HEADER_LEN + 9] = IpProtocols::Tcp;
        let src_bytes: [u8; 4] = REMOTE_IP.into();
        data[ETH_HEADER_LEN + 12..ETH_HEADER_LEN + 16].copy_from_slice(&src_bytes);
        let dst_bytes: [u8; 4] = LOCAL_IP.into();
        data[ETH_HEADER_LEN + 16..ETH_HEADER_LEN + 20].copy_from_slice(&dst_bytes);
        let cksum = compute_ipv4_checksum(&data[ETH_HEADER_LEN..ETH_HEADER_LEN + 20]);
        data[ETH_HEADER_LEN + 10] = cksum[0];
        data[ETH_HEADER_LEN + 11] = cksum[1];

        let len = data.len();
        let frame = Frame::new(0, leak(data), len, false);

        handler.process_ipv4(frame, &nh, &mut free, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1, "truncated frame returned to rx");
        assert_eq!(tx.num_frames(), 0, "no response");
    }

    #[test]
    fn syn_to_listener_generates_syn_ack() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(4);
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        free.push(alloc_free_frame(100));

        let accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();

        // MSS option in SYN.
        let mss_opt = [0x02, 0x04, 0x05, 0xB4]; // MSS=1460
        let data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1000, 0, flags::SYN, 65535, &mss_opt);
        let len = data.len();
        let frame = Frame::new(0, leak(data), len, false);

        handler.process_ipv4(frame, &nh, &mut free, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1, "original frame to rx");
        assert_eq!(tx.num_frames(), 1, "SYN-ACK generated");
        assert_eq!(handler.connections.len(), 1, "connection created");
        assert_eq!(handler.connections[0].state, TcpState::SynReceived);
        assert_eq!(handler.connections[0].snd_mss, 1460);
        assert!(accept_queue.is_empty(), "not yet in accept queue");
    }

    #[test]
    fn handshake_completes_on_ack() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(8);
        let mut rx = BasicFrameBuffer::new(8);
        let mut tx = BasicFrameBuffer::new(8);

        for i in 0..4 {
            free.push(alloc_free_frame(100 + i));
        }

        let accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();

        // Step 1: SYN.
        let syn_data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1000, 0, flags::SYN, 65535, &[]);
        let syn_len = syn_data.len();
        let syn_frame = Frame::new(0, leak(syn_data), syn_len, false);
        handler.process_ipv4(syn_frame, &nh, &mut free, &mut rx, &mut tx);
        assert_eq!(handler.connections[0].state, TcpState::SynReceived);

        // Get ISS from the TCB.
        let server_iss = handler.connections[0].iss;

        // Step 2: ACK completing handshake.
        let ack_data = build_tcp_frame(
            REMOTE_IP, LOCAL_IP, 12345, 80,
            1001, server_iss.wrapping_add(1),
            flags::ACK, 65535, &[],
        );
        let ack_len = ack_data.len();
        let ack_frame = Frame::new(1, leak(ack_data), ack_len, false);
        handler.process_ipv4(ack_frame, &nh, &mut free, &mut rx, &mut tx);

        assert_eq!(handler.connections[0].state, TcpState::Established);
        assert_eq!(accept_queue.len(), 1, "connection in accept queue");
    }

    #[test]
    fn rst_in_syn_received_removes_connection() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(8);
        let mut rx = BasicFrameBuffer::new(8);
        let mut tx = BasicFrameBuffer::new(8);

        for i in 0..4 {
            free.push(alloc_free_frame(100 + i));
        }

        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();

        // SYN.
        let syn_data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1000, 0, flags::SYN, 65535, &[]);
        let syn_len = syn_data.len();
        let syn_frame = Frame::new(0, leak(syn_data), syn_len, false);
        handler.process_ipv4(syn_frame, &nh, &mut free, &mut rx, &mut tx);
        assert_eq!(handler.connections.len(), 1);

        // RST.
        let rcv_nxt = handler.connections[0].rcv_nxt;
        let rst_data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, rcv_nxt, 0, flags::RST, 0, &[]);
        let rst_len = rst_data.len();
        let rst_frame = Frame::new(2, leak(rst_data), rst_len, false);
        handler.process_ipv4(rst_frame, &nh, &mut free, &mut rx, &mut tx);

        assert_eq!(handler.connections.len(), 0, "connection removed");
    }

    #[test]
    fn backlog_limits_syn_received() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(16);
        let mut rx = BasicFrameBuffer::new(16);
        let mut tx = BasicFrameBuffer::new(16);

        for i in 0..8 {
            free.push(alloc_free_frame(100 + i));
        }

        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 2).unwrap();

        // Send 3 SYNs — only 2 should be accepted (backlog=2).
        for i in 0..3u16 {
            let syn_data = build_tcp_frame(
                REMOTE_IP, LOCAL_IP,
                10000 + i, 80,
                1000, 0, flags::SYN, 65535, &[],
            );
            let syn_len = syn_data.len();
            let syn_frame = Frame::new(i as u64, leak(syn_data), syn_len, false);
            handler.process_ipv4(syn_frame, &nh, &mut free, &mut rx, &mut tx);
        }

        assert_eq!(handler.connections.len(), 2, "backlog limits connections");
    }

    #[test]
    fn frame_accounting_after_rst() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(4);
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        free.push(alloc_free_frame(100));

        let data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1000, 0, flags::SYN, 65535, &[]);
        let len = data.len();
        let frame = Frame::new(0, leak(data), len, false);

        handler.process_ipv4(frame, &nh, &mut free, &mut rx, &mut tx);

        let total = free.num_frames() + rx.num_frames() + tx.num_frames();
        assert_eq!(total, 2, "all frames accounted for (1 rx + 1 tx)");
    }

    #[test]
    fn window_scale_negotiation() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(8);
        let mut rx = BasicFrameBuffer::new(8);
        let mut tx = BasicFrameBuffer::new(8);

        for i in 0..4 {
            free.push(alloc_free_frame(100 + i));
        }

        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();

        // SYN with MSS + Window Scale options.
        let ws_opts = [
            0x02, 0x04, 0x05, 0xB4, // MSS=1460
            0x01,                     // NOP
            0x03, 0x03, 0x07,         // Window Scale=7
        ];
        let syn_data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1000, 0, flags::SYN, 65535, &ws_opts);
        let syn_len = syn_data.len();
        let syn_frame = Frame::new(0, leak(syn_data), syn_len, false);
        handler.process_ipv4(syn_frame, &nh, &mut free, &mut rx, &mut tx);

        assert_eq!(handler.connections[0].wscale_enabled, true);
        assert_eq!(handler.connections[0].snd_wscale, 7);
        assert_eq!(handler.connections[0].rcv_wscale, DEFAULT_RCV_WSCALE);
    }

    #[test]
    fn established_receives_in_order_data() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(16);
        let mut rx = BasicFrameBuffer::new(16);
        let mut tx = BasicFrameBuffer::new(16);

        for i in 0..8 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete the handshake.
        let accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1000, 0, flags::SYN, 65535, &[]);
        let syn_len = syn_data.len();
        handler.process_ipv4(Frame::new(0, leak(syn_data), syn_len, false), &nh, &mut free, &mut rx, &mut tx);
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1001, server_iss.wrapping_add(1), flags::ACK, 65535, &[]);
        let ack_len = ack_data.len();
        handler.process_ipv4(Frame::new(1, leak(ack_data), ack_len, false), &nh, &mut free, &mut rx, &mut tx);
        assert_eq!(handler.connections[0].state, TcpState::Established);

        // Clear tx from handshake.
        while tx.pop().is_some() {}

        // Send a data segment.
        let payload = b"Hello, TCP!";
        let data = build_tcp_frame_with_payload(
            REMOTE_IP, LOCAL_IP, 12345, 80,
            1001, server_iss.wrapping_add(1),
            flags::ACK, 65535, &[], payload,
        );
        let data_len = data.len();
        handler.process_ipv4(Frame::new(2, leak(data), data_len, false), &nh, &mut free, &mut rx, &mut tx);

        // Verify: frame returned to rx_return, ACK generated on tx.
        assert!(rx.num_frames() >= 1, "incoming frame returned to rx_return");
        assert_eq!(tx.num_frames(), 1, "ACK generated");

        // Verify: data is in the receive ring buffer.
        let tcb = &handler.connections[0];
        assert_eq!(tcb.recv_buffer.available(), payload.len());
        assert_eq!(tcb.rcv_nxt, 1001 + payload.len() as u32);

        drop(accept_queue);
    }
}
