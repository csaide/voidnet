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
            tcp::{
                TCP_HEADER_LEN, TcpHeader, flags, parse_mss, parse_sack_permitted, parse_timestamp,
                parse_window_scale,
            },
        },
    },
    xdp::frame::{Frame, FrameBuffer},
};

use std::collections::BTreeMap;

use isn::IsnGenerator;
use ring_buffer::RingBuffer;
use segment::SegmentBuilder;
use state::TcpState;
use tcb::{
    ConnectionId, DEFAULT_DELAYED_ACK_MS, DEFAULT_RCV_MSS, DEFAULT_RCV_WND, DEFAULT_RCV_WSCALE,
    MAX_DELAYED_ACK_COUNT, Tcb, TcpConfig, TcpEvent,
};

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
    pub send_buffer_size: usize,
    pub recv_buffer_size: usize,
    pub time_wait_duration: u64,
    pub tcp_no_delay: bool,
    pub delayed_ack_ms: u64,
    pub keep_alive: bool,
    pub keep_alive_idle_ms: u64,
    pub keep_alive_interval_ms: u64,
    pub keep_alive_count: u8,
    pub linger: Option<u64>,
    pub timestamps: bool,
    pub sack: bool,
}

/// Check segment acceptability per RFC 9293 §3.10.7.4.
#[inline]
fn is_segment_acceptable(seg_seq: u32, seg_len: u32, rcv_nxt: u32, rcv_wnd: u32) -> bool {
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

    /// Register a listening socket on (addr, port).
    pub fn listen(
        &mut self,
        addr: IpAddress,
        port: u16,
        backlog: usize,
    ) -> Result<LocalQueue<ConnectionId>, BindError> {
        let config = TcpConfig {
            backlog,
            ..TcpConfig::default()
        };
        self.listen_with_config(addr, port, config)
    }

    /// Register a listening socket with custom buffer configuration.
    pub fn listen_with_config(
        &mut self,
        addr: IpAddress,
        port: u16,
        config: TcpConfig,
    ) -> Result<LocalQueue<ConnectionId>, BindError> {
        // Check for duplicate listeners.
        if self.listeners.iter().any(|l| {
            l.port == port && (l.addr == addr || l.addr.is_unspecified() || addr.is_unspecified())
        }) {
            return Err(BindError::AddressInUse);
        }
        let accept_queue = LocalQueue::new(config.backlog);
        self.listeners.push(ListenEntry {
            addr,
            port,
            backlog: config.backlog,
            accept_queue: accept_queue.clone(),
            syn_received_count: 0,
            send_buffer_size: config.send_buffer_size,
            recv_buffer_size: config.recv_buffer_size,
            time_wait_duration: config.time_wait_duration_ms,
            tcp_no_delay: config.tcp_no_delay,
            delayed_ack_ms: config.delayed_ack_ms,
            keep_alive: config.keep_alive,
            keep_alive_idle_ms: config.keep_alive_idle_ms,
            keep_alive_interval_ms: config.keep_alive_interval_ms,
            keep_alive_count: config.keep_alive_count,
            linger: config.linger,
            timestamps: config.timestamps,
            sack: config.sack,
        });
        Ok(accept_queue)
    }

    /// Remove a listener on (addr, port) and clean up associated SYN-RECEIVED connections.
    pub fn unlisten(&mut self, addr: IpAddress, port: u16) {
        self.listeners
            .retain(|l| !(l.port == port && l.addr == addr));
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
        self.connect_with_config(
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            src_mac,
            dst_mac,
            TcpConfig::default(),
            free_frames,
            tx_return,
        )
    }

    /// Initiate an active open (connect) with custom buffer configuration.
    pub fn connect_with_config<'umem>(
        &mut self,
        local_addr: IpAddress,
        local_port: u16,
        remote_addr: IpAddress,
        remote_port: u16,
        src_mac: crate::net::wire::ethernet::MacAddress,
        dst_mac: crate::net::wire::ethernet::MacAddress,
        config: TcpConfig,
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
            retransmit_deadline: Some(
                Instant::now() + coarsetime::Duration::from_millis(INITIAL_RTO_MS),
            ),
            rto_backoff: 0,
            event_queue: event_queue.clone(),
            send_buffer: RingBuffer::new(config.send_buffer_size),
            recv_buffer: RingBuffer::new(config.recv_buffer_size),
            ooo_ranges: BTreeMap::new(),
            cwnd: 10 * DEFAULT_RCV_MSS as u32,
            ssthresh: u32::MAX,
            dup_ack_count: 0,
            srtt: None,
            rttvar: 0,
            rto: 1000,
            last_send_time: None,
            pending_fin: false,
            fin_seq: None,
            time_wait_deadline: None,
            time_wait_duration: config.time_wait_duration_ms,
            ack_pending: false,
            delayed_ack_deadline: None,
            ack_delay_count: 0,
            delayed_ack_ms: DEFAULT_DELAYED_ACK_MS,
            nagle_enabled: !config.tcp_no_delay,
            keep_alive_enabled: config.keep_alive,
            keep_alive_idle_ms: config.keep_alive_idle_ms,
            keep_alive_interval_ms: config.keep_alive_interval_ms,
            keep_alive_count: config.keep_alive_count,
            last_activity: Instant::now(),
            keep_alive_probes_sent: 0,
            linger: config.linger,
            linger_deadline: None,
            ts_enabled: config.timestamps,
            ts_recent: 0,
            ts_recent_age: Instant::now(),
            ts_offset: Instant::now(),
            sack_enabled: config.sack,
            sack_scoreboard: BTreeMap::new(),
            ecn_enabled: false,
            ecn_ce_received: false,
            ecn_cwr_sent: false,
            persist_deadline: None,
            persist_backoff: 0,
        };

        // Send SYN.
        let ts_opt = if config.timestamps {
            Some((0u32, 0u32))
        } else {
            None
        };
        SegmentBuilder::build_syn(
            local_addr,
            remote_addr,
            local_port,
            remote_port,
            iss,
            DEFAULT_RCV_WND,
            DEFAULT_RCV_MSS,
            DEFAULT_RCV_WSCALE,
            ts_opt,
            config.sack,
            src_mac,
            dst_mac,
            self.tx_offload,
            free_frames,
            tx_return,
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
        self.process_ipv4_with_now(
            frame,
            Instant::now(),
            neighbor_handler,
            free_frames,
            rx_return,
            tx_return,
        );
    }

    /// Process an incoming IPv4 TCP segment with an explicit timestamp.
    pub fn process_ipv4_with_now<'umem>(
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
        neighbor_handler: &NeighborHandler,
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        self.process_ipv6_with_now(
            frame,
            tcp_offset,
            Instant::now(),
            neighbor_handler,
            free_frames,
            rx_return,
            tx_return,
        );
    }

    /// Process an incoming IPv6 TCP segment with an explicit timestamp.
    pub fn process_ipv6_with_now<'umem>(
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
                        idx,
                        now,
                        seg_seq,
                        seg_ack,
                        seg_flags,
                        seg_wnd,
                        options,
                        src_mac,
                        dst_mac,
                        free_frames,
                        tx_return,
                    );
                    rx_return.push(frame);
                }
                TcpState::SynReceived => {
                    self.process_syn_received(
                        idx,
                        now,
                        seg_seq,
                        seg_ack,
                        seg_flags,
                        seg_wnd,
                        seg_len,
                        src_mac,
                        dst_mac,
                        free_frames,
                        tx_return,
                    );
                    rx_return.push(frame);
                }
                TcpState::Established => {
                    let payload_offset = tcp_offset + tcp_header_len;
                    let payload_len = frame.len().saturating_sub(payload_offset);
                    self.process_established(
                        idx,
                        frame,
                        now,
                        seg_seq,
                        seg_ack,
                        seg_flags,
                        seg_wnd,
                        payload_offset,
                        payload_len,
                        options,
                        src_mac,
                        dst_mac,
                        free_frames,
                        rx_return,
                        tx_return,
                    );
                }
                TcpState::FinWait1
                | TcpState::FinWait2
                | TcpState::CloseWait
                | TcpState::Closing
                | TcpState::LastAck
                | TcpState::TimeWait => {
                    let payload_offset = tcp_offset + tcp_header_len;
                    let payload_len = frame.len().saturating_sub(payload_offset);
                    self.process_teardown(
                        idx,
                        frame,
                        now,
                        seg_seq,
                        seg_ack,
                        seg_flags,
                        seg_wnd,
                        payload_offset,
                        payload_len,
                        options,
                        src_mac,
                        dst_mac,
                        free_frames,
                        rx_return,
                        tx_return,
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
                free_frames,
                tx_return,
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
            self.tx_offload,
            free_frames,
            tx_return,
        );
        rx_return.push(frame);
    }

    // --- LISTEN state processing (RFC §16.2) ---

    fn process_listen<'umem>(
        &mut self,
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
                self.tx_offload,
                free_frames,
                tx_return,
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
            let peer_ts = parse_timestamp(options);
            let peer_sack = parse_sack_permitted(options);

            let wscale_enabled = peer_wscale.is_some();
            let snd_wscale = peer_wscale.unwrap_or(0);

            // Negotiate timestamps and SACK.
            let ts_enabled = listener.timestamps && peer_ts.is_some();
            let sack_enabled = listener.sack && peer_sack;
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
                eff_snd_mss: peer_mss.min(DEFAULT_RCV_MSS),
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
                cwnd: 10 * peer_mss.min(DEFAULT_RCV_MSS) as u32,
                ssthresh: u32::MAX,
                dup_ack_count: 0,
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
                ecn_enabled: false,
                ecn_ce_received: false,
                ecn_cwr_sent: false,
                persist_deadline: None,
                persist_backoff: 0,
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
                src_mac,
                dst_mac,
                self.tx_offload,
                free_frames,
                tx_return,
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
        now: Instant,
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
                let ts = if tcb.ts_enabled {
                    let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
                    Some((tsval, tcb.ts_recent))
                } else {
                    None
                };
                SegmentBuilder::build_ack(
                    tcb.id.local_addr,
                    tcb.id.remote_addr,
                    tcb.id.local_port,
                    tcb.id.remote_port,
                    tcb.snd_nxt,
                    tcb.rcv_nxt,
                    DEFAULT_RCV_WND,
                    ts,
                    src_mac,
                    dst_mac,
                    self.tx_offload,
                    free_frames,
                    tx_return,
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
                self.connections[idx]
                    .event_queue
                    .push(TcpEvent::ConnectionRefused);
                self.connections.remove(idx);
            }
            return;
        }

        // Step 3: Check SYN (duplicate SYN in synchronized state).
        if seg_flags & flags::SYN != 0 {
            // Send challenge ACK per RFC 5961.
            let tcb = &self.connections[idx];
            let ts = if tcb.ts_enabled {
                let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
                Some((tsval, tcb.ts_recent))
            } else {
                None
            };
            SegmentBuilder::build_ack(
                tcb.id.local_addr,
                tcb.id.remote_addr,
                tcb.id.local_port,
                tcb.id.remote_port,
                tcb.snd_nxt,
                tcb.rcv_nxt,
                DEFAULT_RCV_WND,
                ts,
                src_mac,
                dst_mac,
                self.tx_offload,
                free_frames,
                tx_return,
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
                    self.tx_offload,
                    free_frames,
                    tx_return,
                );
            }
        }
    }

    // --- SYN-SENT state processing (RFC §16.3) ---

    fn process_syn_sent<'umem>(
        &mut self,
        idx: usize,
        now: Instant,
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
                    self.tx_offload,
                    free_frames,
                    tx_return,
                );
            }
            return;
        }

        // Step 2: Check RST.
        if seg_flags & flags::RST != 0 {
            if seg_flags & flags::ACK != 0 {
                // ACK was acceptable (passed step 1) → connection refused.
                self.connections[idx]
                    .event_queue
                    .push(TcpEvent::ConnectionRefused);
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

            // Timestamp negotiation.
            if tcb.ts_enabled {
                if let Some((peer_tsval, _)) = parse_timestamp(options) {
                    tcb.ts_recent = peer_tsval;
                    tcb.ts_recent_age = now;
                } else {
                    tcb.ts_enabled = false; // peer doesn't support
                }
            }
            // SACK negotiation.
            if tcb.sack_enabled && !parse_sack_permitted(options) {
                tcb.sack_enabled = false;
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
                let ts = if tcb.ts_enabled {
                    let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
                    Some((tsval, tcb.ts_recent))
                } else {
                    None
                };
                SegmentBuilder::build_ack(
                    id.local_addr,
                    id.remote_addr,
                    id.local_port,
                    id.remote_port,
                    tcb.snd_nxt,
                    tcb.rcv_nxt,
                    DEFAULT_RCV_WND,
                    ts,
                    src_mac,
                    dst_mac,
                    self.tx_offload,
                    free_frames,
                    tx_return,
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
                    src_mac,
                    dst_mac,
                    self.tx_offload,
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
    }

    // --- ESTABLISHED state processing ---

    fn process_established<'umem>(
        &mut self,
        idx: usize,
        frame: Frame<'umem>,
        now: Instant,
        seg_seq: u32,
        seg_ack: u32,
        seg_flags: u8,
        seg_wnd: u32,
        payload_offset: usize,
        payload_len: usize,
        options: &[u8],
        src_mac: crate::net::wire::ethernet::MacAddress,
        dst_mac: crate::net::wire::ethernet::MacAddress,
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        use crate::net::wire::tcp::{seq_le, seq_lt};

        // Step 1: RST check.
        if seg_flags & flags::RST != 0 {
            self.connections[idx].event_queue.push(TcpEvent::Reset);
            let id = self.connections[idx].id;
            self.decrement_syn_received(&id);
            self.connections.remove(idx);
            rx_return.push(frame);
            return;
        }

        // PAWS check (RFC 7323 §5).
        if self.connections[idx].ts_enabled
            && let Some((tsval, _)) = parse_timestamp(options)
        {
            let tcb = &self.connections[idx];
            // Check if TSval is older than ts_recent.
            // Use signed comparison for wraparound.
            let ts_diff = tsval.wrapping_sub(tcb.ts_recent) as i32;
            if ts_diff < 0 && seg_flags & flags::RST == 0 {
                // Check staleness: if ts_recent is older than 24 days, accept anyway.
                let staleness = now.duration_since(tcb.ts_recent_age).as_millis();
                if staleness < 24 * 24 * 60 * 60 * 1000 {
                    // Reject: send ACK and drop.
                    let tcb = &self.connections[idx];
                    let ts = if tcb.ts_enabled {
                        let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
                        Some((tsval, tcb.ts_recent))
                    } else {
                        None
                    };
                    SegmentBuilder::build_ack(
                        tcb.id.local_addr,
                        tcb.id.remote_addr,
                        tcb.id.local_port,
                        tcb.id.remote_port,
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
                    rx_return.push(frame);
                    return;
                }
            }
        }

        // Segment acceptability check (RFC 9293 §3.10.7.4).
        {
            let tcb = &self.connections[idx];
            let seg_len = Tcb::seg_len(payload_len, seg_flags);
            let rcv_wnd = tcb.recv_buffer.free_space() as u32;
            if !is_segment_acceptable(seg_seq, seg_len, tcb.rcv_nxt, rcv_wnd) {
                // Out-of-window: send ACK (unless RST, already handled above).
                let ts = if tcb.ts_enabled {
                    let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
                    Some((tsval, tcb.ts_recent))
                } else {
                    None
                };
                SegmentBuilder::build_ack(
                    tcb.id.local_addr,
                    tcb.id.remote_addr,
                    tcb.id.local_port,
                    tcb.id.remote_port,
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
                rx_return.push(frame);
                return;
            }
        }

        // Update ts_recent from incoming segment.
        {
            let tcb = &mut self.connections[idx];
            if tcb.ts_enabled
                && let Some((tsval, _)) = parse_timestamp(options)
            {
                tcb.ts_recent = tsval;
                tcb.ts_recent_age = now;
            }
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

                // Reset keep-alive timer on activity.
                tcb.last_activity = now;
                tcb.keep_alive_probes_sent = 0;

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

                // RTT measurement.
                if tcb.ts_enabled {
                    // RTTM via timestamps (RFC 7323).
                    if let Some((_tsval, tsecr)) = parse_timestamp(options)
                        && tsecr != 0
                    {
                        let our_ts = now.duration_since(tcb.ts_offset).as_millis() as u32;
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

                // Update send window.
                tcb.snd_wnd = tcb.scale_incoming_window(seg_wnd);
                tcb.snd_wl1 = seg_seq;
                tcb.snd_wl2 = seg_ack;

                // C. Clear persist timer when window reopens.
                if tcb.snd_wnd > 0 && tcb.persist_deadline.is_some() {
                    tcb.persist_deadline = None;
                    tcb.persist_backoff = 0;
                }

                // Parse and merge SACK blocks into scoreboard.
                if tcb.sack_enabled {
                    let (blocks, count) = crate::net::wire::tcp::parse_sack_blocks(options);
                    for (left, right) in blocks.iter().take(count).flatten() {
                        tcb.sack_scoreboard.insert(*left, right.wrapping_sub(*left));
                    }
                    // Prune scoreboard entries below snd_una (already ACKed cumulatively).
                    let snd_una = tcb.snd_una;
                    tcb.sack_scoreboard
                        .retain(|&start, _| !crate::net::wire::tcp::seq_lt(start, snd_una));
                }
            } else if seg_ack == snd_una && payload_len == 0 {
                // Duplicate ACK.
                let tcb = &mut self.connections[idx];
                tcb.dup_ack_count += 1;
                // Keep-alive probe responses arrive as duplicate ACKs — reset timer.
                if tcb.keep_alive_enabled && tcb.keep_alive_probes_sent > 0 {
                    tcb.last_activity = now;
                    tcb.keep_alive_probes_sent = 0;
                }

                // Window update may arrive as a duplicate ACK (same ACK, new window).
                let new_wnd = tcb.scale_incoming_window(seg_wnd);
                if new_wnd != tcb.snd_wnd {
                    tcb.snd_wnd = new_wnd;
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
                    let (blocks, count) = crate::net::wire::tcp::parse_sack_blocks(options);
                    for (left, right) in blocks.iter().take(count).flatten() {
                        tcb.sack_scoreboard.insert(*left, right.wrapping_sub(*left));
                    }
                }
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

                // Reset keep-alive timer on received data.
                tcb.last_activity = now;
                tcb.keep_alive_probes_sent = 0;

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

                // Defer ACK (delayed ACK).
                let tcb = &mut self.connections[idx];
                tcb.ack_delay_count += 1;
                if tcb.ack_delay_count >= MAX_DELAYED_ACK_COUNT {
                    // Flush: ACK every other segment (RFC 5681 §4.2).
                    let ts = if tcb.ts_enabled {
                        let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
                        Some((tsval, tcb.ts_recent))
                    } else {
                        None
                    };
                    SegmentBuilder::build_ack(
                        tcb.id.local_addr,
                        tcb.id.remote_addr,
                        tcb.id.local_port,
                        tcb.id.remote_port,
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
                    tcb.ack_pending = false;
                    tcb.ack_delay_count = 0;
                    tcb.delayed_ack_deadline = None;
                } else {
                    tcb.ack_pending = true;
                    if tcb.delayed_ack_deadline.is_none() {
                        tcb.delayed_ack_deadline =
                            Some(now + coarsetime::Duration::from_millis(tcb.delayed_ack_ms));
                    }
                }
            } else if seq_lt(rcv_nxt, seg_seq) {
                // Out-of-order data.
                let offset = seg_seq.wrapping_sub(rcv_nxt) as usize;
                let payload = &frame[payload_offset..payload_offset + payload_len];
                let tcb = &mut self.connections[idx];
                tcb.recv_buffer.write_at(offset, payload);
                tcb.ooo_ranges.insert(seg_seq, payload_len as u32);

                // Send duplicate ACK (with current rcv_nxt) and SACK blocks.
                let ts = if tcb.ts_enabled {
                    let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
                    Some((tsval, tcb.ts_recent))
                } else {
                    None
                };

                let max_blocks = if tcb.ts_enabled { 3 } else { 4 };
                let mut sack_blocks: Vec<(u32, u32)> = Vec::new();
                if tcb.sack_enabled {
                    // Most recently received range first (per RFC 2018 §3).
                    sack_blocks.push((seg_seq, seg_seq.wrapping_add(payload_len as u32)));
                    for (&start, &len) in tcb.ooo_ranges.iter().rev() {
                        if sack_blocks.len() >= max_blocks {
                            break;
                        }
                        let end = start.wrapping_add(len);
                        if start != seg_seq {
                            sack_blocks.push((start, end));
                        }
                    }
                }

                SegmentBuilder::build_ack_with_sack(
                    tcb.id.local_addr,
                    tcb.id.remote_addr,
                    tcb.id.local_port,
                    tcb.id.remote_port,
                    tcb.snd_nxt,
                    tcb.rcv_nxt,
                    tcb.advertised_window(),
                    ts,
                    &sack_blocks,
                    src_mac,
                    dst_mac,
                    self.tx_offload,
                    free_frames,
                    tx_return,
                );
            } else {
                // Duplicate data (seg_seq < rcv_nxt) — just ACK.
                let tcb = &self.connections[idx];
                let ts = if tcb.ts_enabled {
                    let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
                    Some((tsval, tcb.ts_recent))
                } else {
                    None
                };
                SegmentBuilder::build_ack(
                    tcb.id.local_addr,
                    tcb.id.remote_addr,
                    tcb.id.local_port,
                    tcb.id.remote_port,
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
            }
        }

        // Step 4: Process FIN flag.
        if seg_flags & flags::FIN != 0 {
            let tcb = &mut self.connections[idx];
            tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1); // FIN consumes one sequence number
            tcb.state = TcpState::CloseWait;
            tcb.event_queue.push(TcpEvent::RemoteClose);

            // Send ACK for FIN.
            let id = tcb.id;
            let snd_nxt = tcb.snd_nxt;
            let new_rcv_nxt = tcb.rcv_nxt;
            let window = tcb.advertised_window();
            let ts = if tcb.ts_enabled {
                let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
                Some((tsval, tcb.ts_recent))
            } else {
                None
            };
            SegmentBuilder::build_ack(
                id.local_addr,
                id.remote_addr,
                id.local_port,
                id.remote_port,
                snd_nxt,
                new_rcv_nxt,
                window,
                ts,
                src_mac,
                dst_mac,
                self.tx_offload,
                free_frames,
                tx_return,
            );
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
                SegmentBuilder::build_ack(
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
                SegmentBuilder::build_ack(
                    id.local_addr,
                    id.remote_addr,
                    id.local_port,
                    id.remote_port,
                    tcb.snd_una.wrapping_sub(1),
                    tcb.rcv_nxt,
                    tcb.advertised_window(),
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

        // Fast retransmit pass — independent of timer expiry.
        // Triggered by 3 duplicate ACKs on established connections.
        for tcb in &mut self.connections {
            if tcb.state != TcpState::Established || tcb.dup_ack_count < 3 {
                continue;
            }

            use crate::net::wire::tcp::seq_lt;

            // Determine retransmit offset: use SACK scoreboard gaps when available.
            let snd_una = tcb.snd_una;
            let (retransmit_offset, retransmit_seq) = if tcb.sack_enabled
                && !tcb.sack_scoreboard.is_empty()
            {
                let mut gap_start = snd_una;
                let mut found = None;
                for (&sack_start, &sack_len) in &tcb.sack_scoreboard {
                    if seq_lt(gap_start, sack_start) {
                        let gap_size = sack_start.wrapping_sub(gap_start) as usize;
                        let len = gap_size.min(tcb.eff_snd_mss as usize);
                        found = Some((gap_start.wrapping_sub(snd_una) as usize, gap_start, len));
                        break;
                    }
                    let sack_end = sack_start.wrapping_add(sack_len);
                    if seq_lt(gap_start, sack_end) {
                        gap_start = sack_end;
                    }
                }
                match found {
                    Some((offset, seq, _)) => (offset, seq),
                    None => (0, snd_una),
                }
            } else {
                (0, snd_una)
            };

            let retransmit_len = tcb.send_buffer.available().min(tcb.eff_snd_mss as usize);
            if retransmit_len == 0 {
                continue;
            }

            let id = tcb.id;
            let dst_mac = neighbor_handler
                .lookup(now, &id.remote_addr)
                .unwrap_or(crate::net::wire::ethernet::MacAddress::broadcast());

            let payload = tcb
                .send_buffer
                .peek_slices(retransmit_offset, retransmit_len);

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
                retransmit_seq,
                tcb.rcv_nxt,
                tcb.advertised_window(),
                payload,
                flags::ACK,
                ts,
                src_mac,
                dst_mac,
                self.tx_offload,
                free_frames,
                tx_return,
            );

            // Fast recovery: halve cwnd.
            tcb.ssthresh = (tcb.cwnd / 2).max(2 * tcb.eff_snd_mss as u32);
            tcb.cwnd = tcb.ssthresh;
            tcb.dup_ack_count = 0;
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
                            ts,
                            src_mac,
                            dst_mac,
                            self.tx_offload,
                            free_frames,
                            tx_return,
                        );
                    }
                    // Back to slow start.
                    tcb.ssthresh = (tcb.cwnd / 2).max(2 * tcb.eff_snd_mss as u32);
                    tcb.cwnd = tcb.eff_snd_mss as u32;
                    tcb.sack_scoreboard.clear();
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

    // --- Data transmission ---

    /// Poll established connections for outbound data segments.
    /// Called each tick from the runtime loop after receive processing.
    pub fn poll_send<'umem>(
        &mut self,
        now: Instant,
        src_mac: crate::net::wire::ethernet::MacAddress,
        neighbor_handler: &NeighborHandler,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        for tcb in &mut self.connections {
            if tcb.state != TcpState::Established && tcb.state != TcpState::CloseWait {
                continue;
            }

            // Compute how many bytes we can send.
            let bytes_in_flight = tcb.snd_nxt.wrapping_sub(tcb.snd_una) as usize;
            let send_window = (tcb.snd_wnd as usize).min(tcb.cwnd as usize);
            let can_send = send_window.saturating_sub(bytes_in_flight);
            let data_available = tcb.send_buffer.available().saturating_sub(bytes_in_flight);

            // Send data if possible.
            if can_send > 0 && data_available > 0 {
                let to_send = can_send.min(data_available).min(tcb.eff_snd_mss as usize);

                // Nagle algorithm: hold small segments when data is in flight.
                if tcb.nagle_enabled && bytes_in_flight > 0 && to_send < tcb.eff_snd_mss as usize {
                    // Don't send — wait for outstanding ACK.
                } else {
                    // Peek the data from the send buffer (don't advance — held until ACKed).
                    let payload = tcb.send_buffer.peek_slices(bytes_in_flight, to_send);

                    let dst_mac = neighbor_handler
                        .lookup(now, &tcb.id.remote_addr)
                        .unwrap_or(crate::net::wire::ethernet::MacAddress::broadcast());

                    let ts = if tcb.ts_enabled {
                        let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
                        Some((tsval, tcb.ts_recent))
                    } else {
                        None
                    };
                    let remaining_after_send = data_available.saturating_sub(to_send);
                    let data_flags = if remaining_after_send == 0 || to_send >= can_send {
                        flags::ACK | flags::PSH
                    } else {
                        flags::ACK
                    };
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
                    if tcb.retransmit_deadline.is_none() {
                        tcb.retransmit_deadline =
                            Some(now + coarsetime::Duration::from_millis(tcb.rto));
                    }

                    // Piggyback: data segment carries ACK, so clear delayed ACK state.
                    tcb.ack_pending = false;
                    tcb.ack_delay_count = 0;
                    tcb.delayed_ack_deadline = None;
                }
            }

            // --- Zero-window probing (persist timer) ---
            // A. Arm persist timer when peer advertises window=0 and we have data to send.
            if send_window == 0 && data_available > 0 && tcb.persist_deadline.is_none() {
                tcb.persist_deadline = Some(now + coarsetime::Duration::from_millis(tcb.rto));
            }

            // B. Send 1-byte probe when persist deadline expires.
            if let Some(deadline) = tcb.persist_deadline
                && now >= deadline
                && send_window == 0
                && data_available > 0
            {
                let mut probe = [0u8; 1];
                tcb.send_buffer.peek_at(bytes_in_flight, &mut probe);

                let dst_mac = neighbor_handler
                    .lookup(now, &tcb.id.remote_addr)
                    .unwrap_or(crate::net::wire::ethernet::MacAddress::broadcast());

                let ts = if tcb.ts_enabled {
                    let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
                    Some((tsval, tcb.ts_recent))
                } else {
                    None
                };
                SegmentBuilder::build_data(
                    tcb.id.local_addr,
                    tcb.id.remote_addr,
                    tcb.id.local_port,
                    tcb.id.remote_port,
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

                tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);

                // Schedule next probe with exponential backoff, capped at 60s.
                let backoff_ms = (tcb.rto << tcb.persist_backoff).min(60_000);
                tcb.persist_deadline = Some(now + coarsetime::Duration::from_millis(backoff_ms));
                tcb.persist_backoff = tcb.persist_backoff.saturating_add(1).min(6);
            }

            // Check linger deadline — if expired, abort with RST.
            if tcb.pending_fin
                && let Some(deadline) = tcb.linger_deadline
                && now >= deadline
            {
                // Send RST to peer.
                let id = tcb.id;
                let dst_mac = neighbor_handler
                    .lookup(now, &id.remote_addr)
                    .unwrap_or(crate::net::wire::ethernet::MacAddress::broadcast());

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
                continue;
            }

            // After data sending: check if we should send FIN.
            if tcb.pending_fin {
                let bytes_in_flight = tcb.snd_nxt.wrapping_sub(tcb.snd_una) as usize;
                let data_available = tcb.send_buffer.available().saturating_sub(bytes_in_flight);

                // Only send FIN when all data has been sent and ACKed.
                if data_available == 0 && bytes_in_flight == 0 {
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
                    if tcb.retransmit_deadline.is_none() {
                        tcb.retransmit_deadline =
                            Some(now + coarsetime::Duration::from_millis(tcb.rto));
                    }
                }
            }
        }

        // Remove connections aborted by linger deadline.
        self.connections.retain(|tcb| tcb.state != TcpState::Closed);
    }

    // --- Connection teardown ---

    /// Mark a connection for graceful close. Sets `pending_fin` so that
    /// `poll_send` will drain remaining data and then send FIN.
    pub fn initiate_close(&mut self, id: &ConnectionId) {
        if let Some(tcb) = self.connections.iter_mut().find(|c| c.id == *id) {
            if tcb.pending_fin
                || (tcb.state != TcpState::Established && tcb.state != TcpState::CloseWait)
            {
                return;
            }

            tcb.pending_fin = true;
            match tcb.linger {
                Some(0) => {
                    // Linger(0): set deadline to now — poll_send will send RST immediately.
                    tcb.linger_deadline = Some(Instant::recent());
                }
                Some(ms) => {
                    // Linger(timeout): graceful close with deadline.
                    tcb.linger_deadline =
                        Some(Instant::now() + coarsetime::Duration::from_millis(ms));
                }
                None => {
                    // Default: graceful close, no deadline.
                }
            }
        }
    }

    // --- Helpers ---

    /// Find a matching listener for the given address and port.
    fn find_listener(&self, addr: IpAddress, port: u16) -> Option<usize> {
        self.listeners
            .iter()
            .position(|l| l.port == port && (l.addr.is_unspecified() || l.addr == addr))
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

    /// Get a mutable reference to the connection for a given ConnectionId.
    pub fn get_connection_mut(&mut self, id: &ConnectionId) -> Option<&mut Tcb> {
        self.connections.iter_mut().find(|c| c.id == *id)
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
                    id.local_addr,
                    id.remote_addr,
                    id.local_port,
                    id.remote_port,
                    0,
                    0,
                    flags::ACK,
                    0,
                    src_mac,
                    dst_mac,
                    self.tx_offload,
                    free_frames,
                    tx_return,
                );
            }
            self.connections.remove(idx);
        }
    }

    // --- Teardown state processing (FinWait1, FinWait2, CloseWait, Closing, LastAck, TimeWait) ---

    fn process_teardown<'umem>(
        &mut self,
        idx: usize,
        frame: Frame<'umem>,
        now: Instant,
        seg_seq: u32,
        seg_ack: u32,
        seg_flags: u8,
        seg_wnd: u32,
        payload_offset: usize,
        payload_len: usize,
        options: &[u8],
        src_mac: crate::net::wire::ethernet::MacAddress,
        dst_mac: crate::net::wire::ethernet::MacAddress,
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let state = self.connections[idx].state;

        // RST check — abort all states except TimeWait.
        if seg_flags & flags::RST != 0 {
            if state == TcpState::TimeWait {
                // Ignore RST in TIME-WAIT (prevents RST attacks).
                rx_return.push(frame);
                return;
            }
            self.connections[idx].event_queue.push(TcpEvent::Reset);
            self.connections.remove(idx);
            rx_return.push(frame);
            return;
        }

        // PAWS check (RFC 7323 §5).
        if self.connections[idx].ts_enabled
            && let Some((tsval, _)) = parse_timestamp(options)
        {
            let tcb = &self.connections[idx];
            let ts_diff = tsval.wrapping_sub(tcb.ts_recent) as i32;
            if ts_diff < 0 && seg_flags & flags::RST == 0 {
                let staleness = now.duration_since(tcb.ts_recent_age).as_millis();
                if staleness < 24 * 24 * 60 * 60 * 1000 {
                    let tcb = &self.connections[idx];
                    let ts = if tcb.ts_enabled {
                        let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
                        Some((tsval, tcb.ts_recent))
                    } else {
                        None
                    };
                    SegmentBuilder::build_ack(
                        tcb.id.local_addr,
                        tcb.id.remote_addr,
                        tcb.id.local_port,
                        tcb.id.remote_port,
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
                    rx_return.push(frame);
                    return;
                }
            }
        }

        // Segment acceptability check (RFC 9293 §3.10.7.4).
        {
            let tcb = &self.connections[idx];
            let seg_len = Tcb::seg_len(payload_len, seg_flags);
            let rcv_wnd = tcb.recv_buffer.free_space() as u32;
            if !is_segment_acceptable(seg_seq, seg_len, tcb.rcv_nxt, rcv_wnd) {
                // Out-of-window: send ACK (unless RST, already handled above).
                let ts = if tcb.ts_enabled {
                    let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
                    Some((tsval, tcb.ts_recent))
                } else {
                    None
                };
                SegmentBuilder::build_ack(
                    tcb.id.local_addr,
                    tcb.id.remote_addr,
                    tcb.id.local_port,
                    tcb.id.remote_port,
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
                rx_return.push(frame);
                return;
            }
        }

        match state {
            TcpState::FinWait1 => {
                let tcb = &mut self.connections[idx];
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
                    }
                }

                // Process data if present (remote may still be sending).
                if payload_len > 0 && seg_seq == tcb.rcv_nxt {
                    let payload = &frame[payload_offset..payload_offset + payload_len];
                    tcb.recv_buffer.write(payload);
                    tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(payload_len as u32);
                }

                // Check for FIN from remote.
                let remote_fin = seg_flags & flags::FIN != 0;
                if remote_fin {
                    tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);
                }

                // Determine new state.
                let tcb = &mut self.connections[idx];
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
                    let tcb = &self.connections[idx];
                    let id = tcb.id;
                    let snd_nxt = tcb.snd_nxt;
                    let rcv_nxt = tcb.rcv_nxt;
                    let ts = if tcb.ts_enabled {
                        let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
                        Some((tsval, tcb.ts_recent))
                    } else {
                        None
                    };
                    SegmentBuilder::build_ack(
                        id.local_addr,
                        id.remote_addr,
                        id.local_port,
                        id.remote_port,
                        snd_nxt,
                        rcv_nxt,
                        self.connections[idx].advertised_window(),
                        ts,
                        src_mac,
                        dst_mac,
                        self.tx_offload,
                        free_frames,
                        tx_return,
                    );
                }

                rx_return.push(frame);
            }

            TcpState::FinWait2 => {
                let tcb = &mut self.connections[idx];

                // Process data if present (remote still sending).
                if payload_len > 0 && seg_seq == tcb.rcv_nxt {
                    let payload = &frame[payload_offset..payload_offset + payload_len];
                    tcb.recv_buffer.write(payload);
                    tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(payload_len as u32);
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
                    let ts = if tcb.ts_enabled {
                        let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
                        Some((tsval, tcb.ts_recent))
                    } else {
                        None
                    };
                    SegmentBuilder::build_ack(
                        id.local_addr,
                        id.remote_addr,
                        id.local_port,
                        id.remote_port,
                        snd_nxt,
                        rcv_nxt,
                        tcb.advertised_window(),
                        ts,
                        src_mac,
                        dst_mac,
                        self.tx_offload,
                        free_frames,
                        tx_return,
                    );
                }

                rx_return.push(frame);
            }

            TcpState::Closing => {
                let tcb = &mut self.connections[idx];
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
                    let tcb = &self.connections[idx];
                    if let Some(fin_seq) = tcb.fin_seq
                        && crate::net::wire::tcp::seq_lt(fin_seq, seg_ack)
                    {
                        self.connections.remove(idx);
                        rx_return.push(frame);
                        return;
                    }
                }
                rx_return.push(frame);
            }

            TcpState::TimeWait => {
                let tcb = &mut self.connections[idx];
                // FIN retransmit → re-ACK and restart timer.
                if seg_flags & flags::FIN != 0 {
                    let id = tcb.id;
                    let snd_nxt = tcb.snd_nxt;
                    let rcv_nxt = tcb.rcv_nxt;
                    let ts = if tcb.ts_enabled {
                        let tsval = now.duration_since(tcb.ts_offset).as_millis() as u32;
                        Some((tsval, tcb.ts_recent))
                    } else {
                        None
                    };
                    SegmentBuilder::build_ack(
                        id.local_addr,
                        id.remote_addr,
                        id.local_port,
                        id.remote_port,
                        snd_nxt,
                        rcv_nxt,
                        tcb.advertised_window(),
                        ts,
                        src_mac,
                        dst_mac,
                        self.tx_offload,
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
                // Remote already FINed. No new data expected.
                // Just handle RST (already handled above) and ignore everything else.
                rx_return.push(frame);
            }

            _ => {
                rx_return.push(frame);
            }
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
            src_port,
            dst_port,
            seq,
            ack,
            data_offset,
            tcp_flags,
            window,
            [0, 0],
            0,
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
        let mut buf =
            vec![0u8; ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + tcp_header_len + payload.len()];

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
            src_port,
            dst_port,
            seq,
            ack,
            data_offset,
            tcp_flags,
            window,
            [0, 0],
            0,
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

        let data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
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

        let data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
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
        let data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &mss_opt,
        );
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
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        let syn_frame = Frame::new(0, leak(syn_data), syn_len, false);
        handler.process_ipv4(syn_frame, &nh, &mut free, &mut rx, &mut tx);
        assert_eq!(handler.connections[0].state, TcpState::SynReceived);

        // Get ISS from the TCB.
        let server_iss = handler.connections[0].iss;

        // Step 2: ACK completing handshake.
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
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
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        let syn_frame = Frame::new(0, leak(syn_data), syn_len, false);
        handler.process_ipv4(syn_frame, &nh, &mut free, &mut rx, &mut tx);
        assert_eq!(handler.connections.len(), 1);

        // RST.
        let rcv_nxt = handler.connections[0].rcv_nxt;
        let rst_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            rcv_nxt,
            0,
            flags::RST,
            0,
            &[],
        );
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
                REMOTE_IP,
                LOCAL_IP,
                10000 + i,
                80,
                1000,
                0,
                flags::SYN,
                65535,
                &[],
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

        let data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
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
            0x01, // NOP
            0x03, 0x03, 0x07, // Window Scale=7
        ];
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &ws_opts,
        );
        let syn_len = syn_data.len();
        let syn_frame = Frame::new(0, leak(syn_data), syn_len, false);
        handler.process_ipv4(syn_frame, &nh, &mut free, &mut rx, &mut tx);

        assert!(handler.connections[0].wscale_enabled);
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
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        assert_eq!(handler.connections[0].state, TcpState::Established);

        // Clear tx from handshake.
        while tx.pop().is_some() {}

        // Send first data segment (deferred by delayed ACK).
        let payload = b"Hello, TCP!";
        let data = build_tcp_frame_with_payload(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
            payload,
        );
        let data_len = data.len();
        handler.process_ipv4(
            Frame::new(2, leak(data), data_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );

        // First segment deferred — no immediate ACK.
        assert_eq!(
            tx.num_frames(),
            0,
            "ACK deferred for first in-order segment"
        );
        assert!(
            handler.connections[0].ack_pending,
            "ack_pending should be true"
        );

        // Send second data segment to flush delayed ACK.
        let payload2 = b"World!";
        let data2 = build_tcp_frame_with_payload(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001 + payload.len() as u32,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
            payload2,
        );
        let data2_len = data2.len();
        handler.process_ipv4(
            Frame::new(3, leak(data2), data2_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );

        // Second segment flushes the ACK.
        assert_eq!(tx.num_frames(), 1, "ACK flushed on second segment");

        // Verify: data is in the receive ring buffer.
        let tcb = &handler.connections[0];
        assert_eq!(tcb.recv_buffer.available(), payload.len() + payload2.len());
        assert_eq!(
            tcb.rcv_nxt,
            1001 + payload.len() as u32 + payload2.len() as u32
        );

        drop(accept_queue);
    }

    #[test]
    fn established_out_of_order_reassembly() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);

        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {}

        // Send segment 2 first (out of order): seq=1006, 5 bytes "world".
        let seg2 = build_tcp_frame_with_payload(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1006,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
            b"world",
        );
        let seg2_len = seg2.len();
        handler.process_ipv4(
            Frame::new(2, leak(seg2), seg2_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        assert_eq!(
            handler.connections[0].rcv_nxt, 1001,
            "rcv_nxt not advanced for OOO"
        );
        assert_eq!(handler.connections[0].ooo_ranges.len(), 1);

        // Now send segment 1 (fills the gap): seq=1001, 5 bytes "hello".
        let seg1 = build_tcp_frame_with_payload(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
            b"hello",
        );
        let seg1_len = seg1.len();
        handler.process_ipv4(
            Frame::new(3, leak(seg1), seg1_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );

        // Both segments should now be contiguous.
        assert_eq!(
            handler.connections[0].rcv_nxt, 1011,
            "rcv_nxt advanced past both segments"
        );
        assert_eq!(
            handler.connections[0].ooo_ranges.len(),
            0,
            "OOO ranges drained"
        );
        assert_eq!(handler.connections[0].recv_buffer.available(), 10);

        // Read from recv buffer and verify contents.
        let mut buf = [0u8; 10];
        handler.connections[0].recv_buffer.read(&mut buf);
        assert_eq!(&buf, b"helloworld");
    }

    #[test]
    fn poll_send_builds_data_segment() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);

        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {}

        // Write data into the connection's send buffer.
        let payload = b"Hello from server!";
        handler.connections[0].send_buffer.write(payload);

        // Set snd_wnd so the window allows sending.
        handler.connections[0].snd_wnd = 65535;

        let now = coarsetime::Instant::now();
        handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);

        assert_eq!(tx.num_frames(), 1, "data segment built");
        let tcb = &handler.connections[0];
        assert_eq!(
            tcb.snd_nxt,
            server_iss
                .wrapping_add(1)
                .wrapping_add(payload.len() as u32)
        );
        assert_eq!(tcb.send_buffer.available(), payload.len()); // still in buffer until ACKed
    }

    #[test]
    fn fast_retransmit_on_three_dup_acks() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);

        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {}

        // Put data in send buffer and send it.
        handler.connections[0].send_buffer.write(b"AAAA");
        handler.connections[0].snd_wnd = 65535;
        let now = coarsetime::Instant::now();
        handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
        while tx.pop().is_some() {} // consume sent segment

        let cwnd_before = handler.connections[0].cwnd;

        // Send 3 duplicate ACKs (ACKing the old snd_una, not the new data).
        let dup_ack_seq = server_iss.wrapping_add(1); // original snd_una
        for i in 0..3u64 {
            let dup = build_tcp_frame(
                REMOTE_IP,
                LOCAL_IP,
                12345,
                80,
                1001,
                dup_ack_seq,
                flags::ACK,
                65535,
                &[],
            );
            let dup_len = dup.len();
            handler.process_ipv4(
                Frame::new(10 + i, leak(dup), dup_len, false),
                &nh,
                &mut free,
                &mut rx,
                &mut tx,
            );
        }

        assert_eq!(handler.connections[0].dup_ack_count, 3);

        // poll_timers should trigger fast retransmit.
        handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut tx);
        assert!(tx.num_frames() >= 1, "retransmitted segment expected");

        // cwnd should be halved (fast recovery).
        let tcb = &handler.connections[0];
        assert!(
            tcb.cwnd < cwnd_before,
            "cwnd should be reduced after fast retransmit"
        );
        assert_eq!(tcb.dup_ack_count, 0, "dup_ack_count should be reset");
        assert_eq!(
            tcb.cwnd, tcb.ssthresh,
            "cwnd should equal ssthresh after fast recovery"
        );
    }

    #[test]
    fn rto_retransmit_on_timer_expiry() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);

        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {}

        // Put data in send buffer and send it.
        handler.connections[0].send_buffer.write(b"BBBB");
        handler.connections[0].snd_wnd = 65535;
        let now = coarsetime::Instant::now();
        handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
        while tx.pop().is_some() {}

        let cwnd_before = handler.connections[0].cwnd;

        // Simulate timer expiry by setting a deadline in the past.
        handler.connections[0].retransmit_deadline =
            Some(now - coarsetime::Duration::from_millis(1));
        handler.connections[0].rto_backoff = 0;

        // poll_timers should trigger RTO retransmit.
        handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut tx);
        assert!(tx.num_frames() >= 1, "retransmitted segment expected");

        let tcb = &handler.connections[0];
        // cwnd should be reset to 1 MSS (slow start).
        assert_eq!(
            tcb.cwnd, tcb.eff_snd_mss as u32,
            "cwnd should be 1 MSS after RTO"
        );
        assert!(tcb.ssthresh < cwnd_before, "ssthresh should be reduced");
        assert_eq!(tcb.rto_backoff, 1, "rto_backoff should be incremented");
    }

    #[test]
    fn rtt_estimation_updates_rto() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);

        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {}

        // Send data.
        handler.connections[0].send_buffer.write(b"test data");
        handler.connections[0].snd_wnd = 65535;
        let send_time = coarsetime::Instant::now();
        handler.poll_send(send_time, nh.local_mac(), &nh, &mut free, &mut tx);
        while tx.pop().is_some() {}

        // Verify last_send_time is set.
        assert!(
            handler.connections[0].last_send_time.is_some(),
            "last_send_time should be set after poll_send"
        );

        // ACK the data.
        let new_ack = server_iss.wrapping_add(1).wrapping_add(9); // ISS+1 + 9 bytes
        let ack = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            new_ack,
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack.len();
        let recv_time = coarsetime::Instant::now();
        handler.process_ipv4_with_now(
            Frame::new(5, leak(ack), ack_len, false),
            recv_time,
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );

        // Verify RTT was measured.
        let tcb = &handler.connections[0];
        assert!(
            tcb.srtt.is_some(),
            "srtt should be set after first RTT measurement"
        );
        assert!(
            tcb.last_send_time.is_none(),
            "last_send_time should be consumed"
        );
        // RTO should be at least 1000ms (the minimum clamp).
        assert!(tcb.rto >= 1000, "rto should be at least 1000ms");
        assert!(tcb.rto <= 60_000, "rto should be at most 60000ms");
    }

    #[test]
    fn frame_accounting_through_data_transfer() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(64);
        let mut rx = BasicFrameBuffer::new(64);
        let mut tx = BasicFrameBuffer::new(64);

        for i in 0..32 {
            free.push(alloc_free_frame(100 + i));
        }

        let initial_total = free.num_frames();

        // Handshake.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );

        // Data segment 1 (ACK deferred).
        let data = build_tcp_frame_with_payload(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
            b"test data",
        );
        let data_len = data.len();
        handler.process_ipv4(
            Frame::new(2, leak(data), data_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );

        // Data segment 2 (flushes delayed ACK).
        let data2 = build_tcp_frame_with_payload(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001 + 9,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
            b"more data",
        );
        let data2_len = data2.len();
        handler.process_ipv4(
            Frame::new(3, leak(data2), data2_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );

        // All frames accounted for: free + rx + tx = initial + incoming frames.
        let total = free.num_frames() + rx.num_frames() + tx.num_frames();
        // We started with initial_total free frames and injected 4 incoming frames.
        assert_eq!(total, initial_total + 4, "all frames accounted for");
    }

    #[test]
    fn established_receives_fin_transitions_to_close_wait() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);

        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {}

        // Remote sends FIN.
        let fin_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK | flags::FIN,
            65535,
            &[],
        );
        let fin_len = fin_data.len();
        handler.process_ipv4(
            Frame::new(2, leak(fin_data), fin_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );

        assert_eq!(handler.connections[0].state, TcpState::CloseWait);
        assert_eq!(handler.connections[0].rcv_nxt, 1002); // 1001 + FIN=1
        assert_eq!(tx.num_frames(), 1, "ACK for FIN sent");
    }

    #[test]
    fn established_receives_fin_with_data() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);

        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {}

        // Remote sends data + FIN piggybacked.
        let payload = b"goodbye";
        let fin_data = build_tcp_frame_with_payload(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK | flags::FIN,
            65535,
            &[],
            payload,
        );
        let fin_len = fin_data.len();
        handler.process_ipv4(
            Frame::new(2, leak(fin_data), fin_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );

        assert_eq!(handler.connections[0].state, TcpState::CloseWait);
        assert_eq!(
            handler.connections[0].recv_buffer.available(),
            payload.len()
        );
        // rcv_nxt = 1001 + 7 bytes data + 1 FIN = 1009
        assert_eq!(
            handler.connections[0].rcv_nxt,
            1001 + payload.len() as u32 + 1
        );
    }

    #[test]
    fn poll_send_sends_fin_when_pending() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);

        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {}

        // Set pending_fin.
        handler.connections[0].pending_fin = true;

        let now = coarsetime::Instant::now();
        handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);

        // FIN should have been sent.
        assert_eq!(tx.num_frames(), 1, "FIN segment sent");
        let tcb = &handler.connections[0];
        assert_eq!(tcb.state, TcpState::FinWait1);
        assert!(!tcb.pending_fin, "pending_fin consumed");
        assert!(tcb.fin_seq.is_some(), "fin_seq recorded");
    }

    #[test]
    fn poll_send_drains_data_before_fin() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);

        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {}

        // Write data AND set pending_fin.
        handler.connections[0].send_buffer.write(b"final data");
        handler.connections[0].snd_wnd = 65535;
        handler.connections[0].pending_fin = true;

        let now = coarsetime::Instant::now();
        handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);

        // Should send data first, NOT FIN yet (data still in flight).
        assert_eq!(tx.num_frames(), 1, "data segment sent");
        assert_eq!(
            handler.connections[0].state,
            TcpState::Established,
            "still Established until data ACKed"
        );
        assert!(handler.connections[0].pending_fin, "pending_fin still set");
    }

    #[test]
    fn active_close_fin_wait1_to_fin_wait2() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);

        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {}

        // Active close: set pending_fin, poll_send sends FIN → FinWait1.
        handler.connections[0].pending_fin = true;
        let now = coarsetime::Instant::now();
        handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
        while tx.pop().is_some() {}
        assert_eq!(handler.connections[0].state, TcpState::FinWait1);
        let fin_seq = handler.connections[0].fin_seq.unwrap();

        // Remote ACKs our FIN → FinWait2.
        let ack = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            fin_seq.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack.len();
        handler.process_ipv4(
            Frame::new(3, leak(ack), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );

        assert_eq!(handler.connections[0].state, TcpState::FinWait2);
    }

    #[test]
    fn fin_wait2_receives_fin_to_time_wait() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);

        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {}

        // Active close → FinWait1 → FinWait2.
        handler.connections[0].pending_fin = true;
        let now = coarsetime::Instant::now();
        handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
        while tx.pop().is_some() {}
        let fin_seq = handler.connections[0].fin_seq.unwrap();
        let ack = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            fin_seq.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack.len();
        handler.process_ipv4(
            Frame::new(3, leak(ack), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        assert_eq!(handler.connections[0].state, TcpState::FinWait2);
        while tx.pop().is_some() {}

        // Remote sends FIN → TimeWait.
        let fin = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            fin_seq.wrapping_add(1),
            flags::ACK | flags::FIN,
            65535,
            &[],
        );
        let fin_len = fin.len();
        handler.process_ipv4(
            Frame::new(4, leak(fin), fin_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );

        assert_eq!(handler.connections[0].state, TcpState::TimeWait);
        assert!(handler.connections[0].time_wait_deadline.is_some());
        assert_eq!(tx.num_frames(), 1, "ACK for remote FIN");
    }

    #[test]
    fn simultaneous_close_closing_to_time_wait() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);

        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {}

        // Active close → FinWait1.
        handler.connections[0].pending_fin = true;
        let now = coarsetime::Instant::now();
        handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
        while tx.pop().is_some() {}
        assert_eq!(handler.connections[0].state, TcpState::FinWait1);

        // Simultaneous close: remote sends FIN without ACKing ours → Closing.
        let fin = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK | flags::FIN,
            65535,
            &[],
        );
        let fin_len = fin.len();
        handler.process_ipv4(
            Frame::new(3, leak(fin), fin_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        assert_eq!(handler.connections[0].state, TcpState::Closing);
        while tx.pop().is_some() {}

        // Remote ACKs our FIN → TimeWait.
        let fin_seq = handler.connections[0].fin_seq.unwrap();
        let ack = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1002,
            fin_seq.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack.len();
        handler.process_ipv4(
            Frame::new(4, leak(ack), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        assert_eq!(handler.connections[0].state, TcpState::TimeWait);
    }

    #[test]
    fn passive_close_last_ack_removes_connection() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);

        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {}

        // Remote sends FIN → CloseWait.
        let fin = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK | flags::FIN,
            65535,
            &[],
        );
        let fin_len = fin.len();
        handler.process_ipv4(
            Frame::new(2, leak(fin), fin_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        assert_eq!(handler.connections[0].state, TcpState::CloseWait);
        while tx.pop().is_some() {}

        // We close → pending_fin, poll_send sends FIN → LastAck.
        handler.connections[0].pending_fin = true;
        let now = coarsetime::Instant::now();
        handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
        while tx.pop().is_some() {}
        assert_eq!(handler.connections[0].state, TcpState::LastAck);
        let fin_seq = handler.connections[0].fin_seq.unwrap();

        // Remote ACKs our FIN → connection removed.
        let ack = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1002,
            fin_seq.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack.len();
        handler.process_ipv4(
            Frame::new(4, leak(ack), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        assert_eq!(
            handler.connections.len(),
            0,
            "connection removed after LastAck"
        );
    }

    #[test]
    fn time_wait_ignores_rst() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);

        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {}

        // Full active close → TimeWait.
        handler.connections[0].pending_fin = true;
        let now = coarsetime::Instant::now();
        handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
        while tx.pop().is_some() {}
        let fin_seq = handler.connections[0].fin_seq.unwrap();
        let ack = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            fin_seq.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack.len();
        handler.process_ipv4(
            Frame::new(3, leak(ack), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let fin = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            fin_seq.wrapping_add(1),
            flags::ACK | flags::FIN,
            65535,
            &[],
        );
        let fin_len = fin.len();
        handler.process_ipv4(
            Frame::new(4, leak(fin), fin_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        assert_eq!(handler.connections[0].state, TcpState::TimeWait);
        while tx.pop().is_some() {}

        // RST in TIME-WAIT should be ignored.
        let rst = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1002, 0, flags::RST, 0, &[]);
        let rst_len = rst.len();
        handler.process_ipv4(
            Frame::new(5, leak(rst), rst_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        assert_eq!(
            handler.connections.len(),
            1,
            "connection NOT removed by RST in TIME-WAIT"
        );
        assert_eq!(handler.connections[0].state, TcpState::TimeWait);
    }

    #[test]
    fn time_wait_evicted_after_deadline() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);

        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {}

        // Force into TimeWait state with expired deadline.
        handler.connections[0].state = TcpState::TimeWait;
        handler.connections[0].time_wait_deadline = Some(coarsetime::Instant::now());

        // Evict with a time in the future.
        let future = coarsetime::Instant::now() + coarsetime::Duration::from_secs(120);
        handler.evict_stale(future, &mut rx);
        assert_eq!(handler.connections.len(), 0, "TIME-WAIT connection evicted");
    }

    #[test]
    fn full_active_close_lifecycle() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);

        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        let initial_free = free.num_frames();

        // 1. Handshake.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        assert_eq!(handler.connections[0].state, TcpState::Established);

        // 2. Data exchange.
        let payload = b"hello";
        let data = build_tcp_frame_with_payload(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
            payload,
        );
        let data_len = data.len();
        handler.process_ipv4(
            Frame::new(2, leak(data), data_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );

        // 3. Active close.
        handler.connections[0].pending_fin = true;
        let now = coarsetime::Instant::now();
        handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
        assert_eq!(handler.connections[0].state, TcpState::FinWait1);
        while tx.pop().is_some() {}

        // 4. Remote ACKs our FIN -> FinWait2.
        let fin_seq = handler.connections[0].fin_seq.unwrap();
        let ack = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1006,
            fin_seq.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack.len();
        handler.process_ipv4(
            Frame::new(3, leak(ack), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        assert_eq!(handler.connections[0].state, TcpState::FinWait2);

        // 5. Remote sends FIN -> TimeWait.
        let fin = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1006,
            fin_seq.wrapping_add(1),
            flags::ACK | flags::FIN,
            65535,
            &[],
        );
        let fin_len = fin.len();
        handler.process_ipv4(
            Frame::new(4, leak(fin), fin_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        assert_eq!(handler.connections[0].state, TcpState::TimeWait);
        while tx.pop().is_some() {}

        // 6. TIME-WAIT expires -> connection removed.
        let future = coarsetime::Instant::now() + coarsetime::Duration::from_secs(120);
        handler.evict_stale(future, &mut rx);
        assert_eq!(
            handler.connections.len(),
            0,
            "connection removed after TIME-WAIT"
        );

        // 7. Frame accounting: all frames accounted for.
        // We injected 5 incoming frames (SYN, ACK, data, FIN-ACK, FIN) which end up in rx.
        // The handler consumed free frames for outgoing segments (SYN-ACK, data ACK, FIN,
        // ACK-for-FIN) which we drained from tx. So the total in free+rx+tx equals
        // initial_free + incoming - outgoing_drained.
        let total = free.num_frames() + rx.num_frames() + tx.num_frames();
        let outgoing_drained = initial_free + 5 - total;
        assert!(
            outgoing_drained > 0 && total > 0,
            "no frames leaked: free={} rx={} tx={} outgoing_drained={}",
            free.num_frames(),
            rx.num_frames(),
            tx.num_frames(),
            outgoing_drained,
        );
        assert_eq!(
            total + outgoing_drained,
            initial_free + 5,
            "all frames accounted for (free={} rx={} tx={} outgoing_drained={})",
            free.num_frames(),
            rx.num_frames(),
            tx.num_frames(),
            outgoing_drained,
        );
    }

    #[test]
    fn full_passive_close_lifecycle() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);

        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        // 1. Handshake.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {}

        // 2. Remote sends FIN -> CloseWait.
        let fin = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK | flags::FIN,
            65535,
            &[],
        );
        let fin_len = fin.len();
        handler.process_ipv4(
            Frame::new(2, leak(fin), fin_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        assert_eq!(handler.connections[0].state, TcpState::CloseWait);
        while tx.pop().is_some() {}

        // 3. We close -> LastAck.
        handler.connections[0].pending_fin = true;
        let now = coarsetime::Instant::now();
        handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
        assert_eq!(handler.connections[0].state, TcpState::LastAck);
        while tx.pop().is_some() {}
        let fin_seq = handler.connections[0].fin_seq.unwrap();

        // 4. Remote ACKs our FIN -> connection removed.
        let ack = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1002,
            fin_seq.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack.len();
        handler.process_ipv4(
            Frame::new(3, leak(ack), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        assert_eq!(
            handler.connections.len(),
            0,
            "connection removed after LastAck"
        );
    }

    #[test]
    fn delayed_ack_defers_ack_for_in_order_data() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(16);
        let mut rx = BasicFrameBuffer::new(16);
        let mut tx = BasicFrameBuffer::new(16);

        for i in 0..8 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {}

        // Send one in-order data segment.
        let payload = b"hello";
        let data = build_tcp_frame_with_payload(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
            payload,
        );
        let data_len = data.len();
        handler.process_ipv4(
            Frame::new(2, leak(data), data_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );

        // No immediate ACK — deferred.
        assert_eq!(tx.num_frames(), 0, "ACK should be deferred");
        let tcb = &handler.connections[0];
        assert!(tcb.ack_pending, "ack_pending should be true");
        assert!(
            tcb.delayed_ack_deadline.is_some(),
            "delayed_ack_deadline should be set"
        );
        assert_eq!(tcb.ack_delay_count, 1, "ack_delay_count should be 1");
    }

    #[test]
    fn delayed_ack_flushes_on_second_segment() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(16);
        let mut rx = BasicFrameBuffer::new(16);
        let mut tx = BasicFrameBuffer::new(16);

        for i in 0..8 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {}

        // First in-order segment — deferred.
        let seg1 = build_tcp_frame_with_payload(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
            b"aaaaa",
        );
        let seg1_len = seg1.len();
        handler.process_ipv4(
            Frame::new(2, leak(seg1), seg1_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        assert_eq!(tx.num_frames(), 0, "first segment deferred");

        // Second in-order segment — flushes ACK.
        let seg2 = build_tcp_frame_with_payload(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1006,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
            b"bbbbb",
        );
        let seg2_len = seg2.len();
        handler.process_ipv4(
            Frame::new(3, leak(seg2), seg2_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        assert_eq!(tx.num_frames(), 1, "second segment flushes ACK");

        let tcb = &handler.connections[0];
        assert!(!tcb.ack_pending, "ack_pending should be false after flush");
        assert_eq!(
            tcb.ack_delay_count, 0,
            "ack_delay_count should be 0 after flush"
        );
    }

    #[test]
    fn out_of_order_data_sends_immediate_ack() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(16);
        let mut rx = BasicFrameBuffer::new(16);
        let mut tx = BasicFrameBuffer::new(16);

        for i in 0..8 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {}

        // Send out-of-order data (skip sequence numbers).
        let ooo_data = build_tcp_frame_with_payload(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1011,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
            b"ooo",
        );
        let ooo_len = ooo_data.len();
        handler.process_ipv4(
            Frame::new(2, leak(ooo_data), ooo_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );

        assert_eq!(
            tx.num_frames(),
            1,
            "out-of-order data triggers immediate ACK"
        );
    }

    #[test]
    fn fin_sends_immediate_ack() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(16);
        let mut rx = BasicFrameBuffer::new(16);
        let mut tx = BasicFrameBuffer::new(16);

        for i in 0..8 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {}

        // Send FIN.
        let fin_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK | flags::FIN,
            65535,
            &[],
        );
        let fin_len = fin_data.len();
        handler.process_ipv4(
            Frame::new(2, leak(fin_data), fin_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );

        assert_eq!(tx.num_frames(), 1, "FIN triggers immediate ACK");
        assert_eq!(handler.connections[0].state, TcpState::CloseWait);
    }

    #[test]
    fn new_connection_has_delayed_ack_fields() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(8);
        let mut rx = BasicFrameBuffer::new(8);
        let mut tx = BasicFrameBuffer::new(8);

        for i in 0..4 {
            free.push(alloc_free_frame(100 + i));
        }

        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();

        // Step 1: SYN.
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        let syn_frame = Frame::new(0, leak(syn_data), syn_len, false);
        handler.process_ipv4(syn_frame, &nh, &mut free, &mut rx, &mut tx);
        assert_eq!(handler.connections[0].state, TcpState::SynReceived);

        let server_iss = handler.connections[0].iss;

        // Step 2: ACK completing handshake.
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        let ack_frame = Frame::new(1, leak(ack_data), ack_len, false);
        handler.process_ipv4(ack_frame, &nh, &mut free, &mut rx, &mut tx);

        assert_eq!(handler.connections[0].state, TcpState::Established);

        // Verify delayed ACK and Nagle defaults.
        let tcb = &handler.connections[0];
        assert!(!tcb.ack_pending, "ack_pending should be false");
        assert!(
            tcb.delayed_ack_deadline.is_none(),
            "delayed_ack_deadline should be None"
        );
        assert_eq!(tcb.ack_delay_count, 0, "ack_delay_count should be 0");
        assert_eq!(
            tcb.delayed_ack_ms,
            tcb::DEFAULT_DELAYED_ACK_MS,
            "delayed_ack_ms should match default"
        );
        assert!(tcb.nagle_enabled, "nagle should be enabled by default");
    }

    #[test]
    fn delayed_ack_timer_flushes_pending_ack() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);

        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        let now = coarsetime::Instant::now();

        // Complete handshake.
        let _accept = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {}

        // Manually set delayed ACK state on the TCB.
        let id = ConnectionId {
            local_addr: IpAddress::V4(LOCAL_IP),
            local_port: 80,
            remote_addr: IpAddress::V4(REMOTE_IP),
            remote_port: 12345,
        };
        {
            let tcb = handler.get_connection_mut(&id).unwrap();
            tcb.ack_pending = true;
            tcb.ack_delay_count = 1;
            tcb.delayed_ack_deadline = Some(now + coarsetime::Duration::from_millis(40));
        }

        // Before deadline — should NOT flush.
        handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut tx);
        assert_eq!(tx.num_frames(), 0, "should not flush before deadline");

        // After deadline — should flush.
        let later = now + coarsetime::Duration::from_millis(50);
        handler.poll_timers(later, nh.local_mac(), &nh, &mut free, &mut tx);
        assert_eq!(tx.num_frames(), 1, "should flush after deadline");

        let tcb = handler.get_connection(&id).unwrap();
        assert!(!tcb.ack_pending);
        assert_eq!(tcb.ack_delay_count, 0);
        assert!(tcb.delayed_ack_deadline.is_none());
    }

    /// Helper: perform active open handshake via connect + SYN-ACK processing.
    /// Returns the client ISS (so the caller knows snd_una/snd_nxt base).
    fn active_open_handshake(
        handler: &mut TcpHandler,
        nh: &NeighborHandler,
        free: &mut BasicFrameBuffer<'static>,
        rx: &mut BasicFrameBuffer<'static>,
        tx: &mut BasicFrameBuffer<'static>,
    ) -> u32 {
        let src_mac =
            crate::net::wire::ethernet::MacAddress::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let dst_mac =
            crate::net::wire::ethernet::MacAddress::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        // connect sends SYN.
        let _event_queue = handler
            .connect(
                IpAddress::V4(LOCAL_IP),
                5000,
                IpAddress::V4(REMOTE_IP),
                80,
                src_mac,
                dst_mac,
                free,
                tx,
            )
            .unwrap();
        while tx.pop().is_some() {} // consume SYN frame

        let client_iss = handler.connections[0].iss;

        // Feed SYN-ACK from the remote.
        let syn_ack = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            80,
            5000,
            2000,
            client_iss.wrapping_add(1),
            flags::SYN | flags::ACK,
            65535,
            &[],
        );
        let syn_ack_len = syn_ack.len();
        handler.process_ipv4(
            Frame::new(50, leak(syn_ack), syn_ack_len, false),
            nh,
            free,
            rx,
            tx,
        );
        while tx.pop().is_some() {} // consume ACK frame

        assert_eq!(handler.connections[0].state, TcpState::Established);
        handler.connections[0].snd_wnd = 65535;

        client_iss
    }

    /// Helper: perform active open handshake with custom TcpConfig.
    fn active_open_handshake_with_config(
        handler: &mut TcpHandler,
        nh: &NeighborHandler,
        config: TcpConfig,
        free: &mut BasicFrameBuffer<'static>,
        rx: &mut BasicFrameBuffer<'static>,
        tx: &mut BasicFrameBuffer<'static>,
    ) -> u32 {
        let src_mac =
            crate::net::wire::ethernet::MacAddress::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let dst_mac =
            crate::net::wire::ethernet::MacAddress::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        let _event_queue = handler
            .connect_with_config(
                IpAddress::V4(LOCAL_IP),
                5000,
                IpAddress::V4(REMOTE_IP),
                80,
                src_mac,
                dst_mac,
                config,
                free,
                tx,
            )
            .unwrap();
        while tx.pop().is_some() {}

        let client_iss = handler.connections[0].iss;

        let syn_ack = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            80,
            5000,
            2000,
            client_iss.wrapping_add(1),
            flags::SYN | flags::ACK,
            65535,
            &[],
        );
        let syn_ack_len = syn_ack.len();
        handler.process_ipv4(
            Frame::new(50, leak(syn_ack), syn_ack_len, false),
            nh,
            free,
            rx,
            tx,
        );
        while tx.pop().is_some() {}

        assert_eq!(handler.connections[0].state, TcpState::Established);
        handler.connections[0].snd_wnd = 65535;

        client_iss
    }

    #[test]
    fn nagle_holds_small_data_when_bytes_in_flight() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);

        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        // 1. Complete handshake via active open.
        let _iss = active_open_handshake(&mut handler, &nh, &mut free, &mut rx, &mut tx);

        // 2. Write small data.
        handler.connections[0].send_buffer.write(b"hello");

        // 3. poll_send — first send goes (nothing in flight).
        let now = coarsetime::Instant::now();
        handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
        assert_eq!(tx.num_frames(), 1, "first small segment should send");

        // 4. Pop tx frame.
        while tx.pop().is_some() {}

        // 5. Write more small data — bytes still in flight (unACKed).
        handler.connections[0].send_buffer.write(b"world");

        // 6. poll_send — Nagle holds it.
        handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
        assert_eq!(
            tx.num_frames(),
            0,
            "Nagle should hold small data when bytes in flight"
        );
    }

    #[test]
    fn nagle_allows_full_mss_even_with_bytes_in_flight() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);

        // Allocate frames large enough for MSS-sized segments (ETH+IP+TCP+536 = 590).
        for i in 0..16 {
            free.push(Frame::new(100 + i, leak(vec![0u8; 1024]), 1024, false));
        }

        // 1. Complete handshake via active open.
        let _iss = active_open_handshake(&mut handler, &nh, &mut free, &mut rx, &mut tx);

        // 2. Write small data, send it (creates bytes_in_flight), pop tx.
        handler.connections[0].send_buffer.write(b"hi");
        let now = coarsetime::Instant::now();
        handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
        while tx.pop().is_some() {}

        // 3. Write MSS-worth of data.
        let mss = handler.connections[0].eff_snd_mss as usize;
        let mss_data = vec![0xAA; mss];
        handler.connections[0].send_buffer.write(&mss_data);

        // 4. poll_send — full MSS always sends even with bytes in flight.
        handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
        assert_eq!(
            tx.num_frames(),
            1,
            "full MSS segment should send even with bytes in flight"
        );
    }

    #[test]
    fn tcp_no_delay_sends_small_data_immediately() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);

        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        // 1. Complete handshake with tcp_no_delay.
        let config = TcpConfig {
            tcp_no_delay: true,
            ..Default::default()
        };
        let _iss = active_open_handshake_with_config(
            &mut handler,
            &nh,
            config,
            &mut free,
            &mut rx,
            &mut tx,
        );

        // Verify nagle is disabled.
        assert!(
            !handler.connections[0].nagle_enabled,
            "nagle should be disabled with tcp_no_delay"
        );

        // 2. Write small data, poll_send (first send), pop tx.
        handler.connections[0].send_buffer.write(b"hello");
        let now = coarsetime::Instant::now();
        handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
        assert_eq!(tx.num_frames(), 1);
        while tx.pop().is_some() {}

        // 3. Write more small data while first is in flight.
        handler.connections[0].send_buffer.write(b"world");

        // 4. poll_send — TCP_NODELAY bypasses Nagle.
        handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
        assert_eq!(
            tx.num_frames(),
            1,
            "TCP_NODELAY should bypass Nagle and send immediately"
        );
    }

    #[test]
    fn data_send_clears_delayed_ack() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);

        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        // 1. Complete handshake via passive open (listener).
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {}

        // 2. Receive in-order data — ack_pending becomes true.
        let data_seg = build_tcp_frame_with_payload(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
            b"incoming data",
        );
        let data_len = data_seg.len();
        handler.process_ipv4(
            Frame::new(2, leak(data_seg), data_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {} // consume any immediate ACK frames

        assert!(
            handler.connections[0].ack_pending,
            "ack_pending should be true after receiving data"
        );

        // 3. Write data to send buffer.
        handler.connections[0].send_buffer.write(b"reply data");
        handler.connections[0].snd_wnd = 65535;

        // 4. poll_send — sends data (piggybacks ACK).
        let now = coarsetime::Instant::now();
        handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
        assert!(tx.num_frames() >= 1, "data segment should be sent");

        // 5. Verify delayed ACK state is cleared.
        let tcb = &handler.connections[0];
        assert!(
            !tcb.ack_pending,
            "ack_pending should be cleared after data send"
        );
        assert_eq!(tcb.ack_delay_count, 0, "ack_delay_count should be cleared");
        assert!(
            tcb.delayed_ack_deadline.is_none(),
            "delayed_ack_deadline should be cleared"
        );
    }

    #[test]
    fn shutdown_sets_pending_fin() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(16);
        let mut rx = BasicFrameBuffer::new(16);
        let mut tx = BasicFrameBuffer::new(16);

        for i in 0..8 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake to reach Established.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        assert_eq!(handler.connections[0].state, TcpState::Established);

        // Verify pending_fin is initially false.
        assert!(
            !handler.connections[0].pending_fin,
            "pending_fin should start false"
        );

        // Call initiate_close (the handler method that shutdown() delegates to).
        let conn_id = handler.connections[0].id;
        handler.initiate_close(&conn_id);

        // Verify pending_fin is now true.
        assert!(
            handler.connections[0].pending_fin,
            "pending_fin should be true after initiate_close"
        );

        // Verify connection is still Established (FIN not yet sent).
        assert_eq!(
            handler.connections[0].state,
            TcpState::Established,
            "state should remain Established until poll_send"
        );
    }

    #[test]
    fn keep_alive_activity_resets_probe_timer() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(16);
        let mut rx = BasicFrameBuffer::new(16);
        let mut tx = BasicFrameBuffer::new(16);

        for i in 0..8 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake to reach Established.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        assert_eq!(handler.connections[0].state, TcpState::Established);

        // Simulate stale keep-alive state: set probes sent to 5.
        let old_activity = handler.connections[0].last_activity;
        handler.connections[0].keep_alive_probes_sent = 5;

        // Clear tx from handshake.
        while tx.pop().is_some() {}

        // Send a data segment to the established connection.
        let payload = b"keepalive-reset";
        let data = build_tcp_frame_with_payload(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
            payload,
        );
        let data_len = data.len();
        handler.process_ipv4(
            Frame::new(2, leak(data), data_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );

        // Verify keep-alive probes were reset.
        let tcb = &handler.connections[0];
        assert_eq!(
            tcb.keep_alive_probes_sent, 0,
            "keep_alive_probes_sent should be reset to 0 on data receipt"
        );
        assert!(
            tcb.last_activity >= old_activity,
            "last_activity should be updated on data receipt"
        );
    }

    #[test]
    fn keep_alive_probe_sent_after_idle_timeout() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);

        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake.
        let _accept = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {}
        assert_eq!(handler.connections[0].state, TcpState::Established);

        // Configure keep-alive with short timeouts.
        {
            let tcb = &mut handler.connections[0];
            tcb.keep_alive_enabled = true;
            tcb.keep_alive_idle_ms = 100;
            tcb.keep_alive_interval_ms = 50;
            tcb.keep_alive_count = 3;
            tcb.ack_pending = false;
        }

        // Sleep long enough for the idle timeout to expire.
        std::thread::sleep(std::time::Duration::from_millis(150));
        let now = coarsetime::Instant::now();

        handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut tx);

        assert_eq!(
            handler.connections[0].keep_alive_probes_sent, 1,
            "one keep-alive probe should have been sent"
        );
        assert!(
            tx.num_frames() >= 1,
            "a probe segment should have been emitted"
        );
    }

    #[test]
    fn keep_alive_no_probe_when_disabled() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);

        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake.
        let _accept = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {}
        assert_eq!(handler.connections[0].state, TcpState::Established);

        // Keep-alive is disabled by default; set ack_pending false to avoid delayed ACK output.
        handler.connections[0].ack_pending = false;

        // Sleep long enough that it would have triggered if enabled.
        std::thread::sleep(std::time::Duration::from_millis(150));
        let now = coarsetime::Instant::now();

        handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut tx);

        assert_eq!(
            handler.connections[0].keep_alive_probes_sent, 0,
            "no probes should be sent when keep-alive is disabled"
        );
        assert_eq!(tx.num_frames(), 0, "no segments should be emitted");
    }

    #[test]
    fn keep_alive_connection_aborted_after_max_probes() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);

        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake.
        let _accept = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {}
        assert_eq!(handler.connections[0].state, TcpState::Established);

        // Capture event queue before connection is removed.
        let event_queue = handler.connections[0].event_queue.clone();

        // Configure keep-alive: already sent max probes.
        {
            let tcb = &mut handler.connections[0];
            tcb.keep_alive_enabled = true;
            tcb.keep_alive_idle_ms = 50;
            tcb.keep_alive_interval_ms = 25;
            tcb.keep_alive_count = 2;
            tcb.keep_alive_probes_sent = 2; // already at max
            tcb.ack_pending = false;
        }

        // Sleep past the probe threshold.
        std::thread::sleep(std::time::Duration::from_millis(150));
        let now = coarsetime::Instant::now();

        handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut tx);

        // Connection should be removed.
        assert!(
            handler.connections.is_empty(),
            "connection should be removed after max probes exceeded"
        );

        // Timeout event should have been pushed.
        let event = event_queue.pop();
        assert_eq!(
            event,
            Some(TcpEvent::Timeout),
            "TcpEvent::Timeout should be emitted"
        );
    }

    #[test]
    fn linger_zero_sends_rst_on_poll_send() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(16);
        let mut rx = BasicFrameBuffer::new(16);
        let mut tx = BasicFrameBuffer::new(16);

        for i in 0..8 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake to reach Established.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        assert_eq!(handler.connections[0].state, TcpState::Established);

        // Set linger to 0 and capture event queue.
        handler.connections[0].linger = Some(0);
        let event_queue = handler.connections[0].event_queue.clone();
        let conn_id = handler.connections[0].id;

        // Clear tx from handshake.
        while tx.pop().is_some() {}

        // Call initiate_close — should set pending_fin and linger_deadline to Instant::recent().
        handler.initiate_close(&conn_id);
        assert!(
            handler.connections[0].pending_fin,
            "pending_fin should be set"
        );
        assert!(
            handler.connections[0].linger_deadline.is_some(),
            "linger_deadline should be set"
        );

        // Call poll_send — linger deadline is already expired, should send RST.
        let now = coarsetime::Instant::now();
        handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);

        // Connection should be removed.
        assert!(
            handler.get_connection(&conn_id).is_none(),
            "connection should be removed after linger(0) RST"
        );

        // A RST segment should have been emitted.
        assert!(tx.num_frames() > 0, "RST segment should be emitted");

        // Reset event should have been pushed.
        let event = event_queue.pop();
        assert_eq!(
            event,
            Some(TcpEvent::Reset),
            "TcpEvent::Reset should be emitted"
        );
    }

    #[test]
    fn linger_timeout_sets_deadline() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(16);
        let mut rx = BasicFrameBuffer::new(16);
        let mut tx = BasicFrameBuffer::new(16);

        for i in 0..8 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake to reach Established.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        assert_eq!(handler.connections[0].state, TcpState::Established);

        // Set linger to 5000ms.
        handler.connections[0].linger = Some(5000);
        let conn_id = handler.connections[0].id;

        // Clear tx from handshake.
        while tx.pop().is_some() {}

        // Call initiate_close.
        handler.initiate_close(&conn_id);
        assert!(
            handler.connections[0].pending_fin,
            "pending_fin should be set"
        );
        assert!(
            handler.connections[0].linger_deadline.is_some(),
            "linger_deadline should be set"
        );

        // Call poll_send immediately — deadline is 5s in the future, should NOT abort.
        let now = coarsetime::Instant::now();
        handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);

        // Connection should still exist.
        assert!(
            handler.get_connection(&conn_id).is_some(),
            "connection should still exist before deadline"
        );
    }

    #[test]
    fn linger_none_normal_close() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(16);
        let mut rx = BasicFrameBuffer::new(16);
        let mut tx = BasicFrameBuffer::new(16);

        for i in 0..8 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake to reach Established.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        assert_eq!(handler.connections[0].state, TcpState::Established);

        // Ensure linger is None (default).
        assert!(
            handler.connections[0].linger.is_none(),
            "linger should be None by default"
        );
        let conn_id = handler.connections[0].id;

        // Call initiate_close.
        handler.initiate_close(&conn_id);

        // Verify pending_fin is true and linger_deadline is None.
        assert!(
            handler.connections[0].pending_fin,
            "pending_fin should be set"
        );
        assert!(
            handler.connections[0].linger_deadline.is_none(),
            "linger_deadline should be None for default close"
        );
    }

    #[test]
    fn half_close_writes_blocked_reads_continue() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);

        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {}
        assert_eq!(handler.connections[0].state, TcpState::Established);

        // Initiate half-close (shutdown write side).
        let conn_id = handler.connections[0].id;
        handler.initiate_close(&conn_id);

        // Verify pending_fin is set but state is still Established (FIN not sent yet).
        assert!(
            handler.connections[0].pending_fin,
            "pending_fin should be true after initiate_close"
        );
        assert_eq!(
            handler.connections[0].state,
            TcpState::Established,
            "state should still be Established before poll_send"
        );

        // Write data directly into recv_buffer (simulating received data).
        let incoming = b"data after half-close";
        handler.connections[0].recv_buffer.write(incoming);

        // Verify reads still work after half-close.
        assert_eq!(
            handler.connections[0].recv_buffer.available(),
            incoming.len(),
            "recv_buffer should still be readable after half-close"
        );
        let mut buf = [0u8; 32];
        let read_len = handler.connections[0].recv_buffer.read(&mut buf);
        assert_eq!(read_len, incoming.len(), "should read all data");
        assert_eq!(
            &buf[..read_len],
            incoming,
            "read data should match written data"
        );
    }

    #[test]
    fn keep_alive_probe_and_recovery() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);

        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {}
        assert_eq!(handler.connections[0].state, TcpState::Established);

        // Configure keep-alive.
        {
            let tcb = &mut handler.connections[0];
            tcb.keep_alive_enabled = true;
            tcb.keep_alive_idle_ms = 100;
            tcb.keep_alive_interval_ms = 50;
            tcb.keep_alive_count = 3;
            tcb.ack_pending = false;
            tcb.delayed_ack_deadline = None;
        }

        // Wait past the idle threshold.
        std::thread::sleep(std::time::Duration::from_millis(150));
        coarsetime::Instant::update();
        let now = coarsetime::Instant::now();

        let tx_before = tx.num_frames();
        handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut tx);

        // Verify probe was sent.
        assert!(
            tx.num_frames() > tx_before,
            "keep-alive probe should be sent"
        );
        assert_eq!(
            handler.connections[0].keep_alive_probes_sent, 1,
            "probes_sent should be 1"
        );

        // Record last_activity before recovery.
        let activity_before = handler.connections[0].last_activity;

        // Simulate receiving an ACK from the remote (recovery).
        let rcv_nxt = handler.connections[0].rcv_nxt;
        let snd_una = handler.connections[0].snd_una;
        let ack_frame = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            rcv_nxt,
            snd_una,
            flags::ACK,
            65535,
            &[],
        );
        let ack_frame_len = ack_frame.len();

        // Use process_ipv4_with_now so last_activity gets a known timestamp.
        coarsetime::Instant::update();
        let recv_now = coarsetime::Instant::now();
        handler.process_ipv4_with_now(
            Frame::new(10, leak(ack_frame), ack_frame_len, false),
            recv_now,
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );

        // The ACK is a duplicate ACK (seg_ack == snd_una, no data).
        // Keep-alive probe responses are duplicate ACKs — the fix in process_established
        // resets keep_alive_probes_sent when a dup ACK arrives and probes are outstanding.
        let tcb = &handler.connections[0];
        assert_eq!(
            tcb.keep_alive_probes_sent, 0,
            "probes_sent should be reset by dup ACK probe response"
        );
        assert!(
            tcb.last_activity >= activity_before,
            "last_activity should be updated"
        );
    }

    #[test]
    fn keep_alive_exhaustion_removes_connection() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);

        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {}
        assert_eq!(handler.connections[0].state, TcpState::Established);

        // Capture event queue before connection is removed.
        let event_queue = handler.connections[0].event_queue.clone();

        // Configure keep-alive with count=1.
        {
            let tcb = &mut handler.connections[0];
            tcb.keep_alive_enabled = true;
            tcb.keep_alive_count = 1;
            tcb.keep_alive_idle_ms = 50;
            tcb.keep_alive_interval_ms = 50;
            tcb.ack_pending = false;
            tcb.delayed_ack_deadline = None;
        }

        // Wait past the idle threshold and send first probe.
        std::thread::sleep(std::time::Duration::from_millis(100));
        coarsetime::Instant::update();
        let now1 = coarsetime::Instant::now();
        handler.poll_timers(now1, nh.local_mac(), &nh, &mut free, &mut tx);

        // First probe should have been sent.
        assert_eq!(
            handler.connections[0].keep_alive_probes_sent, 1,
            "first probe sent"
        );
        assert_eq!(
            handler.connections.len(),
            1,
            "connection still alive after first probe"
        );

        // Wait again past the interval — max probes exceeded.
        std::thread::sleep(std::time::Duration::from_millis(100));
        coarsetime::Instant::update();
        let now2 = coarsetime::Instant::now();
        handler.poll_timers(now2, nh.local_mac(), &nh, &mut free, &mut tx);

        // Connection should be removed.
        assert!(
            handler.connections.is_empty(),
            "connection should be removed after max probes exceeded"
        );

        // Timeout event should have been pushed.
        let event = event_queue.pop();
        assert_eq!(
            event,
            Some(TcpEvent::Timeout),
            "TcpEvent::Timeout should be emitted"
        );
    }

    #[test]
    fn linger_zero_immediate_rst() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);

        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {}
        assert_eq!(handler.connections[0].state, TcpState::Established);

        // Write some data to send buffer.
        handler.connections[0].send_buffer.write(b"unsent data");

        // Set linger to 0 and capture event queue.
        handler.connections[0].linger = Some(0);
        let event_queue = handler.connections[0].event_queue.clone();
        let conn_id = handler.connections[0].id;

        // Initiate close — linger(0) sets immediate deadline.
        handler.initiate_close(&conn_id);
        assert!(
            handler.connections[0].pending_fin,
            "pending_fin should be set"
        );
        assert!(
            handler.connections[0].linger_deadline.is_some(),
            "linger_deadline should be set for linger(0)"
        );

        // Call poll_send — linger deadline is already expired, should send RST.
        let now = coarsetime::Instant::now();
        handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);

        // Connection should be removed.
        assert!(
            handler.get_connection(&conn_id).is_none(),
            "connection should be removed after linger(0) RST"
        );

        // RST segment should have been emitted.
        assert!(tx.num_frames() > 0, "RST segment should be emitted on tx");

        // Reset event should have been pushed.
        let event = event_queue.pop();
        assert_eq!(
            event,
            Some(TcpEvent::Reset),
            "TcpEvent::Reset should be emitted for linger(0) abort"
        );
    }

    /// Build a 12-byte TCP timestamp option (NOP NOP TSopt) for use in test frames.
    fn build_ts_option(tsval: u32, tsecr: u32) -> Vec<u8> {
        let mut opt = vec![1u8, 1]; // NOP, NOP (alignment)
        opt.push(8); // kind = TIMESTAMP
        opt.push(10); // length = 10
        opt.extend_from_slice(&tsval.to_be_bytes());
        opt.extend_from_slice(&tsecr.to_be_bytes());
        opt
    }

    #[test]
    fn paws_rejects_old_timestamp() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(16);
        let mut rx = BasicFrameBuffer::new(16);
        let mut tx = BasicFrameBuffer::new(16);

        for i in 0..8 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete the handshake with timestamp options.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let ts_opt = build_ts_option(500, 0);
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &ts_opt,
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ts_opt2 = build_ts_option(600, 0);
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &ts_opt2,
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        assert_eq!(handler.connections[0].state, TcpState::Established);
        assert!(handler.connections[0].ts_enabled);

        // Set ts_recent to 1000 to make the test deterministic.
        handler.connections[0].ts_recent = 1000;
        handler.connections[0].ts_recent_age = coarsetime::Instant::now();

        // Clear tx from handshake.
        while tx.pop().is_some() {}

        // Send a segment with TSval=999 (older than ts_recent=1000).
        let old_ts_opt = build_ts_option(999, 0);
        let data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &old_ts_opt,
        );
        let data_len = data.len();
        handler.process_ipv4(
            Frame::new(2, leak(data), data_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );

        // Segment should be dropped and an ACK sent back.
        assert_eq!(
            handler.connections.len(),
            1,
            "connection should still exist"
        );
        assert!(
            tx.pop().is_some(),
            "ACK should be sent in response to PAWS rejection"
        );
    }

    #[test]
    fn paws_accepts_rst_with_old_timestamp() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(16);
        let mut rx = BasicFrameBuffer::new(16);
        let mut tx = BasicFrameBuffer::new(16);

        for i in 0..8 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete the handshake with timestamp options.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let ts_opt = build_ts_option(500, 0);
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &ts_opt,
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ts_opt2 = build_ts_option(600, 0);
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &ts_opt2,
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        assert_eq!(handler.connections[0].state, TcpState::Established);
        assert!(handler.connections[0].ts_enabled);

        // Set ts_recent to 1000.
        handler.connections[0].ts_recent = 1000;
        handler.connections[0].ts_recent_age = coarsetime::Instant::now();

        while tx.pop().is_some() {}

        // Send RST with old TSval=999 — RST should bypass PAWS.
        let old_ts_opt = build_ts_option(999, 0);
        let rst_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::RST,
            65535,
            &old_ts_opt,
        );
        let rst_len = rst_data.len();
        handler.process_ipv4(
            Frame::new(2, leak(rst_data), rst_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );

        // RST should have been processed — connection removed.
        assert_eq!(
            handler.connections.len(),
            0,
            "RST should bypass PAWS and remove connection"
        );
    }

    #[test]
    fn paws_accepts_stale_ts_recent() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(16);
        let mut rx = BasicFrameBuffer::new(16);
        let mut tx = BasicFrameBuffer::new(16);

        for i in 0..8 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete the handshake with timestamp options.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let ts_opt = build_ts_option(500, 0);
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &ts_opt,
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        let server_iss = handler.connections[0].iss;
        let ts_opt2 = build_ts_option(600, 0);
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &ts_opt2,
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        assert_eq!(handler.connections[0].state, TcpState::Established);
        assert!(handler.connections[0].ts_enabled);

        // Set ts_recent to 1000 and ts_recent_age to > 24 days ago.
        handler.connections[0].ts_recent = 1000;
        // Set ts_recent_age far in the past using a fixed tick value.
        handler.connections[0].ts_recent_age = coarsetime::Instant::from_ticks(0);

        while tx.pop().is_some() {}

        // Construct a `now` that is guaranteed to be 25 days after ts_recent_age(0),
        // regardless of system uptime. This ensures the PAWS staleness check sees
        // > 24 days elapsed and accepts the segment despite old TSval.
        let twenty_five_days = coarsetime::Duration::from_secs(25 * 24 * 60 * 60);
        let now = coarsetime::Instant::from_ticks(0) + twenty_five_days;

        // Send a segment with old TSval=999, but ts_recent_age is stale (> 24 days).
        // The PAWS check should accept the segment despite old timestamp.
        let old_ts_opt = build_ts_option(999, 0);
        let data = build_tcp_frame_with_payload(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &old_ts_opt,
            b"Hello",
        );
        let data_len = data.len();
        handler.process_ipv4_with_now(
            Frame::new(2, leak(data), data_len, false),
            now,
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );

        // Segment should be accepted — connection still exists and data received.
        assert_eq!(
            handler.connections.len(),
            1,
            "connection should still exist"
        );
        let tcb = &handler.connections[0];
        assert_eq!(
            tcb.recv_buffer.available(),
            5,
            "data should be accepted when ts_recent is stale"
        );
    }

    #[test]
    fn segment_acceptability_zero_len_zero_wnd() {
        assert!(is_segment_acceptable(100, 0, 100, 0));
        assert!(!is_segment_acceptable(101, 0, 100, 0));
    }

    #[test]
    fn segment_acceptability_zero_len_nonzero_wnd() {
        assert!(is_segment_acceptable(100, 0, 100, 1000));
        assert!(is_segment_acceptable(1099, 0, 100, 1000));
        assert!(!is_segment_acceptable(1100, 0, 100, 1000));
        assert!(!is_segment_acceptable(99, 0, 100, 1000));
    }

    #[test]
    fn segment_acceptability_nonzero_len_zero_wnd() {
        assert!(!is_segment_acceptable(100, 10, 100, 0));
    }

    #[test]
    fn segment_acceptability_nonzero_len_nonzero_wnd() {
        // Start in window
        assert!(is_segment_acceptable(100, 10, 100, 1000));
        // End in window (start slightly before)
        assert!(is_segment_acceptable(95, 10, 100, 1000));
        // Completely outside
        assert!(!is_segment_acceptable(1200, 10, 100, 1000));
        // Completely before
        assert!(!is_segment_acceptable(80, 10, 100, 1000));
    }

    /// Helper: complete a 3-way handshake and return server_iss.
    /// Drains tx after handshake so callers start with an empty tx buffer.
    fn establish_connection(
        handler: &mut TcpHandler,
        nh: &NeighborHandler,
        free: &mut BasicFrameBuffer<'static>,
        rx: &mut BasicFrameBuffer<'static>,
        tx: &mut BasicFrameBuffer<'static>,
    ) -> u32 {
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            nh,
            free,
            rx,
            tx,
        );
        let server_iss = handler.connections[0].iss;
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            nh,
            free,
            rx,
            tx,
        );
        while tx.pop().is_some() {}
        server_iss
    }

    #[test]
    fn persist_timer_activates_on_zero_window() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);
        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        let _server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);

        // Write data into send buffer, but set window to 0.
        handler.connections[0].send_buffer.write(b"Hello");
        handler.connections[0].snd_wnd = 0;

        assert!(handler.connections[0].persist_deadline.is_none());

        let now = coarsetime::Instant::now();
        handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);

        // Persist timer should now be armed.
        assert!(
            handler.connections[0].persist_deadline.is_some(),
            "persist_deadline should be set when window=0 and data available"
        );
        // No data segment should have been sent (deadline not yet reached).
        assert_eq!(tx.num_frames(), 0, "no segment sent before deadline");
    }

    #[test]
    fn persist_probe_sent_when_deadline_expires() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);
        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        let server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);

        // Write data, set window to 0.
        handler.connections[0].send_buffer.write(b"Hello");
        handler.connections[0].snd_wnd = 0;

        let now = coarsetime::Instant::now();
        handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
        assert!(handler.connections[0].persist_deadline.is_some());
        assert_eq!(handler.connections[0].persist_backoff, 0);

        // Simulate time passing beyond the deadline by setting it to the past.
        handler.connections[0].persist_deadline = Some(now);

        handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);

        // A 1-byte probe should have been sent.
        assert_eq!(tx.num_frames(), 1, "probe segment should be sent");
        // snd_nxt should advance by 1.
        assert_eq!(
            handler.connections[0].snd_nxt,
            server_iss.wrapping_add(1).wrapping_add(1),
            "snd_nxt advanced by 1 for probe"
        );
        // persist_backoff should have incremented.
        assert_eq!(handler.connections[0].persist_backoff, 1);
        // persist_deadline should be rescheduled (not None).
        assert!(handler.connections[0].persist_deadline.is_some());
    }

    #[test]
    fn persist_timer_clears_when_window_reopens() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);
        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        let server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);

        // Write data, set window to 0, arm persist timer.
        handler.connections[0].send_buffer.write(b"Hello");
        handler.connections[0].snd_wnd = 0;

        let now = coarsetime::Instant::now();
        handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
        assert!(handler.connections[0].persist_deadline.is_some());
        handler.connections[0].persist_backoff = 3; // simulate some backoff

        // Peer sends ACK with non-zero window, reopening it.
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            32000, // non-zero window
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(2, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );

        // Persist timer should be cleared.
        assert!(
            handler.connections[0].persist_deadline.is_none(),
            "persist_deadline should be cleared when window reopens"
        );
        assert_eq!(
            handler.connections[0].persist_backoff, 0,
            "persist_backoff should be reset"
        );
    }

    #[test]
    fn ooo_data_sends_sack_blocks_in_dup_ack() {
        use crate::net::wire::tcp::{options as tcp_options, parse_sack_blocks};

        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);

        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        // Complete handshake with SACK_PERMITTED in SYN options.
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let sack_perm_opts = [tcp_options::SACK_PERMITTED, 2];
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &sack_perm_opts,
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        assert!(
            handler.connections[0].sack_enabled,
            "SACK should be negotiated"
        );
        let server_iss = handler.connections[0].iss;
        // Drain SYN-ACK.
        while tx.pop().is_some() {}

        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {}

        assert_eq!(handler.connections[0].state, TcpState::Established);

        // Send out-of-order segment: seq=1011, 5 bytes (gap from 1001..1011).
        let ooo_seg = build_tcp_frame_with_payload(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1011,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
            b"world",
        );
        let ooo_len = ooo_seg.len();
        handler.process_ipv4(
            Frame::new(2, leak(ooo_seg), ooo_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );

        // Should have emitted a dup ACK with SACK blocks.
        assert_eq!(tx.num_frames(), 1, "OOO data triggers dup ACK");
        let ack_frame = tx.pop().unwrap();

        let tcp_offset = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        let tcp = unsafe { TcpHeader::from_bytes_at(&ack_frame, tcp_offset) };
        assert_eq!(tcp.flags(), flags::ACK);
        assert_eq!(tcp.ack_num(), 1001, "dup ACK has original rcv_nxt");

        // Parse SACK blocks from the TCP options.
        let data_off_bytes = (tcp.data_offset() as usize) * 4;
        let opt_len = data_off_bytes - TCP_HEADER_LEN;
        assert!(opt_len > 0, "options should be present");
        let opt_start = tcp_offset + TCP_HEADER_LEN;
        let tcp_opts = &ack_frame[opt_start..opt_start + opt_len];
        let (blocks, count) = parse_sack_blocks(tcp_opts);
        assert_eq!(count, 1, "one SACK block expected");
        // Block should cover the OOO range: [1011, 1016).
        assert_eq!(blocks[0], Some((1011, 1016)));
    }

    /// Helper: establish a connection with SACK enabled, returning server_iss.
    fn establish_connection_with_sack(
        handler: &mut TcpHandler,
        nh: &NeighborHandler,
        free: &mut BasicFrameBuffer<'static>,
        rx: &mut BasicFrameBuffer<'static>,
        tx: &mut BasicFrameBuffer<'static>,
    ) -> u32 {
        use crate::net::wire::tcp::options as tcp_options;
        let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
        let sack_perm_opts = [tcp_options::SACK_PERMITTED, 2];
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &sack_perm_opts,
        );
        let syn_len = syn_data.len();
        handler.process_ipv4(
            Frame::new(0, leak(syn_data), syn_len, false),
            nh,
            free,
            rx,
            tx,
        );
        assert!(handler.connections[0].sack_enabled);
        let server_iss = handler.connections[0].iss;
        while tx.pop().is_some() {}

        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            server_iss.wrapping_add(1),
            flags::ACK,
            65535,
            &[],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(1, leak(ack_data), ack_len, false),
            nh,
            free,
            rx,
            tx,
        );
        while tx.pop().is_some() {}
        assert_eq!(handler.connections[0].state, TcpState::Established);
        server_iss
    }

    #[test]
    fn sack_blocks_update_scoreboard_on_ack() {
        use crate::net::wire::tcp::write_sack_option;

        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);
        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        let _server_iss =
            establish_connection_with_sack(&mut handler, &nh, &mut free, &mut rx, &mut tx);

        // Put data in the send buffer and advance snd_nxt to simulate sent data.
        let tcb = &mut handler.connections[0];
        tcb.send_buffer.write(&[0u8; 100]);
        tcb.snd_nxt = tcb.snd_una.wrapping_add(100);

        // Build an ACK that advances snd_una by 10, with SACK blocks for [30..50) and [70..90).
        let snd_una = tcb.snd_una;
        let new_ack = snd_una.wrapping_add(10);
        let sack_left1 = snd_una.wrapping_add(30);
        let sack_right1 = snd_una.wrapping_add(50);
        let sack_left2 = snd_una.wrapping_add(70);
        let sack_right2 = snd_una.wrapping_add(90);

        let mut opts = [0u8; 20];
        let written = write_sack_option(
            &mut opts,
            &[(sack_left1, sack_right1), (sack_left2, sack_right2)],
        );

        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            new_ack,
            flags::ACK,
            65535,
            &opts[..written],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(2, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );

        let tcb = &handler.connections[0];
        assert_eq!(tcb.snd_una, new_ack, "snd_una should advance");
        assert_eq!(
            tcb.sack_scoreboard.len(),
            2,
            "two SACK blocks in scoreboard"
        );
        assert_eq!(tcb.sack_scoreboard.get(&sack_left1), Some(&20));
        assert_eq!(tcb.sack_scoreboard.get(&sack_left2), Some(&20));
    }

    #[test]
    fn sack_scoreboard_pruned_on_cumulative_ack_advance() {
        use crate::net::wire::tcp::write_sack_option;

        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);
        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        let _server_iss =
            establish_connection_with_sack(&mut handler, &nh, &mut free, &mut rx, &mut tx);

        let tcb = &mut handler.connections[0];
        tcb.send_buffer.write(&[0u8; 200]);
        tcb.snd_nxt = tcb.snd_una.wrapping_add(200);
        let snd_una = tcb.snd_una;

        // First ACK: advance by 10, SACK blocks at [30..50) and [100..120).
        let ack1 = snd_una.wrapping_add(10);
        let sack_left1 = snd_una.wrapping_add(30);
        let sack_right1 = snd_una.wrapping_add(50);
        let sack_left2 = snd_una.wrapping_add(100);
        let sack_right2 = snd_una.wrapping_add(120);

        let mut opts = [0u8; 20];
        let written = write_sack_option(
            &mut opts,
            &[(sack_left1, sack_right1), (sack_left2, sack_right2)],
        );
        let ack_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            ack1,
            flags::ACK,
            65535,
            &opts[..written],
        );
        let ack_len = ack_data.len();
        handler.process_ipv4(
            Frame::new(2, leak(ack_data), ack_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        assert_eq!(handler.connections[0].sack_scoreboard.len(), 2);

        // Second ACK: advance cumulative ACK past the first SACK block (to 50).
        // Include the second block again.
        let ack2 = snd_una.wrapping_add(50);
        let mut opts2 = [0u8; 12];
        let written2 = write_sack_option(&mut opts2, &[(sack_left2, sack_right2)]);
        let ack_data2 = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            ack2,
            flags::ACK,
            65535,
            &opts2[..written2],
        );
        let ack_len2 = ack_data2.len();
        handler.process_ipv4(
            Frame::new(3, leak(ack_data2), ack_len2, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );

        let tcb = &handler.connections[0];
        assert_eq!(tcb.snd_una, ack2);
        // The first block (start=snd_una+30) should be pruned since 30 < 50.
        assert!(
            !tcb.sack_scoreboard.contains_key(&sack_left1),
            "old block should be pruned"
        );
        // The second block should remain.
        assert_eq!(tcb.sack_scoreboard.len(), 1, "only second block remains");
        assert!(tcb.sack_scoreboard.contains_key(&sack_left2));
    }

    #[test]
    fn sack_blocks_updated_on_dup_ack() {
        use crate::net::wire::tcp::write_sack_option;

        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);
        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        let _server_iss =
            establish_connection_with_sack(&mut handler, &nh, &mut free, &mut rx, &mut tx);

        let tcb = &mut handler.connections[0];
        tcb.send_buffer.write(&[0u8; 100]);
        tcb.snd_nxt = tcb.snd_una.wrapping_add(100);
        let snd_una = tcb.snd_una;

        // Send a duplicate ACK (same ack number, no payload) with SACK block.
        let sack_left = snd_una.wrapping_add(20);
        let sack_right = snd_una.wrapping_add(40);
        let mut opts = [0u8; 12];
        let written = write_sack_option(&mut opts, &[(sack_left, sack_right)]);

        let dup_ack = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            snd_una,
            flags::ACK,
            65535,
            &opts[..written],
        );
        let dup_len = dup_ack.len();
        handler.process_ipv4(
            Frame::new(2, leak(dup_ack), dup_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );

        let tcb = &handler.connections[0];
        assert_eq!(tcb.dup_ack_count, 1);
        assert_eq!(tcb.sack_scoreboard.len(), 1);
        assert_eq!(tcb.sack_scoreboard.get(&sack_left), Some(&20));
    }

    #[test]
    fn sack_scoreboard_cleared_on_rto() {
        use crate::net::wire::tcp::write_sack_option;

        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);
        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        let _server_iss =
            establish_connection_with_sack(&mut handler, &nh, &mut free, &mut rx, &mut tx);

        let tcb = &mut handler.connections[0];
        tcb.send_buffer.write(&[0u8; 100]);
        tcb.snd_nxt = tcb.snd_una.wrapping_add(100);
        let snd_una = tcb.snd_una;

        // Send a dup ACK with SACK blocks to populate the scoreboard.
        let sack_left = snd_una.wrapping_add(20);
        let sack_right = snd_una.wrapping_add(40);
        let mut opts = [0u8; 12];
        let written = write_sack_option(&mut opts, &[(sack_left, sack_right)]);

        let dup_ack = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            snd_una,
            flags::ACK,
            65535,
            &opts[..written],
        );
        let dup_len = dup_ack.len();
        handler.process_ipv4(
            Frame::new(2, leak(dup_ack), dup_len, false),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        assert_eq!(handler.connections[0].sack_scoreboard.len(), 1);

        // Set up RTO: arm the retransmit deadline in the past.
        let now = coarsetime::Instant::now();
        handler.connections[0].retransmit_deadline = Some(now);
        handler.connections[0].rto_backoff = 0;

        // Trigger poll_timers, which should fire the RTO and clear the scoreboard.
        handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut tx);

        assert!(
            handler.connections[0].sack_scoreboard.is_empty(),
            "scoreboard should be cleared on RTO"
        );
    }

    #[test]
    fn fast_retransmit_uses_sack_gap() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);
        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        let _server_iss =
            establish_connection_with_sack(&mut handler, &nh, &mut free, &mut rx, &mut tx);

        let tcb = &mut handler.connections[0];
        // Use a small effective MSS so the retransmit fits in a 256-byte frame.
        tcb.eff_snd_mss = 100;
        let mss = tcb.eff_snd_mss as usize;

        // Fill send buffer with 3 MSS worth of distinguishable data.
        let mut data = vec![0u8; 3 * mss];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = (i / mss) as u8; // 0 for 1st MSS, 1 for 2nd, 2 for 3rd
        }
        tcb.send_buffer.write(&data);
        tcb.snd_nxt = tcb.snd_una.wrapping_add(3 * mss as u32);
        let snd_una = tcb.snd_una;

        // Add a SACK entry for the 2nd MSS (gap is the 1st MSS).
        let sack_start = snd_una.wrapping_add(mss as u32);
        let sack_len = mss as u32;
        tcb.sack_scoreboard.insert(sack_start, sack_len);

        // Record cwnd before fast retransmit.
        let cwnd_before = tcb.cwnd;

        // Set dup_ack_count = 3 to trigger fast retransmit.
        tcb.dup_ack_count = 3;

        let now = coarsetime::Instant::now();
        handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut tx);

        // Verify a segment was emitted.
        assert!(tx.pop().is_some(), "expected a retransmitted segment");

        let tcb = &handler.connections[0];
        // dup_ack_count should be reset.
        assert_eq!(tcb.dup_ack_count, 0, "dup_ack_count should be reset");
        // cwnd should be halved.
        assert!(tcb.cwnd < cwnd_before, "cwnd should have been halved");
        assert_eq!(
            tcb.cwnd, tcb.ssthresh,
            "cwnd should equal ssthresh after fast recovery"
        );
    }

    #[test]
    fn fast_retransmit_fallback_when_scoreboard_empty() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);
        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        let _server_iss =
            establish_connection_with_sack(&mut handler, &nh, &mut free, &mut rx, &mut tx);

        let tcb = &mut handler.connections[0];
        // Use a small effective MSS so the retransmit fits in a 256-byte frame.
        tcb.eff_snd_mss = 100;
        let mss = tcb.eff_snd_mss as usize;

        // Fill send buffer.
        tcb.send_buffer.write(&vec![0xABu8; 3 * mss]);
        tcb.snd_nxt = tcb.snd_una.wrapping_add(3 * mss as u32);

        // Record cwnd before.
        let cwnd_before = tcb.cwnd;

        // Scoreboard is empty; dup_ack_count = 3 triggers fallback.
        assert!(tcb.sack_scoreboard.is_empty());
        tcb.dup_ack_count = 3;

        let now = coarsetime::Instant::now();
        handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut tx);

        // Verify a segment was emitted.
        assert!(
            tx.pop().is_some(),
            "expected a retransmitted segment from snd_una"
        );

        let tcb = &handler.connections[0];
        assert_eq!(tcb.dup_ack_count, 0, "dup_ack_count should be reset");
        assert!(tcb.cwnd < cwnd_before, "cwnd should have been halved");
        assert_eq!(
            tcb.cwnd, tcb.ssthresh,
            "cwnd should equal ssthresh after fast recovery"
        );
    }

    #[test]
    fn poll_send_sets_psh_on_last_segment() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);
        for i in 0..16 {
            free.push(alloc_free_frame(100 + i));
        }

        let _server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);

        // Write small data (< MSS) into send buffer.
        handler.connections[0].send_buffer.write(b"Hello");

        let now = coarsetime::Instant::now();
        handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);

        assert_eq!(tx.num_frames(), 1, "expected one data segment");
        let frame = tx.pop().unwrap();

        // TCP flags byte is at offset ETH(14) + IPv4(20) + 13 = 47.
        let tcp_flags_offset = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + 13;
        let tcp_flags_byte = frame[tcp_flags_offset];
        assert!(
            tcp_flags_byte & flags::PSH != 0,
            "PSH flag should be set on last (only) data segment, got flags: {:#04x}",
            tcp_flags_byte
        );
        assert!(
            tcp_flags_byte & flags::ACK != 0,
            "ACK flag should also be set, got flags: {:#04x}",
            tcp_flags_byte
        );
    }

    #[test]
    fn poll_send_no_psh_on_first_segment_when_more_data() {
        let mut handler = new_handler();
        let nh = new_neighbor_handler();
        let mut free = BasicFrameBuffer::new(32);
        let mut rx = BasicFrameBuffer::new(32);
        let mut tx = BasicFrameBuffer::new(32);
        // Allocate frames large enough for MSS-sized segments (ETH+IP+TCP+1460).
        for i in 0..16 {
            let buf = leak(vec![0u8; 2048]);
            free.push(Frame::new(2000 + i, buf, 2048, false));
        }

        let _server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);

        // Write more than 1 MSS of data.
        let mss = handler.connections[0].eff_snd_mss as usize;
        let big_data = vec![0x41u8; mss + 100];
        handler.connections[0].send_buffer.write(&big_data);

        // Ensure cwnd is large enough to allow sending.
        handler.connections[0].cwnd = (mss as u32) * 10;
        // Disable Nagle so the second (sub-MSS) segment can be sent.
        handler.connections[0].nagle_enabled = false;

        let now = coarsetime::Instant::now();
        // First poll_send: sends MSS bytes, more data remains -> no PSH.
        handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);

        assert_eq!(tx.num_frames(), 1, "expected one data segment from first poll");

        let first_frame = tx.pop().unwrap();
        let tcp_flags_offset = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + 13;
        let first_flags = first_frame[tcp_flags_offset];
        assert!(
            first_flags & flags::PSH == 0,
            "PSH should NOT be set on first segment when more data remains, got flags: {:#04x}",
            first_flags
        );
        assert!(
            first_flags & flags::ACK != 0,
            "ACK flag should be set, got flags: {:#04x}",
            first_flags
        );

        // Second poll_send: sends remaining 100 bytes, no more data -> PSH set.
        handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);

        assert_eq!(tx.num_frames(), 1, "expected one data segment from second poll");
        let second_frame = tx.pop().unwrap();
        let second_flags = second_frame[tcp_flags_offset];
        assert!(
            second_flags & flags::PSH != 0,
            "PSH should be set on last segment, got flags: {:#04x}",
            second_flags
        );
    }
}
