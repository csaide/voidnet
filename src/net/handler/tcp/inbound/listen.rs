use coarsetime::Instant;
use std::collections::BTreeMap;

use rustc_hash::FxHashMap;
use slab::Slab;

use crate::{
    net::{
        socket::LocalQueue,
        wire::{
            ip::IpAddress,
            tcp::{flags, parse_mss, parse_sack_permitted, parse_timestamp, parse_window_scale},
        },
    },
    xdp::frame::FrameBuffer,
};

use super::super::congestion::CubicState;
use super::super::handler::{INITIAL_RTO_MS, TcpHandler};
use super::super::isn::IsnGenerator;
use super::super::listener::ListenEntry;
use super::super::recovery::{FRtoState, PrrState, SackRecovery};
use super::super::ring_buffer::RingBuffer;
use super::super::segment::SegmentBuilder;
use super::super::state::TcpState;
use super::super::tcb::{
    ConnectionId, DEFAULT_RCV_MSS, DEFAULT_RCV_WND, DEFAULT_RCV_WSCALE, TS_OPTION_LEN, Tcb,
};

impl TcpHandler {
    // --- LISTEN state processing (RFC §16.2) ---

    pub(super) fn process_listen<'umem>(
        connections: &mut Slab<Tcb>,
        connection_map: &mut FxHashMap<ConnectionId, usize>,
        listeners: &mut [ListenEntry],
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

            let tcb_id = tcb.id;
            let key = connections.insert(tcb);
            connection_map.insert(tcb_id, key);
            listeners[listener_idx].syn_received_count += 1;
        }

        // Step 4: Other → drop (frame returned by caller).
    }
}
