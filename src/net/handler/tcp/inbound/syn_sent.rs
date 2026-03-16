use coarsetime::Instant;

use crate::xdp::frame::FrameBuffer;

use crate::net::wire::tcp::{
    flags, parse_mss, parse_sack_permitted, parse_timestamp, parse_window_scale,
};

use super::super::handler::{INITIAL_RTO_MS, TcpHandler};
use super::super::segment::SegmentBuilder;
use super::super::state::TcpState;
use super::super::tcb::{DEFAULT_RCV_WND, TS_OPTION_LEN, Tcb, TcpEvent};
use super::PostAction;

impl TcpHandler {
    // --- SYN-SENT state processing (RFC §16.3) ---

    pub(super) fn process_syn_sent<'umem>(
        tcb: &mut Tcb,
        key: usize,
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
                return PostAction::RemoveConnection(key);
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
}
