use crate::xdp::frame::FrameBuffer;

use super::super::handler::TcpHandler;
use super::super::listener::ListenEntry;
use super::super::segment::SegmentBuilder;
use super::super::state::TcpState;
use super::super::tcb::{DEFAULT_RCV_WND, Tcb, TcpEvent};

use super::segment::PostAction;

use crate::net::wire::tcp::flags;

impl TcpHandler {
    pub(super) fn process_syn_received<'umem>(
        tcb: &mut Tcb,
        key: usize,
        listeners: &mut [ListenEntry],
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
                return PostAction::RemoveAndDecrement(key);
            } else {
                // Active open → signal refused.
                tcb.event_queue.push(TcpEvent::ConnectionRefused);
                return PostAction::RemoveConnection(key);
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
                    // Push slab key to listener's accept_queue.
                    Self::push_to_accept_queue_on(listeners, &id, key);
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
}
