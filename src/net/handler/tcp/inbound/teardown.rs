use coarsetime::Instant;

use crate::{
    net::wire::tcp::flags,
    xdp::frame::{Frame, FrameBuffer},
};

use super::super::handler::TcpHandler;
use super::super::options::ParsedOptions;
use super::super::segment::SegmentBuilder;
use super::super::state::TcpState;
use super::super::tcb::{Tcb, TcpEvent};

use super::segment::{PostAction, is_segment_acceptable};

impl TcpHandler {
    // --- Connection teardown ---

    // --- Teardown state processing (FinWait1, FinWait2, CloseWait, Closing, LastAck, TimeWait) ---

    pub(super) fn process_teardown<'umem>(
        tcb: &mut Tcb,
        key: usize,
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
                return PostAction::RemoveConnection(key);
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
                if seg_flags & flags::ACK != 0
                    && let Some(fin_seq) = tcb.fin_seq
                    && crate::net::wire::tcp::seq_lt(fin_seq, seg_ack)
                {
                    rx_return.push(frame);
                    return PostAction::RemoveConnection(key);
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
