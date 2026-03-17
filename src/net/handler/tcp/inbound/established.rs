use coarsetime::Instant;

use crate::{
    net::wire::tcp::flags,
    xdp::frame::{Frame, FrameBuffer},
};

use super::super::handler::TcpHandler;
use super::super::options::ParsedOptions;
use super::super::recovery::FRtoAction;
use super::super::segment::SegmentBuilder;
use super::super::state::TcpState;
use super::super::tcb::{Tcb, TcpEvent};

use super::segment::{PostAction, is_segment_acceptable};

impl TcpHandler {
    /// Handle RST in established state (RFC 5961).
    /// Returns PostAction indicating if connection should be removed.
    #[inline(never)]
    fn handle_rst_established<'umem>(
        tcb: &mut Tcb,
        key: usize,
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
            return PostAction::RemoveAndDecrement(key);
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

    pub(super) fn process_established<'umem>(
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
                key,
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
        if seg_flags & flags::FIN != 0 && seg_seq.wrapping_add(payload_len as u32) == tcb.rcv_nxt {
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
}
