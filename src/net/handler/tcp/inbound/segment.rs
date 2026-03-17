use crate::{
    net::wire::{ip::IpAddress, tcp::flags},
    xdp::frame::{Frame, FrameBuffer},
};

use coarsetime::Instant;

use super::super::handler::TcpHandler;
use super::super::options::ParsedOptions;
use super::super::segment::SegmentBuilder;
use super::super::send_tracker::SendReady;
use super::super::state::TcpState;
use super::super::tcb::ConnectionId;

/// Actions that must be performed after releasing the `&mut Tcb` borrow.
pub(super) enum PostAction {
    None,
    RemoveConnection(usize),
    RemoveAndDecrement(usize),
}

/// Check segment acceptability per RFC 9293 §3.10.7.4.
#[inline]
pub(crate) fn is_segment_acceptable(
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
    /// Unified segment processing for both IPv4 and IPv6.
    #[inline]
    pub(super) fn process_segment<'umem>(
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
        let Self {
            connections,
            connection_map,
            listeners,
            isn_generator,
            send_tracker,
            tx_offload,
            rx_offload: _,
            ..
        } = self;
        let tx_offload = *tx_offload;

        if let Some(&key) = connection_map.get(&conn_id)
            && let Some(tcb) = connections.get_mut(key)
        {
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
                        key,
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
                        key,
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
                    Self::process_established(
                        tcb,
                        key,
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
                    )
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
                    Self::process_teardown(
                        tcb,
                        key,
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
                    )
                }
                _ => {
                    rx_return.push(frame);
                    PostAction::None
                }
            };

            // Handle deferred actions after tcb borrow is released.
            match action {
                PostAction::RemoveConnection(rm_key) => {
                    if let Some(tcb) = connections.get(rm_key) {
                        connection_map.remove(&tcb.id);
                    }
                    send_tracker.unmark(rm_key);
                    connections.remove(rm_key);
                }
                PostAction::RemoveAndDecrement(rm_key) => {
                    if let Some(tcb) = connections.get(rm_key) {
                        Self::decrement_syn_received(listeners, &tcb.id);
                        connection_map.remove(&tcb.id);
                    }
                    send_tracker.unmark(rm_key);
                    connections.remove(rm_key);
                }
                PostAction::None => {
                    // Mark connection for send processing if it has pending work.
                    if let Some(tcb) = connections.get(key)
                        && (tcb.ack_pending
                            || tcb.pending_fin
                            || tcb.send_buffer.available() > 0
                            || tcb.ecn_cwr_sent
                            || tcb.persist_deadline.is_some()
                            || tcb.retransmit_deadline.is_some())
                    {
                        send_tracker.mark(SendReady(key));
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
                connection_map,
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
            if let Some(&key) = connection_map.get(&new_conn_id) {
                send_tracker.mark(SendReady(key));
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
}
