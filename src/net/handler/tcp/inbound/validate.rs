use coarsetime::Instant;

use crate::{
    net::{
        NeighborHandler,
        checksum::verify_tcp_checksum_ip,
        wire::{
            ethernet::EthernetFrame,
            ip::{IpAddress, IpVersion, Ipv4, Ipv4Header, Ipv6, Ipv6Header},
            tcp::{TCP_HEADER_LEN, TcpHeader},
        },
    },
    xdp::frame::{Frame, FrameBuffer},
};

use super::super::handler::TcpHandler;
use super::super::tcb::Tcb;

impl TcpHandler {
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

        self.process_inbound::<Ipv4>(
            frame,
            tcp_offset,
            &src_addr,
            &dst_addr,
            now,
            neighbor_handler,
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

        self.process_inbound::<Ipv6>(
            frame,
            tcp_offset,
            &src_addr,
            &dst_addr,
            now,
            neighbor_handler,
            free_frames,
            rx_return,
            tx_return,
        );
    }

    /// Generic inbound TCP segment processing, parameterized by IP version.
    #[inline]
    fn process_inbound<'umem, V: IpVersion>(
        &mut self,
        frame: Frame<'umem>,
        tcp_offset: usize,
        src_addr: &V::Address,
        dst_addr: &V::Address,
        now: Instant,
        neighbor_handler: &NeighborHandler,
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
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

        // Checksum verification.
        if !self.rx_offload {
            let tcp_segment = &frame[tcp_offset..];
            if !verify_tcp_checksum_ip::<V>(src_addr, dst_addr, tcp_segment) {
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

        // ECN bits extraction (version-specific via trait).
        let ecn_bits = V::get_ecn_bits(&frame, std::mem::size_of::<EthernetFrame>());

        let incoming_src: IpAddress = (*src_addr).into();
        let incoming_dst: IpAddress = (*dst_addr).into();
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
}
