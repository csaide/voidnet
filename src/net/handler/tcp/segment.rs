use crate::net::{
    checksum::compute_tcp_checksum_ip,
    wire::{
        ethernet::{EthernetFrame, MacAddress, write_ethernet_header},
        ip::{IpAddress, IpVersion, Ipv4, Ipv6},
        tcp::{
            TCP_HEADER_LEN, TcpHeader, flags, options, write_mss_option, write_sack_option,
            write_sack_permitted_option, write_timestamp_option, write_window_scale_option,
        },
    },
};
use crate::xdp::frame::{Frame, FrameBuffer};

const ETH_LEN: usize = size_of::<EthernetFrame>();

/// Stateless builder for outbound TCP segments.
///
/// All methods pop a frame from `free_frames`, write Ethernet + IP + TCP
/// headers, compute checksums (unless `tx_offload`), and push the result
/// to `tx_return`. The original received frame is the caller's
/// responsibility.
pub struct SegmentBuilder;

impl SegmentBuilder {
    /// Build a RST segment for the CLOSED state (no matching connection).
    ///
    /// Per RFC 9293 §3.10.7.1:
    /// - If ACK bit off: `<SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>`
    /// - If ACK bit on:  `<SEQ=SEG.ACK><CTL=RST>`
    #[inline]
    pub fn build_rst<'umem>(
        incoming_src_addr: IpAddress,
        incoming_dst_addr: IpAddress,
        incoming_src_port: u16,
        incoming_dst_port: u16,
        incoming_seq: u32,
        incoming_ack: u32,
        incoming_flags: u8,
        incoming_seg_len: u32,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        tx_offload: bool,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let (seq, ack, rst_flags) = if incoming_flags & flags::ACK == 0 {
            // ACK off: <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
            (
                0u32,
                incoming_seq.wrapping_add(incoming_seg_len),
                flags::RST | flags::ACK,
            )
        } else {
            // ACK on: <SEQ=SEG.ACK><CTL=RST>
            (incoming_ack, 0u32, flags::RST)
        };

        match (incoming_dst_addr, incoming_src_addr) {
            (IpAddress::V4(l), IpAddress::V4(r)) => {
                Self::build_segment::<Ipv4>(
                    l,
                    r,
                    incoming_dst_port,
                    incoming_src_port,
                    seq,
                    ack,
                    rst_flags,
                    0,
                    &[],
                    src_mac,
                    dst_mac,
                    tx_offload,
                    free_frames,
                    tx_return,
                );
            }
            (IpAddress::V6(l), IpAddress::V6(r)) => {
                Self::build_segment::<Ipv6>(
                    l,
                    r,
                    incoming_dst_port,
                    incoming_src_port,
                    seq,
                    ack,
                    rst_flags,
                    0,
                    &[],
                    src_mac,
                    dst_mac,
                    tx_offload,
                    free_frames,
                    tx_return,
                );
            }
            _ => {}
        }
    }

    /// Build a SYN segment (active open).
    #[inline]
    pub fn build_syn<'umem>(
        local_addr: IpAddress,
        remote_addr: IpAddress,
        local_port: u16,
        remote_port: u16,
        iss: u32,
        window: u16,
        mss: u16,
        wscale: u8,
        timestamp: Option<(u32, u32)>,
        sack_permitted: bool,
        ecn: bool,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        tx_offload: bool,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        // Max options: MSS(4) + NOP(1) + WSCALE(3) + NOP(1) + NOP(1) + TS(10) + SACK_PERM(2) = 22, pad to 24
        let mut opt_buf = [0u8; 24];
        let mut opt_len = write_mss_option(&mut opt_buf, mss);
        opt_buf[opt_len] = options::NOP;
        opt_len += 1;
        opt_len += write_window_scale_option(&mut opt_buf[opt_len..], wscale);
        if let Some((tsval, tsecr)) = timestamp {
            opt_buf[opt_len] = options::NOP;
            opt_len += 1;
            opt_buf[opt_len] = options::NOP;
            opt_len += 1;
            opt_len += write_timestamp_option(&mut opt_buf[opt_len..], tsval, tsecr);
        }
        if sack_permitted {
            opt_len += write_sack_permitted_option(&mut opt_buf[opt_len..]);
        }

        let syn_flags = if ecn {
            flags::SYN | flags::ECE | flags::CWR
        } else {
            flags::SYN
        };

        match (local_addr, remote_addr) {
            (IpAddress::V4(l), IpAddress::V4(r)) => {
                Self::build_segment::<Ipv4>(
                    l,
                    r,
                    local_port,
                    remote_port,
                    iss,
                    0,
                    syn_flags,
                    window,
                    &opt_buf[..opt_len],
                    src_mac,
                    dst_mac,
                    tx_offload,
                    free_frames,
                    tx_return,
                );
            }
            (IpAddress::V6(l), IpAddress::V6(r)) => {
                Self::build_segment::<Ipv6>(
                    l,
                    r,
                    local_port,
                    remote_port,
                    iss,
                    0,
                    syn_flags,
                    window,
                    &opt_buf[..opt_len],
                    src_mac,
                    dst_mac,
                    tx_offload,
                    free_frames,
                    tx_return,
                );
            }
            _ => {}
        }
    }

    /// Build a SYN-ACK segment (passive open response).
    #[inline]
    pub fn build_syn_ack<'umem>(
        local_addr: IpAddress,
        remote_addr: IpAddress,
        local_port: u16,
        remote_port: u16,
        iss: u32,
        ack: u32,
        window: u16,
        mss: u16,
        wscale: Option<u8>,
        timestamp: Option<(u32, u32)>,
        sack_permitted: bool,
        ecn: bool,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        tx_offload: bool,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let mut opt_buf = [0u8; 24];
        let mut opt_len = write_mss_option(&mut opt_buf, mss);
        if let Some(shift) = wscale {
            opt_buf[opt_len] = options::NOP;
            opt_len += 1;
            opt_len += write_window_scale_option(&mut opt_buf[opt_len..], shift);
        }
        if let Some((tsval, tsecr)) = timestamp {
            opt_buf[opt_len] = options::NOP;
            opt_len += 1;
            opt_buf[opt_len] = options::NOP;
            opt_len += 1;
            opt_len += write_timestamp_option(&mut opt_buf[opt_len..], tsval, tsecr);
        }
        if sack_permitted {
            opt_len += write_sack_permitted_option(&mut opt_buf[opt_len..]);
        }

        let syn_ack_flags = if ecn {
            flags::SYN | flags::ACK | flags::ECE
        } else {
            flags::SYN | flags::ACK
        };

        match (local_addr, remote_addr) {
            (IpAddress::V4(l), IpAddress::V4(r)) => {
                Self::build_segment::<Ipv4>(
                    l,
                    r,
                    local_port,
                    remote_port,
                    iss,
                    ack,
                    syn_ack_flags,
                    window,
                    &opt_buf[..opt_len],
                    src_mac,
                    dst_mac,
                    tx_offload,
                    free_frames,
                    tx_return,
                );
            }
            (IpAddress::V6(l), IpAddress::V6(r)) => {
                Self::build_segment::<Ipv6>(
                    l,
                    r,
                    local_port,
                    remote_port,
                    iss,
                    ack,
                    syn_ack_flags,
                    window,
                    &opt_buf[..opt_len],
                    src_mac,
                    dst_mac,
                    tx_offload,
                    free_frames,
                    tx_return,
                );
            }
            _ => {}
        }
    }

    /// Build a pure ACK segment (no data, no SYN/FIN).
    ///
    /// The `tcp_flags` parameter allows the caller to set additional flags
    /// (e.g. ECE) alongside the base ACK. Callers typically pass `flags::ACK`
    /// or `flags::ACK | flags::ECE`.
    #[inline]
    pub fn build_ack<'umem>(
        local_addr: IpAddress,
        remote_addr: IpAddress,
        local_port: u16,
        remote_port: u16,
        seq: u32,
        ack: u32,
        window: u16,
        tcp_flags: u8,
        timestamp: Option<(u32, u32)>,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        tx_offload: bool,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let mut ts_buf = [0u8; 12];
        let tcp_options: &[u8] = if let Some((tsval, tsecr)) = timestamp {
            ts_buf[0] = options::NOP;
            ts_buf[1] = options::NOP;
            write_timestamp_option(&mut ts_buf[2..], tsval, tsecr);
            &ts_buf
        } else {
            &[]
        };

        match (local_addr, remote_addr) {
            (IpAddress::V4(l), IpAddress::V4(r)) => {
                Self::build_segment::<Ipv4>(
                    l,
                    r,
                    local_port,
                    remote_port,
                    seq,
                    ack,
                    tcp_flags,
                    window,
                    tcp_options,
                    src_mac,
                    dst_mac,
                    tx_offload,
                    free_frames,
                    tx_return,
                );
            }
            (IpAddress::V6(l), IpAddress::V6(r)) => {
                Self::build_segment::<Ipv6>(
                    l,
                    r,
                    local_port,
                    remote_port,
                    seq,
                    ack,
                    tcp_flags,
                    window,
                    tcp_options,
                    src_mac,
                    dst_mac,
                    tx_offload,
                    free_frames,
                    tx_return,
                );
            }
            _ => {}
        }
    }

    /// Build a pure ACK segment with optional SACK blocks.
    ///
    /// When `sack_blocks` is empty this behaves identically to `build_ack`.
    /// SACK blocks are encoded per RFC 2018 using `write_sack_option`.
    #[inline]
    pub fn build_ack_with_sack<'umem>(
        local_addr: IpAddress,
        remote_addr: IpAddress,
        local_port: u16,
        remote_port: u16,
        seq: u32,
        ack: u32,
        window: u16,
        tcp_flags: u8,
        timestamp: Option<(u32, u32)>,
        sack_blocks: &[(u32, u32)],
        src_mac: MacAddress,
        dst_mac: MacAddress,
        tx_offload: bool,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        // Max options: NOP(1) + NOP(1) + TS(10) + SACK(2 + 4*8) = 44, but TCP
        // options are capped at 40 bytes. With timestamps (12 bytes) we have 28
        // bytes left = room for 3 SACK blocks (2 + 3*8 = 26). Without timestamps
        // we can fit 4 blocks (2 + 4*8 = 34).
        let mut opt_buf = [0u8; 40];
        let mut opt_len = 0usize;

        if let Some((tsval, tsecr)) = timestamp {
            opt_buf[0] = options::NOP;
            opt_buf[1] = options::NOP;
            opt_len = 2 + write_timestamp_option(&mut opt_buf[2..], tsval, tsecr);
        }

        if !sack_blocks.is_empty() {
            opt_len += write_sack_option(&mut opt_buf[opt_len..], sack_blocks);
        }

        let tcp_options = &opt_buf[..opt_len];

        match (local_addr, remote_addr) {
            (IpAddress::V4(l), IpAddress::V4(r)) => {
                Self::build_segment::<Ipv4>(
                    l,
                    r,
                    local_port,
                    remote_port,
                    seq,
                    ack,
                    tcp_flags,
                    window,
                    tcp_options,
                    src_mac,
                    dst_mac,
                    tx_offload,
                    free_frames,
                    tx_return,
                );
            }
            (IpAddress::V6(l), IpAddress::V6(r)) => {
                Self::build_segment::<Ipv6>(
                    l,
                    r,
                    local_port,
                    remote_port,
                    seq,
                    ack,
                    tcp_flags,
                    window,
                    tcp_options,
                    src_mac,
                    dst_mac,
                    tx_offload,
                    free_frames,
                    tx_return,
                );
            }
            _ => {}
        }
    }

    /// Build a FIN-ACK segment (no data). Used for graceful connection close.
    #[inline]
    pub fn build_fin_ack<'umem>(
        local_addr: IpAddress,
        remote_addr: IpAddress,
        local_port: u16,
        remote_port: u16,
        seq: u32,
        ack: u32,
        window: u16,
        timestamp: Option<(u32, u32)>,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        tx_offload: bool,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let mut ts_buf = [0u8; 12];
        let tcp_options: &[u8] = if let Some((tsval, tsecr)) = timestamp {
            ts_buf[0] = options::NOP;
            ts_buf[1] = options::NOP;
            write_timestamp_option(&mut ts_buf[2..], tsval, tsecr);
            &ts_buf
        } else {
            &[]
        };

        match (local_addr, remote_addr) {
            (IpAddress::V4(l), IpAddress::V4(r)) => {
                Self::build_segment::<Ipv4>(
                    l,
                    r,
                    local_port,
                    remote_port,
                    seq,
                    ack,
                    flags::ACK | flags::FIN,
                    window,
                    tcp_options,
                    src_mac,
                    dst_mac,
                    tx_offload,
                    free_frames,
                    tx_return,
                );
            }
            (IpAddress::V6(l), IpAddress::V6(r)) => {
                Self::build_segment::<Ipv6>(
                    l,
                    r,
                    local_port,
                    remote_port,
                    seq,
                    ack,
                    flags::ACK | flags::FIN,
                    window,
                    tcp_options,
                    src_mac,
                    dst_mac,
                    tx_offload,
                    free_frames,
                    tx_return,
                );
            }
            _ => {}
        }
    }

    /// Build a data segment with payload (ACK flag set).
    #[inline]
    pub fn build_data<'umem>(
        local_addr: IpAddress,
        remote_addr: IpAddress,
        local_port: u16,
        remote_port: u16,
        seq: u32,
        ack: u32,
        window: u16,
        payload: &[u8],
        timestamp: Option<(u32, u32)>,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        tx_offload: bool,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let mut ts_buf = [0u8; 12];
        let tcp_options: &[u8] = if let Some((tsval, tsecr)) = timestamp {
            ts_buf[0] = options::NOP;
            ts_buf[1] = options::NOP;
            write_timestamp_option(&mut ts_buf[2..], tsval, tsecr);
            &ts_buf
        } else {
            &[]
        };

        match (local_addr, remote_addr) {
            (IpAddress::V4(l), IpAddress::V4(r)) => {
                Self::build_data_segment::<Ipv4>(
                    l,
                    r,
                    local_port,
                    remote_port,
                    seq,
                    ack,
                    flags::ACK,
                    window,
                    payload,
                    tcp_options,
                    src_mac,
                    dst_mac,
                    tx_offload,
                    free_frames,
                    tx_return,
                );
            }
            (IpAddress::V6(l), IpAddress::V6(r)) => {
                Self::build_data_segment::<Ipv6>(
                    l,
                    r,
                    local_port,
                    remote_port,
                    seq,
                    ack,
                    flags::ACK,
                    window,
                    payload,
                    tcp_options,
                    src_mac,
                    dst_mac,
                    tx_offload,
                    free_frames,
                    tx_return,
                );
            }
            _ => {}
        }
    }

    /// Build a data segment from two contiguous slices (zero-copy from ring buffer).
    #[inline]
    pub fn build_data_from_slices<'umem>(
        local_addr: IpAddress,
        remote_addr: IpAddress,
        local_port: u16,
        remote_port: u16,
        seq: u32,
        ack: u32,
        window: u16,
        payload: (&[u8], &[u8]),
        tcp_flags: u8,
        ecn_ect: bool,
        timestamp: Option<(u32, u32)>,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        tx_offload: bool,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        // Same options construction as build_data
        let mut ts_buf = [0u8; 12];
        let tcp_options: &[u8] = if let Some((tsval, tsecr)) = timestamp {
            ts_buf[0] = options::NOP;
            ts_buf[1] = options::NOP;
            write_timestamp_option(&mut ts_buf[2..], tsval, tsecr);
            &ts_buf
        } else {
            &[]
        };

        match (local_addr, remote_addr) {
            (IpAddress::V4(l), IpAddress::V4(r)) => {
                Self::build_data_segment_slices::<Ipv4>(
                    l,
                    r,
                    local_port,
                    remote_port,
                    seq,
                    ack,
                    tcp_flags,
                    window,
                    payload,
                    tcp_options,
                    ecn_ect,
                    src_mac,
                    dst_mac,
                    tx_offload,
                    free_frames,
                    tx_return,
                );
            }
            (IpAddress::V6(l), IpAddress::V6(r)) => {
                Self::build_data_segment_slices::<Ipv6>(
                    l,
                    r,
                    local_port,
                    remote_port,
                    seq,
                    ack,
                    tcp_flags,
                    window,
                    payload,
                    tcp_options,
                    ecn_ect,
                    src_mac,
                    dst_mac,
                    tx_offload,
                    free_frames,
                    tx_return,
                );
            }
            _ => {}
        }
    }

    // --- Internal helpers ---

    #[inline]
    fn build_segment<'umem, V: IpVersion>(
        src_ip: V::Address,
        dst_ip: V::Address,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        tcp_flags: u8,
        window: u16,
        tcp_options: &[u8],
        src_mac: MacAddress,
        dst_mac: MacAddress,
        tx_offload: bool,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let Some(mut frame) = free_frames.pop() else {
            return;
        };

        let opt_padded_len = (tcp_options.len() + 3) & !3;
        let tcp_header_len = TCP_HEADER_LEN + opt_padded_len;
        let data_offset = (tcp_header_len / 4) as u8;
        let frame_len = ETH_LEN + V::IP_HEADER_LEN + tcp_header_len;

        if frame.capacity() < frame_len {
            free_frames.push(frame);
            return;
        }

        unsafe { frame.set_len(frame_len) };

        // Ethernet header.
        write_ethernet_header(&mut frame, dst_mac, src_mac, V::ETHER_TYPE);

        // IP header (version-specific via trait).
        V::write_ip_header(&mut frame, &src_ip, &dst_ip, tcp_header_len);

        // TCP header.
        let tcp_offset = ETH_LEN + V::IP_HEADER_LEN;
        Self::write_tcp_header(
            &mut frame,
            tcp_offset,
            src_port,
            dst_port,
            seq,
            ack,
            data_offset,
            tcp_flags,
            window,
            tcp_options,
            opt_padded_len,
        );

        // TCP checksum.
        if !tx_offload {
            let tcp_bytes = &frame[tcp_offset..frame_len];
            let checksum = compute_tcp_checksum_ip::<V>(&src_ip, &dst_ip, tcp_bytes, &[]);
            frame[tcp_offset + 16] = checksum[0];
            frame[tcp_offset + 17] = checksum[1];
        }

        tx_return.push(frame);
    }

    #[inline]
    fn build_data_segment<'umem, V: IpVersion>(
        src_ip: V::Address,
        dst_ip: V::Address,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        tcp_flags: u8,
        window: u16,
        payload: &[u8],
        tcp_options: &[u8],
        src_mac: MacAddress,
        dst_mac: MacAddress,
        tx_offload: bool,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let Some(mut frame) = free_frames.pop() else {
            return;
        };

        let opt_padded_len = (tcp_options.len() + 3) & !3;
        let tcp_header_len = TCP_HEADER_LEN + opt_padded_len;
        let data_offset = (tcp_header_len / 4) as u8;
        let frame_len = ETH_LEN + V::IP_HEADER_LEN + tcp_header_len + payload.len();

        if frame.capacity() < frame_len {
            free_frames.push(frame);
            return;
        }

        unsafe { frame.set_len(frame_len) };

        // Ethernet header.
        write_ethernet_header(&mut frame, dst_mac, src_mac, V::ETHER_TYPE);

        // IP header (version-specific via trait).
        V::write_ip_header(&mut frame, &src_ip, &dst_ip, tcp_header_len + payload.len());

        // TCP header.
        let tcp_offset = ETH_LEN + V::IP_HEADER_LEN;
        Self::write_tcp_header(
            &mut frame,
            tcp_offset,
            src_port,
            dst_port,
            seq,
            ack,
            data_offset,
            tcp_flags,
            window,
            tcp_options,
            opt_padded_len,
        );

        // Copy payload.
        let payload_offset = tcp_offset + tcp_header_len;
        frame[payload_offset..payload_offset + payload.len()].copy_from_slice(payload);

        // TCP checksum — must cover header (including options) + payload.
        if !tx_offload {
            let checksum = compute_tcp_checksum_ip::<V>(
                &src_ip,
                &dst_ip,
                &frame[tcp_offset..tcp_offset + tcp_header_len],
                payload,
            );
            frame[tcp_offset + 16] = checksum[0];
            frame[tcp_offset + 17] = checksum[1];
        }

        tx_return.push(frame);
    }

    #[inline]
    fn build_data_segment_slices<'umem, V: IpVersion>(
        src_ip: V::Address,
        dst_ip: V::Address,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        tcp_flags: u8,
        window: u16,
        payload: (&[u8], &[u8]),
        tcp_options: &[u8],
        ecn_ect: bool,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        tx_offload: bool,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let Some(mut frame) = free_frames.pop() else {
            return;
        };

        let payload_len = payload.0.len() + payload.1.len();
        let opt_padded_len = (tcp_options.len() + 3) & !3;
        let tcp_header_len = TCP_HEADER_LEN + opt_padded_len;
        let data_offset = (tcp_header_len / 4) as u8;
        let frame_len = ETH_LEN + V::IP_HEADER_LEN + tcp_header_len + payload_len;

        if frame.capacity() < frame_len {
            free_frames.push(frame);
            return;
        }

        unsafe { frame.set_len(frame_len) };

        // Ethernet header.
        write_ethernet_header(&mut frame, dst_mac, src_mac, V::ETHER_TYPE);

        // IP header (version-specific via trait).
        V::write_ip_header(&mut frame, &src_ip, &dst_ip, tcp_header_len + payload_len);

        // Set ECN ECT(0) if requested (must be after write_ip_header;
        // IPv4 impl recomputes the header checksum).
        if ecn_ect {
            V::set_ecn_ect(&mut frame, ETH_LEN);
        }

        // TCP header.
        let tcp_offset = ETH_LEN + V::IP_HEADER_LEN;
        Self::write_tcp_header(
            &mut frame,
            tcp_offset,
            src_port,
            dst_port,
            seq,
            ack,
            data_offset,
            tcp_flags,
            window,
            tcp_options,
            opt_padded_len,
        );

        // Copy payload (two slices).
        let payload_start = tcp_offset + tcp_header_len;
        frame[payload_start..payload_start + payload.0.len()].copy_from_slice(payload.0);
        if !payload.1.is_empty() {
            let p2_start = payload_start + payload.0.len();
            frame[p2_start..p2_start + payload.1.len()].copy_from_slice(payload.1);
        }

        // TCP checksum — computed from the frame after both slices are written.
        if !tx_offload {
            let checksum = compute_tcp_checksum_ip::<V>(
                &src_ip,
                &dst_ip,
                &frame[tcp_offset..tcp_offset + tcp_header_len],
                &frame[payload_start..frame_len],
            );
            frame[tcp_offset + 16] = checksum[0];
            frame[tcp_offset + 17] = checksum[1];
        }

        tx_return.push(frame);
    }

    #[inline(always)]
    fn write_tcp_header(
        frame: &mut Frame<'_>,
        offset: usize,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        data_offset: u8,
        tcp_flags: u8,
        window: u16,
        tcp_options: &[u8],
        opt_padded_len: usize,
    ) {
        let hdr = TcpHeader::new(
            src_port,
            dst_port,
            seq,
            ack,
            data_offset,
            tcp_flags,
            window,
            [0, 0], // checksum placeholder
            0,      // urgent pointer
        );
        // Write the 20-byte base header.
        let hdr_bytes = unsafe {
            std::slice::from_raw_parts(&hdr as *const TcpHeader as *const u8, TCP_HEADER_LEN)
        };
        frame[offset..offset + TCP_HEADER_LEN].copy_from_slice(hdr_bytes);

        // Write options + padding.
        if !tcp_options.is_empty() {
            let opt_start = offset + TCP_HEADER_LEN;
            frame[opt_start..opt_start + tcp_options.len()].copy_from_slice(tcp_options);
            // Zero-pad remaining bytes to 4-byte boundary.
            for i in tcp_options.len()..opt_padded_len {
                frame[opt_start + i] = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::checksum::verify_tcp_checksum_ip;
    use crate::net::wire::ip::Ipv4;
    use crate::net::wire::ip::{
        IPV4_MIN_HEADER_LEN, IPV6_HEADER_LEN, IpAddress, Ipv4Address, Ipv4Header, Ipv6,
        Ipv6Address, Ipv6Header,
    };
    use crate::xdp::frame::{BasicFrameBuffer, Frame};

    const ETH_HEADER_LEN: usize = 14;

    fn alloc_free_frame(addr: u64) -> Frame<'static> {
        let buf = Box::leak(vec![0u8; 2048].into_boxed_slice());
        Frame::new(addr, buf, 2048, false)
    }

    #[test]
    fn build_data_ipv4() {
        let mut free = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        free.push(alloc_free_frame(100));

        let payload = b"Hello, TCP!";
        let src_mac = MacAddress::new([0xAA; 6]);
        let dst_mac = MacAddress::new([0xBB; 6]);

        SegmentBuilder::build_data(
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])),
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 2])),
            8080,
            80,
            1000,
            500,
            65535,
            payload,
            None,
            src_mac,
            dst_mac,
            false,
            &mut free,
            &mut tx,
        );

        assert_eq!(tx.num_frames(), 1, "data segment built");
        assert_eq!(free.num_frames(), 0, "free frame consumed");

        let frame = tx.pop().unwrap();
        // ETH(14) + IPv4(20) + TCP(20) + payload(11) = 65
        assert_eq!(frame.len(), 65);

        // Verify payload is at the end.
        let payload_start = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + TCP_HEADER_LEN;
        assert_eq!(&frame[payload_start..frame.len()], payload);

        // Verify TCP checksum.
        let tcp_offset = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        let ip = Ipv4Header::from_bytes(&frame);
        assert!(verify_tcp_checksum_ip::<Ipv4>(
            &ip.src_addr,
            &ip.dst_addr,
            &frame[tcp_offset..]
        ));
    }

    #[test]
    fn build_fin_ack_ipv4() {
        let mut free = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        free.push(alloc_free_frame(100));

        SegmentBuilder::build_fin_ack(
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])),
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 2])),
            80,
            12345,
            5000,
            3000,
            65535,
            None,
            MacAddress::new([0xAA; 6]),
            MacAddress::new([0xBB; 6]),
            false,
            &mut free,
            &mut tx,
        );

        assert_eq!(tx.num_frames(), 1, "FIN-ACK segment built");
        assert_eq!(free.num_frames(), 0, "free frame consumed");

        let frame = tx.pop().unwrap();
        let tcp_offset = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        let tcp = unsafe { TcpHeader::from_bytes_at(&frame, tcp_offset) };
        assert_eq!(tcp.flags(), flags::ACK | flags::FIN);
        assert_eq!(tcp.seq_num(), 5000);
        assert_eq!(tcp.ack_num(), 3000);
    }

    #[test]
    fn build_data_frame_too_small() {
        // Frame capacity too small for the segment.
        let buf = Box::leak(vec![0u8; 40].into_boxed_slice());
        let frame = Frame::new(0, buf, 40, false);
        let mut free = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        free.push(frame);

        SegmentBuilder::build_data(
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])),
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 2])),
            8080,
            80,
            1000,
            500,
            65535,
            b"payload",
            None,
            MacAddress::new([0xAA; 6]),
            MacAddress::new([0xBB; 6]),
            false,
            &mut free,
            &mut tx,
        );

        assert_eq!(tx.num_frames(), 0, "no segment built");
        assert_eq!(free.num_frames(), 1, "frame returned to free");
    }

    #[test]
    fn build_data_no_free_frames() {
        let mut free = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        SegmentBuilder::build_data(
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])),
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 2])),
            8080,
            80,
            1000,
            500,
            65535,
            b"payload",
            None,
            MacAddress::new([0xAA; 6]),
            MacAddress::new([0xBB; 6]),
            false,
            &mut free,
            &mut tx,
        );

        assert_eq!(tx.num_frames(), 0, "no segment built");
    }

    #[test]
    fn build_ack_with_sack_blocks_ipv4() {
        let mut free = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        free.push(alloc_free_frame(100));

        let sack_blocks = [(2000u32, 2500u32), (3000u32, 3500u32)];
        let src_mac = MacAddress::new([0xAA; 6]);
        let dst_mac = MacAddress::new([0xBB; 6]);

        SegmentBuilder::build_ack_with_sack(
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])),
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 2])),
            8080,
            80,
            1000,
            500,
            65535,
            flags::ACK,
            None,
            &sack_blocks,
            src_mac,
            dst_mac,
            false,
            &mut free,
            &mut tx,
        );

        assert_eq!(tx.num_frames(), 1, "ACK+SACK segment built");
        assert_eq!(free.num_frames(), 0, "free frame consumed");

        let frame = tx.pop().unwrap();
        let tcp_offset = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        let tcp = unsafe { TcpHeader::from_bytes_at(&frame, tcp_offset) };
        assert_eq!(tcp.flags(), flags::ACK);
        assert_eq!(tcp.seq_num(), 1000);
        assert_eq!(tcp.ack_num(), 500);

        // data_offset should indicate options are present.
        // SACK option: 2 + 2*8 = 18 bytes, padded to 20.
        // TCP header = 20 + 20 = 40, data_offset = 10.
        assert_eq!(tcp.data_offset(), 10);

        // Verify SACK option bytes: kind=5, len=18, then two (left,right) pairs.
        let opt_start = tcp_offset + TCP_HEADER_LEN;
        assert_eq!(frame[opt_start], 5); // SACK kind
        assert_eq!(frame[opt_start + 1], 18); // SACK length: 2 + 2*8
        // First block: left=2000, right=2500.
        assert_eq!(
            u32::from_be_bytes([
                frame[opt_start + 2],
                frame[opt_start + 3],
                frame[opt_start + 4],
                frame[opt_start + 5]
            ]),
            2000
        );
        assert_eq!(
            u32::from_be_bytes([
                frame[opt_start + 6],
                frame[opt_start + 7],
                frame[opt_start + 8],
                frame[opt_start + 9]
            ]),
            2500
        );

        // Verify TCP checksum.
        let ip = Ipv4Header::from_bytes(&frame);
        assert!(verify_tcp_checksum_ip::<Ipv4>(
            &ip.src_addr,
            &ip.dst_addr,
            &frame[tcp_offset..]
        ));
    }

    #[test]
    fn build_ack_with_sack_and_timestamp_ipv4() {
        let mut free = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        free.push(alloc_free_frame(100));

        let sack_blocks = [(5000u32, 5100u32)];

        SegmentBuilder::build_ack_with_sack(
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])),
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 2])),
            8080,
            80,
            1000,
            500,
            65535,
            flags::ACK,
            Some((100, 200)),
            &sack_blocks,
            MacAddress::new([0xAA; 6]),
            MacAddress::new([0xBB; 6]),
            false,
            &mut free,
            &mut tx,
        );

        assert_eq!(tx.num_frames(), 1, "ACK+TS+SACK segment built");

        let frame = tx.pop().unwrap();
        let tcp_offset = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        let tcp = unsafe { TcpHeader::from_bytes_at(&frame, tcp_offset) };
        assert_eq!(tcp.flags(), flags::ACK);

        // Options: NOP(1)+NOP(1)+TS(10) + SACK(2+1*8=10) = 22, padded to 24.
        // data_offset = (20 + 24) / 4 = 11.
        assert_eq!(tcp.data_offset(), 11);

        // Verify timestamp: NOP, NOP, kind=8, len=10.
        let opt_start = tcp_offset + TCP_HEADER_LEN;
        assert_eq!(frame[opt_start], 1); // NOP
        assert_eq!(frame[opt_start + 1], 1); // NOP
        assert_eq!(frame[opt_start + 2], 8); // TS kind
        assert_eq!(frame[opt_start + 3], 10); // TS len

        // SACK follows at offset 12.
        assert_eq!(frame[opt_start + 12], 5); // SACK kind
        assert_eq!(frame[opt_start + 13], 10); // SACK len: 2 + 1*8

        // Verify TCP checksum.
        let ip = Ipv4Header::from_bytes(&frame);
        assert!(verify_tcp_checksum_ip::<Ipv4>(
            &ip.src_addr,
            &ip.dst_addr,
            &frame[tcp_offset..]
        ));
    }

    #[test]
    fn build_data_from_slices_produces_frame() {
        let mut free = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        free.push(alloc_free_frame(100));

        SegmentBuilder::build_data_from_slices(
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])),
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 2])),
            1234,
            80,
            100,
            200,
            65535,
            (b"hel", b"lo"),
            flags::ACK,
            false,
            None,
            MacAddress::broadcast(),
            MacAddress::broadcast(),
            false,
            &mut free,
            &mut tx,
        );

        assert_eq!(tx.num_frames(), 1);

        let frame = tx.pop().unwrap();
        // ETH(14) + IPv4(20) + TCP(20) + payload(5) = 59
        assert_eq!(frame.len(), 59);

        // Verify payload is correctly assembled.
        let payload_start = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + TCP_HEADER_LEN;
        assert_eq!(&frame[payload_start..frame.len()], b"hello");

        // Verify TCP checksum.
        let tcp_offset = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        let ip = Ipv4Header::from_bytes(&frame);
        assert!(verify_tcp_checksum_ip::<Ipv4>(
            &ip.src_addr,
            &ip.dst_addr,
            &frame[tcp_offset..]
        ));
    }

    #[test]
    fn build_ack_with_empty_sack_blocks() {
        let mut free = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        free.push(alloc_free_frame(100));

        SegmentBuilder::build_ack_with_sack(
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])),
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 2])),
            8080,
            80,
            1000,
            500,
            65535,
            flags::ACK,
            None,
            &[],
            MacAddress::new([0xAA; 6]),
            MacAddress::new([0xBB; 6]),
            false,
            &mut free,
            &mut tx,
        );

        assert_eq!(tx.num_frames(), 1, "plain ACK segment built");

        let frame = tx.pop().unwrap();
        // No options: ETH(14) + IPv4(20) + TCP(20) = 54.
        assert_eq!(frame.len(), 54);
        let tcp_offset = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        let tcp = unsafe { TcpHeader::from_bytes_at(&frame, tcp_offset) };
        assert_eq!(tcp.data_offset(), 5); // No options.
    }

    // ---------------------------------------------------------------
    // build_rst tests
    // ---------------------------------------------------------------

    #[test]
    fn build_rst_ack_off_sends_rst_ack() {
        // RFC 9293 §3.10.7.1: ACK off → <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
        let mut free = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        free.push(alloc_free_frame(100));

        let incoming_seq = 1000u32;
        let incoming_seg_len = 50u32;

        SegmentBuilder::build_rst(
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 2])), // incoming src
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])), // incoming dst
            80,                                             // incoming src port
            8080,                                           // incoming dst port
            incoming_seq,
            0,          // incoming ack (irrelevant when ACK off)
            flags::SYN, // ACK bit is off
            incoming_seg_len,
            MacAddress::new([0xAA; 6]),
            MacAddress::new([0xBB; 6]),
            false,
            &mut free,
            &mut tx,
        );

        assert_eq!(tx.num_frames(), 1, "RST segment built");
        assert_eq!(free.num_frames(), 0, "free frame consumed");

        let frame = tx.pop().unwrap();
        // ETH(14) + IPv4(20) + TCP(20) = 54
        assert_eq!(frame.len(), 54);

        let tcp_offset = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        let tcp = unsafe { TcpHeader::from_bytes_at(&frame, tcp_offset) };
        assert_eq!(tcp.flags(), flags::RST | flags::ACK);
        assert_eq!(tcp.seq_num(), 0);
        assert_eq!(tcp.ack_num(), incoming_seq.wrapping_add(incoming_seg_len));
        // Ports are swapped: RST goes back to the sender.
        assert_eq!(tcp.src_port(), 8080);
        assert_eq!(tcp.dst_port(), 80);

        // Verify TCP checksum.
        let ip = Ipv4Header::from_bytes(&frame);
        assert!(verify_tcp_checksum_ip::<Ipv4>(
            &ip.src_addr,
            &ip.dst_addr,
            &frame[tcp_offset..]
        ));
    }

    #[test]
    fn build_rst_ack_on_sends_rst_only() {
        // RFC 9293 §3.10.7.1: ACK on → <SEQ=SEG.ACK><CTL=RST>
        let mut free = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        free.push(alloc_free_frame(100));

        let incoming_ack = 5000u32;

        SegmentBuilder::build_rst(
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 2])),
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])),
            80,
            8080,
            1000,
            incoming_ack,
            flags::ACK, // ACK bit is on
            0,
            MacAddress::new([0xAA; 6]),
            MacAddress::new([0xBB; 6]),
            false,
            &mut free,
            &mut tx,
        );

        assert_eq!(tx.num_frames(), 1);

        let frame = tx.pop().unwrap();
        let tcp_offset = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        let tcp = unsafe { TcpHeader::from_bytes_at(&frame, tcp_offset) };
        assert_eq!(tcp.flags(), flags::RST);
        assert_eq!(tcp.seq_num(), incoming_ack);
        assert_eq!(tcp.ack_num(), 0);

        let ip = Ipv4Header::from_bytes(&frame);
        assert!(verify_tcp_checksum_ip::<Ipv4>(
            &ip.src_addr,
            &ip.dst_addr,
            &frame[tcp_offset..]
        ));
    }

    // ---------------------------------------------------------------
    // build_syn tests
    // ---------------------------------------------------------------

    #[test]
    fn build_syn_all_options_ipv4() {
        let mut free = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        free.push(alloc_free_frame(100));

        let iss = 12345u32;
        let mss = 1460u16;
        let wscale = 7u8;
        let tsval = 1000u32;
        let tsecr = 0u32;

        SegmentBuilder::build_syn(
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])),
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 2])),
            8080,
            80,
            iss,
            65535,
            mss,
            wscale,
            Some((tsval, tsecr)),
            true, // sack_permitted
            false,
            MacAddress::new([0xAA; 6]),
            MacAddress::new([0xBB; 6]),
            false,
            &mut free,
            &mut tx,
        );

        assert_eq!(tx.num_frames(), 1, "SYN segment built");

        let frame = tx.pop().unwrap();
        let tcp_offset = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        let tcp = unsafe { TcpHeader::from_bytes_at(&frame, tcp_offset) };
        assert_eq!(tcp.flags(), flags::SYN);
        assert_eq!(tcp.seq_num(), iss);
        assert_eq!(tcp.ack_num(), 0);
        assert_eq!(tcp.src_port(), 8080);
        assert_eq!(tcp.dst_port(), 80);
        assert_eq!(tcp.window(), 65535);

        // Options: MSS(4) + NOP(1) + WSCALE(3) + NOP(1) + NOP(1) + TS(10) + SACK_PERM(2) = 22, padded to 24
        // data_offset = (20 + 24) / 4 = 11
        assert_eq!(tcp.data_offset(), 11);

        let opt_start = tcp_offset + TCP_HEADER_LEN;
        // MSS option: kind=2, len=4, value=1460
        assert_eq!(frame[opt_start], options::MSS);
        assert_eq!(frame[opt_start + 1], 4);
        assert_eq!(
            u16::from_be_bytes([frame[opt_start + 2], frame[opt_start + 3]]),
            mss
        );
        // NOP
        assert_eq!(frame[opt_start + 4], options::NOP);
        // Window Scale: kind=3, len=3, shift=7
        assert_eq!(frame[opt_start + 5], options::WINDOW_SCALE);
        assert_eq!(frame[opt_start + 6], 3);
        assert_eq!(frame[opt_start + 7], wscale);
        // NOP, NOP
        assert_eq!(frame[opt_start + 8], options::NOP);
        assert_eq!(frame[opt_start + 9], options::NOP);
        // Timestamp: kind=8, len=10
        assert_eq!(frame[opt_start + 10], 8); // TS kind
        assert_eq!(frame[opt_start + 11], 10); // TS len
        assert_eq!(
            u32::from_be_bytes([
                frame[opt_start + 12],
                frame[opt_start + 13],
                frame[opt_start + 14],
                frame[opt_start + 15]
            ]),
            tsval
        );
        assert_eq!(
            u32::from_be_bytes([
                frame[opt_start + 16],
                frame[opt_start + 17],
                frame[opt_start + 18],
                frame[opt_start + 19]
            ]),
            tsecr
        );
        // SACK Permitted: kind=4, len=2
        assert_eq!(frame[opt_start + 20], options::SACK_PERMITTED);
        assert_eq!(frame[opt_start + 21], 2);

        let ip = Ipv4Header::from_bytes(&frame);
        assert!(verify_tcp_checksum_ip::<Ipv4>(
            &ip.src_addr,
            &ip.dst_addr,
            &frame[tcp_offset..]
        ));
    }

    #[test]
    fn build_syn_with_ecn_ipv4() {
        let mut free = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        free.push(alloc_free_frame(100));

        SegmentBuilder::build_syn(
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])),
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 2])),
            8080,
            80,
            1000,
            65535,
            1460,
            7,
            None,
            false,
            true, // ecn
            MacAddress::new([0xAA; 6]),
            MacAddress::new([0xBB; 6]),
            false,
            &mut free,
            &mut tx,
        );

        assert_eq!(tx.num_frames(), 1);

        let frame = tx.pop().unwrap();
        let tcp_offset = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        let tcp = unsafe { TcpHeader::from_bytes_at(&frame, tcp_offset) };
        assert_eq!(tcp.flags(), flags::SYN | flags::ECE | flags::CWR);

        let ip = Ipv4Header::from_bytes(&frame);
        assert!(verify_tcp_checksum_ip::<Ipv4>(
            &ip.src_addr,
            &ip.dst_addr,
            &frame[tcp_offset..]
        ));
    }

    // ---------------------------------------------------------------
    // build_syn_ack tests
    // ---------------------------------------------------------------

    #[test]
    fn build_syn_ack_with_wscale_ipv4() {
        let mut free = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        free.push(alloc_free_frame(100));

        let iss = 9999u32;
        let ack = 10000u32;

        SegmentBuilder::build_syn_ack(
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])),
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 2])),
            80,
            8080,
            iss,
            ack,
            65535,
            1460,
            Some(7),         // wscale
            Some((100, 50)), // timestamp
            true,            // sack_permitted
            false,           // ecn
            MacAddress::new([0xAA; 6]),
            MacAddress::new([0xBB; 6]),
            false,
            &mut free,
            &mut tx,
        );

        assert_eq!(tx.num_frames(), 1, "SYN-ACK segment built");

        let frame = tx.pop().unwrap();
        let tcp_offset = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        let tcp = unsafe { TcpHeader::from_bytes_at(&frame, tcp_offset) };
        assert_eq!(tcp.flags(), flags::SYN | flags::ACK);
        assert_eq!(tcp.seq_num(), iss);
        assert_eq!(tcp.ack_num(), ack);
        assert_eq!(tcp.src_port(), 80);
        assert_eq!(tcp.dst_port(), 8080);

        // Options: MSS(4) + NOP(1) + WSCALE(3) + NOP(1) + NOP(1) + TS(10) + SACK_PERM(2) = 22, padded to 24
        assert_eq!(tcp.data_offset(), 11);

        let opt_start = tcp_offset + TCP_HEADER_LEN;
        // MSS
        assert_eq!(frame[opt_start], options::MSS);
        assert_eq!(frame[opt_start + 1], 4);
        assert_eq!(
            u16::from_be_bytes([frame[opt_start + 2], frame[opt_start + 3]]),
            1460
        );

        let ip = Ipv4Header::from_bytes(&frame);
        assert!(verify_tcp_checksum_ip::<Ipv4>(
            &ip.src_addr,
            &ip.dst_addr,
            &frame[tcp_offset..]
        ));
    }

    #[test]
    fn build_syn_ack_without_wscale_ipv4() {
        let mut free = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        free.push(alloc_free_frame(100));

        SegmentBuilder::build_syn_ack(
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])),
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 2])),
            80,
            8080,
            5000,
            6000,
            32768,
            1460,
            None,  // no wscale
            None,  // no timestamp
            false, // no sack_permitted
            false, // no ecn
            MacAddress::new([0xAA; 6]),
            MacAddress::new([0xBB; 6]),
            false,
            &mut free,
            &mut tx,
        );

        assert_eq!(tx.num_frames(), 1);

        let frame = tx.pop().unwrap();
        let tcp_offset = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        let tcp = unsafe { TcpHeader::from_bytes_at(&frame, tcp_offset) };
        assert_eq!(tcp.flags(), flags::SYN | flags::ACK);

        // Options: MSS(4) only, padded to 4 bytes
        // data_offset = (20 + 4) / 4 = 6
        assert_eq!(tcp.data_offset(), 6);

        let ip = Ipv4Header::from_bytes(&frame);
        assert!(verify_tcp_checksum_ip::<Ipv4>(
            &ip.src_addr,
            &ip.dst_addr,
            &frame[tcp_offset..]
        ));
    }

    #[test]
    fn build_syn_ack_with_ecn_ipv4() {
        let mut free = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        free.push(alloc_free_frame(100));

        SegmentBuilder::build_syn_ack(
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])),
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 2])),
            80,
            8080,
            5000,
            6000,
            65535,
            1460,
            None,
            None,
            false,
            true, // ecn
            MacAddress::new([0xAA; 6]),
            MacAddress::new([0xBB; 6]),
            false,
            &mut free,
            &mut tx,
        );

        assert_eq!(tx.num_frames(), 1);

        let frame = tx.pop().unwrap();
        let tcp_offset = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        let tcp = unsafe { TcpHeader::from_bytes_at(&frame, tcp_offset) };
        // SYN-ACK with ECN sets SYN|ACK|ECE (not CWR)
        assert_eq!(tcp.flags(), flags::SYN | flags::ACK | flags::ECE);

        let ip = Ipv4Header::from_bytes(&frame);
        assert!(verify_tcp_checksum_ip::<Ipv4>(
            &ip.src_addr,
            &ip.dst_addr,
            &frame[tcp_offset..]
        ));
    }

    // ---------------------------------------------------------------
    // build_ack tests
    // ---------------------------------------------------------------

    #[test]
    fn build_ack_with_timestamp_ipv4() {
        let mut free = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        free.push(alloc_free_frame(100));

        let tsval = 555u32;
        let tsecr = 444u32;

        SegmentBuilder::build_ack(
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])),
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 2])),
            8080,
            80,
            2000,
            3000,
            65535,
            flags::ACK,
            Some((tsval, tsecr)),
            MacAddress::new([0xAA; 6]),
            MacAddress::new([0xBB; 6]),
            false,
            &mut free,
            &mut tx,
        );

        assert_eq!(tx.num_frames(), 1, "ACK with timestamp built");

        let frame = tx.pop().unwrap();
        let tcp_offset = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        let tcp = unsafe { TcpHeader::from_bytes_at(&frame, tcp_offset) };
        assert_eq!(tcp.flags(), flags::ACK);
        assert_eq!(tcp.seq_num(), 2000);
        assert_eq!(tcp.ack_num(), 3000);

        // Options: NOP(1) + NOP(1) + TS(10) = 12 bytes, padded to 12 (already aligned)
        // data_offset = (20 + 12) / 4 = 8
        assert_eq!(tcp.data_offset(), 8);

        // Verify timestamp option bytes
        let opt_start = tcp_offset + TCP_HEADER_LEN;
        assert_eq!(frame[opt_start], options::NOP);
        assert_eq!(frame[opt_start + 1], options::NOP);
        assert_eq!(frame[opt_start + 2], 8); // TS kind
        assert_eq!(frame[opt_start + 3], 10); // TS len
        assert_eq!(
            u32::from_be_bytes([
                frame[opt_start + 4],
                frame[opt_start + 5],
                frame[opt_start + 6],
                frame[opt_start + 7]
            ]),
            tsval
        );
        assert_eq!(
            u32::from_be_bytes([
                frame[opt_start + 8],
                frame[opt_start + 9],
                frame[opt_start + 10],
                frame[opt_start + 11]
            ]),
            tsecr
        );

        let ip = Ipv4Header::from_bytes(&frame);
        assert!(verify_tcp_checksum_ip::<Ipv4>(
            &ip.src_addr,
            &ip.dst_addr,
            &frame[tcp_offset..]
        ));
    }

    #[test]
    fn build_ack_without_timestamp_ipv4() {
        let mut free = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        free.push(alloc_free_frame(100));

        SegmentBuilder::build_ack(
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])),
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 2])),
            8080,
            80,
            2000,
            3000,
            65535,
            flags::ACK,
            None,
            MacAddress::new([0xAA; 6]),
            MacAddress::new([0xBB; 6]),
            false,
            &mut free,
            &mut tx,
        );

        assert_eq!(tx.num_frames(), 1);

        let frame = tx.pop().unwrap();
        // ETH(14) + IPv4(20) + TCP(20) = 54, no options
        assert_eq!(frame.len(), 54);

        let tcp_offset = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        let tcp = unsafe { TcpHeader::from_bytes_at(&frame, tcp_offset) };
        assert_eq!(tcp.flags(), flags::ACK);
        assert_eq!(tcp.data_offset(), 5); // no options

        let ip = Ipv4Header::from_bytes(&frame);
        assert!(verify_tcp_checksum_ip::<Ipv4>(
            &ip.src_addr,
            &ip.dst_addr,
            &frame[tcp_offset..]
        ));
    }

    #[test]
    fn build_ack_with_ece_flag_ipv4() {
        let mut free = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        free.push(alloc_free_frame(100));

        SegmentBuilder::build_ack(
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])),
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 2])),
            8080,
            80,
            2000,
            3000,
            65535,
            flags::ACK | flags::ECE,
            None,
            MacAddress::new([0xAA; 6]),
            MacAddress::new([0xBB; 6]),
            false,
            &mut free,
            &mut tx,
        );

        assert_eq!(tx.num_frames(), 1);

        let frame = tx.pop().unwrap();
        let tcp_offset = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
        let tcp = unsafe { TcpHeader::from_bytes_at(&frame, tcp_offset) };
        assert_eq!(tcp.flags(), flags::ACK | flags::ECE);

        let ip = Ipv4Header::from_bytes(&frame);
        assert!(verify_tcp_checksum_ip::<Ipv4>(
            &ip.src_addr,
            &ip.dst_addr,
            &frame[tcp_offset..]
        ));
    }

    // ---------------------------------------------------------------
    // IPv6 segment tests
    // ---------------------------------------------------------------

    const LOCAL_V6: Ipv6Address =
        Ipv6Address::new([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    const REMOTE_V6: Ipv6Address =
        Ipv6Address::new([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

    #[test]
    fn build_syn_ipv6() {
        let mut free = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        free.push(alloc_free_frame(200));

        SegmentBuilder::build_syn(
            IpAddress::V6(LOCAL_V6),
            IpAddress::V6(REMOTE_V6),
            8080,
            80,
            1000,
            65535,
            1440,
            7,
            None,
            false,
            false,
            MacAddress::new([0xAA; 6]),
            MacAddress::new([0xBB; 6]),
            false,
            &mut free,
            &mut tx,
        );

        assert_eq!(tx.num_frames(), 1, "SYN IPv6 segment built");
        assert_eq!(free.num_frames(), 0, "free frame consumed");

        let frame = tx.pop().unwrap();
        let tcp_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        let tcp = unsafe { TcpHeader::from_bytes_at(&frame, tcp_offset) };
        assert_eq!(tcp.flags(), flags::SYN);
        assert_eq!(tcp.seq_num(), 1000);
        assert_eq!(tcp.src_port(), 8080);
        assert_eq!(tcp.dst_port(), 80);

        let ip = Ipv6Header::from_bytes(&frame);
        assert!(verify_tcp_checksum_ip::<Ipv6>(
            &ip.src_addr,
            &ip.dst_addr,
            &frame[tcp_offset..]
        ));
    }

    #[test]
    fn build_ack_ipv6() {
        let mut free = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        free.push(alloc_free_frame(201));

        SegmentBuilder::build_ack(
            IpAddress::V6(LOCAL_V6),
            IpAddress::V6(REMOTE_V6),
            8080,
            80,
            2000,
            3000,
            65535,
            flags::ACK,
            None,
            MacAddress::new([0xAA; 6]),
            MacAddress::new([0xBB; 6]),
            false,
            &mut free,
            &mut tx,
        );

        assert_eq!(tx.num_frames(), 1, "ACK IPv6 segment built");

        let frame = tx.pop().unwrap();
        // ETH(14) + IPv6(40) + TCP(20) = 74
        assert_eq!(frame.len(), 74);

        let tcp_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        let tcp = unsafe { TcpHeader::from_bytes_at(&frame, tcp_offset) };
        assert_eq!(tcp.flags(), flags::ACK);
        assert_eq!(tcp.seq_num(), 2000);
        assert_eq!(tcp.ack_num(), 3000);

        let ip = Ipv6Header::from_bytes(&frame);
        assert!(verify_tcp_checksum_ip::<Ipv6>(
            &ip.src_addr,
            &ip.dst_addr,
            &frame[tcp_offset..]
        ));
    }

    #[test]
    fn build_rst_ipv6() {
        let mut free = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        free.push(alloc_free_frame(202));

        SegmentBuilder::build_rst(
            IpAddress::V6(REMOTE_V6),
            IpAddress::V6(LOCAL_V6),
            80,
            8080,
            1000,
            0,
            flags::SYN, // ACK bit off
            100,
            MacAddress::new([0xAA; 6]),
            MacAddress::new([0xBB; 6]),
            false,
            &mut free,
            &mut tx,
        );

        assert_eq!(tx.num_frames(), 1, "RST IPv6 segment built");

        let frame = tx.pop().unwrap();
        let tcp_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        let tcp = unsafe { TcpHeader::from_bytes_at(&frame, tcp_offset) };
        assert_eq!(tcp.flags(), flags::RST | flags::ACK);

        let ip = Ipv6Header::from_bytes(&frame);
        assert!(verify_tcp_checksum_ip::<Ipv6>(
            &ip.src_addr,
            &ip.dst_addr,
            &frame[tcp_offset..]
        ));
    }

    #[test]
    fn build_fin_ack_ipv6() {
        let mut free = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        free.push(alloc_free_frame(203));

        SegmentBuilder::build_fin_ack(
            IpAddress::V6(LOCAL_V6),
            IpAddress::V6(REMOTE_V6),
            80,
            8080,
            5000,
            3000,
            65535,
            None,
            MacAddress::new([0xAA; 6]),
            MacAddress::new([0xBB; 6]),
            false,
            &mut free,
            &mut tx,
        );

        assert_eq!(tx.num_frames(), 1, "FIN-ACK IPv6 segment built");

        let frame = tx.pop().unwrap();
        let tcp_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        let tcp = unsafe { TcpHeader::from_bytes_at(&frame, tcp_offset) };
        assert_eq!(tcp.flags(), flags::ACK | flags::FIN);
        assert_eq!(tcp.seq_num(), 5000);
        assert_eq!(tcp.ack_num(), 3000);

        let ip = Ipv6Header::from_bytes(&frame);
        assert!(verify_tcp_checksum_ip::<Ipv6>(
            &ip.src_addr,
            &ip.dst_addr,
            &frame[tcp_offset..]
        ));
    }

    #[test]
    fn build_data_ipv6() {
        let mut free = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        free.push(alloc_free_frame(204));

        let payload = b"Hello, IPv6 TCP!";

        SegmentBuilder::build_data(
            IpAddress::V6(LOCAL_V6),
            IpAddress::V6(REMOTE_V6),
            8080,
            80,
            1000,
            500,
            65535,
            payload,
            None,
            MacAddress::new([0xAA; 6]),
            MacAddress::new([0xBB; 6]),
            false,
            &mut free,
            &mut tx,
        );

        assert_eq!(tx.num_frames(), 1, "data IPv6 segment built");

        let frame = tx.pop().unwrap();
        // ETH(14) + IPv6(40) + TCP(20) + payload(16) = 90
        assert_eq!(frame.len(), 90);

        let payload_start = ETH_HEADER_LEN + IPV6_HEADER_LEN + TCP_HEADER_LEN;
        assert_eq!(&frame[payload_start..frame.len()], payload);

        let tcp_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        let ip = Ipv6Header::from_bytes(&frame);
        assert!(verify_tcp_checksum_ip::<Ipv6>(
            &ip.src_addr,
            &ip.dst_addr,
            &frame[tcp_offset..]
        ));
    }

    #[test]
    fn build_mismatched_v4_v6_returns_none() {
        let mut free = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);
        free.push(alloc_free_frame(205));

        // V4 local, V6 remote — mismatched address families
        SegmentBuilder::build_syn(
            IpAddress::V4(Ipv4Address::new([10, 0, 0, 1])),
            IpAddress::V6(REMOTE_V6),
            8080,
            80,
            1000,
            65535,
            1460,
            7,
            None,
            false,
            false,
            MacAddress::new([0xAA; 6]),
            MacAddress::new([0xBB; 6]),
            false,
            &mut free,
            &mut tx,
        );

        assert_eq!(tx.num_frames(), 0, "mismatched AF produces no segment");
        assert_eq!(free.num_frames(), 1, "free frame not consumed");
    }
}
