use crate::net::{
    checksum::{compute_tcp_checksum_from_parts, compute_tcp_checksum_v6_from_parts},
    wire::{
        ethernet::{EtherTypes, EthernetFrame, MacAddress, write_ethernet_header},
        ip::{
            IPV4_MIN_HEADER_LEN, IPV6_HEADER_LEN, IpAddress, IpProtocols, Ipv4Address, Ipv6Address,
        },
        tcp::{TcpHeader, TCP_HEADER_LEN, flags, options, write_mss_option, write_window_scale_option},
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
            (0u32, incoming_seq.wrapping_add(incoming_seg_len), flags::RST | flags::ACK)
        } else {
            // ACK on: <SEQ=SEG.ACK><CTL=RST>
            (incoming_ack, 0u32, flags::RST)
        };

        match (incoming_dst_addr, incoming_src_addr) {
            (IpAddress::V4(local_ip), IpAddress::V4(remote_ip)) => {
                Self::build_ipv4_segment(
                    local_ip, remote_ip,
                    incoming_dst_port, incoming_src_port,
                    seq, ack, rst_flags, 0,
                    &[], // no options
                    src_mac, dst_mac,
                    tx_offload, free_frames, tx_return,
                );
            }
            (IpAddress::V6(local_ip), IpAddress::V6(remote_ip)) => {
                Self::build_ipv6_segment(
                    local_ip, remote_ip,
                    incoming_dst_port, incoming_src_port,
                    seq, ack, rst_flags, 0,
                    &[],
                    src_mac, dst_mac,
                    tx_offload, free_frames, tx_return,
                );
            }
            _ => {} // mixed v4/v6 — should not happen
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
        src_mac: MacAddress,
        dst_mac: MacAddress,
        tx_offload: bool,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        // Build options: MSS (4 bytes) + NOP (1) + Window Scale (3) = 8 bytes
        let mut opt_buf = [0u8; 8];
        let mut opt_len = write_mss_option(&mut opt_buf, mss);
        opt_buf[opt_len] = options::NOP;
        opt_len += 1;
        opt_len += write_window_scale_option(&mut opt_buf[opt_len..], wscale);

        match (local_addr, remote_addr) {
            (IpAddress::V4(local_ip), IpAddress::V4(remote_ip)) => {
                Self::build_ipv4_segment(
                    local_ip, remote_ip,
                    local_port, remote_port,
                    iss, 0, flags::SYN, window,
                    &opt_buf[..opt_len],
                    src_mac, dst_mac,
                    tx_offload, free_frames, tx_return,
                );
            }
            (IpAddress::V6(local_ip), IpAddress::V6(remote_ip)) => {
                Self::build_ipv6_segment(
                    local_ip, remote_ip,
                    local_port, remote_port,
                    iss, 0, flags::SYN, window,
                    &opt_buf[..opt_len],
                    src_mac, dst_mac,
                    tx_offload, free_frames, tx_return,
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
        src_mac: MacAddress,
        dst_mac: MacAddress,
        tx_offload: bool,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let mut opt_buf = [0u8; 8];
        let mut opt_len = write_mss_option(&mut opt_buf, mss);
        if let Some(shift) = wscale {
            opt_buf[opt_len] = options::NOP;
            opt_len += 1;
            opt_len += write_window_scale_option(&mut opt_buf[opt_len..], shift);
        }

        match (local_addr, remote_addr) {
            (IpAddress::V4(local_ip), IpAddress::V4(remote_ip)) => {
                Self::build_ipv4_segment(
                    local_ip, remote_ip,
                    local_port, remote_port,
                    iss, ack, flags::SYN | flags::ACK, window,
                    &opt_buf[..opt_len],
                    src_mac, dst_mac,
                    tx_offload, free_frames, tx_return,
                );
            }
            (IpAddress::V6(local_ip), IpAddress::V6(remote_ip)) => {
                Self::build_ipv6_segment(
                    local_ip, remote_ip,
                    local_port, remote_port,
                    iss, ack, flags::SYN | flags::ACK, window,
                    &opt_buf[..opt_len],
                    src_mac, dst_mac,
                    tx_offload, free_frames, tx_return,
                );
            }
            _ => {}
        }
    }

    /// Build a pure ACK segment (no data, no SYN/FIN).
    #[inline]
    pub fn build_ack<'umem>(
        local_addr: IpAddress,
        remote_addr: IpAddress,
        local_port: u16,
        remote_port: u16,
        seq: u32,
        ack: u32,
        window: u16,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        tx_offload: bool,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        match (local_addr, remote_addr) {
            (IpAddress::V4(local_ip), IpAddress::V4(remote_ip)) => {
                Self::build_ipv4_segment(
                    local_ip, remote_ip,
                    local_port, remote_port,
                    seq, ack, flags::ACK, window,
                    &[],
                    src_mac, dst_mac,
                    tx_offload, free_frames, tx_return,
                );
            }
            (IpAddress::V6(local_ip), IpAddress::V6(remote_ip)) => {
                Self::build_ipv6_segment(
                    local_ip, remote_ip,
                    local_port, remote_port,
                    seq, ack, flags::ACK, window,
                    &[],
                    src_mac, dst_mac,
                    tx_offload, free_frames, tx_return,
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
        src_mac: MacAddress,
        dst_mac: MacAddress,
        tx_offload: bool,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        match (local_addr, remote_addr) {
            (IpAddress::V4(local_ip), IpAddress::V4(remote_ip)) => {
                Self::build_ipv4_data_segment(
                    local_ip, remote_ip,
                    local_port, remote_port,
                    seq, ack, flags::ACK, window,
                    payload,
                    src_mac, dst_mac,
                    tx_offload, free_frames, tx_return,
                );
            }
            (IpAddress::V6(local_ip), IpAddress::V6(remote_ip)) => {
                Self::build_ipv6_data_segment(
                    local_ip, remote_ip,
                    local_port, remote_port,
                    seq, ack, flags::ACK, window,
                    payload,
                    src_mac, dst_mac,
                    tx_offload, free_frames, tx_return,
                );
            }
            _ => {}
        }
    }

    // --- Internal helpers ---

    #[inline]
    fn build_ipv4_segment<'umem>(
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
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

        // Pad options to 4-byte boundary.
        let opt_padded_len = (tcp_options.len() + 3) & !3;
        let tcp_header_len = TCP_HEADER_LEN + opt_padded_len;
        let data_offset = (tcp_header_len / 4) as u8;
        let total_ip_len = (IPV4_MIN_HEADER_LEN + tcp_header_len) as u16;
        let frame_len = ETH_LEN + IPV4_MIN_HEADER_LEN + tcp_header_len;

        if frame.capacity() < frame_len {
            free_frames.push(frame);
            return;
        }

        unsafe { frame.set_len(frame_len) };

        // Ethernet header.
        write_ethernet_header(&mut frame, dst_mac, src_mac, EtherTypes::IPv4);

        // IPv4 header.
        {
            let ip = &mut frame[ETH_LEN..ETH_LEN + IPV4_MIN_HEADER_LEN];
            ip.fill(0);
            ip[0] = 0x45; // version=4, ihl=5
            ip[2..4].copy_from_slice(&total_ip_len.to_be_bytes());
            ip[6] = 0x40; // Don't Fragment
            ip[8] = 64;   // TTL
            ip[9] = IpProtocols::Tcp;
            let src_bytes: [u8; 4] = src_ip.into();
            ip[12..16].copy_from_slice(&src_bytes);
            let dst_bytes: [u8; 4] = dst_ip.into();
            ip[16..20].copy_from_slice(&dst_bytes);
        }
        // Compute IPv4 header checksum.
        {
            let ip = crate::net::wire::ip::Ipv4Header::from_bytes_mut(&mut frame);
            ip.fill_checksum();
        }

        // TCP header.
        let tcp_offset = ETH_LEN + IPV4_MIN_HEADER_LEN;
        Self::write_tcp_header(
            &mut frame, tcp_offset,
            src_port, dst_port, seq, ack, data_offset, tcp_flags, window,
            tcp_options, opt_padded_len,
        );

        // TCP checksum.
        if !tx_offload {
            let tcp_bytes = &frame[tcp_offset..frame_len];
            let checksum = compute_tcp_checksum_from_parts(&src_ip, &dst_ip, tcp_bytes, &[]);
            frame[tcp_offset + 16] = checksum[0];
            frame[tcp_offset + 17] = checksum[1];
        }

        tx_return.push(frame);
    }

    #[inline]
    fn build_ipv6_segment<'umem>(
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
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
        let payload_len = tcp_header_len as u16;
        let frame_len = ETH_LEN + IPV6_HEADER_LEN + tcp_header_len;

        if frame.capacity() < frame_len {
            free_frames.push(frame);
            return;
        }

        unsafe { frame.set_len(frame_len) };

        // Ethernet header.
        write_ethernet_header(&mut frame, dst_mac, src_mac, EtherTypes::IPv6);

        // IPv6 header.
        {
            let ip = &mut frame[ETH_LEN..ETH_LEN + IPV6_HEADER_LEN];
            ip.fill(0);
            ip[0] = 0x60; // version=6
            ip[4..6].copy_from_slice(&payload_len.to_be_bytes());
            ip[6] = IpProtocols::Tcp; // Next Header
            ip[7] = 64; // Hop Limit
            let src_bytes: [u8; 16] = src_ip.into();
            ip[8..24].copy_from_slice(&src_bytes);
            let dst_bytes: [u8; 16] = dst_ip.into();
            ip[24..40].copy_from_slice(&dst_bytes);
        }

        // TCP header.
        let tcp_offset = ETH_LEN + IPV6_HEADER_LEN;
        Self::write_tcp_header(
            &mut frame, tcp_offset,
            src_port, dst_port, seq, ack, data_offset, tcp_flags, window,
            tcp_options, opt_padded_len,
        );

        // TCP checksum.
        if !tx_offload {
            let tcp_bytes = &frame[tcp_offset..frame_len];
            let checksum = compute_tcp_checksum_v6_from_parts(&src_ip, &dst_ip, tcp_bytes, &[]);
            frame[tcp_offset + 16] = checksum[0];
            frame[tcp_offset + 17] = checksum[1];
        }

        tx_return.push(frame);
    }

    #[inline]
    fn build_ipv4_data_segment<'umem>(
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        tcp_flags: u8,
        window: u16,
        payload: &[u8],
        src_mac: MacAddress,
        dst_mac: MacAddress,
        tx_offload: bool,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let Some(mut frame) = free_frames.pop() else {
            return;
        };

        let tcp_header_len = TCP_HEADER_LEN; // no options for data segments
        let data_offset = (tcp_header_len / 4) as u8;
        let total_ip_len = (IPV4_MIN_HEADER_LEN + tcp_header_len + payload.len()) as u16;
        let frame_len = ETH_LEN + IPV4_MIN_HEADER_LEN + tcp_header_len + payload.len();

        if frame.capacity() < frame_len {
            free_frames.push(frame);
            return;
        }

        unsafe { frame.set_len(frame_len) };

        // Ethernet header.
        write_ethernet_header(&mut frame, dst_mac, src_mac, EtherTypes::IPv4);

        // IPv4 header.
        {
            let ip = &mut frame[ETH_LEN..ETH_LEN + IPV4_MIN_HEADER_LEN];
            ip.fill(0);
            ip[0] = 0x45; // version=4, ihl=5
            ip[2..4].copy_from_slice(&total_ip_len.to_be_bytes());
            ip[6] = 0x40; // Don't Fragment
            ip[8] = 64;   // TTL
            ip[9] = IpProtocols::Tcp;
            let src_bytes: [u8; 4] = src_ip.into();
            ip[12..16].copy_from_slice(&src_bytes);
            let dst_bytes: [u8; 4] = dst_ip.into();
            ip[16..20].copy_from_slice(&dst_bytes);
        }
        // Compute IPv4 header checksum.
        {
            let ip = crate::net::wire::ip::Ipv4Header::from_bytes_mut(&mut frame);
            ip.fill_checksum();
        }

        // TCP header.
        let tcp_offset = ETH_LEN + IPV4_MIN_HEADER_LEN;
        Self::write_tcp_header(
            &mut frame, tcp_offset,
            src_port, dst_port, seq, ack, data_offset, tcp_flags, window,
            &[], 0,
        );

        // Copy payload.
        let payload_offset = tcp_offset + tcp_header_len;
        frame[payload_offset..payload_offset + payload.len()].copy_from_slice(payload);

        // TCP checksum — must cover header + payload.
        if !tx_offload {
            let checksum = compute_tcp_checksum_from_parts(
                &src_ip, &dst_ip,
                &frame[tcp_offset..tcp_offset + tcp_header_len],
                payload,
            );
            frame[tcp_offset + 16] = checksum[0];
            frame[tcp_offset + 17] = checksum[1];
        }

        tx_return.push(frame);
    }

    #[inline]
    fn build_ipv6_data_segment<'umem>(
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        tcp_flags: u8,
        window: u16,
        payload: &[u8],
        src_mac: MacAddress,
        dst_mac: MacAddress,
        tx_offload: bool,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let Some(mut frame) = free_frames.pop() else {
            return;
        };

        let tcp_header_len = TCP_HEADER_LEN;
        let data_offset = (tcp_header_len / 4) as u8;
        let ipv6_payload_len = (tcp_header_len + payload.len()) as u16;
        let frame_len = ETH_LEN + IPV6_HEADER_LEN + tcp_header_len + payload.len();

        if frame.capacity() < frame_len {
            free_frames.push(frame);
            return;
        }

        unsafe { frame.set_len(frame_len) };

        // Ethernet header.
        write_ethernet_header(&mut frame, dst_mac, src_mac, EtherTypes::IPv6);

        // IPv6 header.
        {
            let ip = &mut frame[ETH_LEN..ETH_LEN + IPV6_HEADER_LEN];
            ip.fill(0);
            ip[0] = 0x60; // version=6
            ip[4..6].copy_from_slice(&ipv6_payload_len.to_be_bytes());
            ip[6] = IpProtocols::Tcp; // Next Header
            ip[7] = 64; // Hop Limit
            let src_bytes: [u8; 16] = src_ip.into();
            ip[8..24].copy_from_slice(&src_bytes);
            let dst_bytes: [u8; 16] = dst_ip.into();
            ip[24..40].copy_from_slice(&dst_bytes);
        }

        // TCP header.
        let tcp_offset = ETH_LEN + IPV6_HEADER_LEN;
        Self::write_tcp_header(
            &mut frame, tcp_offset,
            src_port, dst_port, seq, ack, data_offset, tcp_flags, window,
            &[], 0,
        );

        // Copy payload.
        let payload_offset = tcp_offset + tcp_header_len;
        frame[payload_offset..payload_offset + payload.len()].copy_from_slice(payload);

        // TCP checksum.
        if !tx_offload {
            let checksum = compute_tcp_checksum_v6_from_parts(
                &src_ip, &dst_ip,
                &frame[tcp_offset..tcp_offset + tcp_header_len],
                payload,
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
            src_port, dst_port, seq, ack,
            data_offset, tcp_flags, window,
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
    use crate::xdp::frame::{BasicFrameBuffer, Frame};
    use crate::net::wire::ip::{Ipv4Address, Ipv6Address, IpAddress, Ipv4Header, IPV4_MIN_HEADER_LEN};
    use crate::net::checksum::verify_tcp_checksum;

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
            8080, 80,
            1000, 500,
            65535,
            payload,
            src_mac, dst_mac,
            false, &mut free, &mut tx,
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
        assert!(verify_tcp_checksum(&ip.src_addr, &ip.dst_addr, &frame[tcp_offset..]));
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
            8080, 80, 1000, 500, 65535,
            b"payload",
            MacAddress::new([0xAA; 6]), MacAddress::new([0xBB; 6]),
            false, &mut free, &mut tx,
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
            8080, 80, 1000, 500, 65535,
            b"payload",
            MacAddress::new([0xAA; 6]), MacAddress::new([0xBB; 6]),
            false, &mut free, &mut tx,
        );

        assert_eq!(tx.num_frames(), 0, "no segment built");
    }
}
