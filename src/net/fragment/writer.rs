use crate::{
    net::wire::{
        ethernet::{self, EtherTypes, EthernetFrame, MacAddress},
        ip::{
            FRAGMENT_EXT_LEN, IPV4_MIN_HEADER_LEN, IPV6_HEADER_LEN, Ipv4Address, Ipv4Header,
            Ipv6Address, Ipv6FragmentHeader, Ipv6Header,
        },
    },
    xdp::{
        error::{NonBlocking, WouldBlock},
        frame::{Frame, FrameBuffer},
    },
};

use super::pkt::Packet;

use super::{id, plan::FragmentPlan, transport::TransportHeader};

const ETH_HEADER_LEN: usize = size_of::<EthernetFrame>();

/// Stateless outbound IP fragmentation.
///
/// Provides static-like methods that fragment a payload into one or more
/// UMEM-backed frames, ready for transmission.
pub struct FragmentWriter;

impl FragmentWriter {
    /// Fragment a payload into IPv4 frames.
    ///
    /// - Writes Ethernet + IPv4 headers per fragment.
    /// - Fragment 0 includes the transport header (via `transport.write_to()`).
    /// - Non-last fragments have 8-byte-aligned data lengths.
    /// - Returns `Packet::Single` if the payload fits in one frame, `Packet::Multi` otherwise.
    /// - Returns `Err(WouldBlock)` if `free_frames` has insufficient frames.
    pub fn fragment_ipv4<'umem>(
        src_mac: MacAddress,
        dst_mac: MacAddress,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        ttl: u8,
        transport: &impl TransportHeader,
        payload: &[u8],
        mtu: u32,
        free_frames: &mut impl FrameBuffer<'umem>,
    ) -> NonBlocking<Packet<'umem>> {
        let transport_header_len = transport.header_len();
        let max_payload = mtu as usize - IPV4_MIN_HEADER_LEN - transport_header_len;

        if payload.len() <= max_payload {
            let protocol = transport.protocol();
            let ip_total_len = (IPV4_MIN_HEADER_LEN + transport_header_len + payload.len()) as u16;
            let identification = id::next_ipv4_id();

            return Self::build_single(
                transport,
                payload,
                IPV4_MIN_HEADER_LEN,
                free_frames,
                |frame| {
                    ethernet::write_ethernet_header(
                        &mut *frame,
                        dst_mac,
                        src_mac,
                        EtherTypes::IPv4,
                    );

                    let ip = Ipv4Header::from_bytes_mut(frame);
                    ip.version_ihl = 0x45;
                    ip.dscp_ecn = 0;
                    ip.total_length = ip_total_len.to_be_bytes();
                    ip.identification = identification.to_be_bytes();
                    ip.flags_fragment_offset = [0x40, 0x00]; // DF set
                    ip.ttl = ttl;
                    ip.protocol = protocol;
                    ip.header_checksum = [0, 0];
                    ip.src_addr = src_ip;
                    ip.dst_addr = dst_ip;
                    ip.fill_checksum();
                },
            );
        }

        let plan = FragmentPlan::new(
            IPV4_MIN_HEADER_LEN,
            transport_header_len,
            mtu,
            payload.len(),
        );

        if free_frames.num_frames() < plan.num_frames {
            return Err(WouldBlock);
        }

        let identification = id::next_ipv4_id();

        Self::fragment_loop(
            transport,
            payload,
            IPV4_MIN_HEADER_LEN,
            &plan,
            free_frames,
            |frame, frag_data_len, frag_byte_offset, is_last| {
                ethernet::write_ethernet_header(&mut *frame, dst_mac, src_mac, EtherTypes::IPv4);

                let ip_total_len = (IPV4_MIN_HEADER_LEN + frag_data_len) as u16;
                let frag_offset_units = (frag_byte_offset / 8) as u16;
                let mf: u8 = if is_last { 0 } else { 0x20 };
                let flags_frag_hi = mf | ((frag_offset_units >> 8) as u8 & 0x1F);
                let flags_frag_lo = frag_offset_units as u8;

                let ip = Ipv4Header::from_bytes_mut(frame);
                ip.version_ihl = 0x45;
                ip.dscp_ecn = 0;
                ip.total_length = ip_total_len.to_be_bytes();
                ip.identification = identification.to_be_bytes();
                ip.flags_fragment_offset = [flags_frag_hi, flags_frag_lo];
                ip.ttl = ttl;
                ip.protocol = transport.protocol();
                ip.header_checksum = [0, 0];
                ip.src_addr = src_ip;
                ip.dst_addr = dst_ip;
                ip.fill_checksum();
            },
        )
    }

    /// Fragment a payload into IPv6 frames.
    ///
    /// - Writes Ethernet + IPv6 + Fragment Extension headers per fragment.
    /// - Fragment 0 includes the transport header (via `transport.write_to()`).
    /// - Non-last fragments have 8-byte-aligned data lengths.
    /// - Returns `Packet::Single` if the payload fits in one frame (no fragment ext header), `Packet::Multi` otherwise.
    /// - Returns `Err(WouldBlock)` if `free_frames` has insufficient frames.
    pub fn fragment_ipv6<'umem>(
        src_mac: MacAddress,
        dst_mac: MacAddress,
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        hop_limit: u8,
        transport: &impl TransportHeader,
        payload: &[u8],
        mtu: u32,
        free_frames: &mut impl FrameBuffer<'umem>,
    ) -> NonBlocking<Packet<'umem>> {
        let transport_header_len = transport.header_len();
        let max_payload = mtu as usize - IPV6_HEADER_LEN - transport_header_len;

        if payload.len() <= max_payload {
            let protocol = transport.protocol();
            let ipv6_payload_len = (transport_header_len + payload.len()) as u16;

            return Self::build_single(transport, payload, IPV6_HEADER_LEN, free_frames, |frame| {
                ethernet::write_ethernet_header(&mut *frame, dst_mac, src_mac, EtherTypes::IPv6);

                let ip = Ipv6Header::from_bytes_mut(frame);
                ip.version_tc_fl = [0x60, 0x00, 0x00, 0x00];
                ip.payload_length = ipv6_payload_len.to_be_bytes();
                ip.next_header = protocol;
                ip.hop_limit = hop_limit;
                ip.src_addr = src_ip;
                ip.dst_addr = dst_ip;
            });
        }

        let ip_overhead = IPV6_HEADER_LEN + FRAGMENT_EXT_LEN;
        let plan = FragmentPlan::new(ip_overhead, transport_header_len, mtu, payload.len());

        if free_frames.num_frames() < plan.num_frames {
            return Err(WouldBlock);
        }

        let identification = id::next_ipv6_id();

        Self::fragment_loop(
            transport,
            payload,
            ip_overhead,
            &plan,
            free_frames,
            |frame, frag_data_len, frag_byte_offset, is_last| {
                ethernet::write_ethernet_header(&mut *frame, dst_mac, src_mac, EtherTypes::IPv6);

                let ipv6_payload_len = (FRAGMENT_EXT_LEN + frag_data_len) as u16;
                {
                    let ip = Ipv6Header::from_bytes_mut(frame);
                    ip.version_tc_fl = [0x60, 0x00, 0x00, 0x00];
                    ip.payload_length = ipv6_payload_len.to_be_bytes();
                    ip.next_header = 44;
                    ip.hop_limit = hop_limit;
                    ip.src_addr = src_ip;
                    ip.dst_addr = dst_ip;
                }

                let frag_ext_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
                let frag_hdr = Ipv6FragmentHeader::from_bytes_at_mut(frame, frag_ext_offset);
                frag_hdr.next_header = transport.protocol();
                frag_hdr.reserved = 0;
                let frag_offset_units = (frag_byte_offset / 8) as u16;
                frag_hdr.set_fragment_offset_mf(frag_offset_units, !is_last);
                frag_hdr.identification = identification.to_be_bytes();
            },
        )
    }

    /// Common fragment loop shared by IPv4 and IPv6 fragmented paths.
    ///
    /// `ip_overhead` is the total bytes between the ethernet header and the
    /// fragment data start (e.g. 20 for IPv4, 48 for IPv6 + fragment ext).
    ///
    /// `write_headers` is called per fragment with `(frame, frag_data_len,
    /// frag_byte_offset, is_last)` and must write all protocol-specific headers.
    fn fragment_loop<'umem>(
        transport: &impl TransportHeader,
        payload: &[u8],
        ip_overhead: usize,
        plan: &FragmentPlan,
        free_frames: &mut impl FrameBuffer<'umem>,
        mut write_headers: impl FnMut(&mut Frame<'umem>, usize, usize, bool),
    ) -> NonBlocking<Packet<'umem>> {
        let transport_header_len = transport.header_len();
        let mut frames = Vec::with_capacity(plan.num_frames);
        let mut payload_offset = 0usize;
        let mut frag_byte_offset = 0usize;

        for i in 0..plan.num_frames {
            let mut frame = free_frames.pop().ok_or(WouldBlock)?;
            let is_last = i == plan.num_frames - 1;

            let (frag_data_len, data_to_copy) =
                plan.fragment_sizes(i, transport_header_len, payload_offset, payload.len());

            let frame_len = ETH_HEADER_LEN + ip_overhead + frag_data_len;
            unsafe { frame.set_len(frame_len) };

            write_headers(&mut frame, frag_data_len, frag_byte_offset, is_last);

            let data_start = ETH_HEADER_LEN + ip_overhead;

            if i == 0 {
                transport.write_to(&mut frame[data_start..data_start + transport_header_len]);

                let chunk = plan.first_chunk.min(payload.len());
                frame[data_start + transport_header_len..data_start + transport_header_len + chunk]
                    .copy_from_slice(&payload[..chunk]);
                payload_offset = chunk;
                frag_byte_offset = transport_header_len + chunk;
            } else {
                frame[data_start..data_start + data_to_copy]
                    .copy_from_slice(&payload[payload_offset..payload_offset + data_to_copy]);
                payload_offset += data_to_copy;
                frag_byte_offset += data_to_copy;
            }

            frames.push(frame);
        }

        debug_assert!(frames.len() >= 2);
        Ok(Packet::Multi(frames))
    }

    /// Build a single (non-fragmented) frame.
    ///
    /// `ip_header_len` is the bytes between the ethernet header and the
    /// transport data (e.g. 20 for IPv4, 40 for IPv6).
    ///
    /// `write_headers` must write the ethernet and IP headers into the frame.
    fn build_single<'umem>(
        transport: &impl TransportHeader,
        payload: &[u8],
        ip_header_len: usize,
        free_frames: &mut impl FrameBuffer<'umem>,
        write_headers: impl FnOnce(&mut Frame<'umem>),
    ) -> NonBlocking<Packet<'umem>> {
        let transport_header_len = transport.header_len();
        let mut frame = free_frames.pop().ok_or(WouldBlock)?;
        let frame_len = ETH_HEADER_LEN + ip_header_len + transport_header_len + payload.len();
        unsafe { frame.set_len(frame_len) };

        write_headers(&mut frame);

        let data_start = ETH_HEADER_LEN + ip_header_len;
        transport.write_to(&mut frame[data_start..data_start + transport_header_len]);
        frame[data_start + transport_header_len..frame_len].copy_from_slice(payload);

        Ok(Packet::Single(frame))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::checksum::compute_ipv4_checksum;
    use crate::net::wire::ip::IpProtocols;
    use crate::xdp::frame::{BasicFrameBuffer, Frame};

    use crate::net::wire::udp::UdpHeader;

    const SRC_MAC: MacAddress = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    const DST_MAC: MacAddress = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    const SRC_V4: Ipv4Address = Ipv4Address::new([192, 168, 1, 1]);
    const DST_V4: Ipv4Address = Ipv4Address::new([10, 0, 0, 1]);
    const SRC_V6: Ipv6Address =
        Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    const DST_V6: Ipv6Address =
        Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

    fn make_free_frames(bufs: &mut Vec<Vec<u8>>, n: usize) -> BasicFrameBuffer<'_> {
        let mut fb = BasicFrameBuffer::new(n * 2);
        for (i, buf) in bufs.iter_mut().enumerate() {
            fb.push(Frame::new(i as u64, buf.as_mut_slice(), 1, false));
        }
        fb
    }

    fn make_udp_transport(payload_len: usize) -> UdpHeader {
        UdpHeader::new(12345, 53, (8 + payload_len) as u16, [0xAB, 0xCD])
    }

    // --- IPv4 single frame ---

    #[test]
    fn ipv4_single_frame() {
        let mut bufs: Vec<Vec<u8>> = (0..4).map(|_| vec![0u8; 2048]).collect();
        let mut free = make_free_frames(&mut bufs, 4);
        let payload = b"Hello, World!";
        let transport = make_udp_transport(payload.len());

        let result = FragmentWriter::fragment_ipv4(
            SRC_MAC, DST_MAC, SRC_V4, DST_V4, 64, &transport, payload, 1500, &mut free,
        );

        let packet = result.expect("should succeed");
        match packet {
            Packet::Single(frame) => {
                let expected_len = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + 8 + payload.len();
                assert_eq!(frame.len(), expected_len);

                let ip = Ipv4Header::from_bytes(&frame);
                assert_eq!(ip.version(), 4);
                assert_eq!(ip.ihl(), 5);
                assert_eq!(ip.ttl, 64);
                assert_eq!(ip.protocol, IpProtocols::Udp);
                assert_eq!(ip.src_addr, SRC_V4);
                assert_eq!(ip.dst_addr, DST_V4);
                assert!(ip.dont_fragment());
                assert!(!ip.is_fragment());

                // Verify IPv4 checksum.
                let ip_bytes = &frame[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN];
                assert_eq!(compute_ipv4_checksum(ip_bytes), [0x00, 0x00]);

                // Verify transport header was written.
                let data_start = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
                assert_eq!(
                    u16::from_be_bytes([frame[data_start], frame[data_start + 1]]),
                    12345
                );
                assert_eq!(
                    u16::from_be_bytes([frame[data_start + 2], frame[data_start + 3]]),
                    53
                );

                // Verify payload.
                assert_eq!(&frame[data_start + 8..frame.len()], payload);
            }
            _ => panic!("expected Single"),
        }
    }

    // --- IPv4 fragmented ---

    #[test]
    fn ipv4_fragmented() {
        let mut bufs: Vec<Vec<u8>> = (0..32).map(|_| vec![0u8; 2048]).collect();
        let mut free = make_free_frames(&mut bufs, 32);
        let payload = vec![0xAB; 3000];
        let transport = make_udp_transport(payload.len());

        let result = FragmentWriter::fragment_ipv4(
            SRC_MAC, DST_MAC, SRC_V4, DST_V4, 64, &transport, &payload, 1500, &mut free,
        );

        let packet = result.expect("should succeed");
        match packet {
            Packet::Multi(frames) => {
                assert!(frames.len() >= 2);

                let first_id = Ipv4Header::from_bytes(&frames[0]).identification();
                for f in &frames {
                    let ip = Ipv4Header::from_bytes(f);
                    assert_eq!(ip.identification(), first_id);
                    assert_eq!(ip.protocol, IpProtocols::Udp);
                    assert_eq!(ip.src_addr, SRC_V4);
                    assert_eq!(ip.dst_addr, DST_V4);
                    assert!(!ip.dont_fragment());

                    // Verify IPv4 checksum.
                    let ip_bytes = &f[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN];
                    assert_eq!(compute_ipv4_checksum(ip_bytes), [0x00, 0x00]);
                }

                // First fragment: MF set, offset 0.
                let first_ip = Ipv4Header::from_bytes(&frames[0]);
                assert!(first_ip.more_fragments());
                assert_eq!(first_ip.fragment_offset(), 0);

                // Last fragment: MF clear.
                let last_ip = Ipv4Header::from_bytes(frames.last().unwrap());
                assert!(!last_ip.more_fragments());

                // Non-last fragments: 8-byte aligned payload.
                for (i, f) in frames.iter().enumerate() {
                    let ip = Ipv4Header::from_bytes(f);
                    if i < frames.len() - 1 {
                        assert_eq!(ip.payload_len() % 8, 0, "non-last fragment not 8-aligned");
                    }
                }

                // Reassemble payload.
                let mut reassembled = Vec::new();
                for (i, f) in frames.iter().enumerate() {
                    let data_start = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
                    if i == 0 {
                        reassembled.extend_from_slice(&f[data_start + 8..f.len()]);
                    } else {
                        reassembled.extend_from_slice(&f[data_start..f.len()]);
                    }
                }
                assert_eq!(reassembled, payload);
            }
            _ => panic!("expected Multi"),
        }
    }

    // --- IPv6 single frame ---

    #[test]
    fn ipv6_single_frame() {
        let mut bufs: Vec<Vec<u8>> = (0..4).map(|_| vec![0u8; 2048]).collect();
        let mut free = make_free_frames(&mut bufs, 4);
        let payload = b"Hello, IPv6!";
        let transport = make_udp_transport(payload.len());

        let result = FragmentWriter::fragment_ipv6(
            SRC_MAC, DST_MAC, SRC_V6, DST_V6, 64, &transport, payload, 1500, &mut free,
        );

        let packet = result.expect("should succeed");
        match packet {
            Packet::Single(frame) => {
                let expected_len = ETH_HEADER_LEN + IPV6_HEADER_LEN + 8 + payload.len();
                assert_eq!(frame.len(), expected_len);

                let ip = Ipv6Header::from_bytes(&frame);
                assert_eq!(ip.version(), 6);
                assert_eq!(ip.hop_limit, 64);
                assert_eq!(ip.next_header, IpProtocols::Udp);
                assert_eq!(ip.src_addr, SRC_V6);
                assert_eq!(ip.dst_addr, DST_V6);

                // Verify payload.
                let data_start = ETH_HEADER_LEN + IPV6_HEADER_LEN;
                assert_eq!(&frame[data_start + 8..frame.len()], payload);
            }
            _ => panic!("expected Single"),
        }
    }

    // --- IPv6 fragmented ---

    #[test]
    fn ipv6_fragmented() {
        let mut bufs: Vec<Vec<u8>> = (0..32).map(|_| vec![0u8; 2048]).collect();
        let mut free = make_free_frames(&mut bufs, 32);
        let payload = vec![0xCD; 3000];
        let transport = make_udp_transport(payload.len());

        let result = FragmentWriter::fragment_ipv6(
            SRC_MAC, DST_MAC, SRC_V6, DST_V6, 64, &transport, &payload, 1500, &mut free,
        );

        let packet = result.expect("should succeed");
        match packet {
            Packet::Multi(frames) => {
                assert!(frames.len() >= 2);

                let frag_ext_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
                let first_frag = Ipv6FragmentHeader::from_bytes_at(&frames[0], frag_ext_offset);
                let first_id = first_frag.identification();

                for f in &frames {
                    let ip = Ipv6Header::from_bytes(f);
                    assert_eq!(ip.next_header, 44); // Fragment ext header
                    assert_eq!(ip.src_addr, SRC_V6);
                    assert_eq!(ip.dst_addr, DST_V6);

                    let frag_hdr = Ipv6FragmentHeader::from_bytes_at(f, frag_ext_offset);
                    assert_eq!(frag_hdr.identification(), first_id);
                    assert_eq!(frag_hdr.next_header, IpProtocols::Udp);
                }

                // First fragment: MF set, offset 0.
                assert!(first_frag.more_fragments());
                assert_eq!(first_frag.fragment_offset(), 0);

                // Last fragment: MF clear.
                let last_frag =
                    Ipv6FragmentHeader::from_bytes_at(frames.last().unwrap(), frag_ext_offset);
                assert!(!last_frag.more_fragments());

                // Reassemble payload.
                let mut reassembled = Vec::new();
                for (i, f) in frames.iter().enumerate() {
                    let data_start = frag_ext_offset + FRAGMENT_EXT_LEN;
                    if i == 0 {
                        reassembled.extend_from_slice(&f[data_start + 8..f.len()]);
                    } else {
                        reassembled.extend_from_slice(&f[data_start..f.len()]);
                    }
                }
                assert_eq!(reassembled, payload);
            }
            _ => panic!("expected Multi"),
        }
    }

    // --- WouldBlock on insufficient frames ---

    #[test]
    fn ipv4_would_block_no_frames() {
        let mut free = BasicFrameBuffer::new(16);
        let transport = make_udp_transport(13);

        let result = FragmentWriter::fragment_ipv4(
            SRC_MAC,
            DST_MAC,
            SRC_V4,
            DST_V4,
            64,
            &transport,
            b"Hello, World!",
            1500,
            &mut free,
        );
        assert_eq!(result.unwrap_err(), WouldBlock);
    }

    #[test]
    fn ipv4_would_block_insufficient_frames_for_fragmentation() {
        // Need 3 frames for 3000-byte payload, only provide 2.
        let mut bufs: Vec<Vec<u8>> = (0..2).map(|_| vec![0u8; 2048]).collect();
        let mut free = make_free_frames(&mut bufs, 2);
        let payload = vec![0xAB; 3000];
        let transport = make_udp_transport(payload.len());

        let result = FragmentWriter::fragment_ipv4(
            SRC_MAC, DST_MAC, SRC_V4, DST_V4, 64, &transport, &payload, 1500, &mut free,
        );
        assert_eq!(result.unwrap_err(), WouldBlock);
    }

    #[test]
    fn ipv6_would_block_no_frames() {
        let mut free = BasicFrameBuffer::new(16);
        let transport = make_udp_transport(12);

        let result = FragmentWriter::fragment_ipv6(
            SRC_MAC,
            DST_MAC,
            SRC_V6,
            DST_V6,
            64,
            &transport,
            b"Hello, IPv6!",
            1500,
            &mut free,
        );
        assert_eq!(result.unwrap_err(), WouldBlock);
    }

    // --- Custom transport header ---

    struct FakeTransport {
        protocol: u8,
        header: [u8; 4],
    }

    impl TransportHeader for FakeTransport {
        fn protocol(&self) -> u8 {
            self.protocol
        }
        fn header_len(&self) -> usize {
            4
        }
        fn write_to(&self, buf: &mut [u8]) {
            buf[0..4].copy_from_slice(&self.header);
        }
    }

    #[test]
    fn ipv4_custom_transport() {
        let mut bufs: Vec<Vec<u8>> = (0..4).map(|_| vec![0u8; 2048]).collect();
        let mut free = make_free_frames(&mut bufs, 4);
        let transport = FakeTransport {
            protocol: 99,
            header: [0xDE, 0xAD, 0xBE, 0xEF],
        };
        let payload = b"test";

        let result = FragmentWriter::fragment_ipv4(
            SRC_MAC, DST_MAC, SRC_V4, DST_V4, 128, &transport, payload, 1500, &mut free,
        );

        match result.unwrap() {
            Packet::Single(frame) => {
                let ip = Ipv4Header::from_bytes(&frame);
                assert_eq!(ip.protocol, 99);
                assert_eq!(ip.ttl, 128);

                let data_start = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
                assert_eq!(
                    &frame[data_start..data_start + 4],
                    &[0xDE, 0xAD, 0xBE, 0xEF]
                );
                assert_eq!(&frame[data_start + 4..frame.len()], b"test");
            }
            _ => panic!("expected Single"),
        }
    }

    // --- Empty payload ---

    #[test]
    fn ipv4_empty_payload() {
        let mut bufs: Vec<Vec<u8>> = (0..4).map(|_| vec![0u8; 2048]).collect();
        let mut free = make_free_frames(&mut bufs, 4);
        let transport = make_udp_transport(0);

        let result = FragmentWriter::fragment_ipv4(
            SRC_MAC,
            DST_MAC,
            SRC_V4,
            DST_V4,
            64,
            &transport,
            &[],
            1500,
            &mut free,
        );

        match result.unwrap() {
            Packet::Single(frame) => {
                assert_eq!(frame.len(), ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + 8);
            }
            _ => panic!("expected Single"),
        }
    }

    #[test]
    fn ipv6_empty_payload() {
        let mut bufs: Vec<Vec<u8>> = (0..4).map(|_| vec![0u8; 2048]).collect();
        let mut free = make_free_frames(&mut bufs, 4);
        let transport = make_udp_transport(0);

        let result = FragmentWriter::fragment_ipv6(
            SRC_MAC,
            DST_MAC,
            SRC_V6,
            DST_V6,
            64,
            &transport,
            &[],
            1500,
            &mut free,
        );

        match result.unwrap() {
            Packet::Single(frame) => {
                assert_eq!(frame.len(), ETH_HEADER_LEN + IPV6_HEADER_LEN + 8);
            }
            _ => panic!("expected Single"),
        }
    }
}
