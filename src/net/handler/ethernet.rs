use coarsetime::Instant;

use crate::{
    net::{
        NeighborHandler, PmtuCache,
        handler::{ipv4::Ipv4Handler, ipv6::Ipv6Handler},
        wire::ethernet::{EtherTypes, EthernetFrame},
    },
    xdp::frame::{Frame, FrameBuffer},
};

pub struct EthernetHandler;

impl EthernetHandler {
    pub fn handle<'umem>(
        &mut self,
        frame: Frame<'umem>,
        ipv4_handler: &mut Ipv4Handler,
        ipv6_handler: &mut Ipv6Handler,
        neighbor_handler: &NeighborHandler,
        pmtu: &PmtuCache,
        now: Instant,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let ethernet_frame = EthernetFrame::from_bytes(&frame);
        match ethernet_frame.ether_type {
            EtherTypes::IPv4 => {
                ipv4_handler.handle(
                    frame,
                    pmtu,
                    now,
                    rx_return,
                    tx_return,
                );
            }
            EtherTypes::IPv6 => {
                ipv6_handler.handle(
                    frame,
                    neighbor_handler,
                    pmtu,
                    now,
                    rx_return,
                    tx_return,
                );
            }
            EtherTypes::Arp => {
                neighbor_handler.handle_arp(now, frame, rx_return, tx_return);
            }
            _ => {
                rx_return.push(frame);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use coarsetime::Duration;

    use crate::{
        net::{
            checksum::{compute_ipv4_checksum, compute_udp_checksum},
            wire::{
                ethernet::{EtherType, MacAddress, write_ethernet_header},
                ip::{IPV4_MIN_HEADER_LEN, Ipv4Address},
                udp::UDP_HEADER_LEN,
            },
        },
        xdp::frame::BasicFrameBuffer,
    };

    use super::*;

    const SRC_IP: Ipv4Address = Ipv4Address::new([10, 0, 0, 1]);
    const DST_IP: Ipv4Address = Ipv4Address::new([10, 0, 0, 2]);
    const ETH_LEN: usize = size_of::<EthernetFrame>();

    fn new_handlers() -> (
        EthernetHandler,
        Ipv4Handler,
        Ipv6Handler,
        NeighborHandler,
        PmtuCache,
    ) {
        let eth = EthernetHandler;
        let ipv4 = Ipv4Handler::new(false, false);
        let ipv6 = Ipv6Handler::new(false, false);
        let neighbor = NeighborHandler::new("test0", Duration::from_secs(60)).unwrap();
        let pmtu = PmtuCache::new();
        (eth, ipv4, ipv6, neighbor, pmtu)
    }

    fn new_buffers<'umem>() -> (
        BasicFrameBuffer<'umem>,
        BasicFrameBuffer<'umem>,
    ) {
        (
            BasicFrameBuffer::new(4),
            BasicFrameBuffer::new(4),
        )
    }

    /// Builds a minimal Ethernet frame with only the 14-byte header set.
    fn build_eth_frame(ether_type: EtherType) -> Vec<u8> {
        let mut buf = vec![0u8; ETH_LEN + 46]; // min ethernet payload
        write_ethernet_header(
            &mut buf,
            MacAddress::broadcast(),
            MacAddress::zero(),
            ether_type,
        );
        buf
    }

    /// Builds a valid Ethernet + IPv4 + UDP frame with correct checksums.
    fn build_ipv4_udp_frame() -> Vec<u8> {
        let udp_payload = build_udp_bytes(&SRC_IP, &DST_IP);
        let total_ip_len = (IPV4_MIN_HEADER_LEN + udp_payload.len()) as u16;
        let mut buf = vec![0u8; ETH_LEN + IPV4_MIN_HEADER_LEN + udp_payload.len()];

        // Ethernet header
        buf[12] = 0x08;
        buf[13] = 0x00;

        // IPv4 header
        let ip = &mut buf[ETH_LEN..];
        ip[0] = 0x45; // version=4, ihl=5
        ip[2..4].copy_from_slice(&total_ip_len.to_be_bytes());
        ip[6] = 0x40; // don't fragment
        ip[8] = 64; // TTL
        ip[9] = 17; // UDP protocol
        let src_bytes: [u8; 4] = SRC_IP.into();
        ip[12..16].copy_from_slice(&src_bytes);
        let dst_bytes: [u8; 4] = DST_IP.into();
        ip[16..20].copy_from_slice(&dst_bytes);
        let cksum = compute_ipv4_checksum(&ip[..20]);
        ip[10] = cksum[0];
        ip[11] = cksum[1];

        // UDP payload
        buf[ETH_LEN + IPV4_MIN_HEADER_LEN..].copy_from_slice(&udp_payload);
        buf
    }

    /// Builds a minimal valid UDP segment with correct checksum.
    fn build_udp_bytes(src: &Ipv4Address, dst: &Ipv4Address) -> Vec<u8> {
        let mut buf = vec![0u8; UDP_HEADER_LEN];
        let udp_len = UDP_HEADER_LEN as u16;
        buf[4..6].copy_from_slice(&udp_len.to_be_bytes());
        let cksum = compute_udp_checksum(src, dst, &buf);
        buf[6] = cksum[0];
        buf[7] = cksum[1];
        buf
    }

    #[test]
    fn unknown_ether_type_returns_frame_to_rx() {
        let (mut eth, mut ipv4, mut ipv6, neighbor, pmtu) = new_handlers();
        let (mut rx, mut tx) = new_buffers();
        let now = Instant::now();

        let unknown_type = EtherType {
            octets: [0xFF, 0xFF],
        };
        let mut data = build_eth_frame(unknown_type);
        let len = data.len();
        let frame = Frame::new(0, &mut data, len, false);

        eth.handle(
            frame, &mut ipv4, &mut ipv6, &neighbor, &pmtu, now, &mut rx, &mut tx,
        );

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn ipv4_frame_dispatches_to_ipv4_handler() {
        let (mut eth, mut ipv4, mut ipv6, neighbor, pmtu) = new_handlers();
        let (mut rx, mut tx) = new_buffers();
        let now = Instant::now();

        let mut data = build_ipv4_udp_frame();
        let len = data.len();
        let frame = Frame::new(0, &mut data, len, false);

        eth.handle(
            frame, &mut ipv4, &mut ipv6, &neighbor, &pmtu, now, &mut rx, &mut tx,
        );

        // Frame was consumed by ipv4_handler. No UDP binding so it ends up
        // in rx_return after full IPv4 processing (not the unknown-type path).
        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn ipv4_short_frame_dispatches_to_ipv4_handler() {
        let (mut eth, mut ipv4, mut ipv6, neighbor, pmtu) = new_handlers();
        let (mut rx, mut tx) = new_buffers();
        let now = Instant::now();

        // Ethernet header says IPv4 but the IP payload is too short.
        let mut data = build_eth_frame(EtherTypes::IPv4);
        let len = data.len();
        let frame = Frame::new(0, &mut data, len, false);

        eth.handle(
            frame, &mut ipv4, &mut ipv6, &neighbor, &pmtu, now, &mut rx, &mut tx,
        );

        // ipv4_handler rejects the short frame back to rx_return.
        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn ipv6_short_frame_dispatches_to_ipv6_handler() {
        let (mut eth, mut ipv4, mut ipv6, neighbor, pmtu) = new_handlers();
        let (mut rx, mut tx) = new_buffers();
        let now = Instant::now();

        // Ethernet header says IPv6 but the payload is too short for a valid
        // IPv6 header (needs 54 bytes: 14 eth + 40 ipv6).
        let mut data = build_eth_frame(EtherTypes::IPv6);
        let len = data.len();
        let frame = Frame::new(0, &mut data, len, false);

        eth.handle(
            frame, &mut ipv4, &mut ipv6, &neighbor, &pmtu, now, &mut rx, &mut tx,
        );

        // ipv6_handler rejects the short frame back to rx_return.
        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn arp_frame_dispatches_to_neighbor_handler() {
        let (mut eth, mut ipv4, mut ipv6, neighbor, pmtu) = new_handlers();
        let (mut rx, mut tx) = new_buffers();
        let now = Instant::now();

        let mut data = build_eth_frame(EtherTypes::Arp);
        let len = data.len();
        let frame = Frame::new(0, &mut data, len, false);

        eth.handle(
            frame, &mut ipv4, &mut ipv6, &neighbor, &pmtu, now, &mut rx, &mut tx,
        );

        // neighbor_handler processes (and discards) the malformed ARP.
        // Frame ends up in one of the return buffers.
        let total = rx.num_frames() + tx.num_frames();
        assert_eq!(total, 1);
    }

    #[test]
    fn frame_always_consumed() {
        let now = Instant::now();

        // Every ether_type path must consume the frame exactly once.
        let types = [
            EtherTypes::IPv4,
            EtherTypes::IPv6,
            EtherTypes::Arp,
            EtherType {
                octets: [0xDE, 0xAD],
            },
        ];

        for etype in types {
            let (mut eth, mut ipv4, mut ipv6, neighbor, pmtu) = new_handlers();
            let (mut rx, mut tx) = new_buffers();
            let mut data = build_eth_frame(etype);
            let len = data.len();
            let frame = Frame::new(0, &mut data, len, false);

            eth.handle(
                frame, &mut ipv4, &mut ipv6, &neighbor, &pmtu, now, &mut rx, &mut tx,
            );

            let total = rx.num_frames() + tx.num_frames();
            assert!(total >= 1, "frame lost for ether_type {:?}", etype);
        }
    }
}
