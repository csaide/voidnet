use coarsetime::Instant;

use crate::{
    net::{
        NeighborHandler,
        wire::ethernet::{EtherTypes, EthernetFrame},
    },
    xdp::frame::{Frame, FrameBuffer},
};

pub struct EthernetHandler;

impl EthernetHandler {
    pub fn handle<'umem>(
        &mut self,
        frame: Frame<'umem>,
        neighbor_handler: &NeighborHandler,
        now: Instant,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let ethernet_frame = EthernetFrame::from_bytes(&frame);
        match ethernet_frame.ether_type {
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
        net::wire::ethernet::{EtherType, MacAddress, write_ethernet_header},
        xdp::frame::BasicFrameBuffer,
    };

    use super::*;

    const ETH_LEN: usize = size_of::<EthernetFrame>();

    fn new_handlers() -> (EthernetHandler, NeighborHandler) {
        let eth = EthernetHandler;
        let neighbor = NeighborHandler::new("test0", Duration::from_secs(60)).unwrap();
        (eth, neighbor)
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

    #[test]
    fn unknown_ether_type_returns_frame_to_rx() {
        let (mut eth, neighbor) = new_handlers();
        let (mut rx, mut tx) = new_buffers();
        let now = Instant::now();

        let unknown_type = EtherType {
            octets: [0xFF, 0xFF],
        };
        let mut data = build_eth_frame(unknown_type);
        let len = data.len();
        let frame = Frame::new(0, &mut data, len, false);

        eth.handle(frame, &neighbor, now, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn arp_frame_dispatches_to_neighbor_handler() {
        let (mut eth, neighbor) = new_handlers();
        let (mut rx, mut tx) = new_buffers();
        let now = Instant::now();

        let mut data = build_eth_frame(EtherTypes::Arp);
        let len = data.len();
        let frame = Frame::new(0, &mut data, len, false);

        eth.handle(frame, &neighbor, now, &mut rx, &mut tx);

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
            EtherTypes::Arp,
            EtherType {
                octets: [0xDE, 0xAD],
            },
        ];

        for etype in types {
            let (mut eth, neighbor) = new_handlers();
            let (mut rx, mut tx) = new_buffers();
            let mut data = build_eth_frame(etype);
            let len = data.len();
            let frame = Frame::new(0, &mut data, len, false);

            eth.handle(frame, &neighbor, now, &mut rx, &mut tx);

            let total = rx.num_frames() + tx.num_frames();
            assert!(total >= 1, "frame lost for ether_type {:?}", etype);
        }
    }
}
