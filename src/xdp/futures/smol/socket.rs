use std::{os::fd::RawFd, sync::Arc};

use async_io::Async;

use crate::xdp::{
    error::Result,
    frame::FrameBuffer,
    socket::{SocketOwner, SocketRx, SocketTx},
};

use super::{SmolFd, SmolRecvFuture, SmolSendFuture, SmolSocketRx, SmolSocketTx};

pub struct SmolSocket<'umem> {
    owner: Arc<SocketOwner<'umem>>,
    rx: SmolSocketRx<'umem>,
    tx: SmolSocketTx<'umem>,
}

unsafe impl<'umem> Send for SmolSocket<'umem> {}

impl<'umem> SmolSocket<'umem> {
    pub fn new(
        owner: Arc<SocketOwner<'umem>>,
        rx: SocketRx<'umem>,
        tx: SocketTx<'umem>,
        async_fd: Arc<Async<SmolFd>>,
    ) -> Self {
        Self {
            owner,
            rx: SmolSocketRx::new(rx, async_fd.clone()),
            tx: SmolSocketTx::new(tx, async_fd),
        }
    }

    /// Splits the socket into its owner, rx, and tx components.
    #[inline(always)]
    pub fn split(
        self,
    ) -> (
        Arc<SocketOwner<'umem>>,
        SmolSocketRx<'umem>,
        SmolSocketTx<'umem>,
    ) {
        (self.owner, self.rx, self.tx)
    }

    /// Returns the file descriptor of the socket.
    #[inline(always)]
    pub fn fd(&self) -> RawFd {
        self.owner.fd()
    }

    /// Possibly wakes the tx queue, so the kernel continues to process outgoing packets.
    #[inline(always)]
    pub fn maybe_wake(&self) -> Result<()> {
        self.tx.maybe_wake()
    }

    /// Receives a batch of frames from the socket.
    #[inline(always)]
    pub fn recv<B: FrameBuffer<'umem>>(&mut self, batch: B) -> SmolRecvFuture<'_, 'umem, B> {
        self.rx.recv(batch)
    }

    /// Sends a batch of frames to the socket.
    #[inline(always)]
    pub fn send<B: FrameBuffer<'umem>>(&mut self, frames: B) -> SmolSendFuture<'_, 'umem, B> {
        self.tx.send(frames)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use crate::xdp::context::XdpContext;
    use crate::xdp::frame::{BasicFrameBuffer, FrameBuffer};
    use crate::xdp::program::AttachMode;
    use crate::xdp::socket::Socket;
    use crate::xdp::test_utils::TestVethPair;
    use crate::xdp::umem::Umem;

    /// Helper to build a minimal Ethernet frame with a payload.
    /// Format: [dst MAC (6)] [src MAC (6)] [EtherType (2)] [payload]
    fn build_ethernet_frame(dst_mac: &[u8; 6], src_mac: &[u8; 6], payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(14 + payload.len());
        frame.extend_from_slice(dst_mac);
        frame.extend_from_slice(src_mac);
        // EtherType 0x88B5 = Local Experimental EtherType
        frame.extend_from_slice(&[0x88, 0xB5]);
        frame.extend_from_slice(payload);
        frame
    }

    /// Test that sends a packet from one side of a veth pair and receives it on the other using smol async.
    #[test]
    fn test_smol_socket_send_recv() {
        smol::block_on(async {
            // Create veth pair
            let veth = TestVethPair::new().expect("failed to create veth pair");

            // Create XDP contexts on both ends
            let mut ctx_outer = XdpContext::builder(veth.outer_name())
                .attach_mode(AttachMode::default())
                .enable_fragmentation(false)
                .build()
                .expect("failed to create outer context");
            let mut ctx_inner = XdpContext::builder(veth.inner_name())
                .attach_mode(AttachMode::default())
                .enable_fragmentation(false)
                .build()
                .expect("failed to create inner context");

            // Create UMEM for outer socket (sender)
            let (umem_outer, _fq_outer, mut cq_outer) = Umem::builder(&mut ctx_outer)
                .num_frames(64)
                .frame_size(4096)
                .fill_ring_size(32)
                .completion_ring_size(32)
                .build_smol()
                .expect("failed to create outer umem")
                .split();

            // Create UMEM for inner socket (receiver)
            let (umem_inner, mut fq_inner, _cq_inner) = Umem::builder(&mut ctx_inner)
                .num_frames(64)
                .frame_size(4096)
                .fill_ring_size(32)
                .completion_ring_size(32)
                .build_smol()
                .expect("failed to create inner umem")
                .split();

            // Initialize frame buffers
            let mut tx_buffer: BasicFrameBuffer<'_> = umem_outer.init_buffer().unwrap();
            let mut rx_buffer: BasicFrameBuffer<'_> = umem_inner.init_buffer().unwrap();

            // Create smol sockets
            let mut socket_outer = Socket::builder(&mut ctx_outer, veth.outer_name(), 0)
                .build_smol(umem_outer.clone())
                .expect("failed to create outer smol socket");

            let mut socket_inner = Socket::builder(&mut ctx_inner, veth.inner_name(), 0)
                .build_smol(umem_inner.clone())
                .expect("failed to create inner smol socket");

            // Prime the receiver's fill queue so it can receive packets
            let rx_prime_count = rx_buffer.num_frames().min(32);
            let mut prime_buffer = BasicFrameBuffer::new(rx_prime_count);
            for frame in rx_buffer.drain(..rx_prime_count) {
                prime_buffer.push(frame);
            }
            fq_inner
                .process_queue(&mut prime_buffer, &[socket_inner.fd()])
                .await
                .expect("failed to process fill queue");

            // Build a test packet
            let payload = b"Hello XDP Smol Socket Test!";
            let packet_data = build_ethernet_frame(
                veth.inner_mac().as_bytes(),
                veth.outer_mac().as_bytes(),
                payload,
            );

            // Prepare a frame for sending
            let mut send_buffer = BasicFrameBuffer::new(1);
            let mut frame = tx_buffer.drain(..1).next().expect("no frames available");
            frame.copy_from(&packet_data);
            send_buffer.push(frame);

            // Send the packet (async)
            let sent = socket_outer
                .send(&mut send_buffer)
                .await
                .expect("send failed");
            assert_eq!(sent, 1, "expected to send 1 frame");
            assert_eq!(send_buffer.num_frames(), 0, "buffer should be drained");

            // Receive the packet with timeout using smol::Timer
            let mut recv_buffer = BasicFrameBuffer::new(16);
            let start = Instant::now();
            let timeout = Duration::from_secs(5);

            let recv_result = smol::future::race(
                async {
                    let r = socket_inner.recv(&mut recv_buffer).await;
                    Ok(r)
                },
                async {
                    smol::Timer::after(timeout).await;
                    Err("recv timed out")
                },
            )
            .await;

            let received = recv_result.expect("recv timed out").expect("recv failed");

            assert!(start.elapsed() < timeout, "should receive before timeout");
            assert!(received > 0, "expected to receive at least 1 frame");
            assert!(
                recv_buffer.num_frames() >= 1,
                "expected at least 1 received frame"
            );

            // Verify the received packet matches what we sent
            let recv_frame = recv_buffer.iter_frames().next().unwrap();
            assert!(
                recv_frame.len() >= packet_data.len(),
                "received frame too short"
            );
            assert_eq!(
                &recv_frame[..packet_data.len()],
                &packet_data[..],
                "packet data mismatch"
            );

            // Clean up: process completion queue to reclaim TX frame
            let mut reclaim_buffer = BasicFrameBuffer::new(1);
            cq_outer
                .process_queue(&mut reclaim_buffer)
                .await
                .expect("failed to process completion queue");
        });
    }

    /// Test smol socket creation and basic properties.
    #[test]
    fn test_smol_socket_creation() {
        smol::block_on(async {
            let veth = TestVethPair::new().expect("failed to create veth pair");

            let mut ctx = XdpContext::builder(veth.outer_name())
                .attach_mode(AttachMode::default())
                .enable_fragmentation(false)
                .build()
                .expect("failed to create context");

            let (umem, _fq, _cq) = Umem::builder(&mut ctx)
                .num_frames(16)
                .frame_size(4096)
                .fill_ring_size(8)
                .completion_ring_size(8)
                .build()
                .expect("failed to create umem")
                .split();

            let socket = Socket::builder(&mut ctx, veth.outer_name(), 0)
                .rx_ring_size(8)
                .tx_ring_size(8)
                .build_smol(umem)
                .expect("failed to create smol socket");

            // Socket should have valid fd
            assert!(socket.fd() >= 0, "socket fd should be valid");

            // Context should now have 1 socket registered
            assert_eq!(ctx.num_sockets(), 1, "context should have 1 socket");
        });
    }

    /// Test smol socket split into owner, rx, tx components.
    #[test]
    fn test_smol_socket_split() {
        smol::block_on(async {
            let veth = TestVethPair::new().expect("failed to create veth pair");

            let mut ctx = XdpContext::builder(veth.outer_name())
                .attach_mode(AttachMode::default())
                .enable_fragmentation(false)
                .build()
                .expect("failed to create context");

            let (umem, _fq, _cq) = Umem::builder(&mut ctx)
                .num_frames(16)
                .frame_size(4096)
                .fill_ring_size(8)
                .completion_ring_size(8)
                .build()
                .expect("failed to create umem")
                .split();

            let socket = Socket::builder(&mut ctx, veth.outer_name(), 0)
                .build_smol(umem)
                .expect("failed to create smol socket");

            let original_fd = socket.fd();
            let (owner, _rx, _tx) = socket.split();

            // Owner should have the same fd
            assert_eq!(owner.fd(), original_fd, "owner fd should match original");
        });
    }
}
