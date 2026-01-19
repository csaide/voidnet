use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use libvoid::xdp::{
    context::XdpContext,
    frame::{BasicFrameBuffer, FrameBuffer},
    socket::Socket,
    test_utils::TestVethPair,
    umem::Umem,
};

fn build_ethernet_frame(dst_mac: &[u8; 6], src_mac: &[u8; 6], payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(dst_mac);
    frame.extend_from_slice(src_mac);
    // EtherType 0x0800 = IPv4, but we'll use a custom one for testing
    frame.extend_from_slice(&[0x88, 0xB5]); // Local Experimental EtherType
    frame.extend_from_slice(payload);
    frame
}

#[test]
fn test_sync() {
    // Create veth pair
    let veth = TestVethPair::new().expect("failed to create veth pair");

    let done_sending = Arc::new(AtomicBool::new(false));
    let target_count = 1_000_000;

    let inner_name = veth.inner_name().to_string();
    let inner_done_sending = done_sending.clone();
    let inner_handle = thread::spawn(move || {
        let mut ctx_inner = XdpContext::builder(&inner_name)
            .build()
            .expect("failed to create inner context");

        // Create UMEM for inner socket (receiver)
        let mut umem_inner = Umem::builder(&mut ctx_inner)
            .num_frames(2048)
            .build()
            .expect("failed to create inner umem");

        // Create inner socket and initialize frame buffer
        let mut socket_inner = Socket::builder(&mut ctx_inner, &inner_name, 0)
            .build(umem_inner.owner().clone())
            .expect("failed to create inner socket");
        let mut rx_buffer: BasicFrameBuffer<'_> = umem_inner.init_buffer().unwrap();

        // Wake up the fill queue and process the fill queue
        umem_inner.maybe_wake_fill_queue(socket_inner.fd()).unwrap();
        umem_inner.process_fill_queue(&mut rx_buffer);

        let mut count = 0;
        while count < target_count {
            match socket_inner.recv(&mut rx_buffer) {
                Ok(n) => {
                    count += n;
                }
                Err(_) if inner_done_sending.load(Ordering::Relaxed) => break,
                Err(_) => {
                    umem_inner.maybe_wake_fill_queue(socket_inner.fd()).unwrap();
                    continue;
                }
            }

            umem_inner.maybe_wake_fill_queue(socket_inner.fd()).unwrap();
            umem_inner.process_fill_queue(&mut rx_buffer);
        }
        assert!(count >= target_count, "did not receive enough packets");
    });

    thread::sleep(Duration::from_millis(100));

    let outer_name = veth.outer_name().to_string();
    let outer_mac = veth.outer_mac();
    let inner_mac = veth.inner_mac();
    let outer_handle = thread::spawn(move || {
        let mut ctx_outer = XdpContext::builder(&outer_name)
            .build()
            .expect("failed to create outer context");

        // Create UMEM for outer socket (sender)
        let mut umem_outer = Umem::builder(&mut ctx_outer)
            .num_frames(32)
            .build()
            .expect("failed to create outer umem");

        // Initialize frame buffers
        let mut tx_buffer: BasicFrameBuffer<'_> = umem_outer.init_buffer().unwrap();

        // Create sockets
        let mut socket_outer = Socket::builder(&mut ctx_outer, &outer_name, 0)
            .build(umem_outer.owner().clone())
            .expect("failed to create outer socket");

        let mut count = 0;

        let packet_data =
            build_ethernet_frame(inner_mac.as_bytes(), outer_mac.as_bytes(), b"Hello, world!");
        for frame in tx_buffer.iter_frames_mut() {
            frame.copy_from(&packet_data);
        }

        while count < target_count {
            match socket_outer.send(&mut tx_buffer) {
                Ok(sent) => {
                    count += sent;
                }
                Err(_) => {
                    continue;
                }
            };

            while let Err(_) = umem_outer.process_completion_queue(&mut tx_buffer) {
                socket_outer.maybe_wake().unwrap();
            }

            for frame in tx_buffer.iter_frames_mut() {
                frame.copy_from(&packet_data);
            }
        }

        assert!(count >= target_count, "did not send enough packets");
        done_sending.store(true, Ordering::Relaxed);
    });

    inner_handle.join().expect("inner thread panicked");
    outer_handle.join().expect("outer thread panicked");
}
