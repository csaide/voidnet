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
    futures::LocalExecutor,
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
fn test_local() {
    // Create veth pair
    let veth = TestVethPair::new().expect("failed to create veth pair");

    let done_sending = Arc::new(AtomicBool::new(false));
    let target_count = 1_000_000;

    let mut inner_exec = LocalExecutor::new().expect("failed to create inner executor");
    let mut outer_exec = LocalExecutor::new().expect("failed to create outer executor");

    let inner_done_sending = done_sending.clone();
    let inner_name = veth.inner_name().to_string();
    let mut ctx_inner = XdpContext::builder(&inner_name)
        .build()
        .expect("failed to create inner context");

    // Create UMEM for inner socket (receiver)
    let mut umem_inner = Umem::builder(&mut ctx_inner)
        .num_frames(2048)
        .build_local()
        .expect("failed to create inner umem");

    // Create inner socket and initialize frame buffer
    let mut socket_inner = Socket::builder(&mut ctx_inner, &inner_name, 0)
        .build_local(umem_inner.owner().clone())
        .expect("failed to create inner socket");
    let mut rx_buffer: BasicFrameBuffer<'_> = umem_inner.init_buffer().unwrap();
    let inner_fd = socket_inner.fd();
    let inner_task = async move {
        // Wake up the fill queue and process the fill queue
        umem_inner
            .process_fill_queue(&mut rx_buffer, &[socket_inner.fd()])
            .await
            .unwrap();

        let mut count = 0;
        while count < target_count {
            match socket_inner.recv(&mut rx_buffer).await {
                Ok(n) => {
                    count += n;
                }
                Err(_) if inner_done_sending.load(Ordering::Relaxed) => break,
                Err(_) => {
                    continue;
                }
            }

            umem_inner
                .process_fill_queue(&mut rx_buffer, &[socket_inner.fd()])
                .await
                .unwrap();
        }
        assert!(count >= target_count, "did not receive enough packets");
    };

    let outer_name = veth.outer_name().to_string();
    let outer_mac = veth.outer_mac();
    let inner_mac = veth.inner_mac();
    let mut ctx_outer = XdpContext::builder(&outer_name)
        .build()
        .expect("failed to create outer context");

    // Create UMEM for outer socket (sender)
    let mut umem_outer = Umem::builder(&mut ctx_outer)
        .num_frames(10)
        .build_local()
        .expect("failed to create outer umem");

    // Initialize frame buffers
    let mut tx_buffer: BasicFrameBuffer<'_> = umem_outer.init_buffer().unwrap();

    // Create sockets
    let mut socket_outer = Socket::builder(&mut ctx_outer, &outer_name, 0)
        .build_local(umem_outer.owner().clone())
        .expect("failed to create outer socket");
    let outer_fd = socket_outer.fd();
    let outer_task = async move {
        let mut count = 0;

        let packet_data =
            build_ethernet_frame(inner_mac.as_bytes(), outer_mac.as_bytes(), b"Hello, world!");
        for frame in tx_buffer.iter_frames_mut() {
            frame.copy_from(&packet_data);
        }

        while count < target_count {
            match socket_outer.send(&mut tx_buffer).await {
                Ok(sent) => {
                    count += sent;
                }
                Err(_) => {
                    continue;
                }
            };

            umem_outer
                .process_completion_queue(&mut tx_buffer)
                .await
                .unwrap();

            for frame in tx_buffer.iter_frames_mut() {
                frame.copy_from(&packet_data);
            }
        }
        assert!(count >= target_count, "did not send enough packets");
        done_sending.store(true, Ordering::Relaxed);
    };

    let inner_handle = thread::spawn(move || {
        inner_exec
            .register(inner_fd)
            .expect("failed to register inner socket");
        inner_exec.run(inner_task);
    });

    thread::sleep(Duration::from_millis(100));

    let outer_handle = thread::spawn(move || {
        outer_exec
            .register(outer_fd)
            .expect("failed to register outer socket");
        outer_exec.run(outer_task);
    });

    inner_handle.join().unwrap();
    outer_handle.join().unwrap();
}
