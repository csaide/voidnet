use super::*;

#[test]
fn syn_to_listener_generates_syn_ack() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(4);
    let mut rx = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(4);

    free.push(alloc_free_frame(100));

    let accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();

    // MSS option in SYN.
    let mss_opt = [0x02, 0x04, 0x05, 0xB4]; // MSS=1460
    let data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1000,
        0,
        flags::SYN,
        65535,
        &mss_opt,
    );
    let len = data.len();
    let frame = Frame::new(0, leak(data), len, false);

    handler.process_ipv4(frame, &nh, &mut free, &mut rx, &mut tx);

    assert_eq!(rx.num_frames(), 1, "original frame to rx");
    assert_eq!(tx.num_frames(), 1, "SYN-ACK generated");
    assert_eq!(handler.connections.len(), 1, "connection created");
    assert_eq!(handler.connections[0].state, TcpState::SynReceived);
    assert_eq!(handler.connections[0].snd_mss, 1460);
    assert!(accept_queue.is_empty(), "not yet in accept queue");
}

#[test]
fn handshake_completes_on_ack() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(8);
    let mut rx = BasicFrameBuffer::new(8);
    let mut tx = BasicFrameBuffer::new(8);

    for i in 0..4 {
        free.push(alloc_free_frame(100 + i));
    }

    let accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();

    // Step 1: SYN.
    let syn_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1000,
        0,
        flags::SYN,
        65535,
        &[],
    );
    let syn_len = syn_data.len();
    let syn_frame = Frame::new(0, leak(syn_data), syn_len, false);
    handler.process_ipv4(syn_frame, &nh, &mut free, &mut rx, &mut tx);
    assert_eq!(handler.connections[0].state, TcpState::SynReceived);

    // Get ISS from the TCB.
    let server_iss = handler.connections[0].iss;

    // Step 2: ACK completing handshake.
    let ack_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        server_iss.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
    );
    let ack_len = ack_data.len();
    let ack_frame = Frame::new(1, leak(ack_data), ack_len, false);
    handler.process_ipv4(ack_frame, &nh, &mut free, &mut rx, &mut tx);

    assert_eq!(handler.connections[0].state, TcpState::Established);
    assert_eq!(accept_queue.len(), 1, "connection in accept queue");
}

#[test]
fn rst_in_syn_received_removes_connection() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(8);
    let mut rx = BasicFrameBuffer::new(8);
    let mut tx = BasicFrameBuffer::new(8);

    for i in 0..4 {
        free.push(alloc_free_frame(100 + i));
    }

    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();

    // SYN.
    let syn_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1000,
        0,
        flags::SYN,
        65535,
        &[],
    );
    let syn_len = syn_data.len();
    let syn_frame = Frame::new(0, leak(syn_data), syn_len, false);
    handler.process_ipv4(syn_frame, &nh, &mut free, &mut rx, &mut tx);
    assert_eq!(handler.connections.len(), 1);

    // RST.
    let rcv_nxt = handler.connections[0].rcv_nxt;
    let rst_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        rcv_nxt,
        0,
        flags::RST,
        0,
        &[],
    );
    let rst_len = rst_data.len();
    let rst_frame = Frame::new(2, leak(rst_data), rst_len, false);
    handler.process_ipv4(rst_frame, &nh, &mut free, &mut rx, &mut tx);

    assert_eq!(handler.connections.len(), 0, "connection removed");
}

#[test]
fn backlog_limits_syn_received() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);

    for i in 0..8 {
        free.push(alloc_free_frame(100 + i));
    }

    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 2).unwrap();

    // Send 3 SYNs — only 2 should be accepted (backlog=2).
    for i in 0..3u16 {
        let syn_data = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            10000 + i,
            80,
            1000,
            0,
            flags::SYN,
            65535,
            &[],
        );
        let syn_len = syn_data.len();
        let syn_frame = Frame::new(i as u64, leak(syn_data), syn_len, false);
        handler.process_ipv4(syn_frame, &nh, &mut free, &mut rx, &mut tx);
    }

    assert_eq!(handler.connections.len(), 2, "backlog limits connections");
}

#[test]
fn window_scale_negotiation() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(8);
    let mut rx = BasicFrameBuffer::new(8);
    let mut tx = BasicFrameBuffer::new(8);

    for i in 0..4 {
        free.push(alloc_free_frame(100 + i));
    }

    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();

    // SYN with MSS + Window Scale options.
    let ws_opts = [
        0x02, 0x04, 0x05, 0xB4, // MSS=1460
        0x01, // NOP
        0x03, 0x03, 0x07, // Window Scale=7
    ];
    let syn_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1000,
        0,
        flags::SYN,
        65535,
        &ws_opts,
    );
    let syn_len = syn_data.len();
    let syn_frame = Frame::new(0, leak(syn_data), syn_len, false);
    handler.process_ipv4(syn_frame, &nh, &mut free, &mut rx, &mut tx);

    assert!(handler.connections[0].wscale_enabled);
    assert_eq!(handler.connections[0].snd_wscale, 7);
    assert_eq!(handler.connections[0].rcv_wscale, DEFAULT_RCV_WSCALE);
}

#[test]
fn simultaneous_open_both_reach_established() {
    // Two handlers representing side A and side B.
    let mut handler_a = new_handler();
    let mut handler_b = new_handler();
    let nh = new_neighbor_handler();

    let ip_a = Ipv4Address::new([10, 0, 0, 1]);
    let ip_b = Ipv4Address::new([10, 0, 0, 2]);
    let port_a: u16 = 5000;
    let port_b: u16 = 6000;
    let mac_a = MacAddress::new([0xAA, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let mac_b = MacAddress::new([0xBB, 0x00, 0x00, 0x00, 0x00, 0x02]);

    let mut free_a = BasicFrameBuffer::new(16);
    let mut free_b = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);

    for i in 0..8 {
        free_a.push(alloc_free_frame(200 + i));
        free_b.push(alloc_free_frame(300 + i));
    }

    // Both sides initiate active open (connect).
    let events_a = handler_a
        .connect(
            IpAddress::V4(ip_a),
            port_a,
            IpAddress::V4(ip_b),
            port_b,
            mac_a,
            mac_b,
            &mut free_a,
            &mut tx,
        )
        .unwrap();
    // Discard the SYN frame emitted by connect — we'll build frames manually.
    while tx.pop().is_some() {}

    let events_b = handler_b
        .connect(
            IpAddress::V4(ip_b),
            port_b,
            IpAddress::V4(ip_a),
            port_a,
            mac_b,
            mac_a,
            &mut free_b,
            &mut tx,
        )
        .unwrap();
    while tx.pop().is_some() {}

    assert_eq!(handler_a.connections[0].state, TcpState::SynSent);
    assert_eq!(handler_b.connections[0].state, TcpState::SynSent);

    let iss_a = handler_a.connections[0].iss;
    let iss_b = handler_b.connections[0].iss;

    // Step 1: Feed side B's SYN to handler A.
    // B sent SYN with seq=ISS_B, no ACK. A should transition to SynReceived.
    let syn_b = build_tcp_frame(
        ip_b,
        ip_a,
        port_b,
        port_a,
        iss_b,
        0,
        flags::SYN,
        65535,
        &[0x02, 0x04, 0x05, 0xB4], // MSS=1460
    );
    let syn_b_len = syn_b.len();
    handler_a.process_ipv4(
        Frame::new(10, leak(syn_b), syn_b_len, false),
        &nh,
        &mut free_a,
        &mut rx,
        &mut tx,
    );
    assert_eq!(
        handler_a.connections[0].state,
        TcpState::SynReceived,
        "A should transition to SynReceived on receiving B's SYN"
    );
    // A emits a SYN-ACK on tx.
    assert!(tx.num_frames() >= 1, "A should emit SYN-ACK");
    while tx.pop().is_some() {}
    while rx.pop().is_some() {}

    // Step 2: Feed side A's SYN to handler B.
    let syn_a = build_tcp_frame(
        ip_a,
        ip_b,
        port_a,
        port_b,
        iss_a,
        0,
        flags::SYN,
        65535,
        &[0x02, 0x04, 0x05, 0xB4],
    );
    let syn_a_len = syn_a.len();
    handler_b.process_ipv4(
        Frame::new(11, leak(syn_a), syn_a_len, false),
        &nh,
        &mut free_b,
        &mut rx,
        &mut tx,
    );
    assert_eq!(
        handler_b.connections[0].state,
        TcpState::SynReceived,
        "B should transition to SynReceived on receiving A's SYN"
    );
    assert!(tx.num_frames() >= 1, "B should emit SYN-ACK");
    while tx.pop().is_some() {}
    while rx.pop().is_some() {}

    // Step 3: Feed B's SYN-ACK to handler A.
    // B's SYN-ACK: seq=ISS_B, ack=ISS_A+1, flags=SYN|ACK.
    let syn_ack_b = build_tcp_frame(
        ip_b,
        ip_a,
        port_b,
        port_a,
        iss_b,
        iss_a.wrapping_add(1),
        flags::SYN | flags::ACK,
        65535,
        &[0x02, 0x04, 0x05, 0xB4],
    );
    let syn_ack_b_len = syn_ack_b.len();
    handler_a.process_ipv4(
        Frame::new(12, leak(syn_ack_b), syn_ack_b_len, false),
        &nh,
        &mut free_a,
        &mut rx,
        &mut tx,
    );
    assert_eq!(
        handler_a.connections[0].state,
        TcpState::Established,
        "A should transition to Established on receiving B's SYN-ACK"
    );
    while tx.pop().is_some() {}
    while rx.pop().is_some() {}

    // Step 4: Feed A's SYN-ACK to handler B.
    let syn_ack_a = build_tcp_frame(
        ip_a,
        ip_b,
        port_a,
        port_b,
        iss_a,
        iss_b.wrapping_add(1),
        flags::SYN | flags::ACK,
        65535,
        &[0x02, 0x04, 0x05, 0xB4],
    );
    let syn_ack_a_len = syn_ack_a.len();
    handler_b.process_ipv4(
        Frame::new(13, leak(syn_ack_a), syn_ack_a_len, false),
        &nh,
        &mut free_b,
        &mut rx,
        &mut tx,
    );
    assert_eq!(
        handler_b.connections[0].state,
        TcpState::Established,
        "B should transition to Established on receiving A's SYN-ACK"
    );

    // Verify both sides emitted Connected events.
    assert!(events_a.pop().is_some(), "A should have a Connected event");
    assert!(events_b.pop().is_some(), "B should have a Connected event");
}

