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

    handler.process_ipv4(
        frame,
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert_eq!(rx.num_frames(), 1, "original frame to rx");
    assert_eq!(tx.num_frames(), 1, "SYN-ACK generated");
    assert_eq!(handler.connections.len(), 1, "connection created");
    assert_eq!(handler.first_connection().state, TcpState::SynReceived);
    assert_eq!(handler.first_connection().snd_mss, 1460);
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
    handler.process_ipv4(
        syn_frame,
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(handler.first_connection().state, TcpState::SynReceived);

    // Get ISS from the TCB.
    let server_iss = handler.first_connection().iss;

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
    handler.process_ipv4(
        ack_frame,
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert_eq!(handler.first_connection().state, TcpState::Established);
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
    handler.process_ipv4(
        syn_frame,
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(handler.connections.len(), 1);

    // RST.
    let rcv_nxt = handler.first_connection().rcv_nxt;
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
    handler.process_ipv4(
        rst_frame,
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

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
        handler.process_ipv4(
            syn_frame,
            coarsetime::Instant::now(),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
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
    handler.process_ipv4(
        syn_frame,
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert!(handler.first_connection().wscale_enabled);
    assert_eq!(handler.first_connection().snd_wscale, 7);
    assert_eq!(handler.first_connection().rcv_wscale, DEFAULT_RCV_WSCALE);
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
    let (_key_a, events_a) = handler_a
        .connect(
            IpAddress::V4(ip_a),
            port_a,
            IpAddress::V4(ip_b),
            port_b,
            mac_a,
            mac_b,
            coarsetime::Instant::now(),
            &mut free_a,
            &mut tx,
        )
        .unwrap();
    // Discard the SYN frame emitted by connect — we'll build frames manually.
    while tx.pop().is_some() {}

    let (_key_b, events_b) = handler_b
        .connect(
            IpAddress::V4(ip_b),
            port_b,
            IpAddress::V4(ip_a),
            port_a,
            mac_b,
            mac_a,
            coarsetime::Instant::now(),
            &mut free_b,
            &mut tx,
        )
        .unwrap();
    while tx.pop().is_some() {}

    assert_eq!(handler_a.first_connection().state, TcpState::SynSent);
    assert_eq!(handler_b.first_connection().state, TcpState::SynSent);

    let iss_a = handler_a.first_connection().iss;
    let iss_b = handler_b.first_connection().iss;

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
        coarsetime::Instant::now(),
        &nh,
        &mut free_a,
        &mut rx,
        &mut tx,
    );
    assert_eq!(
        handler_a.first_connection().state,
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
        coarsetime::Instant::now(),
        &nh,
        &mut free_b,
        &mut rx,
        &mut tx,
    );
    assert_eq!(
        handler_b.first_connection().state,
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
        coarsetime::Instant::now(),
        &nh,
        &mut free_a,
        &mut rx,
        &mut tx,
    );
    assert_eq!(
        handler_a.first_connection().state,
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
        coarsetime::Instant::now(),
        &nh,
        &mut free_b,
        &mut rx,
        &mut tx,
    );
    assert_eq!(
        handler_b.first_connection().state,
        TcpState::Established,
        "B should transition to Established on receiving A's SYN-ACK"
    );

    // Verify both sides emitted Connected events.
    assert!(events_a.pop().is_some(), "A should have a Connected event");
    assert!(events_b.pop().is_some(), "B should have a Connected event");
}

#[test]
fn bad_seq_in_syn_received_sends_challenge_ack() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(8);
    let mut rx = BasicFrameBuffer::new(8);
    let mut tx = BasicFrameBuffer::new(8);

    for i in 0..4 {
        free.push(alloc_free_frame(100 + i));
    }

    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();

    // SYN to create connection in SynReceived.
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
    handler.process_ipv4(
        Frame::new(0, leak(syn_data), syn_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(handler.first_connection().state, TcpState::SynReceived);
    while tx.pop().is_some() {}

    let server_iss = handler.first_connection().iss;
    let rcv_nxt = handler.first_connection().rcv_nxt;

    // Send ACK with bad sequence number (far from rcv_nxt).
    let bad_seq = rcv_nxt.wrapping_add(999);
    let bad_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        bad_seq,
        server_iss.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
    );
    let bad_len = bad_data.len();
    handler.process_ipv4(
        Frame::new(2, leak(bad_data), bad_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Should still be in SynReceived and a challenge ACK should be emitted.
    assert_eq!(handler.first_connection().state, TcpState::SynReceived);
    assert_eq!(tx.num_frames(), 1, "challenge ACK emitted");
}

#[test]
fn bad_seq_rst_in_syn_received_is_ignored() {
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
    handler.process_ipv4(
        Frame::new(0, leak(syn_data), syn_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(handler.connections.len(), 1);
    while tx.pop().is_some() {}

    let rcv_nxt = handler.first_connection().rcv_nxt;

    // RST with bad sequence number — should be silently ignored (no challenge ACK for RST).
    let bad_seq = rcv_nxt.wrapping_add(999);
    let rst_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        bad_seq,
        0,
        flags::RST,
        0,
        &[],
    );
    let rst_len = rst_data.len();
    handler.process_ipv4(
        Frame::new(2, leak(rst_data), rst_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Connection should still exist (RST ignored) and no challenge ACK sent.
    assert_eq!(handler.connections.len(), 1, "connection not removed");
    assert_eq!(tx.num_frames(), 0, "no challenge ACK for out-of-window RST");
}

#[test]
fn rst_in_syn_received_active_open_signals_refused() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);

    for i in 0..8 {
        free.push(alloc_free_frame(100 + i));
    }

    let ip_a = LOCAL_IP;
    let ip_b = REMOTE_IP;
    let port_a: u16 = 5000;
    let port_b: u16 = 6000;
    let src_mac = MacAddress::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    let dst_mac = MacAddress::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

    nh.seed_cache(coarsetime::Instant::now(), IpAddress::V4(ip_b), dst_mac);

    // Active open: connect sends SYN, puts connection in SynSent.
    let (_key, events) = handler
        .connect(
            IpAddress::V4(ip_a),
            port_a,
            IpAddress::V4(ip_b),
            port_b,
            src_mac,
            dst_mac,
            coarsetime::Instant::now(),
            &mut free,
            &mut tx,
        )
        .unwrap();
    while tx.pop().is_some() {}

    let _iss_a = handler.first_connection().iss;

    // Feed a SYN from B (simultaneous open) to move A to SynReceived.
    let syn_b = build_tcp_frame(
        ip_b,
        ip_a,
        port_b,
        port_a,
        2000,
        0,
        flags::SYN,
        65535,
        &[0x02, 0x04, 0x05, 0xB4],
    );
    let syn_b_len = syn_b.len();
    handler.process_ipv4(
        Frame::new(10, leak(syn_b), syn_b_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(handler.first_connection().state, TcpState::SynReceived);
    assert!(!handler.first_connection().from_passive_open);
    while tx.pop().is_some() {}
    while rx.pop().is_some() {}

    // Now send RST with correct seq (rcv_nxt).
    let rcv_nxt = handler.first_connection().rcv_nxt;
    let rst_data = build_tcp_frame(ip_b, ip_a, port_b, port_a, rcv_nxt, 0, flags::RST, 0, &[]);
    let rst_len = rst_data.len();
    handler.process_ipv4(
        Frame::new(11, leak(rst_data), rst_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert_eq!(handler.connections.len(), 0, "connection removed");
    // Should have ConnectionRefused event.
    let event = events.pop();
    assert!(event.is_some(), "event emitted");
    assert!(
        matches!(event.unwrap(), TcpEvent::ConnectionRefused),
        "ConnectionRefused event"
    );
}

#[test]
fn syn_retransmit_in_syn_received_passive_resends_syn_ack() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(8);
    let mut rx = BasicFrameBuffer::new(8);
    let mut tx = BasicFrameBuffer::new(8);

    for i in 0..4 {
        free.push(alloc_free_frame(100 + i));
    }

    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();

    // Original SYN.
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
    handler.process_ipv4(
        Frame::new(0, leak(syn_data), syn_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(handler.first_connection().state, TcpState::SynReceived);
    assert_eq!(tx.num_frames(), 1, "first SYN-ACK");
    while tx.pop().is_some() {}
    while rx.pop().is_some() {}

    // Retransmit the same SYN (same seq, pure SYN no ACK).
    // The seq matches rcv_nxt - 1 via the SYN special case: seg_seq + 1 == rcv_nxt.
    let syn_retransmit = build_tcp_frame(
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
    let syn_rt_len = syn_retransmit.len();
    handler.process_ipv4(
        Frame::new(2, leak(syn_retransmit), syn_rt_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Should still be SynReceived and a SYN-ACK re-sent.
    assert_eq!(handler.first_connection().state, TcpState::SynReceived);
    assert_eq!(tx.num_frames(), 1, "SYN-ACK retransmitted");
}

#[test]
fn syn_retransmit_in_syn_received_active_sends_challenge_ack() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);

    for i in 0..8 {
        free.push(alloc_free_frame(100 + i));
    }

    let ip_a = LOCAL_IP;
    let ip_b = REMOTE_IP;
    let port_a: u16 = 5000;
    let port_b: u16 = 6000;
    let src_mac = MacAddress::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    let dst_mac = MacAddress::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

    nh.seed_cache(coarsetime::Instant::now(), IpAddress::V4(ip_b), dst_mac);

    // Active open.
    let (_key, _events) = handler
        .connect(
            IpAddress::V4(ip_a),
            port_a,
            IpAddress::V4(ip_b),
            port_b,
            src_mac,
            dst_mac,
            coarsetime::Instant::now(),
            &mut free,
            &mut tx,
        )
        .unwrap();
    while tx.pop().is_some() {}

    // Feed B's SYN to move A to SynReceived (simultaneous open).
    let syn_b = build_tcp_frame(
        ip_b,
        ip_a,
        port_b,
        port_a,
        2000,
        0,
        flags::SYN,
        65535,
        &[0x02, 0x04, 0x05, 0xB4],
    );
    let syn_b_len = syn_b.len();
    handler.process_ipv4(
        Frame::new(10, leak(syn_b), syn_b_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(handler.first_connection().state, TcpState::SynReceived);
    assert!(!handler.first_connection().from_passive_open);
    while tx.pop().is_some() {}
    while rx.pop().is_some() {}

    // Retransmit B's SYN again (same seq, pure SYN).
    let syn_b2 = build_tcp_frame(
        ip_b,
        ip_a,
        port_b,
        port_a,
        2000,
        0,
        flags::SYN,
        65535,
        &[0x02, 0x04, 0x05, 0xB4],
    );
    let syn_b2_len = syn_b2.len();
    handler.process_ipv4(
        Frame::new(11, leak(syn_b2), syn_b2_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Active open: sends challenge ACK, not SYN-ACK.
    assert_eq!(handler.first_connection().state, TcpState::SynReceived);
    assert_eq!(
        tx.num_frames(),
        1,
        "challenge ACK emitted for active open SYN retransmit"
    );
}

#[test]
fn bad_ack_in_syn_received_sends_rst() {
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
    handler.process_ipv4(
        Frame::new(0, leak(syn_data), syn_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(handler.first_connection().state, TcpState::SynReceived);
    while tx.pop().is_some() {}

    let rcv_nxt = handler.first_connection().rcv_nxt;

    // ACK with bad ack number (ack=0, which is before snd_una).
    let bad_ack_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        rcv_nxt,
        0,
        flags::ACK,
        65535,
        &[],
    );
    let bad_ack_len = bad_ack_data.len();
    handler.process_ipv4(
        Frame::new(2, leak(bad_ack_data), bad_ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Should still be SynReceived (bad ACK does not transition) and RST emitted.
    assert_eq!(handler.first_connection().state, TcpState::SynReceived);
    assert_eq!(tx.num_frames(), 1, "RST sent for bad ACK");
}

#[test]
fn syn_ack_without_timestamp_disables_timestamps() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);

    for i in 0..8 {
        free.push(alloc_free_frame(100 + i));
    }

    let src_mac = MacAddress::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    let dst_mac = MacAddress::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

    // Active open with timestamps enabled (default).
    let (_key, _events) = handler
        .connect(
            IpAddress::V4(LOCAL_IP),
            5000,
            IpAddress::V4(REMOTE_IP),
            80,
            src_mac,
            dst_mac,
            coarsetime::Instant::now(),
            &mut free,
            &mut tx,
        )
        .unwrap();
    while tx.pop().is_some() {}

    assert!(
        handler.first_connection().ts_enabled,
        "timestamps enabled after connect"
    );
    let client_iss = handler.first_connection().iss;

    // SYN-ACK without timestamp option → timestamps should be disabled.
    let syn_ack = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        80,
        5000,
        2000,
        client_iss.wrapping_add(1),
        flags::SYN | flags::ACK,
        65535,
        &[0x02, 0x04, 0x05, 0xB4], // MSS only, no timestamp
    );
    let syn_ack_len = syn_ack.len();
    handler.process_ipv4(
        Frame::new(50, leak(syn_ack), syn_ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert_eq!(handler.first_connection().state, TcpState::Established);
    assert!(
        !handler.first_connection().ts_enabled,
        "timestamps disabled when peer omits TS option"
    );
    // eff_snd_mss should NOT subtract TS_OPTION_LEN when timestamps are disabled.
    // base_mss = min(peer_mss=1460, rcv_mss); no TS overhead.
    assert_eq!(
        handler.first_connection().eff_snd_mss,
        handler
            .first_connection()
            .snd_mss
            .min(handler.first_connection().rcv_mss)
    );
}

#[test]
fn syn_ack_without_sack_permitted_disables_sack() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);

    for i in 0..8 {
        free.push(alloc_free_frame(100 + i));
    }

    let src_mac = MacAddress::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    let dst_mac = MacAddress::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

    // Active open with SACK enabled (default).
    let (_key, _events) = handler
        .connect(
            IpAddress::V4(LOCAL_IP),
            5000,
            IpAddress::V4(REMOTE_IP),
            80,
            src_mac,
            dst_mac,
            coarsetime::Instant::now(),
            &mut free,
            &mut tx,
        )
        .unwrap();
    while tx.pop().is_some() {}

    assert!(
        handler.first_connection().sack_enabled,
        "SACK enabled after connect"
    );
    let client_iss = handler.first_connection().iss;

    // SYN-ACK without SACK-permitted option → SACK should be disabled.
    let syn_ack = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        80,
        5000,
        2000,
        client_iss.wrapping_add(1),
        flags::SYN | flags::ACK,
        65535,
        &[0x02, 0x04, 0x05, 0xB4], // MSS only, no SACK-permitted
    );
    let syn_ack_len = syn_ack.len();
    handler.process_ipv4(
        Frame::new(50, leak(syn_ack), syn_ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert_eq!(handler.first_connection().state, TcpState::Established);
    assert!(
        !handler.first_connection().sack_enabled,
        "SACK disabled when peer omits SACK-permitted"
    );
}

#[test]
fn syn_ack_without_ece_disables_ecn() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);

    for i in 0..8 {
        free.push(alloc_free_frame(100 + i));
    }

    let src_mac = MacAddress::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    let dst_mac = MacAddress::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

    // Active open with ECN enabled (default).
    let (_key, _events) = handler
        .connect(
            IpAddress::V4(LOCAL_IP),
            5000,
            IpAddress::V4(REMOTE_IP),
            80,
            src_mac,
            dst_mac,
            coarsetime::Instant::now(),
            &mut free,
            &mut tx,
        )
        .unwrap();
    while tx.pop().is_some() {}

    assert!(
        handler.first_connection().ecn_enabled,
        "ECN enabled after connect"
    );
    let client_iss = handler.first_connection().iss;

    // SYN-ACK without ECE flag → ECN should be disabled.
    let syn_ack = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        80,
        5000,
        2000,
        client_iss.wrapping_add(1),
        flags::SYN | flags::ACK, // no ECE bit
        65535,
        &[0x02, 0x04, 0x05, 0xB4],
    );
    let syn_ack_len = syn_ack.len();
    handler.process_ipv4(
        Frame::new(50, leak(syn_ack), syn_ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert_eq!(handler.first_connection().state, TcpState::Established);
    assert!(
        !handler.first_connection().ecn_enabled,
        "ECN disabled when SYN-ACK lacks ECE"
    );
}

#[test]
fn unacceptable_ack_in_syn_sent_sends_rst() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);

    for i in 0..8 {
        free.push(alloc_free_frame(100 + i));
    }

    let src_mac = MacAddress::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    let dst_mac = MacAddress::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

    let (_key, _events) = handler
        .connect(
            IpAddress::V4(LOCAL_IP),
            5000,
            IpAddress::V4(REMOTE_IP),
            80,
            src_mac,
            dst_mac,
            coarsetime::Instant::now(),
            &mut free,
            &mut tx,
        )
        .unwrap();
    while tx.pop().is_some() {}

    let client_iss = handler.first_connection().iss;

    // Send SYN-ACK with ack_seq = ISS (not ISS+1), which is unacceptable
    // because seg_ack <= ISS triggers the check.
    let bad_ack = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        80,
        5000,
        2000,
        client_iss, // ack = ISS, unacceptable (must be > ISS)
        flags::SYN | flags::ACK,
        65535,
        &[0x02, 0x04, 0x05, 0xB4],
    );
    let bad_ack_len = bad_ack.len();
    handler.process_ipv4(
        Frame::new(50, leak(bad_ack), bad_ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Should still be in SynSent (unacceptable ACK is dropped after sending RST).
    assert_eq!(handler.first_connection().state, TcpState::SynSent);
    assert_eq!(tx.num_frames(), 1, "RST sent for unacceptable ACK");
}

#[test]
fn unacceptable_ack_too_high_in_syn_sent_sends_rst() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);

    for i in 0..8 {
        free.push(alloc_free_frame(100 + i));
    }

    let src_mac = MacAddress::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    let dst_mac = MacAddress::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

    let (_key, _events) = handler
        .connect(
            IpAddress::V4(LOCAL_IP),
            5000,
            IpAddress::V4(REMOTE_IP),
            80,
            src_mac,
            dst_mac,
            coarsetime::Instant::now(),
            &mut free,
            &mut tx,
        )
        .unwrap();
    while tx.pop().is_some() {}

    let snd_nxt = handler.first_connection().snd_nxt;

    // Send SYN-ACK with ack_seq far beyond snd_nxt (unacceptable).
    let bad_ack = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        80,
        5000,
        2000,
        snd_nxt.wrapping_add(100), // ack too high
        flags::SYN | flags::ACK,
        65535,
        &[0x02, 0x04, 0x05, 0xB4],
    );
    let bad_ack_len = bad_ack.len();
    handler.process_ipv4(
        Frame::new(50, leak(bad_ack), bad_ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert_eq!(handler.first_connection().state, TcpState::SynSent);
    assert_eq!(tx.num_frames(), 1, "RST sent for ack beyond snd_nxt");
}

#[test]
fn simultaneous_open_syn_without_ack_transitions_to_syn_received() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);

    for i in 0..8 {
        free.push(alloc_free_frame(100 + i));
    }

    let src_mac = MacAddress::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    let dst_mac = MacAddress::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

    let (_key, _events) = handler
        .connect(
            IpAddress::V4(LOCAL_IP),
            5000,
            IpAddress::V4(REMOTE_IP),
            80,
            src_mac,
            dst_mac,
            coarsetime::Instant::now(),
            &mut free,
            &mut tx,
        )
        .unwrap();
    while tx.pop().is_some() {}

    assert_eq!(handler.first_connection().state, TcpState::SynSent);

    // Receive a bare SYN (no ACK) — simultaneous open.
    let peer_syn = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        80,
        5000,
        3000,
        0,
        flags::SYN, // SYN only, no ACK
        65535,
        &[0x02, 0x04, 0x05, 0xB4], // MSS=1460
    );
    let peer_syn_len = peer_syn.len();
    handler.process_ipv4(
        Frame::new(50, leak(peer_syn), peer_syn_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Should transition to SynReceived (simultaneous open path).
    assert_eq!(handler.first_connection().state, TcpState::SynReceived);
    assert!(
        !handler.first_connection().from_passive_open,
        "simultaneous open sets from_passive_open=false"
    );
    assert_eq!(handler.first_connection().irs, 3000);
    assert_eq!(handler.first_connection().rcv_nxt, 3001);
    assert_eq!(handler.first_connection().snd_mss, 1460);
    // A SYN-ACK should be emitted.
    assert!(
        tx.num_frames() >= 1,
        "SYN-ACK emitted for simultaneous open"
    );
}

#[test]
fn rst_with_ack_in_syn_sent_signals_connection_refused() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);

    for i in 0..8 {
        free.push(alloc_free_frame(100 + i));
    }

    let src_mac = MacAddress::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    let dst_mac = MacAddress::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

    let (_key, events) = handler
        .connect(
            IpAddress::V4(LOCAL_IP),
            5000,
            IpAddress::V4(REMOTE_IP),
            80,
            src_mac,
            dst_mac,
            coarsetime::Instant::now(),
            &mut free,
            &mut tx,
        )
        .unwrap();
    while tx.pop().is_some() {}

    let client_iss = handler.first_connection().iss;

    // RST+ACK with acceptable ACK → connection refused.
    let rst_ack = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        80,
        5000,
        0,
        client_iss.wrapping_add(1), // acceptable ACK
        flags::RST | flags::ACK,
        0,
        &[],
    );
    let rst_ack_len = rst_ack.len();
    handler.process_ipv4(
        Frame::new(50, leak(rst_ack), rst_ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert_eq!(handler.connections.len(), 0, "connection removed");
    let event = events.pop();
    assert!(event.is_some(), "event emitted");
    assert!(
        matches!(event.unwrap(), TcpEvent::ConnectionRefused),
        "ConnectionRefused event"
    );
}

#[test]
fn rst_without_ack_in_syn_sent_is_dropped() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);

    for i in 0..8 {
        free.push(alloc_free_frame(100 + i));
    }

    let src_mac = MacAddress::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    let dst_mac = MacAddress::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

    let (_key, _events) = handler
        .connect(
            IpAddress::V4(LOCAL_IP),
            5000,
            IpAddress::V4(REMOTE_IP),
            80,
            src_mac,
            dst_mac,
            coarsetime::Instant::now(),
            &mut free,
            &mut tx,
        )
        .unwrap();
    while tx.pop().is_some() {}

    // RST without ACK → silently dropped.
    let rst_only = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        80,
        5000,
        0,
        0,
        flags::RST, // RST only, no ACK
        0,
        &[],
    );
    let rst_only_len = rst_only.len();
    handler.process_ipv4(
        Frame::new(50, leak(rst_only), rst_only_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Connection should still exist and remain in SynSent.
    assert_eq!(handler.connections.len(), 1, "connection not removed");
    assert_eq!(handler.first_connection().state, TcpState::SynSent);
    assert_eq!(tx.num_frames(), 0, "no RST emitted");
}

#[test]
fn window_scale_applied_on_handshake_completion() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(8);
    let mut rx = BasicFrameBuffer::new(8);
    let mut tx = BasicFrameBuffer::new(8);

    for i in 0..4 {
        free.push(alloc_free_frame(100 + i));
    }

    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();

    // SYN with window scale = 7.
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
    handler.process_ipv4(
        Frame::new(0, leak(syn_data), syn_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(handler.first_connection().state, TcpState::SynReceived);
    assert!(handler.first_connection().wscale_enabled);
    assert_eq!(handler.first_connection().snd_wscale, 7);
    while tx.pop().is_some() {}

    let server_iss = handler.first_connection().iss;

    // Complete handshake with ACK. Window=512 should be scaled by 7 → 512 << 7 = 65536.
    let ack_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        server_iss.wrapping_add(1),
        flags::ACK,
        512,
        &[],
    );
    let ack_len = ack_data.len();
    handler.process_ipv4(
        Frame::new(1, leak(ack_data), ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert_eq!(handler.first_connection().state, TcpState::Established);
    // Window should be scaled: 512 << 7 = 65536.
    assert_eq!(handler.first_connection().snd_wnd, 512 << 7);
}
