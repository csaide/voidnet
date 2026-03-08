use super::*;

#[test]
fn ecn_negotiated_when_both_sides_support() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let tcp_flags_offset = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + 13;

    // Active open with ECN enabled (default config has ecn=true).
    let config = TcpConfig::default();
    assert!(config.ecn, "default config should have ecn=true");
    let _events = handler
        .connect_with_config(
            IpAddress::V4(LOCAL_IP),
            5000,
            IpAddress::V4(REMOTE_IP),
            80,
            nh.local_mac(),
            crate::net::wire::ethernet::MacAddress::broadcast(),
            coarsetime::Instant::now(),
            config,
            &mut free,
            &mut tx,
        )
        .unwrap();

    // Verify SYN has ECE+CWR flags.
    assert_eq!(tx.num_frames(), 1, "SYN should be sent");
    let syn_frame = tx.pop().unwrap();
    let syn_flags = syn_frame[tcp_flags_offset];
    assert!(
        syn_flags & flags::SYN != 0,
        "SYN flag should be set, got {:#04x}",
        syn_flags
    );
    assert!(
        syn_flags & flags::ECE != 0,
        "ECE flag should be set on SYN when ECN enabled, got {:#04x}",
        syn_flags
    );
    assert!(
        syn_flags & flags::CWR != 0,
        "CWR flag should be set on SYN when ECN enabled, got {:#04x}",
        syn_flags
    );

    // ecn_enabled should be provisionally true.
    assert!(handler.connections[0].ecn_enabled);

    // Send SYN-ACK with ECE (peer supports ECN).
    let server_iss = 2000u32;
    let client_iss = handler.connections[0].iss;
    let syn_ack_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        80,
        5000,
        server_iss,
        client_iss.wrapping_add(1),
        flags::SYN | flags::ACK | flags::ECE,
        65535,
        &[],
    );
    let syn_ack_len = syn_ack_data.len();
    handler.process_ipv4(
        Frame::new(0, leak(syn_ack_data), syn_ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // ECN should remain enabled.
    assert!(
        handler.connections[0].ecn_enabled,
        "ecn_enabled should be true after SYN-ACK with ECE"
    );
    assert_eq!(
        handler.connections[0].state,
        TcpState::Established,
        "connection should be established"
    );
}

#[test]
fn ecn_disabled_when_peer_doesnt_support() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    // Active open with ECN enabled.
    let _events = handler
        .connect_with_config(
            IpAddress::V4(LOCAL_IP),
            5001,
            IpAddress::V4(REMOTE_IP),
            80,
            nh.local_mac(),
            crate::net::wire::ethernet::MacAddress::broadcast(),
            coarsetime::Instant::now(),
            TcpConfig::default(),
            &mut free,
            &mut tx,
        )
        .unwrap();

    // Drain the SYN.
    while tx.pop().is_some() {}

    // ecn_enabled should be provisionally true.
    assert!(handler.connections[0].ecn_enabled);

    // Send SYN-ACK WITHOUT ECE (peer doesn't support ECN).
    let server_iss = 3000u32;
    let client_iss = handler.connections[0].iss;
    let syn_ack_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        80,
        5001,
        server_iss,
        client_iss.wrapping_add(1),
        flags::SYN | flags::ACK,
        65535,
        &[],
    );
    let syn_ack_len = syn_ack_data.len();
    handler.process_ipv4(
        Frame::new(0, leak(syn_ack_data), syn_ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // ECN should be disabled.
    assert!(
        !handler.connections[0].ecn_enabled,
        "ecn_enabled should be false after SYN-ACK without ECE"
    );
    assert_eq!(
        handler.connections[0].state,
        TcpState::Established,
        "connection should be established"
    );
}

#[test]
fn ecn_negotiated_on_passive_open() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let tcp_flags_offset = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + 13;

    // Listen with default config (ecn=true).
    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();

    // Send SYN with ECE+CWR (client supports ECN).
    let syn_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1000,
        0,
        flags::SYN | flags::ECE | flags::CWR,
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

    // Verify SYN-ACK has ECE flag.
    assert_eq!(tx.num_frames(), 1, "SYN-ACK should be sent");
    let syn_ack_frame = tx.pop().unwrap();
    let syn_ack_flags = syn_ack_frame[tcp_flags_offset];
    assert!(
        syn_ack_flags & flags::SYN != 0,
        "SYN flag should be set on SYN-ACK, got {:#04x}",
        syn_ack_flags
    );
    assert!(
        syn_ack_flags & flags::ACK != 0,
        "ACK flag should be set on SYN-ACK, got {:#04x}",
        syn_ack_flags
    );
    assert!(
        syn_ack_flags & flags::ECE != 0,
        "ECE flag should be set on SYN-ACK when ECN negotiated, got {:#04x}",
        syn_ack_flags
    );

    // TCB should have ecn_enabled = true.
    assert!(
        handler.connections[0].ecn_enabled,
        "ecn_enabled should be true on passive side"
    );

    // Complete handshake with final ACK.
    let server_iss = handler.connections[0].iss;
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
    handler.process_ipv4(
        Frame::new(1, leak(ack_data), ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Connection should be established with ECN still enabled.
    assert_eq!(handler.connections[0].state, TcpState::Established);
    assert!(
        handler.connections[0].ecn_enabled,
        "ecn_enabled should remain true after handshake"
    );
}

#[test]
fn ecn_ect_set_on_outgoing_data() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    // Complete handshake via listen path.
    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
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
    let server_iss = handler.connections[0].iss;
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
    handler.process_ipv4(
        Frame::new(1, leak(ack_data), ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    while tx.pop().is_some() {}

    // Enable ECN on the connection.
    handler.connections[0].ecn_enabled = true;
    handler.connections[0].snd_wnd = 65535;

    // Write data into the send buffer.
    let payload = b"Hello ECN!";
    handler.connections[0].send_buffer.write(payload);

    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);

    assert_eq!(tx.num_frames(), 1, "should have one data segment");
    let frame = tx.pop().unwrap();
    // IPv4 ToS byte is at ETH_HEADER_LEN + 1.
    let tos_byte = frame[ETH_HEADER_LEN + 1];
    assert_eq!(tos_byte, 0x02, "ECT(0) should be set in ToS byte");
}

#[test]
fn ecn_ect_not_set_on_retransmit() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    // Complete handshake.
    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
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
    let server_iss = handler.connections[0].iss;
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
    handler.process_ipv4(
        Frame::new(1, leak(ack_data), ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    while tx.pop().is_some() {}

    // Enable ECN and send data.
    handler.connections[0].ecn_enabled = true;
    handler.connections[0].snd_wnd = 65535;
    handler.connections[0].send_buffer.write(b"RTO test data");

    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
    // Drain the initial data segment.
    while tx.pop().is_some() {}

    // Expire the retransmit timer to trigger RTO retransmit.
    handler.connections[0].retransmit_deadline = Some(now);
    handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut tx);

    assert_eq!(tx.num_frames(), 1, "should have one retransmit segment");
    let frame = tx.pop().unwrap();
    let tos_byte = frame[ETH_HEADER_LEN + 1];
    assert_eq!(tos_byte, 0x00, "ECT should NOT be set on RTO retransmit");
}

#[test]
fn ecn_ce_detected_on_incoming() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    // Complete handshake.
    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
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
    let server_iss = handler.connections[0].iss;
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
    handler.process_ipv4(
        Frame::new(1, leak(ack_data), ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    while tx.pop().is_some() {}

    // Enable ECN on the connection.
    handler.connections[0].ecn_enabled = true;
    assert!(
        !handler.connections[0].ecn_ce_received,
        "CE should not be set yet"
    );

    // Build a data segment with CE mark (ToS = 0x03) in the IP header.
    let mut data_frame = build_tcp_frame_with_payload(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        server_iss.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
        b"hello",
    );
    // Set CE codepoint in IPv4 ToS byte: ECN bits = 0b11 = 0x03.
    data_frame[ETH_HEADER_LEN + 1] = 0x03;
    // Recompute IPv4 header checksum after modifying ToS.
    let ip_cksum = compute_ipv4_checksum(&data_frame[ETH_HEADER_LEN..ETH_HEADER_LEN + 20]);
    data_frame[ETH_HEADER_LEN + 10] = ip_cksum[0];
    data_frame[ETH_HEADER_LEN + 11] = ip_cksum[1];

    let data_len = data_frame.len();
    handler.process_ipv4(
        Frame::new(2, leak(data_frame), data_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert!(
        handler.connections[0].ecn_ce_received,
        "ecn_ce_received should be true after receiving CE-marked segment"
    );
}

#[test]
fn ecn_ece_sent_when_ce_received() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    // Complete handshake.
    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
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
    let server_iss = handler.connections[0].iss;
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
    handler.process_ipv4(
        Frame::new(1, leak(ack_data), ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    while tx.pop().is_some() {}

    // Enable ECN and set ecn_ce_received.
    handler.connections[0].ecn_enabled = true;
    handler.connections[0].ecn_ce_received = true;

    // Send data to trigger an ACK with ECE.
    let data_frame = build_tcp_frame_with_payload(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        server_iss.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
        b"hello",
    );
    let data_len = data_frame.len();
    handler.process_ipv4(
        Frame::new(2, leak(data_frame), data_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // The handler should have sent an ACK (delayed or immediate).
    // Force delayed ACK flush if needed.
    if tx.num_frames() == 0 {
        let now = coarsetime::Instant::now();
        handler.connections[0].delayed_ack_deadline = Some(now);
        handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut tx);
    }

    assert!(
        tx.num_frames() >= 1,
        "should have at least one outgoing ACK"
    );
    let frame = tx.pop().unwrap();
    let tcp_flags_byte = frame[ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + 13];
    assert!(
        tcp_flags_byte & flags::ECE != 0,
        "outgoing ACK should have ECE flag set, got flags={:#04x}",
        tcp_flags_byte,
    );
}

#[test]
fn ecn_cwnd_halved_on_ece() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    // Complete handshake.
    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
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
    let server_iss = handler.connections[0].iss;
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
    handler.process_ipv4(
        Frame::new(1, leak(ack_data), ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    while tx.pop().is_some() {}

    // Enable ECN and set cwnd to a known value.
    handler.connections[0].ecn_enabled = true;
    handler.connections[0].snd_wnd = 65535;
    let mss = handler.connections[0].eff_snd_mss as u32;
    handler.connections[0].cubic.cwnd = 10 * mss;
    handler.connections[0].cubic.ssthresh = 20 * mss;

    // Send some data so snd_nxt advances.
    handler.connections[0]
        .send_buffer
        .write(b"test data for ecn");
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
    while tx.pop().is_some() {}

    let snd_nxt = handler.connections[0].snd_nxt;

    // Record cwnd before receiving ECE.
    let cwnd_before = handler.connections[0].cubic.cwnd;

    // Receive ACK with ECE flag — simulating peer's congestion signal.
    let ece_ack = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        snd_nxt,
        flags::ACK | flags::ECE,
        65535,
        &[],
    );
    let ece_len = ece_ack.len();
    handler.process_ipv4(
        Frame::new(3, leak(ece_ack), ece_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Verify cwnd was reduced (halved after congestion avoidance increment).
    let cwnd_after = handler.connections[0].cubic.cwnd;
    assert!(
        cwnd_after < cwnd_before,
        "cwnd should be reduced: before={}, after={}",
        cwnd_before,
        cwnd_after,
    );
    assert_eq!(
        handler.connections[0].cubic.cwnd, handler.connections[0].cubic.ssthresh,
        "cwnd should equal ssthresh after ECN response"
    );
    assert!(
        handler.connections[0].cubic.ssthresh >= 2 * mss,
        "ssthresh should be at least 2*MSS"
    );
    assert!(
        handler.connections[0].ecn_cwr_sent,
        "ecn_cwr_sent should be true"
    );
}

#[test]
fn ecn_cwr_sent_on_next_data() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    // Complete handshake.
    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
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
    let server_iss = handler.connections[0].iss;
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
    handler.process_ipv4(
        Frame::new(1, leak(ack_data), ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    while tx.pop().is_some() {}

    // Enable ECN and set ecn_cwr_sent to true (simulating ECE reception).
    handler.connections[0].ecn_enabled = true;
    handler.connections[0].ecn_cwr_sent = true;
    handler.connections[0].snd_wnd = 65535;

    // Write data and poll_send.
    handler.connections[0].send_buffer.write(b"cwr test data");
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);

    assert_eq!(tx.num_frames(), 1, "should have one data segment");
    let frame = tx.pop().unwrap();
    let tcp_flags_byte = frame[ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + 13];
    assert!(
        tcp_flags_byte & flags::CWR != 0,
        "outgoing data segment should have CWR flag set, got flags={:#04x}",
        tcp_flags_byte,
    );

    // Verify ecn_cwr_sent is cleared after sending.
    assert!(
        !handler.connections[0].ecn_cwr_sent,
        "ecn_cwr_sent should be cleared after sending CWR"
    );
}

#[test]
fn ecn_ce_received_cleared_on_cwr() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    // Complete handshake.
    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
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
    let server_iss = handler.connections[0].iss;
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
    handler.process_ipv4(
        Frame::new(1, leak(ack_data), ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    while tx.pop().is_some() {}

    // Enable ECN and set ecn_ce_received.
    handler.connections[0].ecn_enabled = true;
    handler.connections[0].ecn_ce_received = true;

    // Receive a segment with CWR flag from peer (acknowledging our ECE).
    let rcv_nxt = handler.connections[0].rcv_nxt;
    let cwr_frame = build_tcp_frame_with_payload(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        rcv_nxt,
        server_iss.wrapping_add(1),
        flags::ACK | flags::CWR,
        65535,
        &[],
        b"data",
    );
    let cwr_len = cwr_frame.len();
    handler.process_ipv4(
        Frame::new(2, leak(cwr_frame), cwr_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert!(
        !handler.connections[0].ecn_ce_received,
        "ecn_ce_received should be cleared after receiving CWR"
    );
}

