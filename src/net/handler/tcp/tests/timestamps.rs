use super::*;

#[test]
fn paws_rejects_old_timestamp() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);

    for i in 0..8 {
        free.push(alloc_free_frame(100 + i));
    }

    // Complete the handshake with timestamp options.
    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
    let ts_opt = build_ts_option(500, 0);
    let syn_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1000,
        0,
        flags::SYN,
        65535,
        &ts_opt,
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
    let ts_opt2 = build_ts_option(600, 0);
    let ack_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        server_iss.wrapping_add(1),
        flags::ACK,
        65535,
        &ts_opt2,
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
    assert_eq!(handler.connections[0].state, TcpState::Established);
    assert!(handler.connections[0].ts_enabled);

    // Set ts_recent to 1000 to make the test deterministic.
    handler.connections[0].ts_recent = 1000;
    handler.connections[0].ts_recent_age = coarsetime::Instant::now();

    // Clear tx from handshake.
    while tx.pop().is_some() {}

    // Send a segment with TSval=999 (older than ts_recent=1000).
    let old_ts_opt = build_ts_option(999, 0);
    let data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        server_iss.wrapping_add(1),
        flags::ACK,
        65535,
        &old_ts_opt,
    );
    let data_len = data.len();
    handler.process_ipv4(
        Frame::new(2, leak(data), data_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Segment should be dropped and an ACK sent back.
    assert_eq!(
        handler.connections.len(),
        1,
        "connection should still exist"
    );
    assert!(
        tx.pop().is_some(),
        "ACK should be sent in response to PAWS rejection"
    );
}

#[test]
fn paws_drops_rst_with_old_timestamp() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);

    for i in 0..8 {
        free.push(alloc_free_frame(100 + i));
    }

    // Complete the handshake with timestamp options.
    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
    let ts_opt = build_ts_option(500, 0);
    let syn_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1000,
        0,
        flags::SYN,
        65535,
        &ts_opt,
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
    let ts_opt2 = build_ts_option(600, 0);
    let ack_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        server_iss.wrapping_add(1),
        flags::ACK,
        65535,
        &ts_opt2,
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
    assert_eq!(handler.connections[0].state, TcpState::Established);
    assert!(handler.connections[0].ts_enabled);

    // Set ts_recent to 1000.
    handler.connections[0].ts_recent = 1000;
    handler.connections[0].ts_recent_age = coarsetime::Instant::now();

    while tx.pop().is_some() {}

    // Send RST with old TSval=999 — RST should be silently dropped by PAWS
    // (RFC 5961: RST is no longer exempt from PAWS to prevent replayed RST attacks).
    let old_ts_opt = build_ts_option(999, 0);
    let rst_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        server_iss.wrapping_add(1),
        flags::RST,
        65535,
        &old_ts_opt,
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

    // RST with old timestamp should be silently dropped — connection survives.
    assert_eq!(
        handler.connections.len(),
        1,
        "RST with old timestamp should be dropped by PAWS"
    );
    assert_eq!(handler.connections[0].state, TcpState::Established);
}

#[test]
fn paws_accepts_stale_ts_recent() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);

    for i in 0..8 {
        free.push(alloc_free_frame(100 + i));
    }

    // Complete the handshake with timestamp options.
    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
    let ts_opt = build_ts_option(500, 0);
    let syn_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1000,
        0,
        flags::SYN,
        65535,
        &ts_opt,
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
    let ts_opt2 = build_ts_option(600, 0);
    let ack_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        server_iss.wrapping_add(1),
        flags::ACK,
        65535,
        &ts_opt2,
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
    assert_eq!(handler.connections[0].state, TcpState::Established);
    assert!(handler.connections[0].ts_enabled);

    // Set ts_recent to 1000 and ts_recent_age to > 24 days ago.
    handler.connections[0].ts_recent = 1000;
    // Set ts_recent_age far in the past using a fixed tick value.
    handler.connections[0].ts_recent_age = coarsetime::Instant::from_ticks(0);

    while tx.pop().is_some() {}

    // Construct a `now` that is guaranteed to be 25 days after ts_recent_age(0),
    // regardless of system uptime. This ensures the PAWS staleness check sees
    // > 24 days elapsed and accepts the segment despite old TSval.
    let twenty_five_days = coarsetime::Duration::from_secs(25 * 24 * 60 * 60);
    let now = coarsetime::Instant::from_ticks(0) + twenty_five_days;

    // Send a segment with old TSval=999, but ts_recent_age is stale (> 24 days).
    // The PAWS check should accept the segment despite old timestamp.
    let old_ts_opt = build_ts_option(999, 0);
    let data = build_tcp_frame_with_payload(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        server_iss.wrapping_add(1),
        flags::ACK,
        65535,
        &old_ts_opt,
        b"Hello",
    );
    let data_len = data.len();
    handler.process_ipv4(
        Frame::new(2, leak(data), data_len, false),
        now,
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Segment should be accepted — connection still exists and data received.
    assert_eq!(
        handler.connections.len(),
        1,
        "connection should still exist"
    );
    let tcb = &handler.connections[0];
    assert_eq!(
        tcb.recv_buffer.available(),
        5,
        "data should be accepted when ts_recent is stale"
    );
}

