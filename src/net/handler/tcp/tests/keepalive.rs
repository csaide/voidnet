use super::*;

#[test]
fn keep_alive_activity_resets_probe_timer() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);

    for i in 0..8 {
        free.push(alloc_free_frame(100 + i));
    }

    // Complete handshake to reach Established.
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
    assert_eq!(handler.connections[0].state, TcpState::Established);

    // Simulate stale keep-alive state: set probes sent to 5.
    let old_activity = handler.connections[0].last_activity;
    handler.connections[0].keep_alive_probes_sent = 5;

    // Clear tx from handshake.
    while tx.pop().is_some() {}

    // Send a data segment to the established connection.
    let payload = b"keepalive-reset";
    let data = build_tcp_frame_with_payload(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        server_iss.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
        payload,
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

    // Verify keep-alive probes were reset.
    let tcb = &handler.connections[0];
    assert_eq!(
        tcb.keep_alive_probes_sent, 0,
        "keep_alive_probes_sent should be reset to 0 on data receipt"
    );
    assert!(
        tcb.last_activity >= old_activity,
        "last_activity should be updated on data receipt"
    );
}

#[test]
fn keep_alive_probe_sent_after_idle_timeout() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    // Complete handshake.
    let _accept = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
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
    assert_eq!(handler.connections[0].state, TcpState::Established);

    // Configure keep-alive with short timeouts.
    {
        let tcb = &mut handler.connections[0];
        tcb.keep_alive_enabled = true;
        tcb.keep_alive_idle_ms = 100;
        tcb.keep_alive_interval_ms = 50;
        tcb.keep_alive_count = 3;
        tcb.ack_pending = false;
    }

    // Sleep long enough for the idle timeout to expire.
    std::thread::sleep(std::time::Duration::from_millis(150));
    let now = coarsetime::Instant::now();

    handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut tx);

    assert_eq!(
        handler.connections[0].keep_alive_probes_sent, 1,
        "one keep-alive probe should have been sent"
    );
    assert!(
        tx.num_frames() >= 1,
        "a probe segment should have been emitted"
    );
}

#[test]
fn keep_alive_no_probe_when_disabled() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    // Complete handshake.
    let _accept = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
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
    assert_eq!(handler.connections[0].state, TcpState::Established);

    // Keep-alive is disabled by default; set ack_pending false to avoid delayed ACK output.
    handler.connections[0].ack_pending = false;

    // Sleep long enough that it would have triggered if enabled.
    std::thread::sleep(std::time::Duration::from_millis(150));
    let now = coarsetime::Instant::now();

    handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut tx);

    assert_eq!(
        handler.connections[0].keep_alive_probes_sent, 0,
        "no probes should be sent when keep-alive is disabled"
    );
    assert_eq!(tx.num_frames(), 0, "no segments should be emitted");
}

#[test]
fn keep_alive_connection_aborted_after_max_probes() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    // Complete handshake.
    let _accept = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
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
    assert_eq!(handler.connections[0].state, TcpState::Established);

    // Capture event queue before connection is removed.
    let event_queue = handler.connections[0].event_queue.clone();

    // Configure keep-alive: already sent max probes.
    {
        let tcb = &mut handler.connections[0];
        tcb.keep_alive_enabled = true;
        tcb.keep_alive_idle_ms = 50;
        tcb.keep_alive_interval_ms = 25;
        tcb.keep_alive_count = 2;
        tcb.keep_alive_probes_sent = 2; // already at max
        tcb.ack_pending = false;
    }

    // Sleep past the probe threshold.
    std::thread::sleep(std::time::Duration::from_millis(150));
    let now = coarsetime::Instant::now();

    handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut tx);

    // Connection should be removed.
    assert!(
        handler.connections.is_empty(),
        "connection should be removed after max probes exceeded"
    );

    // Timeout event should have been pushed.
    let event = event_queue.pop();
    assert_eq!(
        event,
        Some(TcpEvent::Timeout),
        "TcpEvent::Timeout should be emitted"
    );
}

#[test]
fn linger_zero_sends_rst_on_poll_send() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);

    for i in 0..8 {
        free.push(alloc_free_frame(100 + i));
    }

    // Complete handshake to reach Established.
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
    assert_eq!(handler.connections[0].state, TcpState::Established);

    // Set linger to 0 and capture event queue.
    handler.connections[0].linger = Some(0);
    let event_queue = handler.connections[0].event_queue.clone();
    let conn_id = handler.connections[0].id;

    // Clear tx from handshake.
    while tx.pop().is_some() {}

    // Call initiate_close — should set pending_fin and linger_deadline to Instant::recent().
    handler.initiate_close(&conn_id);
    assert!(
        handler.connections[0].pending_fin,
        "pending_fin should be set"
    );
    assert!(
        handler.connections[0].linger_deadline.is_some(),
        "linger_deadline should be set"
    );

    // Call poll_send — linger deadline is already expired, should send RST.
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);

    // Connection should be removed.
    assert!(
        handler.get_connection(&conn_id).is_none(),
        "connection should be removed after linger(0) RST"
    );

    // A RST segment should have been emitted.
    assert!(tx.num_frames() > 0, "RST segment should be emitted");

    // Reset event should have been pushed.
    let event = event_queue.pop();
    assert_eq!(
        event,
        Some(TcpEvent::Reset),
        "TcpEvent::Reset should be emitted"
    );
}

#[test]
fn linger_timeout_sets_deadline() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);

    for i in 0..8 {
        free.push(alloc_free_frame(100 + i));
    }

    // Complete handshake to reach Established.
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
    assert_eq!(handler.connections[0].state, TcpState::Established);

    // Set linger to 5000ms.
    handler.connections[0].linger = Some(5000);
    let conn_id = handler.connections[0].id;

    // Clear tx from handshake.
    while tx.pop().is_some() {}

    // Call initiate_close.
    handler.initiate_close(&conn_id);
    assert!(
        handler.connections[0].pending_fin,
        "pending_fin should be set"
    );
    assert!(
        handler.connections[0].linger_deadline.is_some(),
        "linger_deadline should be set"
    );

    // Call poll_send immediately — deadline is 5s in the future, should NOT abort.
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);

    // Connection should still exist.
    assert!(
        handler.get_connection(&conn_id).is_some(),
        "connection should still exist before deadline"
    );
}

#[test]
fn linger_none_normal_close() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);

    for i in 0..8 {
        free.push(alloc_free_frame(100 + i));
    }

    // Complete handshake to reach Established.
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
    assert_eq!(handler.connections[0].state, TcpState::Established);

    // Ensure linger is None (default).
    assert!(
        handler.connections[0].linger.is_none(),
        "linger should be None by default"
    );
    let conn_id = handler.connections[0].id;

    // Call initiate_close.
    handler.initiate_close(&conn_id);

    // Verify pending_fin is true and linger_deadline is None.
    assert!(
        handler.connections[0].pending_fin,
        "pending_fin should be set"
    );
    assert!(
        handler.connections[0].linger_deadline.is_none(),
        "linger_deadline should be None for default close"
    );
}

#[test]
fn keep_alive_probe_and_recovery() {
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
    assert_eq!(handler.connections[0].state, TcpState::Established);

    // Configure keep-alive.
    {
        let tcb = &mut handler.connections[0];
        tcb.keep_alive_enabled = true;
        tcb.keep_alive_idle_ms = 100;
        tcb.keep_alive_interval_ms = 50;
        tcb.keep_alive_count = 3;
        tcb.ack_pending = false;
        tcb.delayed_ack_deadline = None;
    }

    // Wait past the idle threshold.
    std::thread::sleep(std::time::Duration::from_millis(150));
    coarsetime::Instant::update();
    let now = coarsetime::Instant::now();

    let tx_before = tx.num_frames();
    handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut tx);

    // Verify probe was sent.
    assert!(
        tx.num_frames() > tx_before,
        "keep-alive probe should be sent"
    );
    assert_eq!(
        handler.connections[0].keep_alive_probes_sent, 1,
        "probes_sent should be 1"
    );

    // Record last_activity before recovery.
    let activity_before = handler.connections[0].last_activity;

    // Simulate receiving an ACK from the remote (recovery).
    let rcv_nxt = handler.connections[0].rcv_nxt;
    let snd_una = handler.connections[0].snd_una;
    let ack_frame = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        rcv_nxt,
        snd_una,
        flags::ACK,
        65535,
        &[],
    );
    let ack_frame_len = ack_frame.len();

    // Use process_ipv4 with a known timestamp so last_activity is deterministic.
    coarsetime::Instant::update();
    let recv_now = coarsetime::Instant::now();
    handler.process_ipv4(
        Frame::new(10, leak(ack_frame), ack_frame_len, false),
        recv_now,
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // The ACK is a duplicate ACK (seg_ack == snd_una, no data).
    // Keep-alive probe responses are duplicate ACKs — the fix in process_established
    // resets keep_alive_probes_sent when a dup ACK arrives and probes are outstanding.
    let tcb = &handler.connections[0];
    assert_eq!(
        tcb.keep_alive_probes_sent, 0,
        "probes_sent should be reset by dup ACK probe response"
    );
    assert!(
        tcb.last_activity >= activity_before,
        "last_activity should be updated"
    );
}

#[test]
fn keep_alive_exhaustion_removes_connection() {
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
    assert_eq!(handler.connections[0].state, TcpState::Established);

    // Capture event queue before connection is removed.
    let event_queue = handler.connections[0].event_queue.clone();

    // Configure keep-alive with count=1.
    {
        let tcb = &mut handler.connections[0];
        tcb.keep_alive_enabled = true;
        tcb.keep_alive_count = 1;
        tcb.keep_alive_idle_ms = 50;
        tcb.keep_alive_interval_ms = 50;
        tcb.ack_pending = false;
        tcb.delayed_ack_deadline = None;
    }

    // Wait past the idle threshold and send first probe.
    std::thread::sleep(std::time::Duration::from_millis(100));
    coarsetime::Instant::update();
    let now1 = coarsetime::Instant::now();
    handler.poll_timers(now1, nh.local_mac(), &nh, &mut free, &mut tx);

    // First probe should have been sent.
    assert_eq!(
        handler.connections[0].keep_alive_probes_sent, 1,
        "first probe sent"
    );
    assert_eq!(
        handler.connections.len(),
        1,
        "connection still alive after first probe"
    );

    // Wait again past the interval — max probes exceeded.
    std::thread::sleep(std::time::Duration::from_millis(100));
    coarsetime::Instant::update();
    let now2 = coarsetime::Instant::now();
    handler.poll_timers(now2, nh.local_mac(), &nh, &mut free, &mut tx);

    // Connection should be removed.
    assert!(
        handler.connections.is_empty(),
        "connection should be removed after max probes exceeded"
    );

    // Timeout event should have been pushed.
    let event = event_queue.pop();
    assert_eq!(
        event,
        Some(TcpEvent::Timeout),
        "TcpEvent::Timeout should be emitted"
    );
}

#[test]
fn linger_zero_immediate_rst() {
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
    assert_eq!(handler.connections[0].state, TcpState::Established);

    // Write some data to send buffer.
    handler.connections[0].send_buffer.write(b"unsent data");

    // Set linger to 0 and capture event queue.
    handler.connections[0].linger = Some(0);
    let event_queue = handler.connections[0].event_queue.clone();
    let conn_id = handler.connections[0].id;

    // Initiate close — linger(0) sets immediate deadline.
    handler.initiate_close(&conn_id);
    assert!(
        handler.connections[0].pending_fin,
        "pending_fin should be set"
    );
    assert!(
        handler.connections[0].linger_deadline.is_some(),
        "linger_deadline should be set for linger(0)"
    );

    // Call poll_send — linger deadline is already expired, should send RST.
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);

    // Connection should be removed.
    assert!(
        handler.get_connection(&conn_id).is_none(),
        "connection should be removed after linger(0) RST"
    );

    // RST segment should have been emitted.
    assert!(tx.num_frames() > 0, "RST segment should be emitted on tx");

    // Reset event should have been pushed.
    let event = event_queue.pop();
    assert_eq!(
        event,
        Some(TcpEvent::Reset),
        "TcpEvent::Reset should be emitted for linger(0) abort"
    );
}

