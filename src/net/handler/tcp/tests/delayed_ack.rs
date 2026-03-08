use super::*;

#[test]
fn delayed_ack_defers_ack_for_in_order_data() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);

    for i in 0..8 {
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
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    while tx.pop().is_some() {}

    // Send one in-order data segment.
    let payload = b"hello";
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
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // No immediate ACK — deferred.
    assert_eq!(tx.num_frames(), 0, "ACK should be deferred");
    let tcb = &handler.connections[0];
    assert!(tcb.ack_pending, "ack_pending should be true");
    assert!(
        tcb.delayed_ack_deadline.is_some(),
        "delayed_ack_deadline should be set"
    );
    assert_eq!(tcb.ack_delay_count, 1, "ack_delay_count should be 1");
}

#[test]
fn delayed_ack_flushes_on_second_segment() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);

    for i in 0..8 {
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
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    while tx.pop().is_some() {}

    // First in-order segment — deferred.
    let seg1 = build_tcp_frame_with_payload(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        server_iss.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
        b"aaaaa",
    );
    let seg1_len = seg1.len();
    handler.process_ipv4(
        Frame::new(2, leak(seg1), seg1_len, false),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(tx.num_frames(), 0, "first segment deferred");

    // Second in-order segment — flushes ACK.
    let seg2 = build_tcp_frame_with_payload(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1006,
        server_iss.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
        b"bbbbb",
    );
    let seg2_len = seg2.len();
    handler.process_ipv4(
        Frame::new(3, leak(seg2), seg2_len, false),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(tx.num_frames(), 1, "second segment flushes ACK");

    let tcb = &handler.connections[0];
    assert!(!tcb.ack_pending, "ack_pending should be false after flush");
    assert_eq!(
        tcb.ack_delay_count, 0,
        "ack_delay_count should be 0 after flush"
    );
}

#[test]
fn out_of_order_data_sends_immediate_ack() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);

    for i in 0..8 {
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
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    while tx.pop().is_some() {}

    // Send out-of-order data (skip sequence numbers).
    let ooo_data = build_tcp_frame_with_payload(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1011,
        server_iss.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
        b"ooo",
    );
    let ooo_len = ooo_data.len();
    handler.process_ipv4(
        Frame::new(2, leak(ooo_data), ooo_len, false),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert_eq!(
        tx.num_frames(),
        1,
        "out-of-order data triggers immediate ACK"
    );
}

#[test]
fn fin_sends_immediate_ack() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);

    for i in 0..8 {
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
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    while tx.pop().is_some() {}

    // Send FIN.
    let fin_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        server_iss.wrapping_add(1),
        flags::ACK | flags::FIN,
        65535,
        &[],
    );
    let fin_len = fin_data.len();
    handler.process_ipv4(
        Frame::new(2, leak(fin_data), fin_len, false),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert_eq!(tx.num_frames(), 1, "FIN triggers immediate ACK");
    assert_eq!(handler.connections[0].state, TcpState::CloseWait);
}

#[test]
fn new_connection_has_delayed_ack_fields() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(8);
    let mut rx = BasicFrameBuffer::new(8);
    let mut tx = BasicFrameBuffer::new(8);

    for i in 0..4 {
        free.push(alloc_free_frame(100 + i));
    }

    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();

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

    // Verify delayed ACK and Nagle defaults.
    let tcb = &handler.connections[0];
    assert!(!tcb.ack_pending, "ack_pending should be false");
    assert!(
        tcb.delayed_ack_deadline.is_none(),
        "delayed_ack_deadline should be None"
    );
    assert_eq!(tcb.ack_delay_count, 0, "ack_delay_count should be 0");
    assert_eq!(
        tcb.delayed_ack_ms,
        tcb::DEFAULT_DELAYED_ACK_MS,
        "delayed_ack_ms should match default"
    );
    assert!(tcb.nagle_enabled, "nagle should be enabled by default");
}

#[test]
fn delayed_ack_timer_flushes_pending_ack() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let now = coarsetime::Instant::now();

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
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    while tx.pop().is_some() {}

    // Manually set delayed ACK state on the TCB.
    let id = ConnectionId {
        local_addr: IpAddress::V4(LOCAL_IP),
        local_port: 80,
        remote_addr: IpAddress::V4(REMOTE_IP),
        remote_port: 12345,
    };
    {
        let tcb = handler.get_connection_mut(&id).unwrap();
        tcb.ack_pending = true;
        tcb.ack_delay_count = 1;
        tcb.delayed_ack_deadline = Some(now + coarsetime::Duration::from_millis(40));
    }

    // Before deadline — should NOT flush.
    handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut tx);
    assert_eq!(tx.num_frames(), 0, "should not flush before deadline");

    // After deadline — should flush.
    let later = now + coarsetime::Duration::from_millis(50);
    handler.poll_timers(later, nh.local_mac(), &nh, &mut free, &mut tx);
    assert_eq!(tx.num_frames(), 1, "should flush after deadline");

    let tcb = handler.get_connection(&id).unwrap();
    assert!(!tcb.ack_pending);
    assert_eq!(tcb.ack_delay_count, 0);
    assert!(tcb.delayed_ack_deadline.is_none());
}

#[test]
fn data_send_clears_delayed_ack() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    // 1. Complete handshake via passive open (listener).
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
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    while tx.pop().is_some() {}

    // 2. Receive in-order data — ack_pending becomes true.
    let data_seg = build_tcp_frame_with_payload(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        server_iss.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
        b"incoming data",
    );
    let data_len = data_seg.len();
    handler.process_ipv4(
        Frame::new(2, leak(data_seg), data_len, false),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    while tx.pop().is_some() {} // consume any immediate ACK frames

    assert!(
        handler.connections[0].ack_pending,
        "ack_pending should be true after receiving data"
    );

    // 3. Write data to send buffer.
    handler.connections[0].send_buffer.write(b"reply data");
    handler.connections[0].snd_wnd = 65535;

    // 4. poll_send — sends data (piggybacks ACK).
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
    assert!(tx.num_frames() >= 1, "data segment should be sent");

    // 5. Verify delayed ACK state is cleared.
    let tcb = &handler.connections[0];
    assert!(
        !tcb.ack_pending,
        "ack_pending should be cleared after data send"
    );
    assert_eq!(tcb.ack_delay_count, 0, "ack_delay_count should be cleared");
    assert!(
        tcb.delayed_ack_deadline.is_none(),
        "delayed_ack_deadline should be cleared"
    );
}

