use super::*;

#[test]
fn established_receives_fin_transitions_to_close_wait() {
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
    let server_iss = handler.first_connection().iss;
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

    // Remote sends FIN.
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
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert_eq!(handler.first_connection().state, TcpState::CloseWait);
    assert_eq!(handler.first_connection().rcv_nxt, 1002); // 1001 + FIN=1
    assert_eq!(tx.num_frames(), 1, "ACK for FIN sent");
}

#[test]
fn established_receives_fin_with_data() {
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
    let server_iss = handler.first_connection().iss;
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

    // Remote sends data + FIN piggybacked.
    let payload = b"goodbye";
    let fin_data = build_tcp_frame_with_payload(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        server_iss.wrapping_add(1),
        flags::ACK | flags::FIN,
        65535,
        &[],
        payload,
    );
    let fin_len = fin_data.len();
    handler.process_ipv4(
        Frame::new(2, leak(fin_data), fin_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert_eq!(handler.first_connection().state, TcpState::CloseWait);
    assert_eq!(
        handler.first_connection().recv_buffer.available(),
        payload.len()
    );
    // rcv_nxt = 1001 + 7 bytes data + 1 FIN = 1009
    assert_eq!(
        handler.first_connection().rcv_nxt,
        1001 + payload.len() as u32 + 1
    );
}

#[test]
fn poll_send_sends_fin_when_pending() {
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
    let server_iss = handler.first_connection().iss;
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

    // Set pending_fin.
    handler.first_connection_mut().pending_fin = true;

    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);

    // FIN should have been sent.
    assert_eq!(tx.num_frames(), 1, "FIN segment sent");
    let tcb = handler.first_connection();
    assert_eq!(tcb.state, TcpState::FinWait1);
    assert!(!tcb.pending_fin, "pending_fin consumed");
    assert!(tcb.fin_seq.is_some(), "fin_seq recorded");
}

#[test]
fn poll_send_drains_data_before_fin() {
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
    let server_iss = handler.first_connection().iss;
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

    // Write data AND set pending_fin.
    handler
        .first_connection_mut()
        .send_buffer
        .write(b"final data");
    handler.first_connection_mut().snd_wnd = 65535;
    handler.first_connection_mut().pending_fin = true;

    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);

    // Should send data first, NOT FIN yet (data still in flight).
    assert_eq!(tx.num_frames(), 1, "data segment sent");
    assert_eq!(
        handler.first_connection().state,
        TcpState::Established,
        "still Established until data ACKed"
    );
    assert!(
        handler.first_connection().pending_fin,
        "pending_fin still set"
    );
}

#[test]
fn active_close_fin_wait1_to_fin_wait2() {
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
    let server_iss = handler.first_connection().iss;
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

    // Active close: set pending_fin, poll_send sends FIN → FinWait1.
    handler.first_connection_mut().pending_fin = true;
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}
    assert_eq!(handler.first_connection().state, TcpState::FinWait1);
    let fin_seq = handler.first_connection().fin_seq.unwrap();

    // Remote ACKs our FIN → FinWait2.
    let ack = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        fin_seq.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
    );
    let ack_len = ack.len();
    handler.process_ipv4(
        Frame::new(3, leak(ack), ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert_eq!(handler.first_connection().state, TcpState::FinWait2);
}

#[test]
fn fin_wait2_receives_fin_to_time_wait() {
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
    let server_iss = handler.first_connection().iss;
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

    // Active close → FinWait1 → FinWait2.
    handler.first_connection_mut().pending_fin = true;
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}
    let fin_seq = handler.first_connection().fin_seq.unwrap();
    let ack = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        fin_seq.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
    );
    let ack_len = ack.len();
    handler.process_ipv4(
        Frame::new(3, leak(ack), ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(handler.first_connection().state, TcpState::FinWait2);
    while tx.pop().is_some() {}

    // Remote sends FIN → TimeWait.
    let fin = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        fin_seq.wrapping_add(1),
        flags::ACK | flags::FIN,
        65535,
        &[],
    );
    let fin_len = fin.len();
    handler.process_ipv4(
        Frame::new(4, leak(fin), fin_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert_eq!(handler.first_connection().state, TcpState::TimeWait);
    assert!(handler.first_connection().time_wait_deadline.is_some());
    assert_eq!(tx.num_frames(), 1, "ACK for remote FIN");
}

#[test]
fn simultaneous_close_closing_to_time_wait() {
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
    let server_iss = handler.first_connection().iss;
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

    // Active close → FinWait1.
    handler.first_connection_mut().pending_fin = true;
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}
    assert_eq!(handler.first_connection().state, TcpState::FinWait1);

    // Simultaneous close: remote sends FIN without ACKing ours → Closing.
    let fin = build_tcp_frame(
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
    let fin_len = fin.len();
    handler.process_ipv4(
        Frame::new(3, leak(fin), fin_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(handler.first_connection().state, TcpState::Closing);
    while tx.pop().is_some() {}

    // Remote ACKs our FIN → TimeWait.
    let fin_seq = handler.first_connection().fin_seq.unwrap();
    let ack = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1002,
        fin_seq.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
    );
    let ack_len = ack.len();
    handler.process_ipv4(
        Frame::new(4, leak(ack), ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(handler.first_connection().state, TcpState::TimeWait);
}

#[test]
fn passive_close_last_ack_removes_connection() {
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
    let server_iss = handler.first_connection().iss;
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

    // Remote sends FIN → CloseWait.
    let fin = build_tcp_frame(
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
    let fin_len = fin.len();
    handler.process_ipv4(
        Frame::new(2, leak(fin), fin_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(handler.first_connection().state, TcpState::CloseWait);
    while tx.pop().is_some() {}

    // We close → pending_fin, poll_send sends FIN → LastAck.
    handler.first_connection_mut().pending_fin = true;
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}
    assert_eq!(handler.first_connection().state, TcpState::LastAck);
    let fin_seq = handler.first_connection().fin_seq.unwrap();

    // Remote ACKs our FIN → connection removed.
    let ack = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1002,
        fin_seq.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
    );
    let ack_len = ack.len();
    handler.process_ipv4(
        Frame::new(4, leak(ack), ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(
        handler.connections.len(),
        0,
        "connection removed after LastAck"
    );
}

#[test]
fn time_wait_ignores_rst() {
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
    let server_iss = handler.first_connection().iss;
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

    // Full active close → TimeWait.
    handler.first_connection_mut().pending_fin = true;
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}
    let fin_seq = handler.first_connection().fin_seq.unwrap();
    let ack = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        fin_seq.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
    );
    let ack_len = ack.len();
    handler.process_ipv4(
        Frame::new(3, leak(ack), ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    let fin = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        fin_seq.wrapping_add(1),
        flags::ACK | flags::FIN,
        65535,
        &[],
    );
    let fin_len = fin.len();
    handler.process_ipv4(
        Frame::new(4, leak(fin), fin_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(handler.first_connection().state, TcpState::TimeWait);
    while tx.pop().is_some() {}

    // RST in TIME-WAIT should be ignored.
    let rst = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1002, 0, flags::RST, 0, &[]);
    let rst_len = rst.len();
    handler.process_ipv4(
        Frame::new(5, leak(rst), rst_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(
        handler.connections.len(),
        1,
        "connection NOT removed by RST in TIME-WAIT"
    );
    assert_eq!(handler.first_connection().state, TcpState::TimeWait);
}

#[test]
fn time_wait_evicted_after_deadline() {
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
    let server_iss = handler.first_connection().iss;
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

    // Force into TimeWait state with expired deadline.
    handler.first_connection_mut().state = TcpState::TimeWait;
    handler.first_connection_mut().time_wait_deadline = Some(coarsetime::Instant::now());

    // Evict with a time in the future.
    let future = coarsetime::Instant::now() + coarsetime::Duration::from_secs(120);
    handler.evict_stale(future, &mut rx);
    assert_eq!(handler.connections.len(), 0, "TIME-WAIT connection evicted");
}

#[test]
fn full_active_close_lifecycle() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let initial_free = free.num_frames();

    // 1. Handshake.
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
    let server_iss = handler.first_connection().iss;
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
    assert_eq!(handler.first_connection().state, TcpState::Established);

    // 2. Data exchange.
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
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // 3. Active close.
    handler.first_connection_mut().pending_fin = true;
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    assert_eq!(handler.first_connection().state, TcpState::FinWait1);
    while tx.pop().is_some() {}

    // 4. Remote ACKs our FIN -> FinWait2.
    let fin_seq = handler.first_connection().fin_seq.unwrap();
    let ack = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1006,
        fin_seq.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
    );
    let ack_len = ack.len();
    handler.process_ipv4(
        Frame::new(3, leak(ack), ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(handler.first_connection().state, TcpState::FinWait2);

    // 5. Remote sends FIN -> TimeWait.
    let fin = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1006,
        fin_seq.wrapping_add(1),
        flags::ACK | flags::FIN,
        65535,
        &[],
    );
    let fin_len = fin.len();
    handler.process_ipv4(
        Frame::new(4, leak(fin), fin_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(handler.first_connection().state, TcpState::TimeWait);
    while tx.pop().is_some() {}

    // 6. TIME-WAIT expires -> connection removed.
    let future = coarsetime::Instant::now() + coarsetime::Duration::from_secs(120);
    handler.evict_stale(future, &mut rx);
    assert_eq!(
        handler.connections.len(),
        0,
        "connection removed after TIME-WAIT"
    );

    // 7. Frame accounting: all frames accounted for.
    // We injected 5 incoming frames (SYN, ACK, data, FIN-ACK, FIN) which end up in rx.
    // The handler consumed free frames for outgoing segments (SYN-ACK, data ACK, FIN,
    // ACK-for-FIN) which we drained from tx. So the total in free+rx+tx equals
    // initial_free + incoming - outgoing_drained.
    let total = free.num_frames() + rx.num_frames() + tx.num_frames();
    let outgoing_drained = initial_free + 5 - total;
    assert!(
        outgoing_drained > 0 && total > 0,
        "no frames leaked: free={} rx={} tx={} outgoing_drained={}",
        free.num_frames(),
        rx.num_frames(),
        tx.num_frames(),
        outgoing_drained,
    );
    assert_eq!(
        total + outgoing_drained,
        initial_free + 5,
        "all frames accounted for (free={} rx={} tx={} outgoing_drained={})",
        free.num_frames(),
        rx.num_frames(),
        tx.num_frames(),
        outgoing_drained,
    );
}

#[test]
fn full_passive_close_lifecycle() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    // 1. Handshake.
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
    let server_iss = handler.first_connection().iss;
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

    // 2. Remote sends FIN -> CloseWait.
    let fin = build_tcp_frame(
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
    let fin_len = fin.len();
    handler.process_ipv4(
        Frame::new(2, leak(fin), fin_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(handler.first_connection().state, TcpState::CloseWait);
    while tx.pop().is_some() {}

    // 3. We close -> LastAck.
    handler.first_connection_mut().pending_fin = true;
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    assert_eq!(handler.first_connection().state, TcpState::LastAck);
    while tx.pop().is_some() {}
    let fin_seq = handler.first_connection().fin_seq.unwrap();

    // 4. Remote ACKs our FIN -> connection removed.
    let ack = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1002,
        fin_seq.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
    );
    let ack_len = ack.len();
    handler.process_ipv4(
        Frame::new(3, leak(ack), ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(
        handler.connections.len(),
        0,
        "connection removed after LastAck"
    );
}

#[test]
fn shutdown_sets_pending_fin() {
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
    let server_iss = handler.first_connection().iss;
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
    assert_eq!(handler.first_connection().state, TcpState::Established);

    // Verify pending_fin is initially false.
    assert!(
        !handler.first_connection().pending_fin,
        "pending_fin should start false"
    );

    // Call initiate_close (the handler method that shutdown() delegates to).
    handler.initiate_close(handler.first_connection_key());

    // Verify pending_fin is now true.
    assert!(
        handler.first_connection().pending_fin,
        "pending_fin should be true after initiate_close"
    );

    // Verify connection is still Established (FIN not yet sent).
    assert_eq!(
        handler.first_connection().state,
        TcpState::Established,
        "state should remain Established until poll_send"
    );
}

#[test]
fn half_close_writes_blocked_reads_continue() {
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
    let server_iss = handler.first_connection().iss;
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
    assert_eq!(handler.first_connection().state, TcpState::Established);

    // Initiate half-close (shutdown write side).
    handler.initiate_close(handler.first_connection_key());

    // Verify pending_fin is set but state is still Established (FIN not sent yet).
    assert!(
        handler.first_connection().pending_fin,
        "pending_fin should be true after initiate_close"
    );
    assert_eq!(
        handler.first_connection().state,
        TcpState::Established,
        "state should still be Established before poll_send"
    );

    // Write data directly into recv_buffer (simulating received data).
    let incoming = b"data after half-close";
    handler.first_connection_mut().recv_buffer.write(incoming);

    // Verify reads still work after half-close.
    assert_eq!(
        handler.first_connection().recv_buffer.available(),
        incoming.len(),
        "recv_buffer should still be readable after half-close"
    );
    let mut buf = [0u8; 32];
    let read_len = handler.first_connection_mut().recv_buffer.read(&mut buf);
    assert_eq!(read_len, incoming.len(), "should read all data");
    assert_eq!(
        &buf[..read_len],
        incoming,
        "read data should match written data"
    );
}

#[test]
fn close_wait_processes_ack_for_sent_data() {
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
    let server_iss = handler.first_connection().iss;
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

    // Write data into the send buffer.
    let payload = b"half-close data!";
    handler.first_connection_mut().send_buffer.write(payload);
    handler.first_connection_mut().snd_wnd = 65535;

    // poll_send to transmit data (advances snd_nxt).
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}

    let snd_nxt_after_send = handler.first_connection().snd_nxt;
    assert_eq!(
        snd_nxt_after_send,
        server_iss
            .wrapping_add(1)
            .wrapping_add(payload.len() as u32)
    );
    // Data still in send buffer until ACKed.
    assert_eq!(
        handler.first_connection().send_buffer.available(),
        payload.len()
    );

    // Transition to CloseWait by receiving FIN+ACK from remote.
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
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    while tx.pop().is_some() {}
    assert_eq!(handler.first_connection().state, TcpState::CloseWait);

    // Now send an ACK for the data we sent (seg_ack = snd_nxt).
    let data_ack = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1002, // 1001 + FIN consumes 1
        snd_nxt_after_send,
        flags::ACK,
        32000,
        &[],
    );
    let data_ack_len = data_ack.len();
    handler.process_ipv4(
        Frame::new(3, leak(data_ack), data_ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // snd_una should advance to snd_nxt (all data ACKed).
    assert_eq!(
        handler.first_connection().snd_una,
        snd_nxt_after_send,
        "snd_una must advance to cover ACKed data"
    );
    // Send buffer should be drained.
    assert_eq!(
        handler.first_connection().send_buffer.available(),
        0,
        "send buffer must be drained after ACK"
    );
    // Window should be updated.
    assert_eq!(
        handler.first_connection().snd_wnd,
        32000,
        "send window must be updated from ACK"
    );
}

#[test]
fn fin_retransmitted_in_fin_wait1() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    for i in 0..16 {
        free.push(alloc_free_frame(200 + i));
    }

    // Establish connection via passive open.
    let _server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    let id = ConnectionId {
        local_addr: IpAddress::V4(LOCAL_IP),
        local_port: 80,
        remote_addr: IpAddress::V4(REMOTE_IP),
        remote_port: 12345,
    };

    // Manually transition TCB to FinWait1 with an expired retransmit deadline.
    let now = coarsetime::Instant::now();
    {
        let tcb = handler.get_connection_mut(&id).unwrap();
        let fin_seq = tcb.snd_nxt;
        tcb.state = TcpState::FinWait1;
        tcb.fin_seq = Some(fin_seq);
        tcb.retransmit_deadline = Some(coarsetime::Instant::recent()); // already expired
        tcb.rto_backoff = 0;
    }

    // poll_timers should retransmit the FIN-ACK.
    handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);

    // (1) A FIN-ACK segment must be emitted.
    assert!(
        tx.num_frames() >= 1,
        "expected FIN-ACK retransmission, got {} frames",
        tx.num_frames()
    );

    // Verify the emitted frame has FIN|ACK flags.
    let frame = tx.pop().unwrap();
    let tcp_off = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
    // TCP flags byte is at offset 13 in the TCP header.
    let tcp_flags = frame[tcp_off + 13];
    assert_eq!(
        tcp_flags & (flags::FIN | flags::ACK),
        flags::FIN | flags::ACK,
        "retransmitted segment must have FIN|ACK flags"
    );

    // (2) retransmit_deadline must be rescheduled with backoff.
    let tcb = handler.get_connection(&id).unwrap();
    assert!(
        tcb.retransmit_deadline.is_some(),
        "retransmit_deadline must be rescheduled"
    );
    assert_eq!(tcb.rto_backoff, 1, "rto_backoff must be incremented");
}

#[test]
fn out_of_order_fin_does_not_transition_to_close_wait() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    // Complete handshake: remote ISS=1000, so after SYN rcv_nxt=1001.
    let server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);
    assert_eq!(handler.first_connection().state, TcpState::Established);
    assert_eq!(handler.first_connection().rcv_nxt, 1001);

    // Send a data+FIN segment that is out-of-order: there is a gap.
    // rcv_nxt is 1001, but we send seq=1006 with 5 bytes of data + FIN.
    // This means bytes 1001..1005 are missing.
    let fin_data = build_tcp_frame_with_payload(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1006,
        server_iss.wrapping_add(1),
        flags::ACK | flags::FIN,
        65535,
        &[],
        b"world",
    );
    let fin_len = fin_data.len();
    handler.process_ipv4(
        Frame::new(2, leak(fin_data), fin_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Connection must remain Established because preceding data is missing.
    assert_eq!(
        handler.first_connection().state,
        TcpState::Established,
        "FIN must not be processed when there is a gap before it"
    );
    assert_eq!(
        handler.first_connection().rcv_nxt,
        1001,
        "rcv_nxt must not advance past the gap"
    );

    // Drain any ACKs from tx.
    while tx.pop().is_some() {}

    // Now fill the gap: send the missing 5 bytes at seq=1001.
    let fill_data = build_tcp_frame_with_payload(
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
    let fill_len = fill_data.len();
    handler.process_ipv4(
        Frame::new(3, leak(fill_data), fill_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // After gap fill, rcv_nxt should advance through the reassembled data.
    // But FIN was out-of-order and needs to be re-sent by the peer.
    // rcv_nxt should be at 1011 (1001 + 5 gap-fill + 5 OOO data).
    assert_eq!(handler.first_connection().rcv_nxt, 1011);

    // Drain tx again.
    while tx.pop().is_some() {}

    // Re-send the FIN now that all data is received (seq=1011, no payload, FIN).
    let fin_retry = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1011,
        server_iss.wrapping_add(1),
        flags::ACK | flags::FIN,
        65535,
        &[],
    );
    let fin_retry_len = fin_retry.len();
    handler.process_ipv4(
        Frame::new(4, leak(fin_retry), fin_retry_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Now the FIN should be processed and we transition to CloseWait.
    assert_eq!(
        handler.first_connection().state,
        TcpState::CloseWait,
        "FIN should be processed once all preceding data is received"
    );
    assert_eq!(
        handler.first_connection().rcv_nxt,
        1012,
        "rcv_nxt should advance by 1 for the FIN"
    );
}

// ---------------------------------------------------------------------------
// Helper: bring a passive-open connection to FinWait1 and return (server_iss, fin_seq).
// ---------------------------------------------------------------------------
fn setup_fin_wait1(
    handler: &mut super::super::handler::TcpHandler,
    nh: &crate::net::NeighborHandler,
    free: &mut BasicFrameBuffer<'static>,
    rx: &mut BasicFrameBuffer<'static>,
    tx: &mut BasicFrameBuffer<'static>,
) -> (u32, u32) {
    let server_iss = establish_connection(handler, nh, free, rx, tx);
    handler.first_connection_mut().pending_fin = true;
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), nh, free, rx, tx);
    while tx.pop().is_some() {}
    assert_eq!(handler.first_connection().state, TcpState::FinWait1);
    let fin_seq = handler.first_connection().fin_seq.unwrap();
    (server_iss, fin_seq)
}

// Helper: bring connection to FinWait2 and return (server_iss, fin_seq).
fn setup_fin_wait2(
    handler: &mut super::super::handler::TcpHandler,
    nh: &crate::net::NeighborHandler,
    free: &mut BasicFrameBuffer<'static>,
    rx: &mut BasicFrameBuffer<'static>,
    tx: &mut BasicFrameBuffer<'static>,
) -> (u32, u32) {
    let (server_iss, fin_seq) = setup_fin_wait1(handler, nh, free, rx, tx);
    // Remote ACKs our FIN.
    let ack = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        fin_seq.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
    );
    let ack_len = ack.len();
    handler.process_ipv4(
        Frame::new(10, leak(ack), ack_len, false),
        coarsetime::Instant::now(),
        nh,
        free,
        rx,
        tx,
    );
    assert_eq!(handler.first_connection().state, TcpState::FinWait2);
    while tx.pop().is_some() {}
    (server_iss, fin_seq)
}

// Helper: bring connection to TimeWait and return (server_iss, fin_seq).
fn setup_time_wait(
    handler: &mut super::super::handler::TcpHandler,
    nh: &crate::net::NeighborHandler,
    free: &mut BasicFrameBuffer<'static>,
    rx: &mut BasicFrameBuffer<'static>,
    tx: &mut BasicFrameBuffer<'static>,
) -> (u32, u32) {
    let (server_iss, fin_seq) = setup_fin_wait2(handler, nh, free, rx, tx);
    // Remote sends FIN.
    let fin = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        fin_seq.wrapping_add(1),
        flags::ACK | flags::FIN,
        65535,
        &[],
    );
    let fin_len = fin.len();
    handler.process_ipv4(
        Frame::new(11, leak(fin), fin_len, false),
        coarsetime::Instant::now(),
        nh,
        free,
        rx,
        tx,
    );
    assert_eq!(handler.first_connection().state, TcpState::TimeWait);
    while tx.pop().is_some() {}
    (server_iss, fin_seq)
}

// Helper: bring connection to CloseWait and return server_iss.
fn setup_close_wait(
    handler: &mut super::super::handler::TcpHandler,
    nh: &crate::net::NeighborHandler,
    free: &mut BasicFrameBuffer<'static>,
    rx: &mut BasicFrameBuffer<'static>,
    tx: &mut BasicFrameBuffer<'static>,
) -> u32 {
    let server_iss = establish_connection(handler, nh, free, rx, tx);
    // Remote sends FIN.
    let fin = build_tcp_frame(
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
    let fin_len = fin.len();
    handler.process_ipv4(
        Frame::new(10, leak(fin), fin_len, false),
        coarsetime::Instant::now(),
        nh,
        free,
        rx,
        tx,
    );
    assert_eq!(handler.first_connection().state, TcpState::CloseWait);
    while tx.pop().is_some() {}
    server_iss
}

fn alloc_buffers() -> (
    BasicFrameBuffer<'static>,
    BasicFrameBuffer<'static>,
    BasicFrameBuffer<'static>,
) {
    let mut free = BasicFrameBuffer::new(32);
    let rx = BasicFrameBuffer::new(32);
    let tx = BasicFrameBuffer::new(32);
    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }
    (free, rx, tx)
}

// ---------------------------------------------------------------------------
// FinWait1: receives FIN+ACK simultaneously → TimeWait
// ---------------------------------------------------------------------------
#[test]
fn fin_wait1_fin_and_ack_simultaneously_transitions_to_time_wait() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let (mut free, mut rx, mut tx) = alloc_buffers();

    let (_server_iss, fin_seq) = setup_fin_wait1(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    // Remote sends FIN+ACK that also ACKs our FIN.
    let fin_ack = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        fin_seq.wrapping_add(1),
        flags::ACK | flags::FIN,
        65535,
        &[],
    );
    let len = fin_ack.len();
    handler.process_ipv4(
        Frame::new(20, leak(fin_ack), len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert_eq!(handler.first_connection().state, TcpState::TimeWait);
    assert!(handler.first_connection().time_wait_deadline.is_some());
    assert!(handler.first_connection().retransmit_deadline.is_none());
    // Should have sent an ACK for the FIN.
    assert!(tx.num_frames() >= 1, "ACK for remote FIN expected");
}

// ---------------------------------------------------------------------------
// FinWait1: receives data while waiting for FIN-ACK
// ---------------------------------------------------------------------------
#[test]
fn fin_wait1_processes_incoming_data() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let (mut free, mut rx, mut tx) = alloc_buffers();

    let (server_iss, _fin_seq) = setup_fin_wait1(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    let rcv_nxt_before = handler.first_connection().rcv_nxt;

    // Remote sends data (no ACK of our FIN, just regular ACK).
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
        b"hello",
    );
    let len = data.len();
    handler.process_ipv4(
        Frame::new(20, leak(data), len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // rcv_nxt should advance by payload length.
    assert_eq!(
        handler.first_connection().rcv_nxt,
        rcv_nxt_before.wrapping_add(5),
        "rcv_nxt should advance for data received in FinWait1"
    );
    // State should remain FinWait1 (no FIN-ACK yet, no remote FIN).
    assert_eq!(handler.first_connection().state, TcpState::FinWait1);
    // ACK should be sent for the data.
    assert!(tx.num_frames() >= 1, "ACK for data expected");
}

// ---------------------------------------------------------------------------
// FinWait2: receives data before FIN
// ---------------------------------------------------------------------------
#[test]
fn fin_wait2_processes_data_before_fin() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let (mut free, mut rx, mut tx) = alloc_buffers();

    let (_server_iss, fin_seq) = setup_fin_wait2(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    let rcv_nxt_before = handler.first_connection().rcv_nxt;

    // Remote sends data.
    let data = build_tcp_frame_with_payload(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        fin_seq.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
        b"still sending",
    );
    let len = data.len();
    handler.process_ipv4(
        Frame::new(20, leak(data), len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert_eq!(
        handler.first_connection().rcv_nxt,
        rcv_nxt_before.wrapping_add(13),
        "rcv_nxt should advance for data in FinWait2"
    );
    assert_eq!(handler.first_connection().state, TcpState::FinWait2);
    assert!(tx.num_frames() >= 1, "ACK for data expected");
}

// ---------------------------------------------------------------------------
// TimeWait: duplicate FIN → re-ACK and restart timer
// ---------------------------------------------------------------------------
#[test]
fn time_wait_duplicate_fin_reacks_and_restarts_timer() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let (mut free, mut rx, mut tx) = alloc_buffers();

    let (_server_iss, fin_seq) = setup_time_wait(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    let old_deadline = handler.first_connection().time_wait_deadline.unwrap();

    // Remote retransmits FIN.
    let dup_fin = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        fin_seq.wrapping_add(1),
        flags::ACK | flags::FIN,
        65535,
        &[],
    );
    let len = dup_fin.len();
    handler.process_ipv4(
        Frame::new(30, leak(dup_fin), len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Connection still in TimeWait.
    assert_eq!(handler.first_connection().state, TcpState::TimeWait);
    // Timer restarted (new deadline >= old deadline).
    let new_deadline = handler.first_connection().time_wait_deadline.unwrap();
    assert!(
        new_deadline >= old_deadline,
        "time_wait_deadline should be restarted"
    );
    // ACK should be sent.
    assert!(tx.num_frames() >= 1, "re-ACK for duplicate FIN expected");
}

// ---------------------------------------------------------------------------
// CloseWait: window update with WL1/WL2 guard
// ---------------------------------------------------------------------------
#[test]
fn close_wait_window_update_with_wl_guard() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let (mut free, mut rx, mut tx) = alloc_buffers();

    let _server_iss = setup_close_wait(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    // Set up known snd_wl1/snd_wl2 values.
    let snd_una = handler.first_connection().snd_una;
    handler.first_connection_mut().snd_wl1 = 1000;
    handler.first_connection_mut().snd_wl2 = snd_una;

    // We need seg_ack to be valid (snd_una < seg_ack <= snd_nxt).
    // Write some data so snd_nxt > snd_una.
    handler
        .first_connection_mut()
        .send_buffer
        .write(b"test data");
    handler.first_connection_mut().snd_wnd = 65535;
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}
    let snd_nxt = handler.first_connection().snd_nxt;

    let ack = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1002,
        snd_nxt,
        flags::ACK,
        32000,
        &[],
    );
    let ack_len = ack.len();
    handler.process_ipv4(
        Frame::new(20, leak(ack), ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert_eq!(handler.first_connection().state, TcpState::CloseWait);
    assert_eq!(
        handler.first_connection().snd_wnd,
        32000,
        "window should be updated in CloseWait"
    );
    assert_eq!(handler.first_connection().snd_wl1, 1002);
    assert_eq!(handler.first_connection().snd_wl2, snd_nxt);
}

// ---------------------------------------------------------------------------
// RST exact match in teardown state → reset + remove connection
// ---------------------------------------------------------------------------
#[test]
fn teardown_rst_exact_match_removes_connection() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let (mut free, mut rx, mut tx) = alloc_buffers();

    let (_server_iss, _fin_seq) = setup_fin_wait1(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    let rcv_nxt = handler.first_connection().rcv_nxt;

    // Send RST with seq == rcv_nxt (exact match).
    let rst = build_tcp_frame(
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
    let len = rst.len();
    handler.process_ipv4(
        Frame::new(20, leak(rst), len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert_eq!(handler.connections.len(), 0, "RST should remove connection");
}

// ---------------------------------------------------------------------------
// RST in-window but not exact → challenge ACK
// ---------------------------------------------------------------------------
#[test]
fn teardown_rst_in_window_sends_challenge_ack() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let (mut free, mut rx, mut tx) = alloc_buffers();

    let (_server_iss, _fin_seq) = setup_fin_wait1(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    let rcv_nxt = handler.first_connection().rcv_nxt;

    // Send RST with seq in window but not exact match.
    let rst = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        rcv_nxt.wrapping_add(1),
        0,
        flags::RST,
        0,
        &[],
    );
    let len = rst.len();
    handler.process_ipv4(
        Frame::new(20, leak(rst), len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Connection should NOT be removed.
    assert_eq!(
        handler.connections.len(),
        1,
        "in-window RST should not remove connection"
    );
    // Challenge ACK should be sent.
    assert!(
        tx.num_frames() >= 1,
        "challenge ACK expected for in-window RST"
    );
}

// ---------------------------------------------------------------------------
// SYN in teardown state → challenge ACK (RFC 5961)
// ---------------------------------------------------------------------------
#[test]
fn teardown_syn_sends_challenge_ack() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let (mut free, mut rx, mut tx) = alloc_buffers();

    let (_server_iss, _fin_seq) = setup_fin_wait1(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    let rcv_nxt = handler.first_connection().rcv_nxt;

    // Send SYN in teardown state.
    let syn = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        rcv_nxt,
        0,
        flags::SYN,
        65535,
        &[],
    );
    let len = syn.len();
    handler.process_ipv4(
        Frame::new(20, leak(syn), len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Connection should remain.
    assert_eq!(handler.connections.len(), 1);
    assert_eq!(handler.first_connection().state, TcpState::FinWait1);
    // Challenge ACK sent.
    assert!(
        tx.num_frames() >= 1,
        "challenge ACK expected for SYN in teardown"
    );
}

// ---------------------------------------------------------------------------
// No ACK bit → segment dropped
// ---------------------------------------------------------------------------
#[test]
fn teardown_no_ack_bit_drops_segment() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let (mut free, mut rx, mut tx) = alloc_buffers();

    let (_server_iss, _fin_seq) = setup_fin_wait1(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    let rcv_nxt = handler.first_connection().rcv_nxt;

    // Send segment with no flags set (no ACK, no SYN, no RST, no FIN).
    // This won't pass SYN/RST checks and will hit the "ACK bit off" check.
    // We need a bare segment — just no flags.
    let bare = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, rcv_nxt, 0, 0, 65535, &[]);
    let len = bare.len();
    handler.process_ipv4(
        Frame::new(20, leak(bare), len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Should be silently dropped: no tx frames, connection unchanged.
    assert_eq!(handler.connections.len(), 1);
    assert_eq!(handler.first_connection().state, TcpState::FinWait1);
    assert_eq!(tx.num_frames(), 0, "no ACK should be sent for bare segment");
}

// ---------------------------------------------------------------------------
// Out-of-window segment → ACK sent (not RST)
// ---------------------------------------------------------------------------
#[test]
fn teardown_out_of_window_sends_ack() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let (mut free, mut rx, mut tx) = alloc_buffers();

    let (_server_iss, _fin_seq) = setup_fin_wait1(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    let rcv_nxt = handler.first_connection().rcv_nxt;

    // Send segment far outside the window.
    let oow = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        rcv_nxt.wrapping_add(1_000_000),
        0,
        flags::ACK,
        65535,
        &[],
    );
    let len = oow.len();
    handler.process_ipv4(
        Frame::new(20, leak(oow), len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Connection still exists.
    assert_eq!(handler.connections.len(), 1);
    assert_eq!(handler.first_connection().state, TcpState::FinWait1);
    // ACK should be sent for out-of-window non-RST.
    assert!(
        tx.num_frames() >= 1,
        "ACK expected for out-of-window segment"
    );
}

// ---------------------------------------------------------------------------
// Out-of-window RST → silently dropped
// ---------------------------------------------------------------------------
#[test]
fn teardown_out_of_window_rst_silently_dropped() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let (mut free, mut rx, mut tx) = alloc_buffers();

    let (_server_iss, _fin_seq) = setup_fin_wait1(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    let rcv_nxt = handler.first_connection().rcv_nxt;

    // Send RST far outside the window.
    let rst = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        rcv_nxt.wrapping_add(1_000_000),
        0,
        flags::RST,
        0,
        &[],
    );
    let len = rst.len();
    handler.process_ipv4(
        Frame::new(20, leak(rst), len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Connection still exists, no frames sent.
    assert_eq!(handler.connections.len(), 1);
    assert_eq!(handler.first_connection().state, TcpState::FinWait1);
    assert_eq!(
        tx.num_frames(),
        0,
        "out-of-window RST should be silently dropped"
    );
}

// ---------------------------------------------------------------------------
// FinWait1: ACK advances snd_una and updates window
// ---------------------------------------------------------------------------
#[test]
fn fin_wait1_ack_advances_snd_una() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let (mut free, mut rx, mut tx) = alloc_buffers();

    let _server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    // Write data, send it, ACK it, then close — so FIN and data are separate.
    handler
        .first_connection_mut()
        .send_buffer
        .write(b"data before close");
    handler.first_connection_mut().snd_wnd = 65535;
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}

    let snd_nxt_after_data = handler.first_connection().snd_nxt;

    // ACK the data so bytes_in_flight goes to 0.
    let data_ack = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        snd_nxt_after_data,
        flags::ACK,
        65535,
        &[],
    );
    let data_ack_len = data_ack.len();
    handler.process_ipv4(
        Frame::new(15, leak(data_ack), data_ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    while tx.pop().is_some() {}

    // Now close: set pending_fin and poll_send to send FIN.
    handler.first_connection_mut().pending_fin = true;
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}
    assert_eq!(handler.first_connection().state, TcpState::FinWait1);

    let fin_seq = handler.first_connection().fin_seq.unwrap();

    // Remote ACKs the FIN → FinWait2.
    let fin_ack = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        fin_seq.wrapping_add(1),
        flags::ACK,
        40000,
        &[],
    );
    let len = fin_ack.len();
    handler.process_ipv4(
        Frame::new(20, leak(fin_ack), len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // snd_una should advance past FIN.
    assert_eq!(
        handler.first_connection().snd_una,
        fin_seq.wrapping_add(1),
        "snd_una should advance for FIN ACK in FinWait1"
    );
    // Window should be updated.
    assert_eq!(handler.first_connection().snd_wnd, 40000);
    // Should transition to FinWait2.
    assert_eq!(handler.first_connection().state, TcpState::FinWait2);
    // Send buffer should be drained.
    assert_eq!(handler.first_connection().send_buffer.available(), 0);
}

// ---------------------------------------------------------------------------
// Closing: ACK of our FIN → TimeWait (with snd_una advance)
// ---------------------------------------------------------------------------
#[test]
fn closing_ack_of_fin_transitions_to_time_wait() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let (mut free, mut rx, mut tx) = alloc_buffers();

    let (server_iss, fin_seq) = setup_fin_wait1(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    // Remote sends FIN without ACKing ours → Closing.
    let fin = build_tcp_frame(
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
    let len = fin.len();
    handler.process_ipv4(
        Frame::new(20, leak(fin), len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(handler.first_connection().state, TcpState::Closing);
    while tx.pop().is_some() {}

    // Now remote ACKs our FIN → TimeWait.
    let ack = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1002,
        fin_seq.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
    );
    let ack_len = ack.len();
    handler.process_ipv4(
        Frame::new(21, leak(ack), ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert_eq!(handler.first_connection().state, TcpState::TimeWait);
    assert!(handler.first_connection().time_wait_deadline.is_some());
    assert!(handler.first_connection().retransmit_deadline.is_none());
    assert_eq!(
        handler.first_connection().snd_una,
        fin_seq.wrapping_add(1),
        "snd_una should advance to cover FIN"
    );
}

// ---------------------------------------------------------------------------
// FinWait2: data + FIN in same segment → TimeWait
// ---------------------------------------------------------------------------
#[test]
fn fin_wait2_data_and_fin_transitions_to_time_wait() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let (mut free, mut rx, mut tx) = alloc_buffers();

    let (_server_iss, fin_seq) = setup_fin_wait2(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    let rcv_nxt_before = handler.first_connection().rcv_nxt;

    // Remote sends data + FIN.
    let data_fin = build_tcp_frame_with_payload(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        fin_seq.wrapping_add(1),
        flags::ACK | flags::FIN,
        65535,
        &[],
        b"last data",
    );
    let len = data_fin.len();
    handler.process_ipv4(
        Frame::new(20, leak(data_fin), len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert_eq!(handler.first_connection().state, TcpState::TimeWait);
    // rcv_nxt should advance by data_len + 1 (for FIN).
    assert_eq!(
        handler.first_connection().rcv_nxt,
        rcv_nxt_before.wrapping_add(9 + 1),
        "rcv_nxt should advance by data + FIN"
    );
    assert!(handler.first_connection().time_wait_deadline.is_some());
    assert!(tx.num_frames() >= 1, "ACK expected for data+FIN");
}

// ---------------------------------------------------------------------------
// LastAck: ACK that does NOT cover FIN → connection stays
// ---------------------------------------------------------------------------
#[test]
fn last_ack_partial_ack_does_not_remove_connection() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let (mut free, mut rx, mut tx) = alloc_buffers();

    let _server_iss = setup_close_wait(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    // Close → LastAck.
    handler.first_connection_mut().pending_fin = true;
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}
    assert_eq!(handler.first_connection().state, TcpState::LastAck);
    let fin_seq = handler.first_connection().fin_seq.unwrap();

    // Send ACK that does NOT cover the FIN (ack = fin_seq, not fin_seq+1).
    let ack = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1002,
        fin_seq,
        flags::ACK,
        65535,
        &[],
    );
    let len = ack.len();
    handler.process_ipv4(
        Frame::new(20, leak(ack), len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Connection should still exist in LastAck.
    assert_eq!(handler.connections.len(), 1);
    assert_eq!(handler.first_connection().state, TcpState::LastAck);
}
