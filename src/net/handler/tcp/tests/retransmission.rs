use super::*;

#[test]
fn fast_retransmit_on_three_dup_acks() {
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

    // Put data in send buffer and send it.
    handler.connections[0].send_buffer.write(b"AAAA");
    handler.connections[0].snd_wnd = 65535;
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {} // consume sent segment

    let cwnd_before = handler.connections[0].cubic.cwnd;

    // Send 3 duplicate ACKs (ACKing the old snd_una, not the new data).
    let dup_ack_seq = server_iss.wrapping_add(1); // original snd_una
    for i in 0..3u64 {
        let dup = build_tcp_frame(
            REMOTE_IP,
            LOCAL_IP,
            12345,
            80,
            1001,
            dup_ack_seq,
            flags::ACK,
            65535,
            &[],
        );
        let dup_len = dup.len();
        handler.process_ipv4(
            Frame::new(10 + i, leak(dup), dup_len, false),
            coarsetime::Instant::now(),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
    }

    // Recovery entry now happens at dup ACK processing time (not poll_timers).
    let tcb = &handler.connections[0];
    assert_eq!(tcb.recovery.dup_ack_count, 3);
    assert!(tcb.recovery.in_recovery, "should be in SACK recovery");
    // CUBIC beta=0.7: cwnd = ssthresh = cwnd_before * 0.7.
    assert!(
        tcb.cubic.cwnd < cwnd_before,
        "cwnd should be reduced after recovery entry"
    );
    assert_eq!(
        tcb.cubic.cwnd, tcb.cubic.ssthresh,
        "cwnd should equal ssthresh after CUBIC on_loss"
    );
}

#[test]
fn rto_retransmit_on_timer_expiry() {
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

    // Put data in send buffer and send it.
    handler.connections[0].send_buffer.write(b"BBBB");
    handler.connections[0].snd_wnd = 65535;
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}

    let cwnd_before = handler.connections[0].cubic.cwnd;

    // Simulate timer expiry by setting a deadline in the past.
    handler.connections[0].retransmit_deadline = Some(now - coarsetime::Duration::from_millis(1));
    handler.connections[0].rto_backoff = 0;

    // poll_timers should trigger RTO retransmit.
    handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    assert!(tx.num_frames() >= 1, "retransmitted segment expected");

    let tcb = &handler.connections[0];
    // cwnd should be reset to 1 MSS (slow start).
    assert_eq!(
        tcb.cubic.cwnd, tcb.eff_snd_mss as u32,
        "cwnd should be 1 MSS after RTO"
    );
    assert!(
        tcb.cubic.ssthresh < cwnd_before,
        "ssthresh should be reduced"
    );
    assert_eq!(tcb.rto_backoff, 1, "rto_backoff should be incremented");
}

#[test]
fn rtt_estimation_updates_rto() {
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

    // Send data.
    handler.connections[0].send_buffer.write(b"test data");
    handler.connections[0].snd_wnd = 65535;
    let send_time = coarsetime::Instant::now();
    handler.poll_send(send_time, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}

    // Verify last_send_time is set.
    assert!(
        handler.connections[0].last_send_time.is_some(),
        "last_send_time should be set after poll_send"
    );

    // ACK the data.
    let new_ack = server_iss.wrapping_add(1).wrapping_add(9); // ISS+1 + 9 bytes
    let ack = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        new_ack,
        flags::ACK,
        65535,
        &[],
    );
    let ack_len = ack.len();
    let recv_time = coarsetime::Instant::now();
    handler.process_ipv4(
        Frame::new(5, leak(ack), ack_len, false),
        recv_time,
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Verify RTT was measured.
    let tcb = &handler.connections[0];
    assert!(
        tcb.srtt.is_some(),
        "srtt should be set after first RTT measurement"
    );
    assert!(
        tcb.last_send_time.is_none(),
        "last_send_time should be consumed"
    );
    // RTO should be at least 1000ms (the minimum clamp).
    assert!(tcb.rto >= 1000, "rto should be at least 1000ms");
    assert!(tcb.rto <= 60_000, "rto should be at most 60000ms");
}

#[test]
fn limited_transmit_sends_on_first_dup_ack() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(64);
    let mut rx = BasicFrameBuffer::new(64);
    let mut tx = BasicFrameBuffer::new(64);
    for i in 0..32 {
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

    let mss = handler.connections[0].eff_snd_mss as usize;
    // Fill send buffer with 6 MSS of data, set cwnd to 3*MSS.
    handler.connections[0]
        .send_buffer
        .write(&vec![0xAA; mss * 6]);
    handler.connections[0].snd_wnd = 65535;
    handler.connections[0].cubic.cwnd = (mss * 3) as u32;

    // Send 3 segments (fills cwnd).
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}

    let snd_nxt_before = handler.connections[0].snd_nxt;
    let snd_una = handler.connections[0].snd_una;

    // First dup ACK.
    let dup = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        snd_una,
        flags::ACK,
        65535,
        &[],
    );
    let dup_len = dup.len();
    handler.process_ipv4(
        Frame::new(10, leak(dup), dup_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert_eq!(handler.connections[0].recovery.dup_ack_count, 1);

    // poll_send should allow 1 MSS of new data (limited transmit).
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);

    let snd_nxt_after = handler.connections[0].snd_nxt;
    assert_eq!(
        snd_nxt_after.wrapping_sub(snd_nxt_before) as usize,
        mss,
        "limited transmit: 1 MSS sent on first dup ACK"
    );
}

#[test]
fn rto_backoff_resets_on_new_ack() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    // Put data in server's send buffer and transmit it.
    handler.connections[0].send_buffer.write(b"CCCC");
    handler.connections[0].snd_wnd = 65535;
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}

    // Artificially set rto_backoff as if an RTO had fired.
    handler.connections[0].rto_backoff = 2;
    handler.connections[0].retransmit_deadline =
        Some(coarsetime::Instant::now() + coarsetime::Duration::from_millis(10_000));

    // Client ACKs the server's data (new ACK that advances snd_una).
    let new_ack = server_iss.wrapping_add(1).wrapping_add(4); // ISS+1 + 4 bytes
    let client_seq = 1001u32;
    let data = build_tcp_frame_with_payload(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        client_seq,
        new_ack,
        flags::ACK,
        65535,
        &[],
        b"hello",
    );
    let data_len = data.len();
    handler.process_ipv4(
        Frame::new(10, leak(data), data_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    let tcb = &handler.connections[0];
    assert_eq!(tcb.rto_backoff, 0, "rto_backoff should be reset on new ACK");
    // snd_una == snd_nxt (all data ACKed), so retransmit timer should be off.
    assert!(
        tcb.retransmit_deadline.is_none(),
        "retransmit_deadline should be None when all data is ACKed"
    );
}
