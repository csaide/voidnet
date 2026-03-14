use super::*;

#[test]
fn cubic_slow_start_on_new_ack() {
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

    let cwnd_before = handler.connections[0].cubic.cwnd;
    let mss = handler.connections[0].eff_snd_mss;

    // Send data and get it ACKed.
    handler.connections[0].send_buffer.write(&[0xAA; 1460]);
    handler.connections[0].snd_wnd = 65535;
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}

    // ACK the data.
    let snd_nxt = handler.connections[0].snd_nxt;
    let ack = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        snd_nxt,
        flags::ACK,
        65535,
        &[],
    );
    let ack_len = ack.len();
    handler.process_ipv4(
        Frame::new(2, leak(ack), ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // In slow start: cwnd should increase by MSS (CUBIC slow start same as Reno).
    let cwnd_after = handler.connections[0].cubic.cwnd;
    assert_eq!(
        cwnd_after,
        cwnd_before + mss as u32,
        "slow start: cwnd += MSS"
    );
}

#[test]
fn frto_restores_cwnd_on_spurious_rto() {
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

    // Send 2 MSS of data (poll_send sends 1 MSS per call).
    let mss = handler.connections[0].eff_snd_mss as usize;
    handler.connections[0]
        .send_buffer
        .write(&vec![0xAA; mss * 2]);
    handler.connections[0].snd_wnd = 65535;
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}

    let cwnd_before_rto = handler.connections[0].cubic.cwnd;

    // Trigger RTO by setting deadline in the past.
    handler.connections[0].retransmit_deadline = Some(now);
    let rto_time = now + coarsetime::Duration::from_millis(1100);
    handler.poll_timers(rto_time, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}

    // F-RTO should be active.
    assert!(
        handler.connections[0].frto.is_active(),
        "F-RTO should be in Step1"
    );
    assert_eq!(
        handler.connections[0].cubic.cwnd, mss as u32,
        "cwnd should be 1 MSS after RTO"
    );

    // First ACK advances snd_una.
    let snd_una = handler.connections[0].snd_una;
    let ack1_seq = snd_una.wrapping_add(mss as u32);
    let ack1 = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        ack1_seq,
        flags::ACK,
        65535,
        &[],
    );
    let ack1_len = ack1.len();
    handler.process_ipv4(
        Frame::new(10, leak(ack1), ack1_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert!(
        handler.connections[0].frto.is_active(),
        "F-RTO should be in Step2"
    );

    // Second ACK advances snd_una again => spurious RTO.
    let snd_una = handler.connections[0].snd_una;
    let ack2_seq = snd_una.wrapping_add(mss as u32);
    let ack2 = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        ack2_seq,
        flags::ACK,
        65535,
        &[],
    );
    let ack2_len = ack2.len();
    handler.process_ipv4(
        Frame::new(11, leak(ack2), ack2_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // cwnd should be restored.
    assert!(
        !handler.connections[0].frto.is_active(),
        "F-RTO should be disabled"
    );
    assert_eq!(
        handler.connections[0].cubic.cwnd, cwnd_before_rto,
        "cwnd should be restored after spurious RTO"
    );
}
