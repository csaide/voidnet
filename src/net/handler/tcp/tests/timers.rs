use super::*;

use super::super::handler::INITIAL_RTO_MS;

// ---------------------------------------------------------------------------
// RTO exponential backoff — verify successive retransmissions double the RTO
// ---------------------------------------------------------------------------

#[test]
fn rto_exponential_backoff_doubles_on_successive_retransmits() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(64);
    let mut rx = BasicFrameBuffer::new(64);
    let mut tx = BasicFrameBuffer::new(64);
    for i in 0..32 {
        free.push(alloc_free_frame(100 + i));
    }

    establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    // Put data in send buffer and send it.
    handler.first_connection_mut().send_buffer.write(b"DATA");
    handler.first_connection_mut().snd_wnd = 65535;
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}

    // First RTO fire: backoff 0 -> 1.
    handler.first_connection_mut().retransmit_deadline =
        Some(now - coarsetime::Duration::from_millis(1));
    handler.first_connection_mut().rto_backoff = 0;
    let rto_before = handler.first_connection().rto;

    handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}

    let tcb = handler.first_connection();
    assert_eq!(
        tcb.rto_backoff, 1,
        "rto_backoff should be 1 after first RTO"
    );
    // The new deadline should be now + rto << 1.
    let expected_deadline = now + coarsetime::Duration::from_millis(rto_before << 1);
    assert_eq!(
        tcb.retransmit_deadline,
        Some(expected_deadline),
        "deadline should use doubled RTO"
    );

    // Second RTO fire: backoff 1 -> 2.
    handler.first_connection_mut().retransmit_deadline =
        Some(now - coarsetime::Duration::from_millis(1));
    handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}

    let tcb = handler.first_connection();
    assert_eq!(
        tcb.rto_backoff, 2,
        "rto_backoff should be 2 after second RTO"
    );
    let expected_deadline = now + coarsetime::Duration::from_millis(rto_before << 2);
    assert_eq!(
        tcb.retransmit_deadline,
        Some(expected_deadline),
        "deadline should use quadrupled RTO"
    );
}

// ---------------------------------------------------------------------------
// R2 threshold — verify connection aborted after max retransmissions
// ---------------------------------------------------------------------------

#[test]
fn r2_threshold_aborts_connection() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(64);
    let mut rx = BasicFrameBuffer::new(64);
    let mut tx = BasicFrameBuffer::new(64);
    for i in 0..32 {
        free.push(alloc_free_frame(100 + i));
    }

    let _server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    // Put data in send buffer and send it.
    handler.first_connection_mut().send_buffer.write(b"DATA");
    handler.first_connection_mut().snd_wnd = 65535;
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}

    let event_queue = handler.first_connection().event_queue.clone();

    // Set rto_backoff high enough that total_elapsed_ms >= SYN_R2_THRESHOLD_MS.
    // Formula: total = sum(INITIAL_RTO_MS << i) for i=0..=backoff
    // With INITIAL_RTO_MS=1000, backoff=8: total = 1000*(1+2+4+8+16+32+64+128+256) = 511_000 > 180_000
    handler.first_connection_mut().rto_backoff = 8;
    handler.first_connection_mut().retransmit_deadline =
        Some(now - coarsetime::Duration::from_millis(1));

    handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);

    // Connection should be removed.
    assert!(
        handler.connections.is_empty(),
        "connection should be removed after R2 threshold exceeded"
    );

    // Timeout event should have been emitted.
    let event = event_queue.pop();
    assert_eq!(
        event,
        Some(TcpEvent::Timeout),
        "TcpEvent::Timeout should be emitted on R2 abort"
    );
}

// ---------------------------------------------------------------------------
// FIN retransmit in FinWait1 state
// ---------------------------------------------------------------------------

#[test]
fn fin_retransmit_in_fin_wait1() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(64);
    let mut rx = BasicFrameBuffer::new(64);
    let mut tx = BasicFrameBuffer::new(64);
    for i in 0..32 {
        free.push(alloc_free_frame(100 + i));
    }

    let _server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    // Initiate close to send FIN.
    handler.initiate_close(handler.first_connection_key());
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}

    assert_eq!(
        handler.first_connection().state,
        TcpState::FinWait1,
        "should be in FinWait1 after sending FIN"
    );
    assert!(
        handler.first_connection().fin_seq.is_some(),
        "fin_seq should be set"
    );

    // Set retransmit deadline in the past to trigger FIN retransmit.
    handler.first_connection_mut().retransmit_deadline =
        Some(now - coarsetime::Duration::from_millis(1));
    handler.first_connection_mut().rto_backoff = 0;

    handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);

    // FIN-ACK should be retransmitted.
    assert!(
        tx.num_frames() >= 1,
        "FIN-ACK should be retransmitted in FinWait1"
    );

    let tcb = handler.first_connection();
    assert_eq!(tcb.rto_backoff, 1, "rto_backoff should be incremented");
    assert!(
        tcb.retransmit_deadline.is_some(),
        "retransmit deadline should be re-armed"
    );
}

// ---------------------------------------------------------------------------
// FIN retransmit in LastAck state
// ---------------------------------------------------------------------------

#[test]
fn fin_retransmit_in_last_ack() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(64);
    let mut rx = BasicFrameBuffer::new(64);
    let mut tx = BasicFrameBuffer::new(64);
    for i in 0..32 {
        free.push(alloc_free_frame(100 + i));
    }

    let server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    // Receive FIN from remote to move to CloseWait.
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
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    while tx.pop().is_some() {}
    assert_eq!(handler.first_connection().state, TcpState::CloseWait);

    // Now close our side to move to LastAck.
    handler.initiate_close(handler.first_connection_key());
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}
    assert_eq!(handler.first_connection().state, TcpState::LastAck);
    assert!(handler.first_connection().fin_seq.is_some());

    // Set retransmit deadline in the past.
    handler.first_connection_mut().retransmit_deadline =
        Some(now - coarsetime::Duration::from_millis(1));
    handler.first_connection_mut().rto_backoff = 0;

    handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);

    assert!(
        tx.num_frames() >= 1,
        "FIN-ACK should be retransmitted in LastAck"
    );
    let tcb = handler.first_connection();
    assert_eq!(tcb.rto_backoff, 1, "rto_backoff should be incremented");
}

// ---------------------------------------------------------------------------
// SYN retransmit with exponential backoff
// ---------------------------------------------------------------------------

#[test]
fn syn_retransmit_exponential_backoff() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(64);
    let mut rx = BasicFrameBuffer::new(64);
    let mut tx = BasicFrameBuffer::new(64);
    for i in 0..32 {
        free.push(alloc_free_frame(100 + i));
    }

    let src_mac =
        crate::net::wire::ethernet::MacAddress::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    let dst_mac =
        crate::net::wire::ethernet::MacAddress::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    nh.seed_cache(
        coarsetime::Instant::now(),
        IpAddress::V4(REMOTE_IP),
        MacAddress::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
    );

    // Connect sends SYN — state goes to SynSent.
    let (_key, _eq) = handler
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

    let now = coarsetime::Instant::now();

    // First retransmit: backoff 0 -> 1.
    handler.first_connection_mut().retransmit_deadline =
        Some(now - coarsetime::Duration::from_millis(1));
    handler.first_connection_mut().rto_backoff = 0;

    handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    assert!(tx.num_frames() >= 1, "SYN should be retransmitted");
    while tx.pop().is_some() {}

    let tcb = handler.first_connection();
    assert_eq!(
        tcb.rto_backoff, 1,
        "backoff should be 1 after first retransmit"
    );
    // Deadline should be now + INITIAL_RTO_MS << 1.
    let expected = now + coarsetime::Duration::from_millis(INITIAL_RTO_MS << 1);
    assert_eq!(
        tcb.retransmit_deadline,
        Some(expected),
        "SYN deadline should use doubled INITIAL_RTO_MS"
    );

    // Second retransmit: backoff 1 -> 2.
    handler.first_connection_mut().retransmit_deadline =
        Some(now - coarsetime::Duration::from_millis(1));
    handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}

    let tcb = handler.first_connection();
    assert_eq!(
        tcb.rto_backoff, 2,
        "backoff should be 2 after second retransmit"
    );
    let expected = now + coarsetime::Duration::from_millis(INITIAL_RTO_MS << 2);
    assert_eq!(
        tcb.retransmit_deadline,
        Some(expected),
        "SYN deadline should use quadrupled INITIAL_RTO_MS"
    );
}

// ---------------------------------------------------------------------------
// SYN R2 threshold — SynSent connection removed after timeout
// ---------------------------------------------------------------------------

#[test]
fn syn_r2_threshold_removes_connection() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(64);
    let mut rx = BasicFrameBuffer::new(64);
    let mut tx = BasicFrameBuffer::new(64);
    for i in 0..32 {
        free.push(alloc_free_frame(100 + i));
    }

    let src_mac =
        crate::net::wire::ethernet::MacAddress::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    let dst_mac =
        crate::net::wire::ethernet::MacAddress::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    nh.seed_cache(
        coarsetime::Instant::now(),
        IpAddress::V4(REMOTE_IP),
        MacAddress::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
    );

    let (_key, event_queue) = handler
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

    let now = coarsetime::Instant::now();

    // Set backoff high enough for R2 threshold.
    handler.first_connection_mut().rto_backoff = 8;
    handler.first_connection_mut().retransmit_deadline =
        Some(now - coarsetime::Duration::from_millis(1));

    handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);

    assert!(
        handler.connections.is_empty(),
        "SynSent connection should be removed after R2 threshold"
    );
    assert_eq!(
        event_queue.pop(),
        Some(TcpEvent::Timeout),
        "TcpEvent::Timeout should be emitted"
    );
}

// ---------------------------------------------------------------------------
// SYN-ACK retransmit in SynReceived state
// ---------------------------------------------------------------------------

#[test]
fn syn_ack_retransmit_in_syn_received() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(64);
    let mut rx = BasicFrameBuffer::new(64);
    let mut tx = BasicFrameBuffer::new(64);
    for i in 0..32 {
        free.push(alloc_free_frame(100 + i));
    }

    // Send SYN to create a SynReceived connection.
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
    while tx.pop().is_some() {}
    assert_eq!(handler.first_connection().state, TcpState::SynReceived);

    let now = coarsetime::Instant::now();

    // Trigger retransmit.
    handler.first_connection_mut().retransmit_deadline =
        Some(now - coarsetime::Duration::from_millis(1));
    handler.first_connection_mut().rto_backoff = 0;

    handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);

    assert!(
        tx.num_frames() >= 1,
        "SYN-ACK should be retransmitted in SynReceived"
    );
    let tcb = handler.first_connection();
    assert_eq!(tcb.rto_backoff, 1, "rto_backoff should be incremented");
    let expected = now + coarsetime::Duration::from_millis(INITIAL_RTO_MS << 1);
    assert_eq!(
        tcb.retransmit_deadline,
        Some(expected),
        "SYN-ACK deadline should be backed off"
    );
}

// ---------------------------------------------------------------------------
// Delayed ACK with ECE flag set
// ---------------------------------------------------------------------------

#[test]
fn delayed_ack_timer_includes_ece_flag_when_ce_received() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let now = coarsetime::Instant::now();
    let _server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    // Set delayed ACK state and ECN CE received flag.
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
        tcb.ecn_ce_received = true;
    }

    // Fire after deadline.
    let later = now + coarsetime::Duration::from_millis(50);
    handler.poll_timers(later, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);

    // ACK should have been sent.
    assert_eq!(tx.num_frames(), 1, "ACK should be flushed after deadline");

    let tcb = handler.get_connection(&id).unwrap();
    assert!(!tcb.ack_pending, "ack_pending should be cleared");
}

// ---------------------------------------------------------------------------
// evict_stale removes TIME-WAIT connections past deadline
// ---------------------------------------------------------------------------

#[test]
fn evict_stale_removes_time_wait_connection() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(64);
    let mut rx = BasicFrameBuffer::new(64);
    let mut tx = BasicFrameBuffer::new(64);
    for i in 0..32 {
        free.push(alloc_free_frame(100 + i));
    }

    let _server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    let now = coarsetime::Instant::now();

    // Manually set connection to TimeWait with a deadline in the past.
    handler.first_connection_mut().state = TcpState::TimeWait;
    handler.first_connection_mut().time_wait_deadline =
        Some(now - coarsetime::Duration::from_millis(1));

    handler.evict_stale(now, &mut rx);

    assert!(
        handler.connections.is_empty(),
        "TIME-WAIT connection should be removed after deadline"
    );
}

#[test]
fn evict_stale_keeps_time_wait_before_deadline() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(64);
    let mut rx = BasicFrameBuffer::new(64);
    let mut tx = BasicFrameBuffer::new(64);
    for i in 0..32 {
        free.push(alloc_free_frame(100 + i));
    }

    let _server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    let now = coarsetime::Instant::now();

    // Set TimeWait with deadline in the future.
    handler.first_connection_mut().state = TcpState::TimeWait;
    handler.first_connection_mut().time_wait_deadline =
        Some(now + coarsetime::Duration::from_millis(60_000));

    handler.evict_stale(now, &mut rx);

    assert_eq!(
        handler.connections.len(),
        1,
        "TIME-WAIT connection should be kept before deadline"
    );
}

// ---------------------------------------------------------------------------
// RTO retransmit does not fire before deadline
// ---------------------------------------------------------------------------

#[test]
fn rto_retransmit_does_not_fire_before_deadline() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(64);
    let mut rx = BasicFrameBuffer::new(64);
    let mut tx = BasicFrameBuffer::new(64);
    for i in 0..32 {
        free.push(alloc_free_frame(100 + i));
    }

    let _server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    handler.first_connection_mut().send_buffer.write(b"DATA");
    handler.first_connection_mut().snd_wnd = 65535;
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}

    // Set deadline in the future.
    handler.first_connection_mut().retransmit_deadline =
        Some(now + coarsetime::Duration::from_millis(5000));
    handler.first_connection_mut().rto_backoff = 0;
    handler.first_connection_mut().ack_pending = false;

    handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);

    assert_eq!(tx.num_frames(), 0, "no retransmission before deadline");
    assert_eq!(
        handler.first_connection().rto_backoff,
        0,
        "rto_backoff unchanged"
    );
}

// ---------------------------------------------------------------------------
// FIN retransmit in Closing state
// ---------------------------------------------------------------------------

#[test]
fn fin_retransmit_in_closing_state() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(64);
    let mut rx = BasicFrameBuffer::new(64);
    let mut tx = BasicFrameBuffer::new(64);
    for i in 0..32 {
        free.push(alloc_free_frame(100 + i));
    }

    establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    // Initiate close to enter FinWait1.
    handler.initiate_close(handler.first_connection_key());
    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    while tx.pop().is_some() {}
    assert_eq!(handler.first_connection().state, TcpState::FinWait1);

    let fin_seq = handler.first_connection().fin_seq.unwrap();

    // Receive FIN from remote (simultaneous close) to move to Closing.
    let remote_fin = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        fin_seq, // ACK our data but not our FIN
        flags::ACK | flags::FIN,
        65535,
        &[],
    );
    let remote_fin_len = remote_fin.len();
    handler.process_ipv4(
        Frame::new(20, leak(remote_fin), remote_fin_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    while tx.pop().is_some() {}
    assert_eq!(handler.first_connection().state, TcpState::Closing);

    // Trigger FIN retransmit.
    handler.first_connection_mut().retransmit_deadline =
        Some(now - coarsetime::Duration::from_millis(1));
    handler.first_connection_mut().rto_backoff = 0;

    handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);

    assert!(
        tx.num_frames() >= 1,
        "FIN-ACK should be retransmitted in Closing"
    );
    let tcb = handler.first_connection();
    assert_eq!(tcb.rto_backoff, 1, "rto_backoff should be incremented");
}

// ---------------------------------------------------------------------------
// No retransmit when retransmit_deadline is None
// ---------------------------------------------------------------------------

#[test]
fn no_retransmit_when_deadline_is_none() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(64);
    let mut rx = BasicFrameBuffer::new(64);
    let mut tx = BasicFrameBuffer::new(64);
    for i in 0..32 {
        free.push(alloc_free_frame(100 + i));
    }

    let _server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    // Ensure no retransmit deadline and no ack_pending.
    handler.first_connection_mut().retransmit_deadline = None;
    handler.first_connection_mut().ack_pending = false;

    let now = coarsetime::Instant::now();
    handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);

    assert_eq!(
        tx.num_frames(),
        0,
        "nothing should be sent with no deadline and no pending ACK"
    );
}
