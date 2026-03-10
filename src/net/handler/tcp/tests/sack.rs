use super::*;

#[test]
fn ooo_data_sends_sack_blocks_in_dup_ack() {
    use crate::net::wire::tcp::{options as tcp_options, parse_sack_blocks};

    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    // Complete handshake with SACK_PERMITTED in SYN options.
    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
    let sack_perm_opts = [tcp_options::SACK_PERMITTED, 2];
    let syn_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1000,
        0,
        flags::SYN,
        65535,
        &sack_perm_opts,
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
    assert!(
        handler.connections[0].sack_enabled,
        "SACK should be negotiated"
    );
    let server_iss = handler.connections[0].iss;
    // Drain SYN-ACK.
    while tx.pop().is_some() {}

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

    // Send out-of-order segment: seq=1011, 5 bytes (gap from 1001..1011).
    let ooo_seg = build_tcp_frame_with_payload(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1011,
        server_iss.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
        b"world",
    );
    let ooo_len = ooo_seg.len();
    handler.process_ipv4(
        Frame::new(2, leak(ooo_seg), ooo_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Should have emitted a dup ACK with SACK blocks.
    assert_eq!(tx.num_frames(), 1, "OOO data triggers dup ACK");
    let ack_frame = tx.pop().unwrap();

    let tcp_offset = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
    let tcp = unsafe { TcpHeader::from_bytes_at(&ack_frame, tcp_offset) };
    assert_eq!(tcp.flags(), flags::ACK);
    assert_eq!(tcp.ack_num(), 1001, "dup ACK has original rcv_nxt");

    // Parse SACK blocks from the TCP options.
    let data_off_bytes = (tcp.data_offset() as usize) * 4;
    let opt_len = data_off_bytes - TCP_HEADER_LEN;
    assert!(opt_len > 0, "options should be present");
    let opt_start = tcp_offset + TCP_HEADER_LEN;
    let tcp_opts = &ack_frame[opt_start..opt_start + opt_len];
    let (blocks, count) = parse_sack_blocks(tcp_opts);
    assert_eq!(count, 1, "one SACK block expected");
    // Block should cover the OOO range: [1011, 1016).
    assert_eq!(blocks[0], Some((1011, 1016)));
}

#[test]
fn sack_blocks_update_scoreboard_on_ack() {
    use crate::net::wire::tcp::write_sack_option;

    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let _server_iss =
        establish_connection_with_sack(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    // Put data in the send buffer and advance snd_nxt to simulate sent data.
    let tcb = &mut handler.connections[0];
    tcb.send_buffer.write(&[0u8; 100]);
    tcb.snd_nxt = tcb.snd_una.wrapping_add(100);

    // Build an ACK that advances snd_una by 10, with SACK blocks for [30..50) and [70..90).
    let snd_una = tcb.snd_una;
    let new_ack = snd_una.wrapping_add(10);
    let sack_left1 = snd_una.wrapping_add(30);
    let sack_right1 = snd_una.wrapping_add(50);
    let sack_left2 = snd_una.wrapping_add(70);
    let sack_right2 = snd_una.wrapping_add(90);

    let mut opts = [0u8; 20];
    let written = write_sack_option(
        &mut opts,
        &[(sack_left1, sack_right1), (sack_left2, sack_right2)],
    );

    let ack_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        new_ack,
        flags::ACK,
        65535,
        &opts[..written],
    );
    let ack_len = ack_data.len();
    handler.process_ipv4(
        Frame::new(2, leak(ack_data), ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    let tcb = &handler.connections[0];
    assert_eq!(tcb.snd_una, new_ack, "snd_una should advance");
    assert_eq!(
        tcb.sack_scoreboard.len(),
        2,
        "two SACK blocks in scoreboard"
    );
    assert_eq!(tcb.sack_scoreboard.get(&sack_left1), Some(&20));
    assert_eq!(tcb.sack_scoreboard.get(&sack_left2), Some(&20));
}

#[test]
fn sack_scoreboard_pruned_on_cumulative_ack_advance() {
    use crate::net::wire::tcp::write_sack_option;

    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let _server_iss =
        establish_connection_with_sack(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    let tcb = &mut handler.connections[0];
    tcb.send_buffer.write(&[0u8; 200]);
    tcb.snd_nxt = tcb.snd_una.wrapping_add(200);
    let snd_una = tcb.snd_una;

    // First ACK: advance by 10, SACK blocks at [30..50) and [100..120).
    let ack1 = snd_una.wrapping_add(10);
    let sack_left1 = snd_una.wrapping_add(30);
    let sack_right1 = snd_una.wrapping_add(50);
    let sack_left2 = snd_una.wrapping_add(100);
    let sack_right2 = snd_una.wrapping_add(120);

    let mut opts = [0u8; 20];
    let written = write_sack_option(
        &mut opts,
        &[(sack_left1, sack_right1), (sack_left2, sack_right2)],
    );
    let ack_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        ack1,
        flags::ACK,
        65535,
        &opts[..written],
    );
    let ack_len = ack_data.len();
    handler.process_ipv4(
        Frame::new(2, leak(ack_data), ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(handler.connections[0].sack_scoreboard.len(), 2);

    // Second ACK: advance cumulative ACK past the first SACK block (to 50).
    // Include the second block again.
    let ack2 = snd_una.wrapping_add(50);
    let mut opts2 = [0u8; 12];
    let written2 = write_sack_option(&mut opts2, &[(sack_left2, sack_right2)]);
    let ack_data2 = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        ack2,
        flags::ACK,
        65535,
        &opts2[..written2],
    );
    let ack_len2 = ack_data2.len();
    handler.process_ipv4(
        Frame::new(3, leak(ack_data2), ack_len2, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    let tcb = &handler.connections[0];
    assert_eq!(tcb.snd_una, ack2);
    // The first block (start=snd_una+30) should be pruned since 30 < 50.
    assert!(
        !tcb.sack_scoreboard.contains_key(&sack_left1),
        "old block should be pruned"
    );
    // The second block should remain.
    assert_eq!(tcb.sack_scoreboard.len(), 1, "only second block remains");
    assert!(tcb.sack_scoreboard.contains_key(&sack_left2));
}

#[test]
fn sack_blocks_updated_on_dup_ack() {
    use crate::net::wire::tcp::write_sack_option;

    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let _server_iss =
        establish_connection_with_sack(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    let tcb = &mut handler.connections[0];
    tcb.send_buffer.write(&[0u8; 100]);
    tcb.snd_nxt = tcb.snd_una.wrapping_add(100);
    let snd_una = tcb.snd_una;

    // Send a duplicate ACK (same ack number, no payload) with SACK block.
    let sack_left = snd_una.wrapping_add(20);
    let sack_right = snd_una.wrapping_add(40);
    let mut opts = [0u8; 12];
    let written = write_sack_option(&mut opts, &[(sack_left, sack_right)]);

    let dup_ack = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        snd_una,
        flags::ACK,
        65535,
        &opts[..written],
    );
    let dup_len = dup_ack.len();
    handler.process_ipv4(
        Frame::new(2, leak(dup_ack), dup_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    let tcb = &handler.connections[0];
    assert_eq!(tcb.recovery.dup_ack_count, 1);
    assert_eq!(tcb.sack_scoreboard.len(), 1);
    assert_eq!(tcb.sack_scoreboard.get(&sack_left), Some(&20));
}

#[test]
fn sack_scoreboard_cleared_on_rto() {
    use crate::net::wire::tcp::write_sack_option;

    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let _server_iss =
        establish_connection_with_sack(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    let tcb = &mut handler.connections[0];
    tcb.send_buffer.write(&[0u8; 100]);
    tcb.snd_nxt = tcb.snd_una.wrapping_add(100);
    let snd_una = tcb.snd_una;

    // Send a dup ACK with SACK blocks to populate the scoreboard.
    let sack_left = snd_una.wrapping_add(20);
    let sack_right = snd_una.wrapping_add(40);
    let mut opts = [0u8; 12];
    let written = write_sack_option(&mut opts, &[(sack_left, sack_right)]);

    let dup_ack = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        snd_una,
        flags::ACK,
        65535,
        &opts[..written],
    );
    let dup_len = dup_ack.len();
    handler.process_ipv4(
        Frame::new(2, leak(dup_ack), dup_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(handler.connections[0].sack_scoreboard.len(), 1);

    // Set up RTO: arm the retransmit deadline in the past.
    let now = coarsetime::Instant::now();
    handler.connections[0].retransmit_deadline = Some(now);
    handler.connections[0].rto_backoff = 0;

    // Trigger poll_timers, which should fire the RTO and clear the scoreboard.
    handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut tx);

    assert!(
        handler.connections[0].sack_scoreboard.is_empty(),
        "scoreboard should be cleared on RTO"
    );
}

#[test]
fn fast_retransmit_uses_sack_gap() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let _server_iss =
        establish_connection_with_sack(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    let tcb = &mut handler.connections[0];
    // Use a small effective MSS so the retransmit fits in a 256-byte frame.
    tcb.eff_snd_mss = 100;
    let mss = tcb.eff_snd_mss as usize;

    // Fill send buffer with 5 MSS worth of data.
    let mut data = vec![0u8; 5 * mss];
    for (i, byte) in data.iter_mut().enumerate() {
        *byte = (i / mss) as u8;
    }
    tcb.send_buffer.write(&data);
    tcb.snd_nxt = tcb.snd_una.wrapping_add(5 * mss as u32);
    let snd_una = tcb.snd_una;

    // SACK blocks for MSS 2, 3, 4 (gap is the 1st MSS).
    // This gives 3 SACKed segments above snd_una, satisfying DupThresh.
    tcb.sack_scoreboard
        .insert(snd_una.wrapping_add(mss as u32), mss as u32);
    tcb.sack_scoreboard
        .insert(snd_una.wrapping_add(2 * mss as u32), mss as u32);
    tcb.sack_scoreboard
        .insert(snd_una.wrapping_add(3 * mss as u32), mss as u32);

    // Enter SACK recovery (simulating what happens on 3 dup ACKs).
    let cwnd_before = tcb.cubic.cwnd;
    tcb.recovery.dup_ack_count = 3;
    tcb.recovery.enter(tcb.snd_nxt);
    tcb.prr.enter(tcb.snd_nxt.wrapping_sub(tcb.snd_una));
    tcb.cubic.on_loss();

    let now = coarsetime::Instant::now();
    handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut tx);

    // Verify a segment was emitted (the 1st MSS gap should be retransmitted).
    assert!(tx.pop().is_some(), "expected a retransmitted segment");

    let tcb = &handler.connections[0];
    assert!(tcb.recovery.in_recovery, "should still be in recovery");
    // cwnd should be reduced by CUBIC on_loss (beta=0.7).
    assert!(
        tcb.cubic.cwnd < cwnd_before,
        "cwnd should have been reduced"
    );
    assert_eq!(
        tcb.cubic.cwnd, tcb.cubic.ssthresh,
        "cwnd should equal ssthresh after CUBIC on_loss"
    );
}

#[test]
fn fast_retransmit_fallback_when_scoreboard_empty() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let _server_iss =
        establish_connection_with_sack(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    let tcb = &mut handler.connections[0];
    // Use a small effective MSS so the retransmit fits in a 256-byte frame.
    tcb.eff_snd_mss = 100;
    let mss = tcb.eff_snd_mss as usize;

    // Fill send buffer.
    tcb.send_buffer.write(&vec![0xABu8; 3 * mss]);
    tcb.snd_nxt = tcb.snd_una.wrapping_add(3 * mss as u32);

    // Record cwnd before.
    let cwnd_before = tcb.cubic.cwnd;

    // Scoreboard is empty; enter recovery manually.
    assert!(tcb.sack_scoreboard.is_empty());
    tcb.recovery.dup_ack_count = 3;
    tcb.recovery.enter(tcb.snd_nxt);
    tcb.prr.enter(tcb.snd_nxt.wrapping_sub(tcb.snd_una));
    tcb.cubic.on_loss();

    let now = coarsetime::Instant::now();
    handler.poll_timers(now, nh.local_mac(), &nh, &mut free, &mut tx);

    // With empty scoreboard, next_lost_segment returns None (nothing marked lost
    // by RFC 6675 criteria), so no retransmit is emitted from the recovery loop.
    // This is correct: without SACK blocks, nothing can be determined as lost.
    let tcb = &handler.connections[0];
    assert!(tcb.recovery.in_recovery, "should still be in recovery");
    assert!(
        tcb.cubic.cwnd < cwnd_before,
        "cwnd should have been reduced"
    );
    assert_eq!(
        tcb.cubic.cwnd, tcb.cubic.ssthresh,
        "cwnd should equal ssthresh after CUBIC on_loss"
    );
}

#[test]
fn sack_recovery_enters_on_3_dup_acks() {
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

    // Use small MSS so segments fit in 256-byte test frames.
    let mss = 100u16;
    handler.connections[0].eff_snd_mss = mss;

    // Write 4 MSS of data and simulate 4 segments sent by advancing snd_nxt.
    let data_len = 4 * mss as usize;
    handler.connections[0]
        .send_buffer
        .write(&vec![0xAA; data_len]);
    handler.connections[0].snd_wnd = 65535;
    handler.connections[0].snd_nxt =
        handler.connections[0].snd_una.wrapping_add(data_len as u32);

    let snd_una = handler.connections[0].snd_una;
    let cwnd_before = handler.connections[0].cubic.cwnd;

    // Send 3 dup ACKs.
    for i in 0..3 {
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
            Frame::new(10 + i, leak(dup), dup_len, false),
            coarsetime::Instant::now(),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
    }

    let tcb = &handler.connections[0];
    assert!(tcb.recovery.in_recovery, "should be in SACK recovery");
    assert_eq!(tcb.recovery.dup_ack_count, 3);
    // CUBIC beta=0.7: cwnd should be reduced by on_loss.
    assert!(
        tcb.cubic.cwnd < cwnd_before,
        "cwnd should be reduced by CUBIC on_loss"
    );
}

#[test]
fn sack_recovery_partial_ack_stays_in_recovery() {
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

    // Use small MSS so segments fit in 256-byte test frames.
    let mss = 100u16;
    handler.connections[0].eff_snd_mss = mss;

    // Write 4 MSS of data and simulate 4 segments sent by advancing snd_nxt.
    let data_len = 4 * mss as usize;
    handler.connections[0]
        .send_buffer
        .write(&vec![0xAA; data_len]);
    handler.connections[0].snd_wnd = 65535;
    handler.connections[0].snd_nxt =
        handler.connections[0].snd_una.wrapping_add(data_len as u32);

    let snd_una = handler.connections[0].snd_una;

    // 3 dup ACKs -> enter recovery.
    for i in 0..3 {
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
            Frame::new(10 + i, leak(dup), dup_len, false),
            coarsetime::Instant::now(),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
    }
    assert!(handler.connections[0].recovery.in_recovery);

    // Partial ACK — advances snd_una by 1 MSS but doesn't reach recovery_point.
    let partial_ack_seq = snd_una.wrapping_add(mss as u32);
    let partial = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        partial_ack_seq,
        flags::ACK,
        65535,
        &[],
    );
    let partial_len = partial.len();
    handler.process_ipv4(
        Frame::new(20, leak(partial), partial_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert!(
        handler.connections[0].recovery.in_recovery,
        "should still be in recovery after partial ACK"
    );
    assert_eq!(handler.connections[0].snd_una, partial_ack_seq);
}

