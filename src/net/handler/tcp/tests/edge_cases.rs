use super::*;

#[test]
fn unmatched_syn_generates_rst() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(4);
    let mut rx = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(4);

    free.push(alloc_free_frame(100));

    let data = build_tcp_frame(
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
    let len = data.len();
    let frame = Frame::new(0, leak(data), len, false);

    handler.process_ipv4(frame, &nh, &mut free, &mut rx, &mut tx);

    assert_eq!(rx.num_frames(), 1, "original frame returned to rx");
    assert_eq!(tx.num_frames(), 1, "RST generated on tx");
    assert_eq!(free.num_frames(), 0, "free frame consumed");
}

#[test]
fn rst_to_unbound_port_silently_dropped() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(4);
    let mut rx = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(4);

    let data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1000, 0, flags::RST, 0, &[]);
    let len = data.len();
    let frame = Frame::new(0, leak(data), len, false);

    handler.process_ipv4(frame, &nh, &mut free, &mut rx, &mut tx);

    assert_eq!(rx.num_frames(), 1, "frame returned to rx");
    assert_eq!(tx.num_frames(), 0, "no RST for RST");
}

#[test]
fn invalid_checksum_dropped() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(4);
    let mut rx = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(4);

    let data = build_tcp_frame(
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
    // Corrupt checksum.
    let tcp_off = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
    let leaked = leak(data);
    leaked[tcp_off + 16] ^= 0xFF;
    let len = leaked.len();
    let frame = Frame::new(0, leaked, len, false);

    handler.process_ipv4(frame, &nh, &mut free, &mut rx, &mut tx);

    assert_eq!(rx.num_frames(), 1, "frame returned to rx");
    assert_eq!(tx.num_frames(), 0, "no RST for bad checksum");
}

#[test]
fn truncated_tcp_header_dropped() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(4);
    let mut rx = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(4);

    // Build a frame that's too short for a TCP header.
    let mut data = vec![0u8; ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + 10]; // only 10 bytes of TCP
    data[12] = 0x08;
    data[13] = 0x00;
    data[ETH_HEADER_LEN] = 0x45;
    let total = (IPV4_MIN_HEADER_LEN + 10) as u16;
    data[ETH_HEADER_LEN + 2..ETH_HEADER_LEN + 4].copy_from_slice(&total.to_be_bytes());
    data[ETH_HEADER_LEN + 8] = 64;
    data[ETH_HEADER_LEN + 9] = IpProtocols::Tcp;
    let src_bytes: [u8; 4] = REMOTE_IP.into();
    data[ETH_HEADER_LEN + 12..ETH_HEADER_LEN + 16].copy_from_slice(&src_bytes);
    let dst_bytes: [u8; 4] = LOCAL_IP.into();
    data[ETH_HEADER_LEN + 16..ETH_HEADER_LEN + 20].copy_from_slice(&dst_bytes);
    let cksum = compute_ipv4_checksum(&data[ETH_HEADER_LEN..ETH_HEADER_LEN + 20]);
    data[ETH_HEADER_LEN + 10] = cksum[0];
    data[ETH_HEADER_LEN + 11] = cksum[1];

    let len = data.len();
    let frame = Frame::new(0, leak(data), len, false);

    handler.process_ipv4(frame, &nh, &mut free, &mut rx, &mut tx);

    assert_eq!(rx.num_frames(), 1, "truncated frame returned to rx");
    assert_eq!(tx.num_frames(), 0, "no response");
}

#[test]
fn frame_accounting_after_rst() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(4);
    let mut rx = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(4);

    free.push(alloc_free_frame(100));

    let data = build_tcp_frame(
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
    let len = data.len();
    let frame = Frame::new(0, leak(data), len, false);

    handler.process_ipv4(frame, &nh, &mut free, &mut rx, &mut tx);

    let total = free.num_frames() + rx.num_frames() + tx.num_frames();
    assert_eq!(total, 2, "all frames accounted for (1 rx + 1 tx)");
}

#[test]
fn rst_outside_window_is_dropped() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    // rcv_nxt is 1001, window is 65535 → valid range [1001, 66536).
    // Send RST with seq far outside the window.
    let rst_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        999_999, // way outside window
        server_iss.wrapping_add(1),
        flags::RST | flags::ACK,
        0,
        &[],
    );
    let rst_len = rst_data.len();
    handler.process_ipv4(
        Frame::new(50, leak(rst_data), rst_len, false),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Connection must survive — out-of-window RST should be silently dropped.
    assert_eq!(
        handler.connections.len(),
        1,
        "out-of-window RST must not reset the connection"
    );
    assert_eq!(handler.connections[0].state, TcpState::Established);
}

#[test]
fn rst_in_window_but_not_exact_sends_challenge_ack() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    // rcv_nxt is 1001. Send RST with seq = 1005 (in-window but not exact).
    let rst_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1005, // in-window but != rcv_nxt (1001)
        server_iss.wrapping_add(1),
        flags::RST | flags::ACK,
        0,
        &[],
    );
    let rst_len = rst_data.len();
    handler.process_ipv4(
        Frame::new(50, leak(rst_data), rst_len, false),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Connection must survive — in-window non-exact RST triggers challenge ACK.
    assert_eq!(
        handler.connections.len(),
        1,
        "in-window non-exact RST must not reset the connection"
    );
    assert_eq!(handler.connections[0].state, TcpState::Established);

    // A challenge ACK should have been sent.
    assert!(
        tx.num_frames() > 0,
        "challenge ACK should be sent for in-window non-exact RST"
    );
}

#[test]
fn syn_in_established_sends_challenge_ack() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    // Send a SYN segment to the established connection.
    let syn_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001, // seq = rcv_nxt (in-window)
        server_iss.wrapping_add(1),
        flags::SYN | flags::ACK,
        65535,
        &[],
    );
    let syn_len = syn_data.len();
    handler.process_ipv4(
        Frame::new(50, leak(syn_data), syn_len, false),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // (1) Connection must NOT be reset — it should still be Established.
    assert_eq!(
        handler.connections.len(),
        1,
        "SYN in Established must not destroy the connection"
    );
    assert_eq!(handler.connections[0].state, TcpState::Established);

    // (2) A challenge ACK should have been sent.
    assert!(
        tx.num_frames() > 0,
        "challenge ACK should be sent for SYN in Established (RFC 5961)"
    );

    // (3) No data should have been processed (rcv_nxt unchanged).
    assert_eq!(
        handler.connections[0].rcv_nxt, 1001,
        "rcv_nxt must not advance when SYN is received in Established"
    );
}

#[test]
fn segment_without_ack_is_dropped() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    let rcv_nxt_before = handler.connections[0].rcv_nxt;

    // Send a data segment with no flags set (ACK bit off).
    let no_ack_data = build_tcp_frame_with_payload(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001, // seq = rcv_nxt
        server_iss.wrapping_add(1),
        0, // no flags at all
        65535,
        &[],
        b"hello",
    );
    let no_ack_len = no_ack_data.len();
    handler.process_ipv4(
        Frame::new(50, leak(no_ack_data), no_ack_len, false),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // (1) No data should be written to recv_buffer (rcv_nxt unchanged).
    assert_eq!(
        handler.connections[0].rcv_nxt, rcv_nxt_before,
        "rcv_nxt must not advance for segment without ACK"
    );

    // (2) No response should be sent (tx empty).
    assert_eq!(
        tx.num_frames(),
        0,
        "no response should be sent for segment without ACK"
    );
}

#[test]
fn ack_beyond_snd_nxt_sends_ack_and_drops() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    let snd_una_before = handler.connections[0].snd_una;
    let snd_nxt_before = handler.connections[0].snd_nxt;
    let rcv_nxt_before = handler.connections[0].rcv_nxt;

    // Send a segment with seg_ack far beyond snd_nxt.
    let bad_ack = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,                                            // seq = rcv_nxt (in-window)
        server_iss.wrapping_add(1).wrapping_add(999999), // ACK for unsent data
        flags::ACK,
        65535,
        &[],
    );
    let bad_ack_len = bad_ack.len();
    handler.process_ipv4(
        Frame::new(50, leak(bad_ack), bad_ack_len, false),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // (1) Connection must survive.
    assert_eq!(
        handler.connections.len(),
        1,
        "connection must not be destroyed by future ACK"
    );
    assert_eq!(handler.connections[0].state, TcpState::Established);

    // (2) An ACK must be sent in response.
    assert!(
        tx.num_frames() > 0,
        "ACK must be sent when seg_ack > snd_nxt (RFC 9293 §3.10.7.4)"
    );

    // Verify the response has ACK flags.
    let resp = tx.pop().unwrap();
    let tcp_off = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
    let tcp_flags = resp[tcp_off + 13];
    assert_eq!(
        tcp_flags & flags::ACK,
        flags::ACK,
        "response must be an ACK"
    );

    // (3) No state changes: snd_una must be unchanged.
    assert_eq!(
        handler.connections[0].snd_una, snd_una_before,
        "snd_una must not change on future ACK"
    );
    assert_eq!(
        handler.connections[0].snd_nxt, snd_nxt_before,
        "snd_nxt must not change on future ACK"
    );
    assert_eq!(
        handler.connections[0].rcv_nxt, rcv_nxt_before,
        "rcv_nxt must not change on future ACK"
    );
}

#[test]
fn stale_segment_does_not_regress_window() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(8);
    let mut rx = BasicFrameBuffer::new(8);
    let mut tx = BasicFrameBuffer::new(8);
    for i in 0..6 {
        free.push(alloc_free_frame(100 + i));
    }

    let server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);
    while rx.pop().is_some() {}

    // Segment B arrives first: higher seg_seq (1002), window = 8000.
    let seg_b = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1002,
        server_iss.wrapping_add(1),
        flags::ACK,
        8000,
        &[],
    );
    let seg_b_len = seg_b.len();
    handler.process_ipv4(
        Frame::new(10, leak(seg_b), seg_b_len, false),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    while rx.pop().is_some() {}
    while tx.pop().is_some() {}

    assert_eq!(
        handler.connections[0].snd_wnd, 8000,
        "window set to 8000 from seg B"
    );
    assert_eq!(
        handler.connections[0].snd_wl1, 1002,
        "snd_wl1 set from seg B"
    );

    // Segment A arrives late: lower seg_seq (1001), window = 4000.
    // This is stale — its window must NOT regress.
    let seg_a = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        server_iss.wrapping_add(1),
        flags::ACK,
        4000,
        &[],
    );
    let seg_a_len = seg_a.len();
    handler.process_ipv4(
        Frame::new(11, leak(seg_a), seg_a_len, false),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    while rx.pop().is_some() {}
    while tx.pop().is_some() {}

    assert_eq!(
        handler.connections[0].snd_wnd, 8000,
        "stale segment must not regress snd_wnd"
    );
    assert_eq!(
        handler.connections[0].snd_wl1, 1002,
        "stale segment must not regress snd_wl1"
    );
}

#[test]
fn sender_sws_avoidance_holds_small_sends() {
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

    let mss = handler.connections[0].eff_snd_mss;

    // Set max_snd_wnd high (simulates the peer previously advertised a large window).
    handler.connections[0].max_snd_wnd = 65535;
    // Set current snd_wnd to 10 bytes — much less than MSS and max_snd_wnd/2.
    handler.connections[0].snd_wnd = 10;

    // Write more data than can_send (10 bytes) so data_available > can_send.
    handler.connections[0].send_buffer.write(&[0x41u8; 100]);

    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);

    // SWS check: can_send=10, eff_snd_mss=1460, max_snd_wnd/2=32767, data_available=100.
    // 10 < 1460 (not full MSS), 10 < 32767 (not half max window), 100 > 10 (not all data fits).
    // sws_ok = false → no send.
    assert_eq!(
        tx.num_frames(),
        0,
        "sender SWS should hold: window too small"
    );

    // Now set snd_wnd to eff_snd_mss — should send.
    handler.connections[0].snd_wnd = mss as u32;
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);
    assert_eq!(
        tx.num_frames(),
        1,
        "should send when can_send >= eff_snd_mss"
    );
}

#[test]
fn sender_sws_allows_send_when_all_data_fits() {
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

    // Set max_snd_wnd high, snd_wnd to 5 bytes (small window).
    handler.connections[0].max_snd_wnd = 65535;
    handler.connections[0].snd_wnd = 5;

    // Write only 3 bytes — all data fits in the window.
    handler.connections[0].send_buffer.write(b"abc");

    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut tx);

    // SWS: can_send=5, data_available=3, 3 <= 5 → all data fits → sws_ok = true.
    assert_eq!(
        tx.num_frames(),
        1,
        "should send when all data fits in window"
    );
}

