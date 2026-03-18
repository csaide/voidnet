use super::super::timer_kinds::{TcpTimerKind, tcp_timer_id};
use super::*;

#[test]
fn unmatched_syn_generates_rst() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(4);
    let mut rx = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(4);
    let mut wheel = new_wheel();

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

    handler.process_ipv4(
        frame,
        coarsetime::Instant::now(),
        &mut wheel,
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

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
    let mut wheel = new_wheel();

    let data = build_tcp_frame(REMOTE_IP, LOCAL_IP, 12345, 80, 1000, 0, flags::RST, 0, &[]);
    let len = data.len();
    let frame = Frame::new(0, leak(data), len, false);

    handler.process_ipv4(
        frame,
        coarsetime::Instant::now(),
        &mut wheel,
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

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
    let mut wheel = new_wheel();

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

    handler.process_ipv4(
        frame,
        coarsetime::Instant::now(),
        &mut wheel,
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

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
    let mut wheel = new_wheel();

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

    handler.process_ipv4(
        frame,
        coarsetime::Instant::now(),
        &mut wheel,
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

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
    let mut wheel = new_wheel();

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

    handler.process_ipv4(
        frame,
        coarsetime::Instant::now(),
        &mut wheel,
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

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
    let mut wheel = new_wheel();
    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let server_iss =
        establish_connection(&mut handler, &mut wheel, &nh, &mut free, &mut rx, &mut tx);

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
        coarsetime::Instant::now(),
        &mut wheel,
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
    assert_eq!(handler.first_connection().state, TcpState::Established);
}

#[test]
fn rst_in_window_but_not_exact_sends_challenge_ack() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    let mut wheel = new_wheel();
    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let server_iss =
        establish_connection(&mut handler, &mut wheel, &nh, &mut free, &mut rx, &mut tx);

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
        coarsetime::Instant::now(),
        &mut wheel,
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
    assert_eq!(handler.first_connection().state, TcpState::Established);

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
    let mut wheel = new_wheel();
    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let server_iss =
        establish_connection(&mut handler, &mut wheel, &nh, &mut free, &mut rx, &mut tx);

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
        coarsetime::Instant::now(),
        &mut wheel,
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
    assert_eq!(handler.first_connection().state, TcpState::Established);

    // (2) A challenge ACK should have been sent.
    assert!(
        tx.num_frames() > 0,
        "challenge ACK should be sent for SYN in Established (RFC 5961)"
    );

    // (3) No data should have been processed (rcv_nxt unchanged).
    assert_eq!(
        handler.first_connection().rcv_nxt,
        1001,
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
    let mut wheel = new_wheel();
    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let server_iss =
        establish_connection(&mut handler, &mut wheel, &nh, &mut free, &mut rx, &mut tx);

    let rcv_nxt_before = handler.first_connection().rcv_nxt;

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
        coarsetime::Instant::now(),
        &mut wheel,
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // (1) No data should be written to recv_buffer (rcv_nxt unchanged).
    assert_eq!(
        handler.first_connection().rcv_nxt,
        rcv_nxt_before,
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
    let mut wheel = new_wheel();
    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let server_iss =
        establish_connection(&mut handler, &mut wheel, &nh, &mut free, &mut rx, &mut tx);

    let snd_una_before = handler.first_connection().snd_una;
    let snd_nxt_before = handler.first_connection().snd_nxt;
    let rcv_nxt_before = handler.first_connection().rcv_nxt;

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
        coarsetime::Instant::now(),
        &mut wheel,
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
    assert_eq!(handler.first_connection().state, TcpState::Established);

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
        handler.first_connection().snd_una,
        snd_una_before,
        "snd_una must not change on future ACK"
    );
    assert_eq!(
        handler.first_connection().snd_nxt,
        snd_nxt_before,
        "snd_nxt must not change on future ACK"
    );
    assert_eq!(
        handler.first_connection().rcv_nxt,
        rcv_nxt_before,
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
    let mut wheel = new_wheel();
    for i in 0..6 {
        free.push(alloc_free_frame(100 + i));
    }

    let server_iss =
        establish_connection(&mut handler, &mut wheel, &nh, &mut free, &mut rx, &mut tx);
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
        coarsetime::Instant::now(),
        &mut wheel,
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    while rx.pop().is_some() {}
    while tx.pop().is_some() {}

    assert_eq!(
        handler.first_connection().snd_wnd,
        8000,
        "window set to 8000 from seg B"
    );
    assert_eq!(
        handler.first_connection().snd_wl1,
        1002,
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
        coarsetime::Instant::now(),
        &mut wheel,
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    while rx.pop().is_some() {}
    while tx.pop().is_some() {}

    assert_eq!(
        handler.first_connection().snd_wnd,
        8000,
        "stale segment must not regress snd_wnd"
    );
    assert_eq!(
        handler.first_connection().snd_wl1,
        1002,
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
    let mut wheel = new_wheel();

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
        &mut wheel,
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
        &mut wheel,
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    while tx.pop().is_some() {}

    let mss = handler.first_connection().eff_snd_mss;

    // Set max_snd_wnd high (simulates the peer previously advertised a large window).
    handler.first_connection_mut().max_snd_wnd = 65535;
    // Set current snd_wnd to 10 bytes — much less than MSS and max_snd_wnd/2.
    handler.first_connection_mut().snd_wnd = 10;

    // Write more data than can_send (10 bytes) so data_available > can_send.
    handler
        .first_connection_mut()
        .send_buffer
        .write(&[0x41u8; 100]);

    let now = coarsetime::Instant::now();
    handler.poll_send(
        now,
        &mut wheel,
        nh.local_mac(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // SWS check: can_send=10, eff_snd_mss=1460, max_snd_wnd/2=32767, data_available=100.
    // 10 < 1460 (not full MSS), 10 < 32767 (not half max window), 100 > 10 (not all data fits).
    // sws_ok = false → no send.
    assert_eq!(
        tx.num_frames(),
        0,
        "sender SWS should hold: window too small"
    );

    // Now set snd_wnd to eff_snd_mss — should send.
    handler.first_connection_mut().snd_wnd = mss as u32;
    handler.poll_send(
        now,
        &mut wheel,
        nh.local_mac(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(
        tx.num_frames(),
        1,
        "should send when can_send >= eff_snd_mss"
    );
}

#[test]
fn handshake_with_wrapping_isn() {
    // Verify that a 3-way handshake completes correctly when the client ISN is
    // near u32::MAX so that rcv_nxt wraps around the 2^32 boundary.
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(8);
    let mut rx = BasicFrameBuffer::new(8);
    let mut tx = BasicFrameBuffer::new(8);
    let mut wheel = new_wheel();

    for i in 0..4 {
        free.push(alloc_free_frame(100 + i));
    }

    let accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();

    // Client ISN chosen so that ISN + 1 = u32::MAX (one step before wrapping to 0).
    let client_isn: u32 = u32::MAX - 1;

    // Step 1: SYN with wrapping ISN.
    let syn_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        client_isn,
        0,
        flags::SYN,
        65535,
        &[],
    );
    let syn_len = syn_data.len();
    handler.process_ipv4(
        Frame::new(0, leak(syn_data), syn_len, false),
        coarsetime::Instant::now(),
        &mut wheel,
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Handler must have created a connection in SynReceived and sent a SYN-ACK.
    assert_eq!(handler.connections.len(), 1, "connection created");
    assert_eq!(handler.first_connection().state, TcpState::SynReceived);
    assert_eq!(tx.num_frames(), 1, "SYN-ACK generated");

    // Inspect the SYN-ACK: ack_num must wrap (ISN + 1 mod 2^32 = 0).
    let expected_ack = client_isn.wrapping_add(1); // == 0
    let syn_ack_frame = tx.pop().unwrap();
    let tcp_off = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
    let syn_ack_ack_num =
        u32::from_be_bytes(syn_ack_frame[tcp_off + 8..tcp_off + 12].try_into().unwrap());
    assert_eq!(
        syn_ack_ack_num, expected_ack,
        "SYN-ACK ack_number must wrap correctly (expected {})",
        expected_ack
    );
    let syn_ack_flags = syn_ack_frame[tcp_off + 13];
    assert_eq!(
        syn_ack_flags & (flags::SYN | flags::ACK),
        flags::SYN | flags::ACK,
        "SYN-ACK must have SYN and ACK flags set"
    );

    // Step 2: Complete the handshake with the final ACK.
    let server_iss = handler.first_connection().iss;
    let ack_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        client_isn.wrapping_add(1), // == 0
        server_iss.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
    );
    let ack_len = ack_data.len();
    handler.process_ipv4(
        Frame::new(1, leak(ack_data), ack_len, false),
        coarsetime::Instant::now(),
        &mut wheel,
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    assert_eq!(
        handler.first_connection().state,
        TcpState::Established,
        "handshake must complete to Established"
    );
    assert_eq!(
        handler.first_connection().rcv_nxt,
        client_isn.wrapping_add(1),
        "rcv_nxt must be ISN+1 (wrapped)"
    );
    assert_eq!(accept_queue.len(), 1, "connection in accept queue");
}

#[test]
fn data_transfer_across_sequence_wrap() {
    // Verify that a data segment whose sequence numbers cross the u32::MAX boundary
    // is received and ACKed correctly.
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    let mut wheel = new_wheel();

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    // Use an ISN 10 bytes before u32::MAX so that 20 bytes of data cross the wrap.
    // ISN = u32::MAX - 10 → first data seq = ISN+1 = u32::MAX - 9
    // After 20 bytes: last byte seq = (ISN+1+19) mod 2^32 = u32::MAX - 9 + 19 = 10
    let client_isn: u32 = u32::MAX - 10;

    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();

    // Manual handshake instead of establish_connection() because that helper
    // hard-codes ISN=1000 — we need a custom ISN near u32::MAX.

    // SYN.
    let syn_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        client_isn,
        0,
        flags::SYN,
        65535,
        &[],
    );
    let syn_len = syn_data.len();
    handler.process_ipv4(
        Frame::new(0, leak(syn_data), syn_len, false),
        coarsetime::Instant::now(),
        &mut wheel,
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(handler.first_connection().state, TcpState::SynReceived);
    let server_iss = handler.first_connection().iss;
    while tx.pop().is_some() {}

    // ACK completing handshake.
    let ack_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        client_isn.wrapping_add(1),
        server_iss.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
    );
    let ack_len = ack_data.len();
    handler.process_ipv4(
        Frame::new(1, leak(ack_data), ack_len, false),
        coarsetime::Instant::now(),
        &mut wheel,
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(handler.first_connection().state, TcpState::Established);
    while tx.pop().is_some() {}

    // Send 20 bytes of data starting at seq = client_isn + 1.
    // This crosses the u32::MAX boundary (10 bytes before wrap, 10 bytes after).
    let payload = [0x42u8; 20];
    let data_seq = client_isn.wrapping_add(1);
    let data_frame = build_tcp_frame_with_payload(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        data_seq,
        server_iss.wrapping_add(1),
        flags::ACK | flags::PSH,
        65535,
        &[],
        &payload,
    );
    let data_len = data_frame.len();
    handler.process_ipv4(
        Frame::new(2, leak(data_frame), data_len, false),
        coarsetime::Instant::now(),
        &mut wheel,
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // rcv_nxt must have advanced by 20 bytes (wrapping).
    let expected_rcv_nxt = data_seq.wrapping_add(20);
    assert_eq!(
        handler.first_connection().rcv_nxt,
        expected_rcv_nxt,
        "rcv_nxt must advance past wrap boundary"
    );

    // Flush delayed ACK: send a second data segment (triggers ack_pending),
    // then call poll_send to emit the pure ACK.
    let payload2 = [0x43u8; 1];
    let data2_seq = expected_rcv_nxt;
    let data_frame2 = build_tcp_frame_with_payload(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        data2_seq,
        server_iss.wrapping_add(1),
        flags::ACK | flags::PSH,
        65535,
        &[],
        &payload2,
    );
    let data2_len = data_frame2.len();
    handler.process_ipv4(
        Frame::new(3, leak(data_frame2), data2_len, false),
        coarsetime::Instant::now(),
        &mut wheel,
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // poll_send flushes the pending delayed ACK.
    handler.poll_send(
        coarsetime::Instant::now(),
        &mut wheel,
        nh.local_mac(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // An ACK must have been sent.
    assert!(
        tx.num_frames() > 0,
        "ACK must be sent after poll_send flushes delayed ACK"
    );

    // The ACK frame's ack_num must equal rcv_nxt after both segments.
    let ack_frame = tx.pop().unwrap();
    let tcp_off = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
    let ack_num = u32::from_be_bytes(ack_frame[tcp_off + 8..tcp_off + 12].try_into().unwrap());
    let expected_final_rcv_nxt = expected_rcv_nxt.wrapping_add(1);
    assert_eq!(
        ack_num, expected_final_rcv_nxt,
        "ACK ack_num must reflect all received data ({})",
        expected_final_rcv_nxt
    );
    assert_eq!(
        handler.first_connection().rcv_nxt,
        expected_final_rcv_nxt,
        "rcv_nxt must reflect all received data after wrap"
    );
}

#[test]
fn remove_connection_sends_rst_with_correct_seq() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    let mut wheel = new_wheel();

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let server_iss =
        establish_connection(&mut handler, &mut wheel, &nh, &mut free, &mut rx, &mut tx);

    // snd_nxt after handshake = server_iss + 1 (SYN consumed one sequence number).
    let expected_seq = server_iss.wrapping_add(1);

    // Capture the connection id before calling remove_connection.
    let id = handler.first_connection().id;

    // MAC addresses matching what the test infrastructure uses.
    let src_mac =
        crate::net::wire::ethernet::MacAddress::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    let dst_mac =
        crate::net::wire::ethernet::MacAddress::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

    handler.remove_connection(&id, src_mac, dst_mac, &mut free, &mut tx);

    // The connection should be removed.
    assert_eq!(handler.connections.len(), 0, "connection removed");

    // A RST frame should have been emitted.
    assert_eq!(
        tx.num_frames(),
        1,
        "RST frame generated on remove_connection"
    );

    // Parse the RST frame and check its sequence number.
    let rst_frame = tx.pop().unwrap();
    let tcp_off = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN;
    let rst_seq = u32::from_be_bytes(rst_frame[tcp_off + 4..tcp_off + 8].try_into().unwrap());
    let rst_flags = rst_frame[tcp_off + 13];

    assert_eq!(
        rst_flags & flags::RST,
        flags::RST,
        "frame must have RST flag set"
    );
    assert_ne!(
        rst_seq, 0,
        "RST sequence number must not be 0 (would be silently dropped by peer)"
    );
    assert_eq!(
        rst_seq, expected_seq,
        "RST seq must equal snd_nxt = server_iss + 1 = {}",
        expected_seq
    );
}

#[test]
fn rst_exact_match_resets_connection() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    let mut wheel = new_wheel();
    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let server_iss =
        establish_connection(&mut handler, &mut wheel, &nh, &mut free, &mut rx, &mut tx);

    // rcv_nxt is 1001. Send RST with seq = 1001 (exact match).
    let rst_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001, // == rcv_nxt (exact match)
        server_iss.wrapping_add(1),
        flags::RST | flags::ACK,
        0,
        &[],
    );
    let rst_len = rst_data.len();
    handler.process_ipv4(
        Frame::new(50, leak(rst_data), rst_len, false),
        coarsetime::Instant::now(),
        &mut wheel,
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Connection must be removed — exact-match RST resets the connection.
    assert_eq!(
        handler.connections.len(),
        0,
        "exact-match RST must reset and remove the connection"
    );
}

#[test]
fn duplicate_data_sends_ack() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    let mut wheel = new_wheel();
    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let server_iss =
        establish_connection(&mut handler, &mut wheel, &nh, &mut free, &mut rx, &mut tx);

    // Send data to advance rcv_nxt.
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
        &mut wheel,
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    while tx.pop().is_some() {}
    assert_eq!(handler.first_connection().rcv_nxt, 1006);

    // Now send duplicate data with seg_seq < rcv_nxt (already received).
    let dup_data = build_tcp_frame_with_payload(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001, // < rcv_nxt (1006)
        server_iss.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
        b"hello",
    );
    let dup_len = dup_data.len();
    handler.process_ipv4(
        Frame::new(3, leak(dup_data), dup_len, false),
        coarsetime::Instant::now(),
        &mut wheel,
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Should respond with an ACK for duplicate data.
    assert!(
        tx.num_frames() > 0,
        "duplicate data (seg_seq < rcv_nxt) should trigger ACK"
    );
    // rcv_nxt must not change.
    assert_eq!(
        handler.first_connection().rcv_nxt,
        1006,
        "rcv_nxt must not change for duplicate data"
    );
}

#[test]
fn out_of_window_non_rst_sends_ack() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    let mut wheel = new_wheel();
    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let server_iss =
        establish_connection(&mut handler, &mut wheel, &nh, &mut free, &mut rx, &mut tx);

    // Send a data segment with seq far outside the window (not RST).
    let oow_data = build_tcp_frame_with_payload(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        999_999, // way outside window
        server_iss.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
        b"oow",
    );
    let oow_len = oow_data.len();
    handler.process_ipv4(
        Frame::new(50, leak(oow_data), oow_len, false),
        coarsetime::Instant::now(),
        &mut wheel,
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Should respond with an ACK (not silently dropped like RST).
    assert!(
        tx.num_frames() > 0,
        "out-of-window non-RST segment should trigger ACK"
    );
    // Connection must survive.
    assert_eq!(handler.first_connection().state, TcpState::Established);
}

#[test]
fn recovery_exit_on_full_ack() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(64);
    let mut rx = BasicFrameBuffer::new(64);
    let mut tx = BasicFrameBuffer::new(64);
    let mut wheel = new_wheel();
    for i in 0..32 {
        free.push(alloc_free_frame(100 + i));
    }

    let _server_iss =
        establish_connection(&mut handler, &mut wheel, &nh, &mut free, &mut rx, &mut tx);

    let tcb = handler.first_connection_mut();
    tcb.eff_snd_mss = 100;
    let mss = tcb.eff_snd_mss as usize;

    // Write 4 MSS of data and simulate 4 segments sent.
    let data_len = 4 * mss;
    tcb.send_buffer.write(&vec![0xAA; data_len]);
    tcb.snd_wnd = 65535;
    tcb.snd_nxt = tcb.snd_una.wrapping_add(data_len as u32);
    let snd_una = tcb.snd_una;
    let recovery_point = tcb.snd_nxt;

    // Enter recovery.
    tcb.recovery.enter(recovery_point);
    tcb.prr.enter(recovery_point.wrapping_sub(snd_una));
    tcb.cubic.on_loss();
    assert!(handler.first_connection().recovery.in_recovery);

    // Send a full ACK that covers the recovery_point.
    let full_ack = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        recovery_point, // ACK up to recovery_point
        flags::ACK,
        65535,
        &[],
    );
    let full_ack_len = full_ack.len();
    handler.process_ipv4(
        Frame::new(20, leak(full_ack), full_ack_len, false),
        coarsetime::Instant::now(),
        &mut wheel,
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Recovery should have exited.
    assert!(
        !handler.first_connection().recovery.in_recovery,
        "full ACK covering recovery_point should exit recovery"
    );
}

#[test]
fn persist_timer_cleared_on_new_ack_with_window() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    let mut wheel = new_wheel();
    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let _server_iss =
        establish_connection(&mut handler, &mut wheel, &nh, &mut free, &mut rx, &mut tx);

    // Set up: send some data so snd_nxt > snd_una, then arm persist timer.
    let key = handler.first_connection_key();
    let tcb = handler.first_connection_mut();
    tcb.send_buffer.write(&[0u8; 100]);
    tcb.snd_nxt = tcb.snd_una.wrapping_add(100);
    tcb.persist_backoff = 3;
    let snd_una = tcb.snd_una;
    // Arm persist timer.
    let handle = wheel.arm(tcp_timer_id(key, TcpTimerKind::Persist), 0);
    handler.timer_handles[key].set(TcpTimerKind::Persist, handle);

    // Send a new ACK that advances snd_una, with a non-zero window.
    let new_ack = snd_una.wrapping_add(50);
    let ack_frame = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        new_ack,
        flags::ACK,
        65535, // non-zero window
        &[],
    );
    let ack_len = ack_frame.len();
    handler.process_ipv4(
        Frame::new(5, leak(ack_frame), ack_len, false),
        coarsetime::Instant::now(),
        &mut wheel,
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    let tcb = handler.first_connection();
    assert_eq!(tcb.snd_una, new_ack, "snd_una should advance");
    assert!(
        !handler.timer_handles[key].is_armed(TcpTimerKind::Persist),
        "persist timer should be cleared when window reopens on new ACK"
    );
    assert_eq!(tcb.persist_backoff, 0, "persist backoff should be reset");
}

#[test]
fn rtt_update_with_existing_srtt_slow_path() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    let mut wheel = new_wheel();
    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let _server_iss =
        establish_connection(&mut handler, &mut wheel, &nh, &mut free, &mut rx, &mut tx);

    // Set up: some data in flight, with an existing SRTT.
    let tcb = handler.first_connection_mut();
    tcb.send_buffer.write(&[0u8; 100]);
    tcb.snd_nxt = tcb.snd_una.wrapping_add(100);
    tcb.srtt = Some(50); // existing SRTT of 50ms
    tcb.rttvar = 25;
    tcb.last_send_time = Some(coarsetime::Instant::now());
    let snd_una = tcb.snd_una;

    // Send a new ACK to trigger RTT update with existing SRTT.
    let new_ack = snd_una.wrapping_add(50);
    let ack_frame = build_tcp_frame(
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
    let ack_len = ack_frame.len();
    handler.process_ipv4(
        Frame::new(5, leak(ack_frame), ack_len, false),
        coarsetime::Instant::now(),
        &mut wheel,
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    let tcb = handler.first_connection();
    // SRTT should have been updated (from the existing 50ms).
    assert!(tcb.srtt.is_some(), "SRTT should still be set");
    // last_send_time should be consumed.
    assert!(
        tcb.last_send_time.is_none(),
        "last_send_time should be consumed after RTT measurement"
    );
}

#[test]
fn sender_sws_allows_send_when_all_data_fits() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    let mut wheel = new_wheel();

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
        &mut wheel,
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
        &mut wheel,
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    while tx.pop().is_some() {}

    // Set max_snd_wnd high, snd_wnd to 5 bytes (small window).
    handler.first_connection_mut().max_snd_wnd = 65535;
    handler.first_connection_mut().snd_wnd = 5;

    // Write only 3 bytes — all data fits in the window.
    handler.first_connection_mut().send_buffer.write(b"abc");

    let now = coarsetime::Instant::now();
    handler.poll_send(
        now,
        &mut wheel,
        nh.local_mac(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // SWS: can_send=5, data_available=3, 3 <= 5 → all data fits → sws_ok = true.
    assert_eq!(
        tx.num_frames(),
        1,
        "should send when all data fits in window"
    );
}
