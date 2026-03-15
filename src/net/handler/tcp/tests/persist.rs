use super::*;

#[test]
fn persist_timer_activates_on_zero_window() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let _server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    // Write data into send buffer, but set window to 0.
    handler.first_connection_mut().send_buffer.write(b"Hello");
    handler.first_connection_mut().snd_wnd = 0;

    assert!(handler.first_connection().persist_deadline.is_none());

    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);

    // Persist timer should now be armed.
    assert!(
        handler.first_connection().persist_deadline.is_some(),
        "persist_deadline should be set when window=0 and data available"
    );
    // No data segment should have been sent (deadline not yet reached).
    assert_eq!(tx.num_frames(), 0, "no segment sent before deadline");
}

#[test]
fn persist_probe_sent_when_deadline_expires() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    // Write data, set window to 0.
    handler.first_connection_mut().send_buffer.write(b"Hello");
    handler.first_connection_mut().snd_wnd = 0;

    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    assert!(handler.first_connection().persist_deadline.is_some());
    assert_eq!(handler.first_connection().persist_backoff, 0);

    // Simulate time passing beyond the deadline by setting it to the past.
    handler.first_connection_mut().persist_deadline = Some(now);

    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);

    // A 1-byte probe should have been sent.
    assert_eq!(tx.num_frames(), 1, "probe segment should be sent");
    // snd_nxt should advance by 1.
    assert_eq!(
        handler.first_connection().snd_nxt,
        server_iss.wrapping_add(1).wrapping_add(1),
        "snd_nxt advanced by 1 for probe"
    );
    // persist_backoff should have incremented.
    assert_eq!(handler.first_connection().persist_backoff, 1);
    // persist_deadline should be rescheduled (not None).
    assert!(handler.first_connection().persist_deadline.is_some());
}

#[test]
fn persist_timer_clears_when_window_reopens() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    // Write data, set window to 0, arm persist timer.
    handler.first_connection_mut().send_buffer.write(b"Hello");
    handler.first_connection_mut().snd_wnd = 0;

    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);
    assert!(handler.first_connection().persist_deadline.is_some());
    handler.first_connection_mut().persist_backoff = 3; // simulate some backoff

    // Peer sends ACK with non-zero window, reopening it.
    let ack_data = build_tcp_frame(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        server_iss.wrapping_add(1),
        flags::ACK,
        32000, // non-zero window
        &[],
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

    // Persist timer should be cleared.
    assert!(
        handler.first_connection().persist_deadline.is_none(),
        "persist_deadline should be cleared when window reopens"
    );
    assert_eq!(
        handler.first_connection().persist_backoff,
        0,
        "persist_backoff should be reset"
    );
}
