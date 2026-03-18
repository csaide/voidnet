use super::*;

#[test]
fn nagle_holds_small_data_when_bytes_in_flight() {
    let mut wheel = new_wheel();
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    // 1. Complete handshake via active open.
    let _iss = active_open_handshake(&mut handler, &mut wheel, &nh, &mut free, &mut rx, &mut tx);

    // 2. Write small data.
    handler.first_connection_mut().send_buffer.write(b"hello");

    // 3. poll_send — first send goes (nothing in flight).
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
    assert_eq!(tx.num_frames(), 1, "first small segment should send");

    // 4. Pop tx frame.
    while tx.pop().is_some() {}

    // 5. Write more small data — bytes still in flight (unACKed).
    handler.first_connection_mut().send_buffer.write(b"world");

    // 6. poll_send — Nagle holds it.
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
        0,
        "Nagle should hold small data when bytes in flight"
    );
}

#[test]
fn nagle_allows_full_mss_even_with_bytes_in_flight() {
    let mut wheel = new_wheel();
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    // Allocate frames large enough for MSS-sized segments (ETH+IP+TCP+536 = 590).
    for i in 0..16 {
        free.push(Frame::new(100 + i, leak(vec![0u8; 1024]), 1024, false));
    }

    // 1. Complete handshake via active open.
    let _iss = active_open_handshake(&mut handler, &mut wheel, &nh, &mut free, &mut rx, &mut tx);

    // 2. Write small data, send it (creates bytes_in_flight), pop tx.
    handler.first_connection_mut().send_buffer.write(b"hi");
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
    while tx.pop().is_some() {}

    // 3. Write MSS-worth of data.
    let mss = handler.first_connection().eff_snd_mss as usize;
    let mss_data = vec![0xAA; mss];
    handler.first_connection_mut().send_buffer.write(&mss_data);

    // 4. poll_send — full MSS always sends even with bytes in flight.
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
        "full MSS segment should send even with bytes in flight"
    );
}

#[test]
fn tcp_no_delay_sends_small_data_immediately() {
    let mut wheel = new_wheel();
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);

    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    // 1. Complete handshake with tcp_no_delay.
    let config = TcpConfig {
        tcp_no_delay: true,
        ..Default::default()
    };
    let _iss = active_open_handshake_with_config(
        &mut handler,
        &mut wheel,
        &nh,
        config,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Verify nagle is disabled.
    assert!(
        !handler.first_connection().nagle_enabled,
        "nagle should be disabled with tcp_no_delay"
    );

    // 2. Write small data, poll_send (first send), pop tx.
    handler.first_connection_mut().send_buffer.write(b"hello");
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
    assert_eq!(tx.num_frames(), 1);
    while tx.pop().is_some() {}

    // 3. Write more small data while first is in flight.
    handler.first_connection_mut().send_buffer.write(b"world");

    // 4. poll_send — TCP_NODELAY bypasses Nagle.
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
        "TCP_NODELAY should bypass Nagle and send immediately"
    );
}
