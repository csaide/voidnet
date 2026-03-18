use super::super::timer_kinds::{TcpTimerKind, tcp_timer_id};
use super::*;

#[test]
fn persist_timer_activates_on_zero_window() {
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

    // Write data into send buffer, but set window to 0.
    handler.first_connection_mut().send_buffer.write(b"Hello");
    handler.first_connection_mut().snd_wnd = 0;

    let key = handler.first_connection_key();
    assert!(!handler.timer_handles[key].is_armed(TcpTimerKind::Persist));

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

    // Persist timer should now be armed.
    assert!(
        handler.timer_handles[key].is_armed(TcpTimerKind::Persist),
        "persist timer should be armed when window=0 and data available"
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
    let mut wheel = new_wheel();
    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let server_iss =
        establish_connection(&mut handler, &mut wheel, &nh, &mut free, &mut rx, &mut tx);

    // Write data, set window to 0.
    handler.first_connection_mut().send_buffer.write(b"Hello");
    handler.first_connection_mut().snd_wnd = 0;

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
    let key = handler.first_connection_key();
    assert!(handler.timer_handles[key].is_armed(TcpTimerKind::Persist));
    assert_eq!(handler.first_connection().persist_backoff, 0);

    // Simulate time passing beyond the deadline by arming persist at tick 0.
    let handle = wheel.arm(
        tcp_timer_id(key, TcpTimerKind::Persist),
        coarsetime::Instant::now(),
    );
    handler.timer_handles[key].set(TcpTimerKind::Persist, handle);

    // Fire the persist timer via poll_timers, then let poll_send handle the probe.
    poll_timers(
        &mut handler,
        &mut wheel,
        now,
        nh.local_mac(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

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
    // persist timer should be rescheduled.
    assert!(handler.timer_handles[key].is_armed(TcpTimerKind::Persist));
}

#[test]
fn persist_timer_clears_when_window_reopens() {
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

    // Write data, set window to 0, arm persist timer.
    handler.first_connection_mut().send_buffer.write(b"Hello");
    handler.first_connection_mut().snd_wnd = 0;

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
    let key = handler.first_connection_key();
    assert!(handler.timer_handles[key].is_armed(TcpTimerKind::Persist));
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
        &mut wheel,
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Persist timer should be cleared.
    assert!(
        !handler.timer_handles[key].is_armed(TcpTimerKind::Persist),
        "persist timer should be cleared when window reopens"
    );
    assert_eq!(
        handler.first_connection().persist_backoff,
        0,
        "persist_backoff should be reset"
    );
}

#[test]
fn persist_backoff_caps_at_six() {
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

    // Write enough data to sustain many probes (each probe sends 1 byte).
    handler
        .first_connection_mut()
        .send_buffer
        .write(&[0x41u8; 20]);
    handler.first_connection_mut().snd_wnd = 0;

    let now = coarsetime::Instant::now();
    let key = handler.first_connection_key();

    // Arm the persist timer.
    handler.poll_send(
        now,
        &mut wheel,
        nh.local_mac(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert!(handler.timer_handles[key].is_armed(TcpTimerKind::Persist));
    assert_eq!(handler.first_connection().persist_backoff, 0);

    // Fire the persist probe multiple times (more than 6) by arming at tick 0.
    for i in 0..10 {
        let handle = wheel.arm(
            tcp_timer_id(key, TcpTimerKind::Persist),
            coarsetime::Instant::now(),
        );
        handler.timer_handles[key].set(TcpTimerKind::Persist, handle);
        poll_timers(
            &mut handler,
            &mut wheel,
            now,
            nh.local_mac(),
            &nh,
            &mut free,
            &mut rx,
            &mut tx,
        );
        while tx.pop().is_some() {}

        let expected = (i + 1).min(6);
        assert_eq!(
            handler.first_connection().persist_backoff,
            expected,
            "persist_backoff should be {} after {} probes",
            expected,
            i + 1
        );
    }

    // Final check: backoff must be capped at exactly 6.
    assert_eq!(
        handler.first_connection().persist_backoff,
        6,
        "persist_backoff must be capped at 6"
    );
}
