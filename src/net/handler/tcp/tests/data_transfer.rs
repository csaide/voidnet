use super::*;

#[test]
fn established_receives_in_order_data() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);

    for i in 0..8 {
        free.push(alloc_free_frame(100 + i));
    }

    // Complete the handshake.
    let accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
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

    // Clear tx from handshake.
    while tx.pop().is_some() {}

    // Send first data segment (deferred by delayed ACK).
    let payload = b"Hello, TCP!";
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

    // First segment deferred — no immediate ACK.
    assert_eq!(
        tx.num_frames(),
        0,
        "ACK deferred for first in-order segment"
    );
    assert!(
        handler.first_connection().ack_pending,
        "ack_pending should be true"
    );

    // Send second data segment to flush delayed ACK.
    let payload2 = b"World!";
    let data2 = build_tcp_frame_with_payload(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001 + payload.len() as u32,
        server_iss.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
        payload2,
    );
    let data2_len = data2.len();
    handler.process_ipv4(
        Frame::new(3, leak(data2), data2_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // ACK is now deferred to poll_send for piggyback opportunity.
    assert_eq!(tx.num_frames(), 0, "ACK deferred until poll_send");
    assert!(
        handler.first_connection().ack_pending,
        "ack_pending should be true"
    );

    // poll_send generates pure ACK since no data to piggyback.
    handler.poll_send(
        coarsetime::Instant::now(),
        nh.local_mac(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(tx.num_frames(), 1, "ACK flushed by poll_send");

    // Verify: data is in the receive ring buffer.
    let tcb = handler.first_connection();
    assert_eq!(tcb.recv_buffer.available(), payload.len() + payload2.len());
    assert_eq!(
        tcb.rcv_nxt,
        1001 + payload.len() as u32 + payload2.len() as u32
    );

    drop(accept_queue);
}

#[test]
fn established_out_of_order_reassembly() {
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

    // Send segment 2 first (out of order): seq=1006, 5 bytes "world".
    let seg2 = build_tcp_frame_with_payload(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1006,
        server_iss.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
        b"world",
    );
    let seg2_len = seg2.len();
    handler.process_ipv4(
        Frame::new(2, leak(seg2), seg2_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(
        handler.first_connection().rcv_nxt, 1001,
        "rcv_nxt not advanced for OOO"
    );
    assert_eq!(handler.first_connection().ooo_ranges.len(), 1);

    // Now send segment 1 (fills the gap): seq=1001, 5 bytes "hello".
    let seg1 = build_tcp_frame_with_payload(
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
    let seg1_len = seg1.len();
    handler.process_ipv4(
        Frame::new(3, leak(seg1), seg1_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Both segments should now be contiguous.
    assert_eq!(
        handler.first_connection().rcv_nxt, 1011,
        "rcv_nxt advanced past both segments"
    );
    assert_eq!(
        handler.first_connection().ooo_ranges.len(),
        0,
        "OOO ranges drained"
    );
    assert_eq!(handler.first_connection().recv_buffer.available(), 10);

    // Read from recv buffer and verify contents.
    let mut buf = [0u8; 10];
    handler.first_connection_mut().recv_buffer.read(&mut buf);
    assert_eq!(&buf, b"helloworld");
}

#[test]
fn poll_send_builds_data_segment() {
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

    // Write data into the connection's send buffer.
    let payload = b"Hello from server!";
    handler.first_connection_mut().send_buffer.write(payload);

    // Set snd_wnd so the window allows sending.
    handler.first_connection_mut().snd_wnd = 65535;

    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);

    assert_eq!(tx.num_frames(), 1, "data segment built");
    let tcb = handler.first_connection();
    assert_eq!(
        tcb.snd_nxt,
        server_iss
            .wrapping_add(1)
            .wrapping_add(payload.len() as u32)
    );
    assert_eq!(tcb.send_buffer.available(), payload.len()); // still in buffer until ACKed
}

#[test]
fn frame_accounting_through_data_transfer() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(64);
    let mut rx = BasicFrameBuffer::new(64);
    let mut tx = BasicFrameBuffer::new(64);

    for i in 0..32 {
        free.push(alloc_free_frame(100 + i));
    }

    let initial_total = free.num_frames();

    // Handshake.
    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
    let syn = build_tcp_frame(
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
    let syn_len = syn.len();
    handler.process_ipv4(
        Frame::new(0, leak(syn), syn_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    let server_iss = handler.first_connection().iss;
    let ack = build_tcp_frame(
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
    let ack_len = ack.len();
    handler.process_ipv4(
        Frame::new(1, leak(ack), ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // Data segment 1 (ACK deferred).
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
        b"test data",
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

    // Data segment 2 (flushes delayed ACK).
    let data2 = build_tcp_frame_with_payload(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001 + 9,
        server_iss.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
        b"more data",
    );
    let data2_len = data2.len();
    handler.process_ipv4(
        Frame::new(3, leak(data2), data2_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );

    // All frames accounted for: free + rx + tx = initial + incoming frames.
    let total = free.num_frames() + rx.num_frames() + tx.num_frames();
    // We started with initial_total free frames and injected 4 incoming frames.
    assert_eq!(total, initial_total + 4, "all frames accounted for");
}

#[test]
fn poll_send_sets_psh_on_last_segment() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    for i in 0..16 {
        free.push(alloc_free_frame(100 + i));
    }

    let _server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    // Write small data (< MSS) into send buffer.
    handler.first_connection_mut().send_buffer.write(b"Hello");

    let now = coarsetime::Instant::now();
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);

    assert_eq!(tx.num_frames(), 1, "expected one data segment");
    let frame = tx.pop().unwrap();

    // TCP flags byte is at offset ETH(14) + IPv4(20) + 13 = 47.
    let tcp_flags_offset = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + 13;
    let tcp_flags_byte = frame[tcp_flags_offset];
    assert!(
        tcp_flags_byte & flags::PSH != 0,
        "PSH flag should be set on last (only) data segment, got flags: {:#04x}",
        tcp_flags_byte
    );
    assert!(
        tcp_flags_byte & flags::ACK != 0,
        "ACK flag should also be set, got flags: {:#04x}",
        tcp_flags_byte
    );
}

#[test]
fn poll_send_no_psh_on_first_segment_when_more_data() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(32);
    let mut rx = BasicFrameBuffer::new(32);
    let mut tx = BasicFrameBuffer::new(32);
    // Allocate frames large enough for MSS-sized segments (ETH+IP+TCP+1460).
    for i in 0..16 {
        let buf = leak(vec![0u8; 2048]);
        free.push(Frame::new(2000 + i, buf, 2048, false));
    }

    let _server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);

    // Write more than 1 MSS of data.
    let mss = handler.first_connection().eff_snd_mss as usize;
    let big_data = vec![0x41u8; mss + 100];
    handler.first_connection_mut().send_buffer.write(&big_data);

    // Ensure cwnd is large enough to allow sending.
    handler.first_connection_mut().cubic.cwnd = (mss as u32) * 10;
    // Disable Nagle so the second (sub-MSS) segment can be sent.
    handler.first_connection_mut().nagle_enabled = false;

    let now = coarsetime::Instant::now();
    // poll_send now sends all segments in one call (fills the window).
    handler.poll_send(now, nh.local_mac(), &nh, &mut free, &mut rx, &mut tx);

    assert_eq!(
        tx.num_frames(),
        2,
        "expected two data segments from poll_send"
    );

    let first_frame = tx.pop().unwrap();
    let tcp_flags_offset = ETH_HEADER_LEN + IPV4_MIN_HEADER_LEN + 13;
    let first_flags = first_frame[tcp_flags_offset];
    assert!(
        first_flags & flags::PSH == 0,
        "PSH should NOT be set on first segment when more data remains, got flags: {:#04x}",
        first_flags
    );
    assert!(
        first_flags & flags::ACK != 0,
        "ACK flag should be set, got flags: {:#04x}",
        first_flags
    );

    // Second frame: remaining 100 bytes, no more data -> PSH set.
    let second_frame = tx.pop().unwrap();
    let second_flags = second_frame[tcp_flags_offset];
    assert!(
        second_flags & flags::PSH != 0,
        "PSH should be set on last segment, got flags: {:#04x}",
        second_flags
    );
}

#[test]
fn rcv_nxt_advances_only_by_bytes_written_to_recv_buffer() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);

    for i in 0..8 {
        free.push(alloc_free_frame(100 + i));
    }

    // Listen with a tiny recv buffer (32 bytes, must be power of two).
    let config = TcpConfig {
        recv_buffer_size: 32,
        backlog: 128,
        timestamps: false,
        sack: false,
        ecn: false,
        ..TcpConfig::default()
    };
    let _accept_queue = handler
        .listen_with_config(IpAddress::V4(LOCAL_IP), 80, config)
        .unwrap();

    // SYN from remote.
    let syn = build_tcp_frame(
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
    let syn_len = syn.len();
    handler.process_ipv4(
        Frame::new(0, leak(syn), syn_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    let server_iss = handler.first_connection().iss;

    // ACK to complete handshake.
    let ack = build_tcp_frame(
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
    let ack_len = ack.len();
    handler.process_ipv4(
        Frame::new(1, leak(ack), ack_len, false),
        coarsetime::Instant::now(),
        &nh,
        &mut free,
        &mut rx,
        &mut tx,
    );
    assert_eq!(handler.first_connection().state, TcpState::Established);
    while tx.pop().is_some() {}

    // Fill 20 of 32 bytes in the recv buffer directly, leaving 12 free.
    let filler = [0xAA_u8; 20];
    handler.first_connection_mut().recv_buffer.write(&filler);
    // Advance rcv_nxt to account for the filler (as if received normally).
    handler.first_connection_mut().rcv_nxt = handler.first_connection_mut().rcv_nxt.wrapping_add(20);
    let rcv_nxt_before = handler.first_connection().rcv_nxt;

    // Send a 20-byte payload — only 12 should fit.
    let payload = [0xBB_u8; 20];
    let data = build_tcp_frame_with_payload(
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        rcv_nxt_before,
        server_iss.wrapping_add(1),
        flags::ACK,
        65535,
        &[],
        &payload,
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

    // rcv_nxt must advance by only 12 (the bytes actually written), not 20.
    let rcv_nxt_after = handler.first_connection().rcv_nxt;
    let advanced = rcv_nxt_after.wrapping_sub(rcv_nxt_before);
    assert_eq!(
        advanced, 12,
        "rcv_nxt should advance by bytes written (12), not payload len (20); got {}",
        advanced
    );
    assert_eq!(
        handler.first_connection().recv_buffer.available(),
        32,
        "recv buffer should be completely full (20 filler + 12 new)"
    );
}
