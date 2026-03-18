use std::collections::BTreeMap;

use coarsetime::Instant;

use crate::{
    net::{
        handler::tcp::{
            congestion::CubicState,
            recovery::{FRtoState, PrrState, SackRecovery},
            ring_buffer::RingBuffer,
            state::TcpState,
            tcb::{ConnectionId, DEFAULT_DELAYED_ACK_MS, DEFAULT_RCV_MSS, Tcb},
        },
        socket::LocalQueue,
        wire::{ethernet::MacAddress, ip::IpAddress},
    },
    xdp::frame::{BasicFrameBuffer, FrameBuffer},
};

use super::{
    LOCAL_IP, REMOTE_IP, alloc_free_frame, establish_connection, new_handler, new_neighbor_handler,
    new_wheel,
};

/// Build a minimal Tcb for unit testing handler methods.
fn make_test_tcb(state: TcpState, local_port: u16, remote_port: u16) -> Tcb {
    let now = Instant::now();
    Tcb {
        id: ConnectionId {
            local_addr: IpAddress::V4(LOCAL_IP),
            local_port,
            remote_addr: IpAddress::V4(REMOTE_IP),
            remote_port,
        },
        state,
        from_passive_open: false,
        iss: 1000,
        snd_una: 1000,
        snd_nxt: 1001,
        snd_wnd: 65535,
        snd_wl1: 0,
        snd_wl2: 0,
        irs: 2000,
        rcv_nxt: 2001,
        rcv_wnd: 65535,
        snd_mss: DEFAULT_RCV_MSS,
        rcv_mss: DEFAULT_RCV_MSS,
        eff_snd_mss: DEFAULT_RCV_MSS,
        snd_wscale: 0,
        rcv_wscale: 7,
        wscale_enabled: false,
        rto_backoff: 0,
        event_queue: LocalQueue::new(16),
        send_buffer: RingBuffer::new(1024),
        recv_buffer: RingBuffer::new(1024),
        ooo_ranges: BTreeMap::new(),
        cubic: CubicState::new(DEFAULT_RCV_MSS),
        recovery: SackRecovery::new(),
        prr: PrrState::new(),
        frto: FRtoState::new(),
        srtt: None,
        rttvar: 0,
        rto: 1000,
        last_send_time: None,
        pending_fin: false,
        fin_seq: None,
        time_wait_duration: 60_000,
        ack_pending: false,
        ack_delay_count: 0,
        delayed_ack_ms: DEFAULT_DELAYED_ACK_MS,
        nagle_enabled: true,
        keep_alive_enabled: false,
        keep_alive_idle_ms: 7_200_000,
        keep_alive_interval_ms: 75_000,
        keep_alive_count: 9,
        last_activity: now,
        keep_alive_probes_sent: 0,
        linger: None,
        ts_enabled: false,
        ts_recent: 0,
        ts_recent_age: now,
        ts_offset: now,
        sack_enabled: false,
        sack_scoreboard: BTreeMap::new(),
        ecn_enabled: false,
        ecn_ce_received: false,
        ecn_cwr_sent: false,
        persist_backoff: 0,
        max_snd_wnd: 0,
        last_advertised_right_edge: 0,
    }
}

// ---------------------------------------------------------------------------
// insert_connection / get_connection / get_by_key
// ---------------------------------------------------------------------------

#[test]
fn insert_and_retrieve_by_id() {
    let mut handler = new_handler();
    let tcb = make_test_tcb(TcpState::Established, 5000, 80);
    let id = tcb.id;
    let key = handler.insert_connection(tcb);

    // Retrieve by ConnectionId.
    let conn = handler
        .get_connection(&id)
        .expect("connection should exist");
    assert_eq!(conn.state, TcpState::Established);
    assert_eq!(conn.id, id);

    // Retrieve by slab key.
    let conn2 = handler
        .get_by_key(key)
        .expect("connection should exist by key");
    assert_eq!(conn2.id, id);
}

#[test]
fn insert_and_retrieve_mut_by_id() {
    let mut handler = new_handler();
    let tcb = make_test_tcb(TcpState::Established, 5000, 80);
    let id = tcb.id;
    handler.insert_connection(tcb);

    let conn = handler
        .get_connection_mut(&id)
        .expect("connection should exist");
    conn.state = TcpState::CloseWait;
    assert_eq!(
        handler.get_connection(&id).unwrap().state,
        TcpState::CloseWait
    );
}

#[test]
fn insert_and_retrieve_mut_by_key() {
    let mut handler = new_handler();
    let tcb = make_test_tcb(TcpState::Established, 5000, 80);
    let key = handler.insert_connection(tcb);

    let conn = handler.get_by_key_mut(key).expect("should exist");
    conn.state = TcpState::FinWait1;
    assert_eq!(handler.get_by_key(key).unwrap().state, TcpState::FinWait1);
}

#[test]
fn connection_key_lookup() {
    let mut handler = new_handler();
    let tcb = make_test_tcb(TcpState::Established, 5000, 80);
    let id = tcb.id;
    let key = handler.insert_connection(tcb);

    assert_eq!(handler.connection_key(&id), Some(key));

    // Unknown id returns None.
    let unknown = ConnectionId {
        local_addr: IpAddress::V4(LOCAL_IP),
        local_port: 9999,
        remote_addr: IpAddress::V4(REMOTE_IP),
        remote_port: 80,
    };
    assert_eq!(handler.connection_key(&unknown), None);
}

#[test]
fn get_connection_nonexistent_returns_none() {
    let handler = new_handler();
    let id = ConnectionId {
        local_addr: IpAddress::V4(LOCAL_IP),
        local_port: 5000,
        remote_addr: IpAddress::V4(REMOTE_IP),
        remote_port: 80,
    };
    assert!(handler.get_connection(&id).is_none());
    assert!(handler.get_by_key(999).is_none());
}

// ---------------------------------------------------------------------------
// remove_connection_by_key
// ---------------------------------------------------------------------------

#[test]
fn remove_connection_by_key_returns_tcb() {
    let mut handler = new_handler();
    let tcb = make_test_tcb(TcpState::Established, 5000, 80);
    let id = tcb.id;
    let key = handler.insert_connection(tcb);

    let removed = handler.remove_connection_by_key(key);
    assert!(removed.is_some());
    assert_eq!(removed.unwrap().id, id);

    // After removal, lookups return None.
    assert!(handler.get_connection(&id).is_none());
    assert!(handler.get_by_key(key).is_none());
}

#[test]
fn remove_connection_by_key_nonexistent_returns_none() {
    let mut handler = new_handler();
    assert!(handler.remove_connection_by_key(42).is_none());
}

// ---------------------------------------------------------------------------
// remove_connection (with RST generation)
// ---------------------------------------------------------------------------

#[test]
fn remove_connection_synchronized_generates_rst() {
    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(4);
    let mut rx = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(4);
    let mut wheel = new_wheel();

    // Establish a real connection via 3-way handshake.
    let _server_iss =
        establish_connection(&mut handler, &mut wheel, &nh, &mut free, &mut rx, &mut tx);
    assert_eq!(handler.first_connection().state, TcpState::Established);

    let id = handler.first_connection().id;
    let src_mac = MacAddress::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    let dst_mac = MacAddress::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

    // Provide free frames for RST construction.
    free.push(alloc_free_frame(100));

    handler.remove_connection(&id, src_mac, dst_mac, &mut free, &mut tx);

    // Connection should be gone.
    assert!(handler.get_connection(&id).is_none());

    // RST should have been placed on tx.
    assert!(tx.pop().is_some(), "RST frame should be on tx queue");
}

#[test]
fn remove_connection_syn_received_generates_rst() {
    let mut handler = new_handler();
    let tcb = make_test_tcb(TcpState::SynReceived, 80, 12345);
    let id = tcb.id;
    handler.insert_connection(tcb);

    let src_mac = MacAddress::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    let dst_mac = MacAddress::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    let mut free = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(4);
    let mut wheel = new_wheel();

    free.push(alloc_free_frame(200));
    handler.remove_connection(&id, src_mac, dst_mac, &mut free, &mut tx);

    assert!(handler.get_connection(&id).is_none());
    assert!(tx.pop().is_some(), "RST should be sent for SynReceived");
}

#[test]
fn remove_connection_syn_sent_no_rst() {
    let mut handler = new_handler();
    let tcb = make_test_tcb(TcpState::SynSent, 5000, 80);
    let id = tcb.id;
    handler.insert_connection(tcb);

    let src_mac = MacAddress::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    let dst_mac = MacAddress::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    let mut free = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(4);
    let mut wheel = new_wheel();

    handler.remove_connection(&id, src_mac, dst_mac, &mut free, &mut tx);

    assert!(handler.get_connection(&id).is_none());
    assert!(tx.pop().is_none(), "No RST for SynSent (not synchronized)");
}

#[test]
fn remove_connection_not_found_is_noop() {
    let mut handler = new_handler();
    let id = ConnectionId {
        local_addr: IpAddress::V4(LOCAL_IP),
        local_port: 9999,
        remote_addr: IpAddress::V4(REMOTE_IP),
        remote_port: 80,
    };
    let src_mac = MacAddress::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    let dst_mac = MacAddress::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    let mut free = BasicFrameBuffer::new(4);
    let mut tx = BasicFrameBuffer::new(4);
    let mut wheel = new_wheel();

    // Should not panic — just returns early.
    handler.remove_connection(&id, src_mac, dst_mac, &mut free, &mut tx);
    assert!(tx.pop().is_none());
}

// ---------------------------------------------------------------------------
// write_to_send_buffer
// ---------------------------------------------------------------------------

#[test]
fn write_to_send_buffer_inserts_data_and_marks_send() {
    let mut handler = new_handler();
    let tcb = make_test_tcb(TcpState::Established, 5000, 80);
    let key = handler.insert_connection(tcb);

    let n = handler.write_to_send_buffer(key, b"hello").unwrap();
    assert_eq!(n, 5);

    // Verify data is in the send buffer via available().
    let conn = handler.get_by_key(key).unwrap();
    assert_eq!(conn.send_buffer.available(), 5);
}

#[test]
fn write_to_send_buffer_nonexistent_returns_none() {
    let mut handler = new_handler();
    assert!(handler.write_to_send_buffer(999, b"hello").is_none());
}

#[test]
fn write_to_send_buffer_empty_data_returns_zero() {
    let mut handler = new_handler();
    let tcb = make_test_tcb(TcpState::Established, 5000, 80);
    let key = handler.insert_connection(tcb);

    let n = handler.write_to_send_buffer(key, b"").unwrap();
    assert_eq!(n, 0);
}

// ---------------------------------------------------------------------------
// splice_buffers
// ---------------------------------------------------------------------------

#[test]
fn splice_buffers_transfers_recv_to_send() {
    let mut handler = new_handler();
    let tcb = make_test_tcb(TcpState::Established, 5000, 80);
    let key = handler.insert_connection(tcb);

    // Write directly into recv_buffer.
    handler
        .get_by_key_mut(key)
        .unwrap()
        .recv_buffer
        .write(b"payload");

    let (n, is_closed) = handler.splice_buffers(key, 1024).unwrap();
    assert_eq!(n, 7);
    assert!(!is_closed);

    // recv_buffer should be drained, send_buffer should have the data.
    let conn = handler.get_by_key(key).unwrap();
    assert_eq!(conn.recv_buffer.available(), 0);
    assert_eq!(conn.send_buffer.available(), 7);
}

#[test]
fn splice_buffers_reports_remote_closed() {
    let mut handler = new_handler();
    let tcb = make_test_tcb(TcpState::CloseWait, 5000, 80);
    let key = handler.insert_connection(tcb);

    handler.get_by_key_mut(key).unwrap().recv_buffer.write(b"x");
    let (n, is_closed) = handler.splice_buffers(key, 1024).unwrap();
    assert_eq!(n, 1);
    assert!(is_closed, "CloseWait means remote side has closed");
}

#[test]
fn splice_buffers_nonexistent_returns_none() {
    let mut handler = new_handler();
    assert!(handler.splice_buffers(999, 1024).is_none());
}

// ---------------------------------------------------------------------------
// Test helpers: first_connection, first_connection_mut, first_connection_key
// ---------------------------------------------------------------------------

#[test]
fn first_connection_helpers() {
    let mut handler = new_handler();
    let tcb = make_test_tcb(TcpState::Established, 5000, 80);
    let expected_id = tcb.id;
    let key = handler.insert_connection(tcb);

    assert_eq!(handler.first_connection().id, expected_id);
    assert_eq!(handler.first_connection_key(), key);

    handler.first_connection_mut().state = TcpState::FinWait1;
    assert_eq!(handler.first_connection().state, TcpState::FinWait1);
}
