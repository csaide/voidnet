use super::*;
use crate::net::handler::udp::BindError;
use crate::net::wire::ip::IpAddress;

#[test]
fn listen_returns_accept_queue() {
    let mut handler = new_handler();
    let accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128);
    assert!(accept_queue.is_ok());
    assert_eq!(handler.listeners.len(), 1);
    assert_eq!(handler.listeners[0].port, 80);
    assert_eq!(handler.listeners[0].addr, IpAddress::V4(LOCAL_IP));
    assert_eq!(handler.listeners[0].backlog, 128);
}

#[test]
fn listen_same_port_twice_returns_address_in_use() {
    let mut handler = new_handler();
    let _ = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
    let result = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128);
    assert!(matches!(result, Err(BindError::AddressInUse)));
}

#[test]
fn listen_unspecified_conflicts_with_specific_address() {
    let mut handler = new_handler();
    let _ = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
    // Listening on unspecified addr for the same port should conflict.
    let unspec = IpAddress::V4(crate::net::wire::ip::Ipv4Address::new([0, 0, 0, 0]));
    let result = handler.listen(unspec, 80, 128);
    assert!(matches!(result, Err(BindError::AddressInUse)));
}

#[test]
fn listen_specific_conflicts_with_unspecified() {
    let mut handler = new_handler();
    let unspec = IpAddress::V4(crate::net::wire::ip::Ipv4Address::new([0, 0, 0, 0]));
    let _ = handler.listen(unspec, 80, 128).unwrap();
    // Listening on a specific addr for the same port should conflict.
    let result = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128);
    assert!(matches!(result, Err(BindError::AddressInUse)));
}

#[test]
fn listen_different_ports_allowed() {
    let mut handler = new_handler();
    let _ = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
    let result = handler.listen(IpAddress::V4(LOCAL_IP), 443, 128);
    assert!(result.is_ok());
    assert_eq!(handler.listeners.len(), 2);
}

#[test]
fn unlisten_removes_listener() {
    let mut handler = new_handler();
    let _ = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
    assert_eq!(handler.listeners.len(), 1);
    handler.unlisten(IpAddress::V4(LOCAL_IP), 80);
    assert_eq!(handler.listeners.len(), 0);
}

#[test]
fn unlisten_nonexistent_is_noop() {
    let mut handler = new_handler();
    let _ = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();
    handler.unlisten(IpAddress::V4(LOCAL_IP), 443);
    assert_eq!(handler.listeners.len(), 1);
}

#[test]
fn unlisten_cleans_up_syn_received_connections() {
    use crate::net::wire::tcp::flags;
    use crate::xdp::frame::{BasicFrameBuffer, Frame};

    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);
    for i in 0..16u64 {
        free.push(alloc_free_frame(i));
    }

    let _accept_queue = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128).unwrap();

    // Send a SYN to create a SYN-RECEIVED connection.
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

    // Verify we have a SYN-RECEIVED connection.
    assert_eq!(handler.first_connection().state, TcpState::SynReceived);
    assert!(handler.first_connection().from_passive_open);
    assert_eq!(handler.connections.len(), 1);

    // Unlisten should remove the listener and the SYN-RECEIVED connection.
    handler.unlisten(IpAddress::V4(LOCAL_IP), 80);
    assert_eq!(handler.listeners.len(), 0);
    assert_eq!(handler.connections.len(), 0);
}

#[test]
fn unlisten_preserves_established_connections() {
    use crate::xdp::frame::BasicFrameBuffer;

    let mut handler = new_handler();
    let nh = new_neighbor_handler();
    let mut free = BasicFrameBuffer::new(16);
    let mut rx = BasicFrameBuffer::new(16);
    let mut tx = BasicFrameBuffer::new(16);
    for i in 0..16u64 {
        free.push(alloc_free_frame(i));
    }

    // Complete a full handshake to get an ESTABLISHED connection.
    let _server_iss = establish_connection(&mut handler, &nh, &mut free, &mut rx, &mut tx);
    assert_eq!(handler.first_connection().state, TcpState::Established);
    assert_eq!(handler.connections.len(), 1);

    // Unlisten removes listener but NOT the established connection.
    handler.unlisten(IpAddress::V4(LOCAL_IP), 80);
    assert_eq!(handler.listeners.len(), 0);
    assert_eq!(handler.connections.len(), 1);
}

#[test]
fn listen_with_config_propagates_settings() {
    use super::super::tcb::TcpConfig;

    let mut handler = new_handler();
    let config = TcpConfig {
        backlog: 64,
        send_buffer_size: 32768,
        recv_buffer_size: 16384,
        time_wait_duration_ms: 5000,
        tcp_no_delay: true,
        delayed_ack_ms: 0,
        keep_alive: true,
        keep_alive_idle_ms: 1000,
        keep_alive_interval_ms: 500,
        keep_alive_count: 3,
        linger: Some(10000),
        timestamps: true,
        sack: false,
        ecn: true,
    };
    let _queue = handler
        .listen_with_config(IpAddress::V4(LOCAL_IP), 80, config)
        .unwrap();
    let entry = &handler.listeners[0];
    assert_eq!(entry.backlog, 64);
    assert_eq!(entry.send_buffer_size, 32768);
    assert_eq!(entry.recv_buffer_size, 16384);
    assert_eq!(entry.time_wait_duration, 5000);
    assert!(entry.tcp_no_delay);
    assert_eq!(entry.delayed_ack_ms, 0);
    assert!(entry.keep_alive);
    assert_eq!(entry.keep_alive_idle_ms, 1000);
    assert_eq!(entry.keep_alive_interval_ms, 500);
    assert_eq!(entry.keep_alive_count, 3);
    assert_eq!(entry.linger, Some(10000));
    assert!(entry.timestamps);
    assert!(!entry.sack);
    assert!(entry.ecn);
}
