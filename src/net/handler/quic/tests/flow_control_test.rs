use crate::net::handler::quic::transport::flow_control::FlowControl;

#[test]
fn stream_recv_should_send_max_stream_data() {
    use crate::net::handler::quic::stream::recv::RecvHalf;
    let mut recv = RecvHalf::new(1000);
    assert!(recv.receive(0, &[0u8; 600], false).is_ok());
    let mut buf = [0u8; 600];
    let n = recv.read(&mut buf);
    assert_eq!(n, 600);
    let new_max = recv.should_send_max_stream_data();
    assert!(new_max.is_some());
    assert!(new_max.unwrap() > 1000);
    recv.commit_max_stream_data(new_max.unwrap());
    assert!(recv.should_send_max_stream_data().is_none());
}

#[test]
fn flow_control_send_within_limit() {
    let fc = FlowControl::new(1000, 2000);
    assert!(fc.can_send(500));
    assert!(fc.can_send(1000));
}

#[test]
fn flow_control_send_blocked() {
    let mut fc = FlowControl::new(1000, 2000);
    fc.on_data_sent(1000);
    assert!(!fc.can_send(1));
    assert!(!fc.can_send(100));
}

#[test]
fn flow_control_update_max() {
    let mut fc = FlowControl::new(1000, 2000);
    fc.on_data_sent(1000);
    assert!(!fc.can_send(1));
    fc.update_max_data_send(2000);
    assert!(fc.can_send(1000));
    assert!(!fc.can_send(1001));
}

#[test]
fn flow_control_receive_within_limit() {
    let mut fc = FlowControl::new(1000, 2000);
    assert!(fc.on_data_received(500).is_ok());
    assert!(fc.on_data_received(500).is_ok());
    assert!(fc.on_data_received(1000).is_ok());
}

#[test]
fn flow_control_receive_exceeds_limit() {
    let mut fc = FlowControl::new(1000, 2000);
    assert!(fc.on_data_received(2001).is_err());
}

#[test]
fn flow_control_auto_tune() {
    let mut fc = FlowControl::new(1000, 2000);
    // Consume less than half — no MAX_DATA needed
    fc.on_data_consumed(999);
    assert!(fc.should_send_max_data().is_none());
    // Consume more than half (>1000)
    fc.on_data_consumed(2);
    // Now data_consumed = 1001 > 2000/2 = 1000
    let new_max = fc.should_send_max_data();
    assert!(new_max.is_some());
    // New max should be data_consumed + original max_data_recv
    assert_eq!(new_max.unwrap(), 1001 + 2000);
}

#[test]
fn flow_control_should_send_max_data_after_consume() {
    let mut fc = FlowControl::new(1000, 2000);
    assert!(fc.on_data_received(1500).is_ok());
    fc.on_data_consumed(1500);
    let new_max = fc.should_send_max_data();
    assert!(new_max.is_some());
    let val = new_max.unwrap();
    assert!(val > 2000, "new max should exceed original: {}", val);
    fc.commit_max_data(val);
    assert!(fc.should_send_max_data().is_none());
}

#[test]
fn flow_control_blocked_notification() {
    let mut fc = FlowControl::new(1000, 2000);
    fc.on_data_sent(1000);
    // First call: at limit, not yet notified → returns Some
    let blocked = fc.send_blocked();
    assert_eq!(blocked, Some(1000));
    // Second call: already notified at same limit → returns None
    let blocked2 = fc.send_blocked();
    assert!(blocked2.is_none());
    // After update, a new block can be notified
    fc.update_max_data_send(1500);
    fc.on_data_sent(500);
    let blocked3 = fc.send_blocked();
    assert_eq!(blocked3, Some(1500));
}
