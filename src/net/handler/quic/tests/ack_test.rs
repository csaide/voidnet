use coarsetime::Instant;

use crate::net::handler::quic::transport::ack::AckState;

#[test]
fn ack_state_single_packet() {
    let mut state = AckState::new();
    let now = Instant::now();
    state.on_packet_received(0, now);
    assert_eq!(state.largest_received(), Some(0));
    assert_eq!(state.first_ack_range(), 0);
    assert_eq!(state.ack_range_count(), 0);
}

#[test]
fn ack_state_sequential_packets() {
    let mut state = AckState::new();
    let now = Instant::now();
    state.on_packet_received(0, now);
    state.on_packet_received(1, now);
    state.on_packet_received(2, now);
    // One contiguous range [0,2]: largest=2, first_ack_range=2 (2-0=2), no gaps
    assert_eq!(state.largest_received(), Some(2));
    assert_eq!(state.first_ack_range(), 2);
    assert_eq!(state.ack_range_count(), 0);
}

#[test]
fn ack_state_gap() {
    let mut state = AckState::new();
    let now = Instant::now();
    state.on_packet_received(0, now);
    state.on_packet_received(1, now);
    state.on_packet_received(3, now);
    // Two ranges: [3,3] and [0,1]
    // largest=3, first_ack_range=0 (3-3=0), ack_range_count=1
    assert_eq!(state.largest_received(), Some(3));
    assert_eq!(state.first_ack_range(), 0);
    assert_eq!(state.ack_range_count(), 1);
}

#[test]
fn ack_state_multiple_gaps() {
    let mut state = AckState::new();
    let now = Instant::now();
    // Receive 0,1,5,6,10 → three ranges: [10,10],[5,6],[0,1]
    state.on_packet_received(0, now);
    state.on_packet_received(1, now);
    state.on_packet_received(5, now);
    state.on_packet_received(6, now);
    state.on_packet_received(10, now);
    assert_eq!(state.largest_received(), Some(10));
    // First range is [10,10]: first_ack_range = 10-10 = 0
    assert_eq!(state.first_ack_range(), 0);
    // Two additional ranges
    assert_eq!(state.ack_range_count(), 2);
}

#[test]
fn ack_state_out_of_order() {
    let mut state = AckState::new();
    let now = Instant::now();
    state.on_packet_received(3, now);
    state.on_packet_received(1, now);
    state.on_packet_received(2, now);
    state.on_packet_received(0, now);
    // All contiguous [0,3]: largest=3, first_ack_range=3, no extra ranges
    assert_eq!(state.largest_received(), Some(3));
    assert_eq!(state.first_ack_range(), 3);
    assert_eq!(state.ack_range_count(), 0);
}

#[test]
fn ack_state_needs_ack() {
    let mut state = AckState::new();
    assert!(!state.needs_ack());
    state.set_ack_eliciting();
    assert!(state.needs_ack());
    state.ack_sent();
    assert!(!state.needs_ack());
}

#[test]
fn decode_ack_ranges_roundtrip() {
    let mut state = AckState::new();
    let now = Instant::now();
    // Three ranges: [0,1], [5,6], [10,10]
    state.on_packet_received(0, now);
    state.on_packet_received(1, now);
    state.on_packet_received(5, now);
    state.on_packet_received(6, now);
    state.on_packet_received(10, now);

    let largest = state.largest_received().unwrap();
    let first = state.first_ack_range();
    let count = state.ack_range_count();
    let encoded = state.encoded_ranges().to_vec();

    let decoded = AckState::decode_ack_ranges(largest, first, count, &encoded);
    // Should decode back to [(10,10), (5,6), (0,1)] or similar sorted order
    assert_eq!(decoded.len(), 3);
    // Verify all expected ranges are present
    assert!(decoded.contains(&(10, 10)));
    assert!(decoded.contains(&(5, 6)));
    assert!(decoded.contains(&(0, 1)));
}

#[test]
fn ack_state_encoded_ranges_not_empty() {
    let mut state = AckState::new();
    let now = Instant::now();
    state.on_packet_received(0, now);
    state.on_packet_received(2, now);
    // Two ranges — gap/range pair encoded
    // encoded_ranges covers only additional ranges (gaps+ranges after first)
    // With 2 ranges there is 1 additional range → encoded bytes should be non-empty
    assert!(!state.encoded_ranges().is_empty());
}
