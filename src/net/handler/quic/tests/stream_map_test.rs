use crate::net::handler::quic::stream::map::StreamMap;
use crate::net::handler::quic::stream::pool::StreamPool;
use crate::net::handler::quic::stream::recv::{OooRanges, RecvHalf, StreamRingBuffer};
use crate::net::handler::quic::stream::send::SendHalf;
use crate::net::handler::quic::transport::frame::StreamId;

// ── StreamRingBuffer ──────────────────────────────────────────────

#[test]
fn stream_ring_buffer_write_read() {
    let mut rb = StreamRingBuffer::new(64);
    let data = b"hello world";
    let written = rb.write(data);
    assert_eq!(written, data.len());
    assert_eq!(rb.len(), data.len());

    let mut buf = [0u8; 64];
    let read = rb.read(&mut buf);
    assert_eq!(read, data.len());
    assert_eq!(&buf[..read], data);
    assert!(rb.is_empty());
}

#[test]
fn stream_ring_buffer_wrap_around() {
    let mut rb = StreamRingBuffer::new(16); // capacity becomes 16, usable = 15
    let cap = rb.capacity();

    // Fill most of the buffer
    let fill = vec![0xAA; cap - 2];
    let written = rb.write(&fill);
    assert_eq!(written, cap - 2);

    // Read some to move head forward
    let mut tmp = [0u8; 8];
    let read = rb.read(&mut tmp);
    assert_eq!(read, 8);

    // Now write enough to wrap around
    let wrap_data = vec![0xBB; 8];
    let written = rb.write(&wrap_data);
    assert!(written > 0);

    // Read everything back
    let mut out = [0u8; 32];
    let read = rb.read(&mut out);
    assert!(read > 0);
}

#[test]
fn stream_ring_buffer_write_at_offset() {
    let mut rb = StreamRingBuffer::new(64);

    // Write at offset 5 (gap at 0..5)
    let data = b"world";
    let written = rb.write_at(5, data);
    assert_eq!(written, 5);
    assert_eq!(rb.len(), 10); // tail advanced to offset 10

    // Write at offset 0 to fill the gap
    let gap_data = b"hello";
    let written = rb.write_at(0, gap_data);
    assert_eq!(written, 5);

    // Peek to see full data
    let mut buf = [0u8; 10];
    let peeked = rb.peek(&mut buf);
    assert_eq!(peeked, 10);
    assert_eq!(&buf[..5], b"hello");
    assert_eq!(&buf[5..10], b"world");
}

#[test]
fn ring_buffer_write_at_wrapping() {
    use crate::net::handler::quic::stream::recv::StreamRingBuffer;
    let mut rb = StreamRingBuffer::new(8);
    rb.write(&[1, 2, 3, 4, 5, 6]);
    let mut discard = [0u8; 4];
    rb.read(&mut discard);
    rb.write(&[7, 8, 9, 10]);
    let mut out = [0u8; 6];
    let read = rb.peek(&mut out);
    assert_eq!(read, 6);
    assert_eq!(out, [5, 6, 7, 8, 9, 10]);
}

// ── OooRanges ─────────────────────────────────────────────────────

#[test]
fn ooo_ranges_insert_merge() {
    let mut ooo = OooRanges::new(256);
    ooo.insert(10, 5); // [10..15)
    ooo.insert(15, 5); // [15..20) — adjacent, should merge
    assert_eq!(ooo.count(), 1);

    ooo.insert(5, 5); // [5..10) — adjacent to [10..20), merge
    assert_eq!(ooo.count(), 1);

    // Non-adjacent
    ooo.insert(30, 5);
    assert_eq!(ooo.count(), 2);
}

#[test]
fn ooo_ranges_overflow_to_btree() {
    let mut ooo = OooRanges::new(256);
    // Insert 9 non-adjacent ranges to trigger overflow
    for i in 0..9 {
        ooo.insert(i * 100, 10);
    }
    // With 9 distinct non-adjacent ranges, should overflow
    assert_eq!(ooo.count(), 9);
    // Verify it still works after overflow
    ooo.insert(900, 10);
    assert_eq!(ooo.count(), 10);
}

#[test]
fn ooo_ranges_max_entries_limit() {
    let mut ooo = OooRanges::new(256);
    // Insert several ranges
    for i in 0..5 {
        ooo.insert(i * 100, 10);
    }
    assert_eq!(ooo.count(), 5);

    // Remove some
    ooo.remove_up_to(200);
    assert!(ooo.count() < 5);
}

// ── SendHalf ──────────────────────────────────────────────────────

#[test]
fn send_half_write_and_flow_control() {
    let mut send = SendHalf::new(100);
    assert!(!send.can_send()); // no data yet

    send.write(b"hello");
    assert!(send.can_send());

    // Simulate having sent up to the limit
    send.sent = 100;
    assert!(!send.can_send()); // flow control limit reached
}

// ── RecvHalf ──────────────────────────────────────────────────────

#[test]
fn recv_half_sequential_receive() {
    let mut recv = RecvHalf::new(65536);
    recv.receive(0, b"hello", false).unwrap();
    assert_eq!(recv.received, 5);

    recv.receive(5, b" world", false).unwrap();
    assert_eq!(recv.received, 11);

    let mut buf = [0u8; 32];
    let n = recv.read(&mut buf);
    assert_eq!(&buf[..n], b"hello world");
}

#[test]
fn recv_half_out_of_order() {
    let mut recv = RecvHalf::new(65536);

    // Receive second chunk first
    recv.receive(5, b"world", false).unwrap();
    assert_eq!(recv.received, 0); // frontier hasn't advanced

    // Now fill the gap
    recv.receive(0, b"hello", false).unwrap();
    assert_eq!(recv.received, 10); // frontier should advance through both

    let mut buf = [0u8; 32];
    let n = recv.read(&mut buf);
    assert_eq!(n, 10);
    assert_eq!(&buf[..5], b"hello");
    assert_eq!(&buf[5..10], b"world");
}

#[test]
fn recv_half_flow_control_exceeded() {
    let mut recv = RecvHalf::new(10); // limit of 10 bytes
    let result = recv.receive(0, b"this is too long!!", false);
    assert!(result.is_err());
}

// ── StreamMap ─────────────────────────────────────────────────────

#[test]
fn stream_map_get_by_id() {
    let mut map = StreamMap::new(true); // client
    map.peer_max_bidi = 100; // allow creating streams
    // Client-initiated bidi stream 0
    let id = StreamId(0);
    map.get_or_create(id).unwrap();

    assert!(map.get(id).is_some());
    assert!(map.get(StreamId(4)).is_none()); // stream index 1 not created
}

#[test]
fn stream_map_get_or_create() {
    let mut map = StreamMap::new(true); // client
    map.peer_max_bidi = 100; // allow creating streams
    let id = StreamId(8); // client bidi, index 2
    let entry = map.get_or_create(id).unwrap();
    assert!(entry.send.is_some()); // bidi has send
    assert!(entry.recv.is_some()); // bidi has recv

    // Verify it grew the vec
    assert_eq!(map.stream_count(), 1);
}

#[test]
fn stream_map_remove() {
    let mut map = StreamMap::new(true);
    map.peer_max_bidi = 100; // allow creating streams
    let id = StreamId(0);
    map.get_or_create(id).unwrap();
    assert_eq!(map.stream_count(), 1);

    let removed = map.remove(id);
    assert!(removed.is_some());
    assert_eq!(map.stream_count(), 0);
    assert!(map.get(id).is_none());
}

// ── MAX_STREAMS expansion ─────────────────────────────────────────

#[test]
fn max_streams_expansion() {
    use crate::net::handler::quic::stream::map::StreamMap;
    use crate::net::handler::quic::transport::frame::StreamId;
    let mut map = StreamMap::new(false);
    map.local_max_bidi = 4;
    map.committed_max_bidi = 4;
    for i in 0..3u64 {
        assert!(map.get_or_create(StreamId(i * 4)).is_ok());
    }
    let new_bidi = map.should_send_max_streams_bidi();
    assert!(new_bidi.is_some());
    assert!(new_bidi.unwrap() > 4);
}

// ── StreamPool ────────────────────────────────────────────────────

#[test]
fn stream_pool_alloc_release() {
    let mut pool = StreamPool::new(4);

    let send = pool.alloc_send(1000);
    assert_eq!(send.max_stream_data, 1000);

    pool.release_send(send);

    // Reuse from pool
    let send2 = pool.alloc_send(2000);
    assert_eq!(send2.max_stream_data, 2000);
}

#[test]
fn stream_pool_resets_on_release() {
    let mut pool = StreamPool::new(4);

    let mut send = pool.alloc_send(1000);
    send.write(b"dirty data");
    send.sent = 42;
    send.fin_sent = true;

    pool.release_send(send);

    let recycled = pool.alloc_send(5000);
    assert_eq!(recycled.sent, 0);
    assert!(!recycled.fin_sent);
    assert!(recycled.buffer.is_empty());
    assert_eq!(recycled.max_stream_data, 5000);

    // Same for recv
    let mut recv = pool.alloc_recv(1000);
    recv.receive(0, b"some data", false).unwrap();

    pool.release_recv(recv);

    let recycled_r = pool.alloc_recv(8000);
    assert_eq!(recycled_r.received, 0);
    assert!(!recycled_r.fin_received);
    assert!(recycled_r.buffer.is_empty());
    assert_eq!(recycled_r.max_stream_data, 8000);
}
