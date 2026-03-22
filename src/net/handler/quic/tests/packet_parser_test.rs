use crate::net::handler::quic::packet_parser::{
    CryptoBufferError, CryptoRecvBuffer, PnBitset, packet_space, parse_initial_fields,
};
use crate::net::wire::quic::PacketType;

// ─── CryptoRecvBuffer tests ───

#[test]
fn crypto_recv_sequential() {
    let mut buf = CryptoRecvBuffer::new();
    assert!(buf.is_empty());

    let n = buf.write(0, b"hello").unwrap();
    assert_eq!(n, 5);
    assert_eq!(buf.received(), 5);

    let n = buf.write(5, b" world").unwrap();
    assert_eq!(n, 6);
    assert_eq!(buf.received(), 11);

    let data = buf.read_all();
    assert_eq!(data, b"hello world");
}

#[test]
fn crypto_recv_duplicate() {
    let mut buf = CryptoRecvBuffer::new();
    buf.write(0, b"hello").unwrap();

    // Exact duplicate
    let n = buf.write(0, b"hello").unwrap();
    assert_eq!(n, 0);
    assert_eq!(buf.received(), 5);

    // Partial overlap: offset 3 with "lo world" — first 2 bytes overlap
    let n = buf.write(3, b"lo world").unwrap();
    assert_eq!(n, 6); // " world" appended
    assert_eq!(buf.received(), 11);
}

#[test]
fn crypto_recv_gap_dropped() {
    let mut buf = CryptoRecvBuffer::new();
    // Write at offset 100 when received=0 — gap, should drop
    let n = buf.write(100, b"data").unwrap();
    assert_eq!(n, 0);
    assert_eq!(buf.received(), 0);
    assert!(buf.is_empty());
}

#[test]
fn crypto_recv_overflow() {
    let mut buf = CryptoRecvBuffer::new();
    // Fill the buffer completely
    let block = [0xABu8; 4096];
    buf.write(0, &block).unwrap();
    buf.write(4096, &block).unwrap();
    assert_eq!(buf.received(), 8192);

    // Next write should fail
    match buf.write(8192, b"x") {
        Err(CryptoBufferError::BufferFull) => {}
        other => panic!("expected BufferFull, got {:?}", other),
    }
}

#[test]
fn crypto_recv_drain() {
    let mut buf = CryptoRecvBuffer::new();
    buf.write(0, b"hello world").unwrap();

    // Drain first 6 bytes ("hello ")
    buf.drain(6);
    let data = buf.read_all();
    assert_eq!(data, b"world");
    assert!(!buf.is_empty());

    // Drain all remaining
    buf.drain(5);
    assert!(buf.is_empty());
    assert_eq!(buf.read_all().len(), 0);
}

// ─── PnBitset tests ───

#[test]
fn pn_not_duplicate_first() {
    let bs = PnBitset::new();
    assert!(!bs.is_duplicate(0));
    assert!(!bs.is_duplicate(42));
}

#[test]
fn pn_duplicate_after_mark() {
    let mut bs = PnBitset::new();
    bs.mark(5);
    assert!(bs.is_duplicate(5));
    assert!(!bs.is_duplicate(6));
}

#[test]
fn pn_below_window_is_duplicate() {
    let mut bs = PnBitset::new();
    // Mark a high PN to push the window forward
    bs.mark(0);
    bs.mark(2000);
    // PN 0 should now be below the window base and treated as duplicate
    assert!(bs.is_duplicate(0));
}

#[test]
fn pn_above_window_not_duplicate() {
    let mut bs = PnBitset::new();
    bs.mark(0);
    // PN well above the current window should not be considered duplicate
    assert!(!bs.is_duplicate(5000));
}

#[test]
fn pn_window_advance() {
    let mut bs = PnBitset::new();
    // Mark 0..100
    for i in 0..100 {
        bs.mark(i);
    }
    // Mark 1100 — should advance window past 50
    bs.mark(1100);
    // PN 50 is now below window base
    assert!(bs.is_duplicate(50));
    // PN 1100 is marked
    assert!(bs.is_duplicate(1100));
    assert_eq!(bs.largest(), 1100);
}

#[test]
fn pn_reorder_within_window() {
    let mut bs = PnBitset::new();
    bs.mark(100);
    // 50 is within the 1024-bit window (base=100, so offset = -50... wait, base=100)
    // Actually base is set to first mark. Let me re-think:
    // First mark(100): base=100, largest=100
    // is_duplicate(50): 50 < base=100 → true (below window)
    // So let's use a different scenario: mark 0, then 100, then check 50
    let mut bs2 = PnBitset::new();
    bs2.mark(0);
    bs2.mark(100);
    // 50 is within window (base=0, offset=50 < 1024)
    assert!(!bs2.is_duplicate(50));
    bs2.mark(50);
    assert!(bs2.is_duplicate(50));
}

// ─── parse_initial_fields tests ───

#[test]
fn parse_initial_no_token() {
    // token_len=0 (varint 0x00), payload length=100 (varint 0x40 0x64)
    let buf = [0x00, 0x40, 0x64];
    let (token, payload_len, pn_offset) = parse_initial_fields(&buf).unwrap();
    assert_eq!(token.len(), 0);
    assert_eq!(payload_len, 100);
    assert_eq!(pn_offset, 3); // 1 byte token_len + 0 token + 2 bytes length
}

#[test]
fn parse_initial_with_token() {
    // token_len=16 (varint 0x10), 16 bytes of token, payload length=200 (varint 0x40 0xC8)
    let mut buf = Vec::new();
    buf.push(0x10); // token_len = 16
    buf.extend_from_slice(&[0xAA; 16]); // token bytes
    buf.push(0x40); // length varint high byte
    buf.push(0xC8); // length varint low byte (0x40C8 = 200 in 2-byte varint)
    let (token, payload_len, pn_offset) = parse_initial_fields(&buf).unwrap();
    assert_eq!(token.len(), 16);
    assert_eq!(token, &[0xAA; 16]);
    assert_eq!(payload_len, 200);
    assert_eq!(pn_offset, 1 + 16 + 2); // 19
}

#[test]
fn parse_initial_truncated() {
    // Just 1 byte — not enough for anything meaningful after token_len
    let buf = [0x10]; // says token_len=16 but no token data
    assert!(parse_initial_fields(&buf).is_none());

    // Empty buffer
    assert!(parse_initial_fields(&[]).is_none());
}

// ─── packet_space tests ───

#[test]
fn packet_space_mapping() {
    assert_eq!(packet_space(PacketType::Initial), Some(0));
    assert_eq!(packet_space(PacketType::Handshake), Some(1));
    assert_eq!(packet_space(PacketType::ZeroRtt), Some(2));
    assert_eq!(packet_space(PacketType::OneRtt), Some(2));
    assert_eq!(packet_space(PacketType::Retry), None);
    assert_eq!(packet_space(PacketType::Unknown), None);
}
