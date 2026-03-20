use crate::net::handler::quic::transport::varint::{decode_varint, encode_varint, varint_len};

// RFC 9000 §16 test values:
// 0x25 → 37 (1 byte)
// [0x7b, 0xbd] → 15293 (2 bytes)
// [0x9d, 0x7f, 0x3e, 0x7d] → 494878333 (4 bytes)
// [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c] → 151288809941952652 (8 bytes)

#[test]
fn varint_decode_1byte() {
    let buf = [0x25u8];
    let result = decode_varint(&buf);
    assert_eq!(result, Some((37, 1)));
}

#[test]
fn varint_decode_2byte() {
    let buf = [0x7b, 0xbd];
    let result = decode_varint(&buf);
    assert_eq!(result, Some((15293, 2)));
}

#[test]
fn varint_decode_4byte() {
    let buf = [0x9d, 0x7f, 0x3e, 0x7d];
    let result = decode_varint(&buf);
    assert_eq!(result, Some((494878333, 4)));
}

#[test]
fn varint_decode_8byte() {
    let buf = [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c];
    let result = decode_varint(&buf);
    assert_eq!(result, Some((151288809941952652, 8)));
}

#[test]
fn varint_encode_roundtrip() {
    let values: &[u64] = &[0, 63, 64, 16383, 16384, 1073741823, 1073741824];
    for &val in values {
        let mut buf = [0u8; 8];
        let written = encode_varint(val, &mut buf);
        let (decoded, consumed) = decode_varint(&buf[..written]).expect("decode should succeed");
        assert_eq!(decoded, val, "roundtrip failed for value {}", val);
        assert_eq!(consumed, written, "consumed != written for value {}", val);
    }
}

#[test]
fn varint_len_returns_correct_size() {
    assert_eq!(varint_len(0), 1);
    assert_eq!(varint_len(63), 1);
    assert_eq!(varint_len(64), 2);
    assert_eq!(varint_len(16383), 2);
    assert_eq!(varint_len(16384), 4);
    assert_eq!(varint_len(1073741823), 4);
    assert_eq!(varint_len(1073741824), 8);
    assert_eq!(varint_len(4611686018427387903), 8);
}

#[test]
fn varint_decode_empty_buffer() {
    let buf: &[u8] = &[];
    assert_eq!(decode_varint(buf), None);
}
