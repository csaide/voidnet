use crate::net::handler::quic::transport::packet_number::{decode_pn, encode_pn};

// RFC 9000 Appendix A example:
// largest_pn = 0xa82f30ea, truncated = 0x9b32, nbits = 16
// expected_pn = 0xa82f30ea + 1 = 0xa82f30eb
// pn_win = 1 << 16 = 65536
// pn_mask = 65535
// candidate = (0xa82f30eb & ~65535) | 0x9b32 = 0xa82f0000 | 0x9b32 = 0xa82f9b32
// 0xa82f9b32 is NOT > expected_pn + pn_hwin (0xa82fb0eb), so result = candidate
#[test]
fn decode_pn_rfc_example() {
    let largest_pn: u64 = 0xa82f30ea;
    let truncated: u64 = 0x9b32;
    let nbits: u32 = 16;
    let result = decode_pn(largest_pn, truncated, nbits);
    assert_eq!(result, 0xa82f9b32);
}

#[test]
fn encode_pn_minimal_length() {
    // When difference is small, should use 1 byte
    let full_pn: u64 = 100;
    let largest_acked: u64 = 50;
    let (truncated, num_bytes) = encode_pn(full_pn, largest_acked);
    assert_eq!(num_bytes, 1, "small gap should encode to 1 byte");
    // truncated value must fit in 1 byte
    assert!(truncated < 128, "1-byte truncated PN must be < 2^7");

    // A 2-byte boundary
    let full_pn2: u64 = 200;
    let largest_acked2: u64 = 0; // gap = 200, needs 2 bytes (>= 2^7)
    let (_, num_bytes2) = encode_pn(full_pn2, largest_acked2);
    assert_eq!(num_bytes2, 2);
}

#[test]
fn roundtrip_sequential() {
    // Simulate receiving sequential packet numbers
    let mut largest_pn: u64 = 0;
    for pn in 0u64..1000 {
        let (truncated, num_bytes) = encode_pn(pn, if pn == 0 { 0 } else { pn - 1 });
        let nbits = num_bytes as u32 * 8;
        let decoded = decode_pn(largest_pn, truncated, nbits);
        if pn > 0 {
            assert_eq!(decoded, pn, "roundtrip failed at pn={}", pn);
        }
        largest_pn = pn;
    }
}

#[test]
fn roundtrip_large_gap() {
    // Test with large PN values
    let large_pn: u64 = 1_000_000_000;
    let prev_pn: u64 = large_pn - 1;
    let (truncated, num_bytes) = encode_pn(large_pn, prev_pn);
    let nbits = num_bytes as u32 * 8;
    let decoded = decode_pn(prev_pn, truncated, nbits);
    assert_eq!(decoded, large_pn, "roundtrip failed for large PN");
}
