use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use libvoid::net::handler::quic::bench::crypto::{
    DirectionalKey, Side, Version, derive_initial_keys, protect_packet,
};
use libvoid::net::handler::quic::bench::{
    ConnectionId, StreamId, decode_varint, encode_varint, frame_writer, parse_frame,
};

fn bench_varint(c: &mut Criterion) {
    c.bench_function("varint_encode_1byte", |b| {
        let mut buf = [0u8; 8];
        b.iter(|| black_box(encode_varint(black_box(42), &mut buf)));
    });

    c.bench_function("varint_encode_2byte", |b| {
        let mut buf = [0u8; 8];
        b.iter(|| black_box(encode_varint(black_box(16383), &mut buf)));
    });

    c.bench_function("varint_encode_4byte", |b| {
        let mut buf = [0u8; 8];
        b.iter(|| black_box(encode_varint(black_box(1_000_000), &mut buf)));
    });

    c.bench_function("varint_encode_8byte", |b| {
        let mut buf = [0u8; 8];
        b.iter(|| black_box(encode_varint(black_box(4_000_000_000u64), &mut buf)));
    });

    c.bench_function("varint_decode_1byte", |b| {
        let encoded = [0x2A]; // 42
        b.iter(|| black_box(decode_varint(black_box(&encoded))));
    });

    c.bench_function("varint_decode_2byte", |b| {
        let encoded = [0x7F, 0xFF]; // 16383
        b.iter(|| black_box(decode_varint(black_box(&encoded))));
    });

    c.bench_function("varint_decode_4byte", |b| {
        let mut buf = [0u8; 8];
        encode_varint(1_000_000, &mut buf);
        let encoded: [u8; 4] = [buf[0], buf[1], buf[2], buf[3]];
        b.iter(|| black_box(decode_varint(black_box(&encoded))));
    });

    c.bench_function("varint_decode_8byte", |b| {
        let mut buf = [0u8; 8];
        encode_varint(4_000_000_000u64, &mut buf);
        b.iter(|| black_box(decode_varint(black_box(&buf))));
    });
}

fn bench_frames(c: &mut Criterion) {
    c.bench_function("frame_encode_stream", |b| {
        let mut buf = [0u8; 256];
        let data = b"hello world benchmark data payload";
        b.iter(|| {
            black_box(frame_writer::write_stream(
                &mut buf,
                black_box(StreamId(0x04)),
                black_box(1024),
                black_box(data),
                false,
            ))
        });
    });

    c.bench_function("frame_decode_stream", |b| {
        // Pre-encode a STREAM frame for decoding
        let mut buf = [0u8; 256];
        let data = b"hello world benchmark data payload";
        let len = frame_writer::write_stream(&mut buf, StreamId(0x04), 1024, data, false);
        let encoded = &buf[..len];
        b.iter(|| black_box(parse_frame(black_box(encoded))));
    });

    c.bench_function("frame_encode_crypto", |b| {
        let mut buf = [0u8; 256];
        let data = b"crypto handshake data for benchmark";
        b.iter(|| {
            black_box(frame_writer::write_crypto(
                &mut buf,
                black_box(0),
                black_box(data),
            ))
        });
    });

    c.bench_function("frame_decode_ack", |b| {
        // Minimal ACK frame: type(0x02) + largest_acked + delay + range_count + first_range
        let frame = [0x02, 0x10, 0x05, 0x00, 0x10]; // largest=16, delay=5, count=0, first_range=16
        b.iter(|| black_box(parse_frame(black_box(&frame))));
    });
}

fn bench_cid_hash(c: &mut Criterion) {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    c.bench_function("connection_id_hash_8byte", |b| {
        let cid = ConnectionId::from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        b.iter(|| {
            let mut hasher = DefaultHasher::new();
            black_box(&cid).hash(&mut hasher);
            black_box(hasher.finish())
        });
    });

    c.bench_function("connection_id_hash_20byte", |b| {
        let cid = ConnectionId::from_slice(&[0xAA; 20]);
        b.iter(|| {
            let mut hasher = DefaultHasher::new();
            black_box(&cid).hash(&mut hasher);
            black_box(hasher.finish())
        });
    });

    c.bench_function("connection_id_eq_8byte", |b| {
        let cid1 = ConnectionId::from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        let cid2 = ConnectionId::from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        b.iter(|| black_box(black_box(&cid1) == black_box(&cid2)));
    });
}

/// Benchmark QUIC packet protection (encrypt + header protection) hot path.
///
/// Derives initial keys once per benchmark run and measures the cost of
/// `protect_packet` — the AEAD encrypt + header mask path taken for every
/// outgoing QUIC packet.
fn bench_packet_protection(c: &mut Criterion) {
    // RFC 9001 Appendix A test vector DCID.
    let dcid = [0x83u8, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

    // Benchmark key derivation itself (HKDF — hot during connection setup).
    c.bench_function("initial_key_derivation", |b| {
        b.iter(|| {
            let keys = derive_initial_keys(
                black_box(&dcid),
                black_box(Side::Client),
                black_box(Version::V1),
            );
            black_box(keys)
        });
    });

    // Build a client DirectionalKey once for the protect_packet benchmark.
    let (client_dk, _) = derive_initial_keys(&dcid, Side::Client, Version::V1);
    let client_key = DirectionalKey::from_rustls(client_dk);

    let plaintext = b"bench payload data for quic protection";
    let tag_len = client_key.packet_key.tag_len();

    // Packet layout mirrors protect_unprotect_roundtrip in crypto_test.rs.
    // pn_offset = 18 (1 first_byte + 4 version + 1 dcid_len + 8 dcid + 1 scid_len
    //                  + 1 token_len + 2 length_varint)
    let pn_offset: usize = 18;
    let pn_length: usize = 1;
    let total_len = pn_offset + pn_length + plaintext.len() + tag_len;

    // Template packet — protect_packet mutates the buffer so we clone each iter.
    let mut template = vec![0u8; total_len];
    template[0] = 0xC0; // long header, Initial
    template[1..5].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]); // QUIC v1
    template[5] = 0x08; // dcid_len
    template[6..14].copy_from_slice(&dcid);
    // scid_len=0, token_len=0 (bytes 14,15 stay 0)
    let payload_and_tag_len = pn_length + plaintext.len() + tag_len;
    template[16] = 0x40 | ((payload_and_tag_len >> 8) as u8);
    template[17] = (payload_and_tag_len & 0xFF) as u8;
    // pn byte at offset 18 = 0x00 (packet number 0)
    template[pn_offset + pn_length..pn_offset + pn_length + plaintext.len()]
        .copy_from_slice(plaintext);

    c.bench_function("protect_packet", |b| {
        b.iter(|| {
            let mut packet = template.clone();
            black_box(protect_packet(
                &client_key,
                black_box(&mut packet),
                pn_offset,
                pn_length,
                0u64,
            ))
        });
    });
}

/// Benchmark ACK frame parsing — the most common frame type in steady state.
fn bench_ack_processing(c: &mut Criterion) {
    // Single-range ACK: type(0x02) | largest_acked=0x10 | delay=0x05 | range_count=0 | first_range=0x10
    let single_ack = [0x02u8, 0x10, 0x05, 0x00, 0x10];

    c.bench_function("ack_parse_single_range", |b| {
        b.iter(|| black_box(parse_frame(black_box(&single_ack))));
    });

    // Multi-range ACK with 2 additional gap/range pairs.
    // Build it using encode_varint for realistic wire encoding.
    // largest_acked=1000, delay=10, range_count=2, first_range=50,
    //   gap0=5, range0=20, gap1=3, range1=10
    let mut multi_ack = vec![0x02u8]; // ACK type
    let fields: &[u64] = &[1000, 10, 2, 50, 5, 20, 3, 10];
    for &val in fields {
        let mut buf = [0u8; 8];
        let n = encode_varint(val, &mut buf);
        multi_ack.extend_from_slice(&buf[..n]);
    }
    let multi_ack = multi_ack; // freeze

    c.bench_function("ack_parse_multi_range", |b| {
        b.iter(|| black_box(parse_frame(black_box(multi_ack.as_slice()))));
    });
}

/// Benchmark FxHashMap lookup by ConnectionId — the per-packet CID dispatch path.
fn bench_cid_lookup(c: &mut Criterion) {
    use rustc_hash::FxHashMap;

    // Pre-populate map with 1000 entries.
    let mut map: FxHashMap<ConnectionId, usize> = FxHashMap::default();
    for i in 0u32..1000 {
        let bytes = i.to_be_bytes();
        // Pad to 8 bytes so every CID has the same length.
        let cid_bytes = [0u8, 0u8, 0u8, 0u8, bytes[0], bytes[1], bytes[2], bytes[3]];
        map.insert(ConnectionId::from_slice(&cid_bytes), i as usize);
    }

    // Mid-table target (entry 500).
    let target_bytes = 500u32.to_be_bytes();
    let target_cid_bytes = [
        0u8,
        0u8,
        0u8,
        0u8,
        target_bytes[0],
        target_bytes[1],
        target_bytes[2],
        target_bytes[3],
    ];
    let target = ConnectionId::from_slice(&target_cid_bytes);

    c.bench_function("fxhashmap_cid_lookup_1000", |b| {
        b.iter(|| black_box(map.get(black_box(&target))));
    });
}

criterion_group!(
    benches,
    bench_varint,
    bench_frames,
    bench_cid_hash,
    bench_packet_protection,
    bench_ack_processing,
    bench_cid_lookup,
);
criterion_main!(benches);
