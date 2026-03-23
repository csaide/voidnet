use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

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

criterion_group!(benches, bench_varint, bench_frames, bench_cid_hash);
criterion_main!(benches);
