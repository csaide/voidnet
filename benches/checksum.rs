use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use libvoid::net::checksum::{
    compute_tcp_checksum_ip, compute_udp_checksum_ip, sum_words, sum_words_carry,
    verify_tcp_checksum_ip, verify_udp_checksum_ip,
};
use libvoid::net::wire::ip::{Ipv4, Ipv4Address, Ipv6, Ipv6Address};
use std::hint::black_box;

fn bench_sum_words(c: &mut Criterion) {
    let mut group = c.benchmark_group("sum_words");
    for size in [64, 256, 1500, 9000] {
        let data: Vec<u8> = (0..size).map(|i| (i & 0xFF) as u8).collect();
        group.bench_with_input(BenchmarkId::new("bytes", size), &data, |b, data| {
            b.iter(|| black_box(sum_words(data)));
        });
    }
    group.finish();
}

fn bench_sum_words_carry_odd_pending(c: &mut Criterion) {
    let mut group = c.benchmark_group("sum_words_carry_odd");
    let data: Vec<u8> = (0..1499).map(|i| (i & 0xFF) as u8).collect();
    group.bench_function("1499B_pending", |b| {
        b.iter(|| black_box(sum_words_carry(&data, 0, Some(0xAB))));
    });
    group.finish();
}

// --- TCP checksum helpers ---

/// Build a valid TCP segment with correct checksum for IPv4.
fn make_tcp_v4_segment(payload_size: usize) -> (Ipv4Address, Ipv4Address, Vec<u8>) {
    let src = Ipv4Address::new([192, 168, 1, 1]);
    let dst = Ipv4Address::new([10, 0, 0, 1]);
    // 20-byte TCP header (data_offset=5, ACK flag, window=65535)
    let mut segment = vec![
        0xC0, 0x00, // src port 49152
        0x00, 0x50, // dst port 80
        0x00, 0x00, 0x01, 0x00, // seq
        0x00, 0x00, 0x02, 0x00, // ack
        0x50, 0x10, // data_offset=5, ACK
        0xFF, 0xFF, // window
        0x00, 0x00, // checksum (zeroed)
        0x00, 0x00, // urgent
    ];
    // Append payload
    for i in 0..payload_size {
        segment.push((i & 0xFF) as u8);
    }
    // Compute and fill checksum
    let cksum = compute_tcp_checksum_ip::<Ipv4>(&src, &dst, &segment, &[]);
    segment[16] = cksum[0];
    segment[17] = cksum[1];
    (src, dst, segment)
}

/// Build a valid TCP segment with correct checksum for IPv6.
fn make_tcp_v6_segment(payload_size: usize) -> (Ipv6Address, Ipv6Address, Vec<u8>) {
    let src = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let dst = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let mut segment = vec![
        0xC0, 0x00, 0x00, 0x50, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x50, 0x10, 0xFF,
        0xFF, 0x00, 0x00, 0x00, 0x00,
    ];
    for i in 0..payload_size {
        segment.push((i & 0xFF) as u8);
    }
    let cksum = compute_tcp_checksum_ip::<Ipv6>(&src, &dst, &segment, &[]);
    segment[16] = cksum[0];
    segment[17] = cksum[1];
    (src, dst, segment)
}

// --- UDP checksum helpers ---

/// Build a valid UDP segment with correct checksum for IPv4.
fn make_udp_v4_segment(payload_size: usize) -> (Ipv4Address, Ipv4Address, Vec<u8>) {
    let src = Ipv4Address::new([192, 168, 1, 1]);
    let dst = Ipv4Address::new([10, 0, 0, 1]);
    let udp_len = (8 + payload_size) as u16;
    let mut segment = vec![
        0xC0, 0x00, // src port
        0x00, 0x35, // dst port (53)
    ];
    segment.extend_from_slice(&udp_len.to_be_bytes());
    segment.extend_from_slice(&[0x00, 0x00]); // checksum zeroed
    for i in 0..payload_size {
        segment.push((i & 0xFF) as u8);
    }
    // Compute checksum via from_parts (header + payload separately)
    let payload = &segment[8..].to_vec();
    let cksum = compute_udp_checksum_ip::<Ipv4>(&src, &dst, 0xC000, 0x0035, udp_len, payload);
    segment[6] = cksum[0];
    segment[7] = cksum[1];
    (src, dst, segment)
}

/// Build a valid UDP segment with correct checksum for IPv6.
fn make_udp_v6_segment(payload_size: usize) -> (Ipv6Address, Ipv6Address, Vec<u8>) {
    let src = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let dst = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let udp_len = (8 + payload_size) as u16;
    let mut segment = vec![0xC0, 0x00, 0x00, 0x35];
    segment.extend_from_slice(&udp_len.to_be_bytes());
    segment.extend_from_slice(&[0x00, 0x00]);
    for i in 0..payload_size {
        segment.push((i & 0xFF) as u8);
    }
    let payload = &segment[8..].to_vec();
    let cksum = compute_udp_checksum_ip::<Ipv6>(&src, &dst, 0xC000, 0x0035, udp_len, payload);
    segment[6] = cksum[0];
    segment[7] = cksum[1];
    (src, dst, segment)
}

// --- Benchmarks ---

fn bench_verify_tcp_checksum(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_tcp_checksum");
    for payload_size in [44, 1460] {
        let label = format!("{}B", 20 + payload_size);

        let (src4, dst4, seg4) = make_tcp_v4_segment(payload_size);
        group.bench_with_input(BenchmarkId::new("v4", &label), &(), |b, _| {
            b.iter(|| {
                black_box(verify_tcp_checksum_ip::<Ipv4>(
                    black_box(&src4),
                    black_box(&dst4),
                    black_box(&seg4),
                ))
            });
        });

        let (src6, dst6, seg6) = make_tcp_v6_segment(payload_size);
        group.bench_with_input(BenchmarkId::new("v6", &label), &(), |b, _| {
            b.iter(|| {
                black_box(verify_tcp_checksum_ip::<Ipv6>(
                    black_box(&src6),
                    black_box(&dst6),
                    black_box(&seg6),
                ))
            });
        });
    }
    group.finish();
}

fn bench_compute_tcp_checksum(c: &mut Criterion) {
    let mut group = c.benchmark_group("compute_tcp_checksum");
    for payload_size in [44, 1460] {
        let label = format!("{}B", 20 + payload_size);

        let (src4, dst4, seg4) = make_tcp_v4_segment(payload_size);
        // Zero the checksum field for compute benchmarks
        let mut seg4_zeroed = seg4.clone();
        seg4_zeroed[16] = 0;
        seg4_zeroed[17] = 0;
        group.bench_with_input(BenchmarkId::new("v4", &label), &(), |b, _| {
            b.iter(|| {
                black_box(compute_tcp_checksum_ip::<Ipv4>(
                    black_box(&src4),
                    black_box(&dst4),
                    black_box(&seg4_zeroed),
                    black_box(&[]),
                ))
            });
        });

        let (src6, dst6, seg6) = make_tcp_v6_segment(payload_size);
        let mut seg6_zeroed = seg6.clone();
        seg6_zeroed[16] = 0;
        seg6_zeroed[17] = 0;
        group.bench_with_input(BenchmarkId::new("v6", &label), &(), |b, _| {
            b.iter(|| {
                black_box(compute_tcp_checksum_ip::<Ipv6>(
                    black_box(&src6),
                    black_box(&dst6),
                    black_box(&seg6_zeroed),
                    black_box(&[]),
                ))
            });
        });
    }
    group.finish();
}

fn bench_verify_udp_checksum(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_udp_checksum");
    for payload_size in [56, 1492] {
        let label = format!("{}B", 8 + payload_size);

        let (src4, dst4, seg4) = make_udp_v4_segment(payload_size);
        group.bench_with_input(BenchmarkId::new("v4", &label), &(), |b, _| {
            b.iter(|| {
                black_box(verify_udp_checksum_ip::<Ipv4>(
                    black_box(&src4),
                    black_box(&dst4),
                    black_box(&seg4),
                ))
            });
        });

        let (src6, dst6, seg6) = make_udp_v6_segment(payload_size);
        group.bench_with_input(BenchmarkId::new("v6", &label), &(), |b, _| {
            b.iter(|| {
                black_box(verify_udp_checksum_ip::<Ipv6>(
                    black_box(&src6),
                    black_box(&dst6),
                    black_box(&seg6),
                ))
            });
        });
    }
    group.finish();
}

fn bench_compute_udp_checksum(c: &mut Criterion) {
    let mut group = c.benchmark_group("compute_udp_checksum");
    for payload_size in [56, 1492] {
        let label = format!("{}B", 8 + payload_size);
        let udp_len = (8 + payload_size) as u16;
        let payload: Vec<u8> = (0..payload_size).map(|i| (i & 0xFF) as u8).collect();

        let src4 = Ipv4Address::new([192, 168, 1, 1]);
        let dst4 = Ipv4Address::new([10, 0, 0, 1]);
        group.bench_with_input(BenchmarkId::new("v4", &label), &(), |b, _| {
            b.iter(|| {
                black_box(compute_udp_checksum_ip::<Ipv4>(
                    black_box(&src4),
                    black_box(&dst4),
                    black_box(0xC000),
                    black_box(0x0035),
                    black_box(udp_len),
                    black_box(&payload),
                ))
            });
        });

        let src6 = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst6 = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        group.bench_with_input(BenchmarkId::new("v6", &label), &(), |b, _| {
            b.iter(|| {
                black_box(compute_udp_checksum_ip::<Ipv6>(
                    black_box(&src6),
                    black_box(&dst6),
                    black_box(0xC000),
                    black_box(0x0035),
                    black_box(udp_len),
                    black_box(&payload),
                ))
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_sum_words,
    bench_sum_words_carry_odd_pending,
    bench_verify_tcp_checksum,
    bench_compute_tcp_checksum,
    bench_verify_udp_checksum,
    bench_compute_udp_checksum,
);
criterion_main!(benches);
