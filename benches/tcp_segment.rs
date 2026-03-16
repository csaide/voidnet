use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use libvoid::net::handler::tcp::SegmentBuilder;
use libvoid::net::wire::{
    ethernet::MacAddress,
    ip::{IpAddress, Ipv4Address, Ipv6Address},
    tcp::flags,
};
use libvoid::xdp::frame::{BasicFrameBuffer, Frame, FrameBuffer};
use std::hint::black_box;

/// Allocate a single reusable frame. Leaked intentionally — lives for the benchmark's lifetime.
fn alloc_frame() -> Frame<'static> {
    let buf = Box::leak(vec![0u8; 2048].into_boxed_slice());
    Frame::new(0, buf, 2048, false)
}

const SRC_MAC: MacAddress = MacAddress::new([0xAA; 6]);
const DST_MAC: MacAddress = MacAddress::new([0xBB; 6]);
const V4_LOCAL: Ipv4Address = Ipv4Address::new([10, 0, 0, 1]);
const V4_REMOTE: Ipv4Address = Ipv4Address::new([10, 0, 0, 2]);
const V6_LOCAL: Ipv6Address =
    Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
const V6_REMOTE: Ipv6Address =
    Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

fn bench_build_syn(c: &mut Criterion) {
    let mut group = c.benchmark_group("build_syn");

    group.bench_function("v4", |b| {
        let mut free = BasicFrameBuffer::new(1);
        let mut tx = BasicFrameBuffer::new(1);
        free.push(alloc_frame());
        b.iter(|| {
            SegmentBuilder::build_syn(
                black_box(IpAddress::V4(V4_LOCAL)),
                black_box(IpAddress::V4(V4_REMOTE)),
                8080,
                80,
                1000,
                65535,
                1460,
                7,
                Some((100, 0)),
                true,
                false,
                SRC_MAC,
                DST_MAC,
                false,
                &mut free,
                &mut tx,
            );
            // Recycle frame back to free pool.
            free.push(tx.pop().unwrap());
        });
    });

    group.bench_function("v6", |b| {
        let mut free = BasicFrameBuffer::new(1);
        let mut tx = BasicFrameBuffer::new(1);
        free.push(alloc_frame());
        b.iter(|| {
            SegmentBuilder::build_syn(
                black_box(IpAddress::V6(V6_LOCAL)),
                black_box(IpAddress::V6(V6_REMOTE)),
                8080,
                80,
                1000,
                65535,
                1460,
                7,
                Some((100, 0)),
                true,
                false,
                SRC_MAC,
                DST_MAC,
                false,
                &mut free,
                &mut tx,
            );
            free.push(tx.pop().unwrap());
        });
    });

    group.finish();
}

fn bench_build_ack(c: &mut Criterion) {
    let mut group = c.benchmark_group("build_ack");

    group.bench_function("v4", |b| {
        let mut free = BasicFrameBuffer::new(1);
        let mut tx = BasicFrameBuffer::new(1);
        free.push(alloc_frame());
        b.iter(|| {
            SegmentBuilder::build_ack(
                black_box(IpAddress::V4(V4_LOCAL)),
                black_box(IpAddress::V4(V4_REMOTE)),
                8080,
                80,
                1000,
                500,
                65535,
                flags::ACK,
                Some((100, 50)),
                SRC_MAC,
                DST_MAC,
                false,
                &mut free,
                &mut tx,
            );
            free.push(tx.pop().unwrap());
        });
    });

    group.bench_function("v6", |b| {
        let mut free = BasicFrameBuffer::new(1);
        let mut tx = BasicFrameBuffer::new(1);
        free.push(alloc_frame());
        b.iter(|| {
            SegmentBuilder::build_ack(
                black_box(IpAddress::V6(V6_LOCAL)),
                black_box(IpAddress::V6(V6_REMOTE)),
                8080,
                80,
                1000,
                500,
                65535,
                flags::ACK,
                Some((100, 50)),
                SRC_MAC,
                DST_MAC,
                false,
                &mut free,
                &mut tx,
            );
            free.push(tx.pop().unwrap());
        });
    });

    group.finish();
}

fn bench_build_data(c: &mut Criterion) {
    let mut group = c.benchmark_group("build_data");
    let payload = vec![0xABu8; 1400];

    for (label, local, remote) in [
        ("v4", IpAddress::V4(V4_LOCAL), IpAddress::V4(V4_REMOTE)),
        ("v6", IpAddress::V6(V6_LOCAL), IpAddress::V6(V6_REMOTE)),
    ] {
        group.bench_with_input(BenchmarkId::new(label, "1400B"), &(), |b, _| {
            let mut free = BasicFrameBuffer::new(1);
            let mut tx = BasicFrameBuffer::new(1);
            free.push(alloc_frame());
            b.iter(|| {
                SegmentBuilder::build_data(
                    black_box(local),
                    black_box(remote),
                    8080,
                    80,
                    1000,
                    500,
                    65535,
                    black_box(&payload),
                    Some((100, 50)),
                    SRC_MAC,
                    DST_MAC,
                    false,
                    &mut free,
                    &mut tx,
                );
                free.push(tx.pop().unwrap());
            });
        });
    }

    group.finish();
}

fn bench_build_data_from_slices(c: &mut Criterion) {
    let mut group = c.benchmark_group("build_data_from_slices");
    let slice1 = vec![0xABu8; 700];
    let slice2 = vec![0xCDu8; 700];

    for (label, local, remote) in [
        ("v4", IpAddress::V4(V4_LOCAL), IpAddress::V4(V4_REMOTE)),
        ("v6", IpAddress::V6(V6_LOCAL), IpAddress::V6(V6_REMOTE)),
    ] {
        group.bench_with_input(BenchmarkId::new(label, "2x700B"), &(), |b, _| {
            let mut free = BasicFrameBuffer::new(1);
            let mut tx = BasicFrameBuffer::new(1);
            free.push(alloc_frame());
            b.iter(|| {
                SegmentBuilder::build_data_from_slices(
                    black_box(local),
                    black_box(remote),
                    8080,
                    80,
                    1000,
                    500,
                    65535,
                    (black_box(&slice1[..]), black_box(&slice2[..])),
                    flags::ACK,
                    false,
                    Some((100, 50)),
                    SRC_MAC,
                    DST_MAC,
                    false,
                    &mut free,
                    &mut tx,
                );
                free.push(tx.pop().unwrap());
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_build_syn,
    bench_build_ack,
    bench_build_data,
    bench_build_data_from_slices,
);
criterion_main!(benches);
