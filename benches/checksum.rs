use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use libvoid::net::checksum::{sum_words, sum_words_carry};

fn bench_sum_words(c: &mut Criterion) {
    let mut group = c.benchmark_group("sum_words");
    for size in [64, 256, 1500, 9000] {
        let data: Vec<u8> = (0..size).map(|i| (i & 0xFF) as u8).collect();
        group.bench_with_input(
            BenchmarkId::new("bytes", size),
            &data,
            |b, data| {
                b.iter(|| std::hint::black_box(sum_words(data)));
            },
        );
    }
    group.finish();
}

fn bench_sum_words_carry_odd_pending(c: &mut Criterion) {
    let mut group = c.benchmark_group("sum_words_carry_odd");
    let data: Vec<u8> = (0..1499).map(|i| (i & 0xFF) as u8).collect();
    group.bench_function("1499B_pending", |b| {
        b.iter(|| std::hint::black_box(sum_words_carry(&data, 0, Some(0xAB))));
    });
    group.finish();
}

criterion_group!(benches, bench_sum_words, bench_sum_words_carry_odd_pending);
criterion_main!(benches);
