use criterion::{Criterion, criterion_group, criterion_main};

fn tcp_latency(_c: &mut Criterion) {
    // TODO: implement
}

criterion_group!(benches, tcp_latency);
criterion_main!(benches);
