use criterion::{Criterion, criterion_group, criterion_main};

fn tcp_throughput(_c: &mut Criterion) {
    // TODO: implement
}

criterion_group!(benches, tcp_throughput);
criterion_main!(benches);
