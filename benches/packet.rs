use std::{hint::black_box, ptr::null_mut};

use criterion::{Criterion, criterion_group, criterion_main};

use libvoid::xdp::frame::{Frame, Packet};

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("packet generate", |b| {
        b.iter(|| {
            let mut packet: Packet<16> = Packet::new();
            for i in 0..3 {
                let frame = unsafe { Frame::new(i, null_mut(), 0, 0, false) };
                packet.push_frame(black_box(frame));
            }

            while let Some(frame) = packet.pop_frame() {
                black_box(frame);
            }
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
