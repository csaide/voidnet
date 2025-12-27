use std::{hint::black_box, ptr::null_mut};

use criterion::{Criterion, criterion_group, criterion_main};

use libvoid::xdp::frame::{Frame, Packet};

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("packet generate", |b| {
        b.iter(|| {
            let mut packet: Packet = Packet::new(32, 2);
            for i in 0..3 {
                let frame = unsafe { Frame::new(i, null_mut(), 0, 0, false) };
                packet.push_frame(black_box(frame));
            }

            let mut frames = packet.to_frames();
            while let Some(frame) = frames.pop() {
                black_box(frame);
            }
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
