use std::{
    hint::black_box,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use criterion::{Criterion, criterion_group, criterion_main};

use libvoid::xdp::umem::{FrameStack, Stack, ThreadLocalFrameStack};

#[inline(always)]
fn pop_and_push<S: Stack>(stack: Arc<S>, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::Relaxed) {
        let frame = loop {
            if let Some(frame) = stack.pop() {
                break frame;
            }
        };
        black_box(frame);
        loop {
            if stack.push(frame).is_ok() {
                break;
            }
        }
    }
}

fn benchmark(c: &mut Criterion) {
    c.bench_function("framestack pop", |b| {
        let stack = Arc::new(FrameStack::new(1024, 1024));
        let stop = Arc::new(AtomicBool::new(false));

        b.iter_custom(|iters| {
            let t1 = std::thread::spawn({
                let stack = stack.clone();
                let stop = stop.clone();
                move || {
                    pop_and_push(stack, stop);
                }
            });

            let start = Instant::now();
            for _ in 0..iters {
                let frame = loop {
                    if let Some(frame) = stack.pop() {
                        break frame;
                    }
                };
                loop {
                    if stack.push(frame).is_ok() {
                        break;
                    }
                }
            }
            let elapsed = start.elapsed();
            stop.store(true, Ordering::Relaxed);

            t1.join().unwrap();
            elapsed
        });
    });

    let stack = ThreadLocalFrameStack::new(1024, 1024);
    c.bench_function("thread local framestack pop", |b| {
        b.iter(|| {
            let frame = stack.pop().unwrap();
            black_box(frame);
            stack.push(frame).unwrap();
        })
    });
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
