use std::{
    num::NonZero,
    ops::{Deref, DerefMut},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use clap::Parser;

use libvoid::xdp::{
    context::XdpContext,
    frame::{BasicFrameBuffer, FrameBuffer},
    socket::Socket,
    umem::Umem,
};

mod common;
use common::{BaseArgs, GeneratorArgs, Stats, build_frame};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(flatten)]
    base: BaseArgs,
    #[arg(short, long, default_value = "1")]
    num_threads: NonZero<usize>,
    #[command(flatten)]
    generator: GeneratorArgs,
}

impl Deref for Args {
    type Target = BaseArgs;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl DerefMut for Args {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base
    }
}

fn worker_thread<'umem>(
    exit: Arc<AtomicBool>,
    generator: GeneratorArgs,
    mut stats: Stats,
    frame_stack: Arc<Mutex<BasicFrameBuffer<'umem>>>,
    mut socket: Socket<'umem>,
    batch_size: usize,
) {
    let data = build_frame(&generator);
    while !exit.load(Ordering::Relaxed) {
        let mut frames: BasicFrameBuffer<'umem> = {
            let mut frame_stack = frame_stack.lock().unwrap();
            let batch_size = frame_stack.num_frames().min(batch_size);
            if batch_size == 0 {
                socket.maybe_wake().unwrap();
                continue;
            }

            frame_stack.drain(..batch_size).collect()
        };

        for frame in frames.iter_frames_mut() {
            frame.copy_from(&data);
        }

        match socket.send(&mut frames) {
            Ok(sent) => {
                stats.update_batch(sent as usize, data.len());
            }
            Err(_) => {
                // We would have blocked, loop back and try again.
                continue;
            }
        };

        socket.maybe_wake().unwrap();
        stats.maybe_print();
    }
}

fn umem_thread<'umem>(
    exit: Arc<AtomicBool>,
    mut umem: Umem<'umem>,
    frame_stack: Arc<Mutex<BasicFrameBuffer<'umem>>>,
) {
    while !exit.load(Ordering::Relaxed) {
        let guard = frame_stack.lock().unwrap();
        let _ = umem.process_completion_queue(guard);
    }
}

fn main() {
    let args = Args::parse();

    // Every application starts with setting up an XdpContext, this loads the XDP kernel program and attaches it to the named
    // interface.
    let mut xdp_ctx = XdpContext::builder(&args.if_name)
        .attach_mode(args.attach_mode)
        .enable_fragmentation(args.enable_fragmentation)
        .build()
        .expect("Failed to create xdp context");

    // A Umem is created to manage sharing memory buffers between the kernel and user space.
    //
    // You will need one of these for each unique device + queue ID tuple you want to use. In the case of this example, we
    // are using a single device and a single queue on that device so hence a single Umem instance.
    //
    // Each Umem comes associated with three key components:
    // - Owner (umem) > The owner of the UMEM, this is used to create frames and is responsible for cleaning up the UMEM once all is said and done.
    // - Fill Queue (fq) > Used to pass frames from user space to the kernel for reading packet data into.
    // - Completion Queue (cq) > Used to retrieve frames from the kernel after transmission finishes.
    let umem = Umem::builder(&mut xdp_ctx)
        .completion_ring_size(args.completion_ring_size)
        .fill_ring_size(args.fill_ring_size)
        .frame_size(args.frame_size)
        .busy_poll(args.busy_poll)
        .num_frames(args.busy_poll_batch_size * args.num_threads.get())
        .huge_tables(args.huge_tables)
        .unaligned(args.unaligned)
        .build()
        .expect("Failed to create umem");

    // Always catch SIGINT/SIGTERM to ensure we clean up properly, we have a running XDP program attached to the interface.
    //
    // Note: In other words its very important to ensure that the Drop impl for XdpContext is run to detach the XDP program from
    // the interface, OR manually call detach().
    let exit = Arc::new(AtomicBool::new(false));
    ctrlc::set_handler({
        let exit = exit.clone();
        move || {
            exit.store(true, Ordering::Relaxed);
        }
    })
    .expect("Error setting Ctrl-C handler");

    // Since we are going to be using multiple threads, we need to wrap up our frame stack in a arc/mutex to
    // share it between the workers and umem threads
    let frames = umem.init_buffer::<BasicFrameBuffer>().unwrap();
    let frame_stack = Arc::new(Mutex::new(frames));

    // Create some backing collections so we can join our threads.
    let mut threads = Vec::with_capacity(args.num_threads.get() + 1);
    for i in 0..args.num_threads.get() {
        let exit = exit.clone();
        let stats = Stats::new_with_id(i);
        let frame_stack = frame_stack.clone();
        let batch_size = args.busy_poll_batch_size;
        let generator = args.generator.clone();

        // Create a new socket for each thread, in this case passing in the already created umem instance.
        let socket = Socket::builder(&mut xdp_ctx, &args.if_name, args.queue)
            .rx_ring_size(args.rx_ring_size)
            .tx_ring_size(args.tx_ring_size)
            .busy_poll(args.busy_poll)
            .busy_poll_batch_size(args.busy_poll_batch_size)
            .busy_poll_timeout_us(args.busy_poll_timeout_us)
            .copy_mode(args.copy_mode)
            .build(umem.owner().clone())
            .expect("Failed to create socket");

        // Spawn our worker thread, this will handle sending frames to the socket.
        let thread = thread::spawn(move || {
            worker_thread(exit, generator, stats, frame_stack, socket, batch_size)
        });
        threads.push(thread);
    }

    // Spawn our Umem thread, this will handle actually retrieving handled frames from the completion queue, and repopulating
    // the frame stack with new frames to send.
    threads.push(thread::spawn(move || umem_thread(exit, umem, frame_stack)));

    println!("All threads created, sending packets...");

    // Wait for exit of all threads.
    for thread in threads.drain(..) {
        thread.join().unwrap();
    }
}
