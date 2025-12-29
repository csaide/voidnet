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
    frame::{FrameBufferBuilder, LocalFrameBuffer},
    socket::Socket,
    umem::{CompletionQueue, Umem},
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

fn worker_thread(
    exit: Arc<AtomicBool>,
    mut stats: Stats,
    frame_stack: Arc<Mutex<LocalFrameBuffer>>,
    mut socket: Socket,
    batch_size: usize,
    data_len: usize,
) {
    while !exit.load(Ordering::Relaxed) {
        let mut frame_stack = frame_stack.lock().unwrap();
        let batch_size = frame_stack.len().min(batch_size);
        if batch_size == 0 {
            socket.maybe_wake().unwrap();
            continue;
        }

        let mut frames = LocalFrameBuffer::new_buffer(frame_stack.drain(..batch_size));
        match socket.send(&mut frames) {
            Ok(sent) => {
                stats.update_batch(sent as usize, data_len);
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

fn umem_thread(
    exit: Arc<AtomicBool>,
    mut completion_queue: CompletionQueue,
    frame_stack: Arc<Mutex<LocalFrameBuffer>>,
) {
    while !exit.load(Ordering::Relaxed) {
        let mut guard = frame_stack.lock().unwrap();
        completion_queue.process_queue(&mut guard);
    }
}

fn main() {
    let args = Args::parse();

    // Every application starts with setting up an XdpContext, this loads the XDP kernel program and attaches it to the named
    // interface.
    let mut xdp_ctx = XdpContext::new(&args.if_name, args.attach_mode, args.enable_fragmentation)
        .expect("Failed to create xdp context");

    // A Umem is created to manage sharing memory buffers between the kernel and user space.
    //
    // You will need one of these for each unique device + queue ID tuple you want to use. In the case of this example, we
    // are using a single device and a single queue on that device so hence a single Umem instance.
    //
    // Each Umem comes associated with three key components:
    // - Fill Queue (fq) > Used to pass frames from user space to the kernel for reading packet data into.
    // - Completion Queue (cq) > Used to retrieve frames from the kernel after transmission finishes.
    // - Frames (frames) > A set of frames that are backed by the umem which are shared between the kernel and user space.
    let (umem, mut fq, mut cq, mut frames) = Umem::builder()
        .completion_ring_size(args.completion_ring_size)
        .fill_ring_size(args.fill_ring_size)
        .frame_size(args.frame_size)
        .busy_poll(args.busy_poll)
        .num_frames(args.busy_poll_batch_size * args.num_threads.get())
        .huge_tables(args.huge_tables)
        .unaligned(args.unaligned)
        .build::<LocalFrameBuffer>()
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

    // For writes we need to write some data :), so fill up our frames with our mock UDP packet.
    let data = build_frame(&args.generator);
    for frame in frames.iter_mut() {
        unsafe { frame.copy_from(&data) };
    }

    // Since we are going to be using multiple threads, we need to wrap up our frame stack in a arc/mutex to
    // share it between the workers and umem threads
    let frame_stack = Arc::new(Mutex::new(frames));

    // Create some backing collections so we can join our threads.
    let mut threads = Vec::with_capacity(args.num_threads.get() + 1);
    let data_len = data.len();
    for i in 0..args.num_threads.get() {
        let exit = exit.clone();
        let stats = Stats::new_with_id(i);
        let frame_stack = frame_stack.clone();
        let batch_size = args.busy_poll_batch_size;

        // If we are using multiple threads, we need to share the umem instance, otherwise it's technically an error
        // to use a shared umem with a single socket, though it should "work" in most cases.
        let shared_umem = args.num_threads.get() > 1;

        // Create a new socket for each thread, in this case passing in the already created umem instance.
        let socket = Socket::builder(&mut xdp_ctx, &args.if_name, args.queue)
            .rx_ring_size(args.rx_ring_size)
            .tx_ring_size(args.tx_ring_size)
            .busy_poll(args.busy_poll)
            .busy_poll_batch_size(args.busy_poll_batch_size)
            .busy_poll_timeout_us(args.busy_poll_timeout_us)
            .copy_mode(args.copy_mode)
            .shared_umem(shared_umem)
            .build(umem.clone(), &mut fq, &mut cq)
            .expect("Failed to create socket");

        // Spawn our worker thread, this will handle sending frames to the socket.
        let thread = thread::spawn(move || {
            worker_thread(exit, stats, frame_stack, socket, batch_size, data_len)
        });
        threads.push(thread);
    }

    // Spawn our Umem thread, this will handle actually retrieving handled frames from the completion queue, and repopulating
    // the frame stack with new frames to send.
    threads.push(thread::spawn(move || umem_thread(exit, cq, frame_stack)));

    println!("All threads created, sending packets...");

    // Wait for exit of all threads.
    for thread in threads.drain(..) {
        thread.join().unwrap();
    }
}
