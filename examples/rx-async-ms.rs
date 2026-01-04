use std::{
    ffi::c_int,
    num::NonZero,
    ops::{Deref, DerefMut},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use clap::Parser;
use futures::lock::Mutex;

use libvoid::xdp::{
    context::XdpContext,
    frame::{BasicFrameBuffer, FrameBuffer},
    socket::Socket,
    umem::{FillQueue, Umem},
};

mod common;
use common::{BaseArgs, Stats};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(flatten)]
    base: BaseArgs,
    #[arg(short, long, default_value = "2")]
    num_threads: NonZero<usize>,
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

async fn worker_task<'umem>(
    exit: Arc<AtomicBool>,
    mut stats: Stats,
    mut socket: Socket<'umem>,
    frame_stack: Arc<Mutex<BasicFrameBuffer<'umem>>>,
    batch_size: usize,
) {
    let mut frames = BasicFrameBuffer::new(batch_size);
    while !exit.load(Ordering::Relaxed) {
        // Start by reading some frames from the socket. The result of this call is guaranteed to be between 1 and the batch size.
        match socket.recv_async(&mut frames).await {
            Ok(received) => {
                debug_assert!(
                    received > 0 && received <= batch_size as u32,
                    "Received more frames than the batch size or 0 frames, this should never happen!"
                );
            }
            Err(e) => {
                eprintln!("Error receiving frames: {}", e);
                continue;
            }
        }

        // You now have a batch of raw frames, at this level this is an L2 frame, almost assuredly Ethernet based.
        for frame in frames.iter_frames() {
            // Do something with the frame!
            //
            // Note checking the frame.is_fragment() is needed, iff we have fragmentation enabled. In this mode it is possible
            // to receive a fragment of a packat if the MTU of the device is larger than the frame size.
            stats.update(frame.len(), frame.is_fragment());
        }

        // You now have two options in general:
        // - Update the packet data in some way in place, then send all or some number of frames back out the socket achieving true end to end zero copy.
        //   - See the [examples/echo.rs](examples/echo.rs) example for a full end to end zero copy example.
        // - Return the data to the kernel by means of the fill queue. Which is what will be doing here.
        {
            let mut guard = frame_stack.lock().await;
            guard.extend(frames.drain(..));
        }

        // Maybe print the stats for this iteration.
        stats.maybe_print();
    }
}

async fn umem_task<'umem>(
    exit: Arc<AtomicBool>,
    mut fq: FillQueue<'umem>,
    frame_stack: Arc<Mutex<BasicFrameBuffer<'umem>>>,
    fds: Vec<c_int>,
) {
    while !exit.load(Ordering::Relaxed) {
        for fd in fds.iter() {
            fq.maybe_wake(*fd).unwrap();
        }

        {
            let guard = frame_stack.lock().await;
            fq.process_queue(guard);
        }

        tokio::task::yield_now().await;
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args = Args::parse();

    // We are relying on this invariant in the benchmark code bellow, though to be absolutely clear this isn't
    // actually a requirement, in the XDP subsystem itself, though its HIGHLY encouraged.
    debug_assert!(
        args.fill_ring_size >= (args.busy_poll_batch_size * args.num_threads.get()) as u32,
        "Fill ring size must be greater than or equal to the busy poll batch size * number of threads"
    );

    // Every application starts with setting up an XdpContext, this loads the XDP kernel program and attaches it to the named
    // interface.
    let mut xdp_ctx = XdpContext::new(&args.if_name, args.attach_mode, args.enable_fragmentation)
        .expect("Failed to create xdp context");

    // A Umem is created to manage sharing memory buffers between the kernel and user space.
    // You will need one of these for each unique device you want to use.
    //
    // Each Umem comes associated with three key components:
    // - Owner (umem) > The owner of the UMEM, this is used to create frames and is responsible for cleaning up the UMEM once all is said and done.
    // - Fill Queue (fq) > Used to pass frames from user space to the kernel for reading packet data into.
    // - Completion Queue (cq) > Used to retrieve frames from the kernel after transmission finishes.
    let (umem, mut fq, _cq) = Umem::builder()
        .completion_ring_size(args.completion_ring_size)
        .fill_ring_size(args.fill_ring_size)
        .frame_size(args.frame_size)
        .busy_poll(args.busy_poll)
        .num_frames(args.fill_ring_size as usize) // We are benching reads so just set the num frames to the fill ring size.
        .huge_tables(args.huge_tables)
        .unaligned(args.unaligned)
        .build()
        .expect("Failed to create umem");

    let exit = Arc::new(AtomicBool::new(false));
    ctrlc::set_handler({
        let exit = exit.clone();
        move || {
            exit.store(true, Ordering::Relaxed);
        }
    })
    .expect("Error setting Ctrl-C handler");

    let mut frames = umem.init_buffer::<BasicFrameBuffer>().unwrap();
    fq.process_queue(&mut frames);

    let frame_stack = Arc::new(Mutex::new(frames));

    let mut threads = Vec::with_capacity(args.num_threads.get() + 1);
    let mut socket_fds = Vec::with_capacity(args.num_threads.get());

    for i in 0..args.num_threads.get() {
        let exit = exit.clone();
        let stats = Stats::new_with_id(i);
        let frame_stack = frame_stack.clone();
        let batch_size = args.busy_poll_batch_size;

        // A socket represents a standard means of reading/writing packets from/to a network interface.
        //
        // This is the main handle for interacting with the network data, if needed this can be split into its owner, rx, and tx
        // components using the split() function.
        let socket = Socket::builder(&mut xdp_ctx, &args.if_name, args.queue)
            .rx_ring_size(args.rx_ring_size)
            .tx_ring_size(args.tx_ring_size)
            .busy_poll(args.busy_poll)
            .busy_poll_batch_size(args.busy_poll_batch_size)
            .busy_poll_timeout_us(args.busy_poll_timeout_us)
            .copy_mode(args.copy_mode)
            .build(umem.clone())
            .expect("Failed to create socket");
        socket_fds.push(socket.fd());

        // Spawn our worker thread, this will handle pulling frames from the rx ring and processing them.
        let thread = tokio::spawn(worker_task(exit, stats, socket, frame_stack, batch_size));
        threads.push(thread);
    }

    // Spawn our Umem thread, this will handle actually submitting frames to the fill queue.
    threads.push(tokio::spawn(umem_task(exit, fq, frame_stack, socket_fds)));

    println!("All threads created, listening for packets...");

    // Wait for exit of all threads.
    for thread in threads.drain(..) {
        thread.await.unwrap();
    }
}
