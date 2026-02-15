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

use libc::c_int;
use libvoid::xdp::{
    context::XdpContext,
    frame::{BasicFrameBuffer, FrameBuffer},
    socket::Socket,
    umem::Umem,
};

mod common;
use common::{BaseArgs, Stats};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(flatten)]
    base: BaseArgs,
    #[arg(short, long, default_value = "1")]
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

fn worker_thread<'umem>(
    exit: Arc<AtomicBool>,
    mut stats: Stats,
    frame_stack: Arc<Mutex<BasicFrameBuffer<'umem>>>,
    mut socket: Socket<'umem>,
    batch_size: usize,
) {
    let mut frames = BasicFrameBuffer::new(batch_size);
    while !exit.load(Ordering::Relaxed) {
        // Read some frames from the socket.
        //
        // This will return with 1 > N frames in the success case, as soon as possible. If there are no frames it will return an error,
        // at this point we would have blocked so a retry is necessary this is left for the caller to handle.
        match socket.recv(&mut frames) {
            Ok(received) => {
                // We received some number of frames (more than 0), up to the size of our supplied buffer, from the kernel.
                debug_assert!(
                    received > 0 && received <= batch_size as u32,
                    "Received more frames than the batch size or 0 frames, this should never happen!"
                );
            }
            Err(_) => {
                // We would have blocked, loop back and try again.
                continue;
            }
        };

        // You know have a batch of raw frames, at this level this is a full L2 frame, almost assuredly an Ethernet frame.
        for frame in frames.iter_frames() {
            // Do something with the frame!
            //
            // Note checking the frame.is_fragment() is needed, iff we have fragmentation enabled. In this mode it is possible
            // to receive a fragment of a packat if the MTU of the device is larger than the frame size.
            stats.update(frame.len(), frame.is_fragment());
        }

        // Now we need to give back the frames to the kernel so hand them back to the main umem frame stack,
        // the Umem thread will handle the heavy lifting of submitting them to the fill queue.
        {
            let mut guard = frame_stack.lock().unwrap();
            for frame in frames.drain(..) {
                guard.push(frame);
            }
        }

        stats.maybe_print();
    }
}

fn umem_thread<'umem>(
    exit: Arc<AtomicBool>,
    mut umem: Umem<'umem>,
    frame_stack: Arc<Mutex<BasicFrameBuffer<'umem>>>,
    fds: Vec<c_int>,
) {
    while !exit.load(Ordering::Relaxed) {
        for fd in fds.iter() {
            umem.maybe_wake_fill_queue(*fd).unwrap();
        }

        {
            let guard = frame_stack.lock().unwrap();
            umem.process_fill_queue(guard);
        }
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
    let mut umem = Umem::builder()
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

    // For reads to work we need to hand some buffers to the kernel, so it can start reading data into them.
    // Process the frame buffer, this will consume the entire buffer and submit them to the fill queue.
    let mut frames = umem.init_buffer::<BasicFrameBuffer>().unwrap();
    umem.process_fill_queue(&mut frames);

    // Since we are going to be using multiple threads, we need to wrap up our frame stack in a arc/mutex to
    // share it between the workers and umem threads
    let frame_stack = Arc::new(Mutex::new(frames));

    // Create some backing collections so we can join our threads and pass off the socket descriptors to the
    // umem thread. This is needed so we can wake the kernel if needed when submitting frames to the fill queue.
    let mut threads = Vec::with_capacity(args.num_threads.get() + 1);
    let mut socket_fds = Vec::with_capacity(args.num_threads.get());
    for i in 0..args.num_threads.get() {
        let exit = exit.clone();
        let stats = Stats::new_with_id(i);
        let frame_stack = frame_stack.clone();
        let batch_size = args.busy_poll_batch_size;

        // Create a new socket for each thread, in this case passing in the already created umem instance.
        let socket = Socket::builder(&args.if_name, args.queue)
            .rx_ring_size(args.rx_ring_size)
            .tx_ring_size(args.tx_ring_size)
            .busy_poll(args.busy_poll)
            .busy_poll_batch_size(args.busy_poll_batch_size)
            .busy_poll_timeout_us(args.busy_poll_timeout_us)
            .copy_mode(args.copy_mode)
            .build(&mut xdp_ctx, umem.owner().clone())
            .expect("Failed to create socket");
        socket_fds.push(socket.fd());

        // Spawn our worker thread, this will handle pulling frames from the rx ring and processing them.
        let thread =
            thread::spawn(move || worker_thread(exit, stats, frame_stack, socket, batch_size));
        threads.push(thread);
    }

    // Spawn our Umem thread, this will handle actually submitting frames to the fill queue.
    threads.push(thread::spawn(move || {
        umem_thread(exit, umem, frame_stack, socket_fds)
    }));

    println!("All threads created, listening for packets...");

    // Wait for exit of all threads.
    for thread in threads.drain(..) {
        thread.join().unwrap();
    }
}
