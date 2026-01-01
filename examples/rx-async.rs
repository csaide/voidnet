use std::{
    ops::{Deref, DerefMut},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use clap::Parser;

use libvoid::xdp::{
    context::XdpContext,
    frame::{FrameBuffer, LocalFrameBuffer},
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

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let mut stats = Stats::new();
    let args = Args::parse();

    // We are relying on this invariant in the benchmark code bellow, though to be absolutely clear this isn't
    // actually a requirement, in the XDP subsystem itself, though its HIGHLY encouraged.
    debug_assert!(
        args.fill_ring_size >= args.busy_poll_batch_size as u32,
        "Fill ring size must be greater than or equal to the busy poll batch size"
    );

    // Every application starts with setting up an XdpContext, this loads the XDP kernel program and attaches it to the named
    // interface.
    let mut xdp_ctx = XdpContext::new(&args.if_name, args.attach_mode, args.enable_fragmentation)
        .expect("Failed to create xdp context");

    // A Umem is created to manage sharing memory buffers between the kernel and user space.
    // You will need one of these for each unique device you want to use.
    //
    // Each Umem comes associated with three key components:
    // - Fill Queue (fq) > Used to pass frames from user space to the kernel for reading packet data into.
    // - Completion Queue (cq) > Used to retrieve frames from the kernel after transmission finishes.
    // - Frames (initial_frames) > A set of frames that are backed by the umem which are shared between the kernel and user space.
    //
    // Note: The initial frames can be used for anything you need. Namely there are a few key use cases:
    // - Listeners/Traffic Analyzers: Dump all, or some number, of frames into the fill ring to prewarm the ring for reads.
    // - Clients/Traffic Generators: Using them as a pool of buffers for writing packet data to, and sending it out the socket.
    let (mut umem, mut initial_frames) = Umem::builder()
        .completion_ring_size(args.completion_ring_size)
        .fill_ring_size(args.fill_ring_size)
        .frame_size(args.frame_size)
        .busy_poll(args.busy_poll)
        .num_frames(args.fill_ring_size as usize) // We are benching reads so just set the num frames to the fill ring size.
        .huge_tables(args.huge_tables)
        .unaligned(args.unaligned)
        .build::<LocalFrameBuffer>()
        .expect("Failed to create umem");

    // A socket represents a standard means of reading/writing packets from/to a network interface.
    //
    // This is the main handle for interacting with the network data, if needed this can be split into its owner, rx, and tx
    // components using the split() function.
    let mut socket = Socket::builder(&mut xdp_ctx, &args.if_name, args.queue)
        .rx_ring_size(args.rx_ring_size)
        .tx_ring_size(args.tx_ring_size)
        .busy_poll(args.busy_poll)
        .busy_poll_batch_size(args.busy_poll_batch_size)
        .busy_poll_timeout_us(args.busy_poll_timeout_us)
        .copy_mode(args.copy_mode)
        .build(&mut umem)
        .expect("Failed to create socket");

    let exit = Arc::new(AtomicBool::new(false));
    ctrlc::set_handler({
        let exit = exit.clone();
        move || {
            exit.store(true, Ordering::Relaxed);
        }
    })
    .expect("Error setting Ctrl-C handler");

    // We are benchmarking receive throughput so lets give all of our frames to the kernel.
    //
    // This is where the first part of the invariant above comes into play because our num_frames is the same as the fill ring size,
    // the initial_frames buffer will be empty at the end of this call.
    umem.process_fill_queue_async(&mut initial_frames).await;

    // Create a buffer to receive frames into, in theory we could have used the [frames] object above for this usecase,
    // however this is showing that the [LocalFrameBuffer] can be used freely and is a thin wrapper around a [VecDeque] of frames.
    //
    // Due to the above invariant we know that this will be smaller than or equal to our fill ring size, so every read will read up to the full
    // capacity of this buffer, and fill calls will fully drain the buffer. As you can see this is a useful invariant to have here, and likely
    // elsewhere.
    let mut incoming = LocalFrameBuffer::new(args.busy_poll_batch_size);
    while !exit.load(Ordering::Relaxed) {
        // Start by reading some frames from the socket. The result of this call is guaranteed to be between 1 and the batch size.
        let received = socket.recv_async(&mut incoming).await;
        debug_assert!(
            received > 0 && received <= args.busy_poll_batch_size as u32,
            "Received more frames than the batch size or 0 frames, this should \
            never happen!"
        );

        // You now have a batch of raw frames, at this level this is an L2 frame, almost assuredly Ethernet based.
        for frame in incoming.iter() {
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

        // First wake up the kernel, it may skip the wake syscall if it can, but it must always be checked.
        //
        // Note: Errors here are fatal and should cause the program to exit, or reset the XDP state from scratch.
        umem.maybe_wake_async(socket.fd()).await.unwrap();

        // Process the frame buffer, this will consume the entire buffer and submit them to the fill queue.
        umem.process_fill_queue_async(&mut incoming).await;
        debug_assert_eq!(
            incoming.num_frames(),
            0,
            "Frames left after processing fill queue, this should never happen \
            unless our batch size is larger than the fill ring."
        );

        // Maybe print the stats for this iteration.
        stats.maybe_print();
    }
}
