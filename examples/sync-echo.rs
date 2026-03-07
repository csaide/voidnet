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
    error::WouldBlock,
    frame::{BasicFrameBuffer, FrameBuffer},
    socket::Socket,
    umem::Umem,
};

mod common;
use common::{BaseArgs, Stats, swap_addresses};

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

fn main() {
    let mut stats = Stats::new();
    let args = Args::parse();

    // Every application starts with setting up an XdpContext, this loads the XDP kernel program and attaches it to the named
    // interface.
    let mut xdp_ctx = XdpContext::builder(&args.if_name)
        .attach_mode(args.attach_mode)
        .enable_fragmentation(args.enable_fragmentation)
        .build()
        .expect("Failed to create xdp context");

    // A Umem is created to manage sharing memory buffers between the kernel and user space.
    // You will need one of these for each unique device you want to use.
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
        .num_frames(args.busy_poll_batch_size)
        .huge_tables(args.huge_tables)
        .unaligned(args.unaligned)
        .build()
        .expect("Failed to create umem");

    // A socket represents a standard means of reading/writing packets from/to a network interface.
    //
    // This is the main handle for interacting with the network data, if needed this can be split into its owner, rx, and tx
    // components using the split() function.
    let mut socket = Socket::builder(&args.if_name, args.queue)
        .rx_ring_size(args.rx_ring_size)
        .tx_ring_size(args.tx_ring_size)
        .busy_poll(args.busy_poll)
        .busy_poll_batch_size(args.busy_poll_batch_size)
        .busy_poll_timeout_us(args.busy_poll_timeout_us)
        .copy_mode(args.copy_mode)
        .enable_fragmentation(args.enable_fragmentation)
        .build(&mut xdp_ctx, umem.owner().clone())
        .expect("Failed to create socket");

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

    println!("Socket created, listening for packets...");

    // For reads to work we need to hand some buffers to the kernel, so it can start reading data into them.

    // First wake up the kernel, it may skip the wake syscall if it can, but it must always be checked.
    umem.maybe_wake_fill_queue(socket.fd()).unwrap();

    // Process the frame buffer, this will consume the entire buffer and submit them to the fill queue.
    let mut frames = umem.init_buffer::<BasicFrameBuffer>().unwrap();
    umem.process_fill_queue(&mut frames)
        .expect("Failed to process fill queue");

    // Loop forever reading packets from the socket.
    while !exit.load(Ordering::Relaxed) {
        // First read some frames off the socket.
        let received = match socket.recv(&mut frames) {
            Ok(received) => received,
            Err(WouldBlock) => {
                // There were no frames available to read, wake the fill queue and process any outstanding descriptors.
                continue;
            }
        };

        // Guaranteed by the socket.recv() function, given an empty input buffer.
        debug_assert_eq!(frames.num_frames(), received as usize);

        // For each received frame, attempt to swap the addresses.
        for frame in frames.iter_frames_mut() {
            stats.update(frame.len(), frame.is_fragment());

            swap_addresses(frame).unwrap();
        }

        // Send the updated frames to the socket.
        let _ = socket.send(&mut frames);

        // Send will always fully consume the input buffer, so we should have no frames left.
        debug_assert_eq!(frames.num_frames(), 0);

        // So we "sent" the packets but now we need to actually drive the completion of those sends.
        while umem.process_completion_queue(&mut frames).is_err() {
            socket.maybe_wake().expect("Failed to wake tx queue");
        }

        // Now give back all our frames to the kernel by means of the fill queue.
        umem.maybe_wake_fill_queue(socket.fd()).unwrap();
        umem.process_fill_queue(&mut frames)
            .expect("Failed to process fill queue");

        stats.maybe_print();
    }

    println!("Exiting...");
}
