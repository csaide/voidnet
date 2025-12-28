use std::{
    collections::VecDeque,
    ops::{Deref, DerefMut},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use clap::Parser;

use libvoid::xdp::{context::XdpContext, frame::Frame, socket::Socket, umem::Umem};

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

fn main() {
    let mut stats = Stats::new();
    let args = Args::parse();

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
    // - Frames (frames) > A set of frames that are backed by the umem which are shared between the kernel and user space.
    let (umem, mut fq, mut cq, mut frames) = Umem::builder()
        .completion_ring_size(args.completion_ring_size)
        .fill_ring_size(args.fill_ring_size)
        .frame_size(args.frame_size)
        .busy_poll(args.busy_poll)
        .num_frames(args.busy_poll_batch_size)
        .huge_tables(args.huge_tables)
        .build::<VecDeque<Frame>>()
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
        .shared_umem(false)
        .build(umem, &mut fq, &mut cq)
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
    fq.maybe_wake(socket.fd()).unwrap();

    // Process the frame buffer, this will consume the entire buffer and submit them to the fill queue.
    fq.process_queue(&mut frames);

    // Loop forever reading packets from the socket.
    while !exit.load(Ordering::Relaxed) {
        // Read some frames from the socket.
        //
        // This will return with 1 > N frames in the success case, as soon as possible. If there are no frames it will return an error,
        // at this point we would have blocked so a retry is necessary this is left for the caller to handle.
        match socket.recv(&mut frames) {
            Ok(received) => {
                // We received some number of frames (more than 0), up to the size of our supplied buffer, from the kernel.
                debug_assert!(
                    received > 0 && received <= args.busy_poll_batch_size as u32,
                    "Received more frames than the batch size or 0 frames, this should never happen!"
                );
            }
            Err(_) => {
                // We would have blocked, loop back and try again.
                continue;
            }
        };

        // You know have a batch of raw frames, at this level this is a full L2 frame, almost assuredly a Ethernet frame.
        for frame in frames.iter() {
            // Do something with the frame!
            stats.update(frame.len(), frame.is_fragment());
        }

        // Now we need to give back the frames to the kernel by means of the fill queue.

        // First wake up the kernel, it may skip the wake syscall if it can, but it must always be checked.
        fq.maybe_wake(socket.fd()).unwrap();

        // Process the frame buffer, this will consume the entire buffer and submit them to the fill queue.
        fq.process_queue(&mut frames);
        debug_assert_eq!(
            frames.len(),
            0,
            "Frame buffer is not empty after processing, this should never happen!"
        );

        stats.maybe_print();
    }
}
