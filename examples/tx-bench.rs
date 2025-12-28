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
use common::{BaseArgs, GeneratorArgs, Stats, build_frame};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(flatten)]
    base: BaseArgs,
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

fn main() {
    let mut stats = Stats::new();
    let args = Args::parse();

    // Every application starts with setting up an XdpContext, this loads the XDP kernel program and attaches it to the named
    // interface.
    let mut xdp_context =
        XdpContext::new(&args.if_name, args.attach_mode, args.enable_fragmentation)
            .expect("Failed to create xdp context");

    // A Umem is created to manage sharing memory buffers between the kernel and user space.
    // You will need one of these for each unique device you want to use.
    //
    // Each Umem comes associated with three key components:
    // - Fill Queue (fq) > Used to pass frames from user space to the kernel for reading packet data into.
    // - Completion Queue (cq) > Used to retrieve frames from the kernel after transmission finishes.
    // - Write Frames (write_frames) > A set of frames that are backed by the umem which can be used for immediate writes.
    let (umem, mut fq, mut cq, mut write_frames) = Umem::builder()
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
    let mut socket = Socket::builder(&mut xdp_context, &args.if_name, args.queue)
        .rx_ring_size(args.rx_ring_size)
        .tx_ring_size(args.tx_ring_size)
        .busy_poll_batch_size(args.busy_poll_batch_size)
        .busy_poll_timeout_us(args.busy_poll_timeout_us)
        .busy_poll(args.busy_poll)
        .copy_mode(args.copy_mode)
        .enable_fragmentation(args.enable_fragmentation)
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

    // Initial copy of the data into the frames.
    let data = build_frame(&args.generator);
    for frame in write_frames.iter_mut() {
        unsafe { frame.copy_from(&data) };
    }

    println!("Socket created, sending packets...");

    let frames = write_frames.len();
    while !exit.load(Ordering::Relaxed) {
        // Send the prepared frames to the socket.
        //
        // Note this will completely consume the input buffer.
        let sent = match socket.send(&mut write_frames) {
            Ok(sent) => {
                debug_assert!(
                    sent == frames as u32,
                    "Sent a different number of frames than the input buffer, this should never happen!"
                );

                stats.update_batch(sent as usize, data.len());
                sent
            }
            Err(_) => {
                // We would have blocked.
                continue;
            }
        };

        // We should have sent all the frames.
        debug_assert_eq!(
            write_frames.len(),
            0,
            "Write frames is not empty after sending, this should never happen!"
        );

        // Process any outstanding descriptors on the completion queue retrieving the sent frames.
        //
        // This should be a loop because the kernel can only transmit a limited number of frames at a time.
        while write_frames.len() < sent as usize {
            // First wake up the kernel, it may skip the wake syscall if it can, but it must always be checked.
            socket.maybe_wake().unwrap();

            // Process the writen frames, this will consume as many frames as possible from the kernel, but it
            // will be limited to the devices descriptor count.
            cq.process_queue(&mut write_frames, Some(data.len()));
        }

        stats.maybe_print();
    }
}
