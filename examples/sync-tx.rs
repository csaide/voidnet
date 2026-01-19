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
    let mut xdp_context = XdpContext::builder(&args.if_name)
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
    let mut umem = Umem::builder(&mut xdp_context)
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
    let mut socket = Socket::builder(&mut xdp_context, &args.if_name, args.queue)
        .rx_ring_size(args.rx_ring_size)
        .tx_ring_size(args.tx_ring_size)
        .busy_poll_batch_size(args.busy_poll_batch_size)
        .busy_poll_timeout_us(args.busy_poll_timeout_us)
        .busy_poll(args.busy_poll)
        .copy_mode(args.copy_mode)
        .enable_fragmentation(args.enable_fragmentation)
        .build(umem.owner().clone())
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

    // Generate our mock UDP packet to send.
    let packet_data = build_frame(&args.generator);

    println!("Socket created, sending packets...");
    let mut write_frames = umem.init_buffer::<BasicFrameBuffer>().unwrap();
    let frames = write_frames.num_frames();
    while !exit.load(Ordering::Relaxed) {
        // Copy the data into the frames, this is intentionally in the loop to show performance of a real world application.
        // Since generally at some point a copy into the frame is needed from userspace, how this copy is done is up to the caller.
        //
        // Note: Technically the frames SHOULD be untouched after each iteration, so in theory if the frame size/fragmentation is known
        // here you can just set the frame metadata and avoid the copy if done outside the loop and you are simply re-sending the same
        // data.... But be ware this is where dragons live...
        for frame in write_frames.iter_frames_mut() {
            frame.copy_from(&packet_data);
        }

        // Send the prepared frames to the socket.
        //
        // Note this will completely consume the input buffer.
        match socket.send(&mut write_frames) {
            Ok(sent) => {
                debug_assert!(
                    sent == frames as u32,
                    "Sent a different number of frames than the input buffer, this should never happen!"
                );

                stats.update_batch(sent as usize, packet_data.len());
            }
            Err(_) => {
                // We would have blocked.
                continue;
            }
        };

        // Process any outstanding descriptors on the completion queue retrieving the sent frames.
        //
        // This should be a loop because the kernel can only transmit a limited number of frames at a time.
        while let Err(_) = umem.process_completion_queue(&mut write_frames) {
            socket.maybe_wake().expect("Failed to wake tx queue");
        }

        stats.maybe_print();
    }
}
