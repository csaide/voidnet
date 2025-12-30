use std::{
    ops::{Deref, DerefMut},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use clap::Parser;

mod common;
use common::{BaseArgs, Stats};
use libvoid::xdp::{context::XdpContext, frame::LocalFrameBuffer, socket::Socket, umem::Umem};

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
        .shared_umem(false)
        .build(umem, &mut fq, &mut cq)
        .expect("Failed to create socket");

    let exit = Arc::new(AtomicBool::new(false));
    ctrlc::set_handler({
        let exit = exit.clone();
        move || {
            exit.store(true, Ordering::Relaxed);
        }
    })
    .expect("Error setting Ctrl-C handler");

    fq.process_queue_async(&mut frames, socket.fd())
        .await
        .unwrap();

    while !exit.load(Ordering::Relaxed) {
        let received = socket.rx().recv_async(&mut frames).await;
        debug_assert!(
            received > 0 && received <= args.busy_poll_batch_size as u32,
            "Received more frames than the batch size or 0 frames, this should never happen!"
        );

        for frame in frames.iter() {
            stats.update(frame.len(), frame.is_fragment());
        }

        fq.process_queue_async(&mut frames, socket.fd())
            .await
            .unwrap();

        stats.maybe_print();
    }
}
