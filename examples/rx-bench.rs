use std::{
    collections::VecDeque,
    ops::{Deref, DerefMut},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use clap::Parser;

use libvoid::xdp::{context::XdpContext, socket::Socket, umem::Umem};

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
    let args = Args::parse();

    // Every XDP program starts with setting up an XdpContext, this loads the XDP kernel program and attaches it to the named interface.
    let mut xdp_ctx = XdpContext::new(&args.if_name, args.attach_mode, args.enable_fragmentation)
        .expect("Failed to create xdp context");

    // A Umem is created to manage sharing memory buffers between the kernel and user space.
    // You will need one of these for each unique device you want to use, you can however have multiple
    // sockets attached to the same Umem.
    let (umem, mut fq, _cq, _write_frames) = Umem::builder()
        .completion_ring_size(args.completion_ring_size)
        .fill_ring_size(args.fill_ring_size)
        .frame_size(args.frame_size)
        .busy_poll(args.busy_poll)
        .build()
        .expect("Failed to create umem");

    // A socket represents a standard means of reading/writing packets from/to a network interface.
    let mut socket = Socket::builder(&mut xdp_ctx, &args.if_name, args.queue)
        .rx_ring_size(args.rx_ring_size)
        .tx_ring_size(args.tx_ring_size)
        .busy_poll(args.busy_poll)
        .busy_poll_batch_size(args.busy_poll_batch_size)
        .busy_poll_timout_us(args.busy_poll_timout_us)
        .copy_mode(args.copy_mode)
        .build(umem)
        .expect("Failed to create socket");

    // Setup some maintenance logic so we are good stewards and ensure we clean up.
    //
    // Note: if the XdpContext isn't safely dropped (destructor run) then the interface will retain
    // the XDP program attached to it, breaking things in weird ways.... cleanup is important :).
    let exit = Arc::new(AtomicBool::new(false));
    ctrlc::set_handler({
        let exit = exit.clone();
        move || {
            exit.store(true, Ordering::Relaxed);
        }
    })
    .expect("Error setting Ctrl-C handler");

    println!("Socket created, listening for packets...");

    // Setup some stats to track the number of packets and bytes received.
    let mut stats = Stats::new();
    let mut frame_buffer = VecDeque::with_capacity(args.busy_poll_batch_size);
    while !exit.load(Ordering::Relaxed) {
        // This is different than what you might expect, since we are using a Umem we don't specify buffers to fill
        // during recv() instead we request a batch up to a maximum size to read at a time.
        //
        // If no frames are available to read this returns an error of type [Error::WouldBlock]. All other errors are considered fatal.
        match socket.recv(&mut frame_buffer) {
            Ok(_) => {}
            Err(()) => {}
        };

        for frame in frame_buffer.iter() {
            // Do something with the frame!
            stats.update(frame.len());
        }

        fq.maybe_wake(socket.fd()).unwrap();
        fq.process_queue(&mut frame_buffer);

        stats.maybe_print();
    }

    println!("Exiting...");
}
