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
    let args = Args::parse();

    // Every application starts with setting up an XdpContext, this loads the XDP kernel program and attaches it to the named interface.
    let mut xdp_ctx = XdpContext::new(&args.if_name, args.attach_mode, args.enable_fragmentation)
        .expect("Failed to create xdp context");

    // A Umem is created to manage sharing memory buffers between the kernel and user space.
    // You will need one of these for each unique device you want to use.
    //
    // - umem > The actual umem object sharing memory between the kernel and user space.
    // - fq > The fill queue is used to pass frames to the kernel for reading packet data into.
    // - cq > The completion queue is used to retrieve frames the kernel is done sending.
    // - write_frames > A set of frames that are backed by the umem which can be used for immediate writes.
    let (umem, mut fq, mut cq, mut _write_frames) = Umem::builder()
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
        .enable_fragmentation(args.enable_fragmentation)
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
    let mut frames = VecDeque::with_capacity(args.busy_poll_batch_size);
    while !exit.load(Ordering::Relaxed) {
        // First read some frames off the socket.
        let received = match socket.recv(&mut frames) {
            Ok(received) => received,
            Err(()) => {
                // There were no frames available to read, wake the fill queue and process any outstanding descriptors.
                continue;
            }
        };

        // Guaranteed by the socket.recv() function, given an empty input buffer.
        debug_assert_eq!(frames.len(), received as usize);

        // For each received frame, attempt to swap the addresses.
        for mut frame in frames.iter_mut() {
            stats.update(frame.len());

            swap_addresses(&mut frame).unwrap();
        }

        // Send the updated frames to the socket.
        let _ = socket.send(&mut frames);

        // Send will always fully consume the input buffer, so we should have no frames left.
        debug_assert_eq!(frames.len(), 0);

        // So we "sent" the packets but now we need to actually drive the completion of those sends.
        while frames.len() < received as usize {
            socket.maybe_wake().expect("Failed to wake tx queue");
            cq.process_queue(&mut frames, None);
        }

        // Now give back all our frames to the kernel by means of the fill queue.
        fq.maybe_wake(socket.fd()).unwrap();
        fq.process_queue(&mut frames);

        stats.maybe_print();
    }

    println!("Exiting...");
}
