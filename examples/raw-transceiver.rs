use std::{
    ops::{Deref, DerefMut},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use clap::Parser;

use libvoid::{
    raw::RawTransceiver,
    xdp::{
        context::XdpContext,
        frame::{BasicFrameBuffer, FrameBuffer},
    },
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

#[inline(always)]
fn handler<'umem, 'buffer, T: FrameBuffer<'umem>>(frames: T::IterMut<'buffer>, stats: &mut Stats) {
    for frame in frames {
        stats.update(frame.len(), frame.is_fragment());
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

    let mut reciever = RawTransceiver::<BasicFrameBuffer>::builder(&args.if_name, args.queue)
        .rx_ring_size(args.rx_ring_size)
        .tx_ring_size(args.tx_ring_size)
        .busy_poll(args.busy_poll)
        .busy_poll_batch_size(args.busy_poll_batch_size)
        .busy_poll_timeout_us(args.busy_poll_timeout_us)
        .copy_mode(args.copy_mode)
        .enable_fragmentation(args.enable_fragmentation)
        .completion_ring_size(args.completion_ring_size)
        .fill_ring_size(args.fill_ring_size)
        .frame_size(args.frame_size)
        .busy_poll(args.busy_poll)
        .num_frames(args.busy_poll_batch_size)
        .huge_tables(args.huge_tables)
        .unaligned(args.unaligned)
        .build::<BasicFrameBuffer>(&mut xdp_ctx)
        .expect("Failed to create receiver");

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

    // Loop forever reading packets from the socket.
    while !exit.load(Ordering::Relaxed) {
        if let Ok(_) = reciever.echo(|frames| handler::<BasicFrameBuffer>(frames, &mut stats)) {
            stats.maybe_print();
        }
    }
}
