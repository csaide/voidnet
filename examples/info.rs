use std::ops::{Deref, DerefMut};

use clap::Parser;

use libvoid::xdp::context::XdpContext;

mod common;
use common::BaseArgs;

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

    // Every application starts with setting up an XdpContext, this loads the XDP kernel program and attaches it to the named
    // interface.
    let xdp_ctx = XdpContext::builder(&args.if_name)
        .attach_mode(args.attach_mode)
        .enable_fragmentation(args.enable_fragmentation)
        .build()
        .expect("Failed to create xdp context");

    println!("XDP info: {:?}", xdp_ctx.info());
}
