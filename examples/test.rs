use std::mem::size_of;

use libvoid::xdp::frame::Frame;

fn main() {
    println!("Frame size: {} bytes", size_of::<Frame<'_>>());
    println!("u64 size: {} bytes", size_of::<u64>());
    println!("usize size: {} bytes", size_of::<usize>());
    println!("bool size: {} bytes", size_of::<bool>());
    println!("data_ref size: {} bytes", size_of::<&mut [u8]>());
}
