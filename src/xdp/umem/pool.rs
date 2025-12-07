use std::os::raw::c_void;

use crate::xdp::umem::Frame;

pub trait MemoryPool {
    fn get_frame(&mut self, addr: u64, len: usize) -> Frame<'_>;
    fn frame_size(&self) -> usize;
    fn num_frames(&self) -> usize;
    fn as_ptr(&mut self) -> *mut c_void;
}
