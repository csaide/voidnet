use crate::xdp::error::Result;

use super::{Frame, FrameBufferBuilder, Mmap};

pub struct FrameStack {
    frame_size: usize,
    mmap: Mmap,
}

impl FrameStack {
    pub fn new<B: FrameBufferBuilder>(
        num_frames: usize,
        frame_size: usize,
        huge_tables: bool,
    ) -> Result<(Self, B)> {
        let mmap = Mmap::new(num_frames, frame_size, huge_tables)?;
        let stack = Self { frame_size, mmap };
        let frames = B::new_buffer(
            (0..num_frames).map(|i| stack.to_frame(i as u64 * frame_size as u64, 0, false)),
        );
        Ok((stack, frames))
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.mmap.as_ptr()
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.mmap.as_mut_ptr()
    }

    pub fn to_frame(&self, addr: u64, len: usize, is_fragment: bool) -> Frame {
        unsafe {
            Frame::new(
                addr,
                self.mmap.as_ptr().offset(addr as isize) as *mut u8,
                len,
                self.frame_size,
                is_fragment,
            )
        }
    }
}
