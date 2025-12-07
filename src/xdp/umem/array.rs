use std::os::raw::c_void;

use crate::xdp::umem::MemoryPool;

use super::Frame;

#[derive(Debug)]
pub struct Array {
    frame_size: usize,
    num_frames: usize,
    backing: Vec<u8>,
}

impl Array {
    pub fn new(num_frames: usize, frame_size: usize) -> Self {
        debug_assert!(
            num_frames > 0 && frame_size > 0,
            "num_frames and frame_size must be greater than 0"
        );

        debug_assert!(
            num_frames * frame_size <= usize::MAX,
            "num_frames * frame_size must be less than or equal to the maximum usize value"
        );

        Self {
            backing: vec![0; num_frames * frame_size],
            num_frames,
            frame_size,
        }
    }
}

impl MemoryPool for Array {
    fn get_frame(&mut self, addr: u64, len: usize) -> Frame<'_> {
        unsafe {
            Frame::new_with_len(
                addr,
                self.backing.as_mut_ptr().offset(addr as isize),
                len,
                self.frame_size,
            )
        }
    }

    fn frame_size(&self) -> usize {
        self.frame_size
    }

    fn num_frames(&self) -> usize {
        self.num_frames
    }

    fn as_ptr(&mut self) -> *mut c_void {
        self.backing.as_mut_ptr() as *mut c_void
    }
}
