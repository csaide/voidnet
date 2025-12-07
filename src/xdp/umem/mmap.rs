use std::os::raw::c_void;

use memmap2::{MmapMut, MmapOptions};

use super::{Error, Frame, MemoryPool, Result};

pub struct Mmap {
    map: MmapMut,
    frame_size: usize,
    num_frames: usize,
}

impl Mmap {
    pub fn new(num_frames: usize, frame_size: usize) -> Result<Self> {
        let map = MmapOptions::new()
            .len(num_frames * frame_size)
            .map_anon()
            .map_err(|e| Error::Create(e))?;

        Ok(Self {
            map,
            frame_size,
            num_frames,
        })
    }
}

impl MemoryPool for Mmap {
    fn get_frame(&mut self, addr: u64, len: usize) -> Frame<'_> {
        unsafe {
            Frame::new_with_len(
                addr,
                self.map.as_mut_ptr().offset(addr as isize),
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
        self.map.as_mut_ptr() as *mut c_void
    }
}
