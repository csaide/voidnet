use std::{cmp::min, collections::VecDeque, sync::Mutex};

use crate::xdp_v2::error::Result;

use super::{Frame, Mmap};

pub struct FrameStack {
    backing: Mutex<VecDeque<u64>>,
    frame_size: usize,
    mmap: Mmap,
}

impl FrameStack {
    pub fn new(num_frames: usize, frame_size: usize) -> Result<Self> {
        let mmap = Mmap::new(num_frames, frame_size)?;
        let backing = (0..num_frames)
            .map(|i| i as u64 * frame_size as u64)
            .collect();
        Ok(Self {
            backing: Mutex::new(backing),
            frame_size,
            mmap,
        })
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.mmap.as_ptr()
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.mmap.as_mut_ptr()
    }

    pub fn to_frame(&self, addr: u64, len: usize) -> Frame {
        unsafe {
            Frame::new(
                addr,
                self.mmap.as_ptr().offset(addr as isize) as *mut u8,
                len,
                self.frame_size,
            )
        }
    }

    pub fn len(&self) -> usize {
        self.backing.lock().unwrap().len()
    }

    pub fn pop_batch(&self, batch_size: usize) -> Result<Vec<Frame>> {
        let mut backing = self.backing.lock().unwrap();
        let batch_size = min(batch_size, backing.len());
        let batch = backing
            .drain(0..batch_size)
            .map(|addr| self.to_frame(addr, 0))
            .collect();
        Ok(batch)
    }

    pub fn push_frames(&self, batch: &mut Vec<Frame>) {
        let mut backing = self.backing.lock().unwrap();
        for frame in batch.drain(..) {
            backing.push_back(frame.addr());
        }
    }

    pub fn push_addrs(&self, addrs: &mut Vec<u64>) {
        let mut backing = self.backing.lock().unwrap();
        for addr in addrs.drain(..) {
            backing.push_back(addr);
        }
    }
}
