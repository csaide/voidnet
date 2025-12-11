use memmap2::{MmapMut, MmapOptions};

use super::{Error, Result};

/// A wrapper around a [MmapMut] that is used to store data for a packet.
pub struct Mmap {
    map: MmapMut,
    frame_size: usize,
    num_frames: usize,
}

impl Mmap {
    /// Creates a new [Mmap] with the given number of frames and frame size.
    pub fn new(num_frames: usize, frame_size: usize) -> Result<Self> {
        let map = MmapOptions::new()
            .len(num_frames * frame_size)
            .map_anon()
            .map_err(|e| Error::MmapAllocate(e))?;

        Ok(Self {
            map,
            frame_size,
            num_frames,
        })
    }

    /// Returns the size of each frame in the mmap.
    #[inline]
    pub fn frame_size(&self) -> usize {
        self.frame_size
    }

    /// Returns the number of frames in the mmap.
    #[inline]
    pub fn num_frames(&self) -> usize {
        self.num_frames
    }

    /// Returns a pointer to the start of the mmap.
    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        self.map.as_ptr()
    }

    /// Returns a mutable pointer to the start of the mmap.
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.map.as_mut_ptr()
    }
}
