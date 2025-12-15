use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::xdp::error::{Error, Result};

/// A stack of frames that are used to store data for a packet, this is a simple wrapper around a vector of atomic u64s.
#[derive(Debug)]
pub struct FrameStack {
    backing: Vec<AtomicU64>,
    loc: AtomicUsize,
}

impl FrameStack {
    /// Creates a new [FrameStack] with the given number of frames and frame size.
    pub fn new(num_frames: usize, frame_size: usize) -> FrameStack {
        let backing = (0..num_frames)
            .map(|i| AtomicU64::new(i as u64 * frame_size as u64))
            .collect();
        Self {
            backing,
            loc: AtomicUsize::new(0),
        }
    }

    /// Returns the number of frames in the stack that are ready to be used.
    #[inline]
    pub fn len(&self) -> usize {
        self.backing.len() - self.loc.load(Ordering::Acquire)
    }

    /// Returns the number of frames that the stack can take in before it is full.
    #[inline]
    pub fn free_space(&self) -> usize {
        self.loc.load(Ordering::Acquire)
    }

    /// Returns the next frame from the stack, if the stack is empty, it will return None.
    #[inline]
    pub fn pop(&self) -> Option<u64> {
        loop {
            let loc = self.loc.load(Ordering::Acquire);
            if loc >= self.backing.len() {
                return None;
            }

            if self
                .loc
                .compare_exchange(loc, loc + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return Some(self.backing[loc].load(Ordering::Acquire));
            }
        }
    }

    /// Pushes a new frame onto the stack, if the stack is full, it will return an error.
    #[inline]
    pub fn push(&self, addr: u64) -> Result<()> {
        loop {
            let loc = self.loc.load(Ordering::Acquire);
            if loc == 0 {
                return Err(Error::StackFull);
            }

            if self
                .loc
                .compare_exchange(loc, loc - 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                self.backing[loc - 1].store(addr, Ordering::Release);
                return Ok(());
            }
        }
    }
}

/// A non-thread-safe stack of frames that are used to store data for a packet.
/// This is a simple wrapper around a vector of u64s.
///
/// This implementation provides the same interface as [FrameStack] but without
/// thread-safety guarantees. It should only be used in single-threaded contexts.
#[derive(Debug)]
pub struct ThreadLocalFrameStack {
    backing: Vec<UnsafeCell<u64>>,
    loc: UnsafeCell<usize>,
}

impl ThreadLocalFrameStack {
    /// Creates a new [ThreadLocalFrameStack] with the given number of frames and frame size.
    pub fn new(num_frames: usize, frame_size: usize) -> ThreadLocalFrameStack {
        let backing = (0..num_frames)
            .map(|i| UnsafeCell::new(i as u64 * frame_size as u64))
            .collect();
        Self {
            backing,
            loc: UnsafeCell::new(0),
        }
    }

    /// Returns the number of frames in the stack that are ready to be used.
    #[inline]
    pub fn len(&self) -> usize {
        self.backing.len() - unsafe { *self.loc.get() }
    }

    /// Returns the number of frames that the stack can take in before it is full.
    #[inline]
    pub fn free_space(&self) -> usize {
        unsafe { *self.loc.get() }
    }

    /// Returns the next frame from the stack, if the stack is empty, it will return None.
    #[inline]
    pub fn pop(&self) -> Option<u64> {
        unsafe {
            let loc = *self.loc.get();
            if loc >= self.backing.len() {
                return None;
            }
            let frame = *self.backing[loc].get();
            *self.loc.get() = loc + 1;
            Some(frame)
        }
    }

    /// Pushes a new frame onto the stack, if the stack is full, it will return an error.
    #[inline]
    pub fn push(&self, addr: u64) -> Result<()> {
        unsafe {
            let loc = *self.loc.get();
            if loc == 0 {
                return Err(Error::StackFull);
            }
            *self.backing[loc - 1].get() = addr;
            *self.loc.get() = loc - 1;
            Ok(())
        }
    }
}
