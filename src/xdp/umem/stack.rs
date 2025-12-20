use std::cell::UnsafeCell;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crossbeam::queue::ArrayQueue;

use crate::xdp::error::{Error, Result};

pub trait Stack {
    fn pop(&self) -> Option<u64>;
    fn push(&self, addr: u64) -> Result<()>;
}

impl Stack for FrameStack {
    #[inline(always)]
    fn pop(&self) -> Option<u64> {
        self.pop()
    }

    #[inline(always)]
    fn push(&self, addr: u64) -> Result<()> {
        self.push(addr)
    }
}

impl Stack for LockingFrameStack {
    #[inline(always)]
    fn pop(&self) -> Option<u64> {
        self.pop()
    }
    #[inline(always)]
    fn push(&self, addr: u64) -> Result<()> {
        self.push(addr)
    }
}

impl Stack for ThreadLocalFrameStack {
    #[inline(always)]
    fn pop(&self) -> Option<u64> {
        self.pop()
    }
    #[inline(always)]
    fn push(&self, addr: u64) -> Result<()> {
        self.push(addr)
    }
}

impl Stack for UnsafeFrameStack {
    #[inline(always)]
    fn pop(&self) -> Option<u64> {
        self.pop()
    }
    #[inline(always)]
    fn push(&self, addr: u64) -> Result<()> {
        self.push(addr)
    }
}

impl Stack for CrossbeamFrameStack {
    #[inline(always)]
    fn pop(&self) -> Option<u64> {
        self.pop()
    }
    #[inline(always)]
    fn push(&self, addr: u64) -> Result<()> {
        self.push(addr)
    }
}

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

    /// Returns the length of the stack.
    #[inline]
    pub fn len(&self) -> usize {
        self.backing.len() - self.loc.load(Ordering::Acquire)
    }

    /// Returns the next frame from the stack, if the stack is empty, it will return None.
    #[inline]
    pub fn pop(&self) -> Option<u64> {
        loop {
            let loc = self.loc.load(Ordering::Relaxed);
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
            let loc = self.loc.load(Ordering::Relaxed);
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

#[derive(Debug)]
pub struct LockingFrameStack {
    backing: Mutex<Vec<u64>>,
}

impl LockingFrameStack {
    pub fn new(num_frames: usize, frame_size: usize) -> LockingFrameStack {
        let backing = Mutex::new(
            (0..num_frames)
                .map(|i| i as u64 * frame_size as u64)
                .collect(),
        );
        Self { backing }
    }

    #[inline]
    pub fn pop(&self) -> Option<u64> {
        let mut backing = self.backing.lock().unwrap();
        backing.pop()
    }

    #[inline]
    pub fn push(&self, addr: u64) -> Result<()> {
        let mut backing = self.backing.lock().unwrap();
        if backing.len() == backing.capacity() {
            return Err(Error::StackFull);
        }

        backing.push(addr);
        Ok(())
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

pub struct UnsafeFrameStack {
    backing: Vec<UnsafeCell<u64>>,
    loc: AtomicUsize,
}

unsafe impl Send for UnsafeFrameStack {}
unsafe impl Sync for UnsafeFrameStack {}

impl UnsafeFrameStack {
    pub fn new(num_frames: usize, frame_size: usize) -> UnsafeFrameStack {
        let backing = (0..num_frames)
            .map(|i| UnsafeCell::new(i as u64 * frame_size as u64))
            .collect();
        Self {
            backing,
            loc: AtomicUsize::new(0),
        }
    }

    /// Returns the next frame from the stack, if the stack is empty, it will return None.
    #[inline]
    pub fn pop(&self) -> Option<u64> {
        loop {
            let loc = self.loc.load(Ordering::Relaxed);
            if loc >= self.backing.len() {
                return None;
            }

            if self
                .loc
                .compare_exchange(loc, loc + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return Some(unsafe { *self.backing[loc].get() });
            }
        }
    }

    /// Pushes a new frame onto the stack, if the stack is full, it will return an error.
    #[inline]
    pub fn push(&self, addr: u64) -> Result<()> {
        loop {
            let loc = self.loc.load(Ordering::Relaxed);
            if loc == 0 {
                return Err(Error::StackFull);
            }

            if self
                .loc
                .compare_exchange(loc, loc - 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                unsafe { *self.backing[loc - 1].get() = addr };
                return Ok(());
            }
        }
    }
}

pub struct CrossbeamFrameStack {
    stack: ArrayQueue<u64>,
}

impl CrossbeamFrameStack {
    pub fn new(num_frames: usize, frame_size: usize) -> Self {
        let stack = ArrayQueue::new(num_frames);
        for i in 0..num_frames {
            let addr = i as u64 * frame_size as u64;
            stack.push(addr).unwrap();
        }
        Self { stack }
    }

    pub fn pop(&self) -> Option<u64> {
        self.stack.pop()
    }

    pub fn push(&self, value: u64) -> Result<()> {
        self.stack.push(value).map_err(|_| Error::StackFull)
    }
}
