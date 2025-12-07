//! UMEM (User Memory) management for AF_XDP.
//!
//! This module provides utilities for managing the shared memory region
//! between kernel and userspace used for zero-copy packet buffers.

mod area;
mod error;
mod frame;
mod mmap;
mod umem;

pub use area::MemoryArea;
pub use error::{Error, Result};
pub use frame::Frame;
pub use mmap::Mmap;
pub use umem::Umem;
