//! Frame buffer abstractions for AF_XDP frames.
//!
//! This module provides producer and consumer interfaces for managing
//! the fill and completion queues used in AF_XDP packet processing.

mod basic;
mod buffer;
mod frame;

pub use basic::BasicFrameBuffer;
pub use buffer::FrameBuffer;
pub use frame::Frame;
