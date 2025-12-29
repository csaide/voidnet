//! Frame buffer abstractions for AF_XDP frames.
//!
//! This module provides producer and consumer interfaces for managing
//! the fill and completion queues used in AF_XDP packet processing.

use super::Frame;

mod buffer;
mod local;

pub use buffer::{FrameBuffer, FrameBufferBuilder};
pub use local::LocalFrameBuffer;
