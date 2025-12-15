//! Ring buffer abstractions for AF_XDP queues.
//!
//! This module provides producer and consumer interfaces for managing
//! the fill and completion queues used in AF_XDP packet processing.

mod consumer;
mod producer;

pub use consumer::Consumer;
pub use producer::Producer;
