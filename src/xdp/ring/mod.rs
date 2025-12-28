//! Ring buffer abstractions for AF_XDP queues.
//!
//! This module provides producer and consumer interfaces for managing
//! the fill and completion queues used in AF_XDP packet processing.

mod consumer;
mod producer;

/// A marker type for initialized rings.
pub struct Init;

/// A marker type for uninitialized rings.
pub struct Uninit;

pub use consumer::Consumer;
pub use producer::Producer;
