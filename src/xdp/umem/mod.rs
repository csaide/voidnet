//! UMEM abstractions for AF_XDP packet processing.
//!
//! This module provides a builder for creating a new UMEM instance, as well as a high level wrapper around the UMEM instance.

mod comp;
mod fill;
mod owner;
mod umem;

pub use comp::CompletionQueue;
pub use fill::FillQueue;
pub use owner::UmemOwner;
pub use umem::{Umem, UmemBuilder};
