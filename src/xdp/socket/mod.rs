//! AF_XDP socket abstraction for zero-copy networking.
//!
//! This module provides high-level wrappers around Linux AF_XDP sockets,
//! enabling async/await support for packet I/O operations.

mod error;
mod socket;

pub use error::{Error, Result};
pub use socket::{Socket, SocketBuilder};
