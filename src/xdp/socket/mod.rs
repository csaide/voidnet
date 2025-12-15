//! AF_XDP socket abstraction for zero-copy networking.
//!
//! This module provides high-level wrappers around Linux AF_XDP sockets,
//! enabling async/await support for packet I/O operations.

mod rx;
mod socket;
mod tx;

pub use rx::SocketRx;
pub use socket::{Socket, SocketBuilder, SocketOwner};
pub use tx::SocketTx;
