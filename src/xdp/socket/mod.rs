//! Socket management for AF_XDP.
//!
//! This module provides a safe API for managing XDP sockets, including creating and binding them to network interfaces.

mod mode;
mod owner;
mod rx;
mod socket;
mod tx;

pub use mode::{BindMode, CopyMode};
pub use owner::SocketOwner;
pub use rx::SocketRx;
pub use socket::{Socket, SocketBuilder};
pub use tx::SocketTx;
