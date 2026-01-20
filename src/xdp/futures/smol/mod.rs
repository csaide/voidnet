//! Smol executor futures for AF_XDP.
//!
//! This module provides futures for the [Smol] runtime, and associated types for working with the XDP subsystem.
//!
//! [Smol]: smol

mod comp;
mod fd;
mod fill;
mod recv;
mod send;
mod socket;
mod umem;

pub use comp::{SmolCompFuture, SmolCompletionQueue};
pub use fd::{SmolFd, SmolFdFactory};
pub use fill::{SmolFillFuture, SmolFillQueue};
pub use recv::{SmolRecvFuture, SmolSocketRx};
pub use send::{SmolSendFuture, SmolSocketTx};
pub use socket::SmolSocket;
pub use umem::SmolUmem;
