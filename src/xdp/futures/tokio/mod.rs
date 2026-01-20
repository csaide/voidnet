//! Tokio executor futures for AF_XDP.
//!
//! This module provides futures for the [Tokio] runtime, and associated types for working with the XDP subsystem.
//!
//! [Tokio]: tokio

mod comp;
mod fd;
mod fill;
mod recv;
mod send;
mod socket;
mod umem;

pub use comp::{TokioCompFuture, TokioCompletionQueue};
pub use fd::TokioFdFactory;
pub use fill::{TokioFillFuture, TokioFillQueue};
pub use recv::{TokioRecvFuture, TokioSocketRx};
pub use send::{TokioSendFuture, TokioSocketTx};
pub use socket::TokioSocket;
pub use umem::TokioUmem;
