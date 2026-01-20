//! Local executor futures for AF_XDP.
//!
//! This module provides futures for the [LocalExecutor] executor, and associated types for working with the XDP subsystem.
//!
//! So why a local executor? The idea here is that the executor does not use normal waker semanitcs as these semantics cause significant performance overhead when dealing with cross thread synchronization.
//!
//! So this polls the given future on the local thread, sleeping on a custom epoll implementation to await for new IO events. These then drive the future to completion. Removing a
//! significant amount of overhead from the future.
//!
//! The idea here is that it colocates the I/O poller and the actual logic, this removes all needed synchronization _and_ it ensures cache coherency for the duration of the poll loop. This is the fastest possible polling implementation
//! that also leverages the full async/await semantics. A slightly faster version with polling would pull the [Poller] out of the executor and handle manual polling and execution.

mod comp;
mod executor;
mod fill;
mod poller;
mod recv;
mod send;
mod socket;
mod umem;
mod waker;

use poller::Poller;
use waker::waker;

pub use comp::{LocalCompFuture, LocalCompletionQueue};
pub use executor::LocalExecutor;
pub use fill::{LocalFillFuture, LocalFillQueue};
pub use recv::{LocalRecvFuture, LocalSocketRx};
pub use send::{LocalSendFuture, LocalSocketTx};
pub use socket::LocalSocket;
pub use umem::LocalUmem;
