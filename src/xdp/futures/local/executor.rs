use std::task::{Context, Poll};

use futures_util::pin_mut;

use crate::xdp::error::Result;

use super::{Poller, waker};

/// A local executor designed to work with XDP sockets specifically, this is NOT a full async runtime, but a purpose built executor to allow for async ergonomics
/// when the throughput/latency requirements are loose enough.
///
/// The idea here is that the executor does not use normal waker semanitcs as these semantics cause significant performance overhead when dealing with cross thread synchronization.
///
/// So this polls the given future on the local thread, sleeping on a custom epoll implementation to await for new IO events. These then drive the future to completion. Removing a
/// significant amount of overhead from the future.
///
/// When to use this? You want the lowest possible latency but want to use async/await semantics, and _critically_ you either are bringing your own full async runtime or you don't have other
/// async work to do.
pub struct LocalExecutor {
    poller: Poller,
}

impl LocalExecutor {
    /// Creates a new local executor.
    pub fn new() -> Result<Self> {
        Ok(Self {
            poller: Poller::new()?,
        })
    }

    /// Registers a file descriptor with the local executor.
    pub fn register(&self, fd: i32) -> Result<()> {
        self.poller.register(fd)
    }

    /// Deregisters a file descriptor from the local executor.
    pub fn deregister(&self, fd: i32) -> Result<()> {
        self.poller.deregister(fd)
    }

    /// Runs a future on the local executor.
    pub fn run<F: Future>(&mut self, fut: F) -> F::Output {
        let waker = waker();
        let mut cx = Context::from_waker(&waker);

        pin_mut!(fut);
        loop {
            let ready = match self.poller.poll(-1) {
                Ok(events) => events,
                Err(e) => panic!("Poller poll failed: {}", e),
            };

            if !ready {
                continue;
            }

            if let Poll::Ready(output) = fut.as_mut().poll(&mut cx) {
                return output;
            }
        }
    }
}
