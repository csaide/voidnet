use std::task::{Context, Poll};

use futures_util::pin_mut;

use crate::xdp::error::Result;

use super::{Poller, waker};

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
