use std::{os::fd::RawFd, sync::Arc};

use dashmap::DashMap;
use tokio::io::unix::AsyncFd;

use crate::xdp::error::Result;

/// A factory for creating [AsyncFd] instances.
///
/// The purpose of this is to cache [AsyncFd] file descriptors for the lifetime of the program, this is important
/// because [AsyncFd] file descriptors must be unique and we have multiple components that all need a copy. So we
/// store a [Arc<AsyncFd<RawFd>>] in a [DashMap] for the lifetime of the program to share across components with t
/// he same fd.
pub struct TokioFdFactory {
    inner: DashMap<RawFd, Arc<AsyncFd<RawFd>>>,
}

impl TokioFdFactory {
    pub(crate) fn new() -> Self {
        Self {
            inner: DashMap::new(),
        }
    }

    /// Creates a new [TokioFd] instance for the given file descriptor, or return a cached instance if it already exists.
    ///
    /// This returns an error in the event a registration occurs and fails.
    pub fn get_tokio_fd(&self, fd: RawFd) -> Result<Arc<AsyncFd<RawFd>>> {
        use dashmap::Entry::*;
        match self.inner.entry(fd) {
            Occupied(entry) => Ok(entry.get().clone()),
            Vacant(entry) => {
                let async_fd = Arc::new(AsyncFd::new(fd)?);
                entry.insert(async_fd.clone());
                Ok(async_fd)
            }
        }
    }
}
