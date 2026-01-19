use std::{os::fd::RawFd, sync::Arc};

use dashmap::DashMap;
use tokio::io::unix::AsyncFd;

use crate::xdp::error::Result;

pub struct TokioFdFactory {
    inner: DashMap<RawFd, Arc<AsyncFd<RawFd>>>,
}

impl TokioFdFactory {
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
        }
    }

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
