use std::{
    os::fd::{AsFd, BorrowedFd, RawFd},
    sync::Arc,
};

use async_io::Async;
use dashmap::DashMap;

use crate::xdp::error::Result;

pub struct SmolFd(RawFd);

impl AsFd for SmolFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        unsafe { BorrowedFd::borrow_raw(self.0) }
    }
}

pub struct SmolFdFactory {
    inner: DashMap<RawFd, Arc<Async<SmolFd>>>,
}

impl SmolFdFactory {
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
        }
    }

    pub fn get_smol_fd(&self, fd: RawFd) -> Result<Arc<Async<SmolFd>>> {
        use dashmap::Entry::*;
        match self.inner.entry(fd) {
            Occupied(entry) => Ok(entry.get().clone()),
            Vacant(entry) => {
                let async_fd = Arc::new(Async::new(SmolFd(fd))?);
                entry.insert(async_fd.clone());
                Ok(async_fd)
            }
        }
    }
}
