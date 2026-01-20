use std::{
    os::fd::{AsFd, BorrowedFd, RawFd},
    sync::Arc,
};

use async_io::Async;
use dashmap::DashMap;

use crate::xdp::error::Result;

/// A SmolFd is a wrapper around a raw file descriptor that is used to create an [Async] file descriptor.
///
/// We need this because [Async] requires an [AsFd] implementation which [RawFd] does not implement.
pub struct SmolFd(RawFd);

impl AsFd for SmolFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        unsafe { BorrowedFd::borrow_raw(self.0) }
    }
}

/// A factory for creating [SmolFd] instances.
///
/// The purpose of this is to cache [Async] file descriptors for the lifetime of the program, this is important
/// because [Async] file descriptors must be unique and we have multiple components that all need a copy. So we
/// store a [`Arc<Async<SmolFd>>`] in a [DashMap] for the lifetime of the program to share across components with t
/// he same fd.
pub struct SmolFdFactory {
    inner: DashMap<RawFd, Arc<Async<SmolFd>>>,
}

impl SmolFdFactory {
    pub(crate) fn new() -> Self {
        Self {
            inner: DashMap::new(),
        }
    }

    /// Creates a new [SmolFd] instance for the given file descriptor, or return a cached instance if it already exists.
    ///
    /// This returns an error in the event a registration occurs and fails.
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
