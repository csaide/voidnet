use std::os::fd::{AsRawFd, RawFd};

use tokio::io::unix::AsyncFd;

use crate::xdp::{error::Result, umem::UmemOwner};

pub struct AsyncUmemOwner<'umem> {
    umem: AsyncFd<UmemOwner<'umem>>,
}

impl<'umem> AsyncUmemOwner<'umem> {
    pub fn new(umem: UmemOwner<'umem>) -> Result<Self> {
        Ok(Self {
            umem: AsyncFd::new(umem)?,
        })
    }
}

impl<'umem> AsRawFd for UmemOwner<'umem> {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}
