use errno::Errno;
use thiserror::Error;

use crate::xdp::umem::Error as UmemError;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to create socket: {0}")]
    Create(Errno),
    #[error("would block")]
    WouldBlock,
    #[error("umem failure: {0}")]
    Umem(#[from] UmemError),
    #[error("tx queue wake failed: {0}")]
    TxQueueWake(Errno),
}
