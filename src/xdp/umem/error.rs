use errno::Errno;
use thiserror::Error;

/// A result type for umem operations.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
/// An error type for umem operations.
pub enum Error {
    #[error("failed to create umem: {0}")]
    Create(Errno),
    #[error("failed to allocate mmap for umem: {0}")]
    MmapAllocate(std::io::Error),
    #[error("stack is full")]
    StackFull,
    #[error("failed to wake fill queue: {0}")]
    WakeFillQueue(Errno),
}
