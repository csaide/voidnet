use errno::Errno;
use thiserror::Error;

/// A simple type alias for the result type of the futures subsystem, this is used to simplify the error handling code.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to create epoll instance: {0}")]
    EpollCreate(Errno),
    #[error("failed to wait on epoll instance: {0}")]
    EpollWait(Errno),
    #[error("failed to register file descriptor with epoll instance: {0}")]
    EpollCtl(Errno),
}
