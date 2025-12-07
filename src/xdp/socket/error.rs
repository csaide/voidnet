use thiserror::Error;

use crate::xdp::umem::Error as UmemError;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to create socket: {0}")]
    Create(std::io::Error),
    #[error("would block")]
    WouldBlock,
    #[error("failed to fill packets: {0}")]
    Umem(#[from] UmemError),
}
