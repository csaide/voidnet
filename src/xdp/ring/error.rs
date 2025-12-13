use thiserror::Error;

use errno::Errno;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to create ring: {0}")]
    Create(Errno),
    #[error("wake failed: {0}")]
    Wake(Errno),
}
