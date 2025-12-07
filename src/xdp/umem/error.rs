use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("value is too large")]
    ValueTooLarge,
    #[error("invalid byte sequence: {0}")]
    InvalidByteSequence(String),
    #[error("failed to create umem: {0}")]
    Create(std::io::Error),
}
