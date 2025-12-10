use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to allocate packet memory: memory exhausted")]
    MemoryExhausted,
    #[error("buffer too small: need {needed} bytes, have {available}")]
    BufferTooSmall { needed: usize, available: usize },
    #[error("invalid ARP packet")]
    InvalidArpPacket,
}
