use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid Ethernet header: {0}")]
    InvalidEthernetHeader(String),
}

pub type Result<T> = std::result::Result<T, Error>;
