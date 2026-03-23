pub(crate) mod cid_lifecycle;
pub(crate) mod connection;
pub(crate) mod connection_id;
pub(crate) mod crypto;
pub(crate) mod datagram;
pub(crate) mod error;
pub(crate) mod event;
pub(crate) mod handler;
pub(crate) mod packet_parser;
pub(crate) mod path;
pub(crate) mod processor;
pub(crate) mod stream;
pub(crate) mod timer_kinds;
pub(crate) mod token;
pub(crate) mod token_crypto;
pub(crate) mod transport;

pub use handler::QuicHandler;
pub use transport::params::TransportParams;

/// Public re-exports for benchmarks.
pub mod bench {
    pub use super::connection_id::ConnectionId;
    pub use super::transport::frame::{StreamId, parse_frame};
    pub use super::transport::varint::{decode_varint, encode_varint};

    /// Frame encoding functions exposed for benchmarks.
    pub mod frame_writer {
        pub use crate::net::handler::quic::transport::frame_writer::{write_crypto, write_stream};
    }
}

#[cfg(test)]
mod tests;
