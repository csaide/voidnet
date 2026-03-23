use crate::net::handler::quic::error::TransportError;
use crate::net::handler::quic::transport::frame::StreamId;

/// Events from the QUIC handler to the socket layer.
#[derive(Debug)]
pub enum QuicEvent {
    /// TLS handshake completed, connection is ready
    HandshakeComplete,
    /// Peer opened a new stream
    NewStream(StreamId),
    /// Stream has data available to read
    StreamReadable(StreamId),
    /// Stream has buffer space for writing
    StreamWritable(StreamId),
    /// Stream's send side is fully acknowledged
    StreamFinished(StreamId),
    /// Peer reset a stream with an error code
    StreamReset(StreamId, u64),
    /// Connection-level error occurred
    ConnectionError(TransportError),
    /// Stream send data was acknowledged, buffer space freed (backpressure release)
    DataAcked,
    /// Connection was closed (application error code)
    ConnectionClosed(u64),
    /// An unreliable datagram was received (RFC 9221)
    DatagramReceived,
}
