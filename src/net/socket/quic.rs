use std::cell::UnsafeCell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll};

use rustls::{ClientConfig, ServerConfig};

use crate::net::handler::quic::QuicHandler;
use crate::net::handler::quic::error::TransportError;
use crate::net::handler::quic::transport::frame::StreamId;
use crate::net::socket::LocalQueue;
use crate::net::wire::ip::IpAddress;

/// Events from the QUIC handler to the socket layer.
#[derive(Debug)]
pub enum QuicEvent {
    HandshakeComplete,
    NewStream(StreamId),
    StreamReadable(StreamId),
    StreamWritable(StreamId),
    StreamFinished(StreamId),
    StreamReset(StreamId, u64),
    ConnectionError(TransportError),
    ConnectionClosed(u64),
}

/// Error returned by QUIC socket operations.
#[derive(Debug)]
pub enum QuicError {
    Transport(TransportError),
    NotConnected,
    StreamReset(u64),
    ConnectionClosed,
    WouldBlock,
}

// ---- QuicListener ----

/// A listening QUIC socket that accepts incoming connections.
///
/// Created via `QuicListener::listen()` inside a `LocalRuntime::run()` closure.
/// Use `accept()` to wait for incoming connections, which returns a `QuicConnection`.
pub struct QuicListener {
    port: u16,
    accept_queue: LocalQueue<usize>, // connection slab keys
    handler: Rc<UnsafeCell<QuicHandler>>,
}

impl QuicListener {
    /// Bind a QUIC listener on the given address and port.
    /// The TLS config must include server certificates.
    pub fn listen(
        _addr: IpAddress,
        _port: u16,
        _tls_config: Arc<ServerConfig>,
    ) -> Result<Self, QuicError> {
        // TODO: register with QuicHandler via RuntimeContext
        todo!("QuicListener::listen -- requires RuntimeContext wiring")
    }

    /// Accept the next incoming QUIC connection.
    pub fn accept(&self) -> Accept<'_> {
        Accept { listener: self }
    }

    /// Returns the port this listener is bound to.
    pub fn port(&self) -> u16 {
        self.port
    }
}

pub struct Accept<'a> {
    listener: &'a QuicListener,
}

impl<'a> Future for Accept<'a> {
    type Output = QuicConnection;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let queue = &self.listener.accept_queue;
        if let Some(conn_key) = queue.pop() {
            Poll::Ready(QuicConnection {
                conn_key,
                handler: self.listener.handler.clone(),
            })
        } else {
            queue.register_waker(cx.waker());
            Poll::Pending
        }
    }
}

// ---- QuicConnection ----

/// A QUIC connection, either client-initiated or accepted from a listener.
///
/// Provides methods to open and accept streams, query RTT, and close
/// the connection.
pub struct QuicConnection {
    conn_key: usize,
    handler: Rc<UnsafeCell<QuicHandler>>,
}

impl QuicConnection {
    /// Connect to a remote QUIC server.
    pub fn connect(
        _addr: IpAddress,
        _port: u16,
        _server_name: &str,
        _tls_config: Arc<ClientConfig>,
    ) -> Connect {
        Connect { _private: () }
    }

    /// Open a new bidirectional stream.
    pub fn open_bidi_stream(&self) -> Result<QuicStream, QuicError> {
        // TODO: allocate stream ID, create stream entry
        todo!("open_bidi_stream")
    }

    /// Open a new unidirectional (send-only) stream.
    pub fn open_uni_stream(&self) -> Result<QuicSendStream, QuicError> {
        todo!("open_uni_stream")
    }

    /// Accept a peer-initiated stream.
    pub fn accept_stream(&self) -> AcceptStream<'_> {
        AcceptStream { conn: self }
    }

    /// Get the current RTT estimate.
    pub fn rtt(&self) -> std::time::Duration {
        // TODO: read from connection state
        std::time::Duration::from_millis(0)
    }

    /// Close the connection with an error code and optional reason.
    pub fn close(&self, _error_code: u64, _reason: &[u8]) {
        // TODO: send CONNECTION_CLOSE
    }

    /// Returns the internal connection slab key.
    pub fn connection_key(&self) -> usize {
        self.conn_key
    }
}

pub struct Connect {
    _private: (),
}

impl Future for Connect {
    type Output = Result<QuicConnection, QuicError>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        // TODO: drive handshake
        Poll::Pending
    }
}

pub struct AcceptStream<'a> {
    conn: &'a QuicConnection,
}

impl<'a> Future for AcceptStream<'a> {
    type Output = QuicStream;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let _conn = self.conn;
        // TODO: poll for new peer-initiated streams
        Poll::Pending
    }
}

// ---- QuicStream ----

/// A bidirectional QUIC stream with both read and write halves.
///
/// Can be split into separate `QuicRecvStream` and `QuicSendStream`
/// halves via the `split()` method.
pub struct QuicStream {
    conn_key: usize,
    stream_id: StreamId,
    handler: Rc<UnsafeCell<QuicHandler>>,
}

impl QuicStream {
    pub fn read<'a>(&'a self, buf: &'a mut [u8]) -> StreamRead<'a> {
        StreamRead { stream: self, buf }
    }

    pub fn write<'a>(&'a self, buf: &'a [u8]) -> StreamWrite<'a> {
        StreamWrite { stream: self, buf }
    }

    /// Signal that no more data will be sent (send FIN).
    pub fn finish(&self) {
        // TODO: transition send state to DataSent
    }

    /// Reset the stream with an error code.
    pub fn reset(&self, _error_code: u64) {
        // TODO: send RESET_STREAM
    }

    /// Returns the stream identifier.
    pub fn id(&self) -> StreamId {
        self.stream_id
    }

    /// Split into separate read and write halves.
    pub fn split(self) -> (QuicRecvStream, QuicSendStream) {
        let recv = QuicRecvStream {
            conn_key: self.conn_key,
            stream_id: self.stream_id,
            handler: self.handler.clone(),
        };
        let send = QuicSendStream {
            conn_key: self.conn_key,
            stream_id: self.stream_id,
            handler: self.handler,
        };
        (recv, send)
    }
}

pub struct StreamRead<'a> {
    stream: &'a QuicStream,
    buf: &'a mut [u8],
}

impl<'a> Future for StreamRead<'a> {
    type Output = Result<usize, QuicError>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let _stream = self.stream;
        let _buf = &self.get_mut().buf;
        // TODO: read from RecvHalf buffer
        Poll::Pending
    }
}

pub struct StreamWrite<'a> {
    stream: &'a QuicStream,
    buf: &'a [u8],
}

impl<'a> Future for StreamWrite<'a> {
    type Output = Result<usize, QuicError>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let _stream = self.stream;
        let _buf = self.buf;
        // TODO: write to SendHalf buffer
        Poll::Pending
    }
}

// ---- Split halves ----

/// The receive half of a split QUIC stream.
pub struct QuicRecvStream {
    conn_key: usize,
    stream_id: StreamId,
    handler: Rc<UnsafeCell<QuicHandler>>,
}

impl QuicRecvStream {
    pub fn read<'a>(&'a self, buf: &'a mut [u8]) -> RecvStreamRead<'a> {
        RecvStreamRead { stream: self, buf }
    }

    pub fn id(&self) -> StreamId {
        self.stream_id
    }
}

pub struct RecvStreamRead<'a> {
    stream: &'a QuicRecvStream,
    buf: &'a mut [u8],
}

impl<'a> Future for RecvStreamRead<'a> {
    type Output = Result<usize, QuicError>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let _stream = self.stream;
        let _buf = &self.get_mut().buf;
        // TODO: read from RecvHalf buffer
        Poll::Pending
    }
}

/// The send half of a split QUIC stream.
pub struct QuicSendStream {
    conn_key: usize,
    stream_id: StreamId,
    handler: Rc<UnsafeCell<QuicHandler>>,
}

impl QuicSendStream {
    pub fn write<'a>(&'a self, buf: &'a [u8]) -> SendStreamWrite<'a> {
        SendStreamWrite { stream: self, buf }
    }

    /// Signal that no more data will be sent (send FIN).
    pub fn finish(&self) {
        // TODO: transition send state to DataSent
    }

    /// Reset the stream with an error code.
    pub fn reset(&self, _error_code: u64) {
        // TODO: send RESET_STREAM
    }

    pub fn id(&self) -> StreamId {
        self.stream_id
    }
}

pub struct SendStreamWrite<'a> {
    stream: &'a QuicSendStream,
    buf: &'a [u8],
}

impl<'a> Future for SendStreamWrite<'a> {
    type Output = Result<usize, QuicError>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let _stream = self.stream;
        let _buf = self.buf;
        // TODO: write to SendHalf buffer
        Poll::Pending
    }
}
