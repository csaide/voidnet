use std::cell::UnsafeCell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll};

use rustls::{ClientConfig, ServerConfig};

use crate::net::handler::quic::QuicHandler;
use crate::net::handler::quic::connection::ConnectionState;
use crate::net::handler::quic::error::TransportError;
use crate::net::handler::quic::transport::frame::StreamId;
use crate::net::handler::quic::transport::params::TransportParams;
use crate::net::socket::LocalQueue;
use crate::net::wire::ip::IpAddress;
use crate::rt::context::with_runtime_context;

pub use crate::net::handler::quic::event::QuicEvent;

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
        port: u16,
        tls_config: Arc<ServerConfig>,
    ) -> Result<Self, QuicError> {
        with_runtime_context(|ctx| {
            let handler = unsafe { &mut *ctx.quic_handler.get() };
            let accept_queue = LocalQueue::new(128);
            handler.listen_with_queue(
                port,
                tls_config,
                TransportParams::default(),
                accept_queue.clone(),
            );
            Ok(QuicListener {
                port,
                accept_queue,
                handler: ctx.quic_handler.clone(),
            })
        })
    }

    /// Accept the next incoming QUIC connection.
    pub fn accept(&self) -> Accept<'_> {
        Accept { listener: self }
    }

    /// Returns the port this listener is bound to.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Close this listener, removing it from the handler.
    pub fn close(&mut self) {
        let handler = unsafe { &mut *self.handler.get() };
        handler.unlisten(self.port);
    }
}

impl Drop for QuicListener {
    fn drop(&mut self) {
        self.close();
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
            // Verify the connection still exists
            let handler = unsafe { &*self.listener.handler.get() };
            if handler.connections.contains(conn_key) {
                Poll::Ready(QuicConnection {
                    conn_key,
                    handler: self.listener.handler.clone(),
                })
            } else {
                // Connection was removed before we accepted it; keep waiting.
                queue.register_waker(cx.waker());
                Poll::Pending
            }
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
        // Client connect is deferred to a future milestone.
        Connect { _private: () }
    }

    /// Open a new bidirectional stream.
    pub fn open_bidi_stream(&self) -> Result<QuicStream, QuicError> {
        let handler = unsafe { &mut *self.handler.get() };
        let conn = handler
            .connections
            .get_mut(self.conn_key)
            .ok_or(QuicError::NotConnected)?;

        // Allocate next bidi stream ID.
        // Server-initiated bidi: type bits = 0x01 (odd). Client-initiated: 0x00.
        let type_bits: u64 = if conn.streams.is_client { 0 } else { 1 };
        let idx = conn.streams.local_opened_bidi;
        let stream_id = StreamId(idx * 4 + type_bits);

        // This will increment local_opened_bidi and create the entry
        let _ = conn
            .streams
            .get_or_create(stream_id)
            .map_err(|_| QuicError::WouldBlock)?;

        Ok(QuicStream {
            conn_key: self.conn_key,
            stream_id,
            handler: self.handler.clone(),
        })
    }

    /// Open a new unidirectional (send-only) stream.
    pub fn open_uni_stream(&self) -> Result<QuicSendStream, QuicError> {
        let handler = unsafe { &mut *self.handler.get() };
        let conn = handler
            .connections
            .get_mut(self.conn_key)
            .ok_or(QuicError::NotConnected)?;

        // Server-initiated uni: type bits = 0x03. Client-initiated: 0x02.
        let type_bits: u64 = if conn.streams.is_client { 2 } else { 3 };
        let idx = conn.streams.local_opened_uni;
        let stream_id = StreamId(idx * 4 + type_bits);

        let _ = conn
            .streams
            .get_or_create(stream_id)
            .map_err(|_| QuicError::WouldBlock)?;

        Ok(QuicSendStream {
            conn_key: self.conn_key,
            stream_id,
            handler: self.handler.clone(),
        })
    }

    /// Accept a peer-initiated stream.
    pub fn accept_stream(&self) -> AcceptStream<'_> {
        AcceptStream { conn: self }
    }

    /// Get the current RTT estimate.
    pub fn rtt(&self) -> coarsetime::Duration {
        let handler = unsafe { &*self.handler.get() };
        handler
            .connections
            .get(self.conn_key)
            .map(|c| c.loss.smoothed_rtt)
            .unwrap_or(coarsetime::Duration::from_millis(0))
    }

    /// Close the connection with an error code and optional reason.
    pub fn close(&self, _error_code: u64, _reason: &[u8]) {
        let handler = unsafe { &mut *self.handler.get() };
        if let Some(conn) = handler.connections.get_mut(self.conn_key) {
            if !matches!(
                conn.state,
                ConnectionState::Closing | ConnectionState::Closed | ConnectionState::Draining
            ) {
                conn.state = ConnectionState::Closing;
            }
        }
    }

    /// Returns the internal connection slab key.
    pub fn connection_key(&self) -> usize {
        self.conn_key
    }
}

impl Drop for QuicConnection {
    fn drop(&mut self) {
        let handler = unsafe { &mut *self.handler.get() };
        if let Some(conn) = handler.connections.get_mut(self.conn_key) {
            if conn.state != ConnectionState::Closed
                && conn.state != ConnectionState::Closing
                && conn.state != ConnectionState::Draining
            {
                conn.close_error = Some(TransportError::NO_ERROR);
                conn.state = ConnectionState::Closing;
                conn.needs_draining_timer = true;
            }
        }
    }
}

pub struct Connect {
    _private: (),
}

impl Future for Connect {
    type Output = Result<QuicConnection, QuicError>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Client-side connect is deferred to a future milestone.
        Poll::Pending
    }
}

pub struct AcceptStream<'a> {
    conn: &'a QuicConnection,
}

impl<'a> Future for AcceptStream<'a> {
    type Output = Result<QuicStream, QuicError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let handler = unsafe { &*self.conn.handler.get() };
        let conn = match handler.connections.get(self.conn.conn_key) {
            Some(c) => c,
            None => {
                return Poll::Ready(Err(QuicError::ConnectionClosed));
            }
        };

        if let Some(stream_id) = conn.stream_accept_queue.pop() {
            Poll::Ready(Ok(QuicStream {
                conn_key: self.conn.conn_key,
                stream_id,
                handler: self.conn.handler.clone(),
            }))
        } else {
            conn.stream_accept_queue.register_waker(cx.waker());
            Poll::Pending
        }
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
        let handler = unsafe { &mut *self.handler.get() };
        if let Some(conn) = handler.connections.get_mut(self.conn_key) {
            if let Some(entry) = conn.streams.get_mut(self.stream_id) {
                if let Some(ref mut send) = entry.send {
                    send.fin_sent = true;
                }
            }
        }
    }

    /// Reset the stream with an error code.
    pub fn reset(&self, _error_code: u64) {
        // TODO: queue RESET_STREAM frame
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

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let handler = unsafe { &mut *this.stream.handler.get() };
        let conn = match handler.connections.get_mut(this.stream.conn_key) {
            Some(c) => c,
            None => return Poll::Ready(Err(QuicError::NotConnected)),
        };
        let entry = match conn.streams.get_mut(this.stream.stream_id) {
            Some(e) => e,
            None => return Poll::Ready(Err(QuicError::NotConnected)),
        };
        if let Some(ref mut recv) = entry.recv {
            let n = recv.read(this.buf);
            if n > 0 {
                conn.flow.on_data_consumed(n as u64);
                return Poll::Ready(Ok(n));
            }
            // Check if FIN received and all data consumed
            if recv.fin_received && recv.received == recv.read_offset {
                return Poll::Ready(Ok(0)); // EOF
            }
        } else {
            return Poll::Ready(Err(QuicError::NotConnected));
        }
        // Register waker for when data arrives
        conn.event_queue.register_waker(cx.waker());
        Poll::Pending
    }
}

pub struct StreamWrite<'a> {
    stream: &'a QuicStream,
    buf: &'a [u8],
}

impl<'a> Future for StreamWrite<'a> {
    type Output = Result<usize, QuicError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let handler = unsafe { &mut *self.stream.handler.get() };
        let conn = match handler.connections.get_mut(self.stream.conn_key) {
            Some(c) => c,
            None => return Poll::Ready(Err(QuicError::NotConnected)),
        };
        if matches!(
            conn.state,
            ConnectionState::Closing | ConnectionState::Closed | ConnectionState::Draining
        ) {
            return Poll::Ready(Err(QuicError::ConnectionClosed));
        }
        let entry = match conn.streams.get_mut(self.stream.stream_id) {
            Some(e) => e,
            None => return Poll::Ready(Err(QuicError::NotConnected)),
        };
        if let Some(ref mut send) = entry.send {
            if send.fin_sent {
                return Poll::Ready(Err(QuicError::ConnectionClosed));
            }
            let n = send.write(self.buf);
            if n > 0 {
                return Poll::Ready(Ok(n));
            }
        } else {
            return Poll::Ready(Err(QuicError::NotConnected));
        }
        conn.event_queue.register_waker(cx.waker());
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

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let handler = unsafe { &mut *this.stream.handler.get() };
        let conn = match handler.connections.get_mut(this.stream.conn_key) {
            Some(c) => c,
            None => return Poll::Ready(Err(QuicError::NotConnected)),
        };
        let entry = match conn.streams.get_mut(this.stream.stream_id) {
            Some(e) => e,
            None => return Poll::Ready(Err(QuicError::NotConnected)),
        };
        if let Some(ref mut recv) = entry.recv {
            let n = recv.read(this.buf);
            if n > 0 {
                conn.flow.on_data_consumed(n as u64);
                return Poll::Ready(Ok(n));
            }
            if recv.fin_received && recv.received == recv.read_offset {
                return Poll::Ready(Ok(0)); // EOF
            }
        } else {
            return Poll::Ready(Err(QuicError::NotConnected));
        }
        conn.event_queue.register_waker(cx.waker());
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
        let handler = unsafe { &mut *self.handler.get() };
        if let Some(conn) = handler.connections.get_mut(self.conn_key) {
            if let Some(entry) = conn.streams.get_mut(self.stream_id) {
                if let Some(ref mut send) = entry.send {
                    send.fin_sent = true;
                }
            }
        }
    }

    /// Reset the stream with an error code.
    pub fn reset(&self, _error_code: u64) {
        // TODO: queue RESET_STREAM frame
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

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let handler = unsafe { &mut *self.stream.handler.get() };
        let conn = match handler.connections.get_mut(self.stream.conn_key) {
            Some(c) => c,
            None => return Poll::Ready(Err(QuicError::NotConnected)),
        };
        if matches!(
            conn.state,
            ConnectionState::Closing | ConnectionState::Closed | ConnectionState::Draining
        ) {
            return Poll::Ready(Err(QuicError::ConnectionClosed));
        }
        let entry = match conn.streams.get_mut(self.stream.stream_id) {
            Some(e) => e,
            None => return Poll::Ready(Err(QuicError::NotConnected)),
        };
        if let Some(ref mut send) = entry.send {
            if send.fin_sent {
                return Poll::Ready(Err(QuicError::ConnectionClosed));
            }
            let n = send.write(self.buf);
            if n > 0 {
                return Poll::Ready(Ok(n));
            }
        } else {
            return Poll::Ready(Err(QuicError::NotConnected));
        }
        conn.event_queue.register_waker(cx.waker());
        Poll::Pending
    }
}
