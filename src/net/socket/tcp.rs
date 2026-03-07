use std::{
    cell::UnsafeCell,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
};

use coarsetime::Instant;

use crate::{
    net::{
        handler::{
            tcp::TcpHandler,
            udp::BindError,
        },
        wire::{
            ethernet::MacAddress,
            ip::IpAddress,
        },
    },
    rt::context::with_runtime_context,
};

use super::LocalQueue;

pub use crate::net::handler::tcp::tcb::TcpConfig;
use crate::net::handler::tcp::tcb::{ConnectionId, TcpError, TcpEvent};

const DEFAULT_BACKLOG: usize = 128;

/// A listening TCP socket that accepts incoming connections.
///
/// Created via `TcpListener::listen()` inside a `LocalRuntime::run()` closure.
/// Use `accept()` to wait for incoming connections, which returns a `TcpStream`.
pub struct TcpListener {
    local_addr: IpAddress,
    local_port: u16,
    accept_queue: LocalQueue<ConnectionId>,
    handler: Rc<UnsafeCell<TcpHandler>>,
}

impl TcpListener {
    /// Create a new listening TCP socket bound to the given address and port.
    ///
    /// Must be called inside a `LocalRuntime::run()` closure. Panics otherwise.
    pub fn listen(addr: IpAddress, port: u16) -> Result<Self, BindError> {
        Self::listen_with_backlog(addr, port, DEFAULT_BACKLOG)
    }

    /// Create a new listening TCP socket with a custom backlog size.
    pub fn listen_with_backlog(
        addr: IpAddress,
        port: u16,
        backlog: usize,
    ) -> Result<Self, BindError> {
        with_runtime_context(|ctx| {
            let handler = unsafe { &mut *ctx.tcp_handler.get() };
            let accept_queue = handler.listen(addr, port, backlog)?;
            Ok(Self {
                local_addr: addr,
                local_port: port,
                accept_queue,
                handler: ctx.tcp_handler.clone(),
            })
        })
    }

    /// Create a new listening TCP socket with custom configuration.
    ///
    /// The config controls backlog size and per-connection buffer sizes.
    pub fn listen_with_config(
        addr: IpAddress,
        port: u16,
        config: TcpConfig,
    ) -> Result<Self, BindError> {
        with_runtime_context(|ctx| {
            let handler = unsafe { &mut *ctx.tcp_handler.get() };
            let accept_queue = handler.listen_with_config(addr, port, config)?;
            Ok(Self {
                local_addr: addr,
                local_port: port,
                accept_queue,
                handler: ctx.tcp_handler.clone(),
            })
        })
    }

    /// Returns a future that resolves when a new connection is available.
    #[inline(always)]
    pub fn accept(&self) -> Accept<'_> {
        Accept {
            accept_queue: &self.accept_queue,
            handler: &self.handler,
        }
    }

    /// Returns the local address this listener is bound to.
    pub fn local_addr(&self) -> IpAddress {
        self.local_addr
    }

    /// Returns the local port this listener is bound to.
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// Close this listener, removing it from the handler.
    pub fn close(&mut self) {
        let handler = unsafe { &mut *self.handler.get() };
        handler.unlisten(self.local_addr, self.local_port);
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        self.close();
    }
}

/// Future returned by [`TcpListener::accept()`].
///
/// Resolves to a [`TcpStream`] when a new connection completes the 3-way handshake.
pub struct Accept<'listener> {
    accept_queue: &'listener LocalQueue<ConnectionId>,
    handler: &'listener Rc<UnsafeCell<TcpHandler>>,
}

impl<'listener> Future for Accept<'listener> {
    type Output = TcpStream;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match this.accept_queue.pop() {
            Some(conn_id) => {
                let handler = unsafe { &*this.handler.get() };
                let event_queue = handler
                    .get_connection(&conn_id)
                    .map(|tcb| tcb.event_queue.clone());

                if let Some(event_queue) = event_queue {
                    Poll::Ready(TcpStream::from_accepted(
                        conn_id,
                        event_queue,
                        this.handler.clone(),
                    ))
                } else {
                    // Connection was removed (e.g. by RST) before we accepted it.
                    // Keep polling for the next one.
                    Poll::Pending
                }
            }
            None => Poll::Pending,
        }
    }
}

/// A connected TCP stream.
///
/// Created either by [`TcpListener::accept()`] (passive open) or
/// [`TcpStream::connect()`] (active open).
pub struct TcpStream {
    conn_id: ConnectionId,
    #[allow(dead_code)] // used in future data transfer phases
    event_queue: LocalQueue<TcpEvent>,
    handler: Rc<UnsafeCell<TcpHandler>>,
    closed: bool,
}

impl TcpStream {
    /// Initiate an active open (connect) to a remote address.
    ///
    /// Returns a `Connect` future that resolves when the 3-way handshake
    /// completes or fails.
    ///
    /// Must be called inside a `LocalRuntime::run()` closure. Panics otherwise.
    pub fn connect(
        local_addr: IpAddress,
        local_port: u16,
        remote_addr: IpAddress,
        remote_port: u16,
    ) -> Result<Connect, TcpError> {
        with_runtime_context(|ctx| {
            let handler = unsafe { &mut *ctx.tcp_handler.get() };
            let neighbor_handler = &*ctx.neighbor_handler;

            // Resolve MACs for the outbound SYN.
            let src_mac = neighbor_handler.local_mac();
            let dst_mac = neighbor_handler
                .lookup(Instant::now(), &remote_addr)
                .unwrap_or(MacAddress::broadcast());

            let mut free_frames = ctx.free_frames.clone();
            let mut tx_return = ctx.tx_return.clone();

            let event_queue = handler
                .connect(
                    local_addr,
                    local_port,
                    remote_addr,
                    remote_port,
                    src_mac,
                    dst_mac,
                    &mut free_frames,
                    &mut tx_return,
                )
                .map_err(|_| TcpError::NotConnected)?;

            let conn_id = ConnectionId {
                local_addr,
                local_port,
                remote_addr,
                remote_port,
            };

            Ok(Connect {
                conn_id,
                event_queue,
                handler: ctx.tcp_handler.clone(),
            })
        })
    }

    /// Initiate an active open (connect) with custom buffer configuration.
    ///
    /// Returns a `Connect` future that resolves when the 3-way handshake
    /// completes or fails.
    ///
    /// Must be called inside a `LocalRuntime::run()` closure. Panics otherwise.
    pub fn connect_with_config(
        local_addr: IpAddress,
        local_port: u16,
        remote_addr: IpAddress,
        remote_port: u16,
        config: TcpConfig,
    ) -> Result<Connect, TcpError> {
        with_runtime_context(|ctx| {
            let handler = unsafe { &mut *ctx.tcp_handler.get() };
            let neighbor_handler = &*ctx.neighbor_handler;

            // Resolve MACs for the outbound SYN.
            let src_mac = neighbor_handler.local_mac();
            let dst_mac = neighbor_handler
                .lookup(Instant::now(), &remote_addr)
                .unwrap_or(MacAddress::broadcast());

            let mut free_frames = ctx.free_frames.clone();
            let mut tx_return = ctx.tx_return.clone();

            let event_queue = handler
                .connect_with_config(
                    local_addr,
                    local_port,
                    remote_addr,
                    remote_port,
                    src_mac,
                    dst_mac,
                    config,
                    &mut free_frames,
                    &mut tx_return,
                )
                .map_err(|_| TcpError::NotConnected)?;

            let conn_id = ConnectionId {
                local_addr,
                local_port,
                remote_addr,
                remote_port,
            };

            Ok(Connect {
                conn_id,
                event_queue,
                handler: ctx.tcp_handler.clone(),
            })
        })
    }

    /// Internal constructor for connections created via accept.
    fn from_accepted(
        conn_id: ConnectionId,
        event_queue: LocalQueue<TcpEvent>,
        handler: Rc<UnsafeCell<TcpHandler>>,
    ) -> Self {
        Self {
            conn_id,
            event_queue,
            handler,
            closed: false,
        }
    }

    /// Returns the connection's 4-tuple identifier.
    pub fn conn_id(&self) -> &ConnectionId {
        &self.conn_id
    }

    /// Returns the local address of this connection.
    pub fn local_addr(&self) -> IpAddress {
        self.conn_id.local_addr
    }

    /// Returns the local port of this connection.
    pub fn local_port(&self) -> u16 {
        self.conn_id.local_port
    }

    /// Returns the remote address of this connection.
    pub fn remote_addr(&self) -> IpAddress {
        self.conn_id.remote_addr
    }

    /// Returns the remote port of this connection.
    pub fn remote_port(&self) -> u16 {
        self.conn_id.remote_port
    }

    /// Write data to this connection. Returns a future that resolves when
    /// all bytes are copied into the send buffer.
    pub fn write<'a>(&'a self, data: &'a [u8]) -> TcpWrite<'a> {
        TcpWrite {
            handler: &self.handler,
            conn_id: self.conn_id,
            data,
            written: 0,
        }
    }

    /// Read data from this connection. Returns a future that resolves when
    /// data is available in the receive buffer.
    pub fn read<'a>(&'a self, buf: &'a mut [u8]) -> TcpRead<'a> {
        TcpRead {
            handler: &self.handler,
            conn_id: self.conn_id,
            buf,
        }
    }

    /// Initiate graceful close of this connection.
    ///
    /// Sets a flag on the TCB; the runtime's `poll_send` will drain
    /// any remaining send buffer data and then send FIN on the next tick.
    pub fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        let handler = unsafe { &mut *self.handler.get() };
        handler.initiate_close(&self.conn_id);
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        self.close();
    }
}

/// Future returned by [`TcpStream::connect()`].
///
/// Resolves to a [`TcpStream`] when the handshake completes, or returns
/// an error if the connection is refused or times out.
pub struct Connect {
    conn_id: ConnectionId,
    event_queue: LocalQueue<TcpEvent>,
    handler: Rc<UnsafeCell<TcpHandler>>,
}

impl Future for Connect {
    type Output = Result<TcpStream, TcpError>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match this.event_queue.pop() {
            Some(TcpEvent::Connected) => Poll::Ready(Ok(TcpStream {
                conn_id: this.conn_id,
                event_queue: this.event_queue.clone(),
                handler: this.handler.clone(),
                closed: false,
            })),
            Some(TcpEvent::ConnectionRefused) => Poll::Ready(Err(TcpError::ConnectionRefused)),
            Some(TcpEvent::Timeout) => Poll::Ready(Err(TcpError::Timeout)),
            Some(TcpEvent::Reset) => Poll::Ready(Err(TcpError::Reset)),
            Some(TcpEvent::RemoteClose) => Poll::Ready(Err(TcpError::Reset)),
            None => Poll::Pending,
        }
    }
}

/// Future returned by [`TcpStream::write()`].
pub struct TcpWrite<'stream> {
    handler: &'stream Rc<UnsafeCell<TcpHandler>>,
    conn_id: ConnectionId,
    data: &'stream [u8],
    written: usize,
}

impl<'stream> Future for TcpWrite<'stream> {
    type Output = usize;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let handler = unsafe { &mut *this.handler.get() };
        if let Some(tcb) = handler.get_connection_mut(&this.conn_id) {
            let remaining = &this.data[this.written..];
            let n = tcb.send_buffer.write(remaining);
            this.written += n;
            if this.written == this.data.len() {
                Poll::Ready(this.written)
            } else {
                Poll::Pending
            }
        } else {
            Poll::Ready(0) // connection gone
        }
    }
}

/// Future returned by [`TcpStream::read()`].
pub struct TcpRead<'stream> {
    handler: &'stream Rc<UnsafeCell<TcpHandler>>,
    conn_id: ConnectionId,
    buf: &'stream mut [u8],
}

impl<'stream> Future for TcpRead<'stream> {
    type Output = usize;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let handler = unsafe { &mut *this.handler.get() };
        if let Some(tcb) = handler.get_connection_mut(&this.conn_id) {
            let n = tcb.recv_buffer.read(this.buf);
            if n > 0 {
                Poll::Ready(n)
            } else if tcb.state.is_remote_closed() {
                Poll::Ready(0) // EOF — remote has sent FIN and buffer is drained
            } else {
                Poll::Pending
            }
        } else {
            Poll::Ready(0) // connection gone
        }
    }
}
