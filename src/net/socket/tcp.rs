use std::{
    cell::{Cell, UnsafeCell},
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
};

use coarsetime::Instant;

use crate::{
    net::{
        handler::{tcp::TcpHandler, udp::BindError},
        wire::{ethernet::MacAddress, ip::IpAddress},
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

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
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
                    this.accept_queue.register_waker(cx.waker());
                    Poll::Pending
                }
            }
            None => {
                this.accept_queue.register_waker(cx.waker());
                Poll::Pending
            }
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
    cached_idx: Cell<usize>,
    closed: bool,
    write_closed: bool,
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
            let now = Instant::now();

            // Resolve MACs for the outbound SYN.
            let src_mac = neighbor_handler.local_mac();
            let dst_mac = neighbor_handler
                .lookup(now, &remote_addr)
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
                    now,
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
            let now = Instant::now();

            // Resolve MACs for the outbound SYN.
            let src_mac = neighbor_handler.local_mac();
            let dst_mac = neighbor_handler
                .lookup(now, &remote_addr)
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
                    now,
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
        let h = unsafe { &*handler.get() };
        let idx = h.find_connection_idx(&conn_id).unwrap_or(0);
        Self {
            conn_id,
            event_queue,
            handler,
            cached_idx: Cell::new(idx),
            closed: false,
            write_closed: false,
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
            event_queue: &self.event_queue,
            cached_idx: &self.cached_idx,
            data,
            written: 0,
            write_closed: self.write_closed || self.closed,
        }
    }

    /// Transfer data from recv_buffer directly to send_buffer, avoiding the
    /// intermediate user buffer copy. Returns a future that resolves when at
    /// least 1 byte has been transferred, or 0 on EOF.
    pub fn splice(&self, max_len: usize) -> TcpSplice<'_> {
        TcpSplice {
            handler: &self.handler,
            conn_id: self.conn_id,
            event_queue: &self.event_queue,
            cached_idx: &self.cached_idx,
            max_len,
        }
    }

    /// Read data from this connection. Returns a future that resolves when
    /// data is available in the receive buffer.
    pub fn read<'a>(&'a self, buf: &'a mut [u8]) -> TcpRead<'a> {
        TcpRead {
            handler: &self.handler,
            conn_id: self.conn_id,
            event_queue: &self.event_queue,
            cached_idx: &self.cached_idx,
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

    /// Shut down the write side of this connection (half-close).
    ///
    /// Sends FIN to the remote peer but keeps the read side open.
    /// Subsequent writes will return 0. Reads continue until remote FIN.
    pub fn shutdown(&mut self) {
        if self.write_closed || self.closed {
            return;
        }
        self.write_closed = true;
        let handler = unsafe { &mut *self.handler.get() };
        handler.initiate_close(&self.conn_id);
    }

    /// Enable or disable the Nagle algorithm (TCP_NODELAY).
    ///
    /// When `nodelay` is `true`, small segments are sent immediately
    /// without waiting for outstanding ACKs. Default is `false` (Nagle enabled).
    pub fn set_nodelay(&self, nodelay: bool) {
        let handler = unsafe { &mut *self.handler.get() };
        if let Some(tcb) = handler.get_connection_mut(&self.conn_id) {
            tcb.nagle_enabled = !nodelay;
        }
    }

    /// Returns whether TCP_NODELAY is set (Nagle disabled).
    pub fn nodelay(&self) -> bool {
        let handler = unsafe { &*self.handler.get() };
        handler
            .get_connection(&self.conn_id)
            .map(|tcb| !tcb.nagle_enabled)
            .unwrap_or(false)
    }

    /// Enable or disable TCP keep-alive probes.
    pub fn set_keepalive(&self, enabled: bool) {
        let handler = unsafe { &mut *self.handler.get() };
        if let Some(tcb) = handler.get_connection_mut(&self.conn_id) {
            tcb.keep_alive_enabled = enabled;
        }
    }

    /// Returns whether TCP keep-alive is enabled.
    pub fn keepalive(&self) -> bool {
        let handler = unsafe { &*self.handler.get() };
        handler
            .get_connection(&self.conn_id)
            .map(|tcb| tcb.keep_alive_enabled)
            .unwrap_or(false)
    }

    /// Set the SO_LINGER option.
    ///
    /// - `None`: default graceful close
    /// - `Some(0)`: hard RST on close
    /// - `Some(ms)`: graceful close with timeout in milliseconds
    pub fn set_linger(&self, linger: Option<u64>) {
        let handler = unsafe { &mut *self.handler.get() };
        if let Some(tcb) = handler.get_connection_mut(&self.conn_id) {
            tcb.linger = linger;
        }
    }

    /// Returns the current SO_LINGER setting.
    pub fn linger(&self) -> Option<u64> {
        let handler = unsafe { &*self.handler.get() };
        handler
            .get_connection(&self.conn_id)
            .and_then(|tcb| tcb.linger)
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

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match this.event_queue.pop() {
            Some(TcpEvent::Connected) => {
                let handler = unsafe { &*this.handler.get() };
                let idx = handler.find_connection_idx(&this.conn_id).unwrap_or(0);
                Poll::Ready(Ok(TcpStream {
                    conn_id: this.conn_id,
                    event_queue: this.event_queue.clone(),
                    handler: this.handler.clone(),
                    cached_idx: Cell::new(idx),
                    closed: false,
                    write_closed: false,
                }))
            }
            Some(TcpEvent::ConnectionRefused) => Poll::Ready(Err(TcpError::ConnectionRefused)),
            Some(TcpEvent::Timeout) => Poll::Ready(Err(TcpError::Timeout)),
            Some(TcpEvent::Reset) => Poll::Ready(Err(TcpError::Reset)),
            Some(TcpEvent::RemoteClose) => Poll::Ready(Err(TcpError::Reset)),
            None => {
                this.event_queue.register_waker(cx.waker());
                Poll::Pending
            }
        }
    }
}

/// Future returned by [`TcpStream::write()`].
pub struct TcpWrite<'stream> {
    handler: &'stream Rc<UnsafeCell<TcpHandler>>,
    conn_id: ConnectionId,
    event_queue: &'stream LocalQueue<TcpEvent>,
    cached_idx: &'stream Cell<usize>,
    data: &'stream [u8],
    written: usize,
    write_closed: bool,
}

impl<'stream> Future for TcpWrite<'stream> {
    type Output = Result<usize, TcpError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        // Check event queue for errors
        while let Some(event) = this.event_queue.pop() {
            match event {
                TcpEvent::Reset => return Poll::Ready(Err(TcpError::Reset)),
                TcpEvent::Timeout => return Poll::Ready(Err(TcpError::Timeout)),
                _ => {}
            }
        }

        if this.write_closed {
            return Poll::Ready(Err(TcpError::NotConnected));
        }
        let handler = unsafe { &mut *this.handler.get() };
        let idx = this.cached_idx.get();
        if let Some((new_idx, tcb)) = handler.get_connection_by_idx_mut(idx, &this.conn_id) {
            this.cached_idx.set(new_idx);
            let remaining = &this.data[this.written..];
            let n = tcb.send_buffer.write(remaining);
            this.written += n;
            if this.written == this.data.len() {
                Poll::Ready(Ok(this.written))
            } else {
                tcb.send_buffer.register_write_waker(cx.waker());
                this.event_queue.register_waker(cx.waker());
                Poll::Pending
            }
        } else {
            Poll::Ready(Err(TcpError::NotConnected))
        }
    }
}

/// Future returned by [`TcpStream::read()`].
pub struct TcpRead<'stream> {
    handler: &'stream Rc<UnsafeCell<TcpHandler>>,
    conn_id: ConnectionId,
    event_queue: &'stream LocalQueue<TcpEvent>,
    cached_idx: &'stream Cell<usize>,
    buf: &'stream mut [u8],
}

impl<'stream> Future for TcpRead<'stream> {
    type Output = Result<usize, TcpError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        // Check event queue for errors
        while let Some(event) = this.event_queue.pop() {
            match event {
                TcpEvent::Reset => return Poll::Ready(Err(TcpError::Reset)),
                TcpEvent::Timeout => return Poll::Ready(Err(TcpError::Timeout)),
                _ => {}
            }
        }

        let handler = unsafe { &mut *this.handler.get() };
        let idx = this.cached_idx.get();
        if let Some((new_idx, tcb)) = handler.get_connection_by_idx_mut(idx, &this.conn_id) {
            this.cached_idx.set(new_idx);
            let n = tcb.recv_buffer.read(this.buf);
            if n > 0 {
                Poll::Ready(Ok(n))
            } else if tcb.state.is_remote_closed() {
                Poll::Ready(Ok(0)) // EOF — remote has sent FIN and buffer is drained
            } else {
                tcb.recv_buffer.register_read_waker(cx.waker());
                this.event_queue.register_waker(cx.waker());
                Poll::Pending
            }
        } else {
            Poll::Ready(Err(TcpError::NotConnected))
        }
    }
}

/// Future returned by [`TcpStream::splice()`].
pub struct TcpSplice<'stream> {
    handler: &'stream Rc<UnsafeCell<TcpHandler>>,
    conn_id: ConnectionId,
    event_queue: &'stream LocalQueue<TcpEvent>,
    cached_idx: &'stream Cell<usize>,
    max_len: usize,
}

impl<'stream> Future for TcpSplice<'stream> {
    type Output = Result<usize, TcpError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        // Check event queue for errors.
        while let Some(event) = this.event_queue.pop() {
            match event {
                TcpEvent::Reset => return Poll::Ready(Err(TcpError::Reset)),
                TcpEvent::Timeout => return Poll::Ready(Err(TcpError::Timeout)),
                _ => {}
            }
        }

        let handler = unsafe { &mut *this.handler.get() };
        let idx = this.cached_idx.get();
        if let Some((new_idx, tcb)) = handler.get_connection_by_idx_mut(idx, &this.conn_id) {
            this.cached_idx.set(new_idx);
            let n = tcb.recv_buffer.transfer(&mut tcb.send_buffer, this.max_len);
            if n > 0 {
                Poll::Ready(Ok(n))
            } else if tcb.state.is_remote_closed() {
                Poll::Ready(Ok(0)) // EOF
            } else {
                tcb.recv_buffer.register_read_waker(cx.waker());
                this.event_queue.register_waker(cx.waker());
                Poll::Pending
            }
        } else {
            Poll::Ready(Err(TcpError::NotConnected))
        }
    }
}
