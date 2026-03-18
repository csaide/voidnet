use std::{
    cell::UnsafeCell,
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
    accept_queue: LocalQueue<usize>,
    handler: Rc<UnsafeCell<TcpHandler>>,
    wheel: Rc<UnsafeCell<crate::net::timer_wheel::TimerWheel>>,
    base_instant: coarsetime::Instant,
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
                wheel: ctx.wheel.clone(),
                base_instant: ctx.base_instant,
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
                wheel: ctx.wheel.clone(),
                base_instant: ctx.base_instant,
            })
        })
    }

    /// Returns a future that resolves when a new connection is available.
    #[inline(always)]
    pub fn accept(&self) -> Accept<'_> {
        Accept {
            accept_queue: &self.accept_queue,
            handler: &self.handler,
            wheel: &self.wheel,
            base_instant: self.base_instant,
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
    accept_queue: &'listener LocalQueue<usize>,
    handler: &'listener Rc<UnsafeCell<TcpHandler>>,
    wheel: &'listener Rc<UnsafeCell<crate::net::timer_wheel::TimerWheel>>,
    base_instant: coarsetime::Instant,
}

impl<'listener> Future for Accept<'listener> {
    type Output = TcpStream;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match this.accept_queue.pop() {
            Some(conn_key) => {
                let handler = unsafe { &*this.handler.get() };
                let info = handler
                    .get_by_key(conn_key)
                    .map(|tcb| (tcb.id, tcb.event_queue.clone()));

                if let Some((conn_id, event_queue)) = info {
                    Poll::Ready(TcpStream::from_accepted(
                        conn_key,
                        conn_id,
                        event_queue,
                        this.handler.clone(),
                        this.wheel.clone(),
                        this.base_instant,
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
    conn_key: usize,
    conn_id: ConnectionId,
    #[allow(dead_code)] // used in future data transfer phases
    event_queue: LocalQueue<TcpEvent>,
    handler: Rc<UnsafeCell<TcpHandler>>,
    wheel: Rc<UnsafeCell<crate::net::timer_wheel::TimerWheel>>,
    base_instant: coarsetime::Instant,
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
            let wheel = unsafe { &mut *ctx.wheel.get() };
            let neighbor_handler = &*ctx.neighbor_handler;
            let now = Instant::now();

            // Resolve MACs for the outbound SYN.
            let src_mac = neighbor_handler.local_mac();
            let dst_mac = neighbor_handler
                .lookup(now, &remote_addr)
                .unwrap_or(MacAddress::broadcast());

            let mut free_frames = ctx.free_frames.clone();
            let mut tx_return = ctx.tx_return.clone();

            let (conn_key, event_queue) = handler
                .connect(
                    local_addr,
                    local_port,
                    remote_addr,
                    remote_port,
                    src_mac,
                    dst_mac,
                    now,
                    wheel,
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
                conn_key,
                conn_id,
                event_queue,
                handler: ctx.tcp_handler.clone(),
                wheel: ctx.wheel.clone(),
                base_instant: ctx.base_instant,
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
            let wheel = unsafe { &mut *ctx.wheel.get() };
            let neighbor_handler = &*ctx.neighbor_handler;
            let now = Instant::now();

            // Resolve MACs for the outbound SYN.
            let src_mac = neighbor_handler.local_mac();
            let dst_mac = neighbor_handler
                .lookup(now, &remote_addr)
                .unwrap_or(MacAddress::broadcast());

            let mut free_frames = ctx.free_frames.clone();
            let mut tx_return = ctx.tx_return.clone();

            let (conn_key, event_queue) = handler
                .connect_with_config(
                    local_addr,
                    local_port,
                    remote_addr,
                    remote_port,
                    src_mac,
                    dst_mac,
                    now,
                    wheel,
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
                conn_key,
                conn_id,
                event_queue,
                handler: ctx.tcp_handler.clone(),
                wheel: ctx.wheel.clone(),
                base_instant: ctx.base_instant,
            })
        })
    }

    /// Internal constructor for connections created via accept.
    fn from_accepted(
        conn_key: usize,
        conn_id: ConnectionId,
        event_queue: LocalQueue<TcpEvent>,
        handler: Rc<UnsafeCell<TcpHandler>>,
        wheel: Rc<UnsafeCell<crate::net::timer_wheel::TimerWheel>>,
        base_instant: coarsetime::Instant,
    ) -> Self {
        Self {
            conn_key,
            conn_id,
            event_queue,
            handler,
            wheel,
            base_instant,
            closed: false,
            write_closed: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_accepted_for_test(
        conn_key: usize,
        conn_id: ConnectionId,
        event_queue: LocalQueue<TcpEvent>,
        handler: Rc<UnsafeCell<TcpHandler>>,
        wheel: Rc<UnsafeCell<crate::net::timer_wheel::TimerWheel>>,
        base_instant: coarsetime::Instant,
    ) -> Self {
        Self {
            conn_key,
            conn_id,
            event_queue,
            handler,
            wheel,
            base_instant,
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
            conn_key: self.conn_key,
            event_queue: &self.event_queue,
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
            conn_key: self.conn_key,
            event_queue: &self.event_queue,
            max_len,
        }
    }

    /// Read data from this connection. Returns a future that resolves when
    /// data is available in the receive buffer.
    pub fn read<'a>(&'a self, buf: &'a mut [u8]) -> TcpRead<'a> {
        TcpRead {
            handler: &self.handler,
            conn_key: self.conn_key,
            event_queue: &self.event_queue,
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
        let wheel = unsafe { &mut *self.wheel.get() };
        let now = Instant::now();
        handler.initiate_close(self.conn_key, now, wheel);
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
        let wheel = unsafe { &mut *self.wheel.get() };
        let now = Instant::now();
        handler.initiate_close(self.conn_key, now, wheel);
    }

    /// Enable or disable the Nagle algorithm (TCP_NODELAY).
    ///
    /// When `nodelay` is `true`, small segments are sent immediately
    /// without waiting for outstanding ACKs. Default is `false` (Nagle enabled).
    pub fn set_nodelay(&self, nodelay: bool) {
        let handler = unsafe { &mut *self.handler.get() };
        if let Some(tcb) = handler.get_by_key_mut(self.conn_key) {
            tcb.nagle_enabled = !nodelay;
        }
    }

    /// Returns whether TCP_NODELAY is set (Nagle disabled).
    pub fn nodelay(&self) -> bool {
        let handler = unsafe { &*self.handler.get() };
        handler
            .get_by_key(self.conn_key)
            .map(|tcb| !tcb.nagle_enabled)
            .unwrap_or(false)
    }

    /// Enable or disable TCP keep-alive probes.
    pub fn set_keepalive(&self, enabled: bool) {
        let handler = unsafe { &mut *self.handler.get() };
        if let Some(tcb) = handler.get_by_key_mut(self.conn_key) {
            tcb.keep_alive_enabled = enabled;
        }
    }

    /// Returns whether TCP keep-alive is enabled.
    pub fn keepalive(&self) -> bool {
        let handler = unsafe { &*self.handler.get() };
        handler
            .get_by_key(self.conn_key)
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
        if let Some(tcb) = handler.get_by_key_mut(self.conn_key) {
            tcb.linger = linger;
        }
    }

    /// Returns the current SO_LINGER setting.
    pub fn linger(&self) -> Option<u64> {
        let handler = unsafe { &*self.handler.get() };
        handler.get_by_key(self.conn_key).and_then(|tcb| tcb.linger)
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
    conn_key: usize,
    conn_id: ConnectionId,
    event_queue: LocalQueue<TcpEvent>,
    handler: Rc<UnsafeCell<TcpHandler>>,
    wheel: Rc<UnsafeCell<crate::net::timer_wheel::TimerWheel>>,
    base_instant: coarsetime::Instant,
}

impl Future for Connect {
    type Output = Result<TcpStream, TcpError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match this.event_queue.pop() {
            Some(TcpEvent::Connected) => Poll::Ready(Ok(TcpStream {
                conn_key: this.conn_key,
                conn_id: this.conn_id,
                event_queue: this.event_queue.clone(),
                handler: this.handler.clone(),
                wheel: this.wheel.clone(),
                base_instant: this.base_instant,
                closed: false,
                write_closed: false,
            })),
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
    conn_key: usize,
    event_queue: &'stream LocalQueue<TcpEvent>,
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
        let remaining = &this.data[this.written..];
        if let Some(n) = handler.write_to_send_buffer(this.conn_key, remaining) {
            this.written += n;
            if this.written == this.data.len() {
                Poll::Ready(Ok(this.written))
            } else {
                // Need to register waker for when send buffer has space.
                if let Some(tcb) = handler.get_by_key_mut(this.conn_key) {
                    tcb.send_buffer.register_write_waker(cx.waker());
                }
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
    conn_key: usize,
    event_queue: &'stream LocalQueue<TcpEvent>,
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
        if let Some(tcb) = handler.get_by_key_mut(this.conn_key) {
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

pub struct TcpSplice<'stream> {
    handler: &'stream Rc<UnsafeCell<TcpHandler>>,
    conn_key: usize,
    event_queue: &'stream LocalQueue<TcpEvent>,
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
        if let Some((n, is_remote_closed)) = handler.splice_buffers(this.conn_key, this.max_len) {
            if n > 0 {
                Poll::Ready(Ok(n))
            } else if is_remote_closed {
                Poll::Ready(Ok(0)) // EOF
            } else {
                if let Some(tcb) = handler.get_by_key_mut(this.conn_key) {
                    tcb.recv_buffer.register_read_waker(cx.waker());
                }
                this.event_queue.register_waker(cx.waker());
                Poll::Pending
            }
        } else {
            Poll::Ready(Err(TcpError::NotConnected))
        }
    }
}

/// Future returned by [`TcpStream::splice()`].
#[cfg(test)]
mod tests {
    use std::cell::UnsafeCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;

    use coarsetime::Instant;

    use crate::net::handler::tcp::TcpHandler;
    use crate::net::handler::tcp::congestion::CubicState;
    use crate::net::handler::tcp::recovery::{FRtoState, PrrState, SackRecovery};
    use crate::net::handler::tcp::ring_buffer::RingBuffer;
    use crate::net::handler::tcp::state::TcpState;
    use crate::net::handler::tcp::tcb::{
        ConnectionId, DEFAULT_DELAYED_ACK_MS, DEFAULT_RCV_MSS, Tcb,
    };
    use crate::net::socket::LocalQueue;
    use crate::net::wire::ip::{IpAddress, Ipv4Address};

    use super::TcpStream;

    /// Build a TcpStream backed by a real handler + TCB for accessor testing.
    fn make_test_stream() -> TcpStream {
        let local_addr = IpAddress::V4(Ipv4Address {
            octets: [10, 0, 0, 1],
        });
        let remote_addr = IpAddress::V4(Ipv4Address {
            octets: [10, 0, 0, 2],
        });
        let conn_id = ConnectionId {
            local_addr,
            local_port: 4000,
            remote_addr,
            remote_port: 80,
        };
        let event_queue = LocalQueue::new(16);

        let tcb = Tcb {
            id: conn_id,
            state: TcpState::Established,
            from_passive_open: true,
            iss: 1000,
            snd_una: 1000,
            snd_nxt: 1000,
            snd_wnd: 65535,
            snd_wl1: 0,
            snd_wl2: 0,
            irs: 2000,
            rcv_nxt: 2001,
            rcv_wnd: 65535,
            snd_mss: DEFAULT_RCV_MSS,
            rcv_mss: DEFAULT_RCV_MSS,
            eff_snd_mss: DEFAULT_RCV_MSS,
            snd_wscale: 0,
            rcv_wscale: 0,
            wscale_enabled: false,
            rto_backoff: 0,
            event_queue: event_queue.clone(),
            send_buffer: RingBuffer::new(1024),
            recv_buffer: RingBuffer::new(1024),
            ooo_ranges: BTreeMap::new(),
            cubic: CubicState::new(DEFAULT_RCV_MSS),
            recovery: SackRecovery::new(),
            prr: PrrState::new(),
            frto: FRtoState::new(),
            srtt: None,
            rttvar: 0,
            rto: 1000,
            last_send_time: None,
            pending_fin: false,
            fin_seq: None,
            time_wait_duration: 60_000,
            ack_pending: false,
            ack_delay_count: 0,
            delayed_ack_ms: DEFAULT_DELAYED_ACK_MS,
            nagle_enabled: true,
            keep_alive_enabled: false,
            keep_alive_idle_ms: 7_200_000,
            keep_alive_interval_ms: 75_000,
            keep_alive_count: 9,
            last_activity: Instant::now(),
            keep_alive_probes_sent: 0,
            linger: None,
            ts_enabled: false,
            ts_recent: 0,
            ts_recent_age: Instant::now(),
            ts_offset: Instant::now(),
            sack_enabled: false,
            sack_scoreboard: BTreeMap::new(),
            ecn_enabled: false,
            ecn_ce_received: false,
            ecn_cwr_sent: false,
            persist_backoff: 0,
            max_snd_wnd: 0,
            last_advertised_right_edge: 0,
        };

        let mut handler = TcpHandler::new(false, false);
        let key = handler.insert_connection(tcb);
        let handler_rc = Rc::new(UnsafeCell::new(handler));

        let wheel_rc = Rc::new(UnsafeCell::new(crate::net::timer_wheel::TimerWheel::new(0)));
        TcpStream::from_accepted_for_test(
            key,
            conn_id,
            event_queue,
            handler_rc,
            wheel_rc,
            Instant::now(),
        )
    }

    #[test]
    fn local_addr_returns_configured_address() {
        let stream = make_test_stream();
        assert_eq!(
            stream.local_addr(),
            IpAddress::V4(Ipv4Address {
                octets: [10, 0, 0, 1]
            })
        );
    }

    #[test]
    fn local_port_returns_configured_port() {
        let stream = make_test_stream();
        assert_eq!(stream.local_port(), 4000);
    }

    #[test]
    fn remote_addr_returns_configured_address() {
        let stream = make_test_stream();
        assert_eq!(
            stream.remote_addr(),
            IpAddress::V4(Ipv4Address {
                octets: [10, 0, 0, 2]
            })
        );
    }

    #[test]
    fn remote_port_returns_configured_port() {
        let stream = make_test_stream();
        assert_eq!(stream.remote_port(), 80);
    }

    #[test]
    fn conn_id_returns_full_4_tuple() {
        let stream = make_test_stream();
        let id = stream.conn_id();
        assert_eq!(
            id.local_addr,
            IpAddress::V4(Ipv4Address {
                octets: [10, 0, 0, 1]
            })
        );
        assert_eq!(id.local_port, 4000);
        assert_eq!(
            id.remote_addr,
            IpAddress::V4(Ipv4Address {
                octets: [10, 0, 0, 2]
            })
        );
        assert_eq!(id.remote_port, 80);
    }

    #[test]
    fn nodelay_default_is_false() {
        let stream = make_test_stream();
        assert!(
            !stream.nodelay(),
            "default should be Nagle enabled (nodelay=false)"
        );
    }

    #[test]
    fn set_nodelay_true_round_trip() {
        let stream = make_test_stream();
        stream.set_nodelay(true);
        assert!(stream.nodelay());
    }

    #[test]
    fn set_nodelay_false_after_true() {
        let stream = make_test_stream();
        stream.set_nodelay(true);
        assert!(stream.nodelay());
        stream.set_nodelay(false);
        assert!(!stream.nodelay());
    }

    #[test]
    fn keepalive_default_is_false() {
        let stream = make_test_stream();
        assert!(!stream.keepalive());
    }

    #[test]
    fn set_keepalive_true_round_trip() {
        let stream = make_test_stream();
        stream.set_keepalive(true);
        assert!(stream.keepalive());
    }

    #[test]
    fn set_keepalive_false_after_true() {
        let stream = make_test_stream();
        stream.set_keepalive(true);
        assert!(stream.keepalive());
        stream.set_keepalive(false);
        assert!(!stream.keepalive());
    }

    #[test]
    fn linger_default_is_none() {
        let stream = make_test_stream();
        assert_eq!(stream.linger(), None);
    }

    #[test]
    fn set_linger_some_round_trip() {
        let stream = make_test_stream();
        stream.set_linger(Some(5000));
        assert_eq!(stream.linger(), Some(5000));
    }

    #[test]
    fn set_linger_zero_for_rst_on_close() {
        let stream = make_test_stream();
        stream.set_linger(Some(0));
        assert_eq!(stream.linger(), Some(0));
    }

    #[test]
    fn close_sets_closed_flag() {
        let mut stream = make_test_stream();
        assert!(!stream.closed);
        stream.close();
        assert!(stream.closed);
    }

    #[test]
    fn close_is_idempotent() {
        let mut stream = make_test_stream();
        stream.close();
        assert!(stream.closed);
        // Second close should not panic.
        stream.close();
        assert!(stream.closed);
    }

    #[test]
    fn shutdown_sets_write_closed_flag() {
        let mut stream = make_test_stream();
        assert!(!stream.write_closed);
        stream.shutdown();
        assert!(stream.write_closed);
    }

    #[test]
    fn shutdown_is_idempotent() {
        let mut stream = make_test_stream();
        stream.shutdown();
        assert!(stream.write_closed);
        // Second shutdown should not panic.
        stream.shutdown();
        assert!(stream.write_closed);
    }

    #[test]
    fn shutdown_then_close() {
        let mut stream = make_test_stream();
        stream.shutdown();
        assert!(stream.write_closed);
        assert!(!stream.closed);
        stream.close();
        assert!(stream.closed);
    }

    #[test]
    fn close_prevents_shutdown() {
        let mut stream = make_test_stream();
        stream.close();
        // shutdown after close is a no-op (early return because closed=true)
        stream.shutdown();
        assert!(stream.closed);
        // write_closed should still be false since shutdown was a no-op
        assert!(!stream.write_closed);
    }

    #[test]
    fn set_linger_none_clears_previous() {
        let stream = make_test_stream();
        stream.set_linger(Some(3000));
        assert_eq!(stream.linger(), Some(3000));
        stream.set_linger(None);
        assert_eq!(stream.linger(), None);
    }
}
