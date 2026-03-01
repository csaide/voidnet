use std::ops::Deref;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::net::handler::tcp::{
    AcceptedConnection, ConnectionId, SharedFlag, SharedSendBuffer, TcpCommand, TcpEvent,
};
use crate::net::wire::ip::IpAddress;
use crate::xdp::frame::{Frame, FrameBuffer, SharedFrameBuffer};

use super::LocalQueue;

/// A user-facing TCP listener handle.
///
/// Obtained via `LocalRuntime::listen_tcp()`. The handler pushes accepted
/// connections into `accept_queue` when the three-way handshake completes.
/// Calling [`accept`](TcpListener::accept) returns a [`TcpStream`] directly.
pub struct TcpListener<'umem> {
    local_addr: IpAddress,
    local_port: u16,
    accept_queue: LocalQueue<AcceptedConnection<'umem>>,
    rx_return: SharedFrameBuffer<'umem>,
}

impl<'umem> TcpListener<'umem> {
    pub(crate) fn new(
        local_addr: IpAddress,
        local_port: u16,
        accept_queue: LocalQueue<AcceptedConnection<'umem>>,
        rx_return: SharedFrameBuffer<'umem>,
    ) -> Self {
        Self {
            local_addr,
            local_port,
            accept_queue,
            rx_return,
        }
    }

    pub fn local_addr(&self) -> IpAddress {
        self.local_addr
    }

    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// Returns a future that resolves when a new connection is accepted.
    #[inline(always)]
    pub fn accept(&self) -> TcpAcceptFuture<'_, 'umem> {
        TcpAcceptFuture {
            accept_queue: &self.accept_queue,
            rx_return: &self.rx_return,
        }
    }
}

/// Future returned by [`TcpListener::accept`].
///
/// Designed for the `LocalRuntime`'s busy-poll model: the runtime
/// repeatedly polls this future using a no-op waker.
pub struct TcpAcceptFuture<'sock, 'umem> {
    accept_queue: &'sock LocalQueue<AcceptedConnection<'umem>>,
    rx_return: &'sock SharedFrameBuffer<'umem>,
}

impl<'sock, 'umem> Future for TcpAcceptFuture<'sock, 'umem> {
    type Output = TcpStream<'umem>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match this.accept_queue.pop() {
            Some(accepted) => Poll::Ready(TcpStream::from_accepted(
                accepted,
                this.rx_return.clone(),
            )),
            None => Poll::Pending,
        }
    }
}

/// A user-facing TCP stream handle.
///
/// Obtained via `LocalRuntime::connect_tcp()` or by accepting a connection
/// from a `TcpListener`. Provides send/receive operations and close/abort
/// commands.
pub struct TcpStream<'umem> {
    conn_id: ConnectionId,
    rx_queue: LocalQueue<TcpEvent<'umem>>,
    cmd_queue: LocalQueue<TcpCommand>,
    send_buffer: SharedSendBuffer,
    send_notify: SharedFlag,
    rx_return: SharedFrameBuffer<'umem>,
}

impl<'umem> TcpStream<'umem> {
    pub(crate) fn new(
        conn_id: ConnectionId,
        rx_queue: LocalQueue<TcpEvent<'umem>>,
        cmd_queue: LocalQueue<TcpCommand>,
        send_buffer: SharedSendBuffer,
        send_notify: SharedFlag,
        rx_return: SharedFrameBuffer<'umem>,
    ) -> Self {
        Self {
            conn_id,
            rx_queue,
            cmd_queue,
            send_buffer,
            send_notify,
            rx_return,
        }
    }

    fn from_accepted(
        accepted: AcceptedConnection<'umem>,
        rx_return: SharedFrameBuffer<'umem>,
    ) -> Self {
        Self {
            conn_id: accepted.conn_id,
            rx_queue: accepted.rx_queue,
            cmd_queue: accepted.cmd_queue,
            send_buffer: accepted.send_buffer,
            send_notify: accepted.send_notify,
            rx_return,
        }
    }

    pub fn local_addr(&self) -> IpAddress {
        self.conn_id.local_addr
    }

    pub fn local_port(&self) -> u16 {
        self.conn_id.local_port
    }

    pub fn remote_addr(&self) -> IpAddress {
        self.conn_id.remote_addr
    }

    pub fn remote_port(&self) -> u16 {
        self.conn_id.remote_port
    }

    /// Returns a future that copies data into the ring buffer (THE ONE copy).
    /// Returns `usize` bytes accepted. Returns `Pending` when buffer is full.
    #[inline(always)]
    pub fn send<'buf>(&mut self, data: &'buf [u8]) -> TcpSendFuture<'_, 'buf> {
        TcpSendFuture {
            send_buffer: &self.send_buffer,
            send_notify: &self.send_notify,
            data,
            written: 0,
        }
    }

    /// Returns a future that reads data from the TCP stream without copying.
    /// The returned [`TcpRecvResult::Data`] variant holds a [`TcpFrame`] that
    /// provides direct access to the payload in the UMEM frame.
    #[inline(always)]
    pub fn receive(&self) -> TcpReceiveFuture<'_, 'umem> {
        TcpReceiveFuture {
            rx_queue: &self.rx_queue,
            rx_return: self.rx_return.clone(),
        }
    }

    /// Initiate a graceful close (sends FIN).
    pub fn close(&self) {
        self.cmd_queue.push(TcpCommand::Close);
    }

    /// Abort the connection (sends RST).
    pub fn abort(&self) {
        self.cmd_queue.push(TcpCommand::Abort);
    }
}

/// Future wrapping a `TcpStream` that waits for the 3-way handshake to complete.
/// Resolves to `Option<TcpStream>` (None if RST/timeout during handshake).
pub struct TcpConnectFuture<'umem> {
    stream: Option<TcpStream<'umem>>,
}

impl<'umem> TcpConnectFuture<'umem> {
    pub(crate) fn new(stream: TcpStream<'umem>) -> Self {
        Self {
            stream: Some(stream),
        }
    }
}

impl<'umem> Future for TcpConnectFuture<'umem> {
    type Output = Option<TcpStream<'umem>>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let stream = this.stream.as_mut().unwrap();
        match stream.rx_queue.pop() {
            Some(TcpEvent::Connected) => Poll::Ready(this.stream.take()),
            Some(TcpEvent::Reset) | Some(TcpEvent::Closed) => {
                this.stream.take();
                Poll::Ready(None)
            }
            Some(TcpEvent::Data { frame, .. }) => {
                stream.rx_return.push(frame);
                Poll::Pending
            }
            _ => Poll::Pending,
        }
    }
}

/// Future returned by [`TcpStream::send`].
///
/// Copies data into the ring buffer. If all written → `Ready(total)`.
/// If partial/zero → `Pending` (busy-poll retries when space freed by ACKs).
pub struct TcpSendFuture<'sock, 'buf> {
    send_buffer: &'sock SharedSendBuffer,
    send_notify: &'sock SharedFlag,
    data: &'buf [u8],
    written: usize,
}

impl<'sock, 'buf> Future for TcpSendFuture<'sock, 'buf> {
    type Output = usize;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let remaining = &this.data[this.written..];
        if remaining.is_empty() {
            return Poll::Ready(this.written);
        }
        let n = this.send_buffer.push(remaining);
        this.written += n;
        if this.written == this.data.len() {
            Poll::Ready(this.written)
        } else if n > 0 {
            // Partial write — we made progress but buffer is full. Go pending.
            this.send_notify.set(false);
            Poll::Pending
        } else {
            // No space at all. Wait for ACKs to free space.
            this.send_notify.set(false);
            Poll::Pending
        }
    }
}

/// Future returned by [`TcpStream::receive`].
///
/// Designed for the `LocalRuntime`'s busy-poll model.
pub struct TcpReceiveFuture<'sock, 'umem> {
    rx_queue: &'sock LocalQueue<TcpEvent<'umem>>,
    rx_return: SharedFrameBuffer<'umem>,
}

impl<'sock, 'umem> Future for TcpReceiveFuture<'sock, 'umem> {
    type Output = TcpRecvResult<'umem>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        match this.rx_queue.pop() {
            Some(TcpEvent::Data {
                frame,
                payload_offset,
                payload_len,
            }) => Poll::Ready(TcpRecvResult::Data(TcpFrame {
                frame: Some(frame),
                payload_offset,
                payload_len,
                rx_return: this.rx_return.clone(),
            })),
            Some(TcpEvent::Connected) => Poll::Ready(TcpRecvResult::Connected),
            Some(TcpEvent::Fin) => Poll::Ready(TcpRecvResult::Fin),
            Some(TcpEvent::Reset) => Poll::Ready(TcpRecvResult::Reset),
            Some(TcpEvent::Closed) => Poll::Ready(TcpRecvResult::Closed),
            None => Poll::Pending,
        }
    }
}

/// RAII guard providing zero-copy access to received TCP payload data.
///
/// When dropped, the underlying UMEM frame is returned to the rx pool.
/// Use [`Deref<Target=[u8]>`] to access the payload bytes without copying.
pub struct TcpFrame<'umem> {
    frame: Option<Frame<'umem>>,
    payload_offset: usize,
    payload_len: usize,
    rx_return: SharedFrameBuffer<'umem>,
}

impl<'umem> TcpFrame<'umem> {
    /// Returns the length of the payload.
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.payload_len
    }

    /// Returns true if the payload is empty.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.payload_len == 0
    }
}

impl<'umem> Deref for TcpFrame<'umem> {
    type Target = [u8];

    #[inline(always)]
    fn deref(&self) -> &[u8] {
        let frame = self.frame.as_ref().unwrap();
        &frame[self.payload_offset..self.payload_offset + self.payload_len]
    }
}

impl<'umem> Drop for TcpFrame<'umem> {
    fn drop(&mut self) {
        if let Some(frame) = self.frame.take() {
            self.rx_return.push(frame);
        }
    }
}

/// Result of a TCP receive operation.
pub enum TcpRecvResult<'umem> {
    /// Data was received. Contains a [`TcpFrame`] for zero-copy access.
    Data(TcpFrame<'umem>),
    /// Connection established (three-way handshake completed).
    Connected,
    /// Peer sent FIN.
    Fin,
    /// Connection was reset by peer.
    Reset,
    /// Connection fully closed.
    Closed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::wire::ip::Ipv4Address;
    use crate::xdp::frame::BasicFrameBuffer;

    fn make_listener<'umem>(
        addr: IpAddress,
        port: u16,
    ) -> (
        TcpListener<'umem>,
        LocalQueue<AcceptedConnection<'umem>>,
    ) {
        let accept_queue = LocalQueue::new(16);
        let rx_return: SharedFrameBuffer = BasicFrameBuffer::new(256).into();
        let listener = TcpListener::new(
            addr,
            port,
            accept_queue.clone(),
            rx_return,
        );
        (listener, accept_queue)
    }

    #[test]
    fn listener_accessors() {
        let addr = IpAddress::V4(Ipv4Address::new([192, 168, 1, 1]));
        let (listener, _) = make_listener(addr, 8080);

        assert_eq!(listener.local_addr(), addr);
        assert_eq!(listener.local_port(), 8080);
    }

    #[test]
    fn stream_accessors() {
        let local_addr = IpAddress::V4(Ipv4Address::new([192, 168, 1, 1]));
        let remote_addr = IpAddress::V4(Ipv4Address::new([10, 0, 0, 2]));
        let conn_id = ConnectionId {
            local_addr,
            local_port: 8080,
            remote_addr,
            remote_port: 12345,
        };
        let rx_queue = LocalQueue::new(256);
        let cmd_queue = LocalQueue::new(64);
        let send_buffer = SharedSendBuffer::new(65536);
        let send_notify = SharedFlag::new();
        let rx_return: SharedFrameBuffer = BasicFrameBuffer::new(256).into();

        let stream = TcpStream::new(
            conn_id, rx_queue, cmd_queue, send_buffer, send_notify,
            rx_return,
        );

        assert_eq!(stream.local_addr(), local_addr);
        assert_eq!(stream.local_port(), 8080);
        assert_eq!(stream.remote_addr(), remote_addr);
        assert_eq!(stream.remote_port(), 12345);
    }

    #[test]
    fn close_pushes_command() {
        let local_addr = IpAddress::V4(Ipv4Address::new([192, 168, 1, 1]));
        let remote_addr = IpAddress::V4(Ipv4Address::new([10, 0, 0, 2]));
        let conn_id = ConnectionId {
            local_addr,
            local_port: 8080,
            remote_addr,
            remote_port: 12345,
        };
        let rx_queue = LocalQueue::new(256);
        let cmd_queue = LocalQueue::new(64);
        let send_buffer = SharedSendBuffer::new(65536);
        let send_notify = SharedFlag::new();
        let rx_return: SharedFrameBuffer = BasicFrameBuffer::new(256).into();

        let stream = TcpStream::new(
            conn_id, rx_queue, cmd_queue.clone(), send_buffer, send_notify,
            rx_return,
        );
        stream.close();

        match cmd_queue.pop() {
            Some(TcpCommand::Close) => {}
            other => panic!("expected Close, got {:?}", other.is_some()),
        }
    }

    #[test]
    fn abort_pushes_command() {
        let local_addr = IpAddress::V4(Ipv4Address::new([192, 168, 1, 1]));
        let remote_addr = IpAddress::V4(Ipv4Address::new([10, 0, 0, 2]));
        let conn_id = ConnectionId {
            local_addr,
            local_port: 8080,
            remote_addr,
            remote_port: 12345,
        };
        let rx_queue = LocalQueue::new(256);
        let cmd_queue = LocalQueue::new(64);
        let send_buffer = SharedSendBuffer::new(65536);
        let send_notify = SharedFlag::new();
        let rx_return: SharedFrameBuffer = BasicFrameBuffer::new(256).into();

        let stream = TcpStream::new(
            conn_id, rx_queue, cmd_queue.clone(), send_buffer, send_notify,
            rx_return,
        );
        stream.abort();

        match cmd_queue.pop() {
            Some(TcpCommand::Abort) => {}
            other => panic!("expected Abort, got {:?}", other.is_some()),
        }
    }

    #[test]
    fn accept_returns_pending_when_empty() {
        use crate::rt::waker::waker;
        let addr = IpAddress::V4(Ipv4Address::new([192, 168, 1, 1]));
        let (listener, _) = make_listener(addr, 8080);

        let waker = waker();
        let mut cx = std::task::Context::from_waker(&waker);
        let mut fut = listener.accept();
        let pinned = Pin::new(&mut fut);
        assert!(pinned.poll(&mut cx).is_pending());
    }

    #[test]
    fn accept_returns_ready_with_stream() {
        use crate::rt::waker::waker;
        let addr = IpAddress::V4(Ipv4Address::new([192, 168, 1, 1]));
        let remote_addr = IpAddress::V4(Ipv4Address::new([10, 0, 0, 2]));
        let (listener, accept_queue) = make_listener(addr, 8080);

        let conn_id = ConnectionId {
            local_addr: addr,
            local_port: 8080,
            remote_addr,
            remote_port: 12345,
        };
        accept_queue.push(AcceptedConnection {
            conn_id,
            rx_queue: LocalQueue::new(256),
            cmd_queue: LocalQueue::new(64),
            send_buffer: SharedSendBuffer::new(65536),
            send_notify: SharedFlag::new(),
        });

        let waker = waker();
        let mut cx = std::task::Context::from_waker(&waker);
        let mut fut = listener.accept();
        let pinned = Pin::new(&mut fut);
        match pinned.poll(&mut cx) {
            Poll::Ready(stream) => {
                assert_eq!(stream.local_addr(), addr);
                assert_eq!(stream.local_port(), 8080);
                assert_eq!(stream.remote_addr(), remote_addr);
                assert_eq!(stream.remote_port(), 12345);
            }
            Poll::Pending => panic!("expected Ready"),
        }
    }
}
