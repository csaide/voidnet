use std::pin::Pin;
use std::task::{Context, Poll};

use crate::net::handler::tcp::{AcceptedConnection, TcpCommand, TcpEvent};
use crate::net::wire::ip::IpAddress;
use crate::xdp::frame::{Frame, FrameBuffer, SharedFrameBuffer};

use super::SharedQueue;

/// A user-facing TCP listener handle.
///
/// Obtained via `LocalRuntime::listen_tcp()`. The handler pushes accepted
/// connections into `accept_queue` when the three-way handshake completes.
/// Calling [`accept`](TcpListener::accept) returns a [`TcpStream`] directly.
pub struct TcpListener<'umem> {
    local_addr: IpAddress,
    local_port: u16,
    accept_queue: SharedQueue<AcceptedConnection<'umem>>,
    free_frames: SharedFrameBuffer<'umem>,
    rx_return: SharedFrameBuffer<'umem>,
}

impl<'umem> TcpListener<'umem> {
    pub(crate) fn new(
        local_addr: IpAddress,
        local_port: u16,
        accept_queue: SharedQueue<AcceptedConnection<'umem>>,
        free_frames: SharedFrameBuffer<'umem>,
        rx_return: SharedFrameBuffer<'umem>,
    ) -> Self {
        Self {
            local_addr,
            local_port,
            accept_queue,
            free_frames,
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
            free_frames: &self.free_frames,
            rx_return: &self.rx_return,
        }
    }
}

/// Future returned by [`TcpListener::accept`].
///
/// Designed for the `LocalRuntime`'s busy-poll model: the runtime
/// repeatedly polls this future using a no-op waker.
pub struct TcpAcceptFuture<'sock, 'umem> {
    accept_queue: &'sock SharedQueue<AcceptedConnection<'umem>>,
    free_frames: &'sock SharedFrameBuffer<'umem>,
    rx_return: &'sock SharedFrameBuffer<'umem>,
}

impl<'sock, 'umem> Future for TcpAcceptFuture<'sock, 'umem> {
    type Output = TcpStream<'umem>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match this.accept_queue.pop() {
            Some(accepted) => Poll::Ready(TcpStream::new(
                accepted.local_addr,
                accepted.local_port,
                accepted.remote_addr,
                accepted.remote_port,
                accepted.rx_queue,
                accepted.cmd_queue,
                accepted.send_buffer,
                this.free_frames.clone(),
                this.rx_return.clone(),
            )),
            None => Poll::Pending,
        }
    }
}

/// A user-facing TCP stream handle.
///
/// Obtained via `LocalRuntime::connect_tcp()` or by accepting a connection
/// from a `TcpListener`. Provides read/write operations and close/abort
/// commands.
pub struct TcpStream<'umem> {
    local_addr: IpAddress,
    local_port: u16,
    remote_addr: IpAddress,
    remote_port: u16,
    rx_queue: SharedQueue<TcpEvent<'umem>>,
    cmd_queue: SharedQueue<TcpCommand>,
    send_buffer: SharedFrameBuffer<'umem>,
    free_frames: SharedFrameBuffer<'umem>,
    rx_return: SharedFrameBuffer<'umem>,
}

impl<'umem> TcpStream<'umem> {
    pub(crate) fn new(
        local_addr: IpAddress,
        local_port: u16,
        remote_addr: IpAddress,
        remote_port: u16,
        rx_queue: SharedQueue<TcpEvent<'umem>>,
        cmd_queue: SharedQueue<TcpCommand>,
        send_buffer: SharedFrameBuffer<'umem>,
        free_frames: SharedFrameBuffer<'umem>,
        rx_return: SharedFrameBuffer<'umem>,
    ) -> Self {
        Self {
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            rx_queue,
            cmd_queue,
            send_buffer,
            free_frames,
            rx_return,
        }
    }

    pub fn local_addr(&self) -> IpAddress {
        self.local_addr
    }

    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    pub fn remote_addr(&self) -> IpAddress {
        self.remote_addr
    }

    pub fn remote_port(&self) -> u16 {
        self.remote_port
    }

    /// Returns a future that writes data to the TCP stream.
    ///
    /// Allocates a frame from `free_frames`, copies the payload, and pushes
    /// it to `send_buffer`. The handler drains `send_buffer` during `tick()`.
    #[inline(always)]
    pub fn write<'buf>(&mut self, data: &'buf [u8]) -> TcpWriteFuture<'_, 'buf, 'umem> {
        TcpWriteFuture {
            send_buffer: &mut self.send_buffer,
            free_frames: &mut self.free_frames,
            data,
        }
    }

    /// Returns a future that reads data from the TCP stream.
    #[inline(always)]
    pub fn read<'buf>(&mut self, buf: &'buf mut [u8]) -> TcpReadFuture<'_, 'buf, 'umem> {
        TcpReadFuture {
            rx_queue: &self.rx_queue,
            rx_return: &mut self.rx_return,
            buf,
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

    /// Return a frame to the rx_return buffer after direct processing.
    pub fn discard_frame(&mut self, frame: Frame<'umem>) {
        self.rx_return.push(frame);
    }
}

/// Future returned by [`TcpStream::write`].
///
/// Designed for the `LocalRuntime`'s busy-poll model.
pub struct TcpWriteFuture<'sock, 'buf, 'umem> {
    send_buffer: &'sock mut SharedFrameBuffer<'umem>,
    free_frames: &'sock mut SharedFrameBuffer<'umem>,
    data: &'buf [u8],
}

impl<'sock, 'buf, 'umem> Future for TcpWriteFuture<'sock, 'buf, 'umem> {
    type Output = usize;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        let mut frame = match this.free_frames.pop() {
            Some(f) => f,
            None => return Poll::Pending,
        };

        let len = this.data.len().min(frame.capacity());
        unsafe { frame.set_len(len) };
        frame[..len].copy_from_slice(&this.data[..len]);
        this.send_buffer.push(frame);
        Poll::Ready(len)
    }
}

/// Future returned by [`TcpStream::read`].
///
/// Designed for the `LocalRuntime`'s busy-poll model.
pub struct TcpReadFuture<'sock, 'buf, 'umem> {
    rx_queue: &'sock SharedQueue<TcpEvent<'umem>>,
    rx_return: &'sock mut SharedFrameBuffer<'umem>,
    buf: &'buf mut [u8],
}

impl<'sock, 'buf, 'umem> Future for TcpReadFuture<'sock, 'buf, 'umem> {
    type Output = TcpReadResult;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        match this.rx_queue.pop() {
            Some(TcpEvent::Data {
                frame,
                payload_offset,
                payload_len,
            }) => {
                let copy_len = payload_len.min(this.buf.len());
                this.buf[..copy_len]
                    .copy_from_slice(&frame[payload_offset..payload_offset + copy_len]);
                this.rx_return.push(frame);
                Poll::Ready(TcpReadResult::Data(copy_len))
            }
            Some(TcpEvent::Connected) => Poll::Ready(TcpReadResult::Connected),
            Some(TcpEvent::PeerClosed) => Poll::Ready(TcpReadResult::PeerClosed),
            Some(TcpEvent::Reset) => Poll::Ready(TcpReadResult::Reset),
            Some(TcpEvent::Closed) => Poll::Ready(TcpReadResult::Closed),
            None => Poll::Pending,
        }
    }
}

/// Result of a TCP read operation.
#[derive(Debug)]
pub enum TcpReadResult {
    /// Data was received. Contains the number of bytes copied.
    Data(usize),
    /// Connection established (three-way handshake completed).
    Connected,
    /// Peer closed their end of the connection (received FIN).
    PeerClosed,
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
        SharedQueue<AcceptedConnection<'umem>>,
    ) {
        let accept_queue = SharedQueue::new(16);
        let free_frames: SharedFrameBuffer = BasicFrameBuffer::new(256).into();
        let rx_return: SharedFrameBuffer = BasicFrameBuffer::new(256).into();
        let listener = TcpListener::new(
            addr,
            port,
            accept_queue.clone(),
            free_frames,
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
        let rx_queue = SharedQueue::new(256);
        let cmd_queue = SharedQueue::new(64);
        let send_buffer: SharedFrameBuffer = BasicFrameBuffer::new(256).into();
        let free_frames: SharedFrameBuffer = BasicFrameBuffer::new(256).into();
        let rx_return: SharedFrameBuffer = BasicFrameBuffer::new(256).into();

        let stream = TcpStream::new(
            local_addr, 8080, remote_addr, 12345, rx_queue, cmd_queue, send_buffer, free_frames,
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
        let rx_queue = SharedQueue::new(256);
        let cmd_queue = SharedQueue::new(64);
        let send_buffer: SharedFrameBuffer = BasicFrameBuffer::new(256).into();
        let free_frames: SharedFrameBuffer = BasicFrameBuffer::new(256).into();
        let rx_return: SharedFrameBuffer = BasicFrameBuffer::new(256).into();

        let stream = TcpStream::new(
            local_addr, 8080, remote_addr, 12345, rx_queue, cmd_queue.clone(), send_buffer,
            free_frames, rx_return,
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
        let rx_queue = SharedQueue::new(256);
        let cmd_queue = SharedQueue::new(64);
        let send_buffer: SharedFrameBuffer = BasicFrameBuffer::new(256).into();
        let free_frames: SharedFrameBuffer = BasicFrameBuffer::new(256).into();
        let rx_return: SharedFrameBuffer = BasicFrameBuffer::new(256).into();

        let stream = TcpStream::new(
            local_addr, 8080, remote_addr, 12345, rx_queue, cmd_queue.clone(), send_buffer,
            free_frames, rx_return,
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

        accept_queue.push(AcceptedConnection {
            local_addr: addr,
            local_port: 8080,
            remote_addr,
            remote_port: 12345,
            rx_queue: SharedQueue::new(256),
            cmd_queue: SharedQueue::new(64),
            send_buffer: BasicFrameBuffer::new(256).into(),
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
