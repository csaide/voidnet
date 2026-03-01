use std::hash::{Hash, Hasher};

use crate::xdp::frame::Frame;

/// Identifies a TCP connection by its 4-tuple.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct ConnectionId {
    pub local_addr: IpAddress,
    pub local_port: u16,
    pub remote_addr: IpAddress,
    pub remote_port: u16,
}

impl Hash for ConnectionId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.local_addr.hash(state);
        self.local_port.hash(state);
        self.remote_addr.hash(state);
        self.remote_port.hash(state);
    }
}

/// TCP connection state machine (RFC 9293).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

/// Events delivered from the TCP handler to the socket layer.
pub enum TcpEvent<'umem> {
    Connected,
    Data {
        frame: Frame<'umem>,
        payload_offset: usize,
        payload_len: usize,
    },
    Fin,
    Reset,
    Closed,
}

/// Commands sent from the socket layer to the TCP handler.
pub enum TcpCommand {
    Close,
    Abort,
}

use crate::net::socket::LocalQueue;
use crate::net::wire::ip::IpAddress;

use super::tcb::{SharedFlag, SharedSendBuffer};

/// Pre-parsed TCP header fields to avoid redundant parsing.
#[derive(Clone, Copy)]
pub(crate) struct ParsedTcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub flags: u8,
    pub window: u16,
    pub header_len: usize,
}

/// Per-connection state pushed through the accept queue when a
/// three-way handshake completes. Carries everything needed for
/// `TcpListener` to construct a `TcpStream` without calling back
/// into the runtime.
pub(crate) struct AcceptedConnection<'umem> {
    pub conn_id: ConnectionId,
    pub rx_queue: LocalQueue<TcpEvent<'umem>>,
    pub cmd_queue: LocalQueue<TcpCommand>,
    pub send_buffer: SharedSendBuffer,
    pub send_notify: SharedFlag,
}
