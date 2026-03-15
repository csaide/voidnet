use crate::net::handler::udp::BindError;
use crate::net::socket::LocalQueue;
use crate::net::wire::ip::IpAddress;

use super::TcpHandler;
use super::state::TcpState;
use super::tcb::{ConnectionId, TcpConfig};

/// Entry for a listening socket.
pub(crate) struct ListenEntry {
    pub addr: IpAddress,
    pub port: u16,
    pub backlog: usize,
    pub accept_queue: LocalQueue<ConnectionId>,
    pub syn_received_count: usize,
    pub send_buffer_size: usize,
    pub recv_buffer_size: usize,
    pub time_wait_duration: u64,
    pub tcp_no_delay: bool,
    pub delayed_ack_ms: u64,
    pub keep_alive: bool,
    pub keep_alive_idle_ms: u64,
    pub keep_alive_interval_ms: u64,
    pub keep_alive_count: u8,
    pub linger: Option<u64>,
    pub timestamps: bool,
    pub sack: bool,
    pub ecn: bool,
}

impl TcpHandler {
    /// Register a listening socket on (addr, port).
    pub fn listen(
        &mut self,
        addr: IpAddress,
        port: u16,
        backlog: usize,
    ) -> Result<LocalQueue<ConnectionId>, BindError> {
        let config = TcpConfig {
            backlog,
            ..TcpConfig::default()
        };
        self.listen_with_config(addr, port, config)
    }

    /// Register a listening socket with custom buffer configuration.
    pub fn listen_with_config(
        &mut self,
        addr: IpAddress,
        port: u16,
        config: TcpConfig,
    ) -> Result<LocalQueue<ConnectionId>, BindError> {
        // Check for duplicate listeners.
        if self.listeners.iter().any(|l| {
            l.port == port && (l.addr == addr || l.addr.is_unspecified() || addr.is_unspecified())
        }) {
            return Err(BindError::AddressInUse);
        }
        let accept_queue = LocalQueue::new(config.backlog);
        self.listeners.push(ListenEntry {
            addr,
            port,
            backlog: config.backlog,
            accept_queue: accept_queue.clone(),
            syn_received_count: 0,
            send_buffer_size: config.send_buffer_size,
            recv_buffer_size: config.recv_buffer_size,
            time_wait_duration: config.time_wait_duration_ms,
            tcp_no_delay: config.tcp_no_delay,
            delayed_ack_ms: config.delayed_ack_ms,
            keep_alive: config.keep_alive,
            keep_alive_idle_ms: config.keep_alive_idle_ms,
            keep_alive_interval_ms: config.keep_alive_interval_ms,
            keep_alive_count: config.keep_alive_count,
            linger: config.linger,
            timestamps: config.timestamps,
            sack: config.sack,
            ecn: config.ecn,
        });
        Ok(accept_queue)
    }

    /// Remove a listener on (addr, port) and clean up associated SYN-RECEIVED connections.
    pub fn unlisten(&mut self, addr: IpAddress, port: u16) {
        self.listeners
            .retain(|l| !(l.port == port && l.addr == addr));
        // Remove any SYN-RECEIVED connections associated with this listener.
        self.connections.retain(|_id, c| {
            !(c.state == TcpState::SynReceived
                && c.from_passive_open
                && c.id.local_port == port
                && (addr.is_unspecified() || c.id.local_addr == addr))
        });
    }

    /// Push a ConnectionId to the matching listener's accept queue (associated function for split-borrow).
    pub(super) fn push_to_accept_queue_on(
        listeners: &[ListenEntry],
        id: &ConnectionId,
    ) {
        for listener in listeners {
            if listener.port == id.local_port
                && (listener.addr.is_unspecified() || listener.addr == id.local_addr)
            {
                listener.accept_queue.push(*id);
                return;
            }
        }
    }

    /// Decrement syn_received_count on the matching listener (associated function for split-borrow).
    pub(super) fn decrement_syn_received(listeners: &mut Vec<ListenEntry>, id: &ConnectionId) {
        for listener in listeners.iter_mut() {
            if listener.port == id.local_port
                && (listener.addr.is_unspecified() || listener.addr == id.local_addr)
            {
                listener.syn_received_count = listener.syn_received_count.saturating_sub(1);
                return;
            }
        }
    }
}
