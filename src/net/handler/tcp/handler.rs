use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::net::socket::SharedQueue;
use crate::net::wire::ethernet::MacAddress;
use crate::net::wire::ip::IpAddress;
use crate::net::wire::tcp::{flags, write_mss_option};
use crate::xdp::frame::{BasicFrameBuffer, FrameBuffer, SharedFrameBuffer};

use super::segment::*;
use super::tcb::*;
use super::types::*;

/// Manages TCP connections, listeners, and the connection lifecycle.
///
/// Owns all connection state (TCBs) and listener registrations. The
/// `LocalRuntime` drives it each tick via `process_ipv4`/`process_ipv6`
/// for inbound segments, `tick` for outbound data and retransmissions,
/// and `evict_stale` for TIME-WAIT cleanup.
pub struct TcpHandler<'umem> {
    pub(super) connections: HashMap<ConnectionId, Tcb<'umem>>,
    pub(super) listeners: Vec<ListenerState<'umem>>,
    _max_connections: usize,
    pub(super) time_wait_duration: Duration,
    pub(super) tick_conn_ids: Vec<ConnectionId>,
}

impl<'umem> TcpHandler<'umem> {
    /// Creates a new handler with the given maximum connection capacity.
    pub fn new(max_connections: usize) -> Self {
        Self {
            connections: HashMap::new(),
            listeners: Vec::new(),
            _max_connections: max_connections,
            time_wait_duration: DEFAULT_TIME_WAIT_DURATION,
            tick_conn_ids: Vec::new(),
        }
    }

    /// Overrides the default TIME-WAIT duration (60s).
    pub fn set_time_wait_duration(&mut self, duration: Duration) {
        self.time_wait_duration = duration;
    }

    /// Register a listener. Returns the accept queue for the socket layer.
    pub(crate) fn listen(
        &mut self,
        addr: IpAddress,
        port: u16,
        backlog: usize,
    ) -> SharedQueue<AcceptedConnection<'umem>> {
        let accept_queue = SharedQueue::new(backlog);
        self.listeners.push(ListenerState {
            addr,
            port,
            accept_queue: accept_queue.clone(),
            backlog,
            pending: 0,
        });
        accept_queue
    }

    /// Initiate an active open (connect). Returns queues for the socket layer.
    pub fn connect(
        &mut self,
        local_addr: IpAddress,
        local_port: u16,
        remote_addr: IpAddress,
        remote_port: u16,
        local_mac: MacAddress,
        remote_mac: MacAddress,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) -> Option<(
        SharedQueue<TcpEvent<'umem>>,
        SharedQueue<TcpCommand>,
        SharedFrameBuffer<'umem>,
    )> {
        let conn_id = ConnectionId {
            local_addr,
            local_port,
            remote_addr,
            remote_port,
        };
        if self.connections.contains_key(&conn_id) {
            return None;
        }

        let iss = generate_isn(&conn_id);
        let rx_queue = SharedQueue::new(256);
        let cmd_queue = SharedQueue::new(64);
        let send_buffer: SharedFrameBuffer = BasicFrameBuffer::new(256).into();

        let mut tcb = Tcb {
            state: TcpState::SynSent,
            conn_id,
            snd_una: iss,
            snd_nxt: iss.wrapping_add(1),
            snd_wnd: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            iss,
            rcv_nxt: 0,
            rcv_wnd: DEFAULT_RCV_WND,
            irs: 0,
            snd_mss: DEFAULT_RCV_MSS,
            rcv_mss: DEFAULT_RCV_MSS,
            last_activity: Instant::now(),
            time_wait_start: None,
            rx_queue: rx_queue.clone(),
            cmd_queue: cmd_queue.clone(),
            send_buffer: send_buffer.clone(),
            recv_reorder: BTreeMap::new(),
            retransmit_queue: VecDeque::new(),
            rto_state: RtoState::new(),
            congestion: CongestionState::new(DEFAULT_RCV_MSS),
            from_listener: false,
            local_mac,
            remote_mac,
        };

        // Send SYN with retransmit
        let rcv_wnd = tcb.rcv_wnd;
        let mut mss_opt = [0u8; 4];
        write_mss_option(&mut mss_opt, tcb.rcv_mss);
        send_and_queue_retransmit(
            &mut tcb,
            iss,
            0,
            flags::SYN,
            rcv_wnd,
            &mss_opt,
            1,
            free_frames,
            tx_return,
        );
        self.connections.insert(conn_id, tcb);

        Some((rx_queue, cmd_queue, send_buffer))
    }

    /// Number of active connections.
    pub fn num_connections(&self) -> usize {
        self.connections.len()
    }

    pub(super) fn find_listener(&self, addr: IpAddress, port: u16) -> Option<usize> {
        self.listeners
            .iter()
            .position(|l| l.port == port && (l.addr == addr || l.addr.is_unspecified()))
    }

    pub(super) fn remove_connection(
        &mut self,
        conn_id: &ConnectionId,
        rx_return: &mut impl FrameBuffer<'umem>,
    ) {
        if let Some(mut tcb) = self.connections.remove(conn_id) {
            for (_, (frame, _, _)) in tcb.recv_reorder {
                rx_return.push(frame);
            }
            for entry in tcb.retransmit_queue {
                rx_return.push(entry.frame);
            }
            while let Some(frame) = tcb.send_buffer.pop() {
                rx_return.push(frame);
            }
        }
    }

    pub(super) fn decrement_listener_pending(&mut self, conn_id: &ConnectionId) {
        if let Some(idx) = self.find_listener(conn_id.local_addr, conn_id.local_port) {
            if self.listeners[idx].pending > 0 {
                self.listeners[idx].pending -= 1;
            }
        }
    }
}
