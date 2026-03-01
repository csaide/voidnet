use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use rustc_hash::FxHashMap;

use crate::net::socket::LocalQueue;
use crate::net::wire::ethernet::MacAddress;
use crate::net::wire::ip::IpAddress;
use crate::net::wire::tcp::{flags, write_mss_option, write_window_scale_option};
use crate::xdp::frame::FrameBuffer;

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
    pub(super) connections: FxHashMap<ConnectionId, Tcb<'umem>>,
    pub(super) listeners: Vec<ListenerState<'umem>>,
    _max_connections: usize,
    pub(super) time_wait_duration: Duration,
    pub(super) dirty_conn_ids: Vec<ConnectionId>,
}

impl<'umem> TcpHandler<'umem> {
    /// Creates a new handler with the given maximum connection capacity.
    pub fn new(max_connections: usize) -> Self {
        Self {
            connections: FxHashMap::default(),
            listeners: Vec::new(),
            _max_connections: max_connections,
            time_wait_duration: DEFAULT_TIME_WAIT_DURATION,
            dirty_conn_ids: Vec::new(),
        }
    }

    /// Insert a TCB and mark it dirty if it needs ticking.
    #[inline(always)]
    pub(super) fn insert_connection(&mut self, conn_id: ConnectionId, tcb: Tcb<'umem>) {
        if tcb.needs_tick {
            self.dirty_conn_ids.push(conn_id);
        }
        self.connections.insert(conn_id, tcb);
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
    ) -> LocalQueue<AcceptedConnection<'umem>> {
        let accept_queue = LocalQueue::new(backlog);
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
    pub(crate) fn connect(
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
        ConnectionId,
        LocalQueue<TcpEvent<'umem>>,
        LocalQueue<TcpCommand>,
        SharedSendBuffer,
        SharedFlag,
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
        let rx_queue = LocalQueue::new(256);
        let cmd_queue = LocalQueue::new(64);
        let send_buffer = SharedSendBuffer::new(DEFAULT_SEND_BUF_CAPACITY);
        let send_notify = SharedFlag::new();

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
            snd_wnd_scale: 0,
            rcv_wnd_scale: DEFAULT_RCV_WND_SCALE,
            last_activity: Instant::now(),
            time_wait_start: None,
            rx_queue: rx_queue.clone(),
            cmd_queue: cmd_queue.clone(),
            send_buffer: send_buffer.clone(),
            send_notify: send_notify.clone(),
            recv_reorder: BTreeMap::new(),
            retransmit_queue: RetransmitQueue::new(DEFAULT_RETRANSMIT_CAPACITY),
            rto_state: RtoState::new(),
            congestion: CongestionState::new(DEFAULT_RCV_MSS),
            delayed_ack_pending: 0,
            delayed_ack_at: None,
            dup_ack_count: 0,
            in_fast_recovery: false,
            recovery_point: 0,
            needs_tick: true,
            from_listener: false,
            rcv_wnd_per_slot: DEFAULT_RCV_WND / 256,
            local_mac,
            remote_mac,
        };

        // Send SYN with retransmit (include MSS + Window Scale options)
        let rcv_wnd = tcb.wire_rcv_wnd() as u32;
        let mut syn_opts = [0u8; 8]; // MSS(4) + NOP(1) + WS(3)
        write_mss_option(&mut syn_opts[..4], tcb.rcv_mss);
        syn_opts[4] = 1; // NOP for alignment
        write_window_scale_option(&mut syn_opts[5..], DEFAULT_RCV_WND_SCALE);
        send_and_queue_retransmit(
            &mut tcb,
            iss,
            0,
            flags::SYN,
            rcv_wnd,
            &syn_opts,
            1,
            Instant::now(),
            free_frames,
            tx_return,
        );
        self.insert_connection(conn_id, tcb);

        Some((conn_id, rx_queue, cmd_queue, send_buffer, send_notify))
    }

    /// Number of active connections.
    pub fn num_connections(&self) -> usize {
        self.connections.len()
    }

    /// Returns true if any connections need timer-driven processing.
    #[inline]
    pub fn has_pending_work(&self) -> bool {
        !self.dirty_conn_ids.is_empty()
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
        if let Some(tcb) = self.connections.remove(conn_id) {
            tcb.drain_rx_queue(rx_return);
            for (_, (frame, _, _)) in tcb.recv_reorder {
                rx_return.push(frame);
            }
        }
    }

}
