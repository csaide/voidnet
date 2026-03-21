use rustc_hash::FxHashMap;
use slab::Slab;
use std::sync::Arc;
use std::time::Instant;

use crate::net::handler::quic::connection::QuicConnectionState;
use crate::net::handler::quic::connection_id::ConnectionId;
use crate::net::handler::quic::timer_kinds::*;
use crate::net::handler::quic::transport::params::TransportParams;
use crate::net::neighbor::NeighborHandler;
use crate::net::timer_wheel::TimerWheel;
use crate::xdp::frame::{Frame, FrameBuffer};

pub struct ListenerState {
    pub tls_config: Arc<rustls::ServerConfig>,
    pub transport_params: TransportParams,
    // accept_queue will be added in Task 20 (socket API)
}

/// QUIC protocol handler.
///
/// Manages the connection table, listener table, and dispatches
/// incoming QUIC packets through the appropriate state machine.
pub struct QuicHandler {
    pub(crate) connections: Slab<QuicConnectionState>,
    pub(crate) cid_map: FxHashMap<ConnectionId, usize>,
    pub(crate) listeners: FxHashMap<u16, ListenerState>,
    pub(crate) rx_offload: bool,
    pub(crate) tx_offload: bool,
}

impl QuicHandler {
    pub fn new(rx_offload: bool, tx_offload: bool) -> Self {
        Self {
            connections: Slab::new(),
            cid_map: FxHashMap::default(),
            listeners: FxHashMap::default(),
            rx_offload,
            tx_offload,
        }
    }

    /// Check if a UDP destination port is registered as a QUIC listener.
    pub fn is_quic_port(&self, port: u16) -> bool {
        self.listeners.contains_key(&port)
    }

    /// Register a QUIC listener on a port.
    pub fn listen(
        &mut self,
        port: u16,
        tls_config: Arc<rustls::ServerConfig>,
        params: TransportParams,
    ) {
        self.listeners.insert(
            port,
            ListenerState {
                tls_config,
                transport_params: params,
            },
        );
    }

    /// Process an incoming IPv4 UDP packet destined for a QUIC port.
    pub fn process_ipv4<'umem>(
        &mut self,
        frame: Frame<'umem>,
        _now: Instant,
        _wheel: &mut TimerWheel,
        _neighbor_handler: &NeighborHandler,
        _free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        _tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        // TODO: Parse IP + UDP headers, extract QUIC packet
        // For now, just return the frame to rx_return
        rx_return.push(frame);
    }

    /// Process an incoming IPv6 UDP packet destined for a QUIC port.
    pub fn process_ipv6<'umem>(
        &mut self,
        frame: Frame<'umem>,
        _now: Instant,
        _wheel: &mut TimerWheel,
        _neighbor_handler: &NeighborHandler,
        _free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        _tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        rx_return.push(frame);
    }

    /// Handle a fired QUIC timer.
    pub fn handle_timer<'umem>(
        &mut self,
        _key: usize,
        _kind: QuicTimerKind,
        _now: Instant,
        _wheel: &mut TimerWheel,
        _free_frames: &mut impl FrameBuffer<'umem>,
        _rx_return: &mut impl FrameBuffer<'umem>,
        _tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        // TODO: dispatch to connection's timer handler
    }

    /// Poll connections for outgoing data.
    pub fn poll_send<'umem>(
        &mut self,
        _now: Instant,
        _wheel: &mut TimerWheel,
        _free_frames: &mut impl FrameBuffer<'umem>,
        _tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        // TODO: iterate connections with pending data
    }

    /// Evict stale connections (called periodically).
    pub fn evict_stale(&mut self, _now: Instant) {
        // TODO: check idle timeouts
    }

    /// Look up a connection by CID.
    pub fn get_connection(&self, cid: &ConnectionId) -> Option<(usize, &QuicConnectionState)> {
        let key = self.cid_map.get(cid)?;
        Some((*key, &self.connections[*key]))
    }

    /// Look up a mutable connection by CID.
    pub fn get_connection_mut(
        &mut self,
        cid: &ConnectionId,
    ) -> Option<(usize, &mut QuicConnectionState)> {
        let key = self.cid_map.get(cid)?;
        Some((*key, &mut self.connections[*key]))
    }

    /// Insert a new connection, returning its slab key.
    pub fn insert_connection(&mut self, conn: QuicConnectionState) -> usize {
        let dcid = conn.dcid;
        let key = self.connections.insert(conn);
        self.cid_map.insert(dcid, key);
        key
    }

    /// Remove a connection by slab key.
    pub fn remove_connection_by_key(&mut self, key: usize) -> Option<QuicConnectionState> {
        if self.connections.contains(key) {
            let conn = self.connections.remove(key);
            self.cid_map.remove(&conn.dcid);
            // Also remove all SCIDs
            for cid in conn.scid_set.iter() {
                self.cid_map.remove(cid);
            }
            Some(conn)
        } else {
            None
        }
    }
}
