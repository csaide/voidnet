use rustc_hash::FxHashMap;
use slab::Slab;

use crate::{
    net::wire::{ethernet::MacAddress, tcp::flags},
    xdp::frame::FrameBuffer,
};

use super::{
    isn::IsnGenerator,
    listener,
    segment::SegmentBuilder,
    send_tracker::SendTracker,
    state::TcpState,
    tcb::{ConnectionId, Tcb},
    timer_kinds::TcpTimerHandles,
};

/// Initial RTO for SYN retransmission (1 second in coarsetime ticks).
pub(super) const INITIAL_RTO_MS: u64 = 1000;

/// R2 threshold for SYN retransmission (~3 minutes per MUST-23).
pub(super) const SYN_R2_THRESHOLD_MS: u64 = 180_000;

/// TCP protocol handler.
///
/// Manages the connection table, listener table, and dispatches
/// incoming TCP segments through the appropriate state machine.
pub struct TcpHandler {
    pub(super) connections: Slab<Tcb>,
    pub(crate) timer_handles: Slab<TcpTimerHandles>,
    pub(super) connection_map: FxHashMap<ConnectionId, usize>,
    pub(super) listeners: Vec<listener::ListenEntry>,
    pub(super) isn_generator: IsnGenerator,
    pub(crate) send_tracker: SendTracker,
    pub(super) rx_offload: bool,
    pub(super) tx_offload: bool,
}

impl TcpHandler {
    pub fn new(rx_offload: bool, tx_offload: bool) -> Self {
        Self {
            connections: Slab::new(),
            timer_handles: Slab::new(),
            connection_map: FxHashMap::default(),
            listeners: Vec::new(),
            isn_generator: IsnGenerator::new(),
            send_tracker: SendTracker::new(),
            rx_offload,
            tx_offload,
        }
    }

    /// Get a reference to the connection for a given ConnectionId.
    pub fn get_connection(&self, id: &ConnectionId) -> Option<&Tcb> {
        let &key = self.connection_map.get(id)?;
        self.connections.get(key)
    }

    /// Get a mutable reference to the connection for a given ConnectionId.
    pub fn get_connection_mut(&mut self, id: &ConnectionId) -> Option<&mut Tcb> {
        let &key = self.connection_map.get(id)?;
        self.connections.get_mut(key)
    }

    /// Look up slab key for a ConnectionId.
    pub fn connection_key(&self, id: &ConnectionId) -> Option<usize> {
        self.connection_map.get(id).copied()
    }

    /// Get a reference to the connection by slab key.
    #[inline(always)]
    pub fn get_by_key(&self, key: usize) -> Option<&Tcb> {
        self.connections.get(key)
    }

    /// Get a mutable reference to the connection by slab key.
    #[inline(always)]
    pub fn get_by_key_mut(&mut self, key: usize) -> Option<&mut Tcb> {
        self.connections.get_mut(key)
    }

    /// Insert a new connection, returning its slab key.
    pub fn insert_connection(&mut self, tcb: Tcb) -> usize {
        let id = tcb.id;
        let key = self.connections.insert(tcb);
        let handle_key = self.timer_handles.insert(TcpTimerHandles::new());
        debug_assert_eq!(key, handle_key, "timer_handles slab key mismatch");
        self.connection_map.insert(id, key);
        key
    }

    /// Remove a connection by slab key.
    pub fn remove_connection_by_key(&mut self, key: usize) -> Option<Tcb> {
        if self.connections.contains(key) {
            let tcb = self.connections.remove(key);
            self.connection_map.remove(&tcb.id);
            if self.timer_handles.contains(key) {
                self.timer_handles.remove(key);
            }
            Some(tcb)
        } else {
            None
        }
    }

    /// Remove a connection by ConnectionId and send RST if synchronized.
    pub fn remove_connection<'umem>(
        &mut self,
        id: &ConnectionId,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let Some(&key) = self.connection_map.get(id) else {
            return;
        };
        let should_rst = self.connections.get(key).map(|tcb| {
            let needs_rst = tcb.state.is_synchronized() || tcb.state == TcpState::SynReceived;
            (needs_rst, tcb.snd_nxt)
        });
        if let Some((true, snd_nxt)) = should_rst {
            SegmentBuilder::build_rst(
                id.local_addr,
                id.remote_addr,
                id.local_port,
                id.remote_port,
                0,
                snd_nxt,
                flags::ACK,
                0,
                src_mac,
                dst_mac,
                self.tx_offload,
                free_frames,
                tx_return,
            );
        }
        self.send_tracker.unmark(key);
        self.remove_connection_by_key(key);
    }

    /// Write data to a connection's send buffer and mark it for sending.
    /// Returns the number of bytes written.
    pub fn write_to_send_buffer(&mut self, key: usize, data: &[u8]) -> Option<usize> {
        let n = self.connections.get_mut(key)?.send_buffer.write(data);
        if n > 0 {
            self.send_tracker.mark(super::send_tracker::SendReady(key));
        }
        Some(n)
    }

    /// Transfer data from recv_buffer to send_buffer and mark for sending.
    /// Returns the number of bytes transferred, or None if connection not found.
    pub fn splice_buffers(&mut self, key: usize, max_len: usize) -> Option<(usize, bool)> {
        let tcb = self.connections.get_mut(key)?;
        let n = tcb.recv_buffer.transfer(&mut tcb.send_buffer, max_len);
        if n > 0 {
            self.send_tracker.mark(super::send_tracker::SendReady(key));
        }
        let is_remote_closed = tcb.state.is_remote_closed();
        Some((n, is_remote_closed))
    }

    /// Get the first connection (test helper).
    #[cfg(test)]
    pub fn first_connection(&self) -> &Tcb {
        self.connections.iter().next().unwrap().1
    }

    /// Get the first connection mutably (test helper).
    #[cfg(test)]
    pub fn first_connection_mut(&mut self) -> &mut Tcb {
        self.connections.iter_mut().next().unwrap().1
    }

    /// Get the first connection's slab key (test helper).
    #[cfg(test)]
    pub fn first_connection_key(&self) -> usize {
        self.connections.iter().next().unwrap().0
    }
}
