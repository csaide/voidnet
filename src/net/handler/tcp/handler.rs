use crate::{
    net::wire::{
        ethernet::MacAddress,
        tcp::flags,
    },
    xdp::frame::FrameBuffer,
};

use super::{
    isn::IsnGenerator,
    listener,
    segment::SegmentBuilder,
    state::TcpState,
    tcb::{ConnectionId, Tcb},
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
    pub(super) connections: Vec<Tcb>,
    pub(super) listeners: Vec<listener::ListenEntry>,
    pub(super) isn_generator: IsnGenerator,
    pub(super) rx_offload: bool,
    pub(super) tx_offload: bool,
}

impl TcpHandler {
    pub fn new(rx_offload: bool, tx_offload: bool) -> Self {
        Self {
            connections: Vec::new(),
            listeners: Vec::new(),
            isn_generator: IsnGenerator::new(),
            rx_offload,
            tx_offload,
        }
    }

    /// Get a reference to the connection for a given ConnectionId.
    pub fn get_connection(&self, id: &ConnectionId) -> Option<&Tcb> {
        self.connections.iter().find(|c| c.id == *id)
    }

    /// Get a mutable reference to the connection for a given ConnectionId.
    pub fn get_connection_mut(&mut self, id: &ConnectionId) -> Option<&mut Tcb> {
        self.connections.iter_mut().find(|c| c.id == *id)
    }

    /// Find the index of a connection by ID.
    #[inline]
    pub fn find_connection_idx(&self, id: &ConnectionId) -> Option<usize> {
        self.connections.iter().position(|c| c.id == *id)
    }

    /// Get a mutable reference by cached index, validating the connection ID matches.
    /// Returns the TCB and the (possibly updated) index, or None if not found.
    /// Falls back to linear scan if the cached index is stale.
    #[inline]
    pub fn get_connection_by_idx_mut(
        &mut self,
        idx: usize,
        id: &ConnectionId,
    ) -> Option<(usize, &mut Tcb)> {
        if let Some(tcb) = self.connections.get(idx) {
            if tcb.id == *id {
                // SAFETY: we just checked bounds above; re-borrow mutably.
                return Some((idx, &mut self.connections[idx]));
            }
        }
        // Index is stale — fall back to linear scan.
        if let Some(new_idx) = self.connections.iter().position(|c| c.id == *id) {
            Some((new_idx, &mut self.connections[new_idx]))
        } else {
            None
        }
    }

    /// Remove a connection by ConnectionId (used by TcpStream::close).
    pub fn remove_connection<'umem>(
        &mut self,
        id: &ConnectionId,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        if let Some(idx) = self.connections.iter().position(|c| c.id == *id) {
            let tcb = &self.connections[idx];
            // Send RST for now (proper FIN sequence deferred).
            if tcb.state.is_synchronized() || tcb.state == TcpState::SynReceived {
                SegmentBuilder::build_rst(
                    id.local_addr,
                    id.remote_addr,
                    id.local_port,
                    id.remote_port,
                    0,
                    0,
                    flags::ACK,
                    0,
                    src_mac,
                    dst_mac,
                    self.tx_offload,
                    free_frames,
                    tx_return,
                );
            }
            self.connections.remove(idx);
        }
    }
}
