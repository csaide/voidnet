use rustc_hash::FxHashMap;

use crate::{
    net::wire::{ethernet::MacAddress, tcp::flags},
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
    pub(super) connections: FxHashMap<ConnectionId, Tcb>,
    pub(super) listeners: Vec<listener::ListenEntry>,
    pub(super) isn_generator: IsnGenerator,
    pub(super) rx_offload: bool,
    pub(super) tx_offload: bool,
}

impl TcpHandler {
    pub fn new(rx_offload: bool, tx_offload: bool) -> Self {
        Self {
            connections: FxHashMap::default(),
            listeners: Vec::new(),
            isn_generator: IsnGenerator::new(),
            rx_offload,
            tx_offload,
        }
    }

    /// Get a reference to the connection for a given ConnectionId.
    pub fn get_connection(&self, id: &ConnectionId) -> Option<&Tcb> {
        self.connections.get(id)
    }

    /// Get a mutable reference to the connection for a given ConnectionId.
    pub fn get_connection_mut(&mut self, id: &ConnectionId) -> Option<&mut Tcb> {
        self.connections.get_mut(id)
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
        // Extract what we need before removing (avoids borrow conflict).
        let should_rst = self.connections.get(id).map(|tcb| {
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
        self.connections.remove(id);
    }

    /// Get the first connection (test helper).
    #[cfg(test)]
    pub fn first_connection(&self) -> &Tcb {
        self.connections.values().next().unwrap()
    }

    /// Get the first connection mutably (test helper).
    #[cfg(test)]
    pub fn first_connection_mut(&mut self) -> &mut Tcb {
        self.connections.values_mut().next().unwrap()
    }
}
