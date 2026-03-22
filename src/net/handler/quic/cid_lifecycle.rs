use super::connection_id::{CidSet, ConnectionId};

/// Manages the connection ID lifecycle per RFC 9000 §5.1
pub struct CidManager {
    /// Peer's CIDs (received via NEW_CONNECTION_ID)
    pub peer_cids: CidSet,
    /// Our CIDs (issued to the peer)
    pub local_cids: CidSet,
    /// Next sequence number for NEW_CONNECTION_ID
    pub next_sequence: u64,
    /// CIDs that need RetireConnectionId frames sent
    pub pending_retire: Vec<u64>,
    /// Active CID limit from peer's transport params
    pub active_limit: u64,
}

impl CidManager {
    pub fn new(initial_cid: ConnectionId, active_limit: u64) -> Self {
        let mut local_cids = CidSet::new();
        local_cids.push_with_seq(initial_cid, 0);
        Self {
            peer_cids: CidSet::new(),
            local_cids,
            next_sequence: 1, // 0 was the initial
            pending_retire: Vec::new(),
            active_limit,
        }
    }

    /// Process a received NEW_CONNECTION_ID frame (RFC 9000 §5.1.1).
    /// Stores the new CID, retires old ones per retire_prior_to.
    /// Returns sequence numbers that need RETIRE_CONNECTION_ID frames.
    pub fn on_new_connection_id(
        &mut self,
        sequence: u64,
        retire_prior_to: u64,
        cid: ConnectionId,
    ) -> Vec<u64> {
        let mut retired = Vec::new();

        // Retire all peer CIDs with sequence < retire_prior_to
        let mut seq = 0u64;
        while seq < retire_prior_to {
            if let Some(_removed) = self.peer_cids.remove_by_seq(seq) {
                retired.push(seq);
            }
            seq += 1;
        }

        // Store the new CID (unless it's one we should retire)
        if sequence >= retire_prior_to {
            self.peer_cids.push_with_seq(cid, sequence);
        } else {
            retired.push(sequence);
        }

        self.pending_retire.extend_from_slice(&retired);
        retired
    }

    /// Get pending RetireConnectionId sequences to send.
    pub fn take_pending_retires(&mut self) -> Vec<u64> {
        std::mem::take(&mut self.pending_retire)
    }

    /// Check if we're at the active CID limit.
    pub fn at_limit(&self) -> bool {
        self.peer_cids.len() as u64 >= self.active_limit
    }
}
