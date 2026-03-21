use super::connection_id::{CidSet, ConnectionId};

/// Manages the connection ID lifecycle per RFC 9000 §5.1
pub struct CidManager {
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
        local_cids.push(initial_cid);
        Self {
            local_cids,
            next_sequence: 1, // 0 was the initial
            pending_retire: Vec::new(),
            active_limit,
        }
    }

    /// Process a received NEW_CONNECTION_ID frame.
    /// Returns CIDs that were retired (need RetireConnectionId frames).
    pub fn on_new_connection_id(
        &mut self,
        sequence: u64,
        retire_prior_to: u64,
        cid: ConnectionId,
    ) -> Vec<u64> {
        let mut retired = Vec::new();

        // Retire all CIDs with sequence < retire_prior_to
        // (In practice, we'd track sequence numbers per CID in the CidSet)
        // For now, store the sequences that need RetireConnectionId frames
        for seq in 0..retire_prior_to {
            if seq < sequence {
                // don't retire the one we just received
                retired.push(seq);
            }
        }

        self.pending_retire.extend_from_slice(&retired);
        let _ = cid; // suppress unused warning; in practice we'd store it
        retired
    }

    /// Get pending RetireConnectionId sequences to send.
    pub fn take_pending_retires(&mut self) -> Vec<u64> {
        std::mem::take(&mut self.pending_retire)
    }

    /// Check if we're at the active CID limit.
    pub fn at_limit(&self) -> bool {
        self.local_cids.len() as u64 >= self.active_limit
    }
}
