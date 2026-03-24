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
    /// Highest sequence number issued to peer via NEW_CONNECTION_ID
    pub highest_issued_seq: u64,
    /// Whether a replacement CID needs to be issued (after peer retires one of ours)
    pub needs_replacement_cid: bool,
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
            highest_issued_seq: 0,
            needs_replacement_cid: false,
        }
    }

    /// Process a received NEW_CONNECTION_ID frame (RFC 9000 §5.1.1).
    /// Stores the new CID, retires old ones per retire_prior_to.
    pub fn on_new_connection_id(&mut self, sequence: u64, retire_prior_to: u64, cid: ConnectionId) {
        // Retire all peer CIDs with sequence < retire_prior_to
        // Iterate over existing entries (bounded by CidSet capacity), not the sequence range
        let seqs_to_retire: smallvec::SmallVec<[u64; 8]> = self
            .peer_cids
            .iter_seqs()
            .filter(|&s| s < retire_prior_to)
            .collect();
        for seq in seqs_to_retire {
            if self.peer_cids.remove_by_seq(seq).is_some() {
                self.pending_retire.push(seq);
            }
        }

        // Store the new CID (unless it's one we should retire)
        if sequence >= retire_prior_to {
            self.peer_cids.push_with_seq(cid, sequence);
        } else {
            self.pending_retire.push(sequence);
        }
    }

    /// Get pending RetireConnectionId sequences to send.
    pub fn take_pending_retires(&mut self) -> Vec<u64> {
        std::mem::take(&mut self.pending_retire)
    }

    /// Generate a new CID entry for the local CID set.
    /// Returns the sequence number to be sent in a NEW_CONNECTION_ID frame.
    /// The caller must generate the random CID bytes and reset token.
    pub fn issue_new_cid(&mut self, cid: ConnectionId) -> Option<u64> {
        let seq = self.next_sequence;
        if !self.local_cids.push_with_seq(cid, seq) {
            return None; // local set full
        }
        self.next_sequence += 1;
        self.highest_issued_seq = seq;
        Some(seq)
    }

    /// Check if we're at the active CID limit.
    pub fn at_limit(&self) -> bool {
        self.peer_cids.len() as u64 >= self.active_limit
    }
}
