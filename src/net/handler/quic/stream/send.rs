use smallvec::SmallVec;

use super::recv::StreamRingBuffer;

/// Send half of a QUIC stream
pub struct SendHalf {
    pub buffer: StreamRingBuffer,
    pub sent: u64,
    pub acked: u64,
    pub max_stream_data: u64,
    pub fin_sent: bool,
    pub blocked_at: Option<u64>,
    pub reset_requested: bool,
    pub reset_error_code: u64,
    /// Byte ranges needing retransmission, kept sorted and merged.
    pub(crate) retransmit: SmallVec<[(u64, u64); 4]>,
    /// Out-of-order ACK ranges above the contiguous acked frontier.
    acked_ooo: SmallVec<[(u64, u64); 4]>,
}

impl SendHalf {
    pub fn new(initial_max_stream_data: u64) -> Self {
        Self {
            buffer: StreamRingBuffer::new(8192),
            sent: 0,
            acked: 0,
            max_stream_data: initial_max_stream_data,
            fin_sent: false,
            blocked_at: None,
            reset_requested: false,
            reset_error_code: 0,
            retransmit: SmallVec::new(),
            acked_ooo: SmallVec::new(),
        }
    }

    pub fn can_send(&self) -> bool {
        self.sent < self.max_stream_data && !self.buffer.is_empty()
    }

    pub fn write(&mut self, data: &[u8]) -> usize {
        self.buffer.write(data)
    }

    pub fn reset(&mut self) {
        self.buffer.clear();
        self.sent = 0;
        self.acked = 0;
        self.fin_sent = false;
        self.blocked_at = None;
        self.retransmit.clear();
        self.acked_ooo.clear();
    }

    pub fn mark_reset(&mut self, error_code: u64) {
        self.reset_requested = true;
        self.reset_error_code = error_code;
    }

    pub fn final_size(&self) -> u64 {
        self.acked + self.buffer.len() as u64
    }

    /// Insert a byte range needing retransmission, merging with any
    /// overlapping or adjacent existing ranges to prevent fragmentation.
    pub fn add_retransmit_range(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }
        let mut new_start = start;
        let mut new_end = end;

        // Build a new list, merging as we go.
        let mut result: SmallVec<[(u64, u64); 4]> = SmallVec::new();
        let mut inserted = false;

        for &(s, e) in &self.retransmit {
            if !inserted {
                if s > new_end {
                    // Current range is fully past new range — insert new first.
                    result.push((new_start, new_end));
                    inserted = true;
                    result.push((s, e));
                } else if e < new_start {
                    // Current range is fully before new range.
                    result.push((s, e));
                } else {
                    // Overlap or adjacency — merge into new range.
                    new_start = new_start.min(s);
                    new_end = new_end.max(e);
                }
            } else {
                result.push((s, e));
            }
        }

        if !inserted {
            result.push((new_start, new_end));
        }

        self.retransmit = result;
    }

    /// Read-only access to retransmit ranges.
    pub fn retransmit_ranges(&self) -> &[(u64, u64)] {
        &self.retransmit
    }

    /// Remove and return the first (lowest offset) retransmit range.
    pub fn pop_retransmit_range(&mut self) -> Option<(u64, u64)> {
        if self.retransmit.is_empty() {
            None
        } else {
            Some(self.retransmit.remove(0))
        }
    }

    /// Remove or trim retransmit ranges that overlap with an acked region.
    /// Builds a new list to avoid borrow conflicts from splits.
    pub fn trim_retransmit_for_ack(&mut self, ack_start: u64, ack_end: u64) {
        let mut result: SmallVec<[(u64, u64); 4]> = SmallVec::new();

        for &(s, e) in &self.retransmit {
            if ack_start >= e || ack_end <= s {
                // No overlap — keep as-is.
                result.push((s, e));
            } else if ack_start <= s && ack_end >= e {
                // Fully acked — drop.
            } else if ack_start <= s {
                // Trim front: ack covers [s, ack_end).
                result.push((ack_end, e));
            } else if ack_end >= e {
                // Trim back: ack covers [ack_start, e).
                result.push((s, ack_start));
            } else {
                // Punch a hole: ack is in the middle.
                result.push((s, ack_start));
                result.push((ack_end, e));
            }
        }

        self.retransmit = result;
    }

    /// Returns true if there is any data pending to send: retransmit ranges,
    /// unsent buffered data, or a FIN that hasn't been sent yet.
    pub fn has_pending_data(&self) -> bool {
        !self.retransmit.is_empty() || !self.buffer.is_empty()
    }
}
