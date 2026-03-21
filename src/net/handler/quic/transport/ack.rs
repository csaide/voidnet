//! ACK state tracking for QUIC (RFC 9000 §13).
//!
//! Maintains received packet number ranges and pre-encodes the wire-format
//! gap/ack-range pairs so they can be copied into outbound ACK frames without
//! re-encoding on every send.

use super::varint::{decode_varint, encode_varint};
use smallvec::SmallVec;

/// Tracks received packet numbers and generates ACK frames efficiently.
///
/// Maintains up to 64 ranges in decoded form, newest first, and keeps a
/// pre-encoded copy of the additional ranges (gap/ack-range pairs) ready for
/// direct insertion into an ACK frame.
pub struct AckState {
    /// Sorted ranges of received PNs: [(start, end), ...] inclusive, newest first.
    /// Index 0 = highest range (containing `largest_received`).
    ranges: [(u64, u64); 64],
    range_count: usize,

    /// Pre-encoded wire bytes for gap/ack-range pairs (all ranges except the first).
    ranges_encoded: [u8; 256],
    ranges_encoded_len: usize,

    /// Largest received PN.
    largest_received: Option<u64>,
    /// Instant when `largest_received` was first received.
    largest_received_time: Option<coarsetime::Instant>,

    /// Whether an ack-eliciting packet has been received since the last ACK.
    ack_eliciting_received: bool,
}

impl AckState {
    pub fn new() -> Self {
        AckState {
            ranges: [(0, 0); 64],
            range_count: 0,
            ranges_encoded: [0u8; 256],
            ranges_encoded_len: 0,
            largest_received: None,
            largest_received_time: None,
            ack_eliciting_received: false,
        }
    }

    /// Record receipt of a packet number.
    #[inline]
    pub fn on_packet_received(&mut self, pn: u64, now: coarsetime::Instant) {
        let is_new_largest = self.largest_received.map_or(true, |l| pn > l);
        if is_new_largest {
            self.largest_received = Some(pn);
            self.largest_received_time = Some(now);
        }
        self.insert_range(pn);
        self.encode_ranges();
    }

    /// Whether we need to send an ACK.
    #[inline]
    pub fn needs_ack(&self) -> bool {
        self.ack_eliciting_received
    }

    /// Mark that we have sent an ACK.
    pub fn ack_sent(&mut self) {
        self.ack_eliciting_received = false;
    }

    /// Record that an ack-eliciting packet was received.
    pub fn set_ack_eliciting(&mut self) {
        self.ack_eliciting_received = true;
    }

    #[inline]
    pub fn largest_received(&self) -> Option<u64> {
        self.largest_received
    }

    pub fn largest_received_time(&self) -> Option<coarsetime::Instant> {
        self.largest_received_time
    }

    /// Pre-encoded gap/ack-range bytes for the additional ACK ranges.
    pub fn encoded_ranges(&self) -> &[u8] {
        &self.ranges_encoded[..self.ranges_encoded_len]
    }

    /// Size of the first ACK range: `largest_acked - start_of_first_range`.
    pub fn first_ack_range(&self) -> u64 {
        if self.range_count > 0 {
            // ranges[0] = (start, end) of the highest range.
            self.ranges[0].1 - self.ranges[0].0
        } else {
            0
        }
    }

    /// Number of additional ACK ranges (all except the first).
    pub fn ack_range_count(&self) -> u64 {
        self.range_count.saturating_sub(1) as u64
    }

    /// Decode gap/ack-range wire bytes back into `(start, end)` inclusive pairs.
    ///
    /// The first range `[largest_acked - first_ack_range, largest_acked]` is
    /// reconstructed from the provided values; subsequent ranges are decoded from
    /// `ranges_data`.
    pub fn decode_ack_ranges(
        largest_acked: u64,
        first_ack_range: u64,
        range_count: u64,
        ranges_data: &[u8],
    ) -> SmallVec<[(u64, u64); 32]> {
        let mut result = SmallVec::new();

        // First range
        let first_end = largest_acked;
        let first_start = largest_acked.saturating_sub(first_ack_range);
        result.push((first_start, first_end));

        let mut cursor = 0usize;
        // Current "ceiling" — the smallest PN in the previous range.
        let mut prev_start = first_start;

        for _ in 0..range_count {
            // gap: number of missing PNs minus 1
            let (gap, n) = match decode_varint(&ranges_data[cursor..]) {
                Some(v) => v,
                None => break,
            };
            cursor += n;

            // ack_range: number of consecutive PNs minus 1
            let (ack_range, n) = match decode_varint(&ranges_data[cursor..]) {
                Some(v) => v,
                None => break,
            };
            cursor += n;

            // End of this range is prev_start - gap - 2
            // (gap+1 missing PNs separate it from prev_start)
            let range_end = prev_start.saturating_sub(gap + 2);
            let range_start = range_end.saturating_sub(ack_range);
            result.push((range_start, range_end));
            prev_start = range_start;
        }

        result
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// Re-encode `ranges[1..]` into the wire-format gap/ack-range buffer.
    fn encode_ranges(&mut self) {
        let mut pos = 0usize;

        for i in 1..self.range_count {
            // Gap = ranges[i-1].0 - ranges[i].1 - 2
            // (number of missing PNs between the two ranges, minus 1)
            let gap = self.ranges[i - 1].0 - self.ranges[i].1 - 2;
            // ack_range = ranges[i].1 - ranges[i].0  (consecutive - 1)
            let ack_range = self.ranges[i].1 - self.ranges[i].0;

            let remaining = &mut self.ranges_encoded[pos..];
            if remaining.len() < 16 {
                break; // no room; truncate
            }
            pos += encode_varint(gap, remaining);
            let remaining = &mut self.ranges_encoded[pos..];
            pos += encode_varint(ack_range, remaining);
        }

        self.ranges_encoded_len = pos;
    }

    /// Insert `pn` into the sorted range list, merging adjacent/overlapping ranges.
    ///
    /// After insertion `ranges[0]` is always the highest range.
    fn insert_range(&mut self, pn: u64) {
        // Find if pn is already covered or adjacent to an existing range.
        for i in 0..self.range_count {
            let (s, e) = self.ranges[i];
            if pn >= s && pn <= e {
                // Already tracked.
                return;
            }
            if pn == s.saturating_sub(1) {
                // Extend range downward.
                self.ranges[i].0 = pn;
                self.try_merge_down(i);
                return;
            }
            if pn == e + 1 {
                // Extend range upward.
                self.ranges[i].1 = pn;
                self.try_merge_up(i);
                return;
            }
        }

        // New range — find insertion position (sorted newest first by end).
        if self.range_count < 64 {
            let pos = self.ranges[..self.range_count]
                .iter()
                .position(|&(_, e)| pn > e)
                .unwrap_or(self.range_count);

            // Shift ranges at pos..range_count to the right.
            let count = self.range_count;
            for j in (pos..count).rev() {
                self.ranges[j + 1] = self.ranges[j];
            }
            self.ranges[pos] = (pn, pn);
            self.range_count += 1;
        } else {
            // Drop oldest (smallest) range to make room if needed.
            // Find insertion point: if pn is larger than the smallest range end,
            // evict the last entry.
            let last = self.ranges[self.range_count - 1];
            if pn > last.1 {
                let pos = self.ranges[..self.range_count]
                    .iter()
                    .position(|&(_, e)| pn > e)
                    .unwrap_or(self.range_count - 1);
                let count = self.range_count;
                for j in (pos..count - 1).rev() {
                    self.ranges[j + 1] = self.ranges[j];
                }
                self.ranges[pos] = (pn, pn);
            }
            // If pn is smaller than everything tracked and we're at capacity, discard.
        }
    }

    /// After extending range `i` downward (decrementing start), try to merge with
    /// the range immediately below it (i.e., `ranges[i+1]`).
    fn try_merge_down(&mut self, i: usize) {
        if i + 1 >= self.range_count {
            return;
        }
        let (s, _) = self.ranges[i];
        let (_, e_next) = self.ranges[i + 1];
        if s == e_next + 1 || s <= e_next {
            // Merge: absorb ranges[i+1] into ranges[i].
            self.ranges[i].0 = self.ranges[i + 1].0;
            // Remove ranges[i+1].
            for j in (i + 1)..(self.range_count - 1) {
                self.ranges[j] = self.ranges[j + 1];
            }
            self.range_count -= 1;
        }
    }

    /// After extending range `i` upward (incrementing end), try to merge with
    /// the range immediately above it (i.e., `ranges[i-1]` which has higher PNs).
    fn try_merge_up(&mut self, i: usize) {
        if i == 0 {
            return;
        }
        let (_, e) = self.ranges[i];
        let (s_prev, _) = self.ranges[i - 1];
        if e + 1 == s_prev || e >= s_prev {
            // Merge: absorb ranges[i-1] into ranges[i].
            self.ranges[i].1 = self.ranges[i - 1].1;
            // Remove ranges[i-1].
            for j in (i - 1)..(self.range_count - 1) {
                self.ranges[j] = self.ranges[j + 1];
            }
            self.range_count -= 1;
        }
    }
}

impl Default for AckState {
    fn default() -> Self {
        Self::new()
    }
}
