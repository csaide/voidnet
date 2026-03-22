//! QUIC loss detection (RFC 9002).
//!
//! Implements RTT estimation (§5.3), packet-threshold and time-threshold loss
//! detection (§6.1), and probe timeout (§6.2).

use coarsetime::{Duration, Instant};
use smallvec::SmallVec;

// --- RFC 9002 constants ---

/// Packet reordering threshold before declaring loss (§6.1.1).
pub const K_PACKET_THRESHOLD: u32 = 3;

/// Time threshold numerator (9/8 of max RTT) (§6.1.2).
pub const K_TIME_THRESHOLD_NUM: u32 = 9;

/// Time threshold denominator.
pub const K_TIME_THRESHOLD_DEN: u32 = 8;

/// Timer granularity in milliseconds (§6.1.2).
pub const K_GRANULARITY_MS: u64 = 1;

/// Initial RTT estimate in milliseconds (§6.2.2).
pub const K_INITIAL_RTT_MS: u64 = 333;

// --- SentPacket ---

/// A packet that has been sent and is being tracked for loss/ack.
#[derive(Debug, Clone)]
pub struct SentPacket {
    pub time_sent: Instant,
    pub size: u16,
    pub ack_eliciting: bool,
    pub in_flight: bool,
    /// Indices into FrameLog (Task 23). (start, end) range.
    pub frame_range: (u32, u32),
}

// --- InFlightRing ---

const RING_SIZE: usize = 256;

/// Fixed-size ring buffer for in-flight packets. O(1) operations, no heap allocations.
///
/// Packets are indexed by `(pn - base_pn)`. When the window fills, call
/// `advance_base` to slide forward and reclaim slots.
pub struct InFlightRing {
    packets: [Option<SentPacket>; RING_SIZE],
    base_pn: u64,
}

impl InFlightRing {
    pub fn new() -> Self {
        Self {
            packets: std::array::from_fn(|_| None),
            base_pn: 0,
        }
    }

    /// Map a packet number to a ring index using modular arithmetic.
    /// The index depends only on the PN itself, not on base_pn, so
    /// advance_base can update base_pn without moving any data.
    #[inline]
    fn index_of(&self, pn: u64) -> Option<usize> {
        if pn < self.base_pn || pn >= self.base_pn + RING_SIZE as u64 {
            return None;
        }
        Some((pn as usize) & (RING_SIZE - 1))
    }

    #[inline]
    pub fn get(&self, pn: u64) -> Option<&SentPacket> {
        self.index_of(pn).and_then(|idx| self.packets[idx].as_ref())
    }

    #[inline]
    pub fn insert(&mut self, pn: u64, pkt: SentPacket) {
        if let Some(idx) = self.index_of(pn) {
            self.packets[idx] = Some(pkt);
        }
        // If pn is beyond the window, caller should advance_base first.
    }

    #[inline]
    pub fn remove(&mut self, pn: u64) -> Option<SentPacket> {
        self.index_of(pn).and_then(|idx| self.packets[idx].take())
    }

    /// Advance the base packet number, clearing any slots that fall behind.
    /// Uses modular indexing so no data needs to be moved — only old slots
    /// are cleared and base_pn is updated.
    pub fn advance_base(&mut self, new_base: u64) {
        if new_base <= self.base_pn {
            return;
        }

        let shift = (new_base - self.base_pn) as usize;

        if shift >= RING_SIZE {
            // Entire ring is invalidated.
            for slot in self.packets.iter_mut() {
                *slot = None;
            }
        } else {
            // Clear old slots that are now before the new base.
            for i in 0..shift {
                let pn = self.base_pn + i as u64;
                let idx = (pn as usize) & (RING_SIZE - 1);
                self.packets[idx] = None;
            }
        }

        self.base_pn = new_base;
    }

    /// Iterate all present packets with their packet numbers.
    pub fn iter(&self) -> impl Iterator<Item = (u64, &SentPacket)> + '_ {
        (0..RING_SIZE as u64).filter_map(move |offset| {
            let pn = self.base_pn + offset;
            let idx = (pn as usize) & (RING_SIZE - 1);
            self.packets[idx].as_ref().map(|pkt| (pn, pkt))
        })
    }
}

// --- PacketNumberSpace ---

/// Per packet-number-space state (Initial, Handshake, or Application Data).
pub struct PacketNumberSpace {
    pub largest_acked: Option<u64>,
    pub in_flight: InFlightRing,
    pub loss_time: Option<Instant>,
    pub ack_eliciting_in_flight: u32,
    pub ecn_ce_counter: u64,
}

impl PacketNumberSpace {
    pub fn new() -> Self {
        Self {
            largest_acked: None,
            in_flight: InFlightRing::new(),
            loss_time: None,
            ack_eliciting_in_flight: 0,
            ecn_ce_counter: 0,
        }
    }
}

// --- LossDetectionResult ---

/// Result of processing a loss detection timeout.
pub enum LossDetectionResult {
    /// Lost packets detected.
    LostPackets(SmallVec<[(u64, SentPacket); 8]>),
    /// PTO expired, need to send probe in the given space.
    SendProbe { space: usize },
    /// Nothing to do.
    None,
}

// --- LossDetector ---

/// The main loss detector (RFC 9002).
pub struct LossDetector {
    pub spaces: [PacketNumberSpace; 3], // Initial=0, Handshake=1, Application=2
    next_pn: [u64; 3],

    // RTT estimation (§5.3)
    pub latest_rtt: Duration,
    pub smoothed_rtt: Duration,
    pub rttvar: Duration,
    pub min_rtt: Duration,
    pub first_rtt_sample: Option<Instant>,

    // PTO (§6.2)
    pub pto_count: u32,
    time_of_last_ack_eliciting_pkt: [Option<Instant>; 3],

    // Handshake state
    pub handshake_confirmed: bool,
    pub peer_completed_address_validation: bool,

    // Bytes in flight (for congestion control interaction)
    pub bytes_in_flight: usize,
}

/// A very large Duration used as the initial min_rtt sentinel.
/// Equivalent to std::time::Duration::MAX in purpose.
const MAX_DURATION: Duration = Duration::from_secs(86400 * 365); // ~1 year

impl LossDetector {
    pub fn new() -> Self {
        let initial_rtt = Duration::from_millis(K_INITIAL_RTT_MS);
        Self {
            spaces: [
                PacketNumberSpace::new(),
                PacketNumberSpace::new(),
                PacketNumberSpace::new(),
            ],
            next_pn: [0; 3],
            latest_rtt: initial_rtt,
            smoothed_rtt: initial_rtt,
            rttvar: initial_rtt / 2,
            min_rtt: MAX_DURATION,
            first_rtt_sample: None,
            pto_count: 0,
            time_of_last_ack_eliciting_pkt: [None; 3],
            handshake_confirmed: false,
            peer_completed_address_validation: false,
            bytes_in_flight: 0,
        }
    }

    /// Get and increment the next packet number for a space.
    pub fn next_pn(&mut self, space: usize) -> u64 {
        let pn = self.next_pn[space];
        self.next_pn[space] += 1;
        pn
    }

    /// Record a sent packet.
    pub fn on_packet_sent(&mut self, space: usize, pn: u64, pkt: SentPacket) {
        if pkt.in_flight {
            self.bytes_in_flight += pkt.size as usize;
        }
        if pkt.ack_eliciting {
            self.spaces[space].ack_eliciting_in_flight += 1;
            self.time_of_last_ack_eliciting_pkt[space] = Some(pkt.time_sent);
        }
        self.spaces[space].in_flight.insert(pn, pkt);
    }

    /// Process an ACK frame. Returns (newly acked packets, lost packets with pn).
    #[inline]
    pub fn on_ack_received(
        &mut self,
        space: usize,
        largest_acked: u64,
        ack_delay: Duration,
        acked_ranges: &[(u64, u64)], // (start, end) inclusive
        max_ack_delay: Duration,
        handshake_confirmed: bool,
        now: Instant,
    ) -> (SmallVec<[SentPacket; 16]>, SmallVec<[(u64, SentPacket); 8]>) {
        let newly_acked_largest = self.spaces[space]
            .largest_acked
            .map_or(true, |la| largest_acked > la);

        if newly_acked_largest {
            self.spaces[space].largest_acked = Some(largest_acked);
        }

        // Grab the send time of the largest_acked packet before removal (for RTT).
        let largest_acked_time_sent = self.spaces[space]
            .in_flight
            .get(largest_acked)
            .map(|p| p.time_sent);

        // Remove acked packets from in-flight tracking.
        let mut acked = SmallVec::<[SentPacket; 16]>::new();
        for &(start, end) in acked_ranges {
            for pn in start..=end {
                if let Some(pkt) = self.spaces[space].in_flight.remove(pn) {
                    if pkt.in_flight {
                        self.bytes_in_flight -= pkt.size as usize;
                    }
                    if pkt.ack_eliciting {
                        self.spaces[space].ack_eliciting_in_flight =
                            self.spaces[space].ack_eliciting_in_flight.saturating_sub(1);
                    }
                    acked.push(pkt);
                }
            }
        }

        // Update RTT if the largest acked packet was newly acked and we had it.
        // Only update RTT if acked packets include at least one ack-eliciting (Fix 14).
        if newly_acked_largest {
            let includes_ack_eliciting = acked.iter().any(|p| p.ack_eliciting);
            if includes_ack_eliciting {
                if let Some(time_sent) = largest_acked_time_sent {
                    let latest_rtt = now.duration_since(time_sent);
                    self.update_rtt(
                        latest_rtt,
                        ack_delay,
                        max_ack_delay,
                        handshake_confirmed,
                        now,
                    );
                }
            }
        }

        // Reset pto_count on successful ack.
        self.pto_count = 0;

        // Detect lost packets.
        let lost = self.detect_lost_packets(space, now);

        (acked, lost)
    }

    /// Update RTT estimates (RFC 9002 §5.3).
    #[inline]
    pub fn update_rtt(
        &mut self,
        latest_rtt: Duration,
        ack_delay: Duration,
        max_ack_delay: Duration,
        handshake_confirmed: bool,
        now: Instant,
    ) {
        self.latest_rtt = latest_rtt;
        self.min_rtt = if latest_rtt < self.min_rtt {
            latest_rtt
        } else {
            self.min_rtt
        };

        if self.first_rtt_sample.is_none() {
            self.first_rtt_sample = Some(now);
            self.smoothed_rtt = latest_rtt;
            self.rttvar = latest_rtt / 2;
            return;
        }

        // Only clamp ack_delay to max_ack_delay after handshake is confirmed
        // (RFC 9002 §5.3): before confirmation, use the raw ack_delay as-is.
        let ack_delay = if handshake_confirmed {
            if ack_delay < max_ack_delay {
                ack_delay
            } else {
                max_ack_delay
            }
        } else {
            ack_delay
        };
        let adjusted_rtt = if latest_rtt > self.min_rtt + ack_delay {
            latest_rtt - ack_delay
        } else {
            latest_rtt
        };

        let diff = if self.smoothed_rtt > adjusted_rtt {
            self.smoothed_rtt - adjusted_rtt
        } else {
            adjusted_rtt - self.smoothed_rtt
        };
        self.rttvar = (self.rttvar * 3 + diff) / 4;
        self.smoothed_rtt = (self.smoothed_rtt * 7 + adjusted_rtt) / 8;
    }

    /// Reset min_rtt to the given value (e.g., after path change or NAT rebinding).
    pub fn reset_min_rtt(&mut self, latest_rtt: coarsetime::Duration) {
        self.min_rtt = latest_rtt;
    }

    /// Detect lost packets in a space (RFC 9002 §6.1).
    #[inline]
    fn detect_lost_packets(
        &mut self,
        space: usize,
        now: Instant,
    ) -> SmallVec<[(u64, SentPacket); 8]> {
        let largest_acked = match self.spaces[space].largest_acked {
            Some(la) => la,
            None => return SmallVec::new(),
        };

        let max_rtt = if self.latest_rtt > self.smoothed_rtt {
            self.latest_rtt
        } else {
            self.smoothed_rtt
        };
        // Compute loss_delay in microseconds to maintain precision.
        let loss_delay_us =
            (K_TIME_THRESHOLD_NUM as u64 * max_rtt.as_micros()) / K_TIME_THRESHOLD_DEN as u64;
        let loss_delay_ms = loss_delay_us / 1000;
        let loss_delay_ms = if loss_delay_ms < K_GRANULARITY_MS {
            K_GRANULARITY_MS
        } else {
            loss_delay_ms
        };
        let loss_delay = Duration::from_millis(loss_delay_ms);

        let lost_send_time = now.checked_sub(loss_delay);

        self.spaces[space].loss_time = None;

        // Collect candidate packet numbers + send times into a stack-allocated buffer
        // to avoid borrowing self.spaces mutably while iterating.
        let mut candidates: SmallVec<[(u64, Instant); 32]> = SmallVec::new();
        for (pn, pkt) in self.spaces[space].in_flight.iter() {
            if pn <= largest_acked {
                candidates.push((pn, pkt.time_sent));
            }
        }

        let mut lost = SmallVec::<[(u64, SentPacket); 8]>::new();

        for (pn, time_sent) in candidates {
            let lost_by_packet = largest_acked >= pn + K_PACKET_THRESHOLD as u64;
            let lost_by_time = lost_send_time.map_or(false, |t| time_sent <= t);

            if lost_by_packet || lost_by_time {
                if let Some(pkt) = self.spaces[space].in_flight.remove(pn) {
                    if pkt.in_flight {
                        self.bytes_in_flight -= pkt.size as usize;
                    }
                    if pkt.ack_eliciting {
                        self.spaces[space].ack_eliciting_in_flight =
                            self.spaces[space].ack_eliciting_in_flight.saturating_sub(1);
                    }
                    lost.push((pn, pkt));
                }
            } else {
                // Not yet lost, but may become lost. Set loss_time.
                let loss_time = time_sent + loss_delay;
                self.spaces[space].loss_time = Some(
                    self.spaces[space]
                        .loss_time
                        .map_or(loss_time, |t| if t < loss_time { t } else { loss_time }),
                );
            }
        }

        lost
    }

    /// Compute PTO duration (RFC 9002 §6.2.1).
    pub fn pto(&self, space: usize, max_ack_delay: Duration) -> Duration {
        let ack_delay = if space == 2 {
            max_ack_delay
        } else {
            Duration::from_millis(0)
        };
        let rttvar4 = self.rttvar * 4;
        let granularity = Duration::from_millis(K_GRANULARITY_MS);
        let var_component = if rttvar4 > granularity {
            rttvar4
        } else {
            granularity
        };
        self.smoothed_rtt + var_component + ack_delay
    }

    /// Get the loss detection timer deadline.
    pub fn loss_detection_timer(&self, max_ack_delay: Duration) -> Option<Instant> {
        // Check loss_time across spaces first (earliest).
        let earliest_loss_time = self.spaces.iter().filter_map(|s| s.loss_time).min();

        if earliest_loss_time.is_some() {
            return earliest_loss_time;
        }

        // If no ack-eliciting packets in flight and peer has validated address,
        // no timer needed (unless we're the client before handshake confirmed).
        if self.peer_completed_address_validation
            && self.spaces.iter().all(|s| s.ack_eliciting_in_flight == 0)
        {
            return None;
        }

        // PTO timer: find the earliest space with ack-eliciting in flight.
        let mut earliest_pto: Option<Instant> = None;

        for space in 0..3 {
            if self.spaces[space].ack_eliciting_in_flight == 0
                && (space != 2 || self.handshake_confirmed)
            {
                continue;
            }

            if let Some(last_sent) = self.time_of_last_ack_eliciting_pkt[space] {
                let pto_duration = self.pto(space, max_ack_delay);
                let backoff = 1u32 << self.pto_count;
                let deadline = last_sent + pto_duration * backoff;
                earliest_pto =
                    Some(earliest_pto.map_or(
                        deadline,
                        |t: Instant| if t < deadline { t } else { deadline },
                    ));
            }
        }

        earliest_pto
    }

    /// Handle loss detection timeout.
    pub fn on_loss_detection_timeout(
        &mut self,
        now: Instant,
        _max_ack_delay: Duration,
    ) -> LossDetectionResult {
        // Check if any space has a loss_time set.
        let earliest_loss_space = self
            .spaces
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.loss_time.map(|t| (i, t)))
            .min_by_key(|&(_, t)| t)
            .map(|(i, _)| i);

        if let Some(space) = earliest_loss_space {
            let lost = self.detect_lost_packets(space, now);
            if !lost.is_empty() {
                return LossDetectionResult::LostPackets(lost);
            }
        }

        // PTO expired. Find the space to probe.
        self.pto_count += 1;

        // Choose space: prefer Initial, then Handshake, then Application.
        for space in 0..3 {
            if self.spaces[space].ack_eliciting_in_flight > 0 {
                return LossDetectionResult::SendProbe { space };
            }
        }

        // If no ack-eliciting in flight, probe Application space.
        LossDetectionResult::SendProbe { space: 2 }
    }

    /// Discard a packet number space (when keys are discarded).
    pub fn discard_space(&mut self, space: usize) {
        // Collect sizes to subtract, then clear.
        let mut bytes_to_remove = 0usize;
        for (_, pkt) in self.spaces[space].in_flight.iter() {
            if pkt.in_flight {
                bytes_to_remove += pkt.size as usize;
            }
        }
        self.bytes_in_flight -= bytes_to_remove;
        self.spaces[space] = PacketNumberSpace::new();
        self.time_of_last_ack_eliciting_pkt[space] = None;
        self.pto_count = 0;
    }
}
