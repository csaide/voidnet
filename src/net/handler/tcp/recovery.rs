use std::collections::BTreeMap;

use crate::net::wire::tcp::{seq_le, seq_lt};

const DUP_THRESH: u32 = 3;

pub struct SackRecovery {
    pub in_recovery: bool,
    pub recovery_point: u32,
    pub pipe: u32,
    pub dup_ack_count: u8,
}

impl SackRecovery {
    pub fn new() -> Self {
        Self {
            in_recovery: false,
            recovery_point: 0,
            pipe: 0,
            dup_ack_count: 0,
        }
    }

    /// Enter SACK recovery. `snd_nxt` is the recovery point.
    pub fn enter(&mut self, snd_nxt: u32) {
        self.in_recovery = true;
        self.recovery_point = snd_nxt;
        // dup_ack_count intentionally NOT reset here — it stays at 3+
        // during recovery and is reset on exit().
    }

    /// Exit recovery, reset state.
    pub fn exit(&mut self) {
        self.in_recovery = false;
        self.recovery_point = 0;
        self.pipe = 0;
        self.dup_ack_count = 0;
    }

    /// Process a new ACK during recovery. Returns true if recovery is complete
    /// (seg_ack >= recovery_point).
    pub fn on_ack(&mut self, seg_ack: u32) -> bool {
        if seq_le(self.recovery_point, seg_ack) {
            self.exit();
            true
        } else {
            false
        }
    }

    /// RFC 6675 S4: IsLost predicate. A segment starting at `seq` is lost if
    /// DupThresh (3) segments above it have been SACKed, or the byte distance
    /// exceeds DupThresh * MSS.
    pub fn is_lost(&self, seq: u32, scoreboard: &BTreeMap<u32, u32>, eff_mss: u16) -> bool {
        let mut sacked_segments_above = 0u32;
        let mut highest_sacked_end: Option<u32> = None;

        for (&start, &len) in scoreboard {
            let end = start.wrapping_add(len);
            // Only consider SACK blocks that are above seq.
            if seq_lt(seq, start) {
                // Count MSS-sized segments within this SACK block.
                let block_segments = len.div_ceil(u32::from(eff_mss));
                sacked_segments_above += block_segments;

                // Track the highest SACKed byte.
                match highest_sacked_end {
                    Some(prev) if seq_lt(prev, end) => highest_sacked_end = Some(end),
                    None => highest_sacked_end = Some(end),
                    _ => {}
                }
            }
        }

        if sacked_segments_above >= DUP_THRESH {
            return true;
        }

        // Check byte distance from seq to highest SACKed end.
        if let Some(high) = highest_sacked_end {
            let byte_distance = high.wrapping_sub(seq);
            if byte_distance > DUP_THRESH * u32::from(eff_mss) {
                return true;
            }
        }

        false
    }

    /// RFC 6675 S4.1: SetPipe -- estimate bytes in the network.
    /// Iterates MSS-sized blocks from snd_una to snd_nxt.
    pub fn set_pipe(
        &mut self,
        snd_una: u32,
        snd_nxt: u32,
        scoreboard: &BTreeMap<u32, u32>,
        eff_mss: u16,
    ) {
        let mss = u32::from(eff_mss);
        let mut pipe: u32 = 0;
        let mut seq = snd_una;

        while seq_lt(seq, snd_nxt) {
            if !self.is_sacked(seq, scoreboard) && !self.is_lost(seq, scoreboard, eff_mss) {
                pipe += mss;
            }
            seq = seq.wrapping_add(mss);
        }

        self.pipe = pipe;
    }

    /// Check if a sequence number falls within a SACKed range.
    fn is_sacked(&self, seq: u32, scoreboard: &BTreeMap<u32, u32>) -> bool {
        for (&start, &len) in scoreboard {
            let end = start.wrapping_add(len);
            if seq_le(start, seq) && seq_lt(seq, end) {
                return true;
            }
        }
        false
    }

    /// Find the lowest lost sequence number >= `from` for retransmission.
    pub fn next_lost_segment(
        &self,
        from: u32,
        snd_nxt: u32,
        scoreboard: &BTreeMap<u32, u32>,
        eff_mss: u16,
    ) -> Option<u32> {
        let mss = u32::from(eff_mss);
        let mut seq = from;

        while seq_lt(seq, snd_nxt) {
            if !self.is_sacked(seq, scoreboard) && self.is_lost(seq, scoreboard, eff_mss) {
                return Some(seq);
            }
            seq = seq.wrapping_add(mss);
        }

        None
    }
}

pub struct PrrState {
    pub prr_delivered: u32,
    pub prr_out: u32,
    pub recover_fs: u32,
}

impl PrrState {
    pub fn new() -> Self {
        Self {
            prr_delivered: 0,
            prr_out: 0,
            recover_fs: 0,
        }
    }

    /// Enter recovery. `bytes_in_flight` = snd_nxt - snd_una at entry.
    pub fn enter(&mut self, bytes_in_flight: u32) {
        self.recover_fs = bytes_in_flight;
        self.prr_delivered = 0;
        self.prr_out = 0;
    }

    /// Reset on recovery exit.
    pub fn exit(&mut self) {
        self.prr_delivered = 0;
        self.prr_out = 0;
        self.recover_fs = 0;
    }

    /// Called on each ACK during recovery. Returns snd_cnt (bytes allowed to send).
    /// `bytes_newly_delivered` = bytes_acked + bytes_newly_sacked.
    /// `pipe` = current pipe estimate. `ssthresh` = target cwnd.
    pub fn on_ack(
        &mut self,
        bytes_newly_delivered: u32,
        pipe: u32,
        ssthresh: u32,
        eff_mss: u16,
    ) -> u32 {
        self.prr_delivered += bytes_newly_delivered;

        if self.recover_fs == 0 {
            return eff_mss as u32;
        }

        if pipe > ssthresh {
            // Proportional: snd_cnt = ceil(prr_delivered * ssthresh / recover_fs) - prr_out.
            let numer = self.prr_delivered as u64 * ssthresh as u64;
            let target = numer.div_ceil(self.recover_fs as u64) as u32;
            target.saturating_sub(self.prr_out)
        } else {
            // Slow start reduction bound.
            let limit = self.prr_delivered.saturating_sub(self.prr_out) + eff_mss as u32;
            ssthresh.saturating_sub(pipe).min(limit)
        }
    }

    /// Called after sending bytes during recovery.
    pub fn on_sent(&mut self, bytes_sent: u32) {
        self.prr_out += bytes_sent;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FRtoPhase {
    Disabled,
    Step1,
    Step2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FRtoAction {
    /// No F-RTO active — proceed normally.
    None,
    /// Send new data (not retransmissions) to probe.
    SendNewData,
    /// Spurious RTO detected — restore cwnd.
    SpuriousRto,
    /// Genuine loss confirmed — keep reduced cwnd.
    GenuineLoss,
}

pub struct FRtoState {
    pub phase: FRtoPhase,
    snd_una_at_rto: u32,
    snd_una_last: u32,
}

impl FRtoState {
    pub fn new() -> Self {
        Self {
            phase: FRtoPhase::Disabled,
            snd_una_at_rto: 0,
            snd_una_last: 0,
        }
    }

    /// Arm F-RTO on RTO retransmit.
    pub fn enter(&mut self, snd_una: u32) {
        self.phase = FRtoPhase::Step1;
        self.snd_una_at_rto = snd_una;
        self.snd_una_last = snd_una;
    }

    /// Process ACK during F-RTO. `new_snd_una` is the updated snd_una after this ACK.
    pub fn on_ack(&mut self, new_snd_una: u32) -> FRtoAction {
        match self.phase {
            FRtoPhase::Disabled => FRtoAction::None,
            FRtoPhase::Step1 => {
                if seq_lt(self.snd_una_last, new_snd_una) {
                    self.snd_una_last = new_snd_una;
                    self.phase = FRtoPhase::Step2;
                    FRtoAction::SendNewData
                } else {
                    self.phase = FRtoPhase::Disabled;
                    FRtoAction::GenuineLoss
                }
            }
            FRtoPhase::Step2 => {
                if seq_lt(self.snd_una_last, new_snd_una) {
                    self.phase = FRtoPhase::Disabled;
                    FRtoAction::SpuriousRto
                } else {
                    self.phase = FRtoPhase::Disabled;
                    FRtoAction::GenuineLoss
                }
            }
        }
    }

    /// Check if F-RTO is active.
    pub fn is_active(&self) -> bool {
        self.phase != FRtoPhase::Disabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_lost_with_3_sacked_above() {
        let recovery = SackRecovery::new();
        let mut scoreboard = BTreeMap::new();
        // SACKed: [2000..3000], [3000..4000], [4000..5000] -- 3 blocks above seq 1000.
        scoreboard.insert(2000u32, 1000u32);
        scoreboard.insert(3000u32, 1000u32);
        scoreboard.insert(4000u32, 1000u32);
        assert!(recovery.is_lost(1000, &scoreboard, 1000));
    }

    #[test]
    fn is_lost_with_large_gap() {
        let recovery = SackRecovery::new();
        let mut scoreboard = BTreeMap::new();
        // Single SACK at [5000..6000] -- 4000 bytes above seq 1000, > 3*MSS.
        scoreboard.insert(5000u32, 1000u32);
        assert!(recovery.is_lost(1000, &scoreboard, 1000));
    }

    #[test]
    fn not_lost_with_insufficient_sacks() {
        let recovery = SackRecovery::new();
        let mut scoreboard = BTreeMap::new();
        // Only 2 blocks above.
        scoreboard.insert(2000u32, 1000u32);
        scoreboard.insert(3000u32, 1000u32);
        assert!(!recovery.is_lost(1000, &scoreboard, 1000));
    }

    #[test]
    fn set_pipe_counts_in_flight() {
        let mut recovery = SackRecovery::new();
        let mut scoreboard = BTreeMap::new();
        // snd_una=1000, snd_nxt=5000 => 4 MSS-sized blocks.
        // All 3 blocks [2000..5000] SACKed. Block [1000..2000] is lost (3 SACKed above).
        scoreboard.insert(2000u32, 1000u32);
        scoreboard.insert(3000u32, 1000u32);
        scoreboard.insert(4000u32, 1000u32);
        recovery.set_pipe(1000, 5000, &scoreboard, 1000);
        assert_eq!(recovery.pipe, 0); // all either SACKed or lost
    }

    #[test]
    fn set_pipe_counts_unacked_unsacked_as_in_flight() {
        let mut recovery = SackRecovery::new();
        let mut scoreboard = BTreeMap::new();
        // snd_una=1000, snd_nxt=6000 => 5 MSS blocks.
        // Only [2000..3000] SACKed.
        scoreboard.insert(2000u32, 1000u32);
        // [1000..2000]: not SACKed, only 1 block above -- not lost => in flight.
        // [2000..3000]: SACKed.
        // [3000..4000]: not SACKed, 0 blocks above => in flight.
        // [4000..5000]: not SACKed, 0 blocks above => in flight.
        // [5000..6000]: not SACKed, 0 blocks above => in flight.
        recovery.set_pipe(1000, 6000, &scoreboard, 1000);
        assert_eq!(recovery.pipe, 4000); // 4 blocks in flight
    }

    #[test]
    fn enter_and_exit_recovery() {
        let mut recovery = SackRecovery::new();
        recovery.enter(5000);
        assert!(recovery.in_recovery);
        assert_eq!(recovery.recovery_point, 5000);

        // Partial ACK -- doesn't exit.
        assert!(!recovery.on_ack(3000));
        assert!(recovery.in_recovery);

        // Full ACK -- exits.
        assert!(recovery.on_ack(5000));
        assert!(!recovery.in_recovery);
    }

    #[test]
    fn prr_proportional_when_pipe_above_ssthresh() {
        let mut prr = PrrState::new();
        prr.enter(10_000); // recover_fs = 10_000.
        let ssthresh = 7_000u32;
        let mss = 1460u16;

        // Simulate ACK delivering 1460 bytes.
        let snd_cnt = prr.on_ack(1460, 8_000, ssthresh, mss);
        // pipe=8000 > ssthresh=7000 => proportional.
        // snd_cnt = ceil(1460 * 7000 / 10000) - 0 = ceil(1022) = 1022.
        assert_eq!(snd_cnt, 1022);

        // After "sending" 1022 bytes.
        prr.on_sent(1022);
        // Second ACK (pipe still above ssthresh).
        let snd_cnt = prr.on_ack(1460, 7_500, ssthresh, mss);
        // snd_cnt = ceil(2920 * 7000 / 10000) - 1022 = ceil(2044) - 1022 = 1022.
        assert_eq!(snd_cnt, 1022);
    }

    #[test]
    fn prr_slow_start_reduction_when_pipe_below_ssthresh() {
        let mut prr = PrrState::new();
        prr.enter(10_000);
        let ssthresh = 7_000u32;
        let mss = 1460u16;

        // pipe=5000 < ssthresh.
        let snd_cnt = prr.on_ack(1460, 5_000, ssthresh, mss);
        // snd_cnt = min(7000 - 5000, 1460 - 0 + 1460) = min(2000, 2920) = 2000.
        assert_eq!(snd_cnt, 2000);
    }

    #[test]
    fn frto_spurious_rto_detected() {
        let mut frto = FRtoState::new();
        frto.enter(1000);

        // First ACK advances snd_una.
        let result = frto.on_ack(2000);
        assert_eq!(result, FRtoAction::SendNewData);

        // Second ACK advances snd_una again => spurious.
        let result = frto.on_ack(3000);
        assert_eq!(result, FRtoAction::SpuriousRto);
    }

    #[test]
    fn frto_genuine_loss_on_first_dup_ack() {
        let mut frto = FRtoState::new();
        frto.enter(1000);

        // First ACK is dup (snd_una doesn't advance).
        let result = frto.on_ack(1000);
        assert_eq!(result, FRtoAction::GenuineLoss);
    }

    #[test]
    fn frto_genuine_loss_on_second_dup_ack() {
        let mut frto = FRtoState::new();
        frto.enter(1000);

        // First ACK advances.
        let result = frto.on_ack(2000);
        assert_eq!(result, FRtoAction::SendNewData);

        // Second ACK is dup.
        let result = frto.on_ack(2000);
        assert_eq!(result, FRtoAction::GenuineLoss);
    }
}
