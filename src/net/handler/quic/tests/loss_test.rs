use crate::net::handler::quic::transport::loss::*;
use coarsetime::{Duration, Instant};

fn make_sent_packet(size: u16, ack_eliciting: bool) -> SentPacket {
    SentPacket {
        time_sent: Instant::now(),
        size,
        ack_eliciting,
        in_flight: true,
        frame_range: (0, 0),
    }
}

fn make_sent_packet_at(time: Instant, size: u16, ack_eliciting: bool) -> SentPacket {
    SentPacket {
        time_sent: time,
        size,
        ack_eliciting,
        in_flight: true,
        frame_range: (0, 0),
    }
}

// --- InFlightRing tests ---

#[test]
fn in_flight_ring_insert_get_remove() {
    let mut ring = InFlightRing::new();
    let pkt = make_sent_packet(100, true);

    ring.insert(0, pkt.clone());
    assert!(ring.get(0).is_some());
    assert_eq!(ring.get(0).unwrap().size, 100);

    ring.insert(5, make_sent_packet(200, false));
    assert!(ring.get(5).is_some());
    assert_eq!(ring.get(5).unwrap().size, 200);

    let removed = ring.remove(0);
    assert!(removed.is_some());
    assert_eq!(removed.unwrap().size, 100);
    assert!(ring.get(0).is_none());
}

#[test]
fn in_flight_ring_advance_base() {
    let mut ring = InFlightRing::new();
    ring.insert(0, make_sent_packet(10, true));
    ring.insert(1, make_sent_packet(20, true));
    ring.insert(2, make_sent_packet(30, true));
    ring.insert(5, make_sent_packet(60, true));

    ring.advance_base(3);
    // Packets 0,1,2 should be gone
    assert!(ring.get(0).is_none());
    assert!(ring.get(1).is_none());
    assert!(ring.get(2).is_none());
    // Packet 5 should still be accessible
    assert!(ring.get(5).is_some());
    assert_eq!(ring.get(5).unwrap().size, 60);
}

#[test]
fn in_flight_ring_iter() {
    let mut ring = InFlightRing::new();
    ring.insert(0, make_sent_packet(10, true));
    ring.insert(3, make_sent_packet(40, true));
    ring.insert(7, make_sent_packet(80, true));

    let entries: Vec<(u64, u16)> = ring.iter().map(|(pn, pkt)| (pn, pkt.size)).collect();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0], (0, 10));
    assert_eq!(entries[1], (3, 40));
    assert_eq!(entries[2], (7, 80));
}

#[test]
fn in_flight_ring_wrap_around() {
    let mut ring = InFlightRing::new();
    // Fill near the end of the ring
    ring.insert(250, make_sent_packet(250, true));
    ring.insert(255, make_sent_packet(255, true));
    assert!(ring.get(250).is_some());
    assert!(ring.get(255).is_some());

    // Packet 256 is beyond the ring with base=0
    assert!(ring.get(256).is_none());

    // Advance base so that new packet numbers fit
    ring.advance_base(200);
    // Old packets should still be accessible (they shifted)
    assert!(ring.get(250).is_some());
    assert!(ring.get(255).is_some());

    // Now we can insert up to base+255 = 455
    ring.insert(400, make_sent_packet(100, true));
    assert!(ring.get(400).is_some());
}

// --- RTT tests ---

#[test]
fn rtt_first_sample() {
    let mut ld = LossDetector::new();
    let rtt = Duration::from_millis(100);
    ld.update_rtt(
        rtt,
        Duration::from_millis(0),
        Duration::from_millis(25),
        Instant::now(),
    );

    assert_eq!(ld.smoothed_rtt, rtt);
    assert_eq!(ld.rttvar, rtt / 2);
    assert_eq!(ld.min_rtt, rtt);
    assert!(ld.first_rtt_sample.is_some());
}

#[test]
fn rtt_subsequent_samples() {
    let mut ld = LossDetector::new();
    let now = Instant::now();

    // First sample
    ld.update_rtt(
        Duration::from_millis(100),
        Duration::from_millis(0),
        Duration::from_millis(25),
        now,
    );

    let srtt_before = ld.smoothed_rtt;
    let rttvar_before = ld.rttvar;

    // Second sample: 120ms
    ld.update_rtt(
        Duration::from_millis(120),
        Duration::from_millis(0),
        Duration::from_millis(25),
        now,
    );

    // EWMA: smoothed_rtt = 7/8 * 100 + 1/8 * 120 = 87.5 + 15 = 102.5ms
    let expected_srtt = (srtt_before * 7 + Duration::from_millis(120)) / 8;
    assert_eq!(ld.smoothed_rtt, expected_srtt);

    // rttvar = 3/4 * 50 + 1/4 * |100 - 120| = 37.5 + 5 = 42.5ms
    let diff = Duration::from_millis(20); // |100 - 120|
    let expected_rttvar = (rttvar_before * 3 + diff) / 4;
    assert_eq!(ld.rttvar, expected_rttvar);
}

#[test]
fn rtt_ack_delay_capped() {
    let mut ld = LossDetector::new();
    let now = Instant::now();

    // First sample
    ld.update_rtt(
        Duration::from_millis(50),
        Duration::from_millis(0),
        Duration::from_millis(25),
        now,
    );

    // Second sample with large ack_delay that should be capped
    ld.update_rtt(
        Duration::from_millis(100),
        Duration::from_millis(50), // ack_delay > max_ack_delay
        Duration::from_millis(25), // max_ack_delay
        now,
    );

    // ack_delay should have been capped to 25ms
    // adjusted_rtt = 100 - 25 = 75ms (since 100 > min_rtt(50) + 25)
    let expected_adjusted = Duration::from_millis(75);
    let expected_srtt = (Duration::from_millis(50) * 7 + expected_adjusted) / 8;
    assert_eq!(ld.smoothed_rtt, expected_srtt);
}

#[test]
fn rtt_ack_delay_not_applied_below_min() {
    let mut ld = LossDetector::new();
    let now = Instant::now();

    // First sample: 50ms
    ld.update_rtt(
        Duration::from_millis(50),
        Duration::from_millis(0),
        Duration::from_millis(25),
        now,
    );

    // Second sample: 55ms with 10ms ack_delay
    // min_rtt = 50ms, latest(55) is NOT > min_rtt(50) + ack_delay(10) = 60ms
    // So ack_delay should NOT be subtracted
    ld.update_rtt(
        Duration::from_millis(55),
        Duration::from_millis(10),
        Duration::from_millis(25),
        now,
    );

    // adjusted_rtt = 55ms (not adjusted because 55 <= 50 + 10)
    let expected_srtt = (Duration::from_millis(50) * 7 + Duration::from_millis(55)) / 8;
    assert_eq!(ld.smoothed_rtt, expected_srtt);
}

// --- PTO tests ---

#[test]
fn pto_computation() {
    let mut ld = LossDetector::new();
    let now = Instant::now();
    ld.update_rtt(
        Duration::from_millis(100),
        Duration::from_millis(0),
        Duration::from_millis(25),
        now,
    );

    // PTO for app space (space 2): srtt + max(4*rttvar, 1ms) + max_ack_delay
    let max_ack_delay = Duration::from_millis(25);
    let pto = ld.pto(2, max_ack_delay);

    // rttvar = 50ms after first sample, 4*50 = 200ms
    let expected = Duration::from_millis(100) + Duration::from_millis(200) + max_ack_delay;
    assert_eq!(pto, expected);

    // PTO for handshake space (space 1): no ack_delay added
    let pto_hs = ld.pto(1, max_ack_delay);
    let expected_hs = Duration::from_millis(100) + Duration::from_millis(200);
    assert_eq!(pto_hs, expected_hs);
}

#[test]
fn pto_initial_value() {
    let ld = LossDetector::new();
    let max_ack_delay = Duration::from_millis(25);

    // Initial: smoothed_rtt = 333ms, rttvar = 333/2 = 166.5ms
    // PTO app = 333 + max(4*166.5, 1) + 25 = 333 + 666 + 25 = 1024ms
    let pto = ld.pto(2, max_ack_delay);
    let rttvar4 = ld.rttvar * 4;
    let granularity = Duration::from_millis(K_GRANULARITY_MS);
    let var_component = if rttvar4 > granularity {
        rttvar4
    } else {
        granularity
    };
    let expected = ld.smoothed_rtt + var_component + max_ack_delay;
    assert_eq!(pto, expected);
}

// --- Loss detection tests ---

#[test]
fn loss_by_packet_threshold() {
    let mut ld = LossDetector::new();
    let now = Instant::now();
    let space = 2;

    // Set up RTT
    ld.update_rtt(
        Duration::from_millis(10),
        Duration::from_millis(0),
        Duration::from_millis(25),
        now,
    );

    // Send packets 0..5
    for pn in 0..5 {
        let pkt = make_sent_packet_at(now, 100, true);
        ld.on_packet_sent(space, pn, pkt);
    }

    // ACK packet 4 (largest). Packets 0,1 are 3+ below → lost by packet threshold.
    let (acked, lost) = ld.on_ack_received(
        space,
        4,
        Duration::from_millis(0),
        &[(4, 4)],
        Duration::from_millis(25),
        now + Duration::from_millis(20),
    );

    assert_eq!(acked.len(), 1);
    let lost_pns: Vec<u64> = lost.iter().map(|(pn, _)| *pn).collect();
    // Packets 0 and 1 should be lost (4 - 0 >= 3, 4 - 1 >= 3)
    assert!(lost_pns.contains(&0), "pn 0 should be lost");
    assert!(lost_pns.contains(&1), "pn 1 should be lost");
    // Packet 2 should NOT be lost (4 - 2 = 2 < 3)
    assert!(!lost_pns.contains(&2), "pn 2 should not be lost");
}

#[test]
fn loss_by_time_threshold() {
    let mut ld = LossDetector::new();
    let now = Instant::now();
    let space = 2;

    // Set up RTT = 10ms
    ld.update_rtt(
        Duration::from_millis(10),
        Duration::from_millis(0),
        Duration::from_millis(25),
        now,
    );

    // Send packet 0 at `now`
    let pkt0 = make_sent_packet_at(now, 100, true);
    ld.on_packet_sent(space, 0, pkt0);

    // Send packet 1 much later
    let later = now + Duration::from_millis(50);
    let pkt1 = make_sent_packet_at(later, 100, true);
    ld.on_packet_sent(space, 1, pkt1);

    // ACK packet 1 well after packet 0's time threshold
    // loss_delay = 9/8 * max(10ms, 10ms) = 11.25ms
    // Packet 0 was sent at `now`, check at `later + 10ms` = now + 60ms
    // now + 60ms - 11.25ms = now + 48.75ms > now → packet 0 is lost
    let ack_time = later + Duration::from_millis(10);
    let (acked, lost) = ld.on_ack_received(
        space,
        1,
        Duration::from_millis(0),
        &[(1, 1)],
        Duration::from_millis(25),
        ack_time,
    );

    assert_eq!(acked.len(), 1);
    let lost_pns: Vec<u64> = lost.iter().map(|(pn, _)| *pn).collect();
    assert!(
        lost_pns.contains(&0),
        "pn 0 should be lost by time threshold"
    );
}

#[test]
fn discard_space_clears_bytes_in_flight() {
    let mut ld = LossDetector::new();
    let now = Instant::now();

    // Send some packets in Initial space (0)
    for pn in 0..3 {
        let pkt = make_sent_packet_at(now, 100, true);
        ld.on_packet_sent(0, pn, pkt);
    }
    assert_eq!(ld.bytes_in_flight, 300);

    // Discard Initial space
    ld.discard_space(0);
    assert_eq!(ld.bytes_in_flight, 0);
    assert!(ld.spaces[0].in_flight.iter().next().is_none());
}

#[test]
fn on_packet_sent_tracks_bytes() {
    let mut ld = LossDetector::new();
    let now = Instant::now();

    let pkt1 = make_sent_packet_at(now, 150, true);
    ld.on_packet_sent(2, 0, pkt1);
    assert_eq!(ld.bytes_in_flight, 150);

    let pkt2 = make_sent_packet_at(now, 200, false);
    ld.on_packet_sent(2, 1, pkt2);
    assert_eq!(ld.bytes_in_flight, 350);

    // Non in-flight packet shouldn't count
    let pkt3 = SentPacket {
        time_sent: now,
        size: 50,
        ack_eliciting: false,
        in_flight: false,
        frame_range: (0, 0),
    };
    ld.on_packet_sent(2, 2, pkt3);
    assert_eq!(ld.bytes_in_flight, 350);

    // Check ack_eliciting tracking
    assert_eq!(ld.spaces[2].ack_eliciting_in_flight, 1); // only pkt1 was ack_eliciting
}
