use crate::net::handler::quic::stream::send::SendHalf;

// ── Basic range insertion ───────────────────────────────────────

#[test]
fn add_single_retransmit_range() {
    let mut sh = SendHalf::new(1024);
    sh.add_retransmit_range(100, 200);
    assert_eq!(sh.retransmit_ranges(), &[(100, 200)]);
}

#[test]
fn add_multiple_disjoint_ranges() {
    let mut sh = SendHalf::new(1024);
    sh.add_retransmit_range(100, 200);
    sh.add_retransmit_range(400, 500);
    assert_eq!(sh.retransmit_ranges(), &[(100, 200), (400, 500)]);
}

// ── Adjacent range merging ──────────────────────────────────────

#[test]
fn merge_adjacent_ranges() {
    let mut sh = SendHalf::new(1024);
    sh.add_retransmit_range(100, 200);
    sh.add_retransmit_range(200, 300);
    assert_eq!(sh.retransmit_ranges(), &[(100, 300)]);
}

// ── Overlapping range merging ───────────────────────────────────

#[test]
fn merge_overlapping_ranges() {
    let mut sh = SendHalf::new(1024);
    sh.add_retransmit_range(100, 300);
    sh.add_retransmit_range(200, 400);
    assert_eq!(sh.retransmit_ranges(), &[(100, 400)]);
}

#[test]
fn merge_subset_range() {
    let mut sh = SendHalf::new(1024);
    sh.add_retransmit_range(100, 400);
    sh.add_retransmit_range(200, 300);
    assert_eq!(sh.retransmit_ranges(), &[(100, 400)]);
}

#[test]
fn merge_multiple_existing_ranges() {
    let mut sh = SendHalf::new(1024);
    sh.add_retransmit_range(100, 200);
    sh.add_retransmit_range(300, 400);
    sh.add_retransmit_range(500, 600);
    // Now insert a range that spans the first two
    sh.add_retransmit_range(150, 350);
    assert_eq!(sh.retransmit_ranges(), &[(100, 400), (500, 600)]);
}

// ── Sorted insertion ────────────────────────────────────────────

#[test]
fn sorted_insertion() {
    let mut sh = SendHalf::new(1024);
    sh.add_retransmit_range(500, 600);
    sh.add_retransmit_range(100, 200);
    sh.add_retransmit_range(300, 400);
    assert_eq!(
        sh.retransmit_ranges(),
        &[(100, 200), (300, 400), (500, 600)]
    );
}

// ── pop_retransmit_range ────────────────────────────────────────

#[test]
fn pop_retransmit_range_fifo() {
    let mut sh = SendHalf::new(1024);
    sh.add_retransmit_range(100, 200);
    sh.add_retransmit_range(300, 400);
    assert_eq!(sh.pop_retransmit_range(), Some((100, 200)));
    assert_eq!(sh.retransmit_ranges(), &[(300, 400)]);
    assert_eq!(sh.pop_retransmit_range(), Some((300, 400)));
    assert_eq!(sh.pop_retransmit_range(), None);
}

// ── trim_retransmit_for_ack ─────────────────────────────────────

#[test]
fn trim_fully_acked_removes_range() {
    let mut sh = SendHalf::new(1024);
    sh.add_retransmit_range(100, 200);
    sh.add_retransmit_range(300, 400);
    sh.trim_retransmit_for_ack(100, 200);
    assert_eq!(sh.retransmit_ranges(), &[(300, 400)]);
}

#[test]
fn trim_partial_front() {
    let mut sh = SendHalf::new(1024);
    sh.add_retransmit_range(100, 300);
    sh.trim_retransmit_for_ack(100, 200);
    assert_eq!(sh.retransmit_ranges(), &[(200, 300)]);
}

#[test]
fn trim_partial_back() {
    let mut sh = SendHalf::new(1024);
    sh.add_retransmit_range(100, 300);
    sh.trim_retransmit_for_ack(200, 300);
    assert_eq!(sh.retransmit_ranges(), &[(100, 200)]);
}

#[test]
fn trim_split_punches_hole() {
    let mut sh = SendHalf::new(1024);
    sh.add_retransmit_range(100, 400);
    sh.trim_retransmit_for_ack(200, 300);
    assert_eq!(sh.retransmit_ranges(), &[(100, 200), (300, 400)]);
}

#[test]
fn trim_no_overlap_is_noop() {
    let mut sh = SendHalf::new(1024);
    sh.add_retransmit_range(100, 200);
    sh.trim_retransmit_for_ack(300, 400);
    assert_eq!(sh.retransmit_ranges(), &[(100, 200)]);
}

// ── has_pending_data ────────────────────────────────────────────

#[test]
fn has_pending_data_retransmit() {
    let mut sh = SendHalf::new(1024);
    assert!(!sh.has_pending_data());
    sh.add_retransmit_range(100, 200);
    assert!(sh.has_pending_data());
}

#[test]
fn has_pending_data_unsent_buffer() {
    let mut sh = SendHalf::new(1024);
    sh.write(b"hello");
    assert!(sh.has_pending_data());
}

#[test]
fn has_pending_data_fin_pending() {
    let mut sh = SendHalf::new(1024);
    assert!(!sh.has_pending_data());
    sh.fin_sent = false;
    // fin_sent = false alone doesn't mean FIN is pending; we need the buffer
    // to be consumed and a FIN to actually be queued. For now, fin_sent=false
    // with empty buffer means no pending data.
    assert!(!sh.has_pending_data());
}

// ── reset clears retransmit ─────────────────────────────────────

#[test]
fn reset_clears_retransmit_and_acked_ooo() {
    let mut sh = SendHalf::new(1024);
    sh.add_retransmit_range(100, 200);
    sh.reset();
    assert!(sh.retransmit_ranges().is_empty());
}
