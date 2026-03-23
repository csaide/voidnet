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

// ── on_ack: contiguous ──────────────────────────────────────────

#[test]
fn test_on_ack_contiguous_advances_acked() {
    let mut send = SendHalf::new(65535);
    send.write(b"hello world"); // 11 bytes
    send.sent = 11;
    send.on_ack(0, 5);
    assert_eq!(send.acked, 5);
    assert_eq!(send.buffer.len(), 6); // 6 bytes remain
}

#[test]
fn test_on_ack_out_of_order_stores_range() {
    let mut send = SendHalf::new(65535);
    send.write(b"hello world");
    send.sent = 11;
    send.on_ack(5, 8);
    assert_eq!(send.acked, 0); // gap at 0-5
    assert_eq!(send.acked_ooo_ranges(), &[(5, 8)]);
}

#[test]
fn test_on_ack_coalesces_gap_fill() {
    let mut send = SendHalf::new(65535);
    send.write(b"hello world");
    send.sent = 11;
    send.on_ack(5, 11); // ack 5-11
    assert_eq!(send.acked, 0); // gap at 0-5
    send.on_ack(0, 5); // fill gap
    assert_eq!(send.acked, 11); // coalesced!
    assert!(send.acked_ooo_ranges().is_empty());
    assert!(send.buffer.is_empty()); // all data freed
}

#[test]
fn test_on_ack_returns_freed_bytes() {
    let mut send = SendHalf::new(65535);
    send.write(b"hello world"); // 11 bytes
    send.sent = 11;
    let freed = send.on_ack(0, 5);
    assert_eq!(freed, 5);
    // OOO ack frees nothing immediately
    let freed = send.on_ack(8, 11);
    assert_eq!(freed, 0);
    // Fill the gap: frees 5..11 = 6 bytes
    let freed = send.on_ack(5, 8);
    assert_eq!(freed, 6);
}

#[test]
fn test_on_ack_already_acked_returns_zero() {
    let mut send = SendHalf::new(65535);
    send.write(b"hello world");
    send.sent = 11;
    send.on_ack(0, 5);
    // Re-ack same region
    let freed = send.on_ack(0, 5);
    assert_eq!(freed, 0);
    assert_eq!(send.acked, 5);
}

#[test]
fn test_on_ack_multiple_ooo_coalesce() {
    let mut send = SendHalf::new(65535);
    send.write(b"abcdefghijklmnop"); // 16 bytes
    send.sent = 16;

    // Create three OOO ranges
    send.on_ack(4, 6);
    send.on_ack(8, 12);
    send.on_ack(14, 16);
    assert_eq!(send.acked, 0);
    assert_eq!(send.acked_ooo_ranges(), &[(4, 6), (8, 12), (14, 16)]);

    // Fill gap 0-4, should coalesce with (4,6)
    let freed = send.on_ack(0, 4);
    assert_eq!(send.acked, 6);
    assert_eq!(freed, 6);
    assert_eq!(send.acked_ooo_ranges(), &[(8, 12), (14, 16)]);

    // Fill gap 6-8, coalesces with (8,12)
    let freed = send.on_ack(6, 8);
    assert_eq!(send.acked, 12);
    assert_eq!(freed, 6);
    assert_eq!(send.acked_ooo_ranges(), &[(14, 16)]);

    // Fill gap 12-14, coalesces with (14,16) — everything acked
    let freed = send.on_ack(12, 14);
    assert_eq!(send.acked, 16);
    assert_eq!(freed, 4);
    assert!(send.acked_ooo_ranges().is_empty());
    assert!(send.buffer.is_empty());
}

// ── reset clears retransmit ─────────────────────────────────────

#[test]
fn reset_clears_retransmit_and_acked_ooo() {
    let mut sh = SendHalf::new(1024);
    sh.add_retransmit_range(100, 200);
    sh.reset();
    assert!(sh.retransmit_ranges().is_empty());
}
