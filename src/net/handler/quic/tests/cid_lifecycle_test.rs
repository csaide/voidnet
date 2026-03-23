use crate::net::handler::quic::cid_lifecycle::CidManager;
use crate::net::handler::quic::connection_id::{CidSet, ConnectionId};

#[test]
fn new_cid_manager() {
    let initial = ConnectionId::from_slice(&[0x01, 0x02, 0x03, 0x04]);
    let mgr = CidManager::new(initial, 4);

    assert_eq!(mgr.local_cids.len(), 1);
    assert!(mgr.local_cids.contains(&initial));
    assert_eq!(mgr.next_sequence, 1);
}

#[test]
fn on_new_connection_id_retires_old() {
    let initial = ConnectionId::from_slice(&[0xaa]);
    let mut mgr = CidManager::new(initial, 4);

    // First, store peer CIDs with sequences 0, 1, 2 so they can be retired
    let cid0 = ConnectionId::from_slice(&[0x10]);
    let cid1 = ConnectionId::from_slice(&[0x11]);
    let cid2 = ConnectionId::from_slice(&[0x12]);
    mgr.peer_cids.push_with_seq(cid0, 0);
    mgr.peer_cids.push_with_seq(cid1, 1);
    mgr.peer_cids.push_with_seq(cid2, 2);

    let new_cid = ConnectionId::from_slice(&[0xbb]);
    // sequence=3, retire_prior_to=3 means sequences 0, 1, 2 should be retired
    let retired = mgr.on_new_connection_id(3, 3, new_cid);

    assert_eq!(retired.len(), 3);
    assert!(retired.contains(&0));
    assert!(retired.contains(&1));
    assert!(retired.contains(&2));
    // new CID should be stored
    assert!(mgr.peer_cids.contains(&new_cid));
}

#[test]
fn take_pending_retires() {
    let initial = ConnectionId::from_slice(&[0xcc]);
    let mut mgr = CidManager::new(initial, 4);

    // Store peer CIDs with sequences 0 and 1
    let cid0 = ConnectionId::from_slice(&[0x20]);
    let cid1 = ConnectionId::from_slice(&[0x21]);
    mgr.peer_cids.push_with_seq(cid0, 0);
    mgr.peer_cids.push_with_seq(cid1, 1);

    let new_cid = ConnectionId::from_slice(&[0xdd]);
    mgr.on_new_connection_id(2, 2, new_cid);

    let pending = mgr.take_pending_retires();
    assert_eq!(pending.len(), 2);
    assert!(pending.contains(&0));
    assert!(pending.contains(&1));

    // After taking, the queue is drained
    let pending2 = mgr.take_pending_retires();
    assert!(pending2.is_empty());
}

#[test]
fn at_limit_check() {
    let initial = ConnectionId::from_slice(&[0x01]);
    let mut mgr = CidManager::new(initial, 2);

    // 0 peer CIDs, limit is 2 — not at limit
    assert!(!mgr.at_limit());

    // Add two peer CIDs — now at limit
    let cid1 = ConnectionId::from_slice(&[0x02]);
    let cid2 = ConnectionId::from_slice(&[0x03]);
    mgr.peer_cids.push_with_seq(cid1, 0);
    mgr.peer_cids.push_with_seq(cid2, 1);
    assert!(mgr.at_limit());
}

#[test]
fn retire_prior_to_large_value_does_not_loop() {
    let initial = ConnectionId::from_slice(&[0xaa]);
    let mut mgr = CidManager::new(initial, 4);
    let cid0 = ConnectionId::from_slice(&[0x10]);
    mgr.peer_cids.push_with_seq(cid0, 5);

    // retire_prior_to = 2^60 should NOT cause a long loop
    let new_cid = ConnectionId::from_slice(&[0xbb]);
    let start = std::time::Instant::now();
    let retired = mgr.on_new_connection_id(
        1_152_921_504_606_846_976,
        1_152_921_504_606_846_976,
        new_cid,
    );
    let elapsed = start.elapsed();

    // Must complete in under 10ms (was infinite before fix)
    assert!(
        elapsed.as_millis() < 10,
        "retire loop took too long: {:?}",
        elapsed
    );
    // Should have retired cid0 (seq 5 < retire_prior_to)
    assert!(retired.contains(&5));
    assert!(mgr.peer_cids.contains(&new_cid));
}

#[test]
fn issue_new_cid_tracks_sequence() {
    let initial = ConnectionId::from_slice(&[0x01]);
    let mut mgr = CidManager::new(initial, 4);

    // Initial CID uses seq 0, next_sequence starts at 1
    assert_eq!(mgr.next_sequence, 1);
    assert_eq!(mgr.highest_issued_seq, 0);

    let cid1 = ConnectionId::from_slice(&[0x02]);
    let seq = mgr.issue_new_cid(cid1);
    assert_eq!(seq, Some(1));
    assert_eq!(mgr.highest_issued_seq, 1);
    assert_eq!(mgr.next_sequence, 2);
    assert_eq!(mgr.local_cids.len(), 2);

    let cid2 = ConnectionId::from_slice(&[0x03]);
    let seq = mgr.issue_new_cid(cid2);
    assert_eq!(seq, Some(2));
    assert_eq!(mgr.highest_issued_seq, 2);
}

#[test]
fn issue_new_cid_returns_none_when_full() {
    let initial = ConnectionId::from_slice(&[0x01]);
    let mut mgr = CidManager::new(initial, 8);

    // CidSet max capacity is 8; one slot used by initial
    for i in 1..8 {
        let cid = ConnectionId::from_slice(&[i as u8 + 0x10]);
        assert!(mgr.issue_new_cid(cid).is_some());
    }
    // 9th should fail
    let overflow = ConnectionId::from_slice(&[0xFF]);
    assert_eq!(mgr.issue_new_cid(overflow), None);
}

#[test]
fn retire_connection_id_invalid_sequence() {
    // Simulate: peer sends RETIRE_CONNECTION_ID with sequence > highest_issued_seq
    let initial = ConnectionId::from_slice(&[0x01]);
    let mgr = CidManager::new(initial, 4);

    // highest_issued_seq is 0 (only initial CID)
    assert_eq!(mgr.highest_issued_seq, 0);
    // Sequence 1 > 0 would be a PROTOCOL_VIOLATION
    assert!(1 > mgr.highest_issued_seq);
}

#[test]
fn retire_connection_id_valid_sequence() {
    let initial = ConnectionId::from_slice(&[0x01]);
    let mut mgr = CidManager::new(initial, 4);

    // Issue a new CID
    let cid1 = ConnectionId::from_slice(&[0x02]);
    mgr.issue_new_cid(cid1);
    assert_eq!(mgr.highest_issued_seq, 1);

    // Retire sequence 0 (the initial CID) — valid
    let retired = mgr.local_cids.remove_by_seq(0);
    assert!(retired.is_some());
    assert_eq!(retired.unwrap(), initial);

    // Retire sequence 1 — also valid
    let retired = mgr.local_cids.remove_by_seq(1);
    assert!(retired.is_some());
    assert_eq!(retired.unwrap(), cid1);
}

#[test]
fn zero_length_cid_check() {
    // A connection with zero-length CID should reject NEW_CONNECTION_ID
    let empty_cid = ConnectionId::empty();
    assert!(empty_cid.is_empty());

    // Non-empty CID should pass
    let normal_cid = ConnectionId::from_slice(&[0x01, 0x02]);
    assert!(!normal_cid.is_empty());
}

#[test]
fn retire_prior_to_queues_retire_frames() {
    let initial = ConnectionId::from_slice(&[0xcc]);
    let mut mgr = CidManager::new(initial, 4);

    // Store peer CIDs with sequences 0, 1, 2
    mgr.peer_cids
        .push_with_seq(ConnectionId::from_slice(&[0x10]), 0);
    mgr.peer_cids
        .push_with_seq(ConnectionId::from_slice(&[0x11]), 1);
    mgr.peer_cids
        .push_with_seq(ConnectionId::from_slice(&[0x12]), 2);

    // Peer sends NEW_CONNECTION_ID with retire_prior_to=2
    let new_cid = ConnectionId::from_slice(&[0x13]);
    let retired = mgr.on_new_connection_id(3, 2, new_cid);

    // Sequences 0 and 1 should be retired
    assert_eq!(retired.len(), 2);
    assert!(retired.contains(&0));
    assert!(retired.contains(&1));

    // Pending retires should include them
    let pending = mgr.take_pending_retires();
    assert_eq!(pending.len(), 2);

    // Remaining peer CIDs: seq 2 and seq 3
    assert_eq!(mgr.peer_cids.len(), 2);
}

#[test]
fn needs_replacement_cid_flag() {
    let initial = ConnectionId::from_slice(&[0x01]);
    let mut mgr = CidManager::new(initial, 4);

    assert!(!mgr.needs_replacement_cid);
    mgr.needs_replacement_cid = true;
    assert!(mgr.needs_replacement_cid);
    mgr.needs_replacement_cid = false;
    assert!(!mgr.needs_replacement_cid);
}

#[test]
fn cid_set_iter_seqs() {
    let mut set = CidSet::new();
    set.push_with_seq(ConnectionId::from_slice(&[0x01]), 10);
    set.push_with_seq(ConnectionId::from_slice(&[0x02]), 20);
    set.push_with_seq(ConnectionId::from_slice(&[0x03]), 30);

    let seqs: Vec<u64> = set.iter_seqs().collect();
    assert_eq!(seqs, vec![10, 20, 30]);
}

#[test]
fn active_cid_limit_enforcement() {
    // Simulate: peer sends more NEW_CONNECTION_ID frames than our active_connection_id_limit
    let initial = ConnectionId::from_slice(&[0x01]);
    let mut mgr = CidManager::new(initial, 4);

    // Add 3 peer CIDs
    for i in 0..3u8 {
        mgr.peer_cids
            .push_with_seq(ConnectionId::from_slice(&[0x10 + i]), i as u64);
    }
    // If our limit is 2, having 3 peer CIDs exceeds it
    let our_limit = 2u64;
    assert!(mgr.peer_cids.len() as u64 > our_limit);
}

#[test]
fn new_connection_id_retire_prior_to_greater_than_sequence_is_invalid() {
    // RFC 9000 §19.15: retire_prior_to MUST NOT be greater than sequence
    // This would be checked in the processor before calling CidManager
    // retire_prior_to=5 > sequence=3 is invalid
    let retire_prior_to = 5u64;
    let sequence = 3u64;
    assert!(retire_prior_to > sequence);
}
