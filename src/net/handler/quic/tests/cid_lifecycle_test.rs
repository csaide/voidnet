use crate::net::handler::quic::cid_lifecycle::CidManager;
use crate::net::handler::quic::connection_id::ConnectionId;

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

    let new_cid = ConnectionId::from_slice(&[0xbb]);
    // sequence=3, retire_prior_to=3 means sequences 0, 1, 2 should be retired
    let retired = mgr.on_new_connection_id(3, 3, new_cid);

    assert_eq!(retired.len(), 3);
    assert!(retired.contains(&0));
    assert!(retired.contains(&1));
    assert!(retired.contains(&2));
}

#[test]
fn take_pending_retires() {
    let initial = ConnectionId::from_slice(&[0xcc]);
    let mut mgr = CidManager::new(initial, 4);

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

    // 1 CID in set, limit is 2 — not at limit
    assert!(!mgr.at_limit());

    // Add a second CID — now at limit
    let cid2 = ConnectionId::from_slice(&[0x02]);
    mgr.local_cids.push(cid2);
    assert!(mgr.at_limit());
}
