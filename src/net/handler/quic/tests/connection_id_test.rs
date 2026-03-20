use crate::net::handler::quic::connection_id::{CidSet, ConnectionId, ConnectionIdRef};
use std::collections::HashSet;

#[test]
fn connection_id_from_slice() {
    let bytes = [0x01u8, 0x02, 0x03, 0x04, 0x05];
    let cid = ConnectionId::from_slice(&bytes);
    assert_eq!(cid.as_bytes(), &bytes);
    assert_eq!(cid.len(), 5);
    assert!(!cid.is_empty());
}

#[test]
fn connection_id_max_length() {
    let bytes = [0xffu8; 20];
    let cid = ConnectionId::from_slice(&bytes);
    assert_eq!(cid.len(), 20);
    assert_eq!(cid.as_bytes(), &bytes);
}

#[test]
#[should_panic]
fn connection_id_too_long() {
    let bytes = [0x00u8; 21];
    let _ = ConnectionId::from_slice(&bytes);
}

#[test]
fn connection_id_empty() {
    let cid = ConnectionId::empty();
    assert_eq!(cid.len(), 0);
    assert!(cid.is_empty());
    assert_eq!(cid.as_bytes(), &[]);
}

#[test]
fn connection_id_eq_and_hash() {
    let a = ConnectionId::from_slice(&[0x01, 0x02, 0x03]);
    let b = ConnectionId::from_slice(&[0x01, 0x02, 0x03]);
    let c = ConnectionId::from_slice(&[0x04, 0x05, 0x06]);

    assert_eq!(a, b);
    assert_ne!(a, c);

    let mut set = HashSet::new();
    set.insert(a);
    assert!(set.contains(&b));
    assert!(!set.contains(&c));
}

#[test]
fn connection_id_ref_to_owned() {
    let bytes = [0xdeu8, 0xad, 0xbe, 0xef];
    let cid_ref = ConnectionIdRef::from_slice(&bytes);
    assert_eq!(cid_ref.len(), 4);
    assert_eq!(cid_ref.as_bytes(), &bytes);

    let owned = cid_ref.to_owned();
    assert_eq!(owned.as_bytes(), &bytes);
    assert_eq!(owned.len(), 4);
}

#[test]
fn cid_set_push_and_remove() {
    let mut set = CidSet::new();
    let a = ConnectionId::from_slice(&[0x01]);
    let b = ConnectionId::from_slice(&[0x02]);

    assert!(set.push(a));
    assert!(set.push(b));
    assert_eq!(set.len(), 2);

    assert!(set.remove(&a));
    assert_eq!(set.len(), 1);
    assert!(!set.contains(&a));
    assert!(set.contains(&b));

    // removing non-existent returns false
    assert!(!set.remove(&a));
}

#[test]
fn cid_set_full() {
    let mut set = CidSet::new();
    for i in 0u8..8 {
        let cid = ConnectionId::from_slice(&[i]);
        assert!(set.push(cid), "push #{i} should succeed");
    }
    assert_eq!(set.len(), 8);
    // ninth push should fail
    let overflow = ConnectionId::from_slice(&[0xff]);
    assert!(!set.push(overflow));
    assert_eq!(set.len(), 8);
}

#[test]
fn cid_set_contains() {
    let mut set = CidSet::new();
    let present = ConnectionId::from_slice(&[0xaa, 0xbb]);
    let absent = ConnectionId::from_slice(&[0xcc, 0xdd]);

    assert!(!set.contains(&present));
    set.push(present);
    assert!(set.contains(&present));
    assert!(!set.contains(&absent));
}
