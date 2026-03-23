//! Tests for NEW_TOKEN feature (RFC 9000 §8.1).

use crate::net::socket::quic::{InMemoryTokenStore, TokenStore};

#[test]
fn token_store_put_and_get() {
    let store = InMemoryTokenStore::new();
    let token = vec![0x01, 0x02, 0x03, 0x04];
    store.put("example.com", 1, token.clone());

    let retrieved = store.get("example.com", 1);
    assert_eq!(retrieved, Some(token));
}

#[test]
fn token_store_returns_none_for_missing() {
    let store = InMemoryTokenStore::new();
    assert_eq!(store.get("example.com", 1), None);
}

#[test]
fn token_store_keys_by_server_name_and_version() {
    let store = InMemoryTokenStore::new();
    let token_v1 = vec![0x01];
    let token_v2 = vec![0x02];
    let token_other = vec![0x03];

    store.put("example.com", 1, token_v1.clone());
    store.put("example.com", 2, token_v2.clone());
    store.put("other.com", 1, token_other.clone());

    assert_eq!(store.get("example.com", 1), Some(token_v1));
    assert_eq!(store.get("example.com", 2), Some(token_v2));
    assert_eq!(store.get("other.com", 1), Some(token_other));
    assert_eq!(store.get("other.com", 2), None);
}

#[test]
fn token_store_overwrites_existing() {
    let store = InMemoryTokenStore::new();
    store.put("example.com", 1, vec![0x01]);
    store.put("example.com", 1, vec![0x02]);

    assert_eq!(store.get("example.com", 1), Some(vec![0x02]));
}
