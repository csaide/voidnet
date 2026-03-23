//! Tests for NEW_TOKEN feature (RFC 9000 §8.1).

use crate::net::handler::quic::transport::frame::{self, QuicFrame};
use crate::net::handler::quic::transport::frame_writer;
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

// --- NEW_TOKEN frame serialization round-trip tests ---

#[test]
fn new_token_frame_write_and_parse_round_trip() {
    let token = b"my-validation-token-12345";
    let mut buf = [0u8; 128];
    let written = frame_writer::write_new_token(&mut buf, token);

    // Parse it back
    let (parsed, consumed) = frame::parse_frame(&buf[..written]).unwrap();
    assert_eq!(consumed, written);
    match parsed {
        QuicFrame::NewToken(nt) => {
            assert_eq!(nt.token, token);
        }
        _ => panic!("expected NewToken frame, got {:?}", parsed),
    }
}

#[test]
fn new_token_frame_round_trip_large_token() {
    let token = vec![0xAB; 200];
    let mut buf = [0u8; 256];
    let written = frame_writer::write_new_token(&mut buf, &token);

    let (parsed, consumed) = frame::parse_frame(&buf[..written]).unwrap();
    assert_eq!(consumed, written);
    match parsed {
        QuicFrame::NewToken(nt) => {
            assert_eq!(nt.token, &token[..]);
        }
        _ => panic!("expected NewToken frame"),
    }
}

#[test]
fn new_token_frame_parse_rejects_empty_token() {
    // 0x07 (type) + 0x00 (length = 0) -> should fail per RFC 9000 §19.7
    let buf = [0x07, 0x00];
    let result = frame::parse_frame(&buf);
    assert!(result.is_err());
}
