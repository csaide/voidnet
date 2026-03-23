//! Tests for NEW_TOKEN feature (RFC 9000 §8.1).

use crate::net::handler::quic::token_crypto::{self, TokenType};
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

// --- Token encryption/decryption tests ---

#[test]
fn token_crypto_encrypt_decrypt_ipv4() {
    let secret = [0xAA; 32];
    let client_ip = [192, 168, 1, 1];
    let timestamp = 1700000000u64;
    let dcid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let version = 0x00000001;

    let encrypted = token_crypto::encrypt_token(
        &secret,
        TokenType::NewToken,
        &client_ip,
        timestamp,
        &dcid,
        version,
    )
    .unwrap();

    let (token_type, ip, ts, d, v) = token_crypto::decrypt_token(&secret, &encrypted).unwrap();
    assert_eq!(token_type, TokenType::NewToken);
    assert_eq!(ip, client_ip);
    assert_eq!(ts, timestamp);
    assert_eq!(d, dcid);
    assert_eq!(v, version);
}

#[test]
fn token_crypto_encrypt_decrypt_ipv6() {
    let secret = [0xBB; 32];
    let client_ip = [
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ];
    let timestamp = 1700000042u64;
    let dcid = [0xFF; 8];
    let version = 0x6b3343cf; // QUIC v2

    let encrypted = token_crypto::encrypt_token(
        &secret,
        TokenType::Retry,
        &client_ip,
        timestamp,
        &dcid,
        version,
    )
    .unwrap();

    let (token_type, ip, ts, d, v) = token_crypto::decrypt_token(&secret, &encrypted).unwrap();
    assert_eq!(token_type, TokenType::Retry);
    assert_eq!(ip, client_ip);
    assert_eq!(ts, timestamp);
    assert_eq!(d, dcid);
    assert_eq!(v, version);
}

#[test]
fn token_crypto_wrong_secret_fails() {
    let secret = [0xAA; 32];
    let wrong_secret = [0xCC; 32];
    let client_ip = [10, 0, 0, 1];

    let encrypted =
        token_crypto::encrypt_token(&secret, TokenType::NewToken, &client_ip, 1000, &[], 1)
            .unwrap();

    let result = token_crypto::decrypt_token(&wrong_secret, &encrypted);
    assert!(result.is_err());
}

#[test]
fn token_crypto_tampered_data_fails() {
    let secret = [0xAA; 32];
    let client_ip = [10, 0, 0, 1];

    let mut encrypted =
        token_crypto::encrypt_token(&secret, TokenType::NewToken, &client_ip, 1000, &[], 1)
            .unwrap();

    // Tamper with a byte in the ciphertext
    if encrypted.len() > 10 {
        encrypted[10] ^= 0xFF;
    }

    let result = token_crypto::decrypt_token(&secret, &encrypted);
    assert!(result.is_err());
}

#[test]
fn token_crypto_empty_dcid() {
    let secret = [0xDD; 32];
    let client_ip = [127, 0, 0, 1];

    let encrypted =
        token_crypto::encrypt_token(&secret, TokenType::NewToken, &client_ip, 999, &[], 1).unwrap();

    let (token_type, ip, ts, d, v) = token_crypto::decrypt_token(&secret, &encrypted).unwrap();
    assert_eq!(token_type, TokenType::NewToken);
    assert_eq!(ip, client_ip);
    assert_eq!(ts, 999);
    assert!(d.is_empty());
    assert_eq!(v, 1);
}

#[test]
fn token_crypto_too_short_fails() {
    let secret = [0xAA; 32];
    let short = [0u8; 10];
    assert!(token_crypto::decrypt_token(&secret, &short).is_err());
}
