use crate::net::handler::quic::crypto::stateless_reset::{
    detect_stateless_reset, generate_reset_token,
};

#[test]
fn generate_token_deterministic() {
    let cid = [0x01, 0x02, 0x03, 0x04];
    let secret = b"server_secret_key";
    let token1 = generate_reset_token(&cid, secret);
    let token2 = generate_reset_token(&cid, secret);
    assert_eq!(token1, token2);
}

#[test]
fn generate_token_different_cids() {
    let secret = b"server_secret_key";
    let token1 = generate_reset_token(&[0x01, 0x02], secret);
    let token2 = generate_reset_token(&[0x03, 0x04], secret);
    assert_ne!(token1, token2);
}

#[test]
fn generate_token_different_secrets() {
    let cid = [0x01, 0x02, 0x03, 0x04];
    let token1 = generate_reset_token(&cid, b"secret_one");
    let token2 = generate_reset_token(&cid, b"secret_two");
    assert_ne!(token1, token2);
}

#[test]
fn detect_reset_match() {
    let cid = [0x11, 0x22, 0x33];
    let secret = b"my_server_secret";
    let token = generate_reset_token(&cid, secret);

    // Build a packet: 5 arbitrary bytes + the 16-byte token
    let mut packet = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee];
    packet.extend_from_slice(&token);

    assert!(detect_stateless_reset(&packet, &[token]));
}

#[test]
fn detect_reset_no_match() {
    let token = [0u8; 16];
    let wrong_token = [0xffu8; 16];

    let mut packet = vec![0xaa, 0xbb];
    packet.extend_from_slice(&token);

    assert!(!detect_stateless_reset(&packet, &[wrong_token]));
}

#[test]
fn detect_reset_too_short() {
    // packet must be at least 17 bytes (1 + 16)
    let token = [0u8; 16];
    let packet = token.to_vec(); // exactly 16 bytes — too short

    assert!(!detect_stateless_reset(&packet, &[token]));
}
