use ring::hmac;

/// Generate a stateless reset token from a CID and server secret.
/// Token must be unpredictable (RFC 9000 §10.3).
pub fn generate_reset_token(cid: &[u8], server_secret: &[u8]) -> [u8; 16] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, server_secret);
    let tag = hmac::sign(&key, cid);
    let mut token = [0u8; 16];
    token.copy_from_slice(&tag.as_ref()[..16]); // truncate to 16 bytes
    token
}

/// Check if the last 16 bytes of a packet match any known reset token.
pub fn detect_stateless_reset(packet: &[u8], known_tokens: &[[u8; 16]]) -> bool {
    if packet.len() < 16 + 1 {
        // minimum: 1 byte + 16 byte token
        return false;
    }
    let token_start = packet.len() - 16;
    let received_token = &packet[token_start..];
    for known in known_tokens {
        // Constant-time comparison
        let mut diff = 0u8;
        for (a, b) in received_token.iter().zip(known.iter()) {
            diff |= a ^ b;
        }
        if diff == 0 {
            return true;
        }
    }
    false
}
