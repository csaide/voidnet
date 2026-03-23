//! Token encryption/decryption for NEW_TOKEN frames (RFC 9000 §8.1).
//!
//! Tokens encode the client IP, timestamp, original DCID, version, and
//! token type (Retry vs NEW_TOKEN).  They are encrypted with AES-256-GCM
//! using a server-held secret so that only the issuing server can validate
//! them.
//!
//! Wire format (plaintext, before encryption):
//!   type(1) + ip_version(1) + ip(4 or 16) + timestamp_secs(8)
//!           + dcid_len(1) + dcid(0-20) + version(4)
//!
//! Encrypted format (on the wire / in NEW_TOKEN frame):
//!   nonce(12) + ciphertext + AES-GCM tag(16)

use ring::aead::{self, AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

/// Distinguishes Retry tokens from NEW_TOKEN tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TokenType {
    Retry = 0x00,
    NewToken = 0x01,
}

/// Encrypt a token for a NEW_TOKEN frame (or Retry).
///
/// Returns the encrypted blob including a 12-byte nonce and the
/// AES-GCM tag.
pub fn encrypt_token(
    secret: &[u8; 32],
    token_type: TokenType,
    client_ip: &[u8],
    timestamp_secs: u64,
    dcid: &[u8],
    version: u32,
) -> Result<Vec<u8>, ()> {
    // Build plaintext
    let ip_version: u8 = match client_ip.len() {
        4 => 4,
        16 => 6,
        _ => return Err(()),
    };

    let plaintext_len = 1 + 1 + client_ip.len() + 8 + 1 + dcid.len() + 4;
    let mut plaintext = Vec::with_capacity(plaintext_len);
    plaintext.push(token_type as u8);
    plaintext.push(ip_version);
    plaintext.extend_from_slice(client_ip);
    plaintext.extend_from_slice(&timestamp_secs.to_be_bytes());
    plaintext.push(dcid.len() as u8);
    plaintext.extend_from_slice(dcid);
    plaintext.extend_from_slice(&version.to_be_bytes());

    // Build 12-byte nonce: 4 bytes timestamp + 8 bytes random
    let ts_bytes = timestamp_secs.to_be_bytes();
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..4].copy_from_slice(&ts_bytes[..4]);
    {
        use ring::rand::SecureRandom;
        ring::rand::SystemRandom::new()
            .fill(&mut nonce_bytes[4..])
            .map_err(|_| ())?;
    }

    let key = UnboundKey::new(&AES_256_GCM, secret).map_err(|_| ())?;
    let key = LessSafeKey::new(key);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    // Encrypt in place (appends 16-byte tag)
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut plaintext)
        .map_err(|_| ())?;

    // Output: nonce(12) + ciphertext_with_tag
    let mut output = Vec::with_capacity(12 + plaintext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&plaintext);
    Ok(output)
}

/// Decrypt a token received in a NEW_TOKEN frame or Initial packet.
///
/// Returns `(token_type, client_ip, timestamp_secs, dcid, version)`.
pub fn decrypt_token(
    secret: &[u8; 32],
    encrypted: &[u8],
) -> Result<(TokenType, Vec<u8>, u64, Vec<u8>, u32), ()> {
    // Minimum size: 12 (nonce) + 1 (type) + 1 (ip_ver) + 4 (ipv4) + 8 (ts) + 1 (dcid_len) + 4 (version) + 16 (tag)
    if encrypted.len() < 12 + 19 + 16 {
        return Err(());
    }

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&encrypted[..12]);
    let mut ciphertext = encrypted[12..].to_vec();

    let key = UnboundKey::new(&AES_256_GCM, secret).map_err(|_| ())?;
    let key = LessSafeKey::new(key);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let plaintext = key
        .open_in_place(nonce, Aad::empty(), &mut ciphertext)
        .map_err(|_| ())?;

    // Parse plaintext fields
    if plaintext.len() < 15 {
        return Err(());
    }

    let token_type = match plaintext[0] {
        0x00 => TokenType::Retry,
        0x01 => TokenType::NewToken,
        _ => return Err(()),
    };

    let ip_version = plaintext[1];
    let ip_len = match ip_version {
        4 => 4usize,
        6 => 16usize,
        _ => return Err(()),
    };

    let mut pos = 2;
    if plaintext.len() < pos + ip_len + 8 + 1 {
        return Err(());
    }

    let client_ip = plaintext[pos..pos + ip_len].to_vec();
    pos += ip_len;

    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&plaintext[pos..pos + 8]);
    let timestamp_secs = u64::from_be_bytes(ts_bytes);
    pos += 8;

    let dcid_len = plaintext[pos] as usize;
    pos += 1;

    if dcid_len > 20 || plaintext.len() < pos + dcid_len + 4 {
        return Err(());
    }

    let dcid = plaintext[pos..pos + dcid_len].to_vec();
    pos += dcid_len;

    let mut ver_bytes = [0u8; 4];
    ver_bytes.copy_from_slice(&plaintext[pos..pos + 4]);
    let version = u32::from_be_bytes(ver_bytes);

    Ok((token_type, client_ip, timestamp_secs, dcid, version))
}
