/// Fixed key for Retry integrity tag computation (RFC 9001 §5.8, QUIC v1)
const RETRY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];

/// Fixed nonce for Retry integrity tag computation (RFC 9001 §5.8, QUIC v1)
const RETRY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

/// Fixed key for Retry integrity tag computation (QUIC v2, RFC 9369)
const RETRY_KEY_V2: [u8; 16] = [
    0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2, 0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92,
];

/// Fixed nonce for Retry integrity tag computation (QUIC v2, RFC 9369)
const RETRY_NONCE_V2: [u8; 12] = [
    0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a,
];

/// Compute Retry integrity tag.
/// `odcid` = Original Destination Connection ID
/// `retry_packet` = the Retry packet bytes WITHOUT the tag (header + token)
/// `version` = QUIC version to select the correct key/nonce (v1 or v2)
pub fn compute_retry_integrity_tag(odcid: &[u8], retry_packet: &[u8], version: u32) -> [u8; 16] {
    use ring::aead;

    use super::super::transport::version::QUIC_VERSION_2;

    let (key_bytes, nonce_bytes) = if version == QUIC_VERSION_2 {
        (&RETRY_KEY_V2, &RETRY_NONCE_V2)
    } else {
        (&RETRY_KEY_V1, &RETRY_NONCE_V1)
    };

    // Build AAD: ODCID_len(1) + ODCID + retry_packet
    let mut aad = Vec::with_capacity(1 + odcid.len() + retry_packet.len());
    aad.push(odcid.len() as u8);
    aad.extend_from_slice(odcid);
    aad.extend_from_slice(retry_packet);

    // AES-128-GCM encrypt with empty plaintext → tag is the output
    let key = aead::UnboundKey::new(&aead::AES_128_GCM, key_bytes).unwrap();
    let nonce = aead::Nonce::assume_unique_for_key(*nonce_bytes);
    let key = aead::LessSafeKey::new(key);

    let mut in_out = Vec::new(); // empty plaintext
    let tag = key
        .seal_in_place_separate_tag(nonce, aead::Aad::from(&aad), &mut in_out)
        .unwrap();

    let mut result = [0u8; 16];
    result.copy_from_slice(tag.as_ref());
    result
}

/// Verify a Retry integrity tag.
pub fn verify_retry_integrity_tag(
    odcid: &[u8],
    retry_packet_with_tag: &[u8],
    version: u32,
) -> bool {
    if retry_packet_with_tag.len() < 16 {
        return false;
    }
    let (packet, tag) = retry_packet_with_tag.split_at(retry_packet_with_tag.len() - 16);
    let expected = compute_retry_integrity_tag(odcid, packet, version);
    // Constant-time comparison (fixed-length, safe to compare byte-by-byte with XOR)
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(tag.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}
