use super::keys::DirectionalKey;

/// Errors that can occur during packet protection/unprotection.
#[derive(Debug)]
pub enum ProtectError {
    BufferTooShort,
    EncryptFailed,
    DecryptFailed,
    HeaderProtectFailed,
}

/// Encrypt a QUIC packet payload in-place and apply header protection.
///
/// `packet` is the entire packet buffer. Everything before `pn_offset` is
/// the unprotected header (used as AEAD AAD). `pn_offset` is where the
/// packet number starts. `pn_length` is 1–4 bytes. The buffer must already
/// contain the plaintext payload at `pn_offset + pn_length` with `tag_len()`
/// bytes of spare capacity at the end.
///
/// Steps (RFC 9001 §5.3-5.4):
/// 1. AEAD-encrypt the payload (bytes after PN) with the header (bytes before
///    PN, including PN bytes) as AAD. The tag is written in-place after the
///    ciphertext.
/// 2. Sample `sample_len()` bytes from the encrypted payload starting at
///    `pn_offset + 4` (RFC 9001 §5.4.2: always assume 4-byte PN field for
///    sample position).
/// 3. Apply header protection: XOR the relevant bits of the first byte and
///    the PN bytes with the mask derived from the sample.
///
/// Returns the total protected packet length (including AEAD tag).
pub fn protect_packet(
    key: &DirectionalKey,
    packet: &mut [u8],
    pn_offset: usize,
    pn_length: usize,
    packet_number: u64,
) -> Result<usize, ProtectError> {
    let tag_len = key.packet_key.tag_len();
    let payload_start = pn_offset + pn_length;
    let total_len = packet.len();

    // Validate: need room for the PN, at least some payload, and the tag.
    if total_len < payload_start + tag_len {
        return Err(ProtectError::BufferTooShort);
    }

    // The AEAD AAD is everything up to and including the PN bytes.
    // payload slice: from payload_start to end (includes tag space).
    let header_end = payload_start;

    // rustls encrypt_in_place operates on a &mut [u8] slice directly and
    // returns the Tag separately. We split the packet buffer so the AEAD
    // header (AAD) and payload are disjoint borrows, then encrypt in-place
    // with zero copies.
    let (header_bytes, payload_and_tag) = packet.split_at_mut(header_end);

    // payload_and_tag currently holds plaintext + zeroed tag area.
    let plaintext_len = total_len - payload_start - tag_len;

    // Encrypt the plaintext portion in-place. The tag is returned separately.
    let tag = key
        .packet_key
        .encrypt_in_place(
            packet_number,
            header_bytes,
            &mut payload_and_tag[..plaintext_len],
        )
        .map_err(|_| ProtectError::EncryptFailed)?;
    // Write tag after ciphertext.
    let tag_bytes = tag.as_ref();
    payload_and_tag[plaintext_len..plaintext_len + tag_len].copy_from_slice(tag_bytes);

    // Header protection: sample starts at pn_offset + 4 (RFC 9001 §5.4.2).
    // This is within the ciphertext region.
    let sample_len = key.header_key.sample_len();
    let sample_offset = pn_offset + 4;
    if packet.len() < sample_offset + sample_len {
        return Err(ProtectError::BufferTooShort);
    }

    // To satisfy borrow checker we read the sample into a stack-allocated array.
    // QUIC header protection sample is always 16 bytes (AES-128/ChaCha20).
    let mut sample = [0u8; 16];
    sample[..sample_len].copy_from_slice(&packet[sample_offset..sample_offset + sample_len]);

    // Apply header protection in-place.
    // first byte and PN bytes are modified by the mask.
    let (first_byte_slice, rest) = packet.split_at_mut(1);
    let pn_slice = &mut rest[pn_offset - 1..pn_offset - 1 + pn_length];

    key.header_key
        .encrypt_in_place(&sample[..sample_len], &mut first_byte_slice[0], pn_slice)
        .map_err(|_| ProtectError::HeaderProtectFailed)?;

    Ok(total_len)
}

/// Remove header protection from a QUIC packet and decode the packet number.
///
/// Only removes header protection and decodes PN. The caller must then call
/// `decrypt_payload` for AEAD decryption.
///
/// Steps (RFC 9001 §5.4, reversed):
/// 1. Sample `sample_len()` bytes from encrypted payload at `pn_offset + 4`.
/// 2. Remove header protection: XOR first byte and PN bytes with mask.
/// 3. Decode packet number length from the unprotected first byte.
/// 4. Decode the packet number from PN bytes.
///
/// Returns `(packet_number, pn_length, payload_offset)`.
pub fn unprotect_header(
    key: &DirectionalKey,
    packet: &mut [u8],
    pn_offset: usize,
) -> Result<(u64, usize, usize), ProtectError> {
    let sample_len = key.header_key.sample_len();

    // Sample starts at pn_offset + 4 (RFC 9001 §5.4.2).
    let sample_offset = pn_offset + 4;
    if packet.len() < sample_offset + sample_len {
        return Err(ProtectError::BufferTooShort);
    }

    // Copy sample into stack-allocated array (before mutation).
    // QUIC header protection sample is always 16 bytes.
    let mut sample = [0u8; 16];
    sample[..sample_len].copy_from_slice(&packet[sample_offset..sample_offset + sample_len]);

    // We need to pass a mutable reference to first byte and to the PN bytes.
    // We don't know pn_length yet — it's encoded in the first byte after
    // removing the mask. Use a temporary approach:
    //   - We know pn_length is at most 4 bytes.
    //   - Pass a 4-byte mutable slice; only the actual pn_length bytes matter.
    if packet.len() < pn_offset + 4 {
        return Err(ProtectError::BufferTooShort);
    }

    {
        let (first_slice, rest) = packet.split_at_mut(1);
        let pn_field = &mut rest[pn_offset - 1..pn_offset - 1 + 4];
        key.header_key
            .decrypt_in_place(&sample[..sample_len], &mut first_slice[0], pn_field)
            .map_err(|_| ProtectError::HeaderProtectFailed)?;
    }

    // Decode pn_length from the unprotected first byte (RFC 9001 §17.2, §17.3).
    // Bits 0-1 of first byte (after masking) encode pn_length - 1.
    let first_byte = packet[0];
    let pn_length = ((first_byte & 0x03) as usize) + 1;

    if packet.len() < pn_offset + pn_length {
        return Err(ProtectError::BufferTooShort);
    }

    // Decode packet number (big-endian, pn_length bytes).
    let mut packet_number: u64 = 0;
    for i in 0..pn_length {
        packet_number = (packet_number << 8) | (packet[pn_offset + i] as u64);
    }

    let payload_offset = pn_offset + pn_length;
    Ok((packet_number, pn_length, payload_offset))
}

/// AEAD-decrypt the payload of a QUIC packet in-place.
///
/// `header` is everything before the payload (including header bytes and PN).
/// `payload` is the encrypted payload including the AEAD tag.
///
/// Returns the plaintext length (payload length minus tag length).
pub fn decrypt_payload(
    key: &DirectionalKey,
    packet_number: u64,
    header: &[u8],
    payload: &mut [u8],
) -> Result<usize, ProtectError> {
    let tag_len = key.packet_key.tag_len();
    if payload.len() < tag_len {
        return Err(ProtectError::BufferTooShort);
    }

    let plaintext = key
        .packet_key
        .decrypt_in_place(packet_number, header, payload)
        .map_err(|_| ProtectError::DecryptFailed)?;

    Ok(plaintext.len())
}
