//! QUIC packet number encode/decode (RFC 9000 §17.1, Appendix A).
//!
//! Packet numbers are truncated on the wire to save space. The receiver
//! reconstructs the full 62-bit value using the largest successfully
//! processed packet number as context.

/// Decode a truncated packet number to its full 62-bit value.
///
/// - `largest_pn`: the largest packet number successfully processed in this
///   packet number space.
/// - `truncated`: the truncated value read from the wire.
/// - `nbits`: the number of bits in the truncated representation (8, 16, 24, or 32).
///
/// This implements the algorithm from RFC 9000 Appendix A.
pub fn decode_pn(largest_pn: u64, truncated: u64, nbits: u32) -> u64 {
    let expected_pn = largest_pn.wrapping_add(1);
    let pn_win: u64 = 1u64 << nbits;
    let pn_hwin: u64 = pn_win / 2;
    let pn_mask: u64 = pn_win - 1;

    // Combine the high bits of expected with the received low bits.
    let candidate_pn = (expected_pn & !pn_mask) | truncated;

    // Adjust upward if the candidate is too far behind the expected value.
    // Guard against underflow: only apply if expected_pn >= pn_hwin.
    if expected_pn >= pn_hwin
        && candidate_pn <= expected_pn - pn_hwin
        && candidate_pn < (1u64 << 62).saturating_sub(pn_win)
    {
        return candidate_pn + pn_win;
    }

    // Adjust downward if the candidate is too far ahead of the expected value.
    if candidate_pn > expected_pn.saturating_add(pn_hwin) && candidate_pn >= pn_win {
        return candidate_pn - pn_win;
    }

    candidate_pn
}

/// Encode a full packet number to its minimal truncated wire form.
///
/// Returns `(truncated_value, num_bytes)` where `num_bytes` is 1, 2, 3, or 4.
///
/// The encoding uses enough bits to unambiguously represent at least twice the
/// distance from the largest acknowledged packet number, as required by
/// RFC 9000 §17.1.
///
/// - 1 byte  if `full_pn - largest_acked < 2^7`
/// - 2 bytes if `full_pn - largest_acked < 2^15`
/// - 3 bytes if `full_pn - largest_acked < 2^23`
/// - 4 bytes otherwise
pub fn encode_pn(full_pn: u64, largest_acked: u64) -> (u64, u8) {
    // Number of unacknowledged packets that the receiver must be able to
    // distinguish. We need at least twice the range.
    let range = full_pn.saturating_sub(largest_acked);

    if range < (1u64 << 7) {
        let truncated = full_pn & 0xff;
        (truncated, 1)
    } else if range < (1u64 << 15) {
        let truncated = full_pn & 0xffff;
        (truncated, 2)
    } else if range < (1u64 << 23) {
        let truncated = full_pn & 0xff_ffff;
        (truncated, 3)
    } else {
        let truncated = full_pn & 0xffff_ffff;
        (truncated, 4)
    }
}
