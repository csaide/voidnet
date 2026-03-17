use crate::net::wire::ip::{Ipv4Address, Ipv6Address};

/// Sum all 16-bit words in `data`, handling trailing bytes.
#[inline]
pub fn sum_words(data: &[u8]) -> u64 {
    let (mut sum, pending) = sum_words_carry(data, 0, None);
    if let Some(hi) = pending {
        sum += (hi as u64) << 8;
    }
    sum
}

/// Sum 16-bit words across a slice, carrying a pending odd byte in/out.
#[inline]
pub fn sum_words_carry(data: &[u8], mut sum: u64, pending: Option<u8>) -> (u64, Option<u8>) {
    let len = data.len();
    let mut i = 0;

    if let Some(hi) = pending {
        if len > 0 {
            sum += ((hi as u64) << 8) | (data[0] as u64);
            i = 1;
        } else {
            return (sum, Some(hi));
        }
    }

    // NEON fast path for large data on aarch64.
    #[cfg(target_arch = "aarch64")]
    {
        if len - i >= 32 {
            // Safety: aarch64 always has NEON.
            return unsafe { super::neon::sum_words_carry(&data[i..], sum) };
        }
    }

    // TODO: Implement a SIMD-based implementation for x86_64.

    // Fallback path just incase the SIMD implementation is not available, or the data is so small it would cost more to do SIMD.
    super::std::sum_words_carry(&data[i..], sum)
}

/// Fold 64-bit running sum to 16 bits, then one's-complement.
#[inline]
pub fn fold_checksum(mut sum: u64) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Fold and check for 0xFFFF (verification path).
#[inline]
pub fn fold_and_verify(mut sum: u64, actual: u16) -> bool {
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16) == actual
}

/// Build the IPv4 pseudo-header sum: src IP + dst IP + protocol + length.
#[inline]
pub fn pseudo_header_sum_v4(
    src_addr: &Ipv4Address,
    dst_addr: &Ipv4Address,
    protocol: u8,
    len: u16,
) -> u64 {
    sum_words(&src_addr.octets) + sum_words(&dst_addr.octets) + protocol as u64 + len as u64
}

/// Build the IPv6 pseudo-header sum: src IP + dst IP + length (u32) + next header.
#[inline]
pub fn pseudo_header_sum_v6(
    src_addr: &Ipv6Address,
    dst_addr: &Ipv6Address,
    protocol: u8,
    len: u32,
) -> u64 {
    sum_words(&src_addr.octets)
        + sum_words(&dst_addr.octets)
        + (len >> 16) as u64
        + (len & 0xFFFF) as u64
        + protocol as u64
}

/// Convert a folded checksum to wire bytes, mapping zero to 0xFFFF per RFC 768.
#[inline]
pub fn checksum_to_bytes(checksum: u16) -> [u8; 2] {
    if checksum == 0 {
        [0xFF, 0xFF]
    } else {
        checksum.to_be_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sum_words_carry_even_boundary() {
        let src = Ipv4Address::new([192, 168, 1, 1]);
        let dst = Ipv4Address::new([10, 0, 0, 1]);
        let mut segment = [
            0x12, 0x34, 0x00, 0x35, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
        ];

        // Compute checksum using the full compute path
        let sum = pseudo_header_sum_v4(&src, &dst, 17, segment.len() as u16) + sum_words(&segment);
        let cksum = checksum_to_bytes(fold_checksum(sum));
        segment[6] = cksum[0];
        segment[7] = cksum[1];

        // Sum across two slices split at an even boundary
        let (a, b) = segment.split_at(8);
        let mut sum2 = pseudo_header_sum_v4(&src, &dst, 17, segment.len() as u16);
        let pending;
        (sum2, pending) = sum_words_carry(a, sum2, None);
        (sum2, _) = sum_words_carry(b, sum2, pending);
        assert!(fold_and_verify(sum2, 0x0000));
    }

    #[test]
    fn sum_words_carry_odd_boundary() {
        let src = Ipv4Address::new([192, 168, 1, 1]);
        let dst = Ipv4Address::new([10, 0, 0, 1]);
        let mut segment = [
            0x12, 0x34, 0x00, 0x35, 0x00, 0x0D, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        ];

        let sum = pseudo_header_sum_v4(&src, &dst, 17, segment.len() as u16) + sum_words(&segment);
        let cksum = checksum_to_bytes(fold_checksum(sum));
        segment[6] = cksum[0];
        segment[7] = cksum[1];

        // Split at an odd boundary (9 bytes + 4 bytes)
        let (a, b) = segment.split_at(9);
        let mut sum2 = pseudo_header_sum_v4(&src, &dst, 17, segment.len() as u16);
        let pending;
        (sum2, pending) = sum_words_carry(a, sum2, None);
        let trailing;
        (sum2, trailing) = sum_words_carry(b, sum2, pending);
        if let Some(hi) = trailing {
            sum2 += (hi as u64) << 8;
        }
        assert!(fold_and_verify(sum2, 0x0000));
    }

    #[test]
    fn sum_words_carry_empty_slice() {
        let (sum, pending) = sum_words_carry(&[], 42, Some(0xAB));
        assert_eq!(sum, 42);
        assert_eq!(pending, Some(0xAB));
    }

    #[test]
    fn fold_checksum_basic() {
        // Known value: all zeros should fold to 0xFFFF
        assert_eq!(fold_checksum(0), 0xFFFF);
    }

    #[test]
    fn pseudo_header_v4_matches_legacy() {
        let src = Ipv4Address::new([192, 168, 1, 1]);
        let dst = Ipv4Address::new([10, 0, 0, 1]);
        // Legacy UDP pseudo-header used protocol=17 hardcoded
        let legacy = sum_words(&src.octets) + sum_words(&dst.octets) + 17u64 + 12u64;
        let new = pseudo_header_sum_v4(&src, &dst, 17, 12);
        assert_eq!(legacy, new);
    }

    #[test]
    fn pseudo_header_v6_matches_legacy() {
        let src = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        // Legacy UDP pseudo-header used protocol=17 hardcoded
        let legacy = sum_words(&src.octets)
            + sum_words(&dst.octets)
            + (12u32 >> 16) as u64
            + (12u32 & 0xFFFF) as u64
            + 17u64;
        let new = pseudo_header_sum_v6(&src, &dst, 17, 12);
        assert_eq!(legacy, new);
    }

    #[test]
    fn checksum_to_bytes_zero_maps_to_ffff() {
        assert_eq!(checksum_to_bytes(0), [0xFF, 0xFF]);
    }

    #[test]
    fn checksum_to_bytes_nonzero() {
        assert_eq!(checksum_to_bytes(0x1234), [0x12, 0x34]);
    }

    #[test]
    fn sum_words_large_data_exercises_wide_loop() {
        let data: Vec<u8> = (0u8..64).collect();
        let sum = sum_words(&data);
        let mut expected = 0u64;
        for chunk in data.chunks(2) {
            expected += ((chunk[0] as u64) << 8) | (chunk[1] as u64);
        }
        assert_eq!(sum, expected);
    }

    #[test]
    fn sum_words_carry_pending_consumed_by_next_byte() {
        let (sum, pending) = sum_words_carry(&[0xCD], 0, Some(0xAB));
        assert_eq!(sum, 0xABCD);
        assert_eq!(pending, None);
    }

    #[test]
    fn sum_words_carry_single_byte_becomes_pending() {
        let (sum, pending) = sum_words_carry(&[0x42], 100, None);
        assert_eq!(sum, 100);
        assert_eq!(pending, Some(0x42));
    }

    #[test]
    fn fold_checksum_near_u16_max() {
        let result = fold_checksum(0xFFFF);
        assert_eq!(result, 0x0000);
    }

    #[test]
    fn fold_checksum_with_carry() {
        let result = fold_checksum(0x1FFFE);
        assert_eq!(result, 0x0000);
    }

    #[test]
    fn fold_and_verify_correct_checksum() {
        let data = [0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00, 0x40, 0x06];
        let sum = sum_words(&data);
        let cksum = fold_checksum(sum);
        let full_sum = sum + cksum as u64;
        assert!(fold_and_verify(full_sum, 0x0000));
    }

    #[test]
    fn sum_words_carry_three_slices() {
        let full = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let expected = sum_words(&full);
        let (s1, p1) = sum_words_carry(&full[0..3], 0, None);
        let (s2, p2) = sum_words_carry(&full[3..5], s1, p1);
        let (mut s3, p3) = sum_words_carry(&full[5..7], s2, p2);
        if let Some(hi) = p3 {
            s3 += (hi as u64) << 8;
        }
        assert_eq!(s3, expected);
    }
}
