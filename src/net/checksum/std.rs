//! RFC 1071 implementation of the checksum algorithm.

/// Sum 16-bit words across a slice, carrying a pending odd byte in/out.
///
/// This is meant to be consumed by the [common::sum_words_carry] function.
///
/// [common::sum_words_carry]: crate::net::checksum::common::sum_words_carry
#[inline]
pub fn sum_words_carry(data: &[u8], mut sum: u64) -> (u64, Option<u8>) {
    let len = data.len();
    let mut i = 0;

    // Process 32 bytes per iteration using 4x u64 wide reads.
    // Each u64 is split into 4 u16 words via shifts — safe for unaligned data
    // because from_be_bytes copies rather than casting pointers.
    while i + 31 < len {
        let w0 = u64::from_be_bytes([
            data[i],
            data[i + 1],
            data[i + 2],
            data[i + 3],
            data[i + 4],
            data[i + 5],
            data[i + 6],
            data[i + 7],
        ]);
        let w1 = u64::from_be_bytes([
            data[i + 8],
            data[i + 9],
            data[i + 10],
            data[i + 11],
            data[i + 12],
            data[i + 13],
            data[i + 14],
            data[i + 15],
        ]);
        let w2 = u64::from_be_bytes([
            data[i + 16],
            data[i + 17],
            data[i + 18],
            data[i + 19],
            data[i + 20],
            data[i + 21],
            data[i + 22],
            data[i + 23],
        ]);
        let w3 = u64::from_be_bytes([
            data[i + 24],
            data[i + 25],
            data[i + 26],
            data[i + 27],
            data[i + 28],
            data[i + 29],
            data[i + 30],
            data[i + 31],
        ]);
        sum += (w0 >> 48) + ((w0 >> 32) & 0xFFFF) + ((w0 >> 16) & 0xFFFF) + (w0 & 0xFFFF);
        sum += (w1 >> 48) + ((w1 >> 32) & 0xFFFF) + ((w1 >> 16) & 0xFFFF) + (w1 & 0xFFFF);
        sum += (w2 >> 48) + ((w2 >> 32) & 0xFFFF) + ((w2 >> 16) & 0xFFFF) + (w2 & 0xFFFF);
        sum += (w3 >> 48) + ((w3 >> 32) & 0xFFFF) + ((w3 >> 16) & 0xFFFF) + (w3 & 0xFFFF);
        i += 32;
    }

    // Handle remaining 4 bytes at a time.
    while i + 3 < len {
        sum += ((data[i] as u64) << 8) | (data[i + 1] as u64);
        sum += ((data[i + 2] as u64) << 8) | (data[i + 3] as u64);
        i += 4;
    }

    if i + 1 < len {
        sum += ((data[i] as u64) << 8) | (data[i + 1] as u64);
        i += 2;
    }

    if i < len {
        return (sum, Some(data[i]));
    }

    (sum, None)
}
