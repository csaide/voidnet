//! NEON-accelerated RFC 1071 internet checksum.
//!
//! On little-endian aarch64, network (big-endian) data loaded via `vld1q_u8`
//! and reinterpreted as u16 gives byte-swapped words. We use `vrev16q_u8` to
//! byte-reverse within each 16-bit element, producing proper big-endian u16
//! values that match the scalar path's intermediate representation exactly.
//! This is critical for `sum_words_carry` where partial sums are threaded
//! across fragments.

use std::arch::aarch64::*;

/// NEON-accelerated version of `sum_words_carry`.
///
/// Processes 32 bytes per iteration using 128-bit NEON vectors.
/// Falls back to scalar for the tail (< 32 bytes).
///
/// Produces the same intermediate `sum` values as the scalar path,
/// so partial sums can be safely mixed across fragments.
///
/// This is meant to be consumed by the [common::sum_words_carry] function.
///
/// # Safety
///
/// Requires aarch64 NEON support (guaranteed on all AArch64 CPUs).
///
/// [common::sum_words_carry]: crate::net::checksum::common::sum_words_carry
#[inline]
#[target_feature(enable = "neon")]
pub(crate) unsafe fn sum_words_carry(data: &[u8], mut sum: u64) -> (u64, Option<u8>) {
    let len = data.len();
    let mut i = 0;

    // SAFETY: all NEON intrinsics below require aarch64 NEON, which is
    // guaranteed on all AArch64 CPUs. Pointer arithmetic is bounded by
    // `len` checks in the loop condition.
    unsafe {
        // NEON accumulator: 2x u64 lanes.
        // We accumulate u32 values (widened from u16) so u64 lanes
        // prevent overflow even for jumbo frames.
        let mut acc = vdupq_n_u64(0);

        while i + 31 < len {
            // Load 32 bytes as two 128-bit u8 vectors.
            let v0 = vld1q_u8(data.as_ptr().add(i));
            let v1 = vld1q_u8(data.as_ptr().add(i + 16));

            // Byte-reverse within each 16-bit element:
            //   [B0, B1, B2, B3, ...] -> [B1, B0, B3, B2, ...]
            // On LE aarch64, reinterpreting [B1, B0] as u16 gives B0*256 + B1,
            // which is the big-endian u16 value -- matching scalar exactly.
            let rev0 = vrev16q_u8(v0);
            let rev1 = vrev16q_u8(v1);

            // Reinterpret as u16 (now proper big-endian values).
            let words0 = vreinterpretq_u16_u8(rev0);
            let words1 = vreinterpretq_u16_u8(rev1);

            // Widen u16 -> u32 via pairwise add.
            let sum32_0 = vpaddlq_u16(words0);
            let sum32_1 = vpaddlq_u16(words1);

            // Widen u32 -> u64 and accumulate.
            acc = vpadalq_u32(acc, sum32_0);
            acc = vpadalq_u32(acc, sum32_1);

            i += 32;
        }

        // Horizontal reduce: sum both u64 lanes into the scalar accumulator.
        sum += vgetq_lane_u64(acc, 0) + vgetq_lane_u64(acc, 1);
    }

    // Scalar tail: handle remaining bytes (< 32).
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
