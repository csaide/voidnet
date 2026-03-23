//! QUIC variable-length integer codec (RFC 9000 §16).
//!
//! The top 2 bits of the first byte indicate the total encoding length:
//! - `00` = 1 byte  (6-bit value,  max 63)
//! - `01` = 2 bytes (14-bit value, max 16383)
//! - `10` = 4 bytes (30-bit value, max 1073741823)
//! - `11` = 8 bytes (62-bit value, max 4611686018427387903)

/// Maximum value encodable as a QUIC variable-length integer (2^62 - 1).
pub const VARINT_MAX: u64 = (1 << 62) - 1;

/// Decode a QUIC variable-length integer from `buf`.
///
/// Returns `(value, bytes_consumed)` or `None` if the buffer is too short.
#[inline]
pub fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let prefix = (buf[0] >> 6) & 0x03;
    match prefix {
        0 => {
            // 1 byte: low 6 bits
            let val = (buf[0] & 0x3f) as u64;
            Some((val, 1))
        }
        1 => {
            // 2 bytes: low 6 bits of first + second byte
            if buf.len() < 2 {
                return None;
            }
            let val = (((buf[0] & 0x3f) as u64) << 8) | (buf[1] as u64);
            Some((val, 2))
        }
        2 => {
            // 4 bytes
            if buf.len() < 4 {
                return None;
            }
            let val = (((buf[0] & 0x3f) as u64) << 24)
                | ((buf[1] as u64) << 16)
                | ((buf[2] as u64) << 8)
                | (buf[3] as u64);
            Some((val, 4))
        }
        3 => {
            // 8 bytes
            if buf.len() < 8 {
                return None;
            }
            let val = (((buf[0] & 0x3f) as u64) << 56)
                | ((buf[1] as u64) << 48)
                | ((buf[2] as u64) << 40)
                | ((buf[3] as u64) << 32)
                | ((buf[4] as u64) << 24)
                | ((buf[5] as u64) << 16)
                | ((buf[6] as u64) << 8)
                | (buf[7] as u64);
            Some((val, 8))
        }
        _ => unreachable!(),
    }
}

/// Encode a QUIC variable-length integer into `buf`.
///
/// Returns the number of bytes written, or 0 if `val` exceeds `VARINT_MAX`.
///
/// # Panics
/// Panics if `buf` is too small to hold the encoded value.
#[inline]
pub fn encode_varint(val: u64, buf: &mut [u8]) -> usize {
    if val <= 63 {
        assert!(!buf.is_empty(), "buffer too small for 1-byte varint");
        buf[0] = val as u8;
        1
    } else if val <= 16383 {
        assert!(buf.len() >= 2, "buffer too small for 2-byte varint");
        let v = val | (0b01 << 14);
        buf[0] = (v >> 8) as u8;
        buf[1] = (v & 0xff) as u8;
        2
    } else if val <= 1_073_741_823 {
        assert!(buf.len() >= 4, "buffer too small for 4-byte varint");
        let v = val | (0b10 << 30);
        buf[0] = (v >> 24) as u8;
        buf[1] = (v >> 16) as u8;
        buf[2] = (v >> 8) as u8;
        buf[3] = (v & 0xff) as u8;
        4
    } else if val <= VARINT_MAX {
        assert!(buf.len() >= 8, "buffer too small for 8-byte varint");
        let v = val | (0b11_u64 << 62);
        buf[0] = (v >> 56) as u8;
        buf[1] = (v >> 48) as u8;
        buf[2] = (v >> 40) as u8;
        buf[3] = (v >> 32) as u8;
        buf[4] = (v >> 24) as u8;
        buf[5] = (v >> 16) as u8;
        buf[6] = (v >> 8) as u8;
        buf[7] = (v & 0xff) as u8;
        8
    } else {
        // Value exceeds 62-bit QUIC varint maximum — return 0 (no bytes written)
        0
    }
}

/// Returns the number of bytes required to encode `val` as a QUIC varint,
/// without writing anything. Returns 8 (max encoding size) for out-of-range values.
#[inline]
pub fn varint_len(val: u64) -> usize {
    if val <= 63 {
        1
    } else if val <= 16383 {
        2
    } else if val <= 1_073_741_823 {
        4
    } else {
        // Return 8 (max encoding size) even for out-of-range values,
        // so callers can size buffers without panicking.
        8
    }
}
