//! Packet parsing utilities: CRYPTO frame reassembly, duplicate PN detection,
//! and Initial packet field extraction.

use crate::net::handler::quic::transport::varint::decode_varint;

// ─── CryptoRecvBuffer ───

/// Out-of-order CRYPTO fragment with inline data storage.
struct OooFragment {
    offset: u64,
    len: u16,
    data: [u8; 512],
}

impl OooFragment {
    const fn empty() -> Self {
        Self {
            offset: 0,
            len: 0,
            data: [0u8; 512],
        }
    }
}

/// Fixed-size reassembly buffer for CRYPTO frames (RFC 9000 §7.5).
/// In-order data goes into the main buffer. Out-of-order data is stored
/// in separate inline fragment buffers to survive drain() operations.
/// Min 4096 bytes per RFC 9000 §7.5.
pub struct CryptoRecvBuffer {
    data: [u8; 8192],
    /// Contiguous frontier — all bytes [0, received) are available.
    received: u64,
    /// Contiguous bytes available in data[0..len].
    len: usize,
    /// Out-of-order fragments with their own data storage.
    ooo: [OooFragment; 4],
    ooo_count: u8,
}

/// Errors from [`CryptoRecvBuffer::write`].
#[derive(Debug)]
pub enum CryptoBufferError {
    /// The buffer is full and cannot accept more data.
    BufferFull,
}

impl CryptoRecvBuffer {
    /// Create a new zeroed buffer.
    pub fn new() -> Self {
        Self {
            data: [0u8; 8192],
            received: 0,
            len: 0,
            ooo: [
                OooFragment::empty(),
                OooFragment::empty(),
                OooFragment::empty(),
                OooFragment::empty(),
            ],
            ooo_count: 0,
        }
    }

    /// Write CRYPTO frame data at the given offset. Returns bytes consumed.
    pub fn write(&mut self, offset: u64, data: &[u8]) -> Result<usize, CryptoBufferError> {
        if data.is_empty() {
            return Ok(0);
        }

        if offset < self.received {
            // Duplicate or partial overlap — trim the already-received prefix
            let overlap = (self.received - offset) as usize;
            if overlap >= data.len() {
                return Ok(0); // fully duplicate
            }
            return self.write(self.received, &data[overlap..]);
        }

        if offset == self.received {
            // In-order: append to main buffer
            let space = 8192 - self.len;
            let to_write = data.len().min(space);
            if to_write == 0 {
                return Err(CryptoBufferError::BufferFull);
            }
            self.data[self.len..self.len + to_write].copy_from_slice(&data[..to_write]);
            self.len += to_write;
            self.received += to_write as u64;
            // Check if any OOO fragments are now contiguous
            self.flush_ooo();
            Ok(to_write)
        } else {
            // Out-of-order: store in a fragment buffer
            let to_store = data.len().min(512);
            if to_store == 0 {
                return Ok(0);
            }
            if !self.insert_ooo(offset, &data[..to_store]) {
                // All fragment slots full — drop (DoS prevention)
                return Ok(0);
            }
            Ok(to_store)
        }
    }

    /// Store an OOO fragment. Returns false if no slot available.
    fn insert_ooo(&mut self, offset: u64, data: &[u8]) -> bool {
        let end = offset + data.len() as u64;
        // Try to merge with existing fragment
        for i in 0..self.ooo_count as usize {
            let f = &self.ooo[i];
            let f_end = f.offset + f.len as u64;
            // Check adjacency: new data extends existing fragment
            if offset == f_end && (f.len as usize + data.len()) <= 512 {
                let start = self.ooo[i].len as usize;
                let new_len = start + data.len();
                self.ooo[i].data[start..new_len].copy_from_slice(data);
                self.ooo[i].len = new_len as u16;
                return true;
            }
            // Fully duplicate
            if offset >= self.ooo[i].offset && end <= f_end {
                return true;
            }
        }
        // New fragment
        if (self.ooo_count as usize) < 4 {
            let idx = self.ooo_count as usize;
            self.ooo[idx].offset = offset;
            self.ooo[idx].len = data.len() as u16;
            self.ooo[idx].data[..data.len()].copy_from_slice(data);
            self.ooo_count += 1;
            true
        } else {
            false
        }
    }

    /// Copy contiguous OOO fragments into the main buffer.
    fn flush_ooo(&mut self) {
        loop {
            let mut flushed = false;
            for i in 0..self.ooo_count as usize {
                let f_offset = self.ooo[i].offset;
                let f_len = self.ooo[i].len as usize;
                let f_end = f_offset + f_len as u64;

                if f_end <= self.received {
                    // Fully consumed — remove
                    self.remove_ooo(i);
                    flushed = true;
                    break;
                }

                if f_offset <= self.received && f_end > self.received {
                    // Partially or fully contiguous — copy new bytes to main buffer
                    let skip = (self.received - f_offset) as usize;
                    let new_bytes = f_len - skip;
                    let space = 8192 - self.len;
                    let to_copy = new_bytes.min(space);
                    if to_copy > 0 {
                        self.data[self.len..self.len + to_copy]
                            .copy_from_slice(&self.ooo[i].data[skip..skip + to_copy]);
                        self.len += to_copy;
                        self.received += to_copy as u64;
                    }
                    self.remove_ooo(i);
                    flushed = true;
                    break; // restart scan
                }
            }
            if !flushed {
                break;
            }
        }
    }

    /// Swap-remove OOO fragment at index.
    fn remove_ooo(&mut self, idx: usize) {
        let last = self.ooo_count as usize - 1;
        if idx != last {
            // Move last entry's data
            let (left, right) = if idx < last {
                let (a, b) = self.ooo.split_at_mut(last);
                (&mut a[idx], &b[0])
            } else {
                unreachable!()
            };
            left.offset = right.offset;
            left.len = right.len;
            left.data[..right.len as usize].copy_from_slice(&right.data[..right.len as usize]);
        }
        self.ooo[last] = OooFragment::empty();
        self.ooo_count -= 1;
    }

    /// Read all available contiguous data.
    pub fn read_all(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Drain `count` consumed bytes (after feeding to rustls).
    pub fn drain(&mut self, count: usize) {
        if count >= self.len {
            self.len = 0;
        } else {
            self.data.copy_within(count..self.len, 0);
            self.len -= count;
        }
    }

    /// The contiguous frontier — next expected byte offset.
    pub fn received(&self) -> u64 {
        self.received
    }

    /// Whether the buffer has no readable data.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether the buffer has any unconsumed data (including out-of-order fragments).
    /// Used to check RFC 9001 §4.1.3 requirement that lower levels have no
    /// unconsumed data when higher-level keys are installed.
    pub fn has_unconsumed_data(&self) -> bool {
        self.len > 0 || self.ooo_count > 0
    }
}

// ─── PnBitset ───

/// Tracks seen packet numbers for duplicate detection.
/// Uses a 1024-bit sliding window around the largest seen PN.
pub struct PnBitset {
    bits: [u64; 16], // 1024 bits
    base: u64,       // lowest PN in window (PNs below are considered duplicates)
    largest: u64,    // largest PN seen
    initialized: bool,
}

impl PnBitset {
    /// Create a new, empty bitset.
    pub fn new() -> Self {
        Self {
            bits: [0; 16],
            base: 0,
            largest: 0,
            initialized: false,
        }
    }

    /// Check if a PN is a duplicate. Returns `true` if already seen or below window.
    pub fn is_duplicate(&self, pn: u64) -> bool {
        if !self.initialized {
            return false;
        }
        if pn < self.base {
            return true; // below window = treat as duplicate
        }
        let offset = (pn - self.base) as usize;
        if offset >= 1024 {
            return false; // above window = new
        }
        let word = offset / 64;
        let bit = offset % 64;
        self.bits[word] & (1u64 << bit) != 0
    }

    /// Mark a PN as seen. Advances the window if needed.
    pub fn mark(&mut self, pn: u64) {
        if !self.initialized {
            self.base = pn;
            self.largest = pn;
            self.bits[0] = 1;
            self.initialized = true;
            return;
        }

        if pn < self.base {
            return; // below window, already considered seen
        }

        let offset = (pn - self.base) as usize;
        if offset >= 1024 {
            // Need to advance window
            let advance = offset - 1023;
            self.advance_window(advance);
            let new_offset = (pn - self.base) as usize;
            let word = new_offset / 64;
            let bit = new_offset % 64;
            self.bits[word] |= 1u64 << bit;
        } else {
            let word = offset / 64;
            let bit = offset % 64;
            self.bits[word] |= 1u64 << bit;
        }

        if pn > self.largest {
            self.largest = pn;
        }
    }

    fn advance_window(&mut self, count: usize) {
        if count >= 1024 {
            self.bits = [0; 16];
            self.base += count as u64;
            return;
        }
        let word_shift = count / 64;
        let bit_shift = count % 64;
        if word_shift > 0 {
            self.bits.rotate_left(word_shift);
            for i in (16 - word_shift)..16 {
                self.bits[i] = 0;
            }
        }
        if bit_shift > 0 {
            let mut carry = 0u64;
            for word in self.bits.iter_mut() {
                let new_carry = *word >> (64 - bit_shift);
                *word = (*word << bit_shift) | carry;
                carry = new_carry;
            }
        }
        self.base += count as u64;
    }

    /// The largest PN seen so far.
    pub fn largest(&self) -> u64 {
        self.largest
    }
}

// ─── Initial packet field parsing ───

/// Parse the Initial-packet-specific fields after SCID.
///
/// `buf` starts at the payload offset (after SCID in the long header).
/// Returns `(token_slice, payload_length, pn_offset)` or `None` if truncated.
///
/// - `token_slice`: the token bytes (may be empty).
/// - `payload_length`: the Length field value (covers PN + encrypted payload).
/// - `pn_offset`: byte offset within `buf` where the packet number starts.
pub fn parse_initial_fields(buf: &[u8]) -> Option<(&[u8], usize, usize)> {
    let mut pos = 0;

    // Token Length (varint)
    let (token_len, consumed) = decode_varint(&buf[pos..])?;
    pos += consumed;

    // Token
    let token_len = token_len as usize;
    if buf.len() < pos + token_len {
        return None;
    }
    let token = &buf[pos..pos + token_len];
    pos += token_len;

    // Length (varint) — length of PN + encrypted payload
    let (payload_length, consumed) = decode_varint(&buf[pos..])?;
    pos += consumed;

    // pn_offset is current position (where PN bytes start)
    Some((token, payload_length as usize, pos))
}

/// Map [`PacketType`] to packet number space index (0 = Initial, 1 = Handshake, 2 = 1-RTT).
///
/// Returns `None` for packet types that have no packet number space (Retry, Unknown).
#[inline]
pub fn packet_space(packet_type: crate::net::wire::quic::PacketType) -> Option<usize> {
    use crate::net::wire::quic::PacketType;
    match packet_type {
        PacketType::Initial => Some(0),
        PacketType::Handshake => Some(1),
        PacketType::ZeroRtt | PacketType::OneRtt => Some(2),
        PacketType::Retry | PacketType::Unknown => None,
    }
}
