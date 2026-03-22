use super::frame::StreamId;
use super::frame_log::{FrameLog, SentFrame};
use super::frame_writer;
use super::packet_number::encode_pn;
use super::varint::{encode_varint, varint_len};

/// Builds a QUIC packet in a byte buffer.
pub struct PacketBuilder<'a> {
    buf: &'a mut [u8],
    /// Offset where packet number starts (needed for encryption)
    pn_offset: usize,
    pn_length: usize,
    /// Current write position (after PN)
    offset: usize,
    /// Packet number for this packet
    packet_number: u64,
    /// Whether this is a long header packet
    is_long_header: bool,
    /// Offset of the Length field in long-header packets (2-byte varint)
    length_offset: usize,
    /// Frame log start index for tracking sent frames
    frame_start: u32,
}

impl<'a> PacketBuilder<'a> {
    /// Begin building a long header packet (Initial, Handshake, 0-RTT).
    /// Writes the header up to and including the packet number.
    /// Returns None if buffer is too small.
    pub fn begin_long(
        buf: &'a mut [u8],
        packet_type_bits: u8, // 0x00=Initial, 0x01=0-RTT, 0x02=Handshake, 0x03=Retry
        version: u32,
        dcid: &[u8],
        scid: &[u8],
        packet_number: u64,
        largest_acked: u64,
        frame_log: &FrameLog,
    ) -> Option<Self> {
        let (truncated_pn, pn_len) = encode_pn(packet_number, largest_acked);

        // Calculate header size: 1 + 4(version) + 1(dcid_len) + dcid + 1(scid_len) + scid
        let header_len = 1 + 4 + 1 + dcid.len() + 1 + scid.len();
        // For Initial: + token_length(varint) + length(varint) + pn
        // Simplified: we'll add token and length fields as part of frame writing

        if buf.len() < header_len + 2 + pn_len as usize + 16 {
            return None; // too small
        }

        let mut offset = 0;

        // First byte: 1(long) 1(fixed) TT(type) PP(pn_len-1)
        buf[offset] = 0xC0 | (packet_type_bits << 4) | ((pn_len - 1) as u8);
        offset += 1;

        // Version
        buf[offset..offset + 4].copy_from_slice(&version.to_be_bytes());
        offset += 4;

        // DCID
        buf[offset] = dcid.len() as u8;
        offset += 1;
        buf[offset..offset + dcid.len()].copy_from_slice(dcid);
        offset += dcid.len();

        // SCID
        buf[offset] = scid.len() as u8;
        offset += 1;
        buf[offset..offset + scid.len()].copy_from_slice(scid);
        offset += scid.len();

        // For Initial packets: token length = 0 (no token for now)
        if packet_type_bits == 0x00 {
            buf[offset] = 0; // token length varint = 0
            offset += 1;
        }

        // Length field placeholder (2-byte varint, filled in finish())
        let length_offset = offset;
        offset += 2; // reserve 2 bytes for length

        // Packet number
        let pn_offset = offset;
        for i in 0..pn_len as usize {
            buf[pn_offset + i] = (truncated_pn >> (8 * (pn_len as usize - 1 - i))) as u8;
        }
        offset += pn_len as usize;

        Some(PacketBuilder {
            buf,
            pn_offset,
            pn_length: pn_len as usize,
            offset,
            packet_number,
            is_long_header: true,
            length_offset,
            frame_start: frame_log.head(),
        })
    }

    /// Begin building a short header (1-RTT) packet.
    pub fn begin_short(
        buf: &'a mut [u8],
        dcid: &[u8],
        packet_number: u64,
        largest_acked: u64,
        key_phase: bool,
        frame_log: &FrameLog,
    ) -> Option<Self> {
        let (truncated_pn, pn_len) = encode_pn(packet_number, largest_acked);

        let header_len = 1 + dcid.len() + pn_len as usize;
        if buf.len() < header_len + 16 {
            return None;
        }

        let mut offset = 0;

        // First byte: 0(short) 1(fixed) S(spin=0) 00(reserved) K(key_phase) PP(pn_len-1)
        buf[offset] = 0x40 | if key_phase { 0x04 } else { 0 } | ((pn_len - 1) as u8);
        offset += 1;

        buf[offset..offset + dcid.len()].copy_from_slice(dcid);
        offset += dcid.len();

        let pn_offset = offset;
        for i in 0..pn_len as usize {
            buf[pn_offset + i] = (truncated_pn >> (8 * (pn_len as usize - 1 - i))) as u8;
        }
        offset += pn_len as usize;

        Some(PacketBuilder {
            buf,
            pn_offset,
            pn_length: pn_len as usize,
            offset,
            packet_number,
            is_long_header: false,
            length_offset: 0, // unused for short headers
            frame_start: frame_log.head(),
        })
    }

    /// Remaining space for payload (before AEAD tag).
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.offset + 16) // 16 for AEAD tag
    }

    /// Write a CRYPTO frame. Returns bytes of crypto data written.
    pub fn write_crypto(
        &mut self,
        offset_val: u64,
        data: &[u8],
        space: u8,
        frame_log: &mut FrameLog,
    ) -> usize {
        // Overhead: 1 (type) + varint(offset) + varint(length)
        // We need to estimate overhead using the max possible data length first
        let overhead = 1 + varint_len(offset_val) + varint_len(data.len() as u64);
        let available = self.remaining().saturating_sub(overhead);
        let max_data = available.min(data.len());
        if max_data == 0 {
            return 0;
        }
        let data = &data[..max_data];
        let written = frame_writer::write_crypto(&mut self.buf[self.offset..], offset_val, data);
        if written > 0 {
            self.offset += written;
            frame_log.push(SentFrame::Crypto {
                space,
                offset: offset_val,
                len: data.len(),
            });
        }
        data.len()
    }

    /// Write a STREAM frame. Returns bytes of stream data written.
    pub fn write_stream(
        &mut self,
        id: StreamId,
        offset_val: u64,
        data: &[u8],
        fin: bool,
        frame_log: &mut FrameLog,
    ) -> usize {
        // Overhead: 1 (type) + varint(stream_id) + varint(offset) if >0 + varint(length)
        let offset_overhead = if offset_val > 0 {
            varint_len(offset_val)
        } else {
            0
        };
        let overhead = 1 + varint_len(id.0) + offset_overhead + varint_len(data.len() as u64);
        let available = self.remaining().saturating_sub(overhead);
        let max_data = available.min(data.len());
        if max_data == 0 && !fin {
            return 0;
        }
        let data = &data[..max_data];
        let written =
            frame_writer::write_stream(&mut self.buf[self.offset..], id, offset_val, data, fin);
        if written > 0 {
            self.offset += written;
            frame_log.push(SentFrame::Stream {
                id,
                offset: offset_val,
                len: data.len(),
                fin,
            });
        }
        data.len()
    }

    /// Write PADDING to reach minimum size.
    pub fn pad_to(&mut self, min_size: usize) {
        let target = min_size.min(self.buf.len().saturating_sub(16));
        if self.offset < target {
            self.buf[self.offset..target].fill(0);
            self.offset = target;
        }
    }

    /// Write an ACK frame using the AckState's pre-encoded data.
    pub fn write_ack(
        &mut self,
        largest_acked: u64,
        ack_delay: u64,
        first_ack_range: u64,
        ack_range_count: u64,
        encoded_ranges: &[u8],
        frame_log: &mut FrameLog,
        space: u8,
    ) -> bool {
        // Type byte (0x02 for ACK without ECN)
        // + largest_acked varint + ack_delay varint + ack_range_count varint
        // + first_ack_range varint + encoded_ranges bytes
        let overhead = 1
            + varint_len(largest_acked)
            + varint_len(ack_delay)
            + varint_len(ack_range_count)
            + varint_len(first_ack_range)
            + encoded_ranges.len();
        if self.remaining() < overhead {
            return false;
        }

        // Write type
        self.buf[self.offset] = 0x02;
        self.offset += 1;
        // Write fields using encode_varint
        self.offset += encode_varint(largest_acked, &mut self.buf[self.offset..]);
        self.offset += encode_varint(ack_delay, &mut self.buf[self.offset..]);
        self.offset += encode_varint(ack_range_count, &mut self.buf[self.offset..]);
        self.offset += encode_varint(first_ack_range, &mut self.buf[self.offset..]);
        // Write pre-encoded ranges
        if !encoded_ranges.is_empty() {
            self.buf[self.offset..self.offset + encoded_ranges.len()]
                .copy_from_slice(encoded_ranges);
            self.offset += encoded_ranges.len();
        }

        frame_log.push(SentFrame::Ack { space });
        true
    }

    /// Write a MAX_DATA frame (0x10). Returns true if written.
    pub fn write_max_data(&mut self, max: u64, frame_log: &mut FrameLog) -> bool {
        let needed = 1 + varint_len(max);
        if self.remaining() < needed {
            return false;
        }
        let written = frame_writer::write_max_data(&mut self.buf[self.offset..], max);
        self.offset += written;
        frame_log.push(SentFrame::MaxData(max));
        true
    }

    /// Write a HANDSHAKE_DONE frame (0x1e). Returns true if written.
    pub fn write_handshake_done(&mut self, frame_log: &mut FrameLog) -> bool {
        if self.remaining() < 1 {
            return false;
        }
        self.buf[self.offset] = 0x1e;
        self.offset += 1;
        frame_log.push(SentFrame::HandshakeDone);
        true
    }

    /// Write a PATH_RESPONSE frame (0x1b + 8 bytes data). Returns true if written.
    pub fn write_path_response(&mut self, data: [u8; 8]) -> bool {
        if self.remaining() < 9 {
            return false;
        }
        self.buf[self.offset] = 0x1b;
        self.offset += 1;
        self.buf[self.offset..self.offset + 8].copy_from_slice(&data);
        self.offset += 8;
        true
    }

    /// Write a CONNECTION_CLOSE frame (0x1c). Returns true if written.
    pub fn write_connection_close(&mut self, error_code: u64, frame_log: &mut FrameLog) -> bool {
        let needed = 1 + 8 + 1 + 1; // generous estimate for type + error_code + frame_type(0) + reason_len(0)
        if self.remaining() < needed {
            return false;
        }
        let written =
            frame_writer::write_connection_close(&mut self.buf[self.offset..], error_code, 0, &[]);
        self.offset += written;
        true
    }

    /// Write a PING frame.
    pub fn write_ping(&mut self, frame_log: &mut FrameLog) {
        if self.remaining() > 0 {
            self.buf[self.offset] = 0x01;
            self.offset += 1;
            frame_log.push(SentFrame::Ping);
        }
    }

    /// Get the packet number.
    pub fn packet_number(&self) -> u64 {
        self.packet_number
    }

    /// Get pn_offset (needed for encryption).
    pub fn pn_offset(&self) -> usize {
        self.pn_offset
    }

    /// Get pn_length.
    pub fn pn_length(&self) -> usize {
        self.pn_length
    }

    /// Get frame range in the FrameLog.
    pub fn frame_range(&self, frame_log: &FrameLog) -> (u32, u32) {
        (self.frame_start, frame_log.head())
    }

    /// Total bytes written so far (header + payload, before AEAD tag).
    pub fn written(&self) -> usize {
        self.offset
    }

    /// Finalize: returns the total packet length including space for AEAD tag.
    /// Caller must then call protect_packet() to encrypt.
    pub fn finish(self) -> usize {
        // Write the Length field for long-header packets
        if self.is_long_header {
            // Length covers: PN + payload + AEAD tag (16 bytes)
            let payload_len = self.offset - self.pn_offset + 16;
            let len_varint = 0x4000 | (payload_len as u16); // 2-byte varint encoding
            self.buf[self.length_offset] = (len_varint >> 8) as u8;
            self.buf[self.length_offset + 1] = (len_varint & 0xFF) as u8;
        }
        self.offset + 16 // +16 for AEAD tag
    }
}
