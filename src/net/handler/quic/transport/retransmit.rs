use super::frame::StreamId;
use super::frame_log::{FrameLog, SentFrame};
use crate::net::handler::quic::connection_id::ConnectionId;
use smallvec::SmallVec;

/// Information that needs to be retransmitted after packet loss.
/// QUIC retransmits *information*, not packets (RFC 9000 §13.3).
#[derive(Debug)]
pub struct RetransmitQueue {
    /// CRYPTO data ranges to re-send: (space, offset, len)
    pub crypto: SmallVec<[(u8, u64, usize); 4]>,
    /// Stream data to re-send: (stream_id, offset, len, fin)
    pub streams: SmallVec<[(StreamId, u64, usize, bool); 8]>,
    /// Whether to re-send MAX_DATA with current value
    pub max_data: bool,
    /// Stream IDs needing MAX_STREAM_DATA re-send
    pub max_stream_data: SmallVec<[StreamId; 4]>,
    /// Whether to re-send MAX_STREAMS
    pub max_streams: bool,
    /// CID sequences to re-send via NEW_CONNECTION_ID
    pub new_connection_ids: SmallVec<[u64; 4]>,
    /// CID sequences to re-send via RETIRE_CONNECTION_ID
    pub retire_connection_ids: SmallVec<[u64; 4]>,
    /// Whether to re-send HANDSHAKE_DONE
    pub handshake_done: bool,
    /// Streams needing RESET_STREAM re-send
    pub reset_streams: SmallVec<[(StreamId, u64, u64); 4]>,
    /// Streams needing STOP_SENDING re-send
    pub stop_sending: SmallVec<[(StreamId, u64); 4]>,
    /// NEW_CONNECTION_ID frames to send: (sequence, retire_prior_to, cid, reset_token)
    pub pending_new_cids: SmallVec<[(u64, u64, ConnectionId, [u8; 16]); 4]>,
    /// Sequences of CIDs to retire via RETIRE_CONNECTION_ID (RFC 9000 §5.1.2)
    pub pending_retire_cids: SmallVec<[u64; 8]>,
}

impl Default for RetransmitQueue {
    fn default() -> Self {
        Self {
            crypto: SmallVec::new(),
            streams: SmallVec::new(),
            max_data: false,
            max_stream_data: SmallVec::new(),
            max_streams: false,
            new_connection_ids: SmallVec::new(),
            retire_connection_ids: SmallVec::new(),
            handshake_done: false,
            reset_streams: SmallVec::new(),
            stop_sending: SmallVec::new(),
            pending_new_cids: SmallVec::new(),
            pending_retire_cids: SmallVec::new(),
        }
    }
}

impl RetransmitQueue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.crypto.is_empty()
            && self.streams.is_empty()
            && !self.max_data
            && self.max_stream_data.is_empty()
            && !self.max_streams
            && self.new_connection_ids.is_empty()
            && self.retire_connection_ids.is_empty()
            && !self.handshake_done
            && self.reset_streams.is_empty()
            && self.stop_sending.is_empty()
            && self.pending_new_cids.is_empty()
            && self.pending_retire_cids.is_empty()
    }
}

/// Process lost packets and build a retransmission queue.
/// `lost_frame_ranges` are the (start, end) frame_range values from lost SentPackets.
pub fn build_retransmit_queue(
    frame_log: &FrameLog,
    lost_frame_ranges: &[(u32, u32)],
) -> RetransmitQueue {
    let mut queue = RetransmitQueue::new();

    for &(start, end) in lost_frame_ranges {
        for frame in frame_log.range(start, end) {
            match frame {
                SentFrame::Crypto { space, offset, len } => {
                    queue.crypto.push((*space, *offset, *len));
                }
                SentFrame::Stream {
                    id,
                    offset,
                    len,
                    fin,
                } => {
                    queue.streams.push((*id, *offset, *len, *fin));
                }
                SentFrame::MaxData(_) => {
                    queue.max_data = true; // re-send with current value, not old
                }
                SentFrame::MaxStreamData(id, _) => {
                    if !queue.max_stream_data.contains(id) {
                        queue.max_stream_data.push(*id);
                    }
                }
                SentFrame::MaxStreams { .. } => {
                    queue.max_streams = true;
                }
                SentFrame::NewConnectionId { sequence } => {
                    queue.new_connection_ids.push(*sequence);
                }
                SentFrame::RetireConnectionId { sequence } => {
                    queue.retire_connection_ids.push(*sequence);
                }
                SentFrame::HandshakeDone => {
                    queue.handshake_done = true;
                }
                SentFrame::ResetStream {
                    id,
                    error_code,
                    final_size,
                } => {
                    queue.reset_streams.push((*id, *error_code, *final_size));
                }
                SentFrame::StopSending { id, error_code } => {
                    queue.stop_sending.push((*id, *error_code));
                }
                SentFrame::Ack { .. } | SentFrame::Ping | SentFrame::Padding => {
                    // ACK, PING, PADDING are not retransmitted
                }
            }
        }
    }

    queue
}
