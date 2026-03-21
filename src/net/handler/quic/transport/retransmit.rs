use super::frame::StreamId;
use super::frame_log::{FrameLog, SentFrame};

/// Information that needs to be retransmitted after packet loss.
/// QUIC retransmits *information*, not packets (RFC 9000 §13.3).
#[derive(Debug, Default)]
pub struct RetransmitQueue {
    /// CRYPTO data ranges to re-send: (space, offset, len)
    pub crypto: Vec<(u8, u64, usize)>,
    /// Stream data to re-send: (stream_id, offset, len, fin)
    pub streams: Vec<(StreamId, u64, usize, bool)>,
    /// Whether to re-send MAX_DATA with current value
    pub max_data: bool,
    /// Stream IDs needing MAX_STREAM_DATA re-send
    pub max_stream_data: Vec<StreamId>,
    /// Whether to re-send MAX_STREAMS
    pub max_streams: bool,
    /// CID sequences to re-send via NEW_CONNECTION_ID
    pub new_connection_ids: Vec<u64>,
    /// CID sequences to re-send via RETIRE_CONNECTION_ID
    pub retire_connection_ids: Vec<u64>,
    /// Whether to re-send HANDSHAKE_DONE
    pub handshake_done: bool,
    /// Streams needing RESET_STREAM re-send
    pub reset_streams: Vec<(StreamId, u64, u64)>,
    /// Streams needing STOP_SENDING re-send
    pub stop_sending: Vec<(StreamId, u64)>,
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
