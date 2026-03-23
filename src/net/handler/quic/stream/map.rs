use super::recv::RecvHalf;
use super::send::SendHalf;
use super::state::StreamState;
use crate::net::handler::quic::transport::frame::StreamId;

/// Absolute upper bound on stream indices per type to prevent memory exhaustion.
/// Even if transport params allow more, we refuse to grow Vecs beyond this.
const MAX_STREAMS_ABSOLUTE: u64 = 1024;

/// Error returned when a stream cannot be created due to concurrency limits.
#[derive(Debug)]
pub struct StreamLimitError;

/// Entry in the stream map
pub struct StreamEntry {
    pub state: StreamState,
    pub send: Option<SendHalf>,
    pub recv: Option<RecvHalf>,
}

/// Direct-indexed stream map. No hashing — StreamId >> 2 is the Vec index.
pub struct StreamMap {
    client_bidi: Vec<Option<StreamEntry>>,
    server_bidi: Vec<Option<StreamEntry>>,
    client_uni: Vec<Option<StreamEntry>>,
    server_uni: Vec<Option<StreamEntry>>,

    /// Whether this endpoint is a client
    pub is_client: bool,

    /// Number of streams with data or a pending FIN to send. Maintained as a
    /// dirty-stream counter so `has_pending_send` is O(1) instead of O(n).
    pub pending_send_count: u32,

    // Concurrency limits (from transport params)
    pub local_max_bidi: u64,
    pub local_max_uni: u64,
    pub peer_max_bidi: u64,
    pub peer_max_uni: u64,

    // Track opened counts
    pub local_opened_bidi: u64,
    pub local_opened_uni: u64,
    pub peer_opened_bidi: u64,
    pub peer_opened_uni: u64,

    // Committed MAX_STREAMS values (last advertised to peer)
    pub committed_max_bidi: u64,
    pub committed_max_uni: u64,

    // Per-stream flow control limits from transport params (RFC 9000 §18.2)
    /// Receive limit for locally-initiated bidi streams (our initial_max_stream_data_bidi_local)
    pub local_recv_max_bidi: u64,
    /// Send limit for peer-initiated bidi streams (peer's initial_max_stream_data_bidi_local)
    pub peer_send_max_bidi: u64,
    /// Receive limit for peer-initiated bidi streams (our initial_max_stream_data_bidi_remote)
    pub local_recv_max_bidi_remote: u64,
    /// Send limit for locally-initiated bidi streams (peer's initial_max_stream_data_bidi_remote)
    pub peer_send_max_bidi_remote: u64,
    /// Receive limit for peer-initiated uni streams (our initial_max_stream_data_uni)
    pub local_recv_max_uni: u64,
    /// Send limit for locally-initiated uni streams (peer's initial_max_stream_data_uni)
    pub peer_send_max_uni: u64,
}

impl StreamMap {
    pub fn new(is_client: bool) -> Self {
        Self {
            client_bidi: Vec::new(),
            server_bidi: Vec::new(),
            client_uni: Vec::new(),
            server_uni: Vec::new(),
            is_client,
            pending_send_count: 0,
            local_max_bidi: 0,
            local_max_uni: 0,
            peer_max_bidi: 0,
            peer_max_uni: 0,
            local_opened_bidi: 0,
            local_opened_uni: 0,
            peer_opened_bidi: 0,
            peer_opened_uni: 0,
            committed_max_bidi: 0,
            committed_max_uni: 0,
            local_recv_max_bidi: 65536,
            peer_send_max_bidi: 65536,
            local_recv_max_bidi_remote: 65536,
            peer_send_max_bidi_remote: 65536,
            local_recv_max_uni: 65536,
            peer_send_max_uni: 65536,
        }
    }

    fn vec_for(&self, id: StreamId) -> &Vec<Option<StreamEntry>> {
        match id.0 & 0x03 {
            0 => &self.client_bidi,
            1 => &self.server_bidi,
            2 => &self.client_uni,
            3 => &self.server_uni,
            _ => unreachable!(),
        }
    }

    fn vec_for_mut(&mut self, id: StreamId) -> &mut Vec<Option<StreamEntry>> {
        match id.0 & 0x03 {
            0 => &mut self.client_bidi,
            1 => &mut self.server_bidi,
            2 => &mut self.client_uni,
            3 => &mut self.server_uni,
            _ => unreachable!(),
        }
    }

    pub fn get(&self, id: StreamId) -> Option<&StreamEntry> {
        let idx = id.index() as usize;
        self.vec_for(id).get(idx)?.as_ref()
    }

    pub fn get_mut(&mut self, id: StreamId) -> Option<&mut StreamEntry> {
        let idx = id.index() as usize;
        self.vec_for_mut(id).get_mut(idx)?.as_mut()
    }

    /// Insert or get a stream entry, growing the Vec if needed.
    /// Returns an error if the stream would exceed concurrency limits.
    pub fn get_or_create(&mut self, id: StreamId) -> Result<&mut StreamEntry, StreamLimitError> {
        let idx = id.index() as usize;

        // Hard upper bound: refuse to grow Vec beyond MAX_STREAMS_ABSOLUTE
        if idx as u64 >= MAX_STREAMS_ABSOLUTE {
            return Err(StreamLimitError);
        }

        let is_bidi = id.is_bidi();
        let is_client = self.is_client;
        let we_initiated = id.initiator_is_client() == is_client;

        // Check if this is a new stream (not already existing)
        let is_new = {
            let vec = self.vec_for(id);
            vec.get(idx).is_none_or(Option::is_none)
        };

        if is_new {
            if !we_initiated {
                let required_count = (idx as u64) + 1;
                if is_bidi {
                    if required_count > self.local_max_bidi {
                        return Err(StreamLimitError);
                    }
                    if required_count > self.peer_opened_bidi {
                        self.peer_opened_bidi = required_count;
                    }
                } else {
                    if required_count > self.local_max_uni {
                        return Err(StreamLimitError);
                    }
                    if required_count > self.peer_opened_uni {
                        self.peer_opened_uni = required_count;
                    }
                }
            } else {
                // locally initiated — keep existing logic
                if is_bidi && self.local_opened_bidi >= self.peer_max_bidi {
                    return Err(StreamLimitError);
                }
                if !is_bidi && self.local_opened_uni >= self.peer_max_uni {
                    return Err(StreamLimitError);
                }
                if is_bidi {
                    self.local_opened_bidi += 1;
                } else {
                    self.local_opened_uni += 1;
                }
            }
        }

        // Compute per-stream flow control limits from transport params (RFC 9000 §18.2)
        // before taking mutable borrow on the Vec.
        let (send_limit, recv_limit) = if is_bidi {
            if we_initiated {
                (self.peer_send_max_bidi_remote, self.local_recv_max_bidi)
            } else {
                (self.peer_send_max_bidi, self.local_recv_max_bidi_remote)
            }
        } else if we_initiated {
            (self.peer_send_max_uni, 0)
        } else {
            (0, self.local_recv_max_uni)
        };

        let vec = self.vec_for_mut(id);
        if vec.len() <= idx {
            vec.resize_with(idx + 1, || None);
        }

        // For peer-initiated streams, create intermediate entries for all indices 0..=idx
        // (RFC 9000 §2.1: stream IDs used out of order open all lower-numbered streams).
        // Intermediate streams (i < idx) are created with deferred buffer allocation
        // (no SendHalf/RecvHalf) to prevent memory exhaustion from large stream ID gaps.
        // Buffers are allocated on-demand when data arrives via get_or_create().
        if !we_initiated && is_new {
            for i in 0..idx {
                if vec.get(i).is_none_or(Option::is_none) {
                    if vec.len() <= i {
                        vec.resize_with(i + 1, || None);
                    }
                    let state = if is_bidi {
                        StreamState::new_bidi()
                    } else {
                        StreamState::new_recv_only()
                    };
                    // Deferred: no send/recv buffers until data arrives
                    vec[i] = Some(StreamEntry {
                        state,
                        send: None,
                        recv: None,
                    });
                }
            }
            // The target stream (idx) gets full buffers
            if vec.get(idx).is_none_or(Option::is_none) {
                let (state, has_send, has_recv) = if is_bidi {
                    (StreamState::new_bidi(), true, true)
                } else {
                    (StreamState::new_recv_only(), false, true)
                };
                vec[idx] = Some(StreamEntry {
                    state,
                    send: if has_send {
                        Some(SendHalf::new(send_limit))
                    } else {
                        None
                    },
                    recv: if has_recv {
                        Some(RecvHalf::new(recv_limit))
                    } else {
                        None
                    },
                });
            }
            return Ok(vec[idx].as_mut().unwrap());
        }

        if vec[idx].is_none() {
            let (state, has_send, has_recv) = if is_bidi {
                (StreamState::new_bidi(), true, true)
            } else if we_initiated {
                (StreamState::new_send_only(), true, false)
            } else {
                (StreamState::new_recv_only(), false, true)
            };
            vec[idx] = Some(StreamEntry {
                state,
                send: if has_send {
                    Some(SendHalf::new(send_limit))
                } else {
                    None
                },
                recv: if has_recv {
                    Some(RecvHalf::new(recv_limit))
                } else {
                    None
                },
            });
        } else if let Some(ref mut entry) = vec[idx] {
            // Lazy-allocate buffers for deferred intermediate streams.
            // These were created with None send/recv to avoid memory exhaustion.
            let needs_send = is_bidi && entry.send.is_none();
            let needs_recv = !we_initiated && entry.recv.is_none();
            if needs_send {
                entry.send = Some(SendHalf::new(send_limit));
            }
            if needs_recv {
                entry.recv = Some(RecvHalf::new(recv_limit));
            }
        }
        Ok(vec[idx].as_mut().unwrap())
    }

    /// Returns a new bidi MAX_STREAMS value to advertise, if the peer has used more than half
    /// of the committed limit. Returns None if no update is needed.
    pub fn should_send_max_streams_bidi(&self) -> Option<u64> {
        if self.peer_opened_bidi > self.committed_max_bidi / 2 {
            Some(self.peer_opened_bidi + self.committed_max_bidi)
        } else {
            None
        }
    }

    /// Returns a new uni MAX_STREAMS value to advertise, if the peer has used more than half
    /// of the committed limit. Returns None if no update is needed.
    pub fn should_send_max_streams_uni(&self) -> Option<u64> {
        if self.peer_opened_uni > self.committed_max_uni / 2 {
            Some(self.peer_opened_uni + self.committed_max_uni)
        } else {
            None
        }
    }

    /// Update local bidi stream limit and record as committed.
    pub fn commit_max_streams_bidi(&mut self, max: u64) {
        self.local_max_bidi = max;
        self.committed_max_bidi = max;
    }

    /// Update local uni stream limit and record as committed.
    pub fn commit_max_streams_uni(&mut self, max: u64) {
        self.local_max_uni = max;
        self.committed_max_uni = max;
    }

    /// Remove a stream entry.
    pub fn remove(&mut self, id: StreamId) -> Option<StreamEntry> {
        let idx = id.index() as usize;
        let vec = self.vec_for_mut(id);
        vec.get_mut(idx)?.take()
    }

    /// Check if any stream has data or a pending FIN to send.
    /// O(1) via the `pending_send_count` dirty-stream counter.
    pub fn has_pending_send(&self) -> bool {
        self.pending_send_count > 0
    }

    /// Iterate over all streams that have send data pending.
    /// Yields (StreamId, &mut StreamEntry) for each stream with data in SendHalf.
    pub fn iter_send_mut(&mut self) -> impl Iterator<Item = (StreamId, &mut StreamEntry)> {
        let type_bits_and_vecs: [(u64, &mut Vec<Option<StreamEntry>>); 4] = [
            (0, &mut self.client_bidi),
            (1, &mut self.server_bidi),
            (2, &mut self.client_uni),
            (3, &mut self.server_uni),
        ];
        type_bits_and_vecs.into_iter().flat_map(|(type_bits, vec)| {
            vec.iter_mut().enumerate().filter_map(move |(idx, slot)| {
                let entry = slot.as_mut()?;
                if let Some(ref send) = entry.send
                    && (!send.buffer.is_empty() || !send.retransmit.is_empty() || send.fin_sent)
                {
                    let stream_id = StreamId((idx as u64) << 2 | type_bits);
                    return Some((stream_id, entry));
                }
                None
            })
        })
    }

    /// Iterate over all streams that have a send half, regardless of buffered data.
    /// Unlike `iter_send_mut`, this includes reset streams with empty buffers.
    pub fn iter_all_send(&self) -> impl Iterator<Item = (StreamId, &StreamEntry)> {
        let types: [(u64, &Vec<Option<StreamEntry>>); 4] = [
            (0, &self.client_bidi),
            (1, &self.server_bidi),
            (2, &self.client_uni),
            (3, &self.server_uni),
        ];
        types.into_iter().flat_map(|(type_bits, vec)| {
            vec.iter().enumerate().filter_map(move |(idx, slot)| {
                let entry = slot.as_ref()?;
                if entry.send.is_some() {
                    Some((StreamId((idx as u64) << 2 | type_bits), entry))
                } else {
                    None
                }
            })
        })
    }

    /// Iterate over all streams that have a recv half, regardless of state.
    pub fn iter_all_recv(&self) -> impl Iterator<Item = (StreamId, &StreamEntry)> {
        let types: [(u64, &Vec<Option<StreamEntry>>); 4] = [
            (0, &self.client_bidi),
            (1, &self.server_bidi),
            (2, &self.client_uni),
            (3, &self.server_uni),
        ];
        types.into_iter().flat_map(|(type_bits, vec)| {
            vec.iter().enumerate().filter_map(move |(idx, slot)| {
                let entry = slot.as_ref()?;
                if entry.recv.is_some() {
                    Some((StreamId((idx as u64) << 2 | type_bits), entry))
                } else {
                    None
                }
            })
        })
    }

    pub fn iter_recv(&self) -> impl Iterator<Item = (StreamId, &StreamEntry)> {
        let types: [(u64, &Vec<Option<StreamEntry>>); 4] = [
            (0, &self.client_bidi),
            (1, &self.server_bidi),
            (2, &self.client_uni),
            (3, &self.server_uni),
        ];
        types.into_iter().flat_map(|(type_bits, vec)| {
            vec.iter().enumerate().filter_map(move |(idx, slot)| {
                slot.as_ref()
                    .map(|entry| (StreamId((idx as u64) << 2 | type_bits), entry))
            })
        })
    }

    pub fn stream_count(&self) -> usize {
        self.client_bidi.iter().filter(|s| s.is_some()).count()
            + self.server_bidi.iter().filter(|s| s.is_some()).count()
            + self.client_uni.iter().filter(|s| s.is_some()).count()
            + self.server_uni.iter().filter(|s| s.is_some()).count()
    }
}
