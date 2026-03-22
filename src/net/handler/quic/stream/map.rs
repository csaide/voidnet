use super::recv::RecvHalf;
use super::send::SendHalf;
use super::state::StreamState;
use crate::net::handler::quic::transport::frame::StreamId;

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
}

impl StreamMap {
    pub fn new(is_client: bool) -> Self {
        Self {
            client_bidi: Vec::new(),
            server_bidi: Vec::new(),
            client_uni: Vec::new(),
            server_uni: Vec::new(),
            is_client,
            local_max_bidi: 0,
            local_max_uni: 0,
            peer_max_bidi: 0,
            peer_max_uni: 0,
            local_opened_bidi: 0,
            local_opened_uni: 0,
            peer_opened_bidi: 0,
            peer_opened_uni: 0,
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
        let is_bidi = id.is_bidi();
        let is_client = self.is_client;
        let we_initiated = id.initiator_is_client() == is_client;

        // Check if this is a new stream (not already existing)
        let is_new = {
            let vec = self.vec_for(id);
            vec.get(idx).map_or(true, |entry| entry.is_none())
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

        let vec = self.vec_for_mut(id);
        if vec.len() <= idx {
            vec.resize_with(idx + 1, || None);
        }

        // For peer-initiated streams, create intermediate entries for all indices 0..=idx
        if !we_initiated && is_new {
            for i in 0..=idx {
                if vec.get(i).map_or(true, |e| e.is_none()) {
                    if vec.len() <= i {
                        vec.resize_with(i + 1, || None);
                    }
                    let (state, has_send, has_recv) = if is_bidi {
                        (StreamState::new_bidi(), true, true)
                    } else {
                        (StreamState::new_recv_only(), false, true)
                    };
                    vec[i] = Some(StreamEntry {
                        state,
                        send: if has_send {
                            Some(SendHalf::new(65536))
                        } else {
                            None
                        },
                        recv: if has_recv {
                            Some(RecvHalf::new(65536))
                        } else {
                            None
                        },
                    });
                }
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
                    Some(SendHalf::new(65536))
                } else {
                    None
                },
                recv: if has_recv {
                    Some(RecvHalf::new(65536))
                } else {
                    None
                },
            });
        }
        Ok(vec[idx].as_mut().unwrap())
    }

    /// Remove a stream entry.
    pub fn remove(&mut self, id: StreamId) -> Option<StreamEntry> {
        let idx = id.index() as usize;
        let vec = self.vec_for_mut(id);
        vec.get_mut(idx)?.take()
    }

    /// Check if any stream has data pending to send.
    pub fn has_pending_send(&self) -> bool {
        for vec in [
            &self.client_bidi,
            &self.server_bidi,
            &self.client_uni,
            &self.server_uni,
        ] {
            for entry in vec.iter().flatten() {
                if let Some(ref send) = entry.send {
                    if send.buffer.len() > 0 || (send.fin_sent && send.sent == send.acked) {
                        return true;
                    }
                }
            }
        }
        false
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
                if let Some(ref send) = entry.send {
                    if send.buffer.len() > 0 || send.fin_sent {
                        let stream_id = StreamId((idx as u64) << 2 | type_bits);
                        return Some((stream_id, entry));
                    }
                }
                None
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
