use core::fmt;
use core::hash::{Hash, Hasher};

/// QUIC Connection ID (max 20 bytes, RFC 9000 §17.2). Inline, no heap.
#[derive(Clone, Copy)]
pub struct ConnectionId {
    bytes: [u8; 20],
    len: u8,
}

impl ConnectionId {
    /// Returns a zero-length CID.
    pub fn empty() -> Self {
        Self {
            bytes: [0u8; 20],
            len: 0,
        }
    }

    /// Constructs a `ConnectionId` from a byte slice. Panics if `src` is longer than 20 bytes.
    pub fn from_slice(src: &[u8]) -> Self {
        assert!(
            src.len() <= 20,
            "ConnectionId: length {} exceeds max 20",
            src.len()
        );
        let mut bytes = [0u8; 20];
        bytes[..src.len()].copy_from_slice(src);
        Self {
            bytes,
            len: src.len() as u8,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len as usize
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

impl PartialEq for ConnectionId {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for ConnectionId {}

impl Hash for ConnectionId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CID(")?;
        for b in self.as_bytes() {
            write!(f, "{:02x}", b)?;
        }
        write!(f, ")")
    }
}

/// Zero-copy borrowed QUIC Connection ID from a packet buffer.
#[derive(Clone, Copy, Debug)]
pub struct ConnectionIdRef<'a> {
    bytes: &'a [u8],
}

impl<'a> ConnectionIdRef<'a> {
    pub fn from_slice(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
    }

    pub fn to_owned(self) -> ConnectionId {
        ConnectionId::from_slice(self.bytes)
    }
}

/// Fixed-size set of Connection IDs with sequence numbers,
/// bounded by `active_connection_id_limit` (max 8).
pub struct CidSet {
    cids: [ConnectionId; 8],
    seqs: [u64; 8],
    count: u8,
}

impl CidSet {
    pub fn new() -> Self {
        Self {
            cids: [ConnectionId::empty(); 8],
            seqs: [0; 8],
            count: 0,
        }
    }

    /// Adds a CID with sequence number 0. Returns `false` if the set is already full (8 entries).
    pub fn push(&mut self, cid: ConnectionId) -> bool {
        self.push_with_seq(cid, self.count as u64)
    }

    /// Adds a CID with an explicit sequence number. Returns `false` if full.
    pub fn push_with_seq(&mut self, cid: ConnectionId, seq: u64) -> bool {
        if self.count as usize >= 8 {
            return false;
        }
        self.cids[self.count as usize] = cid;
        self.seqs[self.count as usize] = seq;
        self.count += 1;
        true
    }

    /// Removes a CID using swap-remove. Returns `false` if not found.
    pub fn remove(&mut self, cid: &ConnectionId) -> bool {
        for i in 0..self.count as usize {
            if &self.cids[i] == cid {
                let last = self.count as usize - 1;
                self.cids[i] = self.cids[last];
                self.seqs[i] = self.seqs[last];
                self.cids[last] = ConnectionId::empty();
                self.seqs[last] = 0;
                self.count -= 1;
                return true;
            }
        }
        false
    }

    /// Remove by sequence number. Returns the CID if found.
    pub fn remove_by_seq(&mut self, seq: u64) -> Option<ConnectionId> {
        for i in 0..self.count as usize {
            if self.seqs[i] == seq {
                let cid = self.cids[i];
                let last = self.count as usize - 1;
                self.cids[i] = self.cids[last];
                self.seqs[i] = self.seqs[last];
                self.cids[last] = ConnectionId::empty();
                self.seqs[last] = 0;
                self.count -= 1;
                return Some(cid);
            }
        }
        None
    }

    pub fn contains(&self, cid: &ConnectionId) -> bool {
        self.cids[..self.count as usize].contains(cid)
    }

    pub fn iter(&self) -> impl Iterator<Item = &ConnectionId> {
        self.cids[..self.count as usize].iter()
    }

    pub fn len(&self) -> usize {
        self.count as usize
    }

    /// Pick an unused CID from the set (one that isn't the current active CID).
    /// Returns (cid, sequence) or None if no spares.
    pub fn pick_unused(&self, active: &ConnectionId) -> Option<(ConnectionId, u64)> {
        for i in 0..self.count as usize {
            if &self.cids[i] != active {
                return Some((self.cids[i], self.seqs[i]));
            }
        }
        None
    }
}

impl Default for CidSet {
    fn default() -> Self {
        Self::new()
    }
}
