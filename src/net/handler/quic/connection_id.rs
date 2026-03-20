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

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

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
#[derive(Clone, Copy)]
pub struct ConnectionIdRef<'a> {
    bytes: &'a [u8],
}

impl<'a> ConnectionIdRef<'a> {
    pub fn from_slice(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
    }

    pub fn to_owned(&self) -> ConnectionId {
        ConnectionId::from_slice(self.bytes)
    }
}

/// Fixed-size set of Connection IDs, bounded by `active_connection_id_limit` (max 8).
pub struct CidSet {
    cids: [ConnectionId; 8],
    count: u8,
}

impl CidSet {
    pub fn new() -> Self {
        Self {
            cids: [ConnectionId::empty(); 8],
            count: 0,
        }
    }

    /// Adds a CID. Returns `false` if the set is already full (8 entries).
    pub fn push(&mut self, cid: ConnectionId) -> bool {
        if self.count as usize >= 8 {
            return false;
        }
        self.cids[self.count as usize] = cid;
        self.count += 1;
        true
    }

    /// Removes a CID using swap-remove. Returns `false` if not found.
    pub fn remove(&mut self, cid: &ConnectionId) -> bool {
        for i in 0..self.count as usize {
            if &self.cids[i] == cid {
                let last = self.count as usize - 1;
                self.cids[i] = self.cids[last];
                self.cids[last] = ConnectionId::empty();
                self.count -= 1;
                return true;
            }
        }
        false
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
}

impl Default for CidSet {
    fn default() -> Self {
        Self::new()
    }
}
