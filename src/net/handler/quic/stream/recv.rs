use std::collections::BTreeMap;

/// Power-of-two ring buffer for stream data. No wakers (socket layer handles those).
pub struct StreamRingBuffer {
    buf: Vec<u8>,
    head: usize,
    tail: usize,
    mask: usize,
}

impl StreamRingBuffer {
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.next_power_of_two();
        Self {
            buf: vec![0; capacity],
            head: 0,
            tail: 0,
            mask: capacity - 1,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.tail.wrapping_sub(self.head) & self.mask
    }

    pub fn capacity(&self) -> usize {
        self.mask
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    #[inline]
    pub fn available(&self) -> usize {
        self.capacity() - self.len()
    }

    #[inline]
    pub fn write(&mut self, data: &[u8]) -> usize {
        let avail = self.available();
        let to_write = data.len().min(avail);
        if to_write == 0 {
            return 0;
        }

        let tail_pos = self.tail & self.mask;
        let first = (self.mask + 1 - tail_pos).min(to_write); // bytes until wrap
        self.buf[tail_pos..tail_pos + first].copy_from_slice(&data[..first]);
        if first < to_write {
            self.buf[..to_write - first].copy_from_slice(&data[first..to_write]);
        }
        self.tail = (self.tail + to_write) & self.mask;
        to_write
    }

    #[inline]
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let avail = self.len();
        let to_read = buf.len().min(avail);
        if to_read == 0 {
            return 0;
        }

        let head_pos = self.head & self.mask;
        let first = (self.mask + 1 - head_pos).min(to_read); // bytes until wrap
        buf[..first].copy_from_slice(&self.buf[head_pos..head_pos + first]);
        if first < to_read {
            buf[first..to_read].copy_from_slice(&self.buf[..to_read - first]);
        }
        self.head = (self.head + to_read) & self.mask;
        to_read
    }

    pub fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
    }

    /// Write at a specific offset from head (for OOO data).
    /// Returns number of bytes written.
    pub fn write_at(&mut self, offset: usize, data: &[u8]) -> usize {
        let cap = self.capacity();
        if offset >= cap {
            return 0;
        }
        let n = data.len().min(cap - offset);
        for i in 0..n {
            self.buf[(self.head + offset + i) & self.mask] = data[i];
        }
        // Advance tail if this write extends beyond current tail
        let new_end = offset + n;
        if new_end > self.len() {
            self.tail = (self.head + new_end) & self.mask;
        }
        n
    }

    /// Peek at data without consuming.
    pub fn peek(&self, buf: &mut [u8]) -> usize {
        let avail = self.len();
        let n = buf.len().min(avail);
        for i in 0..n {
            buf[i] = self.buf[(self.head + i) & self.mask];
        }
        n
    }
}

/// Out-of-order range tracking. 8 inline entries, overflow to BTreeMap.
#[allow(dead_code)]
pub struct OooRanges {
    inline: [(u64, usize); 8],
    len: u8,
    max_entries: u16,
    overflow: Option<Box<BTreeMap<u64, usize>>>,
}

impl OooRanges {
    pub fn new(max_entries: u16) -> Self {
        Self {
            inline: [(0, 0); 8],
            len: 0,
            max_entries,
            overflow: None,
        }
    }

    pub fn insert(&mut self, offset: u64, len: usize) {
        if len == 0 {
            return;
        }

        // Enforce max_entries limit (DoS prevention)
        if self.count() >= self.max_entries as usize {
            return;
        }

        // If using overflow BTreeMap
        if let Some(ref mut map) = self.overflow {
            Self::insert_into_btree(map, offset, len);
            return;
        }

        // Try to merge with existing inline entries
        let new_end = offset + len as u64;
        for i in 0..self.len as usize {
            let (eo, el) = self.inline[i];
            let existing_end = eo + el as u64;
            // Check overlap or adjacency
            if offset <= existing_end && new_end >= eo {
                let merged_start = offset.min(eo);
                let merged_end = new_end.max(existing_end);
                self.inline[i] = (merged_start, (merged_end - merged_start) as usize);
                // Try to merge this entry with other inline entries
                self.merge_inline();
                return;
            }
        }

        // No merge possible — add new entry
        if (self.len as usize) < 8 {
            self.inline[self.len as usize] = (offset, len);
            self.len += 1;
        } else {
            // Overflow to BTreeMap
            let mut map = BTreeMap::new();
            for i in 0..8 {
                let (o, l) = self.inline[i];
                map.insert(o, l);
            }
            Self::insert_into_btree(&mut map, offset, len);
            self.overflow = Some(Box::new(map));
            self.len = 0;
        }
    }

    fn merge_inline(&mut self) {
        // Sort inline entries by offset
        let n = self.len as usize;
        // Simple insertion sort for small n
        for i in 1..n {
            let mut j = i;
            while j > 0 && self.inline[j - 1].0 > self.inline[j].0 {
                self.inline.swap(j - 1, j);
                j -= 1;
            }
        }

        // Merge adjacent/overlapping
        let mut write = 0;
        for read in 1..n {
            let (wo, wl) = self.inline[write];
            let w_end = wo + wl as u64;
            let (ro, rl) = self.inline[read];
            if ro <= w_end {
                let merged_end = w_end.max(ro + rl as u64);
                self.inline[write] = (wo, (merged_end - wo) as usize);
            } else {
                write += 1;
                self.inline[write] = self.inline[read];
            }
        }
        self.len = (write + 1) as u8;
    }

    fn insert_into_btree(map: &mut BTreeMap<u64, usize>, offset: u64, len: usize) {
        let new_end = offset + len as u64;
        let mut merged_start = offset;
        let mut merged_end = new_end;

        // Collect overlapping/adjacent entries
        let to_remove: Vec<u64> = map
            .range(..=new_end)
            .rev()
            .take_while(|e| *e.0 + *e.1 as u64 >= offset)
            .map(|e| *e.0)
            .collect();

        for o in &to_remove {
            if let Some(l) = map.remove(o) {
                merged_start = merged_start.min(*o);
                merged_end = merged_end.max(*o + l as u64);
            }
        }

        // Also check left neighbor
        if let Some((&o, &l)) = map.range(..offset).next_back() {
            if o + l as u64 >= offset {
                merged_start = merged_start.min(o);
                merged_end = merged_end.max(o + l as u64);
                map.remove(&o);
            }
        }

        map.insert(merged_start, (merged_end - merged_start) as usize);
    }

    pub fn remove_up_to(&mut self, offset: u64) {
        if let Some(ref mut map) = self.overflow {
            let to_remove: Vec<u64> = map
                .range(..offset)
                .filter(|e| *e.0 + *e.1 as u64 <= offset)
                .map(|e| *e.0)
                .collect();
            for o in to_remove {
                map.remove(&o);
            }
            // Trim partially overlapping entry
            if let Some((&o, &l)) = map.range(..offset).next_back() {
                let end = o + l as u64;
                if end > offset {
                    map.remove(&o);
                    map.insert(offset, (end - offset) as usize);
                }
            }
            // If BTreeMap is small enough, move back to inline
            if map.len() <= 8 {
                let mut i = 0;
                for (&o, &l) in map.iter() {
                    self.inline[i] = (o, l);
                    i += 1;
                }
                self.len = i as u8;
                self.overflow = None;
            }
            return;
        }

        let mut write = 0;
        for read in 0..self.len as usize {
            let (o, l) = self.inline[read];
            let end = o + l as u64;
            if end <= offset {
                continue; // remove entirely
            }
            if o < offset {
                // Trim
                self.inline[write] = (offset, (end - offset) as usize);
            } else {
                self.inline[write] = (o, l);
            }
            write += 1;
        }
        self.len = write as u8;
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0 && self.overflow.as_ref().map_or(true, |m| m.is_empty())
    }

    pub fn count(&self) -> usize {
        if let Some(ref map) = self.overflow {
            map.len()
        } else {
            self.len as usize
        }
    }
}

#[derive(Debug)]
pub enum RecvError {
    FlowControlExceeded,
    FinalSizeMismatch,
}

/// Receive half of a QUIC stream
pub struct RecvHalf {
    pub buffer: StreamRingBuffer,
    pub received: u64,    // contiguous frontier (stream offset)
    pub read_offset: u64, // how much the app has consumed (stream offset)
    pub max_stream_data: u64,
    pub final_size: Option<u64>,
    pub fin_received: bool,
    pub is_reset: bool,
    pub ooo: OooRanges,
}

impl RecvHalf {
    pub fn new(initial_max_stream_data: u64) -> Self {
        Self {
            buffer: StreamRingBuffer::new(8192),
            received: 0,
            read_offset: 0,
            max_stream_data: initial_max_stream_data,
            final_size: None,
            fin_received: false,
            is_reset: false,
            ooo: OooRanges::new(256),
        }
    }

    pub fn on_reset(&mut self, final_size: u64) -> Result<(), RecvError> {
        if final_size < self.received {
            return Err(RecvError::FinalSizeMismatch);
        }
        if let Some(fs) = self.final_size {
            if fs != final_size {
                return Err(RecvError::FinalSizeMismatch);
            }
        }
        if final_size > self.max_stream_data {
            return Err(RecvError::FlowControlExceeded);
        }
        self.final_size = Some(final_size);
        self.is_reset = true;
        Ok(())
    }

    /// Write received data at an offset. Handles out-of-order.
    /// Returns Ok(bytes_written) where 0 means fully duplicate data.
    pub fn receive(&mut self, offset: u64, data: &[u8], fin: bool) -> Result<usize, RecvError> {
        let end = offset + data.len() as u64;

        // Check flow control
        if end > self.max_stream_data {
            return Err(RecvError::FlowControlExceeded);
        }

        // Check final size consistency
        if fin {
            if let Some(fs) = self.final_size {
                if fs != end {
                    return Err(RecvError::FinalSizeMismatch);
                }
            }
            self.final_size = Some(end);
            self.fin_received = true;
        } else if let Some(fs) = self.final_size {
            if end > fs {
                return Err(RecvError::FinalSizeMismatch);
            }
        }

        if offset < self.received {
            let overlap = (self.received - offset) as usize;
            if overlap >= data.len() {
                return Ok(0); // fully duplicate, already have all this data
            }
            // Partially overlapping — trim prefix, process the new tail
            return self.receive(self.received, &data[overlap..], fin);
        }

        // Calculate buffer-relative offset: how far from current read position
        // read_offset tracks how much the app has consumed from the stream.
        // buffer head corresponds to read_offset in stream-space.
        let buf_offset = (offset - self.read_offset) as usize;
        let written = self.buffer.write_at(buf_offset, data);

        if offset == self.received {
            // In-order: advance contiguous frontier
            self.received = end;
            // Drain any OOO ranges that are now contiguous
            if !self.ooo.is_empty() {
                self.drain_contiguous();
            }
        } else {
            // Out-of-order: track the range
            self.ooo.insert(offset, data.len());
        }

        Ok(written)
    }

    fn drain_contiguous(&mut self) {
        loop {
            let mut advanced = false;
            if self.ooo.overflow.is_none() {
                for i in 0..self.ooo.len as usize {
                    let (o, l) = self.ooo.inline[i];
                    if o <= self.received && o + l as u64 > self.received {
                        self.received = o + l as u64;
                        advanced = true;
                    }
                }
            } else if let Some(ref map) = self.ooo.overflow {
                for (&o, &l) in map.iter() {
                    if o <= self.received && o + l as u64 > self.received {
                        self.received = o + l as u64;
                        advanced = true;
                    } else if o > self.received {
                        break;
                    }
                }
            }
            if advanced {
                self.ooo.remove_up_to(self.received);
            } else {
                break;
            }
        }
    }

    /// Read contiguous data from the buffer (up to the contiguous frontier)
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let contiguous = (self.received - self.read_offset) as usize;
        let n = buf.len().min(contiguous);
        let read = self.buffer.read(&mut buf[..n]);
        self.read_offset += read as u64;
        read
    }

    pub fn reset(&mut self) {
        self.buffer.clear();
        self.received = 0;
        self.read_offset = 0;
        self.final_size = None;
        self.fin_received = false;
        self.is_reset = false;
        self.ooo = OooRanges::new(256);
    }
}
