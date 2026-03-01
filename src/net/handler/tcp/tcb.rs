use std::cell::{Cell, UnsafeCell};
use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::{Duration, Instant};

use crate::net::socket::LocalQueue;
use crate::net::wire::tcp::seq_le;
use crate::xdp::frame::Frame;

use super::types::{AcceptedConnection, ConnectionId, TcpCommand, TcpEvent, TcpState};

/// Tracks congestion window and slow-start threshold per RFC 5681.
pub(crate) struct CongestionState {
    pub cwnd: u32,
    pub ssthresh: u32,
}

impl CongestionState {
    /// RFC 6928: initial window of 10 segments (what all modern stacks use).
    pub fn new(mss: u16) -> Self {
        Self {
            cwnd: 10 * mss as u32,
            ssthresh: u32::MAX,
        }
    }
}

/// Retransmission timeout state using Jacobson/Karels algorithm (RFC 6298).
/// Uses fixed-point u64 microseconds instead of f64 for lower overhead.
pub(crate) struct RtoState {
    srtt_us: Option<u64>,
    rttvar_us: Option<u64>,
    pub rto: Duration,
}

impl RtoState {
    pub fn new() -> Self {
        Self {
            srtt_us: None,
            rttvar_us: None,
            rto: Duration::from_secs(1),
        }
    }

    pub fn update(&mut self, rtt: Duration) {
        let r = rtt.as_micros() as u64;
        match self.srtt_us {
            None => {
                self.srtt_us = Some(r);
                self.rttvar_us = Some(r / 2);
            }
            Some(srtt) => {
                let rttvar = self.rttvar_us.unwrap();
                let diff = if srtt > r { srtt - r } else { r - srtt };
                // rttvar = (3 * rttvar + diff) / 4
                self.rttvar_us = Some((3 * rttvar + diff) / 4);
                // srtt = (7 * srtt + r) / 8
                self.srtt_us = Some((7 * srtt + r) / 8);
            }
        }
        let srtt = self.srtt_us.unwrap();
        let rttvar = self.rttvar_us.unwrap();
        // RTO = SRTT + max(G, 4*RTTVAR), G = 1ms = 1000us
        let rto_us = srtt + (4 * rttvar).max(1000);
        // Minimum RTO = 1 second per RFC 6298
        self.rto = Duration::from_micros(rto_us.max(1_000_000));
    }

    pub fn backoff(&mut self) {
        self.rto = (self.rto * 2).min(Duration::from_secs(60));
    }
}

/// A segment queued for potential retransmission.
/// Stores lightweight metadata; data payload is rebuilt from SendByteBuffer.
pub(crate) struct RetransmitEntry {
    pub seq: u32,
    pub len: usize,
    pub seg_flags: u8,
    pub ack: u32,
    pub window: u32,
    pub options: [u8; 8],
    pub options_len: u8,
    pub sent_at: Instant,
    pub retransmit_count: u32,
    pub is_retransmit: bool,
    pub first_retransmit_time: Option<Instant>,
}

/// Fixed-capacity power-of-2 ring queue for retransmit entries.
/// Never allocates after construction.
pub(crate) struct RetransmitQueue {
    entries: Box<[Option<RetransmitEntry>]>,
    head: usize,
    tail: usize,
    capacity: usize,
}

impl RetransmitQueue {
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.next_power_of_two();
        let entries = (0..capacity)
            .map(|_| None)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            entries,
            head: 0,
            tail: 0,
            capacity,
        }
    }

    #[inline(always)]
    pub fn push_back(&mut self, entry: RetransmitEntry) -> bool {
        if self.len() == self.capacity {
            return false;
        }
        self.entries[self.tail & (self.capacity - 1)] = Some(entry);
        self.tail = self.tail.wrapping_add(1);
        true
    }

    #[inline(always)]
    pub fn pop_front(&mut self) -> Option<RetransmitEntry> {
        if self.head == self.tail {
            return None;
        }
        let entry = self.entries[self.head & (self.capacity - 1)].take();
        self.head = self.head.wrapping_add(1);
        entry
    }

    #[inline(always)]
    pub fn front(&self) -> Option<&RetransmitEntry> {
        if self.head == self.tail {
            return None;
        }
        self.entries[self.head & (self.capacity - 1)].as_ref()
    }

    #[inline(always)]
    pub fn front_mut(&mut self) -> Option<&mut RetransmitEntry> {
        if self.head == self.tail {
            return None;
        }
        self.entries[self.head & (self.capacity - 1)].as_mut()
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.tail.wrapping_sub(self.head)
    }
}

/// Byte-level send buffer for TCP connections.
/// Fixed-capacity power-of-2 ring buffer. Allocated once at connection setup,
/// never reallocated. Doubles as the retransmission store.
pub(crate) struct SendByteBuffer {
    buf: Box<[u8]>,
    head: usize,
    tail: usize,
    capacity: usize,
}

impl SendByteBuffer {
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.next_power_of_two();
        Self {
            buf: vec![0u8; capacity].into_boxed_slice(),
            head: 0,
            tail: 0,
            capacity,
        }
    }

    /// Append bytes to the send buffer. Returns bytes written (0 if full). Never allocates.
    #[inline(always)]
    pub fn push(&mut self, data: &[u8]) -> usize {
        let free = self.free_space();
        let n = data.len().min(free);
        if n == 0 {
            return 0;
        }
        let mask = self.capacity - 1;
        let tail_idx = self.tail & mask;
        let first = n.min(self.capacity - tail_idx);
        self.buf[tail_idx..tail_idx + first].copy_from_slice(&data[..first]);
        if first < n {
            self.buf[..n - first].copy_from_slice(&data[first..n]);
        }
        self.tail = self.tail.wrapping_add(n);
        n
    }

    /// Returns up to two contiguous slices for ring-wrap reads starting at `offset` from head.
    /// No copy. Common case (non-wrapping) returns `(slice, &[])`.
    #[inline(always)]
    pub fn peek_slices(&self, offset: usize, len: usize) -> (&[u8], &[u8]) {
        let available = self.len().saturating_sub(offset);
        let n = len.min(available);
        if n == 0 {
            return (&[], &[]);
        }
        let mask = self.capacity - 1;
        let start = self.head.wrapping_add(offset) & mask;
        let first = n.min(self.capacity - start);
        if first == n {
            (&self.buf[start..start + n], &[])
        } else {
            (&self.buf[start..start + first], &self.buf[..n - first])
        }
    }

    /// Consume `len` bytes from the head (on ACK advancing snd_una). No copy, no allocation.
    #[inline(always)]
    pub fn advance(&mut self, len: usize) {
        let advance = len.min(self.len());
        self.head = self.head.wrapping_add(advance);
    }

    /// Free space in the ring buffer.
    #[inline(always)]
    pub fn free_space(&self) -> usize {
        self.capacity - self.len()
    }

    /// Total bytes available (both unacked and unsent).
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.tail.wrapping_sub(self.head)
    }
}

/// Shared, single-threaded send byte buffer (Rc<UnsafeCell<...>>).
pub(crate) struct SharedSendBuffer {
    inner: Rc<UnsafeCell<SendByteBuffer>>,
}

impl SharedSendBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Rc::new(UnsafeCell::new(SendByteBuffer::new(capacity))),
        }
    }

    #[inline(always)]
    pub fn push(&self, data: &[u8]) -> usize {
        unsafe { &mut *self.inner.get() }.push(data)
    }

    #[inline(always)]
    pub fn peek_slices(&self, offset: usize, len: usize) -> (&[u8], &[u8]) {
        unsafe { &*self.inner.get() }.peek_slices(offset, len)
    }

    #[inline(always)]
    pub fn advance(&self, len: usize) {
        unsafe { &mut *self.inner.get() }.advance(len);
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        unsafe { &*self.inner.get() }.len()
    }
}

impl Clone for SharedSendBuffer {
    fn clone(&self) -> Self {
        Self {
            inner: Rc::clone(&self.inner),
        }
    }
}

/// Simple `Rc<Cell<bool>>` flag for send-buffer-has-space notification.
/// Used by `TcpSendFuture` to know when buffer space is freed by ACKs.
pub(crate) struct SharedFlag(Rc<Cell<bool>>);

impl SharedFlag {
    pub fn new() -> Self {
        Self(Rc::new(Cell::new(false)))
    }

    #[inline(always)]
    pub fn set(&self, val: bool) {
        self.0.set(val);
    }
}

impl Clone for SharedFlag {
    fn clone(&self) -> Self {
        Self(Rc::clone(&self.0))
    }
}

/// Default send buffer capacity: 64KB.
pub(crate) const DEFAULT_SEND_BUF_CAPACITY: usize = 65536;
/// Default retransmit queue capacity: 128 entries.
pub(crate) const DEFAULT_RETRANSMIT_CAPACITY: usize = 128;

/// State for a listening socket waiting for incoming SYNs.
pub(crate) struct ListenerState<'umem> {
    pub addr: IpAddress,
    pub port: u16,
    pub accept_queue: LocalQueue<AcceptedConnection<'umem>>,
    pub backlog: usize,
    pub pending: usize,
}

use crate::net::wire::ip::IpAddress;

/// Transmission Control Block -- per-connection state (RFC 9293 §3.3.1).
pub(crate) struct Tcb<'umem> {
    pub state: TcpState,
    pub conn_id: ConnectionId,

    pub snd_una: u32,
    pub snd_nxt: u32,
    pub snd_wnd: u32,
    pub snd_wl1: u32,
    pub snd_wl2: u32,
    pub iss: u32,

    pub rcv_nxt: u32,
    pub rcv_wnd: u32,
    pub irs: u32,

    pub snd_mss: u16,
    pub rcv_mss: u16,

    /// Peer's window scale factor (from their SYN/SYN-ACK).
    pub snd_wnd_scale: u8,
    /// Our window scale factor (sent in our SYN/SYN-ACK).
    pub rcv_wnd_scale: u8,

    pub last_activity: Instant,
    pub time_wait_start: Option<Instant>,

    pub rx_queue: LocalQueue<TcpEvent<'umem>>,
    pub cmd_queue: LocalQueue<TcpCommand>,
    pub send_buffer: SharedSendBuffer,
    pub send_notify: SharedFlag,

    pub recv_reorder: BTreeMap<u32, (Frame<'umem>, usize, usize)>,

    pub retransmit_queue: RetransmitQueue,
    pub rto_state: RtoState,
    pub congestion: CongestionState,

    /// Delayed ACK: count of unacked data segments since last ACK sent.
    pub delayed_ack_pending: u8,
    /// Delayed ACK: timestamp of first unacked segment (for 40ms timeout).
    pub delayed_ack_at: Option<Instant>,

    /// Fast retransmit: duplicate ACK count (RFC 5681).
    pub dup_ack_count: u8,
    /// True when in fast recovery mode (RFC 5681 §3.2).
    pub in_fast_recovery: bool,
    /// Sequence number marking the end of the fast recovery period.
    pub recovery_point: u32,

    /// True when this connection needs processing in the next tick().
    pub needs_tick: bool,

    /// True when this connection was created by a passive open (listener).
    pub from_listener: bool,

    /// Precomputed `rcv_wnd / rx_queue.capacity()` to avoid per-packet division.
    pub rcv_wnd_per_slot: u32,

    pub local_mac: MacAddress,
    pub remote_mac: MacAddress,
}

use crate::net::wire::ethernet::MacAddress;

impl<'umem> Tcb<'umem> {
    pub fn effective_window(&self) -> u32 {
        self.snd_wnd.min(self.congestion.cwnd)
    }

    /// Compute the 16-bit window value for the wire, scaling by rx_queue fill level.
    ///
    /// Proportional: full queue → window=0 (sender stops), empty → full `rcv_wnd`.
    /// Uses precomputed `rcv_wnd_per_slot` to avoid division on the hot path.
    #[inline]
    pub fn wire_rcv_wnd(&self) -> u16 {
        let free = self.rx_queue.capacity().saturating_sub(self.rx_queue.len());
        let wnd = free as u32 * self.rcv_wnd_per_slot;
        (wnd >> self.rcv_wnd_scale).min(u16::MAX as u32) as u16
    }

    pub fn is_seq_acceptable(&self, seg_seq: u32, seg_len: usize) -> bool {
        let rcv_nxt = self.rcv_nxt;
        let rcv_wnd = self.rcv_wnd;

        if rcv_wnd == 0 {
            seg_len == 0 && seg_seq == rcv_nxt
        } else if seg_len == 0 {
            seq_le(rcv_nxt, seg_seq) && seq_lt(seg_seq, rcv_nxt.wrapping_add(rcv_wnd))
        } else {
            let seg_end = seg_seq.wrapping_add(seg_len as u32).wrapping_sub(1);
            (seq_le(rcv_nxt, seg_seq) && seq_lt(seg_seq, rcv_nxt.wrapping_add(rcv_wnd)))
                || (seq_le(rcv_nxt, seg_end) && seq_lt(seg_end, rcv_nxt.wrapping_add(rcv_wnd)))
        }
    }

    /// Drain all remaining events from the rx_queue, returning any Data frames
    /// to `rx_return`. Must be called before dropping a Tcb to avoid frame leaks.
    pub fn drain_rx_queue(&self, rx_return: &mut impl FrameBuffer<'umem>) {
        while let Some(event) = self.rx_queue.pop() {
            if let TcpEvent::Data { frame, .. } = event {
                rx_return.push(frame);
            }
        }
    }

    /// Push an event to the rx_queue, recovering any evicted frame to rx_return.
    ///
    /// `LocalQueue` uses force-push semantics: when full, the oldest entry is
    /// evicted. If the evicted entry carries a UMEM frame (`TcpEvent::Data`),
    /// that frame must be returned to the pool — otherwise the UMEM address is
    /// permanently leaked and the frame pool drains under sustained load.
    #[inline(always)]
    pub fn push_rx_event(&self, event: TcpEvent<'umem>, rx_return: &mut impl FrameBuffer<'umem>) {
        if let Some(evicted) = self.rx_queue.push(event) {
            if let TcpEvent::Data { frame, .. } = evicted {
                rx_return.push(frame);
            }
        }
    }

    pub fn ack_retransmit_queue(&mut self, seg_ack: u32, now: Instant) {
        use crate::net::wire::tcp::flags;
        let mut acked_bytes: usize = 0;
        while let Some(entry) = self.retransmit_queue.front() {
            let end = if entry.len == 0 {
                // SYN/FIN-only: consumes 1 seq number
                entry.seq.wrapping_add(1)
            } else {
                entry.seq.wrapping_add(entry.len as u32)
            };
            if seq_le(end, seg_ack) {
                let entry = self.retransmit_queue.pop_front().unwrap();
                if !entry.is_retransmit {
                    let rtt = now - entry.sent_at;
                    self.rto_state.update(rtt);
                }
                // Only count actual data bytes toward send buffer advance.
                // SYN/FIN flags consume sequence numbers but not send buffer bytes.
                if entry.seg_flags & (flags::SYN | flags::FIN) == 0 {
                    acked_bytes += entry.len;
                }
            } else {
                break;
            }
        }
        if acked_bytes > 0 {
            self.send_buffer.advance(acked_bytes);
            self.send_notify.set(true);
        }
    }
}

use crate::net::wire::tcp::seq_lt;
use crate::xdp::frame::FrameBuffer;
