use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use crate::net::socket::SharedQueue;
use crate::net::wire::tcp::seq_le;
use crate::xdp::frame::{Frame, FrameBuffer, SharedFrameBuffer};

use super::types::{AcceptedConnection, ConnectionId, TcpCommand, TcpEvent, TcpState};

/// Tracks congestion window and slow-start threshold per RFC 5681.
pub(crate) struct CongestionState {
    pub cwnd: u32,
    pub ssthresh: u32,
}

impl CongestionState {
    /// RFC 5681 §3.1: initial window based on SMSS.
    pub fn new(mss: u16) -> Self {
        let mss_u32 = mss as u32;
        let cwnd = if mss_u32 > 2190 {
            2 * mss_u32
        } else if mss_u32 > 1095 {
            3 * mss_u32
        } else {
            4 * mss_u32
        };
        Self {
            cwnd,
            ssthresh: u32::MAX,
        }
    }
}

/// Retransmission timeout state using Jacobson/Karels algorithm (RFC 6298).
pub(crate) struct RtoState {
    srtt: Option<f64>,
    rttvar: Option<f64>,
    pub rto: Duration,
}

impl RtoState {
    pub fn new() -> Self {
        Self {
            srtt: None,
            rttvar: None,
            rto: Duration::from_secs(1),
        }
    }

    pub fn update(&mut self, rtt: Duration) {
        let r = rtt.as_secs_f64();
        match self.srtt {
            None => {
                self.srtt = Some(r);
                self.rttvar = Some(r / 2.0);
            }
            Some(srtt) => {
                let rttvar = self.rttvar.unwrap();
                self.rttvar = Some(0.75 * rttvar + 0.25 * (srtt - r).abs());
                self.srtt = Some(0.875 * srtt + 0.125 * r);
            }
        }
        let srtt = self.srtt.unwrap();
        let rttvar = self.rttvar.unwrap();
        let rto_secs = srtt + (4.0 * rttvar).max(0.001);
        self.rto = Duration::from_secs_f64(rto_secs.max(1.0));
    }

    pub fn backoff(&mut self) {
        self.rto = (self.rto * 2).min(Duration::from_secs(60));
    }
}

/// A segment queued for potential retransmission.
pub(crate) struct RetransmitEntry<'umem> {
    pub seq: u32,
    pub len: usize,
    pub frame: Frame<'umem>,
    pub sent_at: Instant,
    pub retransmit_count: u32,
    pub is_retransmit: bool,
    pub first_retransmit_time: Option<Instant>,
}

/// State for a listening socket waiting for incoming SYNs.
pub(crate) struct ListenerState<'umem> {
    pub addr: IpAddress,
    pub port: u16,
    pub accept_queue: SharedQueue<AcceptedConnection<'umem>>,
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
    pub snd_wnd: u16,
    pub snd_wl1: u32,
    pub snd_wl2: u32,
    pub iss: u32,

    pub rcv_nxt: u32,
    pub rcv_wnd: u16,
    pub irs: u32,

    pub snd_mss: u16,
    pub rcv_mss: u16,

    pub last_activity: Instant,
    pub time_wait_start: Option<Instant>,

    pub rx_queue: SharedQueue<TcpEvent<'umem>>,
    pub cmd_queue: SharedQueue<TcpCommand>,
    pub send_buffer: SharedFrameBuffer<'umem>,

    pub recv_reorder: BTreeMap<u32, (Frame<'umem>, usize, usize)>,

    pub retransmit_queue: VecDeque<RetransmitEntry<'umem>>,
    pub rto_state: RtoState,
    pub congestion: CongestionState,

    /// True when this connection was created by a passive open (listener).
    pub from_listener: bool,

    pub local_mac: MacAddress,
    pub remote_mac: MacAddress,
}

use crate::net::wire::ethernet::MacAddress;

impl<'umem> Tcb<'umem> {
    pub fn effective_window(&self) -> u32 {
        (self.snd_wnd as u32).min(self.congestion.cwnd)
    }

    pub fn is_seq_acceptable(&self, seg_seq: u32, seg_len: usize) -> bool {
        let rcv_nxt = self.rcv_nxt;
        let rcv_wnd = self.rcv_wnd as u32;

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

    pub fn ack_retransmit_queue(&mut self, seg_ack: u32, rx_return: &mut impl FrameBuffer<'umem>) {
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
                    let rtt = entry.sent_at.elapsed();
                    self.rto_state.update(rtt);
                }
                rx_return.push(entry.frame);
            } else {
                break;
            }
        }
    }
}

use crate::net::wire::tcp::seq_lt;
