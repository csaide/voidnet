use std::collections::BTreeMap;

use coarsetime::Instant;

use crate::net::handler::udp::BindError;
use crate::net::socket::LocalQueue;
use crate::net::wire::ethernet::MacAddress;
use crate::net::wire::ip::IpAddress;
use crate::xdp::frame::FrameBuffer;

use super::TcpHandler;
use super::congestion::CubicState;
use super::handler::INITIAL_RTO_MS;
use super::recovery::{FRtoState, PrrState, SackRecovery};
use super::ring_buffer::RingBuffer;
use super::segment::SegmentBuilder;
use super::state::TcpState;
use super::tcb::{
    ConnectionId, DEFAULT_DELAYED_ACK_MS, DEFAULT_RCV_MSS, DEFAULT_RCV_WND, DEFAULT_RCV_WSCALE,
    Tcb, TcpConfig, TcpEvent,
};

impl TcpHandler {
    // --- Active open ---

    /// Initiate an active open (connect).
    pub fn connect<'umem>(
        &mut self,
        local_addr: IpAddress,
        local_port: u16,
        remote_addr: IpAddress,
        remote_port: u16,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        now: Instant,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) -> Result<LocalQueue<TcpEvent>, BindError> {
        self.connect_with_config(
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            src_mac,
            dst_mac,
            now,
            TcpConfig::default(),
            free_frames,
            tx_return,
        )
    }

    /// Initiate an active open (connect) with custom buffer configuration.
    pub fn connect_with_config<'umem>(
        &mut self,
        local_addr: IpAddress,
        local_port: u16,
        remote_addr: IpAddress,
        remote_port: u16,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        now: Instant,
        config: TcpConfig,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) -> Result<LocalQueue<TcpEvent>, BindError> {
        let id = ConnectionId {
            local_addr,
            local_port,
            remote_addr,
            remote_port,
        };

        // Check for existing connection with same 4-tuple.
        if self.connections.iter().any(|c| c.id == id) {
            return Err(BindError::AddressInUse);
        }

        let iss = self.isn_generator.generate(&id);
        let event_queue = LocalQueue::new(16);

        let tcb = Tcb {
            id,
            state: TcpState::SynSent,
            from_passive_open: false,
            iss,
            snd_una: iss,
            snd_nxt: iss.wrapping_add(1),
            snd_wnd: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            irs: 0,
            rcv_nxt: 0,
            rcv_wnd: DEFAULT_RCV_WND as u32,
            snd_mss: DEFAULT_RCV_MSS,
            rcv_mss: DEFAULT_RCV_MSS,
            eff_snd_mss: DEFAULT_RCV_MSS,
            snd_wscale: 0,
            rcv_wscale: DEFAULT_RCV_WSCALE,
            wscale_enabled: false,
            retransmit_deadline: Some(now + coarsetime::Duration::from_millis(INITIAL_RTO_MS)),
            rto_backoff: 0,
            event_queue: event_queue.clone(),
            send_buffer: RingBuffer::new(config.send_buffer_size),
            recv_buffer: RingBuffer::new(config.recv_buffer_size),
            ooo_ranges: BTreeMap::new(),
            cubic: CubicState::new(DEFAULT_RCV_MSS),
            recovery: SackRecovery::new(),
            prr: PrrState::new(),
            frto: FRtoState::new(),
            srtt: None,
            rttvar: 0,
            rto: 1000,
            last_send_time: None,
            pending_fin: false,
            fin_seq: None,
            time_wait_deadline: None,
            time_wait_duration: config.time_wait_duration_ms,
            ack_pending: false,
            delayed_ack_deadline: None,
            ack_delay_count: 0,
            delayed_ack_ms: DEFAULT_DELAYED_ACK_MS,
            nagle_enabled: !config.tcp_no_delay,
            keep_alive_enabled: config.keep_alive,
            keep_alive_idle_ms: config.keep_alive_idle_ms,
            keep_alive_interval_ms: config.keep_alive_interval_ms,
            keep_alive_count: config.keep_alive_count,
            last_activity: now,
            keep_alive_probes_sent: 0,
            linger: config.linger,
            linger_deadline: None,
            ts_enabled: config.timestamps,
            ts_recent: 0,
            ts_recent_age: now,
            ts_offset: now,
            sack_enabled: config.sack,
            sack_scoreboard: BTreeMap::new(),
            ecn_enabled: config.ecn,
            ecn_ce_received: false,
            ecn_cwr_sent: false,
            persist_deadline: None,
            persist_backoff: 0,
            max_snd_wnd: 0,
            last_advertised_right_edge: 0,
        };

        // Send SYN.
        let ts_opt = if config.timestamps {
            Some((0u32, 0u32))
        } else {
            None
        };
        SegmentBuilder::build_syn(
            local_addr,
            remote_addr,
            local_port,
            remote_port,
            iss,
            DEFAULT_RCV_WND,
            DEFAULT_RCV_MSS,
            DEFAULT_RCV_WSCALE,
            ts_opt,
            config.sack,
            config.ecn,
            src_mac,
            dst_mac,
            self.tx_offload,
            free_frames,
            tx_return,
        );

        self.connections.push(tcb);
        Ok(event_queue)
    }

    /// Initiate a graceful close for a connection.
    pub fn initiate_close(&mut self, id: &ConnectionId) {
        if let Some(tcb) = self.connections.iter_mut().find(|c| c.id == *id) {
            if tcb.pending_fin
                || (tcb.state != TcpState::Established && tcb.state != TcpState::CloseWait)
            {
                return;
            }

            tcb.pending_fin = true;
            match tcb.linger {
                Some(0) => {
                    // Linger(0): set deadline to now — poll_send will send RST immediately.
                    tcb.linger_deadline = Some(Instant::recent());
                }
                Some(ms) => {
                    // Linger(timeout): graceful close with deadline.
                    tcb.linger_deadline =
                        Some(Instant::now() + coarsetime::Duration::from_millis(ms));
                }
                None => {
                    // Default: graceful close, no deadline.
                }
            }
        }
    }
}
