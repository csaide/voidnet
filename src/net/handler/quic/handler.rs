use coarsetime::{Duration, Instant};
use rustc_hash::FxHashMap;
use slab::Slab;
use std::sync::Arc;

use rustls::ClientConfig;

use crate::net::handler::quic::connection::QuicConnectionState;
use crate::net::handler::quic::connection_id::ConnectionId;
use crate::net::handler::quic::timer_kinds::*;
use crate::net::handler::quic::transport::params::TransportParams;
use crate::net::handler::quic::{processor, processor::TimerResult};
use crate::net::neighbor::NeighborHandler;
use crate::net::socket::LocalQueue;
use crate::net::timer_wheel::TimerWheel;
use crate::net::wire::ethernet::MacAddress;
use crate::net::wire::ip::IpAddress;
use crate::xdp::frame::{Frame, FrameBuffer};

/// 5-tuple key for connection demux when CID is zero-length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct FiveTuple {
    pub local_addr: IpAddress,
    pub local_port: u16,
    pub remote_addr: IpAddress,
    pub remote_port: u16,
}

pub struct ListenerState {
    pub tls_config: Arc<rustls::ServerConfig>,
    pub transport_params: TransportParams,
    pub accept_queue: Option<LocalQueue<usize>>,
    /// Server secret for encrypting NEW_TOKEN tokens (RFC 9000 §8.1).
    /// Generated randomly when the listener is created.
    pub token_secret: [u8; 32],
}

/// QUIC protocol handler.
///
/// Manages the connection table, listener table, and dispatches
/// incoming QUIC packets through the appropriate state machine.
pub struct QuicHandler {
    pub(crate) connections: Slab<QuicConnectionState>,
    pub(crate) cid_map: FxHashMap<ConnectionId, usize>,
    /// Fallback demux for zero-length CID connections, keyed by 5-tuple.
    pub(crate) five_tuple_map: FxHashMap<FiveTuple, usize>,
    pub(crate) listeners: FxHashMap<u16, ListenerState>,
    pub(crate) rx_offload: bool,
    pub(crate) tx_offload: bool,
    /// Length of SCIDs we generate (used for short-header DCID parsing).
    pub(crate) local_cid_len: usize,
}

impl QuicHandler {
    pub fn new(rx_offload: bool, tx_offload: bool) -> Self {
        Self {
            connections: Slab::new(),
            cid_map: FxHashMap::default(),
            five_tuple_map: FxHashMap::default(),
            listeners: FxHashMap::default(),
            rx_offload,
            tx_offload,
            local_cid_len: 8,
        }
    }

    /// Check if a UDP destination port is registered as a QUIC listener.
    #[inline]
    pub fn is_quic_port(&self, port: u16) -> bool {
        self.listeners.contains_key(&port)
    }

    /// Generate a random 32-byte token secret for NEW_TOKEN encryption.
    fn generate_token_secret() -> [u8; 32] {
        use ring::rand::SecureRandom;
        let mut secret = [0u8; 32];
        ring::rand::SystemRandom::new()
            .fill(&mut secret)
            .expect("failed to generate random token secret");
        secret
    }

    /// Register a QUIC listener on a port.
    ///
    /// Returns `Err(())` if a listener is already registered on this port.
    pub fn listen(
        &mut self,
        port: u16,
        tls_config: Arc<rustls::ServerConfig>,
        params: TransportParams,
    ) -> Option<()> {
        if self.listeners.contains_key(&port) {
            return None;
        }
        self.listeners.insert(
            port,
            ListenerState {
                tls_config,
                transport_params: params,
                accept_queue: None,
                token_secret: Self::generate_token_secret(),
            },
        );
        Some(())
    }

    /// Register a QUIC listener on a port with an accept queue.
    ///
    /// Creates a new `LocalQueue` internally and returns it to the caller.
    /// The accept queue receives connection slab keys when handshakes complete.
    /// Returns `Err(())` if a listener is already registered on this port.
    pub fn listen_with_queue(
        &mut self,
        port: u16,
        tls_config: Arc<rustls::ServerConfig>,
        params: TransportParams,
    ) -> Option<LocalQueue<usize>> {
        if self.listeners.contains_key(&port) {
            return None;
        }
        let queue = LocalQueue::new(128);
        let accept_queue = queue.clone();
        self.listeners.insert(
            port,
            ListenerState {
                tls_config,
                transport_params: params,
                accept_queue: Some(accept_queue),
                token_secret: Self::generate_token_secret(),
            },
        );
        Some(queue)
    }

    /// Remove a QUIC listener from a port.
    pub fn unlisten(&mut self, port: u16) {
        self.listeners.remove(&port);
    }

    /// Process an incoming IPv4 UDP packet destined for a QUIC port.
    pub fn process_ipv4<'umem>(
        &mut self,
        frame: Frame<'umem>,
        now: Instant,
        wheel: &mut TimerWheel,
        _neighbor_handler: &NeighborHandler,
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        use crate::net::wire::ethernet::EthernetFrame;
        use crate::net::wire::ip::{IPV4_MIN_HEADER_LEN, IpAddress, Ipv4Header};
        use crate::net::wire::quic as wire_quic;
        use crate::net::wire::udp::UdpHeader;

        let eth_len = std::mem::size_of::<EthernetFrame>();
        let ip_offset = eth_len;

        // Need at least Ethernet + IPv4 + UDP headers
        if frame.len() < eth_len + IPV4_MIN_HEADER_LEN + 8 {
            rx_return.push(frame);
            return;
        }

        let ip = Ipv4Header::from_bytes(&frame);
        let actual_ip_hdr_len = ip.header_len();
        let udp_offset = ip_offset + actual_ip_hdr_len;

        if frame.len() < udp_offset + 8 {
            rx_return.push(frame);
            return;
        }

        let udp = unsafe { UdpHeader::from_bytes_at(&frame, udp_offset) };
        let src_port = udp.src_port();
        let dst_port = udp.dst_port();
        let quic_offset = udp_offset + 8; // UDP_HEADER_LEN = 8

        // datagram_len = IP payload size = IP total length - IP header length
        let datagram_len = ip.total_length() as usize - actual_ip_hdr_len;

        let src_addr = IpAddress::V4(ip.src_addr);
        let dst_addr = IpAddress::V4(ip.dst_addr);

        let eth_frame = EthernetFrame::from_bytes(&frame);
        let src_mac = eth_frame.src_mac;
        let dst_mac = eth_frame.dst_mac;

        if frame.len() <= quic_offset {
            rx_return.push(frame);
            return;
        }

        // Peek DCID for connection lookup
        let quic_data = &frame[quic_offset..];
        let dcid = if !quic_data.is_empty() && wire_quic::is_long_header(quic_data[0]) {
            match wire_quic::peek_dcid(quic_data) {
                Some(cid) if cid.len() <= 20 => cid.to_owned(),
                _ => {
                    rx_return.push(frame);
                    return;
                }
            }
        } else {
            // Short header: DCID starts at byte 1, length is our SCID length
            let scid_len = self.local_cid_len;
            if quic_data.len() < 1 + scid_len {
                rx_return.push(frame);
                return;
            }
            crate::net::handler::quic::connection_id::ConnectionId::from_slice(
                &quic_data[1..1 + scid_len],
            )
        };

        // Look up existing connection (CID map first, then 5-tuple fallback)
        let conn_key = self.cid_map.get(&dcid).copied().or_else(|| {
            let tuple = FiveTuple {
                local_addr: dst_addr,
                local_port: dst_port,
                remote_addr: src_addr,
                remote_port: src_port,
            };
            self.five_tuple_map.get(&tuple).copied()
        });

        if let Some(conn_key) = conn_key {
            let mut frame_data = frame;
            let quic_payload = &mut frame_data[quic_offset..];
            let conn = &mut self.connections[conn_key];
            processor::process_packet(conn, quic_payload, datagram_len, now);
            rx_return.push(frame_data);

            // After process_packet(), check for address change (migration detection)
            let conn = &mut self.connections[conn_key];
            if src_addr != conn.remote_addr || src_port != conn.remote_port {
                // NAT rebinding vs intentional migration (RFC 9000 §9.3)
                let port_only_change = src_addr == conn.remote_addr && src_port != conn.remote_port;
                if port_only_change {
                    // NAT rebinding — just update port, no validation needed
                    conn.remote_port = src_port;
                } else {
                    // Full migration — snapshot, validate, rotate CID
                    use crate::net::handler::quic::connection::PreviousPath;
                    conn.prev_path = Some(PreviousPath {
                        remote_addr: conn.remote_addr,
                        remote_port: conn.remote_port,
                        remote_mac: conn.remote_mac,
                        path: std::mem::replace(
                            &mut conn.path,
                            crate::net::handler::quic::path::PathState::new(),
                        ),
                    });
                    conn.remote_addr = src_addr;
                    conn.remote_port = src_port;
                    conn.remote_mac = src_mac;
                    // Initiate path validation
                    let _challenge = conn.path.initiate_validation(now);
                    conn.pending_path_response = None; // clear any stale response
                    // CID rotation for linkability prevention
                    if let Some((new_cid, _seq)) = conn.scid_set.pick_unused(&conn.scid) {
                        use crate::net::handler::quic::connection::MigrationAction;
                        let old_cid = conn.scid;
                        conn.scid = new_cid;
                        conn.pending_migration = Some(MigrationAction { old_cid, new_cid });
                    }
                }
            }

            // Process pending migration CID map update
            let conn = &mut self.connections[conn_key];
            if let Some(migration) = conn.pending_migration.take() {
                self.cid_map.remove(&migration.old_cid);
                self.cid_map.insert(migration.new_cid, conn_key);
            }

            processor::generate_packets(
                &mut self.connections[conn_key],
                conn_key,
                now,
                wheel,
                free_frames,
                tx_return,
            );
            self.sync_cid_map(conn_key);
        } else if !quic_data.is_empty() && wire_quic::is_long_header(quic_data[0]) {
            // Potential new connection — check if Initial + listener exists
            if self.listeners.contains_key(&dst_port) && datagram_len >= 1200 {
                // Extract version from long header bytes [1..5]
                let version = if quic_data.len() >= 5 {
                    u32::from_be_bytes([quic_data[1], quic_data[2], quic_data[3], quic_data[4]])
                } else {
                    0x00000001 // fallback to v1
                };
                // RFC 9000 §6.1: send Version Negotiation for unsupported versions
                if !crate::net::handler::quic::transport::version::is_supported_version(version) {
                    // Extract CIDs from the frame before we overwrite it.
                    // Max CID length is 20 bytes (RFC 9000 §17.2).
                    match Self::extract_cids(quic_data) {
                        Some((dcid_buf, dcid_len, scid_buf, scid_len)) => {
                            Self::build_vn_ipv4(
                                frame,
                                &dcid_buf[..dcid_len],
                                &scid_buf[..scid_len],
                                quic_offset,
                                ip_offset,
                                src_addr,
                                dst_addr,
                                src_port,
                                dst_port,
                                src_mac,
                                dst_mac,
                                tx_return,
                                rx_return,
                            );
                        }
                        None => rx_return.push(frame),
                    }
                } else {
                    // Extract client's SCID from the long header.
                    // RFC 9000 §7.2: server MUST use client's SCID as DCID.
                    let client_scid = match Self::extract_cids(quic_data) {
                        Some((_, _, scid_buf, scid_len)) => {
                            ConnectionId::from_slice(&scid_buf[..scid_len])
                        }
                        None => {
                            rx_return.push(frame);
                            return;
                        }
                    };
                    if let Some(key) = self.create_server_connection(
                        &dcid,
                        &client_scid,
                        dst_addr,
                        src_addr,
                        dst_port,
                        src_port,
                        src_mac,
                        dst_mac,
                        now,
                        version,
                    ) {
                        let conn = &mut self.connections[key];
                        let mut frame_data = frame;
                        let quic_payload = &mut frame_data[quic_offset..];
                        processor::process_packet(conn, quic_payload, datagram_len, now);
                        rx_return.push(frame_data);
                        let conn = &mut self.connections[key];
                        processor::generate_packets(conn, key, now, wheel, free_frames, tx_return);
                        self.sync_cid_map(key);
                    } else {
                        rx_return.push(frame);
                    }
                }
            } else {
                rx_return.push(frame);
            }
        } else {
            rx_return.push(frame);
        }
    }

    /// Process an incoming IPv6 UDP packet destined for a QUIC port.
    pub fn process_ipv6<'umem>(
        &mut self,
        frame: Frame<'umem>,
        now: Instant,
        wheel: &mut TimerWheel,
        _neighbor_handler: &NeighborHandler,
        free_frames: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        use crate::net::wire::ethernet::EthernetFrame;
        use crate::net::wire::ip::{IPV6_HEADER_LEN, IpAddress, Ipv6Header};
        use crate::net::wire::quic as wire_quic;
        use crate::net::wire::udp::UdpHeader;

        let eth_len = std::mem::size_of::<EthernetFrame>();
        let udp_offset = eth_len + IPV6_HEADER_LEN;

        // Need at least Ethernet + IPv6 + UDP headers
        if frame.len() < udp_offset + 8 {
            rx_return.push(frame);
            return;
        }

        let ip = Ipv6Header::from_bytes(&frame);
        let udp = unsafe { UdpHeader::from_bytes_at(&frame, udp_offset) };
        let src_port = udp.src_port();
        let dst_port = udp.dst_port();
        let quic_offset = udp_offset + 8; // UDP_HEADER_LEN = 8

        // datagram_len = IPv6 payload length (does not include the 40-byte IPv6 header)
        let datagram_len = ip.payload_length() as usize;

        let src_addr = IpAddress::V6(ip.src_addr);
        let dst_addr = IpAddress::V6(ip.dst_addr);

        let eth_frame = EthernetFrame::from_bytes(&frame);
        let src_mac = eth_frame.src_mac;
        let dst_mac = eth_frame.dst_mac;

        if frame.len() <= quic_offset {
            rx_return.push(frame);
            return;
        }

        // Peek DCID for connection lookup
        let quic_data = &frame[quic_offset..];
        let dcid = if !quic_data.is_empty() && wire_quic::is_long_header(quic_data[0]) {
            match wire_quic::peek_dcid(quic_data) {
                Some(cid) if cid.len() <= 20 => cid.to_owned(),
                _ => {
                    rx_return.push(frame);
                    return;
                }
            }
        } else {
            // Short header: DCID starts at byte 1, length is our SCID length
            let scid_len = self.local_cid_len;
            if quic_data.len() < 1 + scid_len {
                rx_return.push(frame);
                return;
            }
            crate::net::handler::quic::connection_id::ConnectionId::from_slice(
                &quic_data[1..1 + scid_len],
            )
        };

        // Look up existing connection (CID map first, then 5-tuple fallback)
        let conn_key = self.cid_map.get(&dcid).copied().or_else(|| {
            let tuple = FiveTuple {
                local_addr: dst_addr,
                local_port: dst_port,
                remote_addr: src_addr,
                remote_port: src_port,
            };
            self.five_tuple_map.get(&tuple).copied()
        });

        if let Some(conn_key) = conn_key {
            let mut frame_data = frame;
            let quic_payload = &mut frame_data[quic_offset..];
            let conn = &mut self.connections[conn_key];
            processor::process_packet(conn, quic_payload, datagram_len, now);
            rx_return.push(frame_data);

            // After process_packet(), check for address change (migration detection)
            let conn = &mut self.connections[conn_key];
            if src_addr != conn.remote_addr || src_port != conn.remote_port {
                // NAT rebinding vs intentional migration (RFC 9000 §9.3)
                let port_only_change = src_addr == conn.remote_addr && src_port != conn.remote_port;
                if port_only_change {
                    // NAT rebinding — just update port, no validation needed
                    conn.remote_port = src_port;
                } else {
                    // Full migration — snapshot, validate, rotate CID
                    use crate::net::handler::quic::connection::PreviousPath;
                    conn.prev_path = Some(PreviousPath {
                        remote_addr: conn.remote_addr,
                        remote_port: conn.remote_port,
                        remote_mac: conn.remote_mac,
                        path: std::mem::replace(
                            &mut conn.path,
                            crate::net::handler::quic::path::PathState::new(),
                        ),
                    });
                    conn.remote_addr = src_addr;
                    conn.remote_port = src_port;
                    conn.remote_mac = src_mac;
                    // Initiate path validation
                    let _challenge = conn.path.initiate_validation(now);
                    conn.pending_path_response = None; // clear any stale response
                    // CID rotation for linkability prevention
                    if let Some((new_cid, _seq)) = conn.scid_set.pick_unused(&conn.scid) {
                        use crate::net::handler::quic::connection::MigrationAction;
                        let old_cid = conn.scid;
                        conn.scid = new_cid;
                        conn.pending_migration = Some(MigrationAction { old_cid, new_cid });
                    }
                }
            }

            // Process pending migration CID map update
            let conn = &mut self.connections[conn_key];
            if let Some(migration) = conn.pending_migration.take() {
                self.cid_map.remove(&migration.old_cid);
                self.cid_map.insert(migration.new_cid, conn_key);
            }

            processor::generate_packets(
                &mut self.connections[conn_key],
                conn_key,
                now,
                wheel,
                free_frames,
                tx_return,
            );
            self.sync_cid_map(conn_key);
        } else if !quic_data.is_empty() && wire_quic::is_long_header(quic_data[0]) {
            // Potential new connection — check if Initial + listener exists
            if self.listeners.contains_key(&dst_port) && datagram_len >= 1200 {
                // Extract version from long header bytes [1..5]
                let version = if quic_data.len() >= 5 {
                    u32::from_be_bytes([quic_data[1], quic_data[2], quic_data[3], quic_data[4]])
                } else {
                    0x00000001 // fallback to v1
                };
                // RFC 9000 §6.1: send Version Negotiation for unsupported versions
                if !crate::net::handler::quic::transport::version::is_supported_version(version) {
                    match Self::extract_cids(quic_data) {
                        Some((dcid_buf, dcid_len, scid_buf, scid_len)) => {
                            Self::build_vn_ipv6(
                                frame,
                                &dcid_buf[..dcid_len],
                                &scid_buf[..scid_len],
                                quic_offset,
                                udp_offset,
                                src_addr,
                                dst_addr,
                                src_port,
                                dst_port,
                                src_mac,
                                dst_mac,
                                tx_return,
                                rx_return,
                            );
                        }
                        None => rx_return.push(frame),
                    }
                } else {
                    let client_scid = match Self::extract_cids(quic_data) {
                        Some((_, _, scid_buf, scid_len)) => {
                            ConnectionId::from_slice(&scid_buf[..scid_len])
                        }
                        None => {
                            rx_return.push(frame);
                            return;
                        }
                    };
                    if let Some(key) = self.create_server_connection(
                        &dcid,
                        &client_scid,
                        dst_addr,
                        src_addr,
                        dst_port,
                        src_port,
                        src_mac,
                        dst_mac,
                        now,
                        version,
                    ) {
                        let conn = &mut self.connections[key];
                        let mut frame_data = frame;
                        let quic_payload = &mut frame_data[quic_offset..];
                        processor::process_packet(conn, quic_payload, datagram_len, now);
                        rx_return.push(frame_data);
                        let conn = &mut self.connections[key];
                        processor::generate_packets(conn, key, now, wheel, free_frames, tx_return);
                        self.sync_cid_map(key);
                    } else {
                        rx_return.push(frame);
                    }
                }
            } else {
                rx_return.push(frame);
            }
        } else {
            rx_return.push(frame);
        }
    }

    /// Handle a fired QUIC timer.
    pub fn handle_timer<'umem>(
        &mut self,
        key: usize,
        kind: QuicTimerKind,
        now: Instant,
        wheel: &mut TimerWheel,
        free_frames: &mut impl FrameBuffer<'umem>,
        _rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        if let Some(conn) = self.connections.get_mut(key) {
            let result = processor::handle_timeout(conn, kind, now);
            match result {
                TimerResult::Close => {
                    self.remove_connection_by_key(key);
                }
                TimerResult::Ok => {
                    // Generate any packets triggered by the timeout
                    // (loss retransmit, probe, etc.)
                    if let Some(conn) = self.connections.get_mut(key) {
                        processor::generate_packets(conn, key, now, wheel, free_frames, tx_return);
                    }
                    self.sync_cid_map(key);
                }
            }
        }
    }

    /// Poll connections for outgoing data.
    pub fn poll_send<'umem>(
        &mut self,
        now: Instant,
        wheel: &mut TimerWheel,
        free_frames: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        let keys_with_data: smallvec::SmallVec<[usize; 16]> = self
            .connections
            .iter()
            .filter(|(_, conn)| processor::has_pending_data_any(conn))
            .map(|(key, _)| key)
            .collect();
        for key in &keys_with_data {
            if let Some(conn) = self.connections.get_mut(*key) {
                processor::generate_packets(conn, *key, now, wheel, free_frames, tx_return);
            }
        }
        for key in keys_with_data {
            self.sync_cid_map(key);
        }
    }

    /// Evict stale connections (called periodically).
    /// RFC 9000 §10.1: idle timeout = max(negotiated_timeout, 3×PTO).
    pub fn evict_stale(&mut self, now: Instant) {
        let stale_keys: smallvec::SmallVec<[usize; 8]> = self
            .connections
            .iter()
            .filter(|(_, conn)| {
                // 0 means disabled (RFC 9000 §18.2)
                if conn.idle_timeout.as_millis() == 0 {
                    return false;
                }
                let max_ack_delay = conn
                    .peer_params
                    .as_ref()
                    .map(|p| Duration::from_millis(p.max_ack_delay_ms))
                    .unwrap_or(Duration::from_millis(25));
                let pto_3x = conn.loss.pto(2, max_ack_delay) * 3;
                // RFC 9000 §10.1: effective timeout is at least 3×PTO
                let effective_timeout = if pto_3x > conn.idle_timeout {
                    pto_3x
                } else {
                    conn.idle_timeout
                };
                let elapsed = now.duration_since(conn.last_activity);
                elapsed > effective_timeout
            })
            .map(|(key, _)| key)
            .collect();
        for key in stale_keys {
            self.remove_connection_by_key(key);
        }
    }

    /// Look up a connection by CID.
    pub fn get_connection(&self, cid: &ConnectionId) -> Option<(usize, &QuicConnectionState)> {
        let key = self.cid_map.get(cid)?;
        Some((*key, &self.connections[*key]))
    }

    /// Look up a mutable connection by CID.
    pub fn get_connection_mut(
        &mut self,
        cid: &ConnectionId,
    ) -> Option<(usize, &mut QuicConnectionState)> {
        let key = self.cid_map.get(cid)?;
        Some((*key, &mut self.connections[*key]))
    }

    /// Extract DCID and SCID from a QUIC long header into stack buffers.
    /// Returns (dcid_buf, dcid_len, scid_buf, scid_len).
    fn extract_cids(quic_data: &[u8]) -> Option<([u8; 20], usize, [u8; 20], usize)> {
        if quic_data.len() < 6 {
            return None;
        }
        let dcid_len = quic_data[5] as usize;
        if dcid_len > 20 {
            return None;
        }
        let dcid_end = 6 + dcid_len;
        if quic_data.len() < dcid_end + 1 {
            return None;
        }
        let scid_len = quic_data[dcid_end] as usize;
        if scid_len > 20 {
            return None;
        }
        let scid_start = dcid_end + 1;
        let scid_end = scid_start + scid_len;
        if quic_data.len() < scid_end {
            return None;
        }
        let mut dcid_buf = [0u8; 20];
        let mut scid_buf = [0u8; 20];
        dcid_buf[..dcid_len].copy_from_slice(&quic_data[6..dcid_end]);
        scid_buf[..scid_len].copy_from_slice(&quic_data[scid_start..scid_end]);
        Some((dcid_buf, dcid_len, scid_buf, scid_len))
    }

    /// Build a Version Negotiation packet directly into the RX frame (IPv4).
    /// Reuses the incoming frame — no pop from free_frames needed.
    /// RFC 9000 §6.1, RFC 8999 §6.
    fn build_vn_ipv4<'umem>(
        mut frame: Frame<'umem>,
        dcid: &[u8],
        scid: &[u8],
        quic_offset: usize,
        ip_offset: usize,
        src_addr: IpAddress,
        dst_addr: IpAddress,
        src_port: u16,
        dst_port: u16,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        tx_return: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
    ) {
        use crate::net::handler::quic::transport::version;
        // RFC 8999 §6: swap DCID/SCID in the response
        let vn_len = 1 + 4 + 1 + scid.len() + 1 + dcid.len() + 2 * 4;
        let udp_len = 8 + vn_len;
        let total = quic_offset + vn_len;
        if frame.capacity() < total {
            rx_return.push(frame);
            return;
        }
        unsafe { frame.set_len(frame.capacity()) };
        crate::net::wire::ethernet::write_ethernet_header(
            &mut frame,
            src_mac,
            dst_mac,
            crate::net::wire::ethernet::EtherTypes::IPv4,
        );
        let ip_hdr_len = crate::net::wire::ip::IPV4_MIN_HEADER_LEN;
        let total_ip_len = (ip_hdr_len + udp_len) as u16;
        {
            let ip = &mut frame[ip_offset..ip_offset + ip_hdr_len];
            ip.fill(0);
            ip[0] = 0x45;
            ip[2..4].copy_from_slice(&total_ip_len.to_be_bytes());
            ip[6] = 0x40; // DF
            ip[8] = 64; // TTL
            ip[9] = crate::net::wire::ip::IpProtocols::Udp;
            if let IpAddress::V4(src) = dst_addr {
                let b: [u8; 4] = src.into();
                ip[12..16].copy_from_slice(&b);
            }
            if let IpAddress::V4(dst) = src_addr {
                let b: [u8; 4] = dst.into();
                ip[16..20].copy_from_slice(&b);
            }
        }
        let ip_header = crate::net::wire::ip::Ipv4Header::from_bytes_mut(&mut frame);
        ip_header.fill_checksum();
        let udp_offset = ip_offset + ip_hdr_len;
        {
            let udp = unsafe {
                crate::net::wire::udp::UdpHeader::from_bytes_at_mut(&mut frame, udp_offset)
            };
            udp.src_port = dst_port.to_be_bytes();
            udp.dst_port = src_port.to_be_bytes();
            udp.length = (udp_len as u16).to_be_bytes();
            udp.checksum = [0, 0]; // IPv4 UDP checksum optional
        }
        version::build_version_negotiation(
            &mut frame[quic_offset..],
            scid,
            dcid,
            &[version::QUIC_VERSION_1, version::QUIC_VERSION_2],
        );
        debug_assert!(total >= 64, "QUIC VN IPv4: packet too small: {total} bytes");
        unsafe { frame.set_len(total) };
        tx_return.push(frame);
    }

    /// Build a Version Negotiation packet directly into the RX frame (IPv6).
    /// Reuses the incoming frame — no pop from free_frames needed.
    fn build_vn_ipv6<'umem>(
        mut frame: Frame<'umem>,
        dcid: &[u8],
        scid: &[u8],
        quic_offset: usize,
        udp_offset: usize,
        src_addr: IpAddress,
        dst_addr: IpAddress,
        src_port: u16,
        dst_port: u16,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        tx_return: &mut impl FrameBuffer<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
    ) {
        use crate::net::handler::quic::transport::version;
        let vn_len = 1 + 4 + 1 + scid.len() + 1 + dcid.len() + 2 * 4;
        let udp_len = 8 + vn_len;
        let total = quic_offset + vn_len;
        if frame.capacity() < total {
            rx_return.push(frame);
            return;
        }
        unsafe { frame.set_len(frame.capacity()) };
        let eth_len = std::mem::size_of::<crate::net::wire::ethernet::EthernetFrame>();
        crate::net::wire::ethernet::write_ethernet_header(
            &mut frame,
            src_mac,
            dst_mac,
            crate::net::wire::ethernet::EtherTypes::IPv6,
        );
        {
            let ip = &mut frame[eth_len..eth_len + crate::net::wire::ip::IPV6_HEADER_LEN];
            ip.fill(0);
            ip[0] = 0x60;
            let payload_len = udp_len as u16;
            ip[4..6].copy_from_slice(&payload_len.to_be_bytes());
            ip[6] = crate::net::wire::ip::IpProtocols::Udp;
            ip[7] = 64;
            if let IpAddress::V6(src) = dst_addr {
                ip[8..24].copy_from_slice(&src.octets);
            }
            if let IpAddress::V6(dst) = src_addr {
                ip[24..40].copy_from_slice(&dst.octets);
            }
        }
        {
            let udp = unsafe {
                crate::net::wire::udp::UdpHeader::from_bytes_at_mut(&mut frame, udp_offset)
            };
            udp.src_port = dst_port.to_be_bytes();
            udp.dst_port = src_port.to_be_bytes();
            udp.length = (udp_len as u16).to_be_bytes();
            udp.checksum = [0, 0];
        }
        version::build_version_negotiation(
            &mut frame[quic_offset..],
            scid,
            dcid,
            &[version::QUIC_VERSION_1, version::QUIC_VERSION_2],
        );
        // IPv6 UDP checksum (RFC 8200 §8.1)
        {
            use crate::net::checksum::{
                checksum_to_bytes, fold_checksum, pseudo_header_sum_v6, sum_words,
            };
            if let (IpAddress::V6(src_ip), IpAddress::V6(dst_ip)) = (dst_addr, src_addr) {
                let udp_segment = &frame[udp_offset..total];
                let sum = pseudo_header_sum_v6(
                    &src_ip,
                    &dst_ip,
                    crate::net::wire::ip::IpProtocols::Udp,
                    udp_len as u32,
                ) + sum_words(udp_segment);
                let checksum = checksum_to_bytes(fold_checksum(sum));
                let udp = unsafe {
                    crate::net::wire::udp::UdpHeader::from_bytes_at_mut(&mut frame, udp_offset)
                };
                udp.checksum = checksum;
            }
        }
        debug_assert!(total >= 64, "QUIC VN IPv6: packet too small: {total} bytes");
        unsafe { frame.set_len(total) };
        tx_return.push(frame);
    }

    /// Sync CID map after generate_packets: register newly issued local CIDs,
    /// issue replacement CIDs when peer retires one of ours, and clean up stale entries.
    fn sync_cid_map(&mut self, conn_key: usize) {
        if !self.connections.contains(conn_key) {
            return;
        }

        // Issue replacement CID if peer retired one of ours
        let conn = &mut self.connections[conn_key];
        if conn.cid_manager.needs_replacement_cid {
            conn.cid_manager.needs_replacement_cid = false;
            let cid_len = conn.scid.len();
            if cid_len > 0 {
                let mut cid_buf = [0u8; 20];
                use ring::rand::SecureRandom;
                let _ = ring::rand::SystemRandom::new().fill(&mut cid_buf[..cid_len]);
                let new_cid = crate::net::handler::quic::connection_id::ConnectionId::from_slice(
                    &cid_buf[..cid_len],
                );
                if let Some(seq) = conn.cid_manager.issue_new_cid(new_cid) {
                    let token = [0u8; 16]; // Simplified reset token
                    conn.retransmit
                        .pending_new_cids
                        .push((seq, 0, new_cid, token));
                    // Also add to scid_set for cid_map registration
                    conn.scid_set.push(new_cid);
                }
            }
        }

        // Register all local CIDs (from cid_manager) into cid_map
        let conn = &self.connections[conn_key];
        for cid in conn.cid_manager.local_cids.iter() {
            if !self.cid_map.contains_key(cid) {
                self.cid_map.insert(*cid, conn_key);
            }
        }
    }

    /// Insert a new connection, returning its slab key.
    pub fn insert_connection(&mut self, conn: QuicConnectionState) -> usize {
        let key = self.connections.insert(conn);
        let conn = &self.connections[key];
        self.cid_map.insert(conn.dcid, key);
        for cid in conn.scid_set.iter() {
            self.cid_map.insert(*cid, key);
        }
        // Register 5-tuple fallback for zero-length SCID connections
        if conn.scid.is_empty() {
            let tuple = FiveTuple {
                local_addr: conn.local_addr,
                local_port: conn.local_port,
                remote_addr: conn.remote_addr,
                remote_port: conn.remote_port,
            };
            self.five_tuple_map.insert(tuple, key);
        }
        key
    }

    /// Remove a connection by slab key.
    pub fn remove_connection_by_key(&mut self, key: usize) -> Option<QuicConnectionState> {
        if self.connections.contains(key) {
            // Wake any blocked futures before removal
            let conn = &self.connections[key];
            conn.event_queue.wake();
            conn.stream_accept_queue.wake();
            // Now remove
            let conn = self.connections.remove(key);
            self.cid_map.remove(&conn.dcid);
            // Also remove all SCIDs
            for cid in conn.scid_set.iter() {
                self.cid_map.remove(cid);
            }
            // Also remove CIDs tracked by cid_manager
            for cid in conn.cid_manager.local_cids.iter() {
                self.cid_map.remove(cid);
            }
            // Clean up 5-tuple mapping if present
            if conn.scid.is_empty() {
                let tuple = FiveTuple {
                    local_addr: conn.local_addr,
                    local_port: conn.local_port,
                    remote_addr: conn.remote_addr,
                    remote_port: conn.remote_port,
                };
                self.five_tuple_map.remove(&tuple);
            }
            Some(conn)
        } else {
            None
        }
    }

    /// Create a new server-side connection from an incoming Initial packet.
    ///
    /// `original_dcid` is the client's Initial DCID (for key derivation, RFC 9001 §5.2).
    /// `client_scid` is the client's SCID (used as our DCID per RFC 9000 §7.2).
    /// Returns the slab key on success.
    fn create_server_connection(
        &mut self,
        original_dcid: &ConnectionId,
        client_scid: &ConnectionId,
        local_addr: IpAddress,
        remote_addr: IpAddress,
        local_port: u16,
        remote_port: u16,
        remote_mac: MacAddress,
        local_mac: MacAddress,
        now: Instant,
        version: u32,
    ) -> Option<usize> {
        use crate::net::handler::quic::connection::Side;
        use crate::net::handler::quic::crypto::initial_keys::derive_initial_keys;
        use crate::net::handler::quic::crypto::keys::{DirectionalKey, KeyPair};
        use crate::net::handler::quic::crypto::tls::CryptoState;
        use ring::rand::SecureRandom;

        let listener = self.listeners.get(&local_port)?;

        let rustls_version =
            crate::net::handler::quic::transport::version::rustls_quic_version(version);

        // Derive initial keys from original DCID (RFC 9001 §5.2)
        let (local_dk, remote_dk) = derive_initial_keys(
            original_dcid.as_bytes(),
            rustls::Side::Server,
            rustls_version,
        );
        let initial_keys = KeyPair {
            local: DirectionalKey::from_rustls(local_dk),
            remote: DirectionalKey::from_rustls(remote_dk),
        };

        // Determine CID length from listener transport params or handler default
        let cid_len = listener
            .transport_params
            .cid_length
            .map(|l| l as usize)
            .unwrap_or(self.local_cid_len);

        // Update handler's SCID length so short-header parsing uses correct length
        self.local_cid_len = cid_len;

        let mut scid_buf = [0u8; 20];
        if cid_len > 0 {
            ring::rand::SystemRandom::new()
                .fill(&mut scid_buf[..cid_len])
                .ok()?;
        }
        let scid = ConnectionId::from_slice(&scid_buf[..cid_len]);

        // RFC 9000 §18.2: server MUST include these CID params in the TLS handshake
        let mut server_params = listener.transport_params.clone();
        server_params.original_destination_connection_id = Some(*original_dcid);
        server_params.initial_source_connection_id = Some(scid);

        // RFC 9369 §4.1: include version_information for Compatible VN
        server_params.version_information = Some(
            crate::net::handler::quic::transport::params::VersionInformation {
                chosen_version: version,
                other_versions: vec![
                    crate::net::handler::quic::transport::version::QUIC_VERSION_1,
                    crate::net::handler::quic::transport::version::QUIC_VERSION_2,
                ],
            },
        );

        let mut params_buf = [0u8; 512];
        let params_len = server_params.encode(&mut params_buf);

        let crypto = CryptoState::new_server(
            listener.tls_config.clone(),
            &params_buf[..params_len],
            rustls_version,
        )
        .ok()?;

        let transport_params = listener.transport_params.clone();
        let accept_queue = listener.accept_queue.clone();

        // RFC 9000 §7.2: server uses client's SCID as its DCID
        let mut conn =
            QuicConnectionState::new(*client_scid, Side::Server, transport_params, 1200, now);
        conn.keys.initial = Some(initial_keys);
        conn.crypto = Some(crypto);
        conn.scid = scid;
        conn.scid_set.push(scid);
        conn.cid_manager = super::cid_lifecycle::CidManager::new(scid, 2);
        conn.local_addr = local_addr;
        conn.remote_addr = remote_addr;
        conn.local_port = local_port;
        conn.remote_port = remote_port;
        conn.local_mac = local_mac;
        conn.remote_mac = remote_mac;
        conn.accept_queue = accept_queue;
        conn.version = version;
        conn.token_secret = Some(listener.token_secret);

        let key = self.insert_connection(conn);
        // Also map the original DCID so Initial retransmissions route here
        self.cid_map.insert(*original_dcid, key);
        Some(key)
    }

    /// Create a new client-side QUIC connection and initiate the handshake.
    ///
    /// Generates connection IDs, derives initial keys, performs the TLS ClientHello,
    /// and buffers the initial CRYPTO data for sending.
    /// Returns the slab key on success.
    pub fn initiate_connection(
        &mut self,
        remote_addr: IpAddress,
        remote_port: u16,
        local_addr: IpAddress,
        local_port: u16,
        local_mac: MacAddress,
        remote_mac: MacAddress,
        server_name: &str,
        tls_config: Arc<ClientConfig>,
        transport_params: TransportParams,
        now: Instant,
    ) -> Option<usize> {
        use crate::net::handler::quic::connection::Side;
        use crate::net::handler::quic::crypto::initial_keys::derive_initial_keys;
        use crate::net::handler::quic::crypto::keys::{DirectionalKey, KeyPair};
        use crate::net::handler::quic::crypto::tls::CryptoState;
        use ring::rand::SecureRandom;

        let rng = ring::rand::SystemRandom::new();

        // Determine CID length from transport params or fall back to handler default
        let cid_len = transport_params
            .cid_length
            .map(|l| l as usize)
            .unwrap_or(self.local_cid_len);

        // Update handler's SCID length so short-header parsing uses correct length
        self.local_cid_len = cid_len;

        // Generate random DCID (destination, for Initial key derivation).
        // RFC 9000 §7.2: Initial DCID MUST be at least 8 bytes, regardless of
        // configured CID length. The cid_length only affects our SCID.
        let dcid_len = cid_len.max(8);
        let mut dcid_buf = [0u8; 20];
        rng.fill(&mut dcid_buf[..dcid_len]).ok()?;
        let dcid = ConnectionId::from_slice(&dcid_buf[..dcid_len]);

        // Generate random SCID (our identifier) using configured CID length
        let mut scid_buf = [0u8; 20];
        if cid_len > 0 {
            rng.fill(&mut scid_buf[..cid_len]).ok()?;
        }
        let scid = ConnectionId::from_slice(&scid_buf[..cid_len]);

        let rustls_version = rustls::quic::Version::V1;

        // Derive initial keys from DCID (RFC 9001 §5.2)
        let (local_dk, remote_dk) =
            derive_initial_keys(dcid.as_bytes(), rustls::Side::Client, rustls_version);
        let initial_keys = KeyPair {
            local: DirectionalKey::from_rustls(local_dk),
            remote: DirectionalKey::from_rustls(remote_dk),
        };

        // Encode transport params with our SCID
        let mut client_params = transport_params.clone();
        client_params.initial_source_connection_id = Some(scid);

        // RFC 9369 §4.1: include version_information for Compatible VN
        client_params.version_information = Some(
            crate::net::handler::quic::transport::params::VersionInformation {
                chosen_version: crate::net::handler::quic::transport::version::QUIC_VERSION_1,
                other_versions: vec![
                    crate::net::handler::quic::transport::version::QUIC_VERSION_1,
                    crate::net::handler::quic::transport::version::QUIC_VERSION_2,
                ],
            },
        );

        let mut params_buf = [0u8; 512];
        let params_len = client_params.encode(&mut params_buf);

        // Create client-side crypto state; returns (CryptoState, initial ClientHello data)
        let (crypto, initial_data) = CryptoState::new_client(
            tls_config.clone(),
            server_name,
            &params_buf[..params_len],
            rustls_version,
        )
        .ok()?;

        let mut conn = QuicConnectionState::new(dcid, Side::Client, transport_params, 1200, now);
        conn.keys.initial = Some(initial_keys);
        conn.crypto = Some(crypto);
        conn.scid = scid;
        conn.scid_set.push(scid);
        conn.cid_manager = super::cid_lifecycle::CidManager::new(scid, 2);
        conn.local_addr = local_addr;
        conn.remote_addr = remote_addr;
        conn.local_port = local_port;
        conn.remote_port = remote_port;
        conn.local_mac = local_mac;
        conn.remote_mac = remote_mac;
        conn.client_config = Some(tls_config);
        conn.server_name = Some(server_name.to_string());
        conn.version = crate::net::handler::quic::transport::version::QUIC_VERSION_1;

        // Client is not subject to anti-amplification limits (RFC 9000 §8.1)
        conn.path.amplification.set_validated();

        // Buffer the ClientHello CRYPTO data for the Initial space (index 0)
        conn.pending_crypto[0] = initial_data;

        let key = self.insert_connection(conn);
        Some(key)
    }
}
