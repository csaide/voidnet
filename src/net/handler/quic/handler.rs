use coarsetime::Instant;
use rustc_hash::FxHashMap;
use slab::Slab;
use std::sync::Arc;

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

pub struct ListenerState {
    pub tls_config: Arc<rustls::ServerConfig>,
    pub transport_params: TransportParams,
    pub accept_queue: Option<LocalQueue<usize>>,
}

/// QUIC protocol handler.
///
/// Manages the connection table, listener table, and dispatches
/// incoming QUIC packets through the appropriate state machine.
pub struct QuicHandler {
    pub(crate) connections: Slab<QuicConnectionState>,
    pub(crate) cid_map: FxHashMap<ConnectionId, usize>,
    pub(crate) listeners: FxHashMap<u16, ListenerState>,
    pub(crate) rx_offload: bool,
    pub(crate) tx_offload: bool,
}

impl QuicHandler {
    pub fn new(rx_offload: bool, tx_offload: bool) -> Self {
        Self {
            connections: Slab::new(),
            cid_map: FxHashMap::default(),
            listeners: FxHashMap::default(),
            rx_offload,
            tx_offload,
        }
    }

    /// Check if a UDP destination port is registered as a QUIC listener.
    pub fn is_quic_port(&self, port: u16) -> bool {
        self.listeners.contains_key(&port)
    }

    /// Register a QUIC listener on a port.
    pub fn listen(
        &mut self,
        port: u16,
        tls_config: Arc<rustls::ServerConfig>,
        params: TransportParams,
    ) {
        self.listeners.insert(
            port,
            ListenerState {
                tls_config,
                transport_params: params,
                accept_queue: None,
            },
        );
    }

    /// Register a QUIC listener on a port with an external accept queue.
    /// The accept queue receives connection slab keys when handshakes complete.
    pub fn listen_with_queue(
        &mut self,
        port: u16,
        tls_config: Arc<rustls::ServerConfig>,
        params: TransportParams,
        accept_queue: LocalQueue<usize>,
    ) {
        self.listeners.insert(
            port,
            ListenerState {
                tls_config,
                transport_params: params,
                accept_queue: Some(accept_queue),
            },
        );
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
                Some(cid) => cid.to_owned(),
                None => {
                    rx_return.push(frame);
                    return;
                }
            }
        } else {
            // Short header: DCID starts at byte 1, length is our SCID length
            let scid_len = 8; // default SCID length we generate
            if quic_data.len() < 1 + scid_len {
                rx_return.push(frame);
                return;
            }
            crate::net::handler::quic::connection_id::ConnectionId::from_slice(
                &quic_data[1..1 + scid_len],
            )
        };

        // Look up existing connection
        if let Some(&key) = self.cid_map.get(&dcid) {
            let mut frame_data = frame;
            let quic_payload = &mut frame_data[quic_offset..];
            let conn = &mut self.connections[key];
            processor::process_packet(conn, quic_payload, datagram_len, now);
            processor::generate_packets(conn, key, now, wheel, free_frames, tx_return);
            rx_return.push(frame_data);
        } else if !quic_data.is_empty() && wire_quic::is_long_header(quic_data[0]) {
            // Potential new connection — check if Initial + listener exists
            if self.listeners.contains_key(&dst_port) && datagram_len >= 1200 {
                // Extract version from long header bytes [1..5]
                let version = if quic_data.len() >= 5 {
                    u32::from_be_bytes([quic_data[1], quic_data[2], quic_data[3], quic_data[4]])
                } else {
                    0x00000001 // fallback to v1
                };
                if let Some(key) = self.create_server_connection(
                    &dcid, dst_addr, src_addr, dst_port, src_port, src_mac, dst_mac, now, version,
                ) {
                    let conn = &mut self.connections[key];
                    let mut frame_data = frame;
                    let quic_payload = &mut frame_data[quic_offset..];
                    processor::process_packet(conn, quic_payload, datagram_len, now);
                    processor::generate_packets(conn, key, now, wheel, free_frames, tx_return);
                    rx_return.push(frame_data);
                } else {
                    rx_return.push(frame);
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
                Some(cid) => cid.to_owned(),
                None => {
                    rx_return.push(frame);
                    return;
                }
            }
        } else {
            // Short header: DCID starts at byte 1, length is our SCID length
            let scid_len = 8; // default SCID length we generate
            if quic_data.len() < 1 + scid_len {
                rx_return.push(frame);
                return;
            }
            crate::net::handler::quic::connection_id::ConnectionId::from_slice(
                &quic_data[1..1 + scid_len],
            )
        };

        // Look up existing connection
        if let Some(&key) = self.cid_map.get(&dcid) {
            let mut frame_data = frame;
            let quic_payload = &mut frame_data[quic_offset..];
            let conn = &mut self.connections[key];
            processor::process_packet(conn, quic_payload, datagram_len, now);
            processor::generate_packets(conn, key, now, wheel, free_frames, tx_return);
            rx_return.push(frame_data);
        } else if !quic_data.is_empty() && wire_quic::is_long_header(quic_data[0]) {
            // Potential new connection — check if Initial + listener exists
            if self.listeners.contains_key(&dst_port) && datagram_len >= 1200 {
                // Extract version from long header bytes [1..5]
                let version = if quic_data.len() >= 5 {
                    u32::from_be_bytes([quic_data[1], quic_data[2], quic_data[3], quic_data[4]])
                } else {
                    0x00000001 // fallback to v1
                };
                if let Some(key) = self.create_server_connection(
                    &dcid, dst_addr, src_addr, dst_port, src_port, src_mac, dst_mac, now, version,
                ) {
                    let conn = &mut self.connections[key];
                    let mut frame_data = frame;
                    let quic_payload = &mut frame_data[quic_offset..];
                    processor::process_packet(conn, quic_payload, datagram_len, now);
                    processor::generate_packets(conn, key, now, wheel, free_frames, tx_return);
                    rx_return.push(frame_data);
                } else {
                    rx_return.push(frame);
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
        for (key, conn) in self.connections.iter_mut() {
            if processor::has_pending_data_any(conn) {
                processor::generate_packets(conn, key, now, wheel, free_frames, tx_return);
            }
        }
    }

    /// Evict stale connections (called periodically).
    pub fn evict_stale(&mut self, now: Instant) {
        let stale_keys: smallvec::SmallVec<[usize; 8]> = self
            .connections
            .iter()
            .filter(|(_, conn)| {
                let elapsed = now.duration_since(conn.last_activity);
                elapsed > conn.idle_timeout
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

    /// Insert a new connection, returning its slab key.
    pub fn insert_connection(&mut self, conn: QuicConnectionState) -> usize {
        let key = self.connections.insert(conn);
        let conn = &self.connections[key];
        self.cid_map.insert(conn.dcid, key);
        for cid in conn.scid_set.iter() {
            self.cid_map.insert(*cid, key);
        }
        key
    }

    /// Remove a connection by slab key.
    pub fn remove_connection_by_key(&mut self, key: usize) -> Option<QuicConnectionState> {
        if self.connections.contains(key) {
            let conn = self.connections.remove(key);
            self.cid_map.remove(&conn.dcid);
            // Also remove all SCIDs
            for cid in conn.scid_set.iter() {
                self.cid_map.remove(cid);
            }
            Some(conn)
        } else {
            None
        }
    }

    /// Create a new server-side connection from an incoming Initial packet.
    ///
    /// `client_dcid` is the DCID the client used (becomes our remote CID).
    /// Returns the slab key on success.
    fn create_server_connection(
        &mut self,
        client_dcid: &ConnectionId,
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

        // Map version to rustls quic version for key derivation
        let rustls_version =
            if version == crate::net::handler::quic::transport::version::QUIC_VERSION_2 {
                rustls::quic::Version::V2
            } else {
                rustls::quic::Version::V1
            };

        // Derive initial keys (server side)
        let (local_dk, remote_dk) =
            derive_initial_keys(client_dcid.as_bytes(), rustls::Side::Server, rustls_version);
        let initial_keys = KeyPair {
            local: DirectionalKey::from_rustls(local_dk),
            remote: DirectionalKey::from_rustls(remote_dk),
        };

        // Generate server SCID (8 random bytes)
        let mut scid_bytes = [0u8; 8];
        ring::rand::SystemRandom::new().fill(&mut scid_bytes).ok()?;
        let scid = ConnectionId::from_slice(&scid_bytes);

        // Encode local transport params
        let mut params_buf = [0u8; 512];
        let params_len = listener.transport_params.encode(&mut params_buf);

        // Create CryptoState
        let crypto = CryptoState::new_server(
            listener.tls_config.clone(),
            &params_buf[..params_len],
            rustls_version,
        )
        .ok()?;

        // Clone params and accept queue before borrowing listener is released
        let transport_params = listener.transport_params.clone();
        let accept_queue = listener.accept_queue.clone();

        // Create connection state
        let mut conn = QuicConnectionState::new(
            *client_dcid,
            Side::Server,
            transport_params,
            1200, // max_datagram_size
            now,
        );
        conn.keys.initial = Some(initial_keys);
        conn.crypto = Some(crypto);
        conn.scid = scid;
        conn.scid_set.push(scid);
        conn.local_addr = local_addr;
        conn.remote_addr = remote_addr;
        conn.local_port = local_port;
        conn.remote_port = remote_port;
        conn.local_mac = local_mac;
        conn.remote_mac = remote_mac;
        conn.accept_queue = accept_queue;
        conn.version = version;

        Some(self.insert_connection(conn))
    }
}
