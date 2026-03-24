use coarsetime::{Duration, Instant};
use rustc_hash::FxHashMap;
use slab::Slab;
use std::sync::Arc;

use rustls::ClientConfig;

use crate::net::congestion::CongestionController;
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
    /// Length of SCIDs we generate (used for short-header DCID parsing).
    pub(crate) local_cid_len: usize,
    /// Maximum number of concurrent connections (DoS protection).
    pub(crate) max_connections: usize,
    /// Connection count threshold above which new Initial packets are dropped
    /// (future work: send Retry packets for address validation).
    pub(crate) retry_threshold: usize,
    /// Per-IP connection counter for rate limiting.
    pub(crate) per_ip_conn_count: FxHashMap<IpAddress, u16>,
    /// Maximum connections allowed from a single IP address.
    pub(crate) max_connections_per_ip: u16,
    /// Maximum age of a Retry token before it's considered expired (default 30s).
    pub(crate) retry_token_max_age: coarsetime::Duration,
    /// Server secret for generating stateless reset tokens (RFC 9000 §10.3).
    /// Used to deterministically derive reset tokens from CIDs.
    pub(crate) stateless_reset_secret: [u8; 32],
}

impl QuicHandler {
    pub fn new(_rx_offload: bool, _tx_offload: bool) -> Self {
        Self {
            connections: Slab::new(),
            cid_map: FxHashMap::default(),
            five_tuple_map: FxHashMap::default(),
            listeners: FxHashMap::default(),
            local_cid_len: 8,
            max_connections: 10_000,
            retry_threshold: 5_000,
            per_ip_conn_count: FxHashMap::default(),
            max_connections_per_ip: 100,
            retry_token_max_age: coarsetime::Duration::from_secs(30),
            stateless_reset_secret: Self::generate_token_secret(),
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

    /// Generate a stateless reset token for a given CID (RFC 9000 §10.3.2).
    pub(crate) fn generate_reset_token_for_cid(&self, cid: &ConnectionId) -> [u8; 16] {
        crate::net::handler::quic::crypto::stateless_reset::generate_reset_token(
            cid.as_bytes(),
            &self.stateless_reset_secret,
        )
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
            if (src_addr != conn.remote_addr || src_port != conn.remote_port)
                && conn.key_update.handshake_confirmed
            {
                // RFC 9000 §9: ignore migration if peer set disable_active_migration
                // (NAT rebinding is still allowed per §9.3).
                let peer_disabled = conn
                    .peer_params
                    .as_ref()
                    .is_some_and(|p| p.disable_active_migration);

                // NAT rebinding vs intentional migration (RFC 9000 §9.3)
                let port_only_change = src_addr == conn.remote_addr && src_port != conn.remote_port;
                if port_only_change {
                    // NAT rebinding — just update port, no validation needed
                    conn.remote_port = src_port;
                } else if !peer_disabled {
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
                    // Initiate path validation on the NEW path
                    let _challenge = conn.path.initiate_validation(now);
                    conn.pending_path_response = None; // clear any stale response

                    // RFC 9000 §9.3.3: validate the PREVIOUS path too
                    let prev_challenge = crate::net::handler::quic::path::generate_challenge();
                    conn.pending_prev_path_challenge = Some(prev_challenge);

                    // RFC 9000 §9.4: reset congestion controller and RTT for the new path
                    conn.congestion =
                        super::transport::congestion::QuicCubic::new(conn.max_udp_payload as usize);
                    conn.loss.reset_rtt();

                    // Reset PMTU state for the new path
                    if conn.pmtu_probing_enabled {
                        conn.pmtu.reset(conn.pmtu_ceiling);
                        conn.max_udp_payload = 1200;
                        conn.congestion.on_mtu_update(1200);
                    }

                    // CID rotation for linkability prevention
                    if let Some((new_cid, _seq)) = conn.scid_set.pick_unused(&conn.scid) {
                        use crate::net::handler::quic::connection::MigrationAction;
                        let old_cid = conn.scid;
                        conn.scid = new_cid;
                        conn.pending_migration = Some(MigrationAction { old_cid, new_cid });
                    }
                }
                // else: peer disabled migration and this is a full address change — ignore
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
                    // Extract client's DCID and SCID from the long header.
                    let (dcid_buf, dcid_len, scid_buf, scid_len) =
                        match Self::extract_cids(quic_data) {
                            Some(cids) => cids,
                            None => {
                                rx_return.push(frame);
                                return;
                            }
                        };
                    let client_scid = ConnectionId::from_slice(&scid_buf[..scid_len]);

                    // RFC 9000 §8.1: Retry-based address validation when under load.
                    // Between retry_threshold and max_connections, require a valid Retry token.
                    let in_retry_zone = self.connections.len() >= self.retry_threshold
                        && self.connections.len() < self.max_connections;

                    if in_retry_zone {
                        // Extract token from the Initial packet
                        let token = Self::extract_initial_token(quic_data).unwrap_or(&[]);

                        if token.is_empty() {
                            // No token — send a Retry packet
                            let mut ip_buf = [0u8; 16];
                            let client_ip = src_addr.ip_bytes(&mut ip_buf);
                            let mut retry_buf = [0u8; 512];
                            if let Some(retry_len) = self.generate_retry_packet(
                                &mut retry_buf,
                                &dcid_buf[..dcid_len],
                                &scid_buf[..scid_len],
                                client_ip,
                                dst_port,
                                version,
                            ) {
                                self.send_retry_ipv4(
                                    frame,
                                    &retry_buf[..retry_len],
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
                            } else {
                                rx_return.push(frame);
                            }
                            return;
                        }

                        // Token present — validate it
                        match self.validate_retry_token(&token, &src_addr, dst_port, version) {
                            Some(odcid) => {
                                // Valid Retry token — create connection with original DCID.
                                // The current dcid is the SCID from the Retry packet (RFC 9000 §7.3).
                                let retry_scid = ConnectionId::from_slice(&dcid_buf[..dcid_len]);
                                if let Some(key) = self.create_server_connection(
                                    &odcid,
                                    &client_scid,
                                    dst_addr,
                                    src_addr,
                                    dst_port,
                                    src_port,
                                    src_mac,
                                    dst_mac,
                                    now,
                                    version,
                                    Some(&odcid),
                                    Some(&retry_scid),
                                ) {
                                    let conn = &mut self.connections[key];
                                    let mut frame_data = frame;
                                    let quic_payload = &mut frame_data[quic_offset..];
                                    processor::process_packet(
                                        conn,
                                        quic_payload,
                                        datagram_len,
                                        now,
                                    );
                                    rx_return.push(frame_data);
                                    let conn = &mut self.connections[key];
                                    processor::generate_packets(
                                        conn,
                                        key,
                                        now,
                                        wheel,
                                        free_frames,
                                        tx_return,
                                    );
                                    self.sync_cid_map(key);
                                } else {
                                    rx_return.push(frame);
                                }
                            }
                            None => {
                                // Invalid/expired token — drop silently
                                rx_return.push(frame);
                            }
                        }
                    } else {
                        // Below retry threshold — accept without token validation
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
                            None,
                            None,
                        ) {
                            let conn = &mut self.connections[key];
                            let mut frame_data = frame;
                            let quic_payload = &mut frame_data[quic_offset..];
                            processor::process_packet(conn, quic_payload, datagram_len, now);
                            rx_return.push(frame_data);
                            let conn = &mut self.connections[key];
                            processor::generate_packets(
                                conn,
                                key,
                                now,
                                wheel,
                                free_frames,
                                tx_return,
                            );
                            self.sync_cid_map(key);
                        } else {
                            rx_return.push(frame);
                        }
                    }
                }
            } else {
                rx_return.push(frame);
            }
        } else {
            // Short-header packet for unknown CID — send stateless reset (RFC 9000 §10.3).
            // Only send if there are listeners (we're acting as a server) and packet is
            // large enough to hide the reset token (must be shorter than triggering packet).
            if !quic_data.is_empty()
                && !wire_quic::is_long_header(quic_data[0])
                && !self.listeners.is_empty()
                && quic_data.len() > 41
            {
                // RFC 9000 §10.3.1: stateless reset is at least 21 bytes
                // (1 byte unpredictable + 16 byte token + some random).
                // Must be shorter than the packet that triggered it.
                let token = self.generate_reset_token_for_cid(&dcid);
                let reset_len = 21usize.min(quic_data.len() - 1);
                let random_len = reset_len - 16;
                let mut reset_buf = [0u8; 64];
                // First byte: bit 7 = 0, bit 6 = 1, rest random (looks like short header)
                use ring::rand::SecureRandom;
                let _ = ring::rand::SystemRandom::new().fill(&mut reset_buf[..random_len]);
                // Ensure it looks like a short header (bit 7 clear, fixed bit set)
                reset_buf[0] = (reset_buf[0] & 0x3F) | 0x40;
                // Last 16 bytes = stateless reset token
                reset_buf[random_len..reset_len].copy_from_slice(&token);
                // Rewrite the frame in-place with the reset packet
                let eth_len = std::mem::size_of::<crate::net::wire::ethernet::EthernetFrame>();
                let ip_len = crate::net::wire::ip::IPV4_MIN_HEADER_LEN;
                let udp_start = eth_len + ip_len;
                let quic_start = udp_start + 8;
                let total_len = quic_start + reset_len;
                if frame.capacity() >= total_len {
                    let mut frame_data = frame;
                    unsafe { frame_data.set_len(frame_data.capacity()) };
                    frame_data[quic_start..quic_start + reset_len]
                        .copy_from_slice(&reset_buf[..reset_len]);
                    // Swap src/dst for response
                    {
                        use crate::net::wire::ethernet::EthernetFrame;
                        use crate::net::wire::ip::Ipv4Header;
                        use crate::net::wire::udp::UdpHeader;
                        let eth = EthernetFrame::from_bytes_mut(&mut frame_data);
                        std::mem::swap(&mut eth.src_mac, &mut eth.dst_mac);
                        let ip = Ipv4Header::from_bytes_mut(&mut frame_data);
                        std::mem::swap(&mut ip.src_addr, &mut ip.dst_addr);
                        let total_ip_len = (ip_len + 8 + reset_len) as u16;
                        ip.total_length = total_ip_len.to_be_bytes();
                        ip.fill_checksum();
                        let udp =
                            unsafe { UdpHeader::from_bytes_at_mut(&mut frame_data, udp_start) };
                        let old_src = udp.src_port();
                        let old_dst = udp.dst_port();
                        udp.src_port = old_dst.to_be_bytes();
                        udp.dst_port = old_src.to_be_bytes();
                        udp.length = ((8 + reset_len) as u16).to_be_bytes();
                        udp.checksum = [0, 0]; // UDP checksum optional for IPv4
                    }
                    unsafe { frame_data.set_len(total_len) };
                    tx_return.push(frame_data);
                } else {
                    rx_return.push(frame);
                }
            } else {
                rx_return.push(frame);
            }
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
            if (src_addr != conn.remote_addr || src_port != conn.remote_port)
                && conn.key_update.handshake_confirmed
            {
                // RFC 9000 §9: ignore migration if peer set disable_active_migration
                // (NAT rebinding is still allowed per §9.3).
                let peer_disabled = conn
                    .peer_params
                    .as_ref()
                    .is_some_and(|p| p.disable_active_migration);

                // NAT rebinding vs intentional migration (RFC 9000 §9.3)
                let port_only_change = src_addr == conn.remote_addr && src_port != conn.remote_port;
                if port_only_change {
                    // NAT rebinding — just update port, no validation needed
                    conn.remote_port = src_port;
                } else if !peer_disabled {
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
                    // Initiate path validation on the NEW path
                    let _challenge = conn.path.initiate_validation(now);
                    conn.pending_path_response = None; // clear any stale response

                    // RFC 9000 §9.3.3: validate the PREVIOUS path too
                    let prev_challenge = crate::net::handler::quic::path::generate_challenge();
                    conn.pending_prev_path_challenge = Some(prev_challenge);

                    // RFC 9000 §9.4: reset congestion controller and RTT for the new path
                    conn.congestion =
                        super::transport::congestion::QuicCubic::new(conn.max_udp_payload as usize);
                    conn.loss.reset_rtt();

                    // Reset PMTU state for the new path
                    if conn.pmtu_probing_enabled {
                        conn.pmtu.reset(conn.pmtu_ceiling);
                        conn.max_udp_payload = 1200;
                        conn.congestion.on_mtu_update(1200);
                    }

                    // CID rotation for linkability prevention
                    if let Some((new_cid, _seq)) = conn.scid_set.pick_unused(&conn.scid) {
                        use crate::net::handler::quic::connection::MigrationAction;
                        let old_cid = conn.scid;
                        conn.scid = new_cid;
                        conn.pending_migration = Some(MigrationAction { old_cid, new_cid });
                    }
                }
                // else: peer disabled migration and this is a full address change — ignore
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
                    // Extract client's DCID and SCID from the long header.
                    let (dcid_buf, dcid_len, scid_buf, scid_len) =
                        match Self::extract_cids(quic_data) {
                            Some(cids) => cids,
                            None => {
                                rx_return.push(frame);
                                return;
                            }
                        };
                    let client_scid = ConnectionId::from_slice(&scid_buf[..scid_len]);

                    // RFC 9000 §8.1: Retry-based address validation when under load.
                    let in_retry_zone = self.connections.len() >= self.retry_threshold
                        && self.connections.len() < self.max_connections;

                    if in_retry_zone {
                        let token = Self::extract_initial_token(quic_data).unwrap_or(&[]);

                        if token.is_empty() {
                            // No token — send a Retry packet
                            let mut ip_buf = [0u8; 16];
                            let client_ip = src_addr.ip_bytes(&mut ip_buf);
                            let mut retry_buf = [0u8; 512];
                            if let Some(retry_len) = self.generate_retry_packet(
                                &mut retry_buf,
                                &dcid_buf[..dcid_len],
                                &scid_buf[..scid_len],
                                client_ip,
                                dst_port,
                                version,
                            ) {
                                self.send_retry_ipv6(
                                    frame,
                                    &retry_buf[..retry_len],
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
                            } else {
                                rx_return.push(frame);
                            }
                            return;
                        }

                        // Token present — validate it
                        match self.validate_retry_token(&token, &src_addr, dst_port, version) {
                            Some(odcid) => {
                                // The current dcid is the SCID from the Retry packet (RFC 9000 §7.3).
                                let retry_scid = ConnectionId::from_slice(&dcid_buf[..dcid_len]);
                                if let Some(key) = self.create_server_connection(
                                    &odcid,
                                    &client_scid,
                                    dst_addr,
                                    src_addr,
                                    dst_port,
                                    src_port,
                                    src_mac,
                                    dst_mac,
                                    now,
                                    version,
                                    Some(&odcid),
                                    Some(&retry_scid),
                                ) {
                                    let conn = &mut self.connections[key];
                                    let mut frame_data = frame;
                                    let quic_payload = &mut frame_data[quic_offset..];
                                    processor::process_packet(
                                        conn,
                                        quic_payload,
                                        datagram_len,
                                        now,
                                    );
                                    rx_return.push(frame_data);
                                    let conn = &mut self.connections[key];
                                    processor::generate_packets(
                                        conn,
                                        key,
                                        now,
                                        wheel,
                                        free_frames,
                                        tx_return,
                                    );
                                    self.sync_cid_map(key);
                                } else {
                                    rx_return.push(frame);
                                }
                            }
                            None => {
                                rx_return.push(frame);
                            }
                        }
                    } else {
                        // Below retry threshold — accept without token validation
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
                            None,
                            None,
                        ) {
                            let conn = &mut self.connections[key];
                            let mut frame_data = frame;
                            let quic_payload = &mut frame_data[quic_offset..];
                            processor::process_packet(conn, quic_payload, datagram_len, now);
                            rx_return.push(frame_data);
                            let conn = &mut self.connections[key];
                            processor::generate_packets(
                                conn,
                                key,
                                now,
                                wheel,
                                free_frames,
                                tx_return,
                            );
                            self.sync_cid_map(key);
                        } else {
                            rx_return.push(frame);
                        }
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
        // Single-pass: iterate by slab index to avoid collecting keys.
        let mut key = 0;
        while key < self.connections.capacity() {
            if let Some(conn) = self.connections.get(key) {
                if processor::has_pending_data_any(conn) {
                    let conn = self.connections.get_mut(key).unwrap();
                    processor::generate_packets(conn, key, now, wheel, free_frames, tx_return);
                    self.sync_cid_map(key);
                }
            }
            key += 1;
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

    /// Extract the token from an Initial packet's QUIC payload.
    ///
    /// The Initial packet long header layout after version+CIDs is:
    ///   token_length(varint) + token(token_length bytes)
    /// Returns `None` if the payload is malformed or not an Initial packet.
    pub(crate) fn extract_initial_token(quic_data: &[u8]) -> Option<&[u8]> {
        use crate::net::handler::quic::transport::varint::decode_varint;

        // Need at least: first_byte(1) + version(4) + dcid_len(1)
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
        let scid_end = dcid_end + 1 + scid_len;
        if quic_data.len() < scid_end {
            return None;
        }

        // Now at the token length varint
        let rest = &quic_data[scid_end..];
        let (token_len, consumed) = decode_varint(rest)?;
        let token_len = token_len as usize;
        if token_len == 0 {
            return Some(&[]);
        }
        if rest.len() < consumed + token_len {
            return None;
        }
        Some(&rest[consumed..consumed + token_len])
    }

    /// Generate a Retry packet for the given client parameters.
    ///
    /// Encrypts a Retry token containing the original DCID, client IP, version,
    /// and a timestamp, then wraps it in a Retry packet with integrity tag.
    /// Returns `None` if the listener isn't found or token encryption fails.
    pub(crate) fn generate_retry_packet(
        &self,
        out_buf: &mut [u8],
        odcid: &[u8],
        client_scid: &[u8],
        client_ip: &[u8],
        local_port: u16,
        version: u32,
    ) -> Option<usize> {
        use crate::net::handler::quic::token_crypto::{TokenType, encrypt_token};
        use crate::net::handler::quic::transport::packet_builder::build_retry_packet;
        use ring::rand::SecureRandom;

        let listener = self.listeners.get(&local_port)?;

        // Generate a new server SCID for the Retry packet
        let mut new_scid = [0u8; 8];
        ring::rand::SystemRandom::new().fill(&mut new_scid).ok()?;

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let token = encrypt_token(
            &listener.token_secret,
            TokenType::Retry,
            client_ip,
            now_secs,
            odcid,
            version,
        )
        .ok()?;

        // RFC 9000 §17.2.5: Retry packet DCID = client's SCID,
        // Retry packet SCID = new server CID (different from original DCID)
        build_retry_packet(
            out_buf,
            version,
            client_scid, // DCID in Retry = client's SCID
            &new_scid,   // SCID in Retry = new server-chosen CID
            odcid,       // original DCID for integrity tag
            &token,
        )
    }

    /// Decrypt and validate a Retry token from an Initial packet.
    ///
    /// Checks that the token type is Retry, the client IP matches, the version
    /// matches, and the token hasn't expired. Returns the original DCID on success.
    pub(crate) fn validate_retry_token(
        &self,
        token_bytes: &[u8],
        client_addr: &IpAddress,
        local_port: u16,
        version: u32,
    ) -> Option<ConnectionId> {
        use crate::net::handler::quic::token_crypto::{TokenType, decrypt_token};

        let listener = self.listeners.get(&local_port)?;
        let dt = decrypt_token(&listener.token_secret, token_bytes).ok()?;

        // Must be a Retry token
        if dt.token_type != TokenType::Retry {
            return None;
        }

        // Version must match
        if dt.version != version {
            return None;
        }

        // Client IP must match
        let mut ip_buf = [0u8; 16];
        let client_ip_bytes = client_addr.ip_bytes(&mut ip_buf);
        if dt.client_ip_bytes() != client_ip_bytes {
            return None;
        }

        // Check expiry using wall-clock time (matches encrypt_token's SystemTime)
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let max_age_secs = self.retry_token_max_age.as_secs();
        if now_secs.saturating_sub(dt.timestamp_secs) > max_age_secs {
            return None;
        }

        if dt.dcid_len > 20 {
            return None;
        }
        Some(ConnectionId::from_slice(dt.dcid_bytes()))
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

    /// Build and send a Retry packet using the incoming IPv4 frame buffer.
    /// Mirrors the pattern of `build_vn_ipv4` — reuses the RX frame.
    fn send_retry_ipv4<'umem>(
        &self,
        mut frame: Frame<'umem>,
        retry_packet: &[u8],
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
        let udp_len = 8 + retry_packet.len();
        let total = quic_offset + retry_packet.len();
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
        frame[quic_offset..quic_offset + retry_packet.len()].copy_from_slice(retry_packet);
        unsafe { frame.set_len(total) };
        tx_return.push(frame);
    }

    /// Build and send a Retry packet using the incoming IPv6 frame buffer.
    /// Mirrors the pattern of `build_vn_ipv6` — reuses the RX frame.
    fn send_retry_ipv6<'umem>(
        &self,
        mut frame: Frame<'umem>,
        retry_packet: &[u8],
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
        let udp_len = 8 + retry_packet.len();
        let total = quic_offset + retry_packet.len();
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
        frame[quic_offset..quic_offset + retry_packet.len()].copy_from_slice(retry_packet);
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
            // Decrement per-IP connection counter
            if let Some(count) = self.per_ip_conn_count.get_mut(&conn.remote_addr) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.per_ip_conn_count.remove(&conn.remote_addr);
                }
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
    /// `retry_odcid`: if this connection was validated via Retry, the original DCID from the Retry
    ///   token (used for `original_destination_connection_id` transport param, RFC 9000 §7.3).
    /// `retry_scid`: the SCID from the Retry packet (= client's new DCID, used for
    ///   `retry_source_connection_id` transport param, RFC 9000 §7.3).
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
        retry_odcid: Option<&ConnectionId>,
        retry_scid: Option<&ConnectionId>,
    ) -> Option<usize> {
        use crate::net::handler::quic::connection::Side;
        use crate::net::handler::quic::crypto::initial_keys::derive_initial_keys;
        use crate::net::handler::quic::crypto::keys::{DirectionalKey, KeyPair};
        use crate::net::handler::quic::crypto::tls::CryptoState;
        use ring::rand::SecureRandom;

        // DoS protection: refuse new connections if at capacity
        if self.connections.len() >= self.max_connections {
            return None;
        }

        // Note: retry_threshold check is now done by the caller (process_ipv4/ipv6),
        // which sends Retry packets for address validation (RFC 9000 §8.1).

        // Per-IP rate limiting: reject if this IP has too many connections
        let ip_count = self
            .per_ip_conn_count
            .get(&remote_addr)
            .copied()
            .unwrap_or(0);
        if ip_count >= self.max_connections_per_ip {
            return None;
        }

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
        // RFC 9000 §7.3: after Retry, use the original DCID from the token and include
        // retry_source_connection_id (the SCID from the Retry packet).
        if let (Some(rodcid), Some(rscid)) = (retry_odcid, retry_scid) {
            server_params.original_destination_connection_id = Some(*rodcid);
            server_params.retry_source_connection_id = Some(*rscid);
        } else {
            server_params.original_destination_connection_id = Some(*original_dcid);
        }
        server_params.initial_source_connection_id = Some(scid);
        // RFC 9000 §10.3.2: include stateless reset token for our SCID
        server_params.stateless_reset_token = Some(self.generate_reset_token_for_cid(&scid));

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

        // Track per-IP connection count
        *self.per_ip_conn_count.entry(remote_addr).or_insert(0) += 1;

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

    /// Notify QUIC connections about a PMTU change for a given peer IP.
    pub fn notify_pmtu_update(&mut self, peer_addr: &IpAddress, new_link_mtu: u32) {
        let ip_overhead: u32 = match peer_addr {
            IpAddress::V4(_) => 20 + 8,
            IpAddress::V6(_) => 40 + 8,
        };
        let quic_mtu = new_link_mtu.saturating_sub(ip_overhead) as u16;

        for (_key, conn) in self.connections.iter_mut() {
            if conn.remote_addr == *peer_addr && conn.pmtu_probing_enabled {
                conn.pmtu.on_icmp_reduction(quic_mtu);
                conn.max_udp_payload = conn.pmtu.current_mtu();
                conn.congestion
                    .on_mtu_update(conn.pmtu.current_mtu() as usize);
            }
        }
    }
}
