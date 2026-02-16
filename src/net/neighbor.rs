use std::{
    collections::HashMap,
    mem::size_of,
    net::IpAddr,
    time::{Duration, Instant},
};

use getifaddrs::InterfaceFilter;

use crate::xdp::{
    error::Result,
    frame::{Frame, FrameBuffer},
};

use super::wire::{
    arp::{ARP_FRAME_LEN, ArpHardwareTypes, ArpOperations, ArpPacket},
    ethernet::{EtherTypes, EthernetFrame, MacAddress},
    icmpv6::{Icmpv6Types, compute_icmpv6_checksum},
    ip::{IPV6_HEADER_LEN, IpAddress, IpProtocols, Ipv4Address, Ipv6Address, Ipv6Header},
};

/// ARP Ethernet frame representation.
#[repr(C, packed)]
struct ArpEthernetFrame {
    ethernet: EthernetFrame,
    arp: ArpPacket,
}

impl ArpEthernetFrame {
    fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
}

/// A neighbor entry representation.
struct NeighborEntry {
    mac: MacAddress,
    expires_at: Instant,
}

/// Ethernet header (14) + IPv6 header (40) + ICMPv6 NS header (8) +
/// target address (16) + Source Link-Layer Address option (8) = 86 bytes.
const NDP_NS_FRAME_LEN: usize = size_of::<EthernetFrame>() + IPV6_HEADER_LEN + 32;

/// Minimum NDP message body length: 8 (ICMPv6 header) + 16 (target address).
const NDP_MIN_NS_NA_LEN: usize = 24;

/// Minimum Router Advertisement body length: 8 (ICMPv6 header) +
/// 4 (cur hop limit + flags + router lifetime) + 4 (reachable time) + 4 (retrans timer).
const NDP_MIN_RA_LEN: usize = 16;

/// IPv6 all-nodes link-local multicast address (ff02::1).
const ALL_NODES_MULTICAST: Ipv6Address =
    Ipv6Address::new([0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

/// Unified neighbor-resolution handler for ARP (IPv4) and NDP (IPv6).
///
/// Maintains an internal neighbor cache that maps protocol addresses to
/// hardware (MAC) addresses with a configurable TTL. Incoming ARP traffic
/// (both requests and replies) automatically populates the cache.
pub struct NeighborHandler {
    local_mac: MacAddress,
    local_ipv4: Vec<Ipv4Address>,
    local_ipv6: Vec<Ipv6Address>,
    table: HashMap<IpAddress, NeighborEntry>,
    ttl: Duration,
}

impl NeighborHandler {
    /// Creates a new handler bound to the given MAC and IPv4 address.
    pub fn new(if_name: &str, local_mac: MacAddress, ttl: Duration) -> Result<Self> {
        let mut local_ipv4 = Vec::new();
        let mut local_ipv6 = Vec::new();
        let addresses = InterfaceFilter::new().name(if_name).get()?;
        for addr in addresses {
            let ip_addr = match addr.address.ip_addr() {
                Some(ip_addr) => ip_addr,
                None => continue,
            };
            match ip_addr {
                IpAddr::V4(ip_addr) => {
                    local_ipv4.push(Ipv4Address::from(ip_addr.octets()));
                }
                IpAddr::V6(ip_addr) => {
                    local_ipv6.push(Ipv6Address::from(ip_addr.octets()));
                }
            }
        }
        Ok(Self {
            local_mac,
            local_ipv4,
            local_ipv6,
            table: HashMap::new(),
            ttl,
        })
    }

    /// Registers a local IPv6 address for NDP response.
    pub fn add_local_ipv6(&mut self, addr: Ipv6Address) {
        if !self.local_ipv6.contains(&addr) {
            self.local_ipv6.push(addr);
        }
    }

    /// Registers a local IPv4 address for ARP response.
    pub fn add_local_ipv4(&mut self, addr: Ipv4Address) {
        if !self.local_ipv4.contains(&addr) {
            self.local_ipv4.push(addr);
        }
    }

    /// Looks up a cached MAC for the given IP address (v4 or v6).
    ///
    /// Returns `None` if the entry is missing or expired.
    pub fn lookup(&self, ip: &IpAddress) -> Option<MacAddress> {
        self.table.get(ip).and_then(|e| {
            if Instant::now() < e.expires_at {
                Some(e.mac)
            } else {
                None
            }
        })
    }

    /// Convenience wrapper that looks up an IPv4 address in the neighbor cache.
    pub fn lookup_v4(&self, ip: &Ipv4Address) -> Option<MacAddress> {
        self.lookup(&IpAddress::V4(*ip))
    }

    /// Convenience wrapper that looks up an IPv6 address in the neighbor cache.
    pub fn lookup_v6(&self, ip: &Ipv6Address) -> Option<MacAddress> {
        self.lookup(&IpAddress::V6(*ip))
    }

    /// Returns the local MAC address.
    pub fn local_mac(&self) -> MacAddress {
        self.local_mac
    }

    /// Constructs a broadcast ARP request for `target_ip` and enqueues it on
    /// `tx_return`.
    ///
    /// If the frame capacity is too small the error is logged and the frame
    /// is pushed to `rx_return` instead.
    pub fn resolve_v4<'umem>(
        &self,
        source_ip: Ipv4Address,
        target_ip: Ipv4Address,
        mut frame: Frame<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        if frame.capacity() < ARP_FRAME_LEN {
            eprintln!(
                "arp: frame capacity too small for request ({} bytes, need {})",
                frame.capacity(),
                ARP_FRAME_LEN,
            );
            rx_return.push(frame);
            return;
        }

        let pkt = ArpEthernetFrame {
            ethernet: EthernetFrame {
                dst_mac: MacAddress::broadcast(),
                src_mac: self.local_mac,
                ether_type: EtherTypes::Arp,
            },
            arp: ArpPacket {
                htype: ArpHardwareTypes::Ethernet,
                ptype: EtherTypes::IPv4,
                hlen: 6,
                plen: 4,
                oper: ArpOperations::Request,
                sha: self.local_mac,
                spa: source_ip,
                tha: MacAddress::zero(),
                tpa: target_ip,
            },
        };

        frame.copy_from(pkt.as_bytes());
        tx_return.push(frame);
    }

    /// Constructs a Neighbor Solicitation for `target_ip` and enqueues it
    /// on `tx_return`.
    ///
    /// The solicitation is sent to the solicited-node multicast address
    /// derived from `target_ip` and includes a Source Link-Layer Address
    /// option containing our MAC.
    pub fn resolve_v6<'umem>(
        &self,
        source_ip: Ipv6Address,
        target_ip: Ipv6Address,
        mut frame: Frame<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        if frame.capacity() < NDP_NS_FRAME_LEN {
            eprintln!(
                "ndp: frame capacity too small for NS ({} bytes, need {})",
                frame.capacity(),
                NDP_NS_FRAME_LEN,
            );
            rx_return.push(frame);
            return;
        }

        let sol_mcast = target_ip.solicited_node_multicast();
        let dst_mac = sol_mcast.multicast_mac();

        let eth_len = size_of::<EthernetFrame>();
        let icmpv6_offset = eth_len + IPV6_HEADER_LEN;
        let icmpv6_len = 32; // 8 header + 16 target + 8 option

        let mut buf = [0u8; NDP_NS_FRAME_LEN];

        // Ethernet header
        let dst_mac_bytes: [u8; 6] = dst_mac.into();
        let src_mac_bytes: [u8; 6] = self.local_mac.into();
        buf[0..6].copy_from_slice(&dst_mac_bytes);
        buf[6..12].copy_from_slice(&src_mac_bytes);
        buf[12] = 0x86;
        buf[13] = 0xDD;

        // IPv6 header
        buf[14] = 0x60; // version 6
        let payload_len = (icmpv6_len as u16).to_be_bytes();
        buf[18..20].copy_from_slice(&payload_len);
        buf[20] = IpProtocols::IcmpV6;
        buf[21] = 255; // hop limit per RFC 4861
        let src_bytes: [u8; 16] = source_ip.into();
        buf[22..38].copy_from_slice(&src_bytes);
        let dst_bytes: [u8; 16] = sol_mcast.into();
        buf[38..54].copy_from_slice(&dst_bytes);

        // ICMPv6 Neighbor Solicitation
        buf[icmpv6_offset] = Icmpv6Types::NeighborSolicitation;
        buf[icmpv6_offset + 1] = 0; // code
        // checksum at +2..+4 filled below
        // reserved at +4..+8 = 0
        let target_bytes: [u8; 16] = target_ip.into();
        buf[icmpv6_offset + 8..icmpv6_offset + 24].copy_from_slice(&target_bytes);

        // Source Link-Layer Address option (type=1, len=1 (8 bytes))
        buf[icmpv6_offset + 24] = 1; // option type
        buf[icmpv6_offset + 25] = 1; // option length in units of 8 bytes
        buf[icmpv6_offset + 26..icmpv6_offset + 32].copy_from_slice(&src_mac_bytes);

        // Compute checksum
        let cksum = compute_icmpv6_checksum(
            &source_ip,
            &sol_mcast,
            &buf[icmpv6_offset..icmpv6_offset + icmpv6_len],
        );
        buf[icmpv6_offset + 2] = cksum[0];
        buf[icmpv6_offset + 3] = cksum[1];

        frame.copy_from(&buf[..]);
        tx_return.push(frame);
    }

    /// Processes an incoming ARP frame.
    ///
    /// The frame is always consumed and pushed to exactly one buffer:
    ///
    /// * `rx_return` -- validation errors, non-Ethernet/IPv4 ARP, replies,
    ///   or requests not targeting our IP.
    /// * `tx_return` -- valid ARP requests targeting our IPv4 address, after
    ///   the frame has been modified in-place to carry the reply.
    ///
    /// Both requests and replies from structurally valid Ethernet/IPv4 ARP
    /// packets update the neighbor cache.
    pub fn handle_arp<'umem>(
        &mut self,
        mut frame: Frame<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        if frame.len() < ARP_FRAME_LEN {
            eprintln!(
                "arp: frame too short ({} bytes, need {})",
                frame.len(),
                ARP_FRAME_LEN,
            );
            rx_return.push(frame);
            return;
        }

        let arp = ArpPacket::from_frame(&frame);

        if arp.htype != ArpHardwareTypes::Ethernet {
            eprintln!("arp: unsupported hardware type");
            rx_return.push(frame);
            return;
        }

        if arp.ptype != EtherTypes::IPv4 {
            eprintln!("arp: unsupported protocol type");
            rx_return.push(frame);
            return;
        }

        if arp.hlen != 6 || arp.plen != 4 {
            eprintln!("arp: invalid address lengths");
            rx_return.push(frame);
            return;
        }

        let sha = arp.sha;
        let spa = arp.spa;
        let oper = arp.oper;
        let tpa = arp.tpa;

        self.table.insert(
            IpAddress::V4(spa),
            NeighborEntry {
                mac: sha,
                expires_at: Instant::now() + self.ttl,
            },
        );

        if oper != ArpOperations::Request {
            rx_return.push(frame);
            return;
        }

        if !self.local_ipv4.contains(&tpa) {
            rx_return.push(frame);
            return;
        }

        {
            let eth = EthernetFrame::from_frame_mut(&mut frame);
            eth.dst_mac = sha;
            eth.src_mac = self.local_mac;
        }
        {
            let arp = ArpPacket::from_frame_mut(&mut frame);
            arp.oper = ArpOperations::Reply;
            arp.sha = self.local_mac;
            arp.spa = tpa;
            arp.tha = sha;
            arp.tpa = spa;
        }

        tx_return.push(frame);
    }

    /// Handles an incoming NDP (ICMPv6 Neighbor Discovery) frame.
    ///
    /// Dispatches on ICMPv6 type:
    /// * Neighbor Solicitation (135) -- reply with NA if targeting our address
    /// * Neighbor Advertisement (136) -- cache the advertised MAC
    /// * Router Advertisement (134) -- cache the router's MAC
    /// * Router Solicitation (133) and Redirect (137) -- pass to `rx_return`
    pub fn handle_ndp<'umem>(
        &mut self,
        frame: Frame<'umem>,
        icmpv6_offset: usize,
        icmpv6_len: usize,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        if icmpv6_len < 8 {
            eprintln!("ndp: payload too short ({} bytes)", icmpv6_len);
            rx_return.push(frame);
            return;
        }

        let icmpv6_end = icmpv6_offset + icmpv6_len;

        // Validate checksum.
        {
            let ip = Ipv6Header::from_frame(&frame);
            let src_addr = ip.src_addr;
            let dst_addr = ip.dst_addr;
            if compute_icmpv6_checksum(&src_addr, &dst_addr, &frame[icmpv6_offset..icmpv6_end])
                != [0x00, 0x00]
            {
                eprintln!("ndp: invalid checksum");
                rx_return.push(frame);
                return;
            }
        }

        let icmpv6_type = frame[icmpv6_offset];

        match icmpv6_type {
            Icmpv6Types::NeighborSolicitation => {
                self.handle_neighbor_solicitation(
                    frame,
                    icmpv6_offset,
                    icmpv6_len,
                    rx_return,
                    tx_return,
                );
            }
            Icmpv6Types::NeighborAdvertisement => {
                self.handle_neighbor_advertisement(frame, icmpv6_offset, icmpv6_len, rx_return);
            }
            Icmpv6Types::RouterAdvertisement => {
                self.handle_router_advertisement(frame, icmpv6_offset, icmpv6_len, rx_return);
            }
            _ => {
                // RS (133), Redirect (137), or unknown NDP type.
                rx_return.push(frame);
            }
        }
    }

    fn handle_neighbor_solicitation<'umem>(
        &mut self,
        mut frame: Frame<'umem>,
        icmpv6_offset: usize,
        icmpv6_len: usize,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        if icmpv6_len < NDP_MIN_NS_NA_LEN {
            eprintln!("ndp: NS too short ({} bytes)", icmpv6_len);
            rx_return.push(frame);
            return;
        }

        let icmpv6_end = icmpv6_offset + icmpv6_len;

        // Extract target address (bytes 8..24 relative to ICMPv6 header).
        let mut target_bytes = [0u8; 16];
        target_bytes.copy_from_slice(&frame[icmpv6_offset + 8..icmpv6_offset + 24]);
        let target_addr = Ipv6Address::from(target_bytes);

        // Extract IPv6 source address.
        let ip = Ipv6Header::from_frame(&frame);
        let src_addr = ip.src_addr;

        // Parse Source Link-Layer Address option (type=1) to get sender MAC.
        let options_start = icmpv6_offset + 24;
        let sender_mac = parse_ndp_link_layer_option(&frame, options_start, icmpv6_end, 1);

        // Cache sender's MAC if source is not unspecified (DAD uses ::).
        if !src_addr.is_unspecified() {
            if let Some(mac) = sender_mac {
                self.table.insert(
                    IpAddress::V6(src_addr),
                    NeighborEntry {
                        mac,
                        expires_at: Instant::now() + self.ttl,
                    },
                );
            }
        }

        // Check if the target is one of our addresses.
        if !self.local_ipv6.contains(&target_addr) {
            rx_return.push(frame);
            return;
        }

        // Build NA reply in-place.
        let is_dad = src_addr.is_unspecified();

        // Determine response destination.
        let reply_dst_addr = if is_dad {
            ALL_NODES_MULTICAST
        } else {
            src_addr
        };

        let reply_dst_mac = if is_dad {
            ALL_NODES_MULTICAST.multicast_mac()
        } else {
            sender_mac.unwrap_or_else(|| {
                // Fallback: use the Ethernet source MAC from the frame.
                let eth = EthernetFrame::from_frame(&frame);
                eth.src_mac
            })
        };

        // NA body: 8 (header) + 16 (target) + 8 (Target LLA option) = 32 bytes.
        let na_icmpv6_len: usize = 32;
        let eth_len = size_of::<EthernetFrame>();
        let new_frame_len = eth_len + IPV6_HEADER_LEN + na_icmpv6_len;

        if new_frame_len > frame.capacity() {
            rx_return.push(frame);
            return;
        }

        // Ensure frame is large enough.
        unsafe {
            frame.set_len(frame.len().max(new_frame_len));
        }

        // Ethernet header.
        {
            let eth = EthernetFrame::from_frame_mut(&mut frame);
            eth.dst_mac = reply_dst_mac;
            eth.src_mac = self.local_mac;
        }

        // IPv6 header.
        {
            let ip = Ipv6Header::from_frame_mut(&mut frame);
            ip.src_addr = target_addr;
            ip.dst_addr = reply_dst_addr;
            ip.hop_limit = 255;
            ip.next_header = IpProtocols::IcmpV6;
            ip.payload_length = (na_icmpv6_len as u16).to_be_bytes();
        }

        let icmp_off = eth_len + IPV6_HEADER_LEN;

        // ICMPv6 Neighbor Advertisement.
        frame[icmp_off] = Icmpv6Types::NeighborAdvertisement;
        frame[icmp_off + 1] = 0; // code
        frame[icmp_off + 2] = 0; // checksum (zeroed for computation)
        frame[icmp_off + 3] = 0;

        // Flags: S (solicited) = 1, O (override) = 1 for normal;
        //        S = 0, O = 1 for DAD.
        if is_dad {
            frame[icmp_off + 4] = 0x20; // O=1 only (bit 5)
        } else {
            frame[icmp_off + 4] = 0x60; // S=1 O=1 (bits 6 and 5)
        }
        frame[icmp_off + 5] = 0;
        frame[icmp_off + 6] = 0;
        frame[icmp_off + 7] = 0;

        // Target address.
        let target_bytes: [u8; 16] = target_addr.into();
        frame[icmp_off + 8..icmp_off + 24].copy_from_slice(&target_bytes);

        // Target Link-Layer Address option (type=2, len=1).
        frame[icmp_off + 24] = 2;
        frame[icmp_off + 25] = 1;
        let mac_bytes: [u8; 6] = self.local_mac.into();
        frame[icmp_off + 26..icmp_off + 32].copy_from_slice(&mac_bytes);

        // Set final length.
        unsafe {
            frame.set_len(new_frame_len);
        }

        // Compute checksum.
        let cksum = compute_icmpv6_checksum(
            &target_addr,
            &reply_dst_addr,
            &frame[icmp_off..icmp_off + na_icmpv6_len],
        );
        frame[icmp_off + 2] = cksum[0];
        frame[icmp_off + 3] = cksum[1];

        tx_return.push(frame);
    }

    fn handle_neighbor_advertisement<'umem>(
        &mut self,
        frame: Frame<'umem>,
        icmpv6_offset: usize,
        icmpv6_len: usize,
        rx_return: &mut impl FrameBuffer<'umem>,
    ) {
        if icmpv6_len < NDP_MIN_NS_NA_LEN {
            eprintln!("ndp: NA too short ({} bytes)", icmpv6_len);
            rx_return.push(frame);
            return;
        }

        let icmpv6_end = icmpv6_offset + icmpv6_len;

        // Extract target address.
        let mut target_bytes = [0u8; 16];
        target_bytes.copy_from_slice(&frame[icmpv6_offset + 8..icmpv6_offset + 24]);
        let target_addr = Ipv6Address::from(target_bytes);

        // Parse Target Link-Layer Address option (type=2).
        let options_start = icmpv6_offset + 24;
        if let Some(mac) = parse_ndp_link_layer_option(&frame, options_start, icmpv6_end, 2) {
            self.table.insert(
                IpAddress::V6(target_addr),
                NeighborEntry {
                    mac,
                    expires_at: Instant::now() + self.ttl,
                },
            );
        }

        rx_return.push(frame);
    }

    fn handle_router_advertisement<'umem>(
        &mut self,
        frame: Frame<'umem>,
        icmpv6_offset: usize,
        icmpv6_len: usize,
        rx_return: &mut impl FrameBuffer<'umem>,
    ) {
        if icmpv6_len < NDP_MIN_RA_LEN {
            eprintln!("ndp: RA too short ({} bytes)", icmpv6_len);
            rx_return.push(frame);
            return;
        }

        let icmpv6_end = icmpv6_offset + icmpv6_len;

        // Extract IPv6 source address (router).
        let ip = Ipv6Header::from_frame(&frame);
        let src_addr = ip.src_addr;

        // Parse Source Link-Layer Address option (type=1).
        let options_start = icmpv6_offset + 16; // RA header is 16 bytes
        if let Some(mac) = parse_ndp_link_layer_option(&frame, options_start, icmpv6_end, 1) {
            self.table.insert(
                IpAddress::V6(src_addr),
                NeighborEntry {
                    mac,
                    expires_at: Instant::now() + self.ttl,
                },
            );
        }

        rx_return.push(frame);
    }
}

/// Walks NDP options looking for a Link-Layer Address option of the
/// specified `option_type` (1 = Source, 2 = Target).
///
/// Returns the 6-byte MAC address if found, `None` otherwise.
fn parse_ndp_link_layer_option(
    frame: &[u8],
    mut offset: usize,
    end: usize,
    option_type: u8,
) -> Option<MacAddress> {
    while offset + 2 <= end {
        let opt_type = frame[offset];
        let opt_len = frame[offset + 1] as usize;

        // Option length is in units of 8 bytes; 0 is invalid.
        if opt_len == 0 {
            return None;
        }

        let opt_byte_len = opt_len * 8;
        if offset + opt_byte_len > end {
            return None;
        }

        if opt_type == option_type && opt_byte_len >= 8 {
            let mac = MacAddress::new([
                frame[offset + 2],
                frame[offset + 3],
                frame[offset + 4],
                frame[offset + 5],
                frame[offset + 6],
                frame[offset + 7],
            ]);
            return Some(mac);
        }

        offset += opt_byte_len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::wire::icmpv6::compute_icmpv6_checksum;
    use crate::net::wire::ip::{IPV6_HEADER_LEN, Ipv6Header};
    use crate::xdp::frame::BasicFrameBuffer;

    const TEST_LOCAL_MAC: MacAddress = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    const TEST_LOCAL_IP: Ipv4Address = Ipv4Address::new([192, 168, 1, 1]);
    const TEST_REMOTE_MAC: MacAddress = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    const TEST_REMOTE_IP: Ipv4Address = Ipv4Address::new([192, 168, 1, 100]);

    const TEST_TTL: Duration = Duration::from_secs(60);

    fn new_handler() -> NeighborHandler {
        let mut nh = NeighborHandler::new("test0", TEST_LOCAL_MAC, TEST_TTL).unwrap();
        nh.add_local_ipv4(TEST_LOCAL_IP);
        nh
    }

    fn build_arp_request_bytes(target_ip: Ipv4Address) -> [u8; ARP_FRAME_LEN] {
        let f = ArpEthernetFrame {
            ethernet: EthernetFrame {
                dst_mac: MacAddress::broadcast(),
                src_mac: TEST_REMOTE_MAC,
                ether_type: EtherTypes::Arp,
            },
            arp: ArpPacket {
                htype: ArpHardwareTypes::Ethernet,
                ptype: EtherTypes::IPv4,
                hlen: 6,
                plen: 4,
                oper: ArpOperations::Request,
                sha: TEST_REMOTE_MAC,
                spa: TEST_REMOTE_IP,
                tha: MacAddress::zero(),
                tpa: target_ip,
            },
        };
        let mut bytes = [0u8; ARP_FRAME_LEN];
        bytes.copy_from_slice(f.as_bytes());
        bytes
    }

    fn build_arp_reply_bytes(
        sender_mac: MacAddress,
        sender_ip: Ipv4Address,
    ) -> [u8; ARP_FRAME_LEN] {
        let f = ArpEthernetFrame {
            ethernet: EthernetFrame {
                dst_mac: TEST_LOCAL_MAC,
                src_mac: sender_mac,
                ether_type: EtherTypes::Arp,
            },
            arp: ArpPacket {
                htype: ArpHardwareTypes::Ethernet,
                ptype: EtherTypes::IPv4,
                hlen: 6,
                plen: 4,
                oper: ArpOperations::Reply,
                sha: sender_mac,
                spa: sender_ip,
                tha: TEST_LOCAL_MAC,
                tpa: TEST_LOCAL_IP,
            },
        };
        let mut bytes = [0u8; ARP_FRAME_LEN];
        bytes.copy_from_slice(f.as_bytes());
        bytes
    }

    #[test]
    fn valid_request_produces_reply() {
        let mut handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = build_arp_request_bytes(TEST_LOCAL_IP);
        let frame = Frame::new(0, &mut data, ARP_FRAME_LEN, false);

        handler.handle_arp(frame, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 0);
        assert_eq!(tx.num_frames(), 1);

        let reply = tx.pop().unwrap();
        let eth = EthernetFrame::from_frame(&reply);
        let arp = ArpPacket::from_frame(&reply);

        assert_eq!(eth.dst_mac, TEST_REMOTE_MAC);
        assert_eq!(eth.src_mac, TEST_LOCAL_MAC);
        assert_eq!(arp.oper, ArpOperations::Reply);
        assert_eq!(arp.sha, TEST_LOCAL_MAC);
        assert_eq!(arp.spa, TEST_LOCAL_IP);
        assert_eq!(arp.tha, TEST_REMOTE_MAC);
        assert_eq!(arp.tpa, TEST_REMOTE_IP);
    }

    #[test]
    fn request_for_wrong_ip_goes_to_rx() {
        let mut handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let wrong = Ipv4Address::new([10, 0, 0, 1]);
        let mut data = build_arp_request_bytes(wrong);
        let frame = Frame::new(0, &mut data, ARP_FRAME_LEN, false);

        handler.handle_arp(frame, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn reply_goes_to_rx() {
        let mut handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = build_arp_reply_bytes(TEST_REMOTE_MAC, TEST_REMOTE_IP);
        let frame = Frame::new(0, &mut data, ARP_FRAME_LEN, false);

        handler.handle_arp(frame, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn frame_too_short_goes_to_rx() {
        let mut handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = [0u8; 30];
        let frame = Frame::new(0, &mut data, 30, false);

        handler.handle_arp(frame, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn invalid_htype_goes_to_rx() {
        let mut handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = build_arp_request_bytes(TEST_LOCAL_IP);
        data[14] = 0xFF;
        data[15] = 0xFF;
        let frame = Frame::new(0, &mut data, ARP_FRAME_LEN, false);

        handler.handle_arp(frame, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn invalid_ptype_goes_to_rx() {
        let mut handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = build_arp_request_bytes(TEST_LOCAL_IP);
        data[16] = 0x86;
        data[17] = 0xDD;
        let frame = Frame::new(0, &mut data, ARP_FRAME_LEN, false);

        handler.handle_arp(frame, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn invalid_address_lengths_goes_to_rx() {
        let mut handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = build_arp_request_bytes(TEST_LOCAL_IP);
        data[18] = 8;
        let frame = Frame::new(0, &mut data, ARP_FRAME_LEN, false);

        handler.handle_arp(frame, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn request_caches_sender() {
        let mut handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        assert!(handler.lookup_v4(&TEST_REMOTE_IP).is_none());

        let mut data = build_arp_request_bytes(TEST_LOCAL_IP);
        let frame = Frame::new(0, &mut data, ARP_FRAME_LEN, false);
        handler.handle_arp(frame, &mut rx, &mut tx);

        assert_eq!(handler.lookup_v4(&TEST_REMOTE_IP), Some(TEST_REMOTE_MAC));
    }

    #[test]
    fn reply_caches_sender() {
        let mut handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        assert!(handler.lookup_v4(&TEST_REMOTE_IP).is_none());

        let mut data = build_arp_reply_bytes(TEST_REMOTE_MAC, TEST_REMOTE_IP);
        let frame = Frame::new(0, &mut data, ARP_FRAME_LEN, false);
        handler.handle_arp(frame, &mut rx, &mut tx);

        assert_eq!(handler.lookup_v4(&TEST_REMOTE_IP), Some(TEST_REMOTE_MAC));
    }

    #[test]
    fn wrong_target_still_caches_sender() {
        let mut handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let wrong = Ipv4Address::new([10, 0, 0, 1]);
        let mut data = build_arp_request_bytes(wrong);
        let frame = Frame::new(0, &mut data, ARP_FRAME_LEN, false);
        handler.handle_arp(frame, &mut rx, &mut tx);

        assert_eq!(handler.lookup_v4(&TEST_REMOTE_IP), Some(TEST_REMOTE_MAC));
    }

    #[test]
    fn cache_updates_on_new_mac() {
        let mut handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = build_arp_reply_bytes(TEST_REMOTE_MAC, TEST_REMOTE_IP);
        let frame = Frame::new(0, &mut data, ARP_FRAME_LEN, false);
        handler.handle_arp(frame, &mut rx, &mut tx);
        assert_eq!(handler.lookup_v4(&TEST_REMOTE_IP), Some(TEST_REMOTE_MAC));

        let new_mac = MacAddress::new([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
        let mut data2 = build_arp_reply_bytes(new_mac, TEST_REMOTE_IP);
        let frame2 = Frame::new(0, &mut data2, ARP_FRAME_LEN, false);
        handler.handle_arp(frame2, &mut rx, &mut tx);
        assert_eq!(handler.lookup_v4(&TEST_REMOTE_IP), Some(new_mac));
    }

    #[test]
    fn expired_entry_returns_none() {
        let mut handler = NeighborHandler::new("test0", TEST_LOCAL_MAC, Duration::ZERO).unwrap();
        handler.add_local_ipv4(TEST_LOCAL_IP);
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = build_arp_reply_bytes(TEST_REMOTE_MAC, TEST_REMOTE_IP);
        let frame = Frame::new(0, &mut data, ARP_FRAME_LEN, false);
        handler.handle_arp(frame, &mut rx, &mut tx);

        assert!(handler.lookup_v4(&TEST_REMOTE_IP).is_none());
    }

    #[test]
    fn lookup_unknown_returns_none() {
        let handler = new_handler();
        let unknown = Ipv4Address::new([10, 0, 0, 1]);
        assert!(handler.lookup_v4(&unknown).is_none());
    }

    #[test]
    fn invalid_packet_does_not_cache() {
        let mut handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = [0u8; 30];
        let frame = Frame::new(0, &mut data, 30, false);
        handler.handle_arp(frame, &mut rx, &mut tx);

        assert!(handler.lookup_v4(&TEST_REMOTE_IP).is_none());
    }

    #[test]
    fn resolve_produces_valid_request() {
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let target = Ipv4Address::new([192, 168, 1, 200]);

        let mut data = [0u8; 64];
        let frame = Frame::new(0, &mut data, 1, false);

        handler.resolve_v4(TEST_LOCAL_IP, target, frame, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 0);
        assert_eq!(tx.num_frames(), 1);

        let req = tx.pop().unwrap();
        assert_eq!(req.len(), ARP_FRAME_LEN);

        let eth = EthernetFrame::from_frame(&req);
        let arp = ArpPacket::from_frame(&req);

        assert_eq!(eth.dst_mac, MacAddress::broadcast());
        assert_eq!(eth.src_mac, TEST_LOCAL_MAC);
        assert_eq!(eth.ether_type, EtherTypes::Arp);

        assert_eq!(arp.htype, ArpHardwareTypes::Ethernet);
        assert_eq!(arp.ptype, EtherTypes::IPv4);
        assert_eq!(arp.hlen, 6);
        assert_eq!(arp.plen, 4);
        assert_eq!(arp.oper, ArpOperations::Request);
        assert_eq!(arp.sha, TEST_LOCAL_MAC);
        assert_eq!(arp.spa, TEST_LOCAL_IP);
        assert_eq!(arp.tha, MacAddress::zero());
        assert_eq!(arp.tpa, target);
    }

    #[test]
    fn resolve_frame_too_small_goes_to_rx() {
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = [0u8; 20];
        let frame = Frame::new(0, &mut data, 1, false);

        handler.resolve_v4(
            TEST_LOCAL_IP,
            Ipv4Address::new([10, 0, 0, 1]),
            frame,
            &mut rx,
            &mut tx,
        );

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    const TEST_LOCAL_IPV6: Ipv6Address =
        Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    const TEST_REMOTE_IPV6: Ipv6Address =
        Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

    fn new_ndp_handler() -> NeighborHandler {
        let mut h = new_handler();
        h.add_local_ipv6(TEST_LOCAL_IPV6);
        h
    }

    /// Builds Ethernet + IPv6 + ICMPv6 NDP frame.
    fn build_ndp_frame(
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        icmpv6_payload: &[u8],
    ) -> Vec<u8> {
        use std::mem::size_of;

        let eth_len = size_of::<EthernetFrame>();
        let frame_len = eth_len + IPV6_HEADER_LEN + icmpv6_payload.len();
        let mut buf = vec![0u8; frame_len];

        // Ethernet
        buf[0..6].copy_from_slice(&dst_mac);
        buf[6..12].copy_from_slice(&src_mac);
        buf[12] = 0x86;
        buf[13] = 0xDD;

        // IPv6
        buf[14] = 0x60;
        let payload_len = (icmpv6_payload.len() as u16).to_be_bytes();
        buf[18..20].copy_from_slice(&payload_len);
        buf[20] = IpProtocols::IcmpV6;
        buf[21] = 255; // hop limit
        let src_bytes: [u8; 16] = src_ip.into();
        buf[22..38].copy_from_slice(&src_bytes);
        let dst_bytes: [u8; 16] = dst_ip.into();
        buf[38..54].copy_from_slice(&dst_bytes);

        // ICMPv6
        buf[eth_len + IPV6_HEADER_LEN..].copy_from_slice(icmpv6_payload);

        // Compute and write checksum.
        let icmp_off = eth_len + IPV6_HEADER_LEN;
        buf[icmp_off + 2] = 0;
        buf[icmp_off + 3] = 0;
        let cksum = compute_icmpv6_checksum(&src_ip, &dst_ip, &buf[icmp_off..]);
        buf[icmp_off + 2] = cksum[0];
        buf[icmp_off + 3] = cksum[1];

        buf
    }

    /// Builds an ICMPv6 Neighbor Solicitation payload.
    fn build_ns_payload(target: Ipv6Address, source_mac: Option<[u8; 6]>) -> Vec<u8> {
        let mut payload = vec![0u8; 24]; // type(1) + code(1) + cksum(2) + reserved(4) + target(16)
        payload[0] = 135; // NS type
        let target_bytes: [u8; 16] = target.into();
        payload[8..24].copy_from_slice(&target_bytes);

        if let Some(mac) = source_mac {
            // Source Link-Layer Address option (type=1, len=1)
            payload.push(1); // option type
            payload.push(1); // option length (8 bytes)
            payload.extend_from_slice(&mac);
        }

        payload
    }

    /// Builds an ICMPv6 Neighbor Advertisement payload.
    fn build_na_payload(target: Ipv6Address, flags: u8, target_mac: Option<[u8; 6]>) -> Vec<u8> {
        let mut payload = vec![0u8; 24];
        payload[0] = 136; // NA type
        payload[4] = flags;
        let target_bytes: [u8; 16] = target.into();
        payload[8..24].copy_from_slice(&target_bytes);

        if let Some(mac) = target_mac {
            // Target Link-Layer Address option (type=2, len=1)
            payload.push(2);
            payload.push(1);
            payload.extend_from_slice(&mac);
        }

        payload
    }

    /// Builds an ICMPv6 Router Advertisement payload.
    fn build_ra_payload(source_mac: Option<[u8; 6]>) -> Vec<u8> {
        let mut payload = vec![0u8; 16]; // type(1)+code(1)+cksum(2)+curhop(1)+flags(1)+lifetime(2)+reachable(4)+retrans(4)
        payload[0] = 134; // RA type

        if let Some(mac) = source_mac {
            // Source Link-Layer Address option (type=1, len=1)
            payload.push(1);
            payload.push(1);
            payload.extend_from_slice(&mac);
        }

        payload
    }

    fn icmpv6_offset() -> usize {
        std::mem::size_of::<EthernetFrame>() + IPV6_HEADER_LEN
    }

    #[test]
    fn ns_targeting_our_ip_produces_na() {
        let mut handler = new_ndp_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let remote_mac: [u8; 6] = TEST_REMOTE_MAC.into();
        let local_mac: [u8; 6] = TEST_LOCAL_MAC.into();
        let ns = build_ns_payload(TEST_LOCAL_IPV6, Some(remote_mac));
        let sol_mcast = TEST_LOCAL_IPV6.solicited_node_multicast();
        let frame_data = build_ndp_frame(
            remote_mac,
            sol_mcast.multicast_mac().into(),
            TEST_REMOTE_IPV6,
            sol_mcast,
            &ns,
        );

        let mut buf = vec![0u8; 512];
        buf[..frame_data.len()].copy_from_slice(&frame_data);
        let frame = Frame::new(0, &mut buf, frame_data.len(), false);

        let off = icmpv6_offset();
        let icmp_len = frame_data.len() - off;
        handler.handle_ndp(frame, off, icmp_len, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 0);
        assert_eq!(tx.num_frames(), 1);

        let reply = tx.pop().unwrap();

        // Check ICMPv6 type = NA (136).
        assert_eq!(reply[off], 136);

        // Flags: S=1, O=1 -> 0x60
        assert_eq!(reply[off + 4], 0x60);

        // Target address in NA = our address.
        let mut target = [0u8; 16];
        target.copy_from_slice(&reply[off + 8..off + 24]);
        assert_eq!(Ipv6Address::from(target), TEST_LOCAL_IPV6);

        // Target LLA option (type=2).
        assert_eq!(reply[off + 24], 2);
        assert_eq!(reply[off + 25], 1);
        assert_eq!(&reply[off + 26..off + 32], &local_mac);

        // Hop limit = 255.
        let ip = Ipv6Header::from_frame(&reply);
        assert_eq!(ip.hop_limit, 255);

        // Valid checksum.
        let cksum = compute_icmpv6_checksum(&ip.src_addr, &ip.dst_addr, &reply[off..off + 32]);
        assert_eq!(cksum, [0x00, 0x00]);
    }

    #[test]
    fn ns_targeting_unknown_ip_goes_to_rx() {
        let mut handler = new_ndp_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let unknown = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99]);
        let remote_mac: [u8; 6] = TEST_REMOTE_MAC.into();
        let ns = build_ns_payload(unknown, Some(remote_mac));
        let frame_data = build_ndp_frame(
            remote_mac,
            [0x33, 0x33, 0x00, 0x00, 0x00, 0x63],
            TEST_REMOTE_IPV6,
            unknown.solicited_node_multicast(),
            &ns,
        );

        let mut buf = vec![0u8; 512];
        buf[..frame_data.len()].copy_from_slice(&frame_data);
        let frame = Frame::new(0, &mut buf, frame_data.len(), false);

        let off = icmpv6_offset();
        let icmp_len = frame_data.len() - off;
        handler.handle_ndp(frame, off, icmp_len, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn ns_caches_sender_mac() {
        let mut handler = new_ndp_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        assert!(handler.lookup_v6(&TEST_REMOTE_IPV6).is_none());

        let remote_mac: [u8; 6] = TEST_REMOTE_MAC.into();
        let ns = build_ns_payload(TEST_LOCAL_IPV6, Some(remote_mac));
        let sol_mcast = TEST_LOCAL_IPV6.solicited_node_multicast();
        let frame_data = build_ndp_frame(
            remote_mac,
            sol_mcast.multicast_mac().into(),
            TEST_REMOTE_IPV6,
            sol_mcast,
            &ns,
        );

        let mut buf = vec![0u8; 512];
        buf[..frame_data.len()].copy_from_slice(&frame_data);
        let frame = Frame::new(0, &mut buf, frame_data.len(), false);

        let off = icmpv6_offset();
        let icmp_len = frame_data.len() - off;
        handler.handle_ndp(frame, off, icmp_len, &mut rx, &mut tx);

        assert_eq!(handler.lookup_v6(&TEST_REMOTE_IPV6), Some(TEST_REMOTE_MAC));
    }

    #[test]
    fn ns_dad_produces_na_with_correct_flags() {
        let mut handler = new_ndp_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        // DAD: source = ::, no Source LLA option.
        let ns = build_ns_payload(TEST_LOCAL_IPV6, None);
        let sol_mcast = TEST_LOCAL_IPV6.solicited_node_multicast();
        let all_nodes_mac: [u8; 6] =
            Ipv6Address::new([0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
                .multicast_mac()
                .into();
        let frame_data = build_ndp_frame(
            [0x00; 6],
            sol_mcast.multicast_mac().into(),
            Ipv6Address::unspecified(),
            sol_mcast,
            &ns,
        );

        let mut buf = vec![0u8; 512];
        buf[..frame_data.len()].copy_from_slice(&frame_data);
        let frame = Frame::new(0, &mut buf, frame_data.len(), false);

        let off = icmpv6_offset();
        let icmp_len = frame_data.len() - off;
        handler.handle_ndp(frame, off, icmp_len, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 0);
        assert_eq!(tx.num_frames(), 1);

        let reply = tx.pop().unwrap();

        // Flags: S=0, O=1 -> 0x20
        assert_eq!(reply[off + 4], 0x20);

        // Destination should be all-nodes multicast MAC.
        let eth = EthernetFrame::from_frame(&reply);
        assert_eq!(<[u8; 6]>::from(eth.dst_mac), all_nodes_mac);

        // IPv6 dst should be all-nodes multicast.
        let ip = Ipv6Header::from_frame(&reply);
        assert_eq!(
            ip.dst_addr,
            Ipv6Address::new([0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        );
    }

    #[test]
    fn ns_too_short_goes_to_rx() {
        let mut handler = new_ndp_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        // Only 16 bytes of ICMPv6 (need 24).
        let short_ns = vec![135u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let frame_data = build_ndp_frame(
            [0x11; 6],
            [0x33, 0x33, 0x00, 0x00, 0x00, 0x01],
            TEST_REMOTE_IPV6,
            TEST_LOCAL_IPV6.solicited_node_multicast(),
            &short_ns,
        );

        let mut buf = vec![0u8; 512];
        buf[..frame_data.len()].copy_from_slice(&frame_data);
        let frame = Frame::new(0, &mut buf, frame_data.len(), false);

        let off = icmpv6_offset();
        let icmp_len = frame_data.len() - off;
        handler.handle_ndp(frame, off, icmp_len, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn ns_bad_checksum_goes_to_rx() {
        let mut handler = new_ndp_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let remote_mac: [u8; 6] = TEST_REMOTE_MAC.into();
        let ns = build_ns_payload(TEST_LOCAL_IPV6, Some(remote_mac));
        let sol_mcast = TEST_LOCAL_IPV6.solicited_node_multicast();
        let mut frame_data = build_ndp_frame(
            remote_mac,
            sol_mcast.multicast_mac().into(),
            TEST_REMOTE_IPV6,
            sol_mcast,
            &ns,
        );

        // Corrupt checksum.
        let off = icmpv6_offset();
        frame_data[off + 2] ^= 0xFF;

        let mut buf = vec![0u8; 512];
        buf[..frame_data.len()].copy_from_slice(&frame_data);
        let frame = Frame::new(0, &mut buf, frame_data.len(), false);

        let icmp_len = frame_data.len() - off;
        handler.handle_ndp(frame, off, icmp_len, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn na_caches_target_mac() {
        let mut handler = new_ndp_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        assert!(handler.lookup_v6(&TEST_REMOTE_IPV6).is_none());

        let remote_mac: [u8; 6] = TEST_REMOTE_MAC.into();
        let na = build_na_payload(TEST_REMOTE_IPV6, 0x60, Some(remote_mac));
        let frame_data = build_ndp_frame(
            remote_mac,
            TEST_LOCAL_MAC.into(),
            TEST_REMOTE_IPV6,
            TEST_LOCAL_IPV6,
            &na,
        );

        let mut buf = vec![0u8; 512];
        buf[..frame_data.len()].copy_from_slice(&frame_data);
        let frame = Frame::new(0, &mut buf, frame_data.len(), false);

        let off = icmpv6_offset();
        let icmp_len = frame_data.len() - off;
        handler.handle_ndp(frame, off, icmp_len, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1); // NA always goes to rx
        assert_eq!(tx.num_frames(), 0);
        assert_eq!(handler.lookup_v6(&TEST_REMOTE_IPV6), Some(TEST_REMOTE_MAC));
    }

    #[test]
    fn na_too_short_goes_to_rx() {
        let mut handler = new_ndp_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let short_na = vec![136u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let frame_data = build_ndp_frame(
            [0x11; 6],
            TEST_LOCAL_MAC.into(),
            TEST_REMOTE_IPV6,
            TEST_LOCAL_IPV6,
            &short_na,
        );

        let mut buf = vec![0u8; 512];
        buf[..frame_data.len()].copy_from_slice(&frame_data);
        let frame = Frame::new(0, &mut buf, frame_data.len(), false);

        let off = icmpv6_offset();
        let icmp_len = frame_data.len() - off;
        handler.handle_ndp(frame, off, icmp_len, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn ra_caches_router_mac() {
        let mut handler = new_ndp_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let router_ip = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFE]);
        let router_mac: [u8; 6] = [0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01];

        assert!(handler.lookup_v6(&router_ip).is_none());

        let ra = build_ra_payload(Some(router_mac));
        let frame_data = build_ndp_frame(
            router_mac,
            [0x33, 0x33, 0x00, 0x00, 0x00, 0x01],
            router_ip,
            Ipv6Address::new([0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            &ra,
        );

        let mut buf = vec![0u8; 512];
        buf[..frame_data.len()].copy_from_slice(&frame_data);
        let frame = Frame::new(0, &mut buf, frame_data.len(), false);

        let off = icmpv6_offset();
        let icmp_len = frame_data.len() - off;
        handler.handle_ndp(frame, off, icmp_len, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1); // RA goes to rx
        assert_eq!(tx.num_frames(), 0);
        assert_eq!(
            handler.lookup_v6(&router_ip),
            Some(MacAddress::from(router_mac))
        );
    }

    #[test]
    fn ra_without_source_lla_does_not_crash() {
        let mut handler = new_ndp_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let router_ip = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFE]);
        let ra = build_ra_payload(None);
        let frame_data = build_ndp_frame(
            [0xAA; 6],
            [0x33, 0x33, 0x00, 0x00, 0x00, 0x01],
            router_ip,
            Ipv6Address::new([0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            &ra,
        );

        let mut buf = vec![0u8; 512];
        buf[..frame_data.len()].copy_from_slice(&frame_data);
        let frame = Frame::new(0, &mut buf, frame_data.len(), false);

        let off = icmpv6_offset();
        let icmp_len = frame_data.len() - off;
        handler.handle_ndp(frame, off, icmp_len, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
        assert!(handler.lookup_v6(&router_ip).is_none());
    }

    #[test]
    fn rs_goes_to_rx() {
        let mut handler = new_ndp_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut rs_payload = vec![0u8; 8];
        rs_payload[0] = 133; // RS type
        let frame_data = build_ndp_frame(
            [0x11; 6],
            [0x33, 0x33, 0x00, 0x00, 0x00, 0x02],
            TEST_REMOTE_IPV6,
            Ipv6Address::new([0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
            &rs_payload,
        );

        let mut buf = vec![0u8; 512];
        buf[..frame_data.len()].copy_from_slice(&frame_data);
        let frame = Frame::new(0, &mut buf, frame_data.len(), false);

        let off = icmpv6_offset();
        let icmp_len = frame_data.len() - off;
        handler.handle_ndp(frame, off, icmp_len, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn redirect_goes_to_rx() {
        let mut handler = new_ndp_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        // Redirect needs at least 40 bytes of body (target+dest addresses).
        let mut redirect_payload = vec![0u8; 40];
        redirect_payload[0] = 137; // Redirect type
        let frame_data = build_ndp_frame(
            [0x11; 6],
            TEST_LOCAL_MAC.into(),
            TEST_REMOTE_IPV6,
            TEST_LOCAL_IPV6,
            &redirect_payload,
        );

        let mut buf = vec![0u8; 512];
        buf[..frame_data.len()].copy_from_slice(&frame_data);
        let frame = Frame::new(0, &mut buf, frame_data.len(), false);

        let off = icmpv6_offset();
        let icmp_len = frame_data.len() - off;
        handler.handle_ndp(frame, off, icmp_len, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }

    #[test]
    fn resolve_v6_produces_valid_ns() {
        let handler = new_ndp_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let target = Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42]);

        let mut data = [0u8; 128];
        let frame = Frame::new(0, &mut data, 1, false);

        handler.resolve_v6(TEST_LOCAL_IPV6, target, frame, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 0);
        assert_eq!(tx.num_frames(), 1);

        let req = tx.pop().unwrap();
        assert_eq!(req.len(), NDP_NS_FRAME_LEN);

        // Check Ethernet dst = solicited-node multicast MAC.
        let sol_mcast = target.solicited_node_multicast();
        let expected_mac = sol_mcast.multicast_mac();
        let eth = EthernetFrame::from_frame(&req);
        assert_eq!(eth.dst_mac, expected_mac);
        assert_eq!(eth.src_mac, TEST_LOCAL_MAC);

        // Check IPv6 dst = solicited-node multicast address.
        let ip = Ipv6Header::from_frame(&req);
        assert_eq!(ip.dst_addr, sol_mcast);
        assert_eq!(ip.src_addr, TEST_LOCAL_IPV6);
        assert_eq!(ip.hop_limit, 255);

        // Check ICMPv6 type = NS (135).
        let off = icmpv6_offset();
        assert_eq!(req[off], 135);

        // Check target address.
        let mut target_in_pkt = [0u8; 16];
        target_in_pkt.copy_from_slice(&req[off + 8..off + 24]);
        assert_eq!(Ipv6Address::from(target_in_pkt), target);

        // Check Source LLA option (type=1).
        assert_eq!(req[off + 24], 1);
        assert_eq!(req[off + 25], 1);
        let local_mac_bytes: [u8; 6] = TEST_LOCAL_MAC.into();
        assert_eq!(&req[off + 26..off + 32], &local_mac_bytes);

        // Valid checksum.
        let cksum = compute_icmpv6_checksum(&ip.src_addr, &ip.dst_addr, &req[off..off + 32]);
        assert_eq!(cksum, [0x00, 0x00]);
    }

    #[test]
    fn resolve_v6_frame_too_small_goes_to_rx() {
        let handler = new_ndp_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = [0u8; 20];
        let frame = Frame::new(0, &mut data, 1, false);

        handler.resolve_v6(TEST_LOCAL_IPV6, TEST_REMOTE_IPV6, frame, &mut rx, &mut tx);

        assert_eq!(rx.num_frames(), 1);
        assert_eq!(tx.num_frames(), 0);
    }
}
