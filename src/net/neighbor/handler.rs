use std::net::IpAddr;

use coarsetime::{Duration, Instant};
use dashmap::DashMap;
use getifaddrs::InterfaceFilter;

use crate::{
    net::wire::{
        ethernet::MacAddress,
        ip::{IpAddress, Ipv4Address, Ipv6Address},
    },
    xdp::{
        error::Result,
        frame::{Frame, FrameBuffer},
    },
};

use super::{
    NeighborEntry,
    arp::{handle_arp, resolve_v4},
    ndp::{handle_ndp, resolve_v6},
};

/// Unified neighbor-resolution handler for ARP (IPv4) and NDP (IPv6).
///
/// Maintains an internal neighbor cache that maps protocol addresses to
/// hardware (MAC) addresses with a configurable TTL. Incoming ARP traffic
/// (both requests and replies) automatically populates the cache.
#[derive(Debug)]
pub struct NeighborHandler {
    local_mac: MacAddress,
    local_ipv4: Vec<Ipv4Address>,
    local_ipv6: Vec<Ipv6Address>,
    table: DashMap<IpAddress, NeighborEntry>,
    ttl: Duration,
    rx_offload: bool,
    tx_offload: bool,
}

impl NeighborHandler {
    /// Creates a new handler bound to the given MAC and IPv4 address.
    pub fn new(if_name: &str, ttl: Duration) -> Result<Self> {
        let mut local_ipv4 = Vec::new();
        let mut local_ipv6 = Vec::new();
        let mut local_mac = MacAddress::zero();

        let addresses = InterfaceFilter::new().name(if_name).get()?;
        for addr in addresses {
            if let Some(mac) = addr.address.mac_addr() {
                local_mac = MacAddress::from(mac);
                continue;
            }
            let Some(ip_addr) = addr.address.ip_addr() else {
                continue;
            };
            match ip_addr {
                IpAddr::V4(ip_addr) => {
                    local_ipv4.push(ip_addr.into());
                }
                IpAddr::V6(ip_addr) => {
                    local_ipv6.push(ip_addr.into());
                }
            }
        }
        Ok(Self {
            local_mac,
            local_ipv4,
            local_ipv6,
            table: DashMap::new(),
            ttl,
            rx_offload: false,
            tx_offload: false,
        })
    }

    /// Sets the checksum offload flags.
    pub fn set_offload(&mut self, rx_offload: bool, tx_offload: bool) {
        self.rx_offload = rx_offload;
        self.tx_offload = tx_offload;
    }

    /// Sets the local MAC address.
    pub fn set_local_mac(&mut self, mac: MacAddress) {
        self.local_mac = mac;
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

    /// Registers a local IP address for NDP or ARP response.
    pub fn add_local_ip(&mut self, addr: IpAddress) {
        match addr {
            IpAddress::V4(addr) => self.add_local_ipv4(addr),
            IpAddress::V6(addr) => self.add_local_ipv6(addr),
        }
    }

    /// Removes all entries whose TTL has expired.
    pub fn evict_stale(&self, now: Instant) {
        self.table.retain(|_, entry| !entry.is_expired(now));
    }

    /// Looks up a cached MAC for the given IP address (v4 or v6).
    ///
    /// Returns `None` if the entry is missing or expired.
    pub fn lookup(&self, now: Instant, ip: &IpAddress) -> Option<MacAddress> {
        self.table.get(ip).and_then(|e| {
            if !e.is_expired(now) {
                Some(e.mac())
            } else {
                None
            }
        })
    }

    /// Convenience wrapper that looks up an IPv4 address in the neighbor cache.
    pub fn lookup_v4(&self, now: Instant, ip: &Ipv4Address) -> Option<MacAddress> {
        self.lookup(now, &IpAddress::V4(*ip))
    }

    /// Convenience wrapper that looks up an IPv6 address in the neighbor cache.
    pub fn lookup_v6(&self, now: Instant, ip: &Ipv6Address) -> Option<MacAddress> {
        self.lookup(now, &IpAddress::V6(*ip))
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
        frame: Frame<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        resolve_v4(
            self.local_mac,
            source_ip,
            target_ip,
            frame,
            rx_return,
            tx_return,
        );
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
        frame: Frame<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        resolve_v6(
            self.local_mac,
            source_ip,
            target_ip,
            self.tx_offload,
            frame,
            rx_return,
            tx_return,
        );
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
        &self,
        now: Instant,
        frame: Frame<'umem>,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        handle_arp(
            now,
            &self.table,
            self.local_mac,
            &self.local_ipv4,
            self.ttl,
            frame,
            rx_return,
            tx_return,
        );
    }

    /// Handles an incoming NDP (ICMPv6 Neighbor Discovery) frame.
    ///
    /// Dispatches on ICMPv6 type:
    /// * Neighbor Solicitation (135) -- reply with NA if targeting our address
    /// * Neighbor Advertisement (136) -- cache the advertised MAC
    /// * Router Advertisement (134) -- cache the router's MAC
    /// * Router Solicitation (133) and Redirect (137) -- pass to `rx_return`
    pub fn handle_ndp<'umem>(
        &self,
        now: Instant,
        frame: Frame<'umem>,
        icmpv6_offset: usize,
        icmpv6_len: usize,
        rx_return: &mut impl FrameBuffer<'umem>,
        tx_return: &mut impl FrameBuffer<'umem>,
    ) {
        handle_ndp(
            now,
            self.ttl,
            &self.table,
            &self.local_ipv6,
            self.local_mac,
            self.rx_offload,
            self.tx_offload,
            frame,
            icmpv6_offset,
            icmpv6_len,
            rx_return,
            tx_return,
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        net::wire::{
            arp::{ARP_FRAME_LEN, ArpFrame, ArpHardwareTypes, ArpOperations, ArpPacket},
            ethernet::{EtherTypes, EthernetFrame, MacAddress},
        },
        xdp::frame::BasicFrameBuffer,
    };

    use super::*;

    const TEST_LOCAL_MAC: MacAddress = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    const TEST_LOCAL_IP: Ipv4Address = Ipv4Address::new([192, 168, 1, 1]);
    const TEST_REMOTE_MAC: MacAddress = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    const TEST_REMOTE_IP: Ipv4Address = Ipv4Address::new([192, 168, 1, 100]);
    const TEST_TTL: Duration = Duration::from_secs(60);
    const TEST_LOCAL_IPV6: Ipv6Address =
        Ipv6Address::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    fn new_handler() -> NeighborHandler {
        let mut nh = NeighborHandler::new("test0", TEST_TTL).unwrap();
        nh.set_local_mac(TEST_LOCAL_MAC);
        nh.add_local_ipv4(TEST_LOCAL_IP);
        nh.add_local_ipv6(TEST_LOCAL_IPV6);
        nh
    }

    fn build_arp_reply(sender_mac: MacAddress, sender_ip: Ipv4Address) -> [u8; ARP_FRAME_LEN] {
        let f = ArpFrame {
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

    fn build_arp_request(target_ip: Ipv4Address) -> [u8; ARP_FRAME_LEN] {
        let f = ArpFrame {
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

    #[test]
    fn local_mac_returns_configured_value() {
        let handler = new_handler();
        assert_eq!(handler.local_mac(), TEST_LOCAL_MAC);
    }

    #[test]
    fn lookup_unknown_v4_returns_none() {
        let now = Instant::now();
        let handler = new_handler();
        let unknown = IpAddress::V4(Ipv4Address::new([10, 0, 0, 1]));
        assert!(handler.lookup(now, &unknown).is_none());
    }

    #[test]
    fn lookup_unknown_v6_returns_none() {
        let now = Instant::now();
        let handler = new_handler();
        let unknown = IpAddress::V6(Ipv6Address::new([
            0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99,
        ]));
        assert!(handler.lookup(now, &unknown).is_none());
    }

    #[test]
    fn lookup_returns_cached_entry() {
        let now = Instant::now();
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = build_arp_reply(TEST_REMOTE_MAC, TEST_REMOTE_IP);
        let frame = Frame::new(0, &mut data, ARP_FRAME_LEN, false);
        handler.handle_arp(now, frame, &mut rx, &mut tx);

        assert_eq!(
            handler.lookup(now, &IpAddress::V4(TEST_REMOTE_IP)),
            Some(TEST_REMOTE_MAC)
        );
    }

    #[test]
    fn lookup_expired_entry_returns_none() {
        let now = Instant::now();
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = build_arp_reply(TEST_REMOTE_MAC, TEST_REMOTE_IP);
        let frame = Frame::new(0, &mut data, ARP_FRAME_LEN, false);
        handler.handle_arp(now, frame, &mut rx, &mut tx);

        let future = now + TEST_TTL + Duration::from_secs(1);
        assert!(
            handler
                .lookup(future, &IpAddress::V4(TEST_REMOTE_IP))
                .is_none()
        );
    }

    #[test]
    fn evict_stale_removes_expired_entries() {
        let now = Instant::now();
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = build_arp_reply(TEST_REMOTE_MAC, TEST_REMOTE_IP);
        let frame = Frame::new(0, &mut data, ARP_FRAME_LEN, false);
        handler.handle_arp(now, frame, &mut rx, &mut tx);

        assert!(handler.lookup_v4(now, &TEST_REMOTE_IP).is_some());

        let future = now + TEST_TTL + Duration::from_secs(1);
        handler.evict_stale(future);

        assert!(handler.lookup_v4(future, &TEST_REMOTE_IP).is_none());
    }

    #[test]
    fn evict_stale_keeps_fresh_entries() {
        let now = Instant::now();
        let handler = new_handler();
        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = build_arp_reply(TEST_REMOTE_MAC, TEST_REMOTE_IP);
        let frame = Frame::new(0, &mut data, ARP_FRAME_LEN, false);
        handler.handle_arp(now, frame, &mut rx, &mut tx);

        let still_valid = now + Duration::from_secs(30);
        handler.evict_stale(still_valid);

        assert_eq!(
            handler.lookup_v4(still_valid, &TEST_REMOTE_IP),
            Some(TEST_REMOTE_MAC)
        );
    }

    #[test]
    fn evict_stale_selectively_removes_only_expired() {
        let now = Instant::now();
        let short_ttl = Duration::from_secs(10);
        let mut handler = NeighborHandler::new("test0", short_ttl).unwrap();
        handler.add_local_ipv4(TEST_LOCAL_IP);

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        // Insert entry A at t=0 (expires at t=10)
        let ip_a = Ipv4Address::new([192, 168, 1, 100]);
        let mac_a = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let mut data_a = build_arp_reply(mac_a, ip_a);
        let frame_a = Frame::new(0, &mut data_a, ARP_FRAME_LEN, false);
        handler.handle_arp(now, frame_a, &mut rx, &mut tx);

        // Insert entry B at t=5s (expires at t=15s)
        let t5 = now + Duration::from_secs(5);
        let ip_b = Ipv4Address::new([192, 168, 1, 101]);
        let mac_b = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01]);
        let mut data_b = build_arp_reply(mac_b, ip_b);
        let frame_b = Frame::new(0, &mut data_b, ARP_FRAME_LEN, false);
        handler.handle_arp(t5, frame_b, &mut rx, &mut tx);

        // At t=11, A is expired but B is still valid
        let t11 = now + Duration::from_secs(11);
        handler.evict_stale(t11);

        assert!(handler.lookup_v4(t11, &ip_a).is_none());
        assert_eq!(handler.lookup_v4(t11, &ip_b), Some(mac_b));
    }

    #[test]
    fn add_local_ip_v4_enables_arp_response() {
        let now = Instant::now();
        let mut handler = NeighborHandler::new("test0", TEST_TTL).unwrap();

        let new_ip = Ipv4Address::new([10, 0, 0, 1]);
        handler.add_local_ip(IpAddress::V4(new_ip));

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = build_arp_request(new_ip);
        let frame = Frame::new(0, &mut data, ARP_FRAME_LEN, false);
        handler.handle_arp(now, frame, &mut rx, &mut tx);

        assert_eq!(tx.num_frames(), 1);
        assert_eq!(rx.num_frames(), 0);
    }

    #[test]
    fn add_local_ipv4_dedup_does_not_break_responses() {
        let now = Instant::now();
        let mut handler = NeighborHandler::new("test0", TEST_TTL).unwrap();
        handler.add_local_ipv4(TEST_LOCAL_IP);
        handler.add_local_ipv4(TEST_LOCAL_IP); // duplicate

        let mut rx = BasicFrameBuffer::new(4);
        let mut tx = BasicFrameBuffer::new(4);

        let mut data = build_arp_request(TEST_LOCAL_IP);
        let frame = Frame::new(0, &mut data, ARP_FRAME_LEN, false);
        handler.handle_arp(now, frame, &mut rx, &mut tx);

        assert_eq!(tx.num_frames(), 1);
        assert_eq!(rx.num_frames(), 0);
    }
}
