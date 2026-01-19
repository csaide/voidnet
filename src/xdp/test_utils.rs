//! Test utilities for XDP testing.
//!
//! This module provides infrastructure for creating and managing virtual ethernet (veth)
//! pairs for testing XDP programs and sockets. The main abstraction is [`TestVethPair`],
//! which creates a veth pair on construction and automatically tears it down on drop.
//!
//! # Example
//!
//! ```no_run
//! use libvoid::xdp::test_utils::TestVethPair;
//!
//! let veth = TestVethPair::new().expect("failed to create veth pair");
//! println!("outer interface: {}", veth.outer_name());
//! println!("inner interface: {}", veth.inner_name());
//! // veth pair is automatically cleaned up when `veth` goes out of scope
//! ```

#![allow(dead_code)]

use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
    process::{Command, Output},
    sync::atomic::{AtomicU32, Ordering},
};

use thiserror::Error;

/// Global counter for generating unique veth pair names.
static VETH_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Prefix used for generated veth pair names.
const VETH_PREFIX: &str = "vnt";

/// IPv6 subnet prefix for test environments.
const IP6_SUBNET: &str = "fc00:dead:cafe";

/// Errors that can occur during test environment operations.
#[derive(Error, Debug)]
pub enum TestEnvError {
    #[error("failed to create veth pair: {0}")]
    CreateVethPair(String),

    #[error("failed to configure interface: {0}")]
    ConfigureInterface(String),

    #[error("failed to execute command '{cmd}': {source}")]
    CommandExecution {
        cmd: String,
        #[source]
        source: io::Error,
    },

    #[error("command '{cmd}' failed with status {status}: {stderr}")]
    CommandFailed {
        cmd: String,
        status: i32,
        stderr: String,
    },

    #[error("insufficient permissions: must be run as root")]
    InsufficientPermissions,

    #[error("failed to read interface MAC address: {0}")]
    ReadMacAddress(String),
}

pub type Result<T> = std::result::Result<T, TestEnvError>;

/// A MAC address represented as 6 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    /// Returns the MAC address as a byte slice.
    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

impl std::fmt::Display for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl std::str::FromStr for MacAddress {
    type Err = TestEnvError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let parts: Vec<&str> = s.trim().split(':').collect();
        if parts.len() != 6 {
            return Err(TestEnvError::ReadMacAddress(format!(
                "invalid MAC address format: {}",
                s
            )));
        }

        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            bytes[i] = u8::from_str_radix(part, 16).map_err(|_| {
                TestEnvError::ReadMacAddress(format!("invalid hex byte in MAC: {}", part))
            })?;
        }

        Ok(MacAddress(bytes))
    }
}

/// IP addresses assigned to a veth pair.
#[derive(Debug, Clone, Copy)]
pub struct VethAddresses {
    /// IPv6 address of the outer interface.
    pub outer_ipv6: Ipv6Addr,
    /// IPv6 address of the inner interface.
    pub inner_ipv6: Ipv6Addr,
    /// IPv4 address of the outer interface.
    pub outer_ipv4: Ipv4Addr,
    /// IPv4 address of the inner interface.
    pub inner_ipv4: Ipv4Addr,
}

impl VethAddresses {
    /// Generate addresses based on pair ID to ensure uniqueness.
    fn for_pair(pair_id: u32) -> Self {
        let ipv6_outer: Ipv6Addr = format!("{}:{:x}::1", IP6_SUBNET, pair_id)
            .parse()
            .expect("valid ipv6");
        let ipv6_inner: Ipv6Addr = format!("{}:{:x}::2", IP6_SUBNET, pair_id)
            .parse()
            .expect("valid ipv6");

        let ipv4_third = (pair_id & 0xFF) as u8;
        let ipv4_outer = Ipv4Addr::new(10, 11, ipv4_third, 1);
        let ipv4_inner = Ipv4Addr::new(10, 11, ipv4_third, 2);

        Self {
            outer_ipv6: ipv6_outer,
            inner_ipv6: ipv6_inner,
            outer_ipv4: ipv4_outer,
            inner_ipv4: ipv4_inner,
        }
    }
}

/// A virtual ethernet pair for testing XDP programs.
///
/// This struct manages the lifecycle of a veth pair, creating it on construction
/// and automatically cleaning it up when dropped. Each instance gets unique
/// interface names and addresses to allow parallel test execution.
///
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), libvoid::xdp::test_utils::TestEnvError> {
/// # use libvoid::xdp::test_utils::TestVethPair;
/// let veth = TestVethPair::new()?;
///
/// // Use outer_ifindex() and inner_ifindex() to bind XDP sockets
/// let outer_interface_name = veth.outer_name();
/// let inner_interface_name = veth.inner_name();
///
/// // Send packets through inner interface for testing
/// // ...
/// // veth pair cleaned up here
/// # Ok(()) }
/// ```
pub struct TestVethPair {
    pair_id: u32,
    outer_name: String,
    inner_name: String,
    outer_mac: MacAddress,
    inner_mac: MacAddress,
    addresses: VethAddresses,
}

impl TestVethPair {
    /// Create a new veth pair.
    ///
    /// This creates a veth pair with unique names and addresses, brings up both
    /// interfaces, and reads their MAC addresses. The pair is automatically
    /// cleaned up when dropped.
    pub fn new() -> Result<Self> {
        let pair_id = VETH_COUNTER.fetch_add(1, Ordering::Relaxed);
        let outer_name = format!("{}{}o", VETH_PREFIX, pair_id);
        let inner_name = format!("{}{}i", VETH_PREFIX, pair_id);
        let addresses = VethAddresses::for_pair(pair_id);

        let _ = run_cmd(&["/usr/sbin/ip", "link", "del", "dev", &outer_name]);

        // Create the veth pair
        run_cmd(&[
            "/usr/sbin/ip",
            "link",
            "add",
            "dev",
            &outer_name,
            "type",
            "veth",
            "peer",
            "name",
            &inner_name,
        ])
        .map_err(|e| TestEnvError::CreateVethPair(format!("{}", e)))?;

        // Cleanup helper for error cases
        let cleanup = |outer: &str| {
            let _ = run_cmd(&["/usr/sbin/ip", "link", "del", "dev", outer]);
        };

        // Bring up both interfaces
        if let Err(e) = run_cmd(&["/usr/sbin/ip", "link", "set", "dev", &outer_name, "up"]) {
            cleanup(&outer_name);
            return Err(TestEnvError::ConfigureInterface(format!(
                "failed to bring up {}: {}",
                outer_name, e
            )));
        }

        if let Err(e) = run_cmd(&["/usr/sbin/ip", "link", "set", "dev", &inner_name, "up"]) {
            cleanup(&outer_name);
            return Err(TestEnvError::ConfigureInterface(format!(
                "failed to bring up {}: {}",
                inner_name, e
            )));
        }

        // Configure IPv6 addresses
        let outer_ipv6_addr = format!("{}/64", addresses.outer_ipv6);
        let inner_ipv6_addr = format!("{}/64", addresses.inner_ipv6);

        if let Err(e) = run_cmd(&[
            "/usr/sbin/ip",
            "addr",
            "add",
            "dev",
            &outer_name,
            &outer_ipv6_addr,
        ]) {
            cleanup(&outer_name);
            return Err(TestEnvError::ConfigureInterface(format!(
                "failed to add IPv6 to {}: {}",
                outer_name, e
            )));
        }

        if let Err(e) = run_cmd(&[
            "/usr/sbin/ip",
            "addr",
            "add",
            "dev",
            &inner_name,
            &inner_ipv6_addr,
        ]) {
            cleanup(&outer_name);
            return Err(TestEnvError::ConfigureInterface(format!(
                "failed to add IPv6 to {}: {}",
                inner_name, e
            )));
        }

        // Configure IPv4 addresses
        let outer_ipv4_addr = format!("{}/24", addresses.outer_ipv4);
        let inner_ipv4_addr = format!("{}/24", addresses.inner_ipv4);

        if let Err(e) = run_cmd(&[
            "/usr/sbin/ip",
            "addr",
            "add",
            "dev",
            &outer_name,
            &outer_ipv4_addr,
        ]) {
            cleanup(&outer_name);
            return Err(TestEnvError::ConfigureInterface(format!(
                "failed to add IPv4 to {}: {}",
                outer_name, e
            )));
        }

        if let Err(e) = run_cmd(&[
            "/usr/sbin/ip",
            "addr",
            "add",
            "dev",
            &inner_name,
            &inner_ipv4_addr,
        ]) {
            cleanup(&outer_name);
            return Err(TestEnvError::ConfigureInterface(format!(
                "failed to add IPv4 to {}: {}",
                inner_name, e
            )));
        }

        // Read MAC addresses
        let outer_mac = read_mac_address(&outer_name).map_err(|e| {
            cleanup(&outer_name);
            e
        })?;

        let inner_mac = read_mac_address(&inner_name).map_err(|e| {
            cleanup(&outer_name);
            e
        })?;

        Ok(Self {
            pair_id,
            outer_name,
            inner_name,
            outer_mac,
            inner_mac,
            addresses,
        })
    }

    /// Returns the unique identifier for this veth pair.
    pub fn pair_id(&self) -> u32 {
        self.pair_id
    }

    /// Returns the name of the outer interface.
    pub fn outer_name(&self) -> &str {
        &self.outer_name
    }

    /// Returns the name of the inner interface.
    pub fn inner_name(&self) -> &str {
        &self.inner_name
    }

    /// Returns the MAC address of the outer interface.
    pub fn outer_mac(&self) -> MacAddress {
        self.outer_mac
    }

    /// Returns the MAC address of the inner interface.
    pub fn inner_mac(&self) -> MacAddress {
        self.inner_mac
    }

    /// Returns the assigned addresses for this veth pair.
    pub fn addresses(&self) -> &VethAddresses {
        &self.addresses
    }

    /// Returns the interface index of the outer interface.
    pub fn outer_ifindex(&self) -> Result<u32> {
        get_ifindex(&self.outer_name)
    }

    /// Returns the interface index of the inner interface.
    pub fn inner_ifindex(&self) -> Result<u32> {
        get_ifindex(&self.inner_name)
    }
}

impl Drop for TestVethPair {
    fn drop(&mut self) {
        // Delete the outer interface - this automatically deletes the peer
        if let Err(e) = run_cmd(&["/usr/sbin/ip", "link", "del", "dev", &self.outer_name]) {
            eprintln!(
                "warning: failed to delete veth interface {}: {}",
                self.outer_name, e
            );
        }
    }
}

/// Run a command and return its output.
fn run_cmd(args: &[&str]) -> Result<Output> {
    let cmd_str = args.join(" ");

    let output = Command::new(args[0])
        .args(&args[1..])
        .output()
        .map_err(|e| TestEnvError::CommandExecution {
            cmd: cmd_str.clone(),
            source: e,
        })?;

    if !output.status.success() {
        return Err(TestEnvError::CommandFailed {
            cmd: cmd_str,
            status: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }

    Ok(output)
}

/// Read the MAC address of an interface.
fn read_mac_address(iface: &str) -> Result<MacAddress> {
    let path = format!("/sys/class/net/{}/address", iface);
    match std::fs::read_to_string(&path) {
        Ok(content) => content.trim().parse(),
        Err(_) => {
            // Fallback: try using ip link show
            let output = run_cmd(&["/usr/sbin/ip", "-br", "link", "show", "dev", iface])?;
            let line = String::from_utf8_lossy(&output.stdout);
            // Format: "iface UP/DOWN aa:bb:cc:dd:ee:ff"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                parts[2].parse()
            } else {
                Err(TestEnvError::ReadMacAddress(format!(
                    "unexpected ip link output: {}",
                    line
                )))
            }
        }
    }
}

/// Get the interface index for an interface name.
fn get_ifindex(iface: &str) -> Result<u32> {
    let path = format!("/sys/class/net/{}/ifindex", iface);
    let content = std::fs::read_to_string(&path).map_err(|e| {
        TestEnvError::ConfigureInterface(format!("failed to read ifindex for {}: {}", iface, e))
    })?;

    content.trim().parse().map_err(|e| {
        TestEnvError::ConfigureInterface(format!("failed to parse ifindex for {}: {}", iface, e))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_address_parsing() {
        let mac: MacAddress = "aa:bb:cc:dd:ee:ff".parse().unwrap();
        assert_eq!(mac.as_bytes(), &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(mac.to_string(), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_mac_address_display() {
        let mac = MacAddress([0x01, 0x23, 0x45, 0x67, 0x89, 0xab]);
        assert_eq!(format!("{}", mac), "01:23:45:67:89:ab");
    }

    #[test]
    fn test_veth_addresses_uniqueness() {
        let addr1 = VethAddresses::for_pair(0);
        let addr2 = VethAddresses::for_pair(1);
        let addr3 = VethAddresses::for_pair(255);

        // All should have different addresses
        assert_ne!(addr1.outer_ipv4, addr2.outer_ipv4);
        assert_ne!(addr1.outer_ipv6, addr2.outer_ipv6);
        assert_ne!(addr2.outer_ipv4, addr3.outer_ipv4);
        assert_ne!(addr2.outer_ipv6, addr3.outer_ipv6);
    }

    #[test]
    fn test_veth_pair_creation() {
        let veth = TestVethPair::new().expect("failed to create veth pair");

        assert!(veth.outer_name().starts_with(VETH_PREFIX));
        assert!(!veth.outer_name().is_empty());
        assert!(!veth.inner_name().is_empty());

        // Verify interfaces exist
        assert!(get_ifindex(veth.outer_name()).is_ok());
        assert!(get_ifindex(veth.inner_name()).is_ok());
    }

    #[test]
    fn test_parallel_veth_creation() {
        let handles: Vec<_> = (0..4)
            .map(|_| {
                std::thread::spawn(|| TestVethPair::new().expect("failed to create veth pair"))
            })
            .collect();

        let veths: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Verify all pairs have unique names
        let names: std::collections::HashSet<_> =
            veths.iter().map(|v| v.outer_name().to_string()).collect();
        assert_eq!(names.len(), 4, "all veth pairs should have unique names");

        // Verify all pairs have unique addresses
        let addrs: std::collections::HashSet<_> = veths
            .iter()
            .map(|v| v.addresses().outer_ipv4.to_string())
            .collect();
        assert_eq!(
            addrs.len(),
            4,
            "all veth pairs should have unique addresses"
        );
    }

    #[test]
    fn test_veth_cleanup_on_drop() {
        let outer_name;
        {
            let veth = TestVethPair::new().expect("failed to create veth pair");
            outer_name = veth.outer_name().to_string();
            assert!(get_ifindex(&outer_name).is_ok());
        }
        // veth dropped here, interface should be gone
        assert!(get_ifindex(&outer_name).is_err());
    }
}
