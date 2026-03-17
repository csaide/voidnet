//! IP fragmentation utilities.
//!
//! Provides utilities for fragmenting and reassembling IP packets of any version based on:
//! - [RFC-8200 (IPv6)](./dist/docs/rfc8200-ipv6.txt)
//! - [RFC-791 (IPv4)](./dist/docs/rfc791-ipv4.txt)
//!
//! This module handles the full fragmentation and defragmentation process, including checksum
//! and MTU handling.

mod id;
mod pkt;
mod plan;
mod reader;
mod transport;
mod writer;

pub use pkt::Packet;
pub use reader::{FragmentReader, ReassembledPacket};
pub use transport::TransportHeader;
pub use writer::FragmentWriter;
