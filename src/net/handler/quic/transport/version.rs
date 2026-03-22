pub const QUIC_VERSION_1: u32 = 0x00000001;
pub const QUIC_VERSION_2: u32 = 0x6b3343cf;

/// Check if a version is known/supported
pub fn is_supported_version(version: u32) -> bool {
    version == QUIC_VERSION_1 || version == QUIC_VERSION_2
}

/// Check if version matches the reserved pattern for VN testing (0x?a?a?a?a)
pub fn is_reserved_version(version: u32) -> bool {
    (version & 0x0f0f0f0f) == 0x0a0a0a0a
}

/// Build a Version Negotiation packet.
/// `dcid` and `scid` are echoed from the received packet (swapped: our DCID = their SCID).
/// Returns the VN packet bytes.
pub fn build_version_negotiation(dcid: &[u8], scid: &[u8], supported: &[u32]) -> Vec<u8> {
    // Format: first_byte(1, bit 7 set) + version(0x00000000, 4 bytes) + dcid_len(1) + dcid + scid_len(1) + scid + versions(4 each)
    let len = 1 + 4 + 1 + dcid.len() + 1 + scid.len() + supported.len() * 4;
    let mut buf = Vec::with_capacity(len);
    buf.push(0x80); // long header form, rest arbitrary
    buf.extend_from_slice(&0u32.to_be_bytes()); // version = 0
    buf.push(dcid.len() as u8);
    buf.extend_from_slice(dcid);
    buf.push(scid.len() as u8);
    buf.extend_from_slice(scid);
    for &v in supported {
        buf.extend_from_slice(&v.to_be_bytes());
    }
    buf
}

/// Client-side: check if a VN packet should be processed.
/// Discard if we've already successfully processed any packet on this connection.
pub fn should_process_version_negotiation(has_processed_packet: bool) -> bool {
    !has_processed_packet
}
