pub const QUIC_VERSION_1: u32 = 0x00000001;
pub const QUIC_VERSION_2: u32 = 0x6b3343cf;

/// Map a QUIC version constant to the corresponding rustls quic::Version.
pub fn rustls_quic_version(version: u32) -> rustls::quic::Version {
    match version {
        QUIC_VERSION_2 => rustls::quic::Version::V2,
        _ => rustls::quic::Version::V1,
    }
}

/// Check if a version is known/supported
pub fn is_supported_version(version: u32) -> bool {
    version == QUIC_VERSION_1 || version == QUIC_VERSION_2
}

/// Encode long header packet type bits for the given space and version.
/// Returns the 2-bit type field value (RFC 9000 §17.2 / RFC 9369 §3.2).
pub fn long_packet_type_bits(space: u8, version: u32) -> u8 {
    if version == QUIC_VERSION_2 {
        match space {
            0 => 0x01, // Initial
            1 => 0x03, // Handshake
            _ => 0x02, // 0-RTT (space isn't used for Retry)
        }
    } else {
        match space {
            0 => 0x00, // Initial
            1 => 0x02, // Handshake
            _ => 0x01, // 0-RTT
        }
    }
}

/// Check if the given packet_type_bits represents an Initial packet for the given version.
pub fn is_initial_type(packet_type_bits: u8, version: u32) -> bool {
    if version == QUIC_VERSION_2 {
        packet_type_bits == 0x01
    } else {
        packet_type_bits == 0x00
    }
}

/// Check if version matches the reserved pattern for VN testing (0x?a?a?a?a)
pub fn is_reserved_version(version: u32) -> bool {
    (version & 0x0f0f0f0f) == 0x0a0a0a0a
}

/// Build a Version Negotiation packet directly into `buf`.
/// `dcid` and `scid` are echoed from the received packet (swapped: our DCID = their SCID).
/// Returns the number of bytes written.
pub fn build_version_negotiation(
    buf: &mut [u8],
    dcid: &[u8],
    scid: &[u8],
    supported: &[u32],
) -> usize {
    let mut pos = 0;
    // First byte: bit 7 set, lower 7 bits random (anti-ossification, RFC 8999 §6)
    let first_byte = {
        use ring::rand::SecureRandom;
        let mut b = [0u8; 1];
        ring::rand::SystemRandom::new().fill(&mut b).unwrap();
        0x80 | (b[0] & 0x7F)
    };
    buf[pos] = first_byte;
    pos += 1;
    buf[pos..pos + 4].copy_from_slice(&0u32.to_be_bytes());
    pos += 4;
    buf[pos] = dcid.len() as u8;
    pos += 1;
    buf[pos..pos + dcid.len()].copy_from_slice(dcid);
    pos += dcid.len();
    buf[pos] = scid.len() as u8;
    pos += 1;
    buf[pos..pos + scid.len()].copy_from_slice(scid);
    pos += scid.len();
    for &v in supported {
        buf[pos..pos + 4].copy_from_slice(&v.to_be_bytes());
        pos += 4;
    }
    pos
}

/// Client-side: check if a VN packet should be processed.
/// Discard if we've already successfully processed any packet on this connection.
pub fn should_process_version_negotiation(has_processed_packet: bool) -> bool {
    !has_processed_packet
}
