use rustls::quic::DirectionalKeys;

/// One direction of packet protection (encrypt OR decrypt).
pub struct DirectionalKey {
    pub packet_key: Box<dyn rustls::quic::PacketKey>,
    pub header_key: Box<dyn rustls::quic::HeaderProtectionKey>,
}

impl DirectionalKey {
    pub fn from_rustls(dk: DirectionalKeys) -> Self {
        Self {
            packet_key: dk.packet,
            header_key: dk.header,
        }
    }

    /// Replace the packet key while keeping the existing header protection key.
    /// Used during key updates where header protection keys are unchanged (RFC 9001 §5.4).
    pub fn update_packet_key(&mut self, new_packet_key: Box<dyn rustls::quic::PacketKey>) {
        self.packet_key = new_packet_key;
    }
}

/// A pair of keys for one packet space (local encrypts, remote decrypts).
pub struct KeyPair {
    pub local: DirectionalKey,  // encrypt outgoing
    pub remote: DirectionalKey, // decrypt incoming
}

/// All packet protection keys for a connection.
pub struct PacketKeys {
    pub initial: Option<KeyPair>,
    pub handshake: Option<KeyPair>,
    pub one_rtt: Option<KeyPair>,
    pub zero_rtt_seal: Option<DirectionalKey>, // 0-RTT encrypt only
    pub zero_rtt_open: Option<DirectionalKey>, // 0-RTT decrypt only
}

impl PacketKeys {
    pub fn new() -> Self {
        Self {
            initial: None,
            handshake: None,
            one_rtt: None,
            zero_rtt_seal: None,
            zero_rtt_open: None,
        }
    }
}

impl Default for PacketKeys {
    fn default() -> Self {
        Self::new()
    }
}
