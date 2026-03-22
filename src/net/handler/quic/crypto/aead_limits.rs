/// AEAD usage limits per cipher suite (RFC 9001 §6.6)
#[derive(Clone, Copy)]
pub struct AeadLimits {
    /// Max packets to encrypt per key (confidentiality limit)
    pub confidentiality_limit: u64,
    /// Max failed decryptions per connection (integrity limit)
    pub integrity_limit: u64,
}

impl AeadLimits {
    /// AES-128-GCM / AES-256-GCM limits
    pub const AES_GCM: Self = Self {
        confidentiality_limit: 1 << 23, // 2^23
        integrity_limit: 1 << 52,       // 2^52
    };

    /// ChaCha20-Poly1305 limits
    pub const CHACHA20: Self = Self {
        confidentiality_limit: u64::MAX, // no practical limit
        integrity_limit: 1 << 36,        // 2^36
    };

    /// Check if key update is needed (approaching confidentiality limit)
    pub fn needs_key_update(&self, packets_encrypted: u64) -> bool {
        packets_encrypted + 1 >= self.confidentiality_limit
    }

    /// Check if connection must be closed (integrity limit reached)
    pub fn must_close(&self, failed_decryptions: u64) -> bool {
        failed_decryptions >= self.integrity_limit
    }
}
