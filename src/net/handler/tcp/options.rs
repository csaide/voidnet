use crate::net::wire::tcp::{parse_sack_blocks, parse_timestamp};

/// Pre-parsed TCP options. Computed once per segment, passed by reference.
#[derive(Debug, Clone, Copy)]
pub struct ParsedOptions {
    pub timestamp: Option<(u32, u32)>,
    pub sack_blocks: ([Option<(u32, u32)>; 4], usize),
}

impl ParsedOptions {
    /// Parse TCP options relevant to established-state processing.
    #[inline]
    pub fn parse(options: &[u8]) -> Self {
        Self {
            timestamp: parse_timestamp(options),
            sack_blocks: parse_sack_blocks(options),
        }
    }
}
