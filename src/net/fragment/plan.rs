/// Pre-computed fragment sizing plan for IP fragmentation.
///
/// Accepts a `transport_header_len` parameter instead of hardcoding
/// `UDP_HEADER_LEN`, making it usable with any transport protocol.
pub(crate) struct FragmentPlan {
    /// Maximum data bytes per fragment, 8-byte aligned: `(mtu - ip_overhead) & !7`.
    pub max_frag_data: usize,
    /// Data bytes in the first fragment after the transport header:
    /// `max_frag_data - transport_header_len`.
    pub first_chunk: usize,
    /// Total number of frames needed for the entire datagram.
    pub num_frames: usize,
}

impl FragmentPlan {
    /// Compute a fragmentation plan.
    ///
    /// - `ip_header_overhead`: total IP-layer overhead per fragment
    ///   (e.g. 20 for IPv4, 48 for IPv6 + fragment ext).
    /// - `transport_header_len`: bytes consumed by the transport header
    ///   in the first fragment (e.g. 8 for UDP).
    /// - `pmtu`: path MTU in bytes.
    /// - `payload_len`: application payload length (excluding transport header).
    pub fn new(
        ip_header_overhead: usize,
        transport_header_len: usize,
        pmtu: u32,
        payload_len: usize,
    ) -> Self {
        let max_frag_data = (pmtu as usize - ip_header_overhead) & !7;
        let first_chunk = max_frag_data - transport_header_len;
        let remaining = payload_len.saturating_sub(first_chunk);
        let subsequent_chunks = if remaining == 0 {
            0
        } else {
            remaining.div_ceil(max_frag_data)
        };
        FragmentPlan {
            max_frag_data,
            first_chunk,
            num_frames: 1 + subsequent_chunks,
        }
    }

    /// Returns `(ip_payload_len, data_to_copy)` for fragment `i`.
    ///
    /// - `transport_header_len`: size of the transport header (only relevant for i==0).
    /// - `payload_offset`: current offset into the application payload.
    /// - `payload_len`: total application payload length.
    pub fn fragment_sizes(
        &self,
        i: usize,
        transport_header_len: usize,
        payload_offset: usize,
        payload_len: usize,
    ) -> (usize, usize) {
        if i == 0 {
            let chunk = self.first_chunk.min(payload_len);
            (transport_header_len + chunk, chunk)
        } else if i == self.num_frames - 1 {
            let remaining = payload_len - payload_offset;
            (remaining, remaining)
        } else {
            (self.max_frag_data, self.max_frag_data)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_typical() {
        // IPv4: ip_overhead=20, transport=8 (UDP), MTU=1500, payload=3000
        let plan = FragmentPlan::new(20, 8, 1500, 3000);
        assert_eq!(plan.max_frag_data, 1480);
        assert_eq!(plan.first_chunk, 1472);
        assert_eq!(plan.num_frames, 3);
    }

    #[test]
    fn ipv6_typical() {
        // IPv6 + frag ext: ip_overhead=48, transport=8, MTU=1500, payload=3000
        let plan = FragmentPlan::new(48, 8, 1500, 3000);
        assert_eq!(plan.max_frag_data, 1448);
        assert_eq!(plan.first_chunk, 1440);
        assert_eq!(plan.num_frames, 3);
    }

    #[test]
    fn two_fragments() {
        let plan = FragmentPlan::new(20, 8, 1500, 1473);
        assert_eq!(plan.first_chunk, 1472);
        assert_eq!(plan.num_frames, 2);
    }

    #[test]
    fn exact_first_chunk() {
        let plan = FragmentPlan::new(20, 8, 1500, 1472);
        assert_eq!(plan.num_frames, 1);
    }

    #[test]
    fn eight_byte_alignment() {
        let plan = FragmentPlan::new(20, 8, 1505, 3000);
        assert_eq!(plan.max_frag_data % 8, 0);
        assert_eq!(plan.max_frag_data, 1480);
    }

    #[test]
    fn fragment_sizes_three() {
        let plan = FragmentPlan::new(20, 8, 1500, 3000);
        assert_eq!(plan.fragment_sizes(0, 8, 0, 3000), (1480, 1472));
        assert_eq!(plan.fragment_sizes(1, 8, 1472, 3000), (1480, 1480));
        assert_eq!(plan.fragment_sizes(2, 8, 2952, 3000), (48, 48));
    }

    #[test]
    fn fragment_sizes_two() {
        let plan = FragmentPlan::new(20, 8, 1500, 1473);
        assert_eq!(plan.fragment_sizes(0, 8, 0, 1473), (1480, 1472));
        assert_eq!(plan.fragment_sizes(1, 8, 1472, 1473), (1, 1));
    }

    #[test]
    fn large_payload() {
        let plan = FragmentPlan::new(20, 8, 1500, 65000);
        assert_eq!(plan.max_frag_data, 1480);
        assert_eq!(plan.first_chunk, 1472);
        assert_eq!(plan.num_frames, 44);
    }

    #[test]
    fn custom_transport_header_len() {
        // Transport header = 20 bytes (e.g. TCP), IPv4 overhead = 20
        let plan = FragmentPlan::new(20, 20, 1500, 3000);
        assert_eq!(plan.max_frag_data, 1480);
        assert_eq!(plan.first_chunk, 1460); // 1480 - 20
        // remaining = 3000 - 1460 = 1540, subsequent = ceil(1540/1480) = 2
        assert_eq!(plan.num_frames, 3);
    }
}
