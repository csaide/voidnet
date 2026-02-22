use std::time::{Duration, SystemTime};

use crate::net::wire::ethernet::MacAddress;
use crate::net::wire::ip::{IpAddress, IpProtocols, IPV4_MIN_HEADER_LEN, IPV6_HEADER_LEN, compute_ipv4_checksum};
use crate::net::wire::tcp::{self, TCP_HEADER_LEN, flags};
use crate::xdp::frame::{Frame, FrameBuffer};

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash, Hasher};

use super::tcb::{RetransmitEntry, Tcb};
use super::types::ConnectionId;

use std::time::Instant;

pub(crate) const DEFAULT_RCV_WND: u16 = 65535;
pub(crate) const DEFAULT_RCV_MSS: u16 = 1460;
pub(crate) const DEFAULT_TIME_WAIT_DURATION: Duration = Duration::from_secs(120);
pub(crate) const MAX_RETRANSMIT_TIME: Duration = Duration::from_secs(100);
pub(crate) const ETH_HEADER_LEN: usize = 14;

/// Builds a complete TCP segment (Ethernet + IP + TCP + options + payload).
///
/// Works for both IPv4 and IPv6 based on the address types provided.
pub(crate) fn build_tcp_segment<'umem>(
    mut frame: Frame<'umem>,
    src_mac: MacAddress,
    dst_mac: MacAddress,
    src_addr: IpAddress,
    dst_addr: IpAddress,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    seg_flags: u8,
    window: u16,
    options: &[u8],
    payload: &[u8],
) -> Option<Frame<'umem>> {
    let tcp_header_len = TCP_HEADER_LEN + options.len();

    let ip_header_len = match src_addr {
        IpAddress::V4(_) => IPV4_MIN_HEADER_LEN,
        IpAddress::V6(_) => IPV6_HEADER_LEN,
    };
    let total_len = ETH_HEADER_LEN + ip_header_len + tcp_header_len + payload.len();
    if total_len > frame.capacity() {
        return None;
    }

    // Set the frame length before writing so DerefMut exposes the full buffer.
    unsafe { frame.set_len(total_len) };

    frame[0..6].copy_from_slice(&<[u8; 6]>::from(dst_mac));
    frame[6..12].copy_from_slice(&<[u8; 6]>::from(src_mac));

    let ip_start = ETH_HEADER_LEN;

    match (src_addr, dst_addr) {
        (IpAddress::V4(src_ip), IpAddress::V4(dst_ip)) => {
            frame[12] = 0x08;
            frame[13] = 0x00;

            let ip_total_len = (IPV4_MIN_HEADER_LEN + tcp_header_len + payload.len()) as u16;
            frame[ip_start] = 0x45;
            frame[ip_start + 1] = 0;
            frame[ip_start + 2..ip_start + 4].copy_from_slice(&ip_total_len.to_be_bytes());
            frame[ip_start + 4..ip_start + 6].copy_from_slice(&[0, 0]);
            frame[ip_start + 6] = 0x40; // Don't Fragment
            frame[ip_start + 7] = 0;
            frame[ip_start + 8] = 64; // TTL
            frame[ip_start + 9] = IpProtocols::Tcp;
            frame[ip_start + 10] = 0;
            frame[ip_start + 11] = 0;
            let src_bytes: [u8; 4] = src_ip.into();
            frame[ip_start + 12..ip_start + 16].copy_from_slice(&src_bytes);
            let dst_bytes: [u8; 4] = dst_ip.into();
            frame[ip_start + 16..ip_start + 20].copy_from_slice(&dst_bytes);
            let ip_cksum =
                compute_ipv4_checksum(&frame[ip_start..ip_start + IPV4_MIN_HEADER_LEN]);
            frame[ip_start + 10] = ip_cksum[0];
            frame[ip_start + 11] = ip_cksum[1];
        }
        (IpAddress::V6(src_ip), IpAddress::V6(dst_ip)) => {
            frame[12] = 0x86;
            frame[13] = 0xDD;

            let payload_length = (tcp_header_len + payload.len()) as u16;
            frame[ip_start] = 0x60;
            frame[ip_start + 1] = 0;
            frame[ip_start + 2] = 0;
            frame[ip_start + 3] = 0;
            frame[ip_start + 4..ip_start + 6].copy_from_slice(&payload_length.to_be_bytes());
            frame[ip_start + 6] = IpProtocols::Tcp;
            frame[ip_start + 7] = 64; // Hop Limit
            let src_bytes: [u8; 16] = src_ip.into();
            frame[ip_start + 8..ip_start + 24].copy_from_slice(&src_bytes);
            let dst_bytes: [u8; 16] = dst_ip.into();
            frame[ip_start + 24..ip_start + 40].copy_from_slice(&dst_bytes);
        }
        _ => return None,
    }

    let tcp_off = ETH_HEADER_LEN + ip_header_len;
    let data_offset = (tcp_header_len / 4) as u8;
    frame[tcp_off..tcp_off + 2].copy_from_slice(&src_port.to_be_bytes());
    frame[tcp_off + 2..tcp_off + 4].copy_from_slice(&dst_port.to_be_bytes());
    frame[tcp_off + 4..tcp_off + 8].copy_from_slice(&seq.to_be_bytes());
    frame[tcp_off + 8..tcp_off + 12].copy_from_slice(&ack.to_be_bytes());
    frame[tcp_off + 12] = data_offset << 4;
    frame[tcp_off + 13] = seg_flags;
    frame[tcp_off + 14..tcp_off + 16].copy_from_slice(&window.to_be_bytes());
    frame[tcp_off + 16..tcp_off + 18].copy_from_slice(&[0, 0]); // checksum placeholder
    frame[tcp_off + 18..tcp_off + 20].copy_from_slice(&[0, 0]); // urgent ptr

    if !options.is_empty() {
        frame[tcp_off + TCP_HEADER_LEN..tcp_off + tcp_header_len].copy_from_slice(options);
    }

    if !payload.is_empty() {
        let payload_off = tcp_off + tcp_header_len;
        frame[payload_off..payload_off + payload.len()].copy_from_slice(payload);
    }

    let tcp_segment_len = tcp_header_len + payload.len();
    let cksum = match (src_addr, dst_addr) {
        (IpAddress::V4(src_ip), IpAddress::V4(dst_ip)) => {
            tcp::compute_tcp_checksum(&src_ip, &dst_ip, &frame[tcp_off..tcp_off + tcp_segment_len])
        }
        (IpAddress::V6(src_ip), IpAddress::V6(dst_ip)) => tcp::compute_tcp_checksum_v6(
            &src_ip,
            &dst_ip,
            &frame[tcp_off..tcp_off + tcp_segment_len],
        ),
        _ => unreachable!(),
    };
    frame[tcp_off + 16] = cksum[0];
    frame[tcp_off + 17] = cksum[1];

    Some(frame)
}

/// Send a TCP segment using addressing info from a TCB.
/// Pops a frame from `free_source`, builds the segment, pushes to `tx_return`.
pub(crate) fn send_segment<'umem>(
    tcb: &Tcb<'umem>,
    seq: u32,
    ack: u32,
    seg_flags: u8,
    window: u16,
    options: &[u8],
    payload: &[u8],
    free_source: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) {
    if let Some(frame) = free_source.pop() {
        if let Some(f) = build_tcp_segment(
            frame,
            tcb.local_mac,
            tcb.remote_mac,
            tcb.conn_id.local_addr,
            tcb.conn_id.remote_addr,
            tcb.conn_id.local_port,
            tcb.conn_id.remote_port,
            seq,
            ack,
            seg_flags,
            window,
            options,
            payload,
        ) {
            tx_return.push(f);
        }
    }
}

/// Send a segment and store a copy in the retransmit queue (for SYN, SYN-ACK, FIN).
/// `seq_len` is the number of sequence numbers consumed (1 for SYN/FIN).
pub(crate) fn send_and_queue_retransmit<'umem>(
    tcb: &mut Tcb<'umem>,
    seq: u32,
    ack: u32,
    seg_flags: u8,
    window: u16,
    options: &[u8],
    seq_len: usize,
    free_source: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) {
    let Some(frame) = free_source.pop() else {
        return;
    };
    let Some(tx_f) = build_tcp_segment(
        frame,
        tcb.local_mac,
        tcb.remote_mac,
        tcb.conn_id.local_addr,
        tcb.conn_id.remote_addr,
        tcb.conn_id.local_port,
        tcb.conn_id.remote_port,
        seq,
        ack,
        seg_flags,
        window,
        options,
        &[],
    ) else {
        return;
    };

    // Try to allocate a retransmit copy
    if let Some(mut retransmit_f) = free_source.pop() {
        let len = tx_f.len();
        unsafe { retransmit_f.set_len(len) };
        retransmit_f[..len].copy_from_slice(&tx_f[..len]);
        tcb.retransmit_queue.push_back(RetransmitEntry {
            seq,
            len: seq_len,
            frame: retransmit_f,
            sent_at: Instant::now(),
            retransmit_count: 0,
            is_retransmit: false,
            first_retransmit_time: None,
        });
    }

    tx_return.push(tx_f);
}

/// Send a RST segment without an existing TCB (stateless response).
pub(crate) fn send_rst_stateless<'umem>(
    src_addr: IpAddress,
    dst_addr: IpAddress,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    has_ack: bool,
    src_mac: MacAddress,
    dst_mac: MacAddress,
    free_source: &mut impl FrameBuffer<'umem>,
    tx_return: &mut impl FrameBuffer<'umem>,
) {
    if let Some(frame) = free_source.pop() {
        let seg_flags = flags::RST | if has_ack { flags::ACK } else { 0 };
        if let Some(f) = build_tcp_segment(
            frame, src_mac, dst_mac, src_addr, dst_addr, src_port, dst_port, seq, ack, seg_flags,
            0, &[], &[],
        ) {
            tx_return.push(f);
        }
    }
}

/// Per-process random secret for ISN generation (RFC 6528 §3).
static ISN_HASH_STATE: std::sync::LazyLock<RandomState> =
    std::sync::LazyLock::new(RandomState::new);

/// Generates an initial sequence number per RFC 6528.
///
/// Combines a time component with a cryptographic PRF (SipHash with
/// per-process random key) of the connection 4-tuple.
pub(crate) fn generate_isn(conn_id: &ConnectionId) -> u32 {
    let micros = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_micros() as u32;
    let mut hasher = ISN_HASH_STATE.build_hasher();
    conn_id.hash(&mut hasher);
    let hash = hasher.finish() as u32;
    micros.wrapping_add(hash)
}
