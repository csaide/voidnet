#![allow(clippy::too_many_arguments)]

use criterion::{Criterion, criterion_group, criterion_main};
use libvoid::net::NeighborHandler;
use libvoid::net::checksum::{compute_ipv4_checksum, compute_tcp_checksum_ip};
use libvoid::net::handler::tcp::TcpHandler;
use libvoid::net::timer_wheel::TimerWheel;
use libvoid::net::wire::ethernet::MacAddress;
use libvoid::net::wire::ip::{IPV4_MIN_HEADER_LEN, IpAddress, IpProtocols, Ipv4, Ipv4Address};
use libvoid::net::wire::tcp::{TCP_HEADER_LEN, flags};
use libvoid::xdp::frame::{BasicFrameBuffer, Frame, FrameBuffer};

const ETH_LEN: usize = 14;
const LOCAL_IP: Ipv4Address = Ipv4Address::new([10, 0, 0, 1]);
const REMOTE_IP: Ipv4Address = Ipv4Address::new([10, 0, 0, 2]);
const SRC_MAC: MacAddress = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
const DST_MAC: MacAddress = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

/// Pool of pre-allocated frame buffers to avoid leaking memory in benchmark loops.
struct FramePool {
    bufs: Vec<*mut [u8]>,
    idx: usize,
}

impl FramePool {
    fn new(count: usize) -> Self {
        let bufs = (0..count)
            .map(|_| Box::leak(vec![0u8; 2048].into_boxed_slice()) as *mut [u8])
            .collect();
        Self { bufs, idx: 0 }
    }

    fn next(&mut self) -> &'static mut [u8] {
        // Safety: we cycle through buffers. Each buffer is only used by one Frame at a time
        // because the previous Frame was consumed/dropped before we reuse the buffer.
        let buf = unsafe { &mut *self.bufs[self.idx] };
        self.idx = (self.idx + 1) % self.bufs.len();
        buf
    }
}

fn write_tcp_frame_into(
    buf: &mut [u8],
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    tcp_flags: u8,
    window: u16,
) -> usize {
    let frame_len = ETH_LEN + IPV4_MIN_HEADER_LEN + TCP_HEADER_LEN;
    let total_ip_len = (IPV4_MIN_HEADER_LEN + TCP_HEADER_LEN) as u16;
    buf[..frame_len].fill(0);

    buf[0..6].copy_from_slice(&SRC_MAC.octets);
    buf[6..12].copy_from_slice(&DST_MAC.octets);
    buf[12] = 0x08;
    buf[13] = 0x00;

    let ip = ETH_LEN;
    buf[ip] = 0x45;
    buf[ip + 2..ip + 4].copy_from_slice(&total_ip_len.to_be_bytes());
    buf[ip + 6] = 0x40;
    buf[ip + 8] = 64;
    buf[ip + 9] = IpProtocols::Tcp;
    let src_b: [u8; 4] = src_ip.into();
    let dst_b: [u8; 4] = dst_ip.into();
    buf[ip + 12..ip + 16].copy_from_slice(&src_b);
    buf[ip + 16..ip + 20].copy_from_slice(&dst_b);
    let ck = compute_ipv4_checksum(&buf[ip..ip + IPV4_MIN_HEADER_LEN]);
    buf[ip + 10] = ck[0];
    buf[ip + 11] = ck[1];

    let tcp = ip + IPV4_MIN_HEADER_LEN;
    buf[tcp..tcp + 2].copy_from_slice(&src_port.to_be_bytes());
    buf[tcp + 2..tcp + 4].copy_from_slice(&dst_port.to_be_bytes());
    buf[tcp + 4..tcp + 8].copy_from_slice(&seq.to_be_bytes());
    buf[tcp + 8..tcp + 12].copy_from_slice(&ack.to_be_bytes());
    buf[tcp + 12] = 5 << 4;
    buf[tcp + 13] = tcp_flags;
    buf[tcp + 14..tcp + 16].copy_from_slice(&window.to_be_bytes());
    let tc = compute_tcp_checksum_ip::<Ipv4>(&src_ip, &dst_ip, &buf[tcp..frame_len], &[]);
    buf[tcp + 16] = tc[0];
    buf[tcp + 17] = tc[1];

    frame_len
}

fn write_tcp_data_frame_into(
    buf: &mut [u8],
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    tcp_flags: u8,
    window: u16,
    payload: &[u8],
) -> usize {
    let frame_len = ETH_LEN + IPV4_MIN_HEADER_LEN + TCP_HEADER_LEN + payload.len();
    let total_ip_len = (frame_len - ETH_LEN) as u16;
    buf[..frame_len].fill(0);

    buf[0..6].copy_from_slice(&SRC_MAC.octets);
    buf[6..12].copy_from_slice(&DST_MAC.octets);
    buf[12] = 0x08;
    buf[13] = 0x00;

    let ip = ETH_LEN;
    buf[ip] = 0x45;
    buf[ip + 2..ip + 4].copy_from_slice(&total_ip_len.to_be_bytes());
    buf[ip + 6] = 0x40;
    buf[ip + 8] = 64;
    buf[ip + 9] = IpProtocols::Tcp;
    let src_b: [u8; 4] = src_ip.into();
    let dst_b: [u8; 4] = dst_ip.into();
    buf[ip + 12..ip + 16].copy_from_slice(&src_b);
    buf[ip + 16..ip + 20].copy_from_slice(&dst_b);
    let ck = compute_ipv4_checksum(&buf[ip..ip + IPV4_MIN_HEADER_LEN]);
    buf[ip + 10] = ck[0];
    buf[ip + 11] = ck[1];

    let tcp = ip + IPV4_MIN_HEADER_LEN;
    buf[tcp..tcp + 2].copy_from_slice(&src_port.to_be_bytes());
    buf[tcp + 2..tcp + 4].copy_from_slice(&dst_port.to_be_bytes());
    buf[tcp + 4..tcp + 8].copy_from_slice(&seq.to_be_bytes());
    buf[tcp + 8..tcp + 12].copy_from_slice(&ack.to_be_bytes());
    buf[tcp + 12] = 5 << 4;
    buf[tcp + 13] = tcp_flags;
    buf[tcp + 14..tcp + 16].copy_from_slice(&window.to_be_bytes());
    let ps = tcp + TCP_HEADER_LEN;
    buf[ps..ps + payload.len()].copy_from_slice(payload);
    let tc =
        compute_tcp_checksum_ip::<Ipv4>(&src_ip, &dst_ip, &buf[tcp..tcp + TCP_HEADER_LEN], payload);
    buf[tcp + 16] = tc[0];
    buf[tcp + 17] = tc[1];

    frame_len
}

fn alloc_buf() -> &'static mut [u8] {
    Box::leak(vec![0u8; 2048].into_boxed_slice())
}

fn setup_established(
    handler: &mut TcpHandler,
    nh: &NeighborHandler,
    free: &mut BasicFrameBuffer<'static>,
    rx: &mut BasicFrameBuffer<'static>,
    tx: &mut BasicFrameBuffer<'static>,
) -> u32 {
    let now = coarsetime::Instant::now();
    let _ = handler.listen(IpAddress::V4(LOCAL_IP), 80, 128);

    let syn = alloc_buf();
    let syn_len = write_tcp_frame_into(
        syn,
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1000,
        0,
        flags::SYN,
        65535,
    );
    let mut wheel = TimerWheel::new(coarsetime::Instant::now());
    handler.process_ipv4(
        Frame::new(0, syn, syn_len, false),
        now,
        &mut wheel,
        nh,
        free,
        rx,
        tx,
    );

    let syn_ack = tx.pop().unwrap();
    let t = ETH_LEN + IPV4_MIN_HEADER_LEN;
    let iss = u32::from_be_bytes([
        syn_ack[t + 4],
        syn_ack[t + 5],
        syn_ack[t + 6],
        syn_ack[t + 7],
    ]);
    free.push(syn_ack);

    let ack = alloc_buf();
    let ack_len = write_tcp_frame_into(
        ack,
        REMOTE_IP,
        LOCAL_IP,
        12345,
        80,
        1001,
        iss + 1,
        flags::ACK,
        65535,
    );
    let mut wheel = TimerWheel::new(coarsetime::Instant::now());
    handler.process_ipv4(
        Frame::new(0, ack, ack_len, false),
        now,
        &mut wheel,
        nh,
        free,
        rx,
        tx,
    );
    while let Some(f) = tx.pop() {
        free.push(f);
    }
    while let Some(f) = rx.pop() {
        free.push(f);
    }

    iss
}

fn bench_process_data(c: &mut Criterion) {
    c.bench_function("process_inbound/data_1400B", |b| {
        b.iter_custom(|iters| {
            let mut handler = TcpHandler::new(false, false);
            let nh = NeighborHandler::new("lo", coarsetime::Duration::from_secs(60)).unwrap();
            nh.seed_cache(
                coarsetime::Instant::now(),
                IpAddress::V4(REMOTE_IP),
                DST_MAC,
            );

            let mut free = BasicFrameBuffer::new(64);
            let mut rx = BasicFrameBuffer::new(64);
            let mut tx = BasicFrameBuffer::new(64);
            for _ in 0..64 {
                free.push(Frame::new(0, alloc_buf(), 2048, false));
            }

            let iss = setup_established(&mut handler, &nh, &mut free, &mut rx, &mut tx);
            let payload = vec![0xABu8; 1400];
            let mut seq = 1001u32;
            // Pool of 128 buffers cycled through — each buffer is reused after its Frame is consumed.
            let mut pool = FramePool::new(128);
            let mut wheel = TimerWheel::new(coarsetime::Instant::now());

            let start = std::time::Instant::now();
            for _ in 0..iters {
                let buf = pool.next();
                let len = write_tcp_data_frame_into(
                    buf,
                    REMOTE_IP,
                    LOCAL_IP,
                    12345,
                    80,
                    seq,
                    iss + 1,
                    flags::ACK | flags::PSH,
                    65535,
                    &payload,
                );
                handler.process_ipv4(
                    Frame::new(0, buf, len, false),
                    coarsetime::Instant::now(),
                    &mut wheel,
                    &nh,
                    &mut free,
                    &mut rx,
                    &mut tx,
                );
                seq = seq.wrapping_add(payload.len() as u32);
                while let Some(f) = tx.pop() {
                    free.push(f);
                }
                while rx.pop().is_some() {}
            }
            start.elapsed()
        });
    });
}

fn bench_process_ack(c: &mut Criterion) {
    c.bench_function("process_inbound/ack", |b| {
        b.iter_custom(|iters| {
            let mut handler = TcpHandler::new(false, false);
            let nh = NeighborHandler::new("lo", coarsetime::Duration::from_secs(60)).unwrap();
            nh.seed_cache(
                coarsetime::Instant::now(),
                IpAddress::V4(REMOTE_IP),
                DST_MAC,
            );

            let mut free = BasicFrameBuffer::new(64);
            let mut rx = BasicFrameBuffer::new(64);
            let mut tx = BasicFrameBuffer::new(64);
            for _ in 0..64 {
                free.push(Frame::new(0, alloc_buf(), 2048, false));
            }

            let iss = setup_established(&mut handler, &nh, &mut free, &mut rx, &mut tx);
            let mut pool = FramePool::new(128);
            let mut wheel = TimerWheel::new(coarsetime::Instant::now());

            let start = std::time::Instant::now();
            for _ in 0..iters {
                let buf = pool.next();
                let len = write_tcp_frame_into(
                    buf,
                    REMOTE_IP,
                    LOCAL_IP,
                    12345,
                    80,
                    1001,
                    iss + 1,
                    flags::ACK,
                    65535,
                );
                handler.process_ipv4(
                    Frame::new(0, buf, len, false),
                    coarsetime::Instant::now(),
                    &mut wheel,
                    &nh,
                    &mut free,
                    &mut rx,
                    &mut tx,
                );
                while let Some(f) = tx.pop() {
                    free.push(f);
                }
                while rx.pop().is_some() {}
            }
            start.elapsed()
        });
    });
}

criterion_group!(benches, bench_process_data, bench_process_ack);
criterion_main!(benches);
