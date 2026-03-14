use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use libvoid::net::http::codec::parse;

fn make_request(header_count: usize) -> Vec<u8> {
    let mut buf = b"GET /index.html HTTP/1.1\r\n".to_vec();
    for i in 0..header_count {
        buf.extend_from_slice(
            format!("X-Header-{i}: value-{i}-padding-to-make-it-longer\r\n").as_bytes(),
        );
    }
    buf.extend_from_slice(b"\r\n");
    buf
}

fn bench_memchr_newline(c: &mut Criterion) {
    let mut group = c.benchmark_group("memchr_newline");
    let short = b"GET /index.html HTTP/1.1\r\n";
    let long = b"GET /index.html/with/a/longer/path/to/make/it/more/realistic/for/benchmarking HTTP/1.1\r\n";
    group.bench_function("short_26B", |b| {
        b.iter(|| std::hint::black_box(parse::memchr_newline(short)));
    });
    group.bench_function("long_90B", |b| {
        b.iter(|| std::hint::black_box(parse::memchr_newline(long)));
    });
    group.finish();
}

fn bench_parse_request_line(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_request_line");
    let simple = b"GET /index.html HTTP/1.1\r\n";
    let long_path = b"GET /api/v2/users/12345/documents/67890/metadata HTTP/1.1\r\n";
    group.bench_function("simple", |b| {
        b.iter(|| std::hint::black_box(parse::parse_request_line(simple, 0)));
    });
    group.bench_function("long_path", |b| {
        b.iter(|| std::hint::black_box(parse::parse_request_line(long_path, 0)));
    });
    group.finish();
}

fn bench_parse_headers(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_headers");
    for count in [2, 8, 32, 64] {
        let req = make_request(count);
        // Skip past the request line to get just the header block.
        let header_start = memchr::memchr(b'\n', &req).unwrap() + 1;
        let header_buf = &req[header_start..];
        let label = format!("{count}_headers_{}B", header_buf.len());
        group.bench_with_input(
            BenchmarkId::new("count", &label),
            &header_buf.to_vec(),
            |b, buf| {
                b.iter(|| std::hint::black_box(parse::parse_headers(buf)));
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_memchr_newline,
    bench_parse_request_line,
    bench_parse_headers
);
criterion_main!(benches);
