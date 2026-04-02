//! Benchmarks for RFC 1071 checksum and byte-order helpers.
//!
//! Measures:
//! - `csum()` — single-buffer checksum at IP/TCP/full-packet sizes
//! - `csum_with_header()` — pseudo-header + payload checksum (TCP/UDP path)
//! - `numbers_to_bytes()` / `bytes_to_numbers()` — handshake ID serialization
//!
//! These are called on every sent/received packet, so they're hot-path critical.
//!
//! Run: cargo bench --bench checksum_bench

use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};
use udp2raw::common::{csum, csum_with_header, numbers_to_bytes, bytes_to_numbers};
use udp2raw::network::PseudoHeader;

const SIZES: &[(usize, &str)] = &[
    (20, "20B_ip_hdr"),
    (32, "32B_tcp_hdr_ts"),
    (60, "60B_tcp_full"),
    (576, "576B_min_mtu"),
    (1500, "1500B_eth_mtu"),
    (9000, "9000B_jumbo"),
];

fn bench_csum(c: &mut Criterion) {
    let mut group = c.benchmark_group("csum");

    for &(size, label) in SIZES {
        let data = vec![0xA5u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &data, |b, data| {
            b.iter(|| csum(black_box(data)));
        });
    }
    group.finish();
}

fn bench_csum_with_header(c: &mut Criterion) {
    let mut group = c.benchmark_group("csum_with_header");

    // Simulate TCP checksum: pseudo-header (12B) + TCP segment
    let pseudo_header = PseudoHeader {
        source_address: 0xC0A80164u32.to_be(), // 192.168.1.100
        dest_address: 0x5DB8D822u32.to_be(),    // 93.184.216.34
        placeholder: 0,
        protocol: 6, // TCP
        tcp_length: 0, // will be set per test
    };

    let ph_bytes = unsafe {
        std::slice::from_raw_parts(
            &pseudo_header as *const _ as *const u8,
            std::mem::size_of::<PseudoHeader>(),
        )
    };

    let payload_sizes: &[(usize, &str)] = &[
        (20, "20B_tcp_hdr"),
        (32, "32B_tcp_hdr_ts"),
        (1480, "1480B_full_tcp"),
        (8980, "8980B_jumbo_tcp"),
    ];

    for &(size, label) in payload_sizes {
        let payload = vec![0xA5u8; size];
        group.throughput(Throughput::Bytes((12 + size) as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &payload, |b, payload| {
            b.iter(|| csum_with_header(black_box(ph_bytes), black_box(payload)));
        });
    }
    group.finish();
}

fn bench_handshake_ids(c: &mut Criterion) {
    let mut group = c.benchmark_group("handshake_ids");

    group.bench_function("numbers_to_bytes", |b| {
        b.iter(|| {
            numbers_to_bytes(
                black_box(0xAABBCCDD),
                black_box(0x11223344),
                black_box(0xDEADBEEF),
            )
        });
    });

    group.bench_function("bytes_to_numbers", |b| {
        let data = numbers_to_bytes(0xAABBCCDD, 0x11223344, 0xDEADBEEF);
        b.iter(|| bytes_to_numbers(black_box(&data)));
    });

    // Roundtrip
    group.bench_function("roundtrip", |b| {
        b.iter(|| {
            let bytes = numbers_to_bytes(
                black_box(0xAABBCCDD),
                black_box(0x11223344),
                black_box(0xDEADBEEF),
            );
            bytes_to_numbers(black_box(&bytes))
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_csum,
    bench_csum_with_header,
    bench_handshake_ids,
);
criterion_main!(benches);

