//! Benchmarks for data structures: LruCollector, ConvManager.
//!
//! Measures performance at scale (up to 10k entries) for:
//! - LruCollector: new_key, update, peek_back, erase
//! - ConvManager: insert_conv, find_conv_by_data, update_active_time, clear_inactive
//!
//! These are server-side hot-path when managing many concurrent connections.
//!
//! Run: cargo bench --bench data_structures_bench

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::net::SocketAddr;
use udp2raw::common::LruCollector;
use udp2raw::connection::ConvManager;

fn bench_lru_new_key(c: &mut Criterion) {
    let mut group = c.benchmark_group("lru_collector/new_key");

    let sizes: &[(usize, &str)] = &[
        (100, "100"),
        (1000, "1k"),
        (10000, "10k"),
    ];

    for &(size, label) in sizes {
        group.bench_with_input(BenchmarkId::from_parameter(label), &size, |b, &size| {
            b.iter(|| {
                let mut lru = LruCollector::<u32>::with_capacity(size);
                for i in 0..size as u32 {
                    lru.new_key(black_box(i));
                }
            });
        });
    }
    group.finish();
}

fn bench_lru_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("lru_collector/update");

    let sizes: &[(usize, &str)] = &[
        (100, "100"),
        (1000, "1k"),
        (10000, "10k"),
    ];

    for &(size, label) in sizes {
        let mut lru = LruCollector::<u32>::with_capacity(size);
        for i in 0..size as u32 {
            lru.new_key(i);
        }

        group.bench_with_input(BenchmarkId::from_parameter(label), &size, |b, &size| {
            let mut idx = 0u32;
            b.iter(|| {
                lru.update(&black_box(idx % size as u32));
                idx += 1;
            });
        });
    }
    group.finish();
}

fn bench_lru_peek_back(c: &mut Criterion) {
    let mut group = c.benchmark_group("lru_collector/peek_back");

    let sizes: &[(usize, &str)] = &[
        (100, "100"),
        (1000, "1k"),
        (10000, "10k"),
    ];

    for &(size, label) in sizes {
        let mut lru = LruCollector::<u32>::with_capacity(size);
        for i in 0..size as u32 {
            lru.new_key(i);
        }

        group.bench_with_input(BenchmarkId::from_parameter(label), &size, |b, _| {
            b.iter(|| lru.peek_back());
        });
    }
    group.finish();
}

fn bench_conv_manager_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("conv_manager/insert");

    let sizes: &[(usize, &str)] = &[
        (100, "100"),
        (1000, "1k"),
        (5000, "5k"),
    ];

    for &(size, label) in sizes {
        group.bench_with_input(BenchmarkId::from_parameter(label), &size, |b, &size| {
            b.iter(|| {
                let mut cm = ConvManager::<SocketAddr>::new();
                for i in 0..size {
                    let addr: SocketAddr = format!("10.0.{}.{}:{}", i / 256, i % 256, 10000 + i)
                        .parse()
                        .unwrap();
                    let conv = (i as u32).wrapping_add(1); // non-zero
                    cm.insert_conv(black_box(conv), addr);
                }
            });
        });
    }
    group.finish();
}

fn bench_conv_manager_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("conv_manager/lookup");

    let sizes: &[(usize, &str)] = &[
        (100, "100"),
        (1000, "1k"),
        (5000, "5k"),
    ];

    for &(size, label) in sizes {
        let mut cm = ConvManager::<SocketAddr>::new();
        let mut addrs = Vec::with_capacity(size);
        for i in 0..size {
            let addr: SocketAddr = format!("10.0.{}.{}:{}", i / 256, i % 256, 10000 + i)
                .parse()
                .unwrap();
            let conv = (i as u32).wrapping_add(1);
            cm.insert_conv(conv, addr.clone());
            addrs.push((conv, addr));
        }

        group.bench_with_input(BenchmarkId::new("by_data", label), &size, |b, &size| {
            let mut idx = 0usize;
            b.iter(|| {
                let (_, ref addr) = addrs[idx % size];
                idx += 1;
                cm.find_conv_by_data(black_box(addr))
            });
        });

        group.bench_with_input(BenchmarkId::new("by_conv", label), &size, |b, &size| {
            let mut idx = 0usize;
            b.iter(|| {
                let (conv, _) = addrs[idx % size];
                idx += 1;
                cm.find_data_by_conv(black_box(conv))
            });
        });
    }
    group.finish();
}

fn bench_conv_manager_update_active(c: &mut Criterion) {
    let mut group = c.benchmark_group("conv_manager/update_active");

    let size = 1000usize;
    let mut cm = ConvManager::<SocketAddr>::new();
    let mut convs = Vec::with_capacity(size);
    for i in 0..size {
        let addr: SocketAddr = format!("10.0.{}.{}:{}", i / 256, i % 256, 10000 + i)
            .parse()
            .unwrap();
        let conv = (i as u32).wrapping_add(1);
        cm.insert_conv(conv, addr);
        convs.push(conv);
    }

    group.bench_function("1k_entries", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let conv = convs[idx % size];
            idx += 1;
            cm.update_active_time(black_box(conv));
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_lru_new_key,
    bench_lru_update,
    bench_lru_peek_back,
    bench_conv_manager_insert,
    bench_conv_manager_lookup,
    bench_conv_manager_update_active,
);
criterion_main!(benches);
