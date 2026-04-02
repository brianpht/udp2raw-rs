//! Benchmarks for the anti-replay sliding window.
//!
//! Measures `AntiReplay::is_valid()` performance for:
//! 1. Sequential packets (best case — monotonically increasing seq)
//! 2. Random in-window packets (realistic reordering)
//! 3. Out-of-window rejection (worst case — old packets)
//! 4. Duplicate rejection (already-seen seq numbers)
//! 5. Large gap (full window clear)
//!
//! Run: cargo bench --bench anti_replay_bench

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use udp2raw::connection::AntiReplay;

fn bench_sequential_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("anti_replay/sequential");

    group.bench_function("is_valid", |b| {
        let mut ar = AntiReplay::new();
        let mut seq = 1u64;
        b.iter(|| {
            let result = ar.is_valid(black_box(seq), false);
            seq += 1;
            result
        });
    });

    group.bench_function("get_new_seq_for_send", |b| {
        let mut ar = AntiReplay::new();
        b.iter(|| ar.get_new_seq_for_send());
    });

    group.finish();
}

fn bench_random_in_window(c: &mut Criterion) {
    let mut group = c.benchmark_group("anti_replay/random_in_window");

    group.bench_function("is_valid", |b| {
        let mut ar = AntiReplay::new();
        for i in 1..=5000u64 {
            ar.is_valid(i, false);
        }
        let offsets: Vec<u64> = (0..10000u64)
            .map(|i| {
                let base = 5000 + (i / 3);
                let jitter = (i * 7 + 13) % 50;
                base + jitter
            })
            .collect();
        let mut idx = 0usize;
        b.iter(|| {
            let seq = offsets[idx % offsets.len()];
            idx += 1;
            ar.is_valid(black_box(seq), false)
        });
    });

    group.finish();
}

fn bench_out_of_window_reject(c: &mut Criterion) {
    let mut group = c.benchmark_group("anti_replay/out_of_window");

    group.bench_function("is_valid_reject", |b| {
        let mut ar = AntiReplay::new();
        ar.is_valid(100_000, false);
        let mut seq = 1u64;
        b.iter(|| {
            let result = ar.is_valid(black_box(seq), false);
            seq = (seq % 1000) + 1;
            result
        });
    });

    group.finish();
}

fn bench_duplicate_reject(c: &mut Criterion) {
    let mut group = c.benchmark_group("anti_replay/duplicate");

    group.bench_function("is_valid_dup", |b| {
        let mut ar = AntiReplay::new();
        for i in 1..=2000u64 {
            ar.is_valid(i, false);
        }
        let mut seq = 1u64;
        b.iter(|| {
            let result = ar.is_valid(black_box(seq), false);
            seq = (seq % 2000) + 1;
            result
        });
    });

    group.finish();
}

fn bench_large_gap(c: &mut Criterion) {
    let mut group = c.benchmark_group("anti_replay/large_gap");

    group.bench_function("window_clear", |b| {
        let mut ar = AntiReplay::new();
        let mut seq = 1u64;
        b.iter(|| {
            seq += 5000;
            ar.is_valid(black_box(seq), false)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_sequential_insert,
    bench_random_in_window,
    bench_out_of_window_reject,
    bench_duplicate_reject,
    bench_large_gap,
);
criterion_main!(benches);
