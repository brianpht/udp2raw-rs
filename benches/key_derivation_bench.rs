//! Benchmarks for key derivation and encryptor initialization.
//!
//! Measures:
//! - `EncryptionKeys::derive()` — MD5 + PBKDF2(10000 rounds) + 5× HKDF expand
//! - `Encryptor::new()` — AES key schedule + optional HMAC state init
//!
//! These are one-time costs per connection, but important for server startup
//! with many concurrent connections.
//!
//! Run: cargo bench --bench key_derivation_bench

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use udp2raw::common::{AuthMode, CipherMode};
use udp2raw::encrypt::{EncryptionKeys, Encryptor};

fn bench_key_derivation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_derivation");

    let passwords = &[
        ("short", "pw"),
        ("typical", "my_secret_password"),
        ("long", "a_very_long_password_that_someone_might_actually_use_in_production_environments"),
    ];

    for &(label, password) in passwords {
        group.bench_with_input(
            BenchmarkId::new("derive", label),
            &password,
            |b, pw| {
                b.iter(|| {
                    EncryptionKeys::derive(black_box(pw), true)
                });
            },
        );
    }
    group.finish();
}

fn bench_encryptor_init(c: &mut Criterion) {
    let keys = EncryptionKeys::derive("bench_password", true);

    let combos: &[(CipherMode, AuthMode, &str)] = &[
        (CipherMode::None, AuthMode::None, "none+none"),
        (CipherMode::Xor, AuthMode::Crc32, "xor+crc32"),
        (CipherMode::Aes128Cbc, AuthMode::Md5, "aes128cbc+md5"),
        (CipherMode::Aes128Cbc, AuthMode::HmacSha1, "aes128cbc+hmac_sha1"),
        (CipherMode::Aes128Cfb, AuthMode::HmacSha1, "aes128cfb+hmac_sha1"),
    ];

    let mut group = c.benchmark_group("encryptor_init");
    for &(cipher, auth, label) in combos {
        group.bench_with_input(
            BenchmarkId::from_parameter(label),
            &(),
            |b, _| {
                b.iter(|| {
                    Encryptor::new(black_box(keys.clone()), auth, cipher)
                });
            },
        );
    }
    group.finish();
}

fn bench_full_init_pipeline(c: &mut Criterion) {
    // Measures the complete init cost: derive + encryptor::new
    // This is what happens once per connection establishment
    let mut group = c.benchmark_group("full_init");

    let combos: &[(CipherMode, AuthMode, &str)] = &[
        (CipherMode::Aes128Cbc, AuthMode::Md5, "aes128cbc+md5"),
        (CipherMode::Aes128Cbc, AuthMode::HmacSha1, "aes128cbc+hmac_sha1"),
    ];

    for &(cipher, auth, label) in combos {
        group.bench_with_input(
            BenchmarkId::from_parameter(label),
            &(),
            |b, _| {
                b.iter(|| {
                    let keys = EncryptionKeys::derive(black_box("bench_password"), true);
                    Encryptor::new(keys, auth, cipher)
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_key_derivation,
    bench_encryptor_init,
    bench_full_init_pipeline,
);
criterion_main!(benches);

