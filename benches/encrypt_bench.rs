//! Benchmarks for the encryption/decryption pipeline.
//!
//! Measures `my_encrypt` and `my_decrypt` throughput for all 20 cipher×auth
//! combinations across realistic payload sizes (64B, 512B, 1200B, 9000B).
//!
//! Run: cargo bench --bench encrypt_bench

use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};
use udp2raw::common::{AuthMode, BUF_LEN, CipherMode, HUGE_BUF_LEN};
use udp2raw::encrypt::{EncryptionKeys, Encryptor};

const PAYLOAD_SIZES: &[(usize, &str)] = &[
    (64, "64B"),
    (512, "512B"),
    (1200, "1200B_mtu"),
    (9000, "9000B_jumbo"),
];

const CIPHERS: &[(CipherMode, &str)] = &[
    (CipherMode::None, "none"),
    (CipherMode::Xor, "xor"),
    (CipherMode::Aes128Cbc, "aes128cbc"),
    (CipherMode::Aes128Cfb, "aes128cfb"),
];

const AUTHS: &[(AuthMode, &str)] = &[
    (AuthMode::None, "none"),
    (AuthMode::Md5, "md5"),
    (AuthMode::Crc32, "crc32"),
    (AuthMode::Simple, "simple"),
    (AuthMode::HmacSha1, "hmac_sha1"),
];

fn bench_encrypt(c: &mut Criterion) {
    let client_keys = EncryptionKeys::derive("bench_password", true);

    for &(cipher_mode, cipher_name) in CIPHERS {
        for &(auth_mode, auth_name) in AUTHS {
            let encryptor = Encryptor::new(client_keys.clone(), auth_mode, cipher_mode);

            let group_name = format!("encrypt/{}/{}", cipher_name, auth_name);
            let mut group = c.benchmark_group(&group_name);

            for &(size, size_name) in PAYLOAD_SIZES {
                // AES-CFB requires at least 16 bytes input
                if cipher_mode == CipherMode::Aes128Cfb && size < 16 {
                    continue;
                }

                // BUF_LEN is 2200 (MAX_DATA_LEN + 400); skip sizes that exceed it
                if size > BUF_LEN - 200 {
                    continue;
                }

                let plaintext = vec![0xABu8; size];
                let mut output = vec![0u8; HUGE_BUF_LEN];

                group.throughput(Throughput::Bytes(size as u64));
                group.bench_with_input(
                    BenchmarkId::from_parameter(size_name),
                    &size,
                    |b, _| {
                        b.iter(|| {
                            encryptor
                                .my_encrypt(black_box(&plaintext), &mut output)
                                .unwrap();
                        });
                    },
                );
            }
            group.finish();
        }
    }
}

fn bench_decrypt(c: &mut Criterion) {
    let client_keys = EncryptionKeys::derive("bench_password", true);
    let server_keys = EncryptionKeys::derive("bench_password", false);

    for &(cipher_mode, cipher_name) in CIPHERS {
        for &(auth_mode, auth_name) in AUTHS {
            let client_enc = Encryptor::new(client_keys.clone(), auth_mode, cipher_mode);
            let server_dec = Encryptor::new(server_keys.clone(), auth_mode, cipher_mode);

            let group_name = format!("decrypt/{}/{}", cipher_name, auth_name);
            let mut group = c.benchmark_group(&group_name);

            for &(size, size_name) in PAYLOAD_SIZES {
                if cipher_mode == CipherMode::Aes128Cfb && size < 16 {
                    continue;
                }

                // BUF_LEN is 2200; skip sizes that exceed internal buffer
                if size > BUF_LEN - 200 {
                    continue;
                }

                let plaintext = vec![0xABu8; size];
                let mut encrypted = vec![0u8; HUGE_BUF_LEN];
                let enc_len = client_enc.my_encrypt(&plaintext, &mut encrypted).unwrap();
                let encrypted_data = encrypted[..enc_len].to_vec();

                let mut output = vec![0u8; HUGE_BUF_LEN];

                group.throughput(Throughput::Bytes(size as u64));
                group.bench_with_input(
                    BenchmarkId::from_parameter(size_name),
                    &size,
                    |b, _| {
                        b.iter(|| {
                            server_dec
                                .my_decrypt(black_box(&encrypted_data), &mut output)
                                .unwrap();
                        });
                    },
                );
            }
            group.finish();
        }
    }
}

fn bench_encrypt_decrypt_roundtrip(c: &mut Criterion) {
    let client_keys = EncryptionKeys::derive("bench_password", true);
    let server_keys = EncryptionKeys::derive("bench_password", false);

    // Focus on the most common production combinations
    let combos: &[(CipherMode, AuthMode, &str)] = &[
        (CipherMode::Aes128Cbc, AuthMode::Md5, "aes128cbc+md5"),
        (CipherMode::Aes128Cbc, AuthMode::HmacSha1, "aes128cbc+hmac_sha1"),
        (CipherMode::Aes128Cfb, AuthMode::HmacSha1, "aes128cfb+hmac_sha1"),
        (CipherMode::Xor, AuthMode::Crc32, "xor+crc32"),
        (CipherMode::None, AuthMode::None, "none+none"),
    ];

    let mut group = c.benchmark_group("roundtrip");
    let payload = vec![0xABu8; 1200]; // typical MTU

    for &(cipher, auth, label) in combos {
        let enc = Encryptor::new(client_keys.clone(), auth, cipher);
        let dec = Encryptor::new(server_keys.clone(), auth, cipher);

        group.throughput(Throughput::Bytes(1200));
        group.bench_with_input(BenchmarkId::from_parameter(label), &(), |b, _| {
            let mut enc_buf = vec![0u8; BUF_LEN];
            let mut dec_buf = vec![0u8; BUF_LEN];
            b.iter(|| {
                let enc_len = enc.my_encrypt(black_box(&payload), &mut enc_buf).unwrap();
                dec.my_decrypt(black_box(&enc_buf[..enc_len]), &mut dec_buf)
                    .unwrap();
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_encrypt,
    bench_decrypt,
    bench_encrypt_decrypt_roundtrip,
);
criterion_main!(benches);

