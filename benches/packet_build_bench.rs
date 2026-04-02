//! Benchmarks for wire protocol packet building (serialization only, no I/O).
//!
//! Measures the CPU cost of building bare and safer packet buffers,
//! simulating the logic in `send_bare` and `send_safer` from connection.rs.
//! Includes GRO fix path (AES-ECB encrypt block).
//!
//! Run: cargo bench --bench packet_build_bench

use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};
use udp2raw::common::*;
use udp2raw::encrypt::{EncryptionKeys, Encryptor};
use udp2raw::network::{IpHeader, TcpHeader, PseudoHeader};

/// Simulate send_bare buffer construction + encryption (no raw socket I/O).
fn build_bare_packet(
    data: &[u8],
    encryptor: &Encryptor,
    output: &mut [u8],
) -> usize {
    let mut buf = [0u8; BUF_LEN];

    let iv = 0x0102030405060708u64;
    let padding = 0x090A0B0C0D0E0F10u64;

    let mut offset = 0;
    buf[offset..offset + 8].copy_from_slice(&iv.to_ne_bytes());
    offset += 8;
    buf[offset..offset + 8].copy_from_slice(&padding.to_ne_bytes());
    offset += 8;
    buf[offset] = b'b';
    offset += 1;
    buf[offset..offset + data.len()].copy_from_slice(data);
    let total = offset + data.len();

    encryptor.my_encrypt(&buf[..total], output).unwrap_or(0)
}

/// Simulate send_safer buffer construction + encryption (no raw socket I/O).
fn build_safer_packet(
    data: &[u8],
    my_id: u32,
    opposite_id: u32,
    seq: u64,
    pkt_type: u8,
    roller: u8,
    encryptor: &Encryptor,
    output: &mut [u8],
) -> usize {
    let mut buf = [0u8; BUF_LEN];

    let mut offset = 0;
    buf[offset..offset + 4].copy_from_slice(&my_id.to_be_bytes());
    offset += 4;
    buf[offset..offset + 4].copy_from_slice(&opposite_id.to_be_bytes());
    offset += 4;
    buf[offset..offset + 8].copy_from_slice(&hton64(seq).to_ne_bytes());
    offset += 8;
    buf[offset] = pkt_type;
    offset += 1;
    buf[offset] = roller;
    offset += 1;
    buf[offset..offset + data.len()].copy_from_slice(data);
    let total = offset + data.len();

    encryptor.my_encrypt(&buf[..total], output).unwrap_or(0)
}

/// Simulate GRO fix: prepend 2-byte length + AES-ECB encrypt first 16 bytes.
fn build_safer_gro_packet(
    data: &[u8],
    my_id: u32,
    opposite_id: u32,
    seq: u64,
    encryptor: &Encryptor,
    output: &mut [u8],
) -> usize {
    let mut buf = [0u8; BUF_LEN];

    let mut offset = 0;
    buf[offset..offset + 4].copy_from_slice(&my_id.to_be_bytes());
    offset += 4;
    buf[offset..offset + 4].copy_from_slice(&opposite_id.to_be_bytes());
    offset += 4;
    buf[offset..offset + 8].copy_from_slice(&hton64(seq).to_ne_bytes());
    offset += 8;
    buf[offset] = b'd';
    offset += 1;
    buf[offset] = 0;
    offset += 1;
    buf[offset..offset + data.len()].copy_from_slice(data);
    let total = offset + data.len();

    let enc_len = encryptor.my_encrypt(&buf[..total], &mut output[2..]).unwrap_or(0);
    write_u16(&mut output[..2], enc_len as u16);
    let final_len = enc_len + 2;

    if final_len >= 16 {
        let mut block = [0u8; 16];
        block.copy_from_slice(&output[..16]);
        encryptor.aes_ecb_encrypt_block(&mut block);
        output[..16].copy_from_slice(&block);
    }

    final_len
}

fn bench_bare_packet(c: &mut Criterion) {
    let keys = EncryptionKeys::derive("bench_password", true);
    let encryptor = Encryptor::new(keys, AuthMode::Md5, CipherMode::Aes128Cbc);

    let sizes: &[(usize, &str)] = &[
        (12, "12B_handshake"),
        (64, "64B"),
        (512, "512B"),
        (1200, "1200B_mtu"),
    ];

    let mut group = c.benchmark_group("packet_build/bare");
    for &(size, label) in sizes {
        let data = vec![0xABu8; size];
        let mut output = [0u8; BUF_LEN];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &data, |b, data| {
            b.iter(|| build_bare_packet(black_box(data), &encryptor, &mut output));
        });
    }
    group.finish();
}

fn bench_safer_packet(c: &mut Criterion) {
    let keys = EncryptionKeys::derive("bench_password", true);

    let combos: &[(CipherMode, AuthMode, &str)] = &[
        (CipherMode::Aes128Cbc, AuthMode::Md5, "aes128cbc+md5"),
        (CipherMode::Aes128Cbc, AuthMode::HmacSha1, "aes128cbc+hmac_sha1"),
        (CipherMode::Xor, AuthMode::Crc32, "xor+crc32"),
    ];

    for &(cipher, auth, combo_label) in combos {
        let encryptor = Encryptor::new(keys.clone(), auth, cipher);
        let group_name = format!("packet_build/safer/{}", combo_label);
        let mut group = c.benchmark_group(&group_name);

        let sizes: &[(usize, &str)] = &[
            (64, "64B"),
            (512, "512B"),
            (1200, "1200B_mtu"),
            (9000, "9000B_jumbo"),
        ];

        for &(size, label) in sizes {
            let data = vec![0xABu8; size];
            let mut output = vec![0u8; HUGE_BUF_LEN];
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(BenchmarkId::from_parameter(label), &data, |b, data| {
                b.iter(|| {
                    build_safer_packet(
                        black_box(data),
                        0xAABBCCDD,
                        0x11223344,
                        42,
                        b'd',
                        0,
                        &encryptor,
                        &mut output,
                    )
                });
            });
        }
        group.finish();
    }
}

fn bench_safer_gro_packet(c: &mut Criterion) {
    let keys = EncryptionKeys::derive("bench_password", true);
    let encryptor = Encryptor::new(keys, AuthMode::HmacSha1, CipherMode::Aes128Cbc);

    let sizes: &[(usize, &str)] = &[
        (64, "64B"),
        (512, "512B"),
        (1200, "1200B_mtu"),
        (9000, "9000B_jumbo"),
    ];

    let mut group = c.benchmark_group("packet_build/safer_gro");
    for &(size, label) in sizes {
        let data = vec![0xABu8; size];
        let mut output = vec![0u8; HUGE_BUF_LEN];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &data, |b, data| {
            b.iter(|| {
                build_safer_gro_packet(
                    black_box(data),
                    0xAABBCCDD,
                    0x11223344,
                    42,
                    &encryptor,
                    &mut output,
                )
            });
        });
    }
    group.finish();
}

fn bench_ip_header_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_build/ip_header");

    group.bench_function("build_ipv4_header", |b| {
        b.iter(|| {
            let mut iph = IpHeader::default();
            iph.set_version_ihl(4, 5);
            iph.tos = 0;
            iph.tot_len = 1500u16.to_be();
            iph.id = 42u16.to_be();
            iph.frag_off = 0x4000u16.to_be();
            iph.ttl = 64;
            iph.protocol = 6;
            iph.saddr = 0xC0A80164u32.to_be();
            iph.daddr = 0x5DB8D822u32.to_be();
            iph.check = 0;
            iph.check = csum(iph.as_bytes());
            black_box(iph)
        });
    });

    group.bench_function("build_tcp_header", |b| {
        b.iter(|| {
            let mut tcph = TcpHeader::default();
            tcph.source = 54321u16.to_be();
            tcph.dest = 80u16.to_be();
            tcph.seq = 0x12345678u32.to_be();
            tcph.ack_seq = 0xAABBCCDDu32.to_be();
            tcph.set_doff(8);
            tcph.set_flags(false, false, false, true, true);
            tcph.window = 65535u16.to_be();
            black_box(tcph)
        });
    });

    group.bench_function("tcp_checksum_1200B", |b| {
        let ph = PseudoHeader {
            source_address: 0xC0A80164u32.to_be(),
            dest_address: 0x5DB8D822u32.to_be(),
            placeholder: 0,
            protocol: 6,
            tcp_length: 1220u16.to_be(),
        };
        let ph_bytes = unsafe {
            std::slice::from_raw_parts(
                &ph as *const _ as *const u8,
                std::mem::size_of::<PseudoHeader>(),
            )
        };
        let tcp_segment = vec![0xA5u8; 1220];
        b.iter(|| csum_with_header(black_box(ph_bytes), black_box(&tcp_segment)));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_bare_packet,
    bench_safer_packet,
    bench_safer_gro_packet,
    bench_ip_header_build,
);
criterion_main!(benches);
