//! End-to-end pipeline benchmarks: latency (ns/packet) and throughput (packets/sec, MB/sec).
//!
//! Simulates the full send and recv paths WITHOUT actual I/O (sendto/recvfrom),
//! measuring only CPU processing cost per packet.
//!
//! ## Send path (what `send_safer` + `send_raw_tcp` do):
//!   1. Build safer header (my_id, opp_id, seq, type, roller)
//!   2. Encrypt (cipher + auth)
//!   3. Build TCP header (20-32 bytes) + IP header (20 bytes)
//!   4. Compute TCP checksum (pseudo-header + segment)
//!   5. Compute IP checksum
//!
//! ## Recv path (what `parse_protocol_payload` + `parse_safer_single` do):
//!   1. Parse TCP header + timestamp options
//!   2. Decrypt (auth verify + cipher)
//!   3. Parse safer header (IDs, seq, type, roller)
//!   4. Anti-replay check
//!
//! Reports:
//! - **Latency**: time per packet (ns) via criterion default
//! - **Throughput (packets/sec)**: via `Throughput::Elements(1)`
//! - **Throughput (bytes/sec)**: via `Throughput::Bytes(payload_size)`
//!
//! Run: cargo bench --bench pipeline_bench

use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};
use std::net::Ipv4Addr;
use udp2raw::common::*;
use udp2raw::connection::AntiReplay;
use udp2raw::encrypt::{EncryptionKeys, Encryptor};
use udp2raw::network::{IpHeader, PseudoHeader, RawInfo, TcpHeader, parse_protocol_payload};

// --- Simulated full send path (no I/O) ---

/// Full send pipeline: safer header -> encrypt -> TCP header -> IP header -> checksums.
/// Returns total IP packet length (ready for sendto).
fn simulate_send_safer_tcp(
    payload: &[u8],
    my_id: u32,
    opposite_id: u32,
    seq: u64,
    encryptor: &Encryptor,
    ip_id: u16,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    tcp_seq: u32,
    ack_seq: u32,
    packet_out: &mut [u8],
) -> usize {
    // Step 1: Build safer header + payload
    let mut safer_buf = [0u8; BUF_LEN];
    let mut offset = 0;
    safer_buf[offset..offset + 4].copy_from_slice(&my_id.to_be_bytes());
    offset += 4;
    safer_buf[offset..offset + 4].copy_from_slice(&opposite_id.to_be_bytes());
    offset += 4;
    safer_buf[offset..offset + 8].copy_from_slice(&hton64(seq).to_ne_bytes());
    offset += 8;
    safer_buf[offset] = b'd'; // data packet
    offset += 1;
    safer_buf[offset] = 0; // roller
    offset += 1;
    // Conv ID (4 bytes) + actual payload
    safer_buf[offset..offset + 4].copy_from_slice(&42u32.to_be_bytes());
    offset += 4;
    safer_buf[offset..offset + payload.len()].copy_from_slice(payload);
    let safer_total = offset + payload.len();

    // Step 2: Encrypt
    let mut encrypted = [0u8; BUF_LEN];
    let enc_len = encryptor
        .my_encrypt(&safer_buf[..safer_total], &mut encrypted)
        .unwrap_or(0);

    // Step 3: Build TCP header (with timestamp option -> 32 bytes)
    let tcp_hdr_len: usize = 32;
    let tcp_total = tcp_hdr_len + enc_len;

    let mut tcph = TcpHeader::default();
    tcph.source = src_port.to_be();
    tcph.dest = dst_port.to_be();
    tcph.seq = tcp_seq.to_be();
    tcph.ack_seq = ack_seq.to_be();
    tcph.set_doff(8); // 32 bytes / 4
    tcph.set_flags(false, false, false, true, true); // PSH+ACK
    tcph.window = 65535u16.to_be();
    tcph.check = 0;

    let tcp_start = 20; // after IP header
    packet_out[tcp_start..tcp_start + 20].copy_from_slice(tcph.as_bytes());
    // Timestamp option
    packet_out[tcp_start + 20] = 0x01; // NOP
    packet_out[tcp_start + 21] = 0x01; // NOP
    packet_out[tcp_start + 22] = 0x08; // Timestamp kind
    packet_out[tcp_start + 23] = 0x0A; // Timestamp length
    packet_out[tcp_start + 24..tcp_start + 28].copy_from_slice(&1000u32.to_be_bytes());
    packet_out[tcp_start + 28..tcp_start + 32].copy_from_slice(&999u32.to_be_bytes());
    // Encrypted payload
    packet_out[tcp_start + tcp_hdr_len..tcp_start + tcp_total]
        .copy_from_slice(&encrypted[..enc_len]);

    // Step 4: TCP checksum
    let ph = PseudoHeader {
        source_address: u32::from(src_ip).to_be(),
        dest_address: u32::from(dst_ip).to_be(),
        placeholder: 0,
        protocol: 6, // TCP
        tcp_length: (tcp_total as u16).to_be(),
    };
    let ph_bytes = unsafe {
        std::slice::from_raw_parts(
            &ph as *const _ as *const u8,
            std::mem::size_of::<PseudoHeader>(),
        )
    };
    let tcp_csum = csum_with_header(ph_bytes, &packet_out[tcp_start..tcp_start + tcp_total]);
    packet_out[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_csum.to_ne_bytes());

    // Step 5: IP header
    let ip_total_len = 20 + tcp_total;
    let mut iph = IpHeader::default();
    iph.set_version_ihl(4, 5);
    iph.tot_len = (ip_total_len as u16).to_be();
    iph.id = ip_id.to_be();
    iph.frag_off = 0x4000u16.to_be();
    iph.ttl = 64;
    iph.protocol = 6;
    iph.saddr = u32::from(src_ip).to_be();
    iph.daddr = u32::from(dst_ip).to_be();
    iph.check = 0;
    iph.check = csum(iph.as_bytes());
    packet_out[..20].copy_from_slice(iph.as_bytes());

    ip_total_len
}

/// Full recv pipeline: parse TCP header -> decrypt -> parse safer header -> anti-replay.
/// Returns payload length after all processing.
fn simulate_recv_safer_tcp(
    ip_packet: &[u8],
    my_id: u32,
    opposite_id: u32,
    encryptor: &Encryptor,
    anti_replay: &mut AntiReplay,
) -> usize {
    // Step 1: Parse TCP header from IP payload (skip 20-byte IP header)
    let ip_payload = &ip_packet[20..];
    let mut raw_info = RawInfo::default();

    let mut tcp_payload_buf = [0u8; BUF_LEN];
    let tcp_payload_len = parse_protocol_payload(
        ip_payload,
        &mut raw_info,
        RawMode::FakeTcp,
        &mut tcp_payload_buf,
    )
    .unwrap_or(0);

    if tcp_payload_len == 0 {
        return 0;
    }

    // Step 2: Decrypt
    let mut decrypted = [0u8; BUF_LEN];
    let dec_len = encryptor
        .my_decrypt(&tcp_payload_buf[..tcp_payload_len], &mut decrypted)
        .unwrap_or(0);

    if dec_len < 18 {
        return 0;
    }

    // Step 3: Parse safer header
    let h_opposite_id =
        u32::from_be_bytes([decrypted[0], decrypted[1], decrypted[2], decrypted[3]]);
    let h_my_id = u32::from_be_bytes([decrypted[4], decrypted[5], decrypted[6], decrypted[7]]);
    let mut seq_bytes = [0u8; 8];
    seq_bytes.copy_from_slice(&decrypted[8..16]);
    let h_seq = ntoh64(u64::from_ne_bytes(seq_bytes));

    if h_opposite_id != opposite_id || h_my_id != my_id {
        return 0;
    }

    // Step 4: Anti-replay check
    if !anti_replay.is_valid(h_seq, false) {
        return 0;
    }

    let _pkt_type = decrypted[16];
    let _roller = decrypted[17];

    // Data starts at offset 18 (after safer header)
    dec_len - 18
}

// --- Benchmarks ---

fn bench_send_latency(c: &mut Criterion) {
    let client_keys = EncryptionKeys::derive("bench_password", true);

    let combos: &[(CipherMode, AuthMode, &str)] = &[
        (CipherMode::Aes128Cbc, AuthMode::Md5, "aes128cbc+md5"),
        (CipherMode::Aes128Cbc, AuthMode::HmacSha1, "aes128cbc+hmac_sha1"),
        (CipherMode::Aes128Cfb, AuthMode::HmacSha1, "aes128cfb+hmac_sha1"),
        (CipherMode::Xor, AuthMode::Crc32, "xor+crc32"),
        (CipherMode::None, AuthMode::None, "none+none"),
    ];

    let sizes: &[(usize, &str)] = &[
        (64, "64B"),
        (512, "512B"),
        (1200, "1200B_mtu"),
    ];

    let src_ip = Ipv4Addr::new(192, 168, 1, 100);
    let dst_ip = Ipv4Addr::new(10, 0, 0, 1);

    for &(cipher, auth, combo_label) in combos {
        let encryptor = Encryptor::new(client_keys.clone(), auth, cipher);

        let mut group = c.benchmark_group(format!("pipeline_send_latency/{}", combo_label));

        for &(size, size_label) in sizes {
            let payload = vec![0xABu8; size];
            let mut packet_out = vec![0u8; HUGE_BUF_LEN];

            // Elements(1) -> criterion reports "elements/sec" = packets/sec
            group.throughput(Throughput::Elements(1));
            group.bench_with_input(
                BenchmarkId::from_parameter(size_label),
                &size,
                |b, _| {
                    let mut seq = 1u64;
                    b.iter(|| {
                        let _len = simulate_send_safer_tcp(
                            black_box(&payload),
                            0xAABBCCDD, 0x11223344, seq,
                            &encryptor, 42, src_ip, dst_ip,
                            54321, 80, 0x12345678, 0xAABBCCDD,
                            &mut packet_out,
                        );
                        seq += 1;
                    });
                },
            );
        }
        group.finish();
    }
}

fn bench_send_throughput(c: &mut Criterion) {
    let client_keys = EncryptionKeys::derive("bench_password", true);

    let combos: &[(CipherMode, AuthMode, &str)] = &[
        (CipherMode::Aes128Cbc, AuthMode::Md5, "aes128cbc+md5"),
        (CipherMode::Aes128Cbc, AuthMode::HmacSha1, "aes128cbc+hmac_sha1"),
        (CipherMode::Xor, AuthMode::Crc32, "xor+crc32"),
        (CipherMode::None, AuthMode::None, "none+none"),
    ];

    let src_ip = Ipv4Addr::new(192, 168, 1, 100);
    let dst_ip = Ipv4Addr::new(10, 0, 0, 1);

    for &(cipher, auth, combo_label) in combos {
        let encryptor = Encryptor::new(client_keys.clone(), auth, cipher);
        let mut group = c.benchmark_group(format!("pipeline_send_throughput/{}", combo_label));

        let sizes: &[(usize, &str)] = &[
            (64, "64B"),
            (512, "512B"),
            (1200, "1200B_mtu"),
            (9000, "9000B_jumbo"),
        ];

        for &(size, size_label) in sizes {
            let payload = vec![0xABu8; size];
            let mut packet_out = vec![0u8; HUGE_BUF_LEN];

            // Bytes -> criterion reports MB/sec throughput
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(
                BenchmarkId::from_parameter(size_label),
                &size,
                |b, _| {
                    let mut seq = 1u64;
                    b.iter(|| {
                        let _len = simulate_send_safer_tcp(
                            black_box(&payload),
                            0xAABBCCDD, 0x11223344, seq,
                            &encryptor, 42, src_ip, dst_ip,
                            54321, 80, 0x12345678, 0xAABBCCDD,
                            &mut packet_out,
                        );
                        seq += 1;
                    });
                },
            );
        }
        group.finish();
    }
}

fn bench_recv_latency(c: &mut Criterion) {
    let client_keys = EncryptionKeys::derive("bench_password", true);
    let server_keys = EncryptionKeys::derive("bench_password", false);

    let combos: &[(CipherMode, AuthMode, &str)] = &[
        (CipherMode::Aes128Cbc, AuthMode::Md5, "aes128cbc+md5"),
        (CipherMode::Aes128Cbc, AuthMode::HmacSha1, "aes128cbc+hmac_sha1"),
        (CipherMode::Aes128Cfb, AuthMode::HmacSha1, "aes128cfb+hmac_sha1"),
        (CipherMode::Xor, AuthMode::Crc32, "xor+crc32"),
        (CipherMode::None, AuthMode::None, "none+none"),
    ];

    let sizes: &[(usize, &str)] = &[
        (64, "64B"),
        (512, "512B"),
        (1200, "1200B_mtu"),
    ];

    let src_ip = Ipv4Addr::new(192, 168, 1, 100);
    let dst_ip = Ipv4Addr::new(10, 0, 0, 1);

    for &(cipher, auth, combo_label) in combos {
        let client_enc = Encryptor::new(client_keys.clone(), auth, cipher);
        let server_dec = Encryptor::new(server_keys.clone(), auth, cipher);

        let mut group = c.benchmark_group(format!("pipeline_recv_latency/{}", combo_label));

        for &(size, size_label) in sizes {
            let payload = vec![0xABu8; size];
            let num_packets = 256usize;
            let mut packets: Vec<Vec<u8>> = Vec::with_capacity(num_packets);

            for s in 0..num_packets as u64 {
                let mut pkt_buf = vec![0u8; HUGE_BUF_LEN];
                let pkt_len = simulate_send_safer_tcp(
                    &payload, 0xAABBCCDD, 0x11223344,
                    s + 1_000_000,
                    &client_enc, 42, src_ip, dst_ip,
                    54321, 80, 0x12345678, 0xAABBCCDD,
                    &mut pkt_buf,
                );
                packets.push(pkt_buf[..pkt_len].to_vec());
            }

            group.throughput(Throughput::Elements(1));
            group.bench_with_input(
                BenchmarkId::from_parameter(size_label),
                &size,
                |b, _| {
                    let mut ar = AntiReplay::new();
                    ar.is_valid(999_999, false);
                    let mut idx = 0usize;
                    b.iter(|| {
                        let pkt = &packets[idx % num_packets];
                        idx += 1;
                        simulate_recv_safer_tcp(
                            black_box(pkt),
                            0x11223344, 0xAABBCCDD,
                            &server_dec, &mut ar,
                        )
                    });
                },
            );
        }
        group.finish();
    }
}

fn bench_recv_throughput(c: &mut Criterion) {
    let client_keys = EncryptionKeys::derive("bench_password", true);
    let server_keys = EncryptionKeys::derive("bench_password", false);

    let combos: &[(CipherMode, AuthMode, &str)] = &[
        (CipherMode::Aes128Cbc, AuthMode::Md5, "aes128cbc+md5"),
        (CipherMode::Aes128Cbc, AuthMode::HmacSha1, "aes128cbc+hmac_sha1"),
        (CipherMode::Xor, AuthMode::Crc32, "xor+crc32"),
        (CipherMode::None, AuthMode::None, "none+none"),
    ];

    let src_ip = Ipv4Addr::new(192, 168, 1, 100);
    let dst_ip = Ipv4Addr::new(10, 0, 0, 1);

    for &(cipher, auth, combo_label) in combos {
        let client_enc = Encryptor::new(client_keys.clone(), auth, cipher);
        let server_dec = Encryptor::new(server_keys.clone(), auth, cipher);

        let mut group = c.benchmark_group(format!("pipeline_recv_throughput/{}", combo_label));

        let sizes: &[(usize, &str)] = &[
            (64, "64B"),
            (512, "512B"),
            (1200, "1200B_mtu"),
            (9000, "9000B_jumbo"),
        ];

        for &(size, size_label) in sizes {
            let payload = vec![0xABu8; size];
            let num_packets = 256usize;
            let mut packets: Vec<Vec<u8>> = Vec::with_capacity(num_packets);

            for s in 0..num_packets as u64 {
                let mut pkt_buf = vec![0u8; HUGE_BUF_LEN];
                let pkt_len = simulate_send_safer_tcp(
                    &payload, 0xAABBCCDD, 0x11223344,
                    s + 2_000_000,
                    &client_enc, 42, src_ip, dst_ip,
                    54321, 80, 0x12345678, 0xAABBCCDD,
                    &mut pkt_buf,
                );
                packets.push(pkt_buf[..pkt_len].to_vec());
            }

            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(
                BenchmarkId::from_parameter(size_label),
                &size,
                |b, _| {
                    let mut ar = AntiReplay::new();
                    ar.is_valid(1_999_999, false);
                    let mut idx = 0usize;
                    b.iter(|| {
                        let pkt = &packets[idx % num_packets];
                        idx += 1;
                        simulate_recv_safer_tcp(
                            black_box(pkt),
                            0x11223344, 0xAABBCCDD,
                            &server_dec, &mut ar,
                        )
                    });
                },
            );
        }
        group.finish();
    }
}

/// Full roundtrip
fn bench_roundtrip_latency(c: &mut Criterion) {
    let client_keys = EncryptionKeys::derive("bench_password", true);
    let server_keys = EncryptionKeys::derive("bench_password", false);

    let combos: &[(CipherMode, AuthMode, &str)] = &[
        (CipherMode::Aes128Cbc, AuthMode::Md5, "aes128cbc+md5"),
        (CipherMode::Aes128Cbc, AuthMode::HmacSha1, "aes128cbc+hmac_sha1"),
        (CipherMode::Xor, AuthMode::Crc32, "xor+crc32"),
        (CipherMode::None, AuthMode::None, "none+none"),
    ];

    let src_ip = Ipv4Addr::new(192, 168, 1, 100);
    let dst_ip = Ipv4Addr::new(10, 0, 0, 1);
    let mut group = c.benchmark_group("pipeline_roundtrip");

    for &(cipher, auth, combo_label) in combos {
        let client_enc = Encryptor::new(client_keys.clone(), auth, cipher);
        let server_dec = Encryptor::new(server_keys.clone(), auth, cipher);

        let payload = vec![0xABu8; 1200];
        let mut packet_out = vec![0u8; HUGE_BUF_LEN];

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(combo_label),
            &(),
            |b, _| {
                let mut ar = AntiReplay::new();
                let mut seq = 1u64;
                b.iter(|| {
                    // Client send
                    let pkt_len = simulate_send_safer_tcp(
                        black_box(&payload),
                        0xAABBCCDD, 0x11223344, seq,
                        &client_enc, 42, src_ip, dst_ip,
                        54321, 80, 0x12345678, 0xAABBCCDD,
                        &mut packet_out,
                    );
                    // Server recv
                    let result = simulate_recv_safer_tcp(
                        black_box(&packet_out[..pkt_len]),
                        0x11223344, 0xAABBCCDD,
                        &server_dec, &mut ar,
                    );
                    seq += 1;
                    result
                });
            },
        );
    }
    group.finish();
}

/// Batch throughput: process N packets in a tight loop.
/// Measures cache warming and pipeline effects at scale.
fn bench_batch_throughput(c: &mut Criterion) {
    let client_keys = EncryptionKeys::derive("bench_password", true);
    let server_keys = EncryptionKeys::derive("bench_password", false);

    let client_enc = Encryptor::new(client_keys, AuthMode::Md5, CipherMode::Aes128Cbc);
    let server_dec = Encryptor::new(server_keys, AuthMode::Md5, CipherMode::Aes128Cbc);

    let src_ip = Ipv4Addr::new(192, 168, 1, 100);
    let dst_ip = Ipv4Addr::new(10, 0, 0, 1);
    let payload = vec![0xABu8; 1200];

    let batch_sizes: &[(usize, &str)] = &[
        (1, "1_pkt"),
        (10, "10_pkts"),
        (100, "100_pkts"),
        (1000, "1000_pkts"),
    ];

    let mut group = c.benchmark_group("pipeline_batch/aes128cbc+md5/1200B");

    for &(batch, label) in batch_sizes {
        group.throughput(Throughput::Elements(batch as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &batch, |b, &batch| {
            let mut packet_out = vec![0u8; HUGE_BUF_LEN];
            let mut ar = AntiReplay::new();
            let mut seq = 1u64;
            b.iter(|| {
                for _ in 0..batch {
                    let pkt_len = simulate_send_safer_tcp(
                        black_box(&payload),
                        0xAABBCCDD, 0x11223344, seq,
                        &client_enc, 42, src_ip, dst_ip,
                        54321, 80, 0x12345678, 0xAABBCCDD,
                        &mut packet_out,
                    );
                    simulate_recv_safer_tcp(
                        black_box(&packet_out[..pkt_len]),
                        0x11223344, 0xAABBCCDD,
                        &server_dec, &mut ar,
                    );
                    seq += 1;
                }
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_send_latency,
    bench_send_throughput,
    bench_recv_latency,
    bench_recv_throughput,
    bench_roundtrip_latency,
    bench_batch_throughput,
);
criterion_main!(benches);
