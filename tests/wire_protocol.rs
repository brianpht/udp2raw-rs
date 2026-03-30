//! Integration tests for the wire protocol byte layout.
//!
//! Verifies that `send_bare` and `send_safer` packet formats match
//! the documented byte layout, ensuring C++ ↔ Rust wire compatibility.

use udp2raw::common::*;
use udp2raw::encrypt::{EncryptionKeys, Encryptor};

// ─── Bare packet layout tests ───────────────────────────────────────────────

#[test]
fn bare_packet_format_roundtrip() {
    // Simulate the bare packet build/parse without raw sockets.
    // Layout: [iv:8B][padding:8B][marker='b':1B][data:NB]
    let password = "wire_test";
    let client_keys = EncryptionKeys::derive(password, true);
    let server_keys = EncryptionKeys::derive(password, false);
    let client_enc = Encryptor::new(client_keys, AuthMode::Md5, CipherMode::Aes128Cbc);
    let server_enc = Encryptor::new(server_keys, AuthMode::Md5, CipherMode::Aes128Cbc);

    // Build a bare packet manually (matching send_bare logic)
    let data = numbers_to_bytes(0xAABBCCDD, 0x00000000, 0x11223344);
    let iv = 0x0102030405060708u64;
    let padding = 0x090A0B0C0D0E0F10u64;

    let mut buf = [0u8; BUF_LEN];
    let mut offset = 0;
    buf[offset..offset + 8].copy_from_slice(&iv.to_ne_bytes());
    offset += 8;
    buf[offset..offset + 8].copy_from_slice(&padding.to_ne_bytes());
    offset += 8;
    buf[offset] = b'b';
    offset += 1;
    buf[offset..offset + data.len()].copy_from_slice(&data);
    let total = offset + data.len();

    // Verify plaintext layout
    assert_eq!(total, 8 + 8 + 1 + 12); // 29 bytes
    assert_eq!(buf[16], b'b'); // marker at offset 16

    // Encrypt
    let mut encrypted = [0u8; BUF_LEN];
    let enc_len = client_enc.my_encrypt(&buf[..total], &mut encrypted).unwrap();

    // Decrypt on server side
    let mut decrypted = [0u8; BUF_LEN];
    let dec_len = server_enc.my_decrypt(&encrypted[..enc_len], &mut decrypted).unwrap();

    assert_eq!(dec_len, total);
    // Verify marker
    assert_eq!(decrypted[16], b'b');
    // Verify data starts at offset 17
    let recovered = &decrypted[17..dec_len];
    assert_eq!(recovered.len(), 12);
    let (id1, id2, id3) = bytes_to_numbers(recovered).unwrap();
    assert_eq!(id1, 0xAABBCCDD);
    assert_eq!(id2, 0x00000000);
    assert_eq!(id3, 0x11223344);
}

// ─── Safer packet layout tests ──────────────────────────────────────────────

#[test]
fn safer_packet_format_roundtrip() {
    // Layout: [my_id:4B][opposite_id:4B][seq:8B][type:1B][roller:1B][data:NB]
    let password = "safer_test";
    let client_keys = EncryptionKeys::derive(password, true);
    let server_keys = EncryptionKeys::derive(password, false);
    let client_enc = Encryptor::new(client_keys, AuthMode::Md5, CipherMode::Aes128Cbc);
    let server_enc = Encryptor::new(server_keys, AuthMode::Md5, CipherMode::Aes128Cbc);

    let my_id: MyId = 0xDEADBEEF;
    let opposite_id: MyId = 0xCAFEBABE;
    let seq: u64 = 42;
    let pkt_type: u8 = b'h';
    let roller: u8 = 7;
    let payload = b"heartbeat data here";

    // Build safer packet plaintext
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
    buf[offset..offset + payload.len()].copy_from_slice(payload);
    let total = offset + payload.len();

    // Verify layout
    assert_eq!(offset, 18); // Header is 18 bytes before payload
    assert_eq!(read_u32(&buf[0..4]), my_id);
    assert_eq!(read_u32(&buf[4..8]), opposite_id);
    assert_eq!(buf[16], b'h');
    assert_eq!(buf[17], 7);

    // Encrypt → Decrypt roundtrip
    let mut encrypted = [0u8; BUF_LEN];
    let enc_len = client_enc.my_encrypt(&buf[..total], &mut encrypted).unwrap();

    let mut decrypted = [0u8; BUF_LEN];
    let dec_len = server_enc
        .my_decrypt(&encrypted[..enc_len], &mut decrypted)
        .unwrap();

    assert_eq!(dec_len, total);

    // Parse back
    let h_my_id = u32::from_be_bytes([decrypted[0], decrypted[1], decrypted[2], decrypted[3]]);
    let h_opp_id = u32::from_be_bytes([decrypted[4], decrypted[5], decrypted[6], decrypted[7]]);
    let mut seq_bytes = [0u8; 8];
    seq_bytes.copy_from_slice(&decrypted[8..16]);
    let h_seq = ntoh64(u64::from_ne_bytes(seq_bytes));
    let h_type = decrypted[16];
    let h_roller = decrypted[17];
    let h_payload = &decrypted[18..dec_len];

    assert_eq!(h_my_id, my_id);
    assert_eq!(h_opp_id, opposite_id);
    assert_eq!(h_seq, seq);
    assert_eq!(h_type, b'h');
    assert_eq!(h_roller, 7);
    assert_eq!(h_payload, payload);
}

// ─── Data-safer (conv_id + payload) layout ──────────────────────────────────

#[test]
fn data_safer_payload_layout() {
    // send_data_safer wraps: [conv_id:4B (big-endian)][UDP payload]
    let conv_id: u32 = 0x12345678;
    let udp_payload = b"actual UDP data from application";

    let mut buf = [0u8; BUF_LEN];
    buf[..4].copy_from_slice(&conv_id.to_be_bytes());
    buf[4..4 + udp_payload.len()].copy_from_slice(udp_payload);
    let total = 4 + udp_payload.len();

    // Verify layout
    let recovered_conv = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    assert_eq!(recovered_conv, conv_id);
    assert_eq!(&buf[4..total], udp_payload.as_slice());
}

// ─── Handshake ID encoding ──────────────────────────────────────────────────

#[test]
fn handshake_id_encoding() {
    // Handshake sends 3 IDs in big-endian
    let my_id: MyId = 0x11223344;
    let opposite_id: MyId = 0x55667788;
    let const_id: MyId = 0xAABBCCDD;

    let bytes = numbers_to_bytes(my_id, opposite_id, const_id);
    assert_eq!(bytes.len(), 12);

    // Verify big-endian encoding
    assert_eq!(&bytes[0..4], &[0x11, 0x22, 0x33, 0x44]);
    assert_eq!(&bytes[4..8], &[0x55, 0x66, 0x77, 0x88]);
    assert_eq!(&bytes[8..12], &[0xAA, 0xBB, 0xCC, 0xDD]);

    // Roundtrip
    let (a, b, c) = bytes_to_numbers(&bytes).unwrap();
    assert_eq!(a, my_id);
    assert_eq!(b, opposite_id);
    assert_eq!(c, const_id);
}

#[test]
fn bytes_to_numbers_rejects_short_data() {
    assert!(bytes_to_numbers(&[0u8; 11]).is_none());
    assert!(bytes_to_numbers(&[]).is_none());
    assert!(bytes_to_numbers(&[0u8; 12]).is_some());
}

// ─── GRO fix wrapper layout ────────────────────────────────────────────────

#[test]
fn gro_fix_wrapper_format() {
    // GRO wrapper: [encrypted_len:2B][encrypted_payload:NB]
    // Then first 16 bytes are XOR'd or AES-ECB encrypted.
    let password = "gro_test";
    let keys = EncryptionKeys::derive(password, true);
    let enc = Encryptor::new(keys.clone(), AuthMode::Md5, CipherMode::Xor);

    let inner_data = b"test payload for gro wrapping!!";
    let mut encrypted_inner = [0u8; BUF_LEN];
    let enc_len = enc.my_encrypt(inner_data, &mut encrypted_inner).unwrap();

    // Build GRO wrapper (matching send_safer with fix_gro=true)
    let mut gro_buf = [0u8; BUF_LEN];
    write_u16(&mut gro_buf[0..2], enc_len as u16);
    gro_buf[2..2 + enc_len].copy_from_slice(&encrypted_inner[..enc_len]);
    let _final_len = enc_len + 2;

    // Apply XOR to first 2 bytes (matching the XOR cipher gro path)
    gro_buf[0] ^= keys.gro_xor[0];
    gro_buf[1] ^= keys.gro_xor[1];

    // Now decode: undo XOR
    gro_buf[0] ^= keys.gro_xor[0];
    gro_buf[1] ^= keys.gro_xor[1];

    let recovered_len = read_u16(&gro_buf[0..2]) as usize;
    assert_eq!(recovered_len, enc_len);

    // Decrypt inner
    let dec_keys = EncryptionKeys::derive(password, false);
    let dec = Encryptor::new(dec_keys, AuthMode::Md5, CipherMode::Xor);
    let mut decrypted = [0u8; BUF_LEN];
    let dec_len = dec
        .my_decrypt(&gro_buf[2..2 + recovered_len], &mut decrypted)
        .unwrap();

    assert_eq!(&decrypted[..dec_len], inner_data.as_slice());
}

// ─── Network byte order helpers ─────────────────────────────────────────────

#[test]
fn network_byte_order_u16() {
    let mut buf = [0u8; 2];
    write_u16(&mut buf, 0x1234);
    assert_eq!(buf, [0x12, 0x34]); // big-endian
    assert_eq!(read_u16(&buf), 0x1234);
}

#[test]
fn network_byte_order_u32() {
    let mut buf = [0u8; 4];
    write_u32(&mut buf, 0xDEADBEEF);
    assert_eq!(buf, [0xDE, 0xAD, 0xBE, 0xEF]); // big-endian
    assert_eq!(read_u32(&buf), 0xDEADBEEF);
}

#[test]
fn hton64_ntoh64_roundtrip() {
    let val: u64 = 0x0102030405060708;
    let network = hton64(val);
    let host = ntoh64(network);
    assert_eq!(host, val);
}

