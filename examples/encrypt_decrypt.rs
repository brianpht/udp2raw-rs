//! Example: Encrypt and decrypt messages with all cipher/auth combinations.
//!
//! Demonstrates the encryption pipeline, showing how data is encrypted by the
//! client and decrypted by the server for each supported mode combination.
//!
//! Run: cargo run --example encrypt_decrypt

use udp2raw::common::{AuthMode, BUF_LEN, CipherMode};
use udp2raw::encrypt::{EncryptionKeys, Encryptor};

fn hex_preview(data: &[u8], max: usize) -> String {
    let preview: String = data.iter().take(max).map(|b| format!("{:02x}", b)).collect();
    if data.len() > max {
        format!("{}... ({} bytes)", preview, data.len())
    } else {
        format!("{} ({} bytes)", preview, data.len())
    }
}

fn main() {
    let password = "demo_password";
    let plaintext = b"Hello, udp2raw! This is a test message that will be encrypted.";

    println!("═══════════════════════════════════════════════════════════════════");
    println!("  udp2raw Encrypt/Decrypt Example");
    println!("═══════════════════════════════════════════════════════════════════");
    println!();
    println!("Password:  \"{}\"", password);
    println!("Plaintext: \"{}\"", String::from_utf8_lossy(plaintext));
    println!("           {}", hex_preview(plaintext, 20));
    println!();

    let client_keys = EncryptionKeys::derive(password, true);
    let server_keys = EncryptionKeys::derive(password, false);

    let ciphers = [
        ("none", CipherMode::None),
        ("xor", CipherMode::Xor),
        ("aes128cbc", CipherMode::Aes128Cbc),
        ("aes128cfb", CipherMode::Aes128Cfb),
    ];

    let auths = [
        ("none", AuthMode::None),
        ("md5", AuthMode::Md5),
        ("crc32", AuthMode::Crc32),
        ("simple", AuthMode::Simple),
        ("hmac_sha1", AuthMode::HmacSha1),
    ];

    for (cipher_name, cipher_mode) in &ciphers {
        for (auth_name, auth_mode) in &auths {
            let client_enc = Encryptor::new(client_keys.clone(), *auth_mode, *cipher_mode);
            let server_dec = Encryptor::new(server_keys.clone(), *auth_mode, *cipher_mode);

            let mut encrypted = [0u8; BUF_LEN];
            let mut decrypted = [0u8; BUF_LEN];

            let enc_result = client_enc.my_encrypt(plaintext, &mut encrypted);
            match enc_result {
                Ok(enc_len) => {
                    let dec_result = server_dec.my_decrypt(&encrypted[..enc_len], &mut decrypted);
                    match dec_result {
                        Ok(dec_len) => {
                            let success = &decrypted[..dec_len] == plaintext.as_slice();
                            println!(
                                "  cipher={:<12} auth={:<10} → enc={:<4} dec={:<4} {}",
                                cipher_name,
                                auth_name,
                                enc_len,
                                dec_len,
                                if success { "✓ OK" } else { "✗ MISMATCH" }
                            );
                            if !success {
                                println!(
                                    "    expected: {}",
                                    hex_preview(plaintext, 16)
                                );
                                println!(
                                    "    got:      {}",
                                    hex_preview(&decrypted[..dec_len], 16)
                                );
                            }
                        }
                        Err(_) => {
                            println!(
                                "  cipher={:<12} auth={:<10} → enc={:<4} ✗ DECRYPT FAILED",
                                cipher_name, auth_name, enc_len
                            );
                        }
                    }
                }
                Err(_) => {
                    println!(
                        "  cipher={:<12} auth={:<10} → ✗ ENCRYPT FAILED (data too short?)",
                        cipher_name, auth_name
                    );
                }
            }
        }
    }

    println!();
    println!("── Tamper Detection Demo ─────────────────────────────────────────");
    println!();

    let client_enc = Encryptor::new(client_keys.clone(), AuthMode::HmacSha1, CipherMode::Aes128Cbc);
    let server_dec = Encryptor::new(server_keys.clone(), AuthMode::HmacSha1, CipherMode::Aes128Cbc);

    let mut encrypted = [0u8; BUF_LEN];
    let enc_len = client_enc.my_encrypt(plaintext, &mut encrypted).unwrap();

    // Normal decrypt
    let mut decrypted = [0u8; BUF_LEN];
    let dec_len = server_dec.my_decrypt(&encrypted[..enc_len], &mut decrypted).unwrap();
    println!("  Original:  decrypt OK → \"{}\"", String::from_utf8_lossy(&decrypted[..dec_len]));

    // Tamper with ciphertext
    encrypted[enc_len / 2] ^= 0xFF;
    let tamper_result = server_dec.my_decrypt(&encrypted[..enc_len], &mut decrypted);
    println!(
        "  Tampered:  decrypt → {}",
        if tamper_result.is_err() {
            "✓ correctly rejected (auth failed)"
        } else {
            "✗ should have been rejected!"
        }
    );

    // Wrong password
    let wrong_keys = EncryptionKeys::derive("wrong_password", false);
    let wrong_dec = Encryptor::new(wrong_keys, AuthMode::HmacSha1, CipherMode::Aes128Cbc);
    encrypted[enc_len / 2] ^= 0xFF; // undo tamper
    let wrong_result = wrong_dec.my_decrypt(&encrypted[..enc_len], &mut decrypted);
    println!(
        "  Wrong key: decrypt → {}",
        if wrong_result.is_err() {
            "✓ correctly rejected"
        } else {
            "✗ should have been rejected!"
        }
    );

    println!();
    println!("═══════════════════════════════════════════════════════════════════");
}

