//! Example: Key derivation and inspection.
//!
//! Demonstrates how encryption keys are derived from a password,
//! showing the relationship between client and server keys.
//!
//! Run: cargo run --example key_derivation

use udp2raw::encrypt::EncryptionKeys;

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect::<String>()
}

fn main() {
    let password = "my_secret_password";
    println!("═══════════════════════════════════════════════════════════");
    println!("  udp2raw Key Derivation Example");
    println!("═══════════════════════════════════════════════════════════");
    println!();
    println!("Password: \"{}\"", password);
    println!();

    // Derive keys for client and server
    let client_keys = EncryptionKeys::derive(password, true);
    let server_keys = EncryptionKeys::derive(password, false);

    println!("── Normal Key (MD5 of password + \"key1\") ─────────────────");
    println!("  Client: {}", hex(&client_keys.normal_key));
    println!("  Server: {}", hex(&server_keys.normal_key));
    println!("  Match:  {} (should be true)", client_keys.normal_key == server_keys.normal_key);
    println!();

    println!("── Cipher Keys (HKDF-SHA256 from PBKDF2 output) ─────────");
    println!("  Client encrypt [0..16]: {}", hex(&client_keys.cipher_key_encrypt[..16]));
    println!("  Client decrypt [0..16]: {}", hex(&client_keys.cipher_key_decrypt[..16]));
    println!("  Server encrypt [0..16]: {}", hex(&server_keys.cipher_key_encrypt[..16]));
    println!("  Server decrypt [0..16]: {}", hex(&server_keys.cipher_key_decrypt[..16]));
    println!();
    println!("  Client encrypt == Server decrypt: {}",
        client_keys.cipher_key_encrypt == server_keys.cipher_key_decrypt);
    println!("  Client decrypt == Server encrypt: {}",
        client_keys.cipher_key_decrypt == server_keys.cipher_key_encrypt);
    println!();

    println!("── HMAC Keys ──────────────────────────────────────────────");
    println!("  Client encrypt [0..20]: {}", hex(&client_keys.hmac_key_encrypt[..20]));
    println!("  Client decrypt [0..20]: {}", hex(&client_keys.hmac_key_decrypt[..20]));
    println!("  Server encrypt [0..20]: {}", hex(&server_keys.hmac_key_encrypt[..20]));
    println!("  Server decrypt [0..20]: {}", hex(&server_keys.hmac_key_decrypt[..20]));
    println!();
    println!("  Client HMAC-enc == Server HMAC-dec: {}",
        client_keys.hmac_key_encrypt == server_keys.hmac_key_decrypt);
    println!();

    println!("── GRO XOR Key [0..16] ─────────────────────────────────");
    println!("  Client: {}", hex(&client_keys.gro_xor[..16]));
    println!("  Server: {}", hex(&server_keys.gro_xor[..16]));
    println!("  Match:  {}", client_keys.gro_xor == server_keys.gro_xor);
    println!();

    // Show determinism
    let keys2 = EncryptionKeys::derive(password, true);
    println!("── Determinism Check ──────────────────────────────────────");
    println!("  Same password → same keys: {}",
        client_keys.normal_key == keys2.normal_key
        && client_keys.cipher_key_encrypt == keys2.cipher_key_encrypt);
    println!();

    let different = EncryptionKeys::derive("different_password", true);
    println!("  Different password → different keys: {}",
        client_keys.normal_key != different.normal_key);
    println!();
    println!("═══════════════════════════════════════════════════════════");
}

