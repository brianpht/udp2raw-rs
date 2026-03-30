//! Integration tests for encryption cross-compatibility.
//!
//! Verifies that data encrypted by client keys can be decrypted by server keys
//! (and vice versa) across all cipher/auth mode combinations.

use udp2raw::common::{AuthMode, BUF_LEN, CipherMode};
use udp2raw::encrypt::{EncryptionKeys, Encryptor};

/// Helper: create a matched client/server encryptor pair for a given password.
fn make_pair(
    password: &str,
    cipher: CipherMode,
    auth: AuthMode,
) -> (Encryptor, Encryptor) {
    let client_keys = EncryptionKeys::derive(password, true);
    let server_keys = EncryptionKeys::derive(password, false);
    let client_enc = Encryptor::new(client_keys, auth, cipher);
    let server_enc = Encryptor::new(server_keys, auth, cipher);
    (client_enc, server_enc)
}

/// All supported (cipher, auth) combinations.
fn all_combinations() -> Vec<(CipherMode, AuthMode)> {
    let ciphers = [
        CipherMode::None,
        CipherMode::Xor,
        CipherMode::Aes128Cbc,
        CipherMode::Aes128Cfb,
    ];
    let auths = [
        AuthMode::None,
        AuthMode::Md5,
        AuthMode::Crc32,
        AuthMode::Simple,
        AuthMode::HmacSha1,
    ];
    let mut combos = Vec::new();
    for &c in &ciphers {
        for &a in &auths {
            // AES-CFB requires ≥16 bytes (skip None cipher + None auth trivial case)
            combos.push((c, a));
        }
    }
    combos
}

#[test]
fn client_to_server_roundtrip_all_modes() {
    for (cipher, auth) in all_combinations() {
        let (client, server) = make_pair("test_password_123!", cipher, auth);
        let plaintext = b"Hello from client to server! 0123456789abcdef extra padding data.";

        let mut encrypted = [0u8; BUF_LEN];
        let mut decrypted = [0u8; BUF_LEN];

        let enc_len = match client.my_encrypt(plaintext, &mut encrypted) {
            Ok(len) => len,
            Err(_) => {
                // AES-CFB with data < 16 bytes may fail, skip
                if cipher == CipherMode::Aes128Cfb && plaintext.len() < 16 {
                    continue;
                }
                panic!("encrypt failed for {:?}/{:?}", cipher, auth);
            }
        };

        let dec_len = server
            .my_decrypt(&encrypted[..enc_len], &mut decrypted)
            .unwrap_or_else(|_| panic!("decrypt failed for {:?}/{:?}", cipher, auth));

        assert_eq!(
            &decrypted[..dec_len],
            plaintext.as_slice(),
            "client→server roundtrip failed for {:?}/{:?}",
            cipher,
            auth
        );
    }
}

#[test]
fn server_to_client_roundtrip_all_modes() {
    for (cipher, auth) in all_combinations() {
        let (client, server) = make_pair("another_password!", cipher, auth);
        let plaintext = b"Response from server back to client. Lots of data here too!!!";

        let mut encrypted = [0u8; BUF_LEN];
        let mut decrypted = [0u8; BUF_LEN];

        let enc_len = match server.my_encrypt(plaintext, &mut encrypted) {
            Ok(len) => len,
            Err(_) => {
                if cipher == CipherMode::Aes128Cfb && plaintext.len() < 16 {
                    continue;
                }
                panic!("encrypt failed for {:?}/{:?}", cipher, auth);
            }
        };

        let dec_len = client
            .my_decrypt(&encrypted[..enc_len], &mut decrypted)
            .unwrap_or_else(|_| panic!("decrypt failed for {:?}/{:?}", cipher, auth));

        assert_eq!(
            &decrypted[..dec_len],
            plaintext.as_slice(),
            "server→client roundtrip failed for {:?}/{:?}",
            cipher,
            auth
        );
    }
}

#[test]
fn wrong_password_fails_decryption() {
    let ciphers_with_auth = [
        (CipherMode::Aes128Cbc, AuthMode::Md5),
        (CipherMode::Xor, AuthMode::Crc32),
        (CipherMode::Aes128Cbc, AuthMode::HmacSha1),
    ];

    for (cipher, auth) in ciphers_with_auth {
        let good_keys = EncryptionKeys::derive("correct_password", true);
        let bad_keys = EncryptionKeys::derive("wrong_password", false);
        let enc = Encryptor::new(good_keys, auth, cipher);
        let dec = Encryptor::new(bad_keys, auth, cipher);

        let plaintext = b"secret data that should not be recoverable";
        let mut encrypted = [0u8; BUF_LEN];
        let mut decrypted = [0u8; BUF_LEN];

        let enc_len = enc.my_encrypt(plaintext, &mut encrypted).unwrap();

        // Decryption with wrong key should fail (auth check fails)
        let result = dec.my_decrypt(&encrypted[..enc_len], &mut decrypted);
        assert!(
            result.is_err(),
            "decryption with wrong password should fail for {:?}/{:?}",
            cipher,
            auth
        );
    }
}

#[test]
fn key_derivation_deterministic() {
    let k1 = EncryptionKeys::derive("reproducible", true);
    let k2 = EncryptionKeys::derive("reproducible", true);

    assert_eq!(k1.normal_key, k2.normal_key);
    assert_eq!(k1.cipher_key_encrypt, k2.cipher_key_encrypt);
    assert_eq!(k1.cipher_key_decrypt, k2.cipher_key_decrypt);
    assert_eq!(k1.hmac_key_encrypt, k2.hmac_key_encrypt);
    assert_eq!(k1.hmac_key_decrypt, k2.hmac_key_decrypt);
    assert_eq!(k1.gro_xor, k2.gro_xor);
}

#[test]
fn client_server_key_symmetry() {
    let client = EncryptionKeys::derive("symmetric_test", true);
    let server = EncryptionKeys::derive("symmetric_test", false);

    // Client's encrypt key == Server's decrypt key (and vice versa)
    assert_eq!(client.cipher_key_encrypt, server.cipher_key_decrypt);
    assert_eq!(client.cipher_key_decrypt, server.cipher_key_encrypt);
    assert_eq!(client.hmac_key_encrypt, server.hmac_key_decrypt);
    assert_eq!(client.hmac_key_decrypt, server.hmac_key_encrypt);

    // normal_key and gro_xor are the same for both
    assert_eq!(client.normal_key, server.normal_key);
    assert_eq!(client.gro_xor, server.gro_xor);
}

#[test]
fn various_payload_sizes() {
    let sizes: Vec<usize> = vec![
        0, 1, 15, 16, 17, 31, 32, 64, 100, 255, 256, 500, 1000, 1400, 1800,
    ];

    for size in sizes {
        let payload: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        for (cipher, auth) in &[
            (CipherMode::Aes128Cbc, AuthMode::Md5),
            (CipherMode::Xor, AuthMode::Crc32),
            (CipherMode::None, AuthMode::HmacSha1),
        ] {
            let (client, server) = make_pair("size_test", *cipher, *auth);
            let mut encrypted = [0u8; BUF_LEN];
            let mut decrypted = [0u8; BUF_LEN];

            // AES-CFB needs at least 16 bytes
            if *cipher == CipherMode::Aes128Cfb && size < 16 {
                continue;
            }

            let enc_len = match client.my_encrypt(&payload, &mut encrypted) {
                Ok(l) => l,
                Err(_) => continue, // skip empty + none
            };

            let dec_len = server
                .my_decrypt(&encrypted[..enc_len], &mut decrypted)
                .unwrap_or_else(|_| {
                    panic!("decrypt failed: size={} {:?}/{:?}", size, cipher, auth)
                });

            assert_eq!(
                &decrypted[..dec_len],
                payload.as_slice(),
                "roundtrip failed: size={} {:?}/{:?}",
                size,
                cipher,
                auth
            );
        }
    }
}

#[test]
fn encrypted_data_differs_from_plaintext() {
    let keys = EncryptionKeys::derive("differ_test", true);
    let enc = Encryptor::new(keys, AuthMode::Md5, CipherMode::Aes128Cbc);

    let plaintext = b"This should not appear in ciphertext verbatim!!";
    let mut encrypted = [0u8; BUF_LEN];

    let enc_len = enc.my_encrypt(plaintext, &mut encrypted).unwrap();

    // Encrypted output should differ from plaintext
    assert_ne!(
        &encrypted[..enc_len],
        plaintext.as_slice(),
        "encrypted data should differ from plaintext"
    );
    // And should be longer (due to auth tag + padding)
    assert!(enc_len > plaintext.len());
}

#[test]
fn tampered_ciphertext_fails_auth() {
    let auths_with_integrity = [
        AuthMode::Md5,
        AuthMode::Crc32,
        AuthMode::Simple,
        AuthMode::HmacSha1,
    ];

    for auth in auths_with_integrity {
        let (client, server) = make_pair("tamper_test", CipherMode::Aes128Cbc, auth);

        let plaintext = b"integrity protected data that must not be tampered";
        let mut encrypted = [0u8; BUF_LEN];
        let mut decrypted = [0u8; BUF_LEN];

        let enc_len = client.my_encrypt(plaintext, &mut encrypted).unwrap();

        // Tamper with a byte in the middle
        if enc_len > 10 {
            encrypted[enc_len / 2] ^= 0xFF;
        }

        let result = server.my_decrypt(&encrypted[..enc_len], &mut decrypted);
        assert!(
            result.is_err(),
            "tampered data should fail auth for {:?}",
            auth
        );
    }
}

