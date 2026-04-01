//! Encryption and authentication module.
//! Corresponds to encrypt.{h,cpp} in the C++ version.
//!
//! Supports: AES-128-CBC, AES-128-CFB, XOR cipher, and auth modes MD5, CRC32,
//! simple hash, HMAC-SHA1. Key derivation via PBKDF2-SHA256 + HKDF-SHA256.
//! Wire format is byte-compatible with the C++ implementation.

use crate::common::{AuthMode, BUF_LEN, CipherMode, MAX_DATA_LEN};

use aes::Aes128;
use cipher::{AsyncStreamCipher, BlockDecrypt, BlockEncrypt, KeyInit, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;

type HmacSha1 = Hmac<Sha1>;

const ZERO_IV: [u8; 16] = [0u8; 16];

// ─── Encryption Keys ────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct EncryptionKeys {
    pub normal_key: [u8; 16],
    pub cipher_key_encrypt: [u8; 64],
    pub cipher_key_decrypt: [u8; 64],
    pub hmac_key_encrypt: [u8; 64],
    pub hmac_key_decrypt: [u8; 64],
    pub gro_xor: [u8; 256],
}

impl EncryptionKeys {
    /// Derive all keys from password, matching C++ my_init_keys() exactly.
    pub fn derive(password: &str, is_client: bool) -> Self {
        // 1. normal_key = MD5(password + "key1")
        let mut md5_input = password.to_string();
        md5_input.push_str("key1");
        let normal_key: [u8; 16] = {
            use md5::{Md5, Digest};
            Md5::digest(md5_input.as_bytes()).into()
        };

        // 2. salt = MD5("udp2raw_salt1")
        let salt: [u8; 16] = {
            use md5::{Md5, Digest};
            Md5::digest(b"udp2raw_salt1").into()
        };

        // 3. PBKDF2-SHA256(password, salt[0..16], 10000, 32)
        let mut pbkdf2_output = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt[..16], 10000, &mut pbkdf2_output);

        // 4. HKDF-SHA256-Expand for each key
        // Direction labels: client swaps encrypt/decrypt directions
        let (info_cipher_enc, info_cipher_dec, info_hmac_enc, info_hmac_dec) = if is_client {
            (
                "cipher_key client-->server",
                "cipher_key server-->client",
                "hmac_key client-->server",
                "hmac_key server-->client",
            )
        } else {
            (
                "cipher_key server-->client",
                "cipher_key client-->server",
                "hmac_key server-->client",
                "hmac_key client-->server",
            )
        };

        let hkdf = Hkdf::<Sha256>::from_prk(&pbkdf2_output)
            .expect("HKDF PRK length should be valid");

        let mut cipher_key_encrypt = [0u8; 64];
        let mut cipher_key_decrypt = [0u8; 64];
        let mut hmac_key_encrypt = [0u8; 64];
        let mut hmac_key_decrypt = [0u8; 64];
        let mut gro_xor = [0u8; 256];

        hkdf.expand(info_cipher_enc.as_bytes(), &mut cipher_key_encrypt)
            .expect("HKDF expand failed");
        hkdf.expand(info_cipher_dec.as_bytes(), &mut cipher_key_decrypt)
            .expect("HKDF expand failed");
        hkdf.expand(info_hmac_enc.as_bytes(), &mut hmac_key_encrypt)
            .expect("HKDF expand failed");
        hkdf.expand(info_hmac_dec.as_bytes(), &mut hmac_key_decrypt)
            .expect("HKDF expand failed");
        hkdf.expand(b"gro", &mut gro_xor)
            .expect("HKDF expand failed");

        Self {
            normal_key,
            cipher_key_encrypt,
            cipher_key_decrypt,
            hmac_key_encrypt,
            hmac_key_decrypt,
            gro_xor,
        }
    }
}

// ─── Encryptor struct ───────────────────────────────────────────────────────

pub struct Encryptor {
    pub keys: EncryptionKeys,
    pub auth_mode: AuthMode,
    pub cipher_mode: CipherMode,
    pub is_hmac_used: bool,
    /// Pre-computed AES cipher for encrypt path (CBC/CFB main cipher).
    /// Avoids recomputing the key schedule (~200 cycles) on every packet.
    aes_enc: Option<Aes128>,
    /// Pre-computed AES cipher for decrypt path (CBC/CFB main cipher).
    aes_dec: Option<Aes128>,
    /// Pre-computed AES cipher for GRO ECB encrypt (always cipher_key_encrypt).
    aes_gro_enc: Option<Aes128>,
    /// Pre-computed AES cipher for GRO ECB decrypt (always cipher_key_decrypt).
    aes_gro_dec: Option<Aes128>,
    /// Pre-computed HMAC-SHA1 state for encrypt direction.
    /// Clone per-call to avoid re-deriving ipad/opad (~200 cycles saved per packet).
    hmac_enc: Option<HmacSha1>,
    /// Pre-computed HMAC-SHA1 state for decrypt direction.
    hmac_dec: Option<HmacSha1>,
}

impl Encryptor {
    pub fn new(keys: EncryptionKeys, auth_mode: AuthMode, cipher_mode: CipherMode) -> Self {
        let is_hmac_used = auth_mode == AuthMode::HmacSha1;
        let is_aes = cipher_mode == CipherMode::Aes128Cbc || cipher_mode == CipherMode::Aes128Cfb;

        // Pre-compute AES key schedules once at init time
        let aes_enc = if is_aes {
            let key = if is_hmac_used { &keys.cipher_key_encrypt[..16] } else { &keys.normal_key };
            Some(Aes128::new_from_slice(key).expect("AES encrypt key"))
        } else {
            None
        };
        let aes_dec = if is_aes {
            let key = if is_hmac_used { &keys.cipher_key_decrypt[..16] } else { &keys.normal_key };
            Some(Aes128::new_from_slice(key).expect("AES decrypt key"))
        } else {
            None
        };
        // GRO ECB always uses cipher_key_*, even in non-HMAC mode
        let aes_gro_enc = if is_aes {
            Some(Aes128::new_from_slice(&keys.cipher_key_encrypt[..16]).expect("AES GRO encrypt key"))
        } else {
            None
        };
        let aes_gro_dec = if is_aes {
            Some(Aes128::new_from_slice(&keys.cipher_key_decrypt[..16]).expect("AES GRO decrypt key"))
        } else {
            None
        };

        // Pre-compute HMAC-SHA1 inner state (avoids re-deriving ipad/opad per packet)
        let hmac_enc = if is_hmac_used {
            Some(<HmacSha1 as Mac>::new_from_slice(&keys.hmac_key_encrypt[..20]).expect("HMAC encrypt key"))
        } else {
            None
        };
        let hmac_dec = if is_hmac_used {
            Some(<HmacSha1 as Mac>::new_from_slice(&keys.hmac_key_decrypt[..20]).expect("HMAC decrypt key"))
        } else {
            None
        };

        Self {
            keys,
            auth_mode,
            cipher_mode,
            is_hmac_used,
            aes_enc,
            aes_dec,
            aes_gro_enc,
            aes_gro_dec,
            hmac_enc,
            hmac_dec,
        }
    }

    // ── Top-level encrypt/decrypt (matching C++ my_encrypt/my_decrypt) ──

    pub fn my_encrypt(&self, data: &[u8], output: &mut [u8]) -> Result<usize, ()> {
        if data.len() > MAX_DATA_LEN {
            log::warn!("my_encrypt: data too long {}", data.len());
            return Err(());
        }

        if self.is_hmac_used {
            // Encrypt-then-MAC (AE)
            self.encrypt_ae(data, output)
        } else {
            // MAC-then-Encrypt (legacy) — cipher_encrypt writes directly to output
            let mut buf1 = [0u8; BUF_LEN];
            // auth_cal(data) → buf1
            let auth_len = self.auth_cal(data, &mut buf1)?;
            // cipher_encrypt(buf1) → output directly (no intermediate buf2)
            let enc_len = self.cipher_encrypt(&buf1[..auth_len], output)?;
            Ok(enc_len)
        }
    }

    pub fn my_decrypt(&self, data: &[u8], output: &mut [u8]) -> Result<usize, ()> {
        if data.len() > MAX_DATA_LEN + 200 {
            log::warn!("my_decrypt: data too long {}", data.len());
            return Err(());
        }

        if self.is_hmac_used {
            self.decrypt_ae(data, output)
        } else {
            // cipher_decrypt → output directly, then verify in-place (no intermediate buf)
            let dec_len = self.cipher_decrypt(data, output)?;
            // auth_verify is read-only on the buffer — safe to verify output in-place
            let verified_len = self.auth_verify(&output[..dec_len])?;
            Ok(verified_len)
        }
    }

    // ── AE mode (encrypt-then-MAC, used when HMAC enabled) ──

    fn encrypt_ae(&self, data: &[u8], output: &mut [u8]) -> Result<usize, ()> {
        // Cipher encrypt directly into output — no intermediate buffer needed
        let enc_len = self.cipher_encrypt(data, output)?;
        // Compute auth over output[..enc_len] and append tag in-place
        let auth_len = self.auth_cal_inplace(output, enc_len)?;
        Ok(auth_len)
    }

    fn decrypt_ae(&self, data: &[u8], output: &mut [u8]) -> Result<usize, ()> {
        let verified_len = self.auth_verify(data)?;
        let dec_len = self.cipher_decrypt(&data[..verified_len], output)?;
        Ok(dec_len)
    }

    // ── Auth functions ──

    /// Compute auth tag over data already present in `output[..data_len]`
    /// and append the tag after it. Returns total length (data + tag).
    /// Avoids the copy needed by auth_cal when data is already in the output buffer.
    fn auth_cal_inplace(&self, output: &mut [u8], data_len: usize) -> Result<usize, ()> {
        match self.auth_mode {
            AuthMode::None => Ok(data_len),
            AuthMode::Md5 => {
                use md5::{Md5, Digest};
                let hash = Md5::digest(&output[..data_len]);
                output[data_len..data_len + 16].copy_from_slice(&hash);
                Ok(data_len + 16)
            }
            AuthMode::Crc32 => {
                let crc = crc32fast::hash(&output[..data_len]);
                output[data_len..data_len + 4].copy_from_slice(&crc.to_be_bytes());
                Ok(data_len + 4)
            }
            AuthMode::Simple => {
                let hash = simple_hash(&output[..data_len]);
                output[data_len..data_len + 8].copy_from_slice(&hash);
                Ok(data_len + 8)
            }
            AuthMode::HmacSha1 => {
                let mut mac = self.hmac_enc.as_ref().ok_or(())?.clone();
                mac.update(&output[..data_len]);
                let result = mac.finalize().into_bytes();
                output[data_len..data_len + 20].copy_from_slice(&result);
                Ok(data_len + 20)
            }
        }
    }

    fn auth_cal(&self, data: &[u8], output: &mut [u8]) -> Result<usize, ()> {
        match self.auth_mode {
            AuthMode::None => {
                output[..data.len()].copy_from_slice(data);
                Ok(data.len())
            }
            AuthMode::Md5 => {
                use md5::{Md5, Digest};
                output[..data.len()].copy_from_slice(data);
                let hash = Md5::digest(data);
                output[data.len()..data.len() + 16].copy_from_slice(&hash);
                Ok(data.len() + 16)
            }
            AuthMode::Crc32 => {
                output[..data.len()].copy_from_slice(data);
                let crc = crc32fast::hash(data);
                output[data.len()..data.len() + 4].copy_from_slice(&crc.to_be_bytes());
                Ok(data.len() + 4)
            }
            AuthMode::Simple => {
                output[..data.len()].copy_from_slice(data);
                let hash = simple_hash(data);
                output[data.len()..data.len() + 8].copy_from_slice(&hash);
                Ok(data.len() + 8)
            }
            AuthMode::HmacSha1 => {
                output[..data.len()].copy_from_slice(data);
                let mut mac = self.hmac_enc.as_ref().ok_or(())?.clone();
                mac.update(data);
                let result = mac.finalize().into_bytes();
                output[data.len()..data.len() + 20].copy_from_slice(&result);
                Ok(data.len() + 20)
            }
        }
    }

    fn auth_verify(&self, data: &[u8]) -> Result<usize, ()> {
        match self.auth_mode {
            AuthMode::None => Ok(data.len()),
            AuthMode::Md5 => {
                use md5::{Md5, Digest};
                if data.len() < 16 {
                    return Err(());
                }
                let payload_len = data.len() - 16;
                let computed = Md5::digest(&data[..payload_len]);
                if computed.as_slice() != &data[payload_len..] {
                    log::trace!("MD5 auth verify failed");
                    return Err(());
                }
                Ok(payload_len)
            }
            AuthMode::Crc32 => {
                if data.len() < 4 {
                    return Err(());
                }
                let payload_len = data.len() - 4;
                let computed = crc32fast::hash(&data[..payload_len]);
                let expected =
                    u32::from_be_bytes([data[payload_len], data[payload_len + 1], data[payload_len + 2], data[payload_len + 3]]);
                if computed != expected {
                    return Err(());
                }
                Ok(payload_len)
            }
            AuthMode::Simple => {
                if data.len() < 8 {
                    return Err(());
                }
                let payload_len = data.len() - 8;
                let computed = simple_hash(&data[..payload_len]);
                if computed != data[payload_len..payload_len + 8] {
                    Err(())
                } else {
                    Ok(payload_len)
                }
            }
            AuthMode::HmacSha1 => {
                if data.len() < 20 {
                    return Err(());
                }
                let payload_len = data.len() - 20;
                let mut mac = self.hmac_dec.as_ref().ok_or(())?.clone();
                mac.update(&data[..payload_len]);
                let result = mac.finalize().into_bytes();
                if result.as_slice() != &data[payload_len..] {
                    log::trace!("HMAC-SHA1 auth verify failed");
                    return Err(());
                }
                Ok(payload_len)
            }
        }
    }

    // ── Cipher functions ──

    fn cipher_encrypt(&self, data: &[u8], output: &mut [u8]) -> Result<usize, ()> {
        match self.cipher_mode {
            CipherMode::None => {
                output[..data.len()].copy_from_slice(data);
                Ok(data.len())
            }
            CipherMode::Xor => {
                let key = if self.is_hmac_used {
                    &self.keys.cipher_key_encrypt[..16]
                } else {
                    &self.keys.normal_key
                };
                xor_cipher(data, output, key);
                Ok(data.len())
            }
            CipherMode::Aes128Cbc => {
                let aes = self.aes_enc.as_ref().ok_or(())?;
                // Custom padding directly in output — eliminates intermediate buffer
                output[..data.len()].copy_from_slice(data);
                let padded_len = custom_padding(output, data.len());

                // CBC encrypt block by block using pre-computed key schedule
                let mut prev = ZERO_IV;
                let mut i = 0;
                while i < padded_len {
                    for j in 0..16 {
                        output[i + j] ^= prev[j];
                    }
                    let block =
                        aes::cipher::generic_array::GenericArray::from_mut_slice(&mut output[i..i + 16]);
                    aes.encrypt_block(block);
                    prev.copy_from_slice(&output[i..i + 16]);
                    i += 16;
                }
                Ok(padded_len)
            }
            CipherMode::Aes128Cfb => {
                let aes = self.aes_enc.as_ref().ok_or(())?;
                let key = if self.is_hmac_used {
                    &self.keys.cipher_key_encrypt[..16]
                } else {
                    &self.keys.normal_key
                };
                if data.len() < 16 {
                    return Err(());
                }
                // Copy data directly to output — eliminates intermediate buffer
                output[..data.len()].copy_from_slice(data);

                // Encrypt first block with ECB using pre-computed cipher
                let block = aes::cipher::generic_array::GenericArray::from_mut_slice(&mut output[..16]);
                aes.encrypt_block(block);

                // Then CFB encrypt entire buffer
                let cipher =
                    cfb_mode::Encryptor::<Aes128>::new_from_slices(key, &ZERO_IV).map_err(|_| ())?;
                cipher.encrypt(&mut output[..data.len()]);
                Ok(data.len())
            }
        }
    }

    fn cipher_decrypt(&self, data: &[u8], output: &mut [u8]) -> Result<usize, ()> {
        match self.cipher_mode {
            CipherMode::None => {
                output[..data.len()].copy_from_slice(data);
                Ok(data.len())
            }
            CipherMode::Xor => {
                let key = if self.is_hmac_used {
                    &self.keys.cipher_key_decrypt[..16]
                } else {
                    &self.keys.normal_key
                };
                xor_cipher(data, output, key);
                Ok(data.len())
            }
            CipherMode::Aes128Cbc => {
                let aes = self.aes_dec.as_ref().ok_or(())?;
                let mut len = data.len();
                if !len.is_multiple_of(16) {
                    log::debug!("AES-CBC decrypt: len%16 != 0");
                    return Err(());
                }
                // CBC decrypt block by block using pre-computed key schedule
                output[..len].copy_from_slice(data);
                let mut prev = ZERO_IV;
                let mut i = 0;
                while i < len {
                    let mut block = [0u8; 16];
                    block.copy_from_slice(&output[i..i + 16]);
                    let ga = aes::cipher::generic_array::GenericArray::from_mut_slice(
                        &mut output[i..i + 16],
                    );
                    aes.decrypt_block(ga);
                    for j in 0..16 {
                        output[i + j] ^= prev[j];
                    }
                    prev = block;
                    i += 16;
                }
                // Custom de-padding
                len = custom_de_padding(&output[..len])?;
                Ok(len)
            }
            CipherMode::Aes128Cfb => {
                let aes = self.aes_dec.as_ref().ok_or(())?;
                let key = if self.is_hmac_used {
                    &self.keys.cipher_key_decrypt[..16]
                } else {
                    &self.keys.normal_key
                };
                if data.len() < 16 {
                    return Err(());
                }
                output[..data.len()].copy_from_slice(data);
                let cipher =
                    cfb_mode::Decryptor::<Aes128>::new_from_slices(key, &ZERO_IV).map_err(|_| ())?;
                cipher.decrypt(&mut output[..data.len()]);

                // Decrypt first block with ECB using pre-computed cipher
                let block = aes::cipher::generic_array::GenericArray::from_mut_slice(&mut output[..16]);
                aes.decrypt_block(block);

                Ok(data.len())
            }
        }
    }

    // ── AES-ECB for GRO fix — uses pre-computed key schedules ──

    pub fn aes_ecb_encrypt_block(&self, block: &mut [u8; 16]) {
        let aes = self.aes_gro_enc.as_ref().expect("AES GRO encrypt cipher not initialized");
        let ga = aes::cipher::generic_array::GenericArray::from_mut_slice(block);
        aes.encrypt_block(ga);
    }

    pub fn aes_ecb_decrypt_block(&self, block: &mut [u8; 16]) {
        let aes = self.aes_gro_dec.as_ref().expect("AES GRO decrypt cipher not initialized");
        let ga = aes::cipher::generic_array::GenericArray::from_mut_slice(block);
        aes.decrypt_block(ga);
    }
}

// ─── Utility functions ──────────────────────────────────────────────────────

#[inline]
fn xor_cipher(data: &[u8], output: &mut [u8], key: &[u8]) {
    // Key is always 16 bytes — use bitmask instead of modulo
    for (i, &byte) in data.iter().enumerate() {
        output[i] = byte ^ key[i & 0x0F];
    }
}

/// Custom padding matching C++ padding() function.
/// Appends bytes so that total length is multiple of 16.
/// Last byte = (padded_len - original_len).
fn custom_padding(buf: &mut [u8], data_len: usize) -> usize {
    let mut new_len = data_len + 1;
    if !new_len.is_multiple_of(16) {
        new_len = (new_len / 16) * 16 + 16;
    }
    buf[new_len - 1] = (new_len - data_len) as u8;
    new_len
}

/// Custom de-padding matching C++ de_padding() function.
fn custom_de_padding(data: &[u8]) -> Result<usize, ()> {
    if data.is_empty() {
        return Err(());
    }
    let pad_len = data[data.len() - 1] as usize;
    if pad_len > 16 || pad_len > data.len() {
        return Err(());
    }
    Ok(data.len() - pad_len)
}

/// Simple hash (djb2 + sdbm combined, 8 bytes output) matching C++ simple_hash().
fn simple_hash(data: &[u8]) -> [u8; 8] {
    let mut hash: u32 = 5381;
    let mut hash2: u32 = 0;
    for &c in data {
        hash = (hash.wrapping_shl(5).wrapping_add(hash)) ^ (c as u32);
        hash2 = (c as u32)
            .wrapping_add(hash2.wrapping_shl(6))
            .wrapping_add(hash2.wrapping_shl(16))
            .wrapping_sub(hash2);
    }
    let mut result = [0u8; 8];
    result[..4].copy_from_slice(&hash.to_be_bytes());
    result[4..8].copy_from_slice(&hash2.to_be_bytes());
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_custom_padding() {
        let mut buf = [0u8; 64];
        buf[0] = 0xAA;
        let padded = custom_padding(&mut buf, 1);
        assert_eq!(padded, 16);
        assert_eq!(buf[15], 15); // 16 - 1 = 15

        let padded = custom_padding(&mut buf, 15);
        assert_eq!(padded, 16);
        assert_eq!(buf[15], 1);

        let padded = custom_padding(&mut buf, 16);
        assert_eq!(padded, 32);
        assert_eq!(buf[31], 16);
    }

    #[test]
    fn test_custom_de_padding() {
        let mut buf = [0u8; 16];
        buf[15] = 15;
        assert_eq!(custom_de_padding(&buf), Ok(1));

        buf[15] = 1;
        assert_eq!(custom_de_padding(&buf), Ok(15));
    }

    #[test]
    fn test_xor_roundtrip() {
        let key = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let data = b"Hello, World!!!";
        let mut encrypted = [0u8; 15];
        let mut decrypted = [0u8; 15];
        xor_cipher(data, &mut encrypted, &key);
        xor_cipher(&encrypted, &mut decrypted, &key);
        assert_eq!(data, &decrypted);
    }

    #[test]
    fn test_simple_hash_deterministic() {
        let h1 = simple_hash(b"test data");
        let h2 = simple_hash(b"test data");
        assert_eq!(h1, h2);
        let h3 = simple_hash(b"different data");
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_key_derivation() {
        // Just verify it doesn't panic and produces non-zero keys
        let keys = EncryptionKeys::derive("testpassword", true);
        assert_ne!(keys.normal_key, [0u8; 16]);
        assert_ne!(keys.cipher_key_encrypt[..16], [0u8; 16]);
        assert_ne!(keys.hmac_key_encrypt[..20], [0u8; 20]);

        // Client and server keys should differ (encrypt vs decrypt are swapped)
        let server_keys = EncryptionKeys::derive("testpassword", false);
        assert_eq!(keys.cipher_key_encrypt, server_keys.cipher_key_decrypt);
        assert_eq!(keys.cipher_key_decrypt, server_keys.cipher_key_encrypt);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let keys = EncryptionKeys::derive("mypassword", true);
        let dec_keys = EncryptionKeys::derive("mypassword", false);

        for (auth, cipher) in &[
            (AuthMode::Md5, CipherMode::Aes128Cbc),
            (AuthMode::Crc32, CipherMode::Xor),
            (AuthMode::Simple, CipherMode::None),
            (AuthMode::HmacSha1, CipherMode::Aes128Cbc),
            (AuthMode::None, CipherMode::Aes128Cfb),
        ] {
            let enc = Encryptor::new(keys.clone(), *auth, *cipher);
            let dec = Encryptor::new(dec_keys.clone(), *auth, *cipher);

            let plaintext = b"Hello, World! This is a test message for udp2raw encryption.";
            let mut encrypted = [0u8; BUF_LEN];
            let mut decrypted = [0u8; BUF_LEN];

            let enc_len = enc
                .my_encrypt(plaintext, &mut encrypted)
                .unwrap_or_else(|_| panic!("encrypt failed for {:?}/{:?}", auth, cipher));
            let dec_len = dec
                .my_decrypt(&encrypted[..enc_len], &mut decrypted)
                .unwrap_or_else(|_| panic!("decrypt failed for {:?}/{:?}", auth, cipher));

            assert_eq!(
                &decrypted[..dec_len],
                plaintext.as_slice(),
                "roundtrip failed for {:?}/{:?}",
                auth,
                cipher
            );
        }
    }
}

