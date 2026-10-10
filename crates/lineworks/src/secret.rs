//! 保存された秘密値の復号 (rust-alc-api の `alc_core::auth_lineworks::decrypt_secret` と同じ形式)。
//!
//! 形式: `base64(nonce[12] + ciphertext + tag[16])`、AES-256-GCM、鍵 = SHA-256(`SSO_ENCRYPTION_KEY`)、AAD なし。
//! rust は `ring` で、ここは RustCrypto (`aes-gcm`) で同じものを読む (wasm32 に載せるため)。相互に読めることは
//! tests の `rust_ring_*` が確かめる。
//!
//! エラーは段の名前だけ (暗号文・鍵・平文を文に入れない)。

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use sha2::{Digest, Sha256};

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// 復号の失敗 (どの段で落ちたかだけ)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptError {
    Base64,
    TooShort,
    Aead,
    Utf8,
}

impl std::fmt::Display for DecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Base64 => "base64",
            Self::TooShort => "too_short",
            Self::Aead => "aead",
            Self::Utf8 => "utf8",
        })
    }
}

fn cipher(key_material: &str) -> Aes256Gcm {
    let key = Sha256::digest(key_material.as_bytes());
    Aes256Gcm::new(&key)
}

/// `client_secret_encrypted` などを復号する
pub fn decrypt_secret(ciphertext_b64: &str, key_material: &str) -> Result<String, DecryptError> {
    let data = BASE64
        .decode(ciphertext_b64)
        .map_err(|_| DecryptError::Base64)?;
    if data.len() < NONCE_LEN + TAG_LEN {
        return Err(DecryptError::TooShort);
    }
    let (nonce, body) = data.split_at(NONCE_LEN);
    let plain = cipher(key_material)
        .decrypt(Nonce::from_slice(nonce), body)
        .map_err(|_| DecryptError::Aead)?;
    String::from_utf8(plain).map_err(|_| DecryptError::Utf8)
}

/// 暗号化 (nonce は呼び手が渡す)。worker は使わない — テストで DB に入れる暗号文を作るためと、
/// rust 側が読めることを確かめるためにある
pub fn encrypt_secret_with_nonce(plaintext: &str, key_material: &str, nonce: [u8; 12]) -> String {
    let mut out = nonce.to_vec();
    // 鍵の長さは固定 (32 byte) なので、暗号化は失敗しない
    let sealed = cipher(key_material)
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
        .unwrap_or_default();
    out.extend_from_slice(&sealed);
    BASE64.encode(out)
}

/// PEM の文字列に実の改行が無く、`\n` (2 文字) が在るときだけ、それを改行に直す
/// (rust-alc-api の `normalize_pem_newlines` と同じ。Secrets Store に 1 行で入れた鍵も読めるように)
pub fn normalize_pem_newlines(s: &str) -> String {
    if s.contains("\\n") && !s.contains('\n') {
        s.replace("\\n", "\n")
    } else {
        s.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::aead::{self, Aad, LessSafeKey, Nonce as RingNonce, UnboundKey, AES_256_GCM};
    use ring::rand::{SecureRandom, SystemRandom};

    const KEY: &str = "test-sso-encryption-key";

    // ---- rust-alc-api の crates/alc-core/src/auth_lineworks.rs の encrypt_secret / decrypt_secret の写し (ring) ----

    fn rust_encrypt_secret(plaintext: &str, key_material: &str) -> Result<String, String> {
        let mut key_bytes = [0u8; 32];
        let hash = Sha256::digest(key_material.as_bytes());
        key_bytes.copy_from_slice(&hash);
        let unbound_key =
            UnboundKey::new(&AES_256_GCM, &key_bytes).map_err(|e| format!("Key error: {e}"))?;
        let key = LessSafeKey::new(unbound_key);
        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; 12];
        rng.fill(&mut nonce_bytes)
            .map_err(|e| format!("RNG error: {e}"))?;
        let nonce = RingNonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = plaintext.as_bytes().to_vec();
        let tag_len = aead::AES_256_GCM.tag_len();
        in_out.extend(vec![0u8; tag_len]);
        key.seal_in_place_separate_tag(nonce, Aad::empty(), &mut in_out[..plaintext.len()])
            .map(|tag| {
                in_out[plaintext.len()..].copy_from_slice(tag.as_ref());
            })
            .map_err(|e| format!("Encryption error: {e}"))?;
        let mut result = Vec::with_capacity(12 + in_out.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&in_out);
        Ok(BASE64.encode(&result))
    }

    fn rust_decrypt_secret(ciphertext_b64: &str, key_material: &str) -> Result<String, String> {
        let mut key_bytes = [0u8; 32];
        let hash = Sha256::digest(key_material.as_bytes());
        key_bytes.copy_from_slice(&hash);
        let unbound_key =
            UnboundKey::new(&AES_256_GCM, &key_bytes).map_err(|e| format!("Key error: {e}"))?;
        let key = LessSafeKey::new(unbound_key);
        let data = BASE64
            .decode(ciphertext_b64)
            .map_err(|e| format!("Base64 decode error: {e}"))?;
        if data.len() < 12 + aead::AES_256_GCM.tag_len() {
            return Err("Ciphertext too short".to_string());
        }
        let (nonce_bytes, ciphertext_and_tag) = data.split_at(12);
        let nonce = RingNonce::assume_unique_for_key(nonce_bytes.try_into().unwrap());
        let mut in_out = ciphertext_and_tag.to_vec();
        let plaintext = key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|e| format!("Decryption error: {e}"))?;
        String::from_utf8(plaintext.to_vec()).map_err(|e| format!("UTF-8 error: {e}"))
    }

    #[test]
    fn rust_ring_ciphertext_decrypts_here() {
        for plain in ["test-client-secret", "", "日本語の secret 🔑"] {
            let c = rust_encrypt_secret(plain, KEY).unwrap();
            assert_eq!(decrypt_secret(&c, KEY).unwrap(), plain);
        }
    }

    #[test]
    fn ciphertext_from_here_decrypts_in_rust_ring() {
        let c = encrypt_secret_with_nonce("test-client-secret", KEY, [7; 12]);
        assert_eq!(rust_decrypt_secret(&c, KEY).unwrap(), "test-client-secret");
    }

    /// rust と同じ ring の封じ方で、nonce だけ固定したもの
    fn ring_seal_with_nonce(plaintext: &str, key_material: &str, nonce: [u8; 12]) -> String {
        let hash = Sha256::digest(key_material.as_bytes());
        let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &hash).unwrap());
        let mut in_out = plaintext.as_bytes().to_vec();
        key.seal_in_place_append_tag(
            RingNonce::assume_unique_for_key(nonce),
            Aad::empty(),
            &mut in_out,
        )
        .unwrap();
        let mut out = nonce.to_vec();
        out.extend(in_out);
        BASE64.encode(out)
    }

    /// 固定の値 (鍵の材料・nonce・平文) から作った暗号文が ring と 1 byte も違わず、固定の文字列のまま読めること
    #[test]
    fn known_answer() {
        let c = encrypt_secret_with_nonce("abc", "k", [0; 12]);
        assert_eq!(c, ring_seal_with_nonce("abc", "k", [0; 12]));
        assert_eq!(c, "AAAAAAAAAAAAAAAAAvErgQzMywjsCKsh7LKnKfQlcA==");
        assert_eq!(rust_decrypt_secret(&c, "k").unwrap(), "abc");
        assert_eq!(decrypt_secret(&c, "k").unwrap(), "abc");
    }

    #[test]
    fn errors() {
        assert_eq!(
            decrypt_secret("not base64!", KEY),
            Err(DecryptError::Base64)
        );
        let short = BASE64.encode([0u8; 27]);
        assert_eq!(decrypt_secret(&short, KEY), Err(DecryptError::TooShort));
        // rust も同じ長さを拒む
        assert!(rust_decrypt_secret(&short, KEY).is_err());
        let c = encrypt_secret_with_nonce("x", KEY, [1; 12]);
        assert_eq!(decrypt_secret(&c, "other-key"), Err(DecryptError::Aead));
        let bad_utf8 = rust_encrypt_secret_bytes(&[0xff, 0xfe], KEY);
        assert_eq!(decrypt_secret(&bad_utf8, KEY), Err(DecryptError::Utf8));
        let names: Vec<String> = [
            DecryptError::Base64,
            DecryptError::TooShort,
            DecryptError::Aead,
            DecryptError::Utf8,
        ]
        .iter()
        .map(|e| e.to_string())
        .collect();
        assert_eq!(names, ["base64", "too_short", "aead", "utf8"]);
    }

    fn rust_encrypt_secret_bytes(plain: &[u8], key_material: &str) -> String {
        let nonce = [3u8; 12];
        let mut out = nonce.to_vec();
        out.extend(
            cipher(key_material)
                .encrypt(Nonce::from_slice(&nonce), plain)
                .unwrap(),
        );
        BASE64.encode(out)
    }

    /// 中身の無い偽の PEM (区切りの行は実行時に組み立てる — ソースに鍵の形の文字列を置かない)
    fn fake_pem(label: &str, body: &str, sep: &str) -> String {
        let d = "-".repeat(5);
        format!("{d}BEGIN {label}{d}{sep}{body}{sep}{d}END {label}{d}")
    }

    #[test]
    fn pem_newlines() {
        let escaped = fake_pem("PRIVATE KEY", "MIIE", "\\n");
        let fixed = normalize_pem_newlines(&escaped);
        assert_eq!(fixed, fake_pem("PRIVATE KEY", "MIIE", "\n"));
        let valid = "a\nb";
        assert_eq!(normalize_pem_newlines(valid), valid);
        let mixed = "a\nb\\nc";
        assert_eq!(normalize_pem_newlines(mixed), mixed);
    }
}
