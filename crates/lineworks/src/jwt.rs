//! LINE WORKS の Service Account 認証の JWT (RS256)。
//!
//! claim は rust-alc-api の `LineworksBotClient::issue_token` と同じ: `iss` = Client ID・`sub` = Service Account・
//! `iat` = 今・`exp` = 今 + 60 秒。header は `{"alg":"RS256","typ":"JWT"}`。
//!
//! Private Key は Secrets Store の `LINEWORKS_PRIVATE_KEY` の 1 か所だけから読む (bot_configs の `private_key_encrypted` は
//! 読まない)。PKCS#1 (`BEGIN RSA PRIVATE KEY`) と PKCS#8 (`BEGIN PRIVATE KEY`) の両方を受け、実の改行が無く `\n` (2 文字) が
//! 在れば改行に直す ([`crate::secret::normalize_pem_newlines`])。

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::RsaPrivateKey;
use serde::Serialize;
use sha2::Sha256;

use crate::secret::normalize_pem_newlines;

/// JWT の有効期間 (秒)
pub const JWT_TTL_SECS: u64 = 60;

const HEADER: &str = r#"{"alg":"RS256","typ":"JWT"}"#;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
}

pub fn claims(client_id: &str, service_account: &str, now: u64) -> Claims {
    Claims {
        iss: client_id.to_owned(),
        sub: service_account.to_owned(),
        iat: now,
        exp: now + JWT_TTL_SECS,
    }
}

/// Private Key が読めない (中身は文に入れない)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyError;

/// PEM (PKCS#1 か PKCS#8) を読む
pub fn parse_private_key(pem: &str) -> Result<RsaPrivateKey, KeyError> {
    let pem = normalize_pem_newlines(pem.trim());
    if pem.contains("BEGIN RSA PRIVATE KEY") {
        RsaPrivateKey::from_pkcs1_pem(&pem).map_err(|_| KeyError)
    } else {
        RsaPrivateKey::from_pkcs8_pem(&pem).map_err(|_| KeyError)
    }
}

/// `header.payload.signature` (どれも base64url・padding なし)
pub fn sign_rs256(key: &RsaPrivateKey, claims: &Claims) -> String {
    let payload = serde_json::to_vec(claims).unwrap_or_default();
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(HEADER),
        URL_SAFE_NO_PAD.encode(payload)
    );
    let signature = SigningKey::<Sha256>::new(key.clone()).sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    use rsa::signature::Verifier;
    use std::sync::OnceLock;

    /// テスト用の鍵 (生成は重いので 1 回だけ。1024 bit = テスト専用の大きさ)
    pub(crate) fn test_key() -> &'static RsaPrivateKey {
        static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
        KEY.get_or_init(|| RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap())
    }

    pub(crate) fn pkcs8_pem() -> String {
        test_key().to_pkcs8_pem(LineEnding::LF).unwrap().to_string()
    }

    fn pkcs1_pem() -> String {
        test_key().to_pkcs1_pem(LineEnding::LF).unwrap().to_string()
    }

    fn b64json(part: &str) -> serde_json::Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
    }

    #[test]
    fn claims_are_iss_sub_iat_exp() {
        let c = claims("client-1", "sa@example", 1_000);
        assert_eq!(
            serde_json::to_value(&c).unwrap(),
            serde_json::json!({"iss": "client-1", "sub": "sa@example", "iat": 1000, "exp": 1060})
        );
    }

    #[test]
    fn signs_verifiable_rs256() {
        let jwt = sign_rs256(test_key(), &claims("c", "s", 5));
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(
            b64json(parts[0]),
            serde_json::json!({"alg": "RS256", "typ": "JWT"})
        );
        assert_eq!(
            b64json(parts[1]),
            serde_json::json!({"iss": "c", "sub": "s", "iat": 5, "exp": 65})
        );
        let sig =
            Signature::try_from(URL_SAFE_NO_PAD.decode(parts[2]).unwrap().as_slice()).unwrap();
        let verifier = VerifyingKey::<Sha256>::new(test_key().to_public_key());
        let input = format!("{}.{}", parts[0], parts[1]);
        verifier.verify(input.as_bytes(), &sig).unwrap();
        assert!(verifier.verify(b"other", &sig).is_err());
    }

    #[test]
    fn reads_pkcs1_and_pkcs8() {
        assert_eq!(&parse_private_key(&pkcs8_pem()).unwrap(), test_key());
        assert_eq!(&parse_private_key(&pkcs1_pem()).unwrap(), test_key());
    }

    #[test]
    fn reads_escaped_newlines_and_surrounding_space() {
        for pem in [pkcs8_pem(), pkcs1_pem()] {
            let escaped = format!("  {}  ", pem.trim().replace('\n', "\\n"));
            assert!(!escaped.contains('\n'));
            assert_eq!(&parse_private_key(&escaped).unwrap(), test_key());
        }
    }

    /// 中身の無い偽の PEM (区切りの行は実行時に組み立てる — ソースに鍵の形の文字列を置かない)
    fn fake_pem(label: &str, body: &str, sep: &str) -> String {
        let d = "-".repeat(5);
        format!("{d}BEGIN {label}{d}{sep}{body}{sep}{d}END {label}{d}")
    }

    #[test]
    fn rejects_broken_keys() {
        assert_eq!(parse_private_key(""), Err(KeyError));
        assert_eq!(
            parse_private_key(&fake_pem("RSA PRIVATE KEY", "AAAA", "\n")),
            Err(KeyError)
        );
        assert_eq!(
            parse_private_key(&fake_pem("PRIVATE KEY", "AAAA", "\n")),
            Err(KeyError)
        );
    }
}
