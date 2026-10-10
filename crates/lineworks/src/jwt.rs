//! LINE WORKS の Service Account 認証の JWT (RS256) の claim。
//!
//! claim は rust-alc-api の `LineworksBotClient::issue_token` と同じ: `iss` = Client ID・`sub` = Service Account・
//! `iat` = 今・`exp` = 今 + 60 秒。署名は `alc_worker_crypto::jwt::sign_rs256(pem, None, &claims)` (header は kid なしの
//! `{"alg":"RS256","typ":"JWT"}`。PKCS#1 / PKCS#8 の PEM と、1 行に `\n` (2 文字) で入れた PEM を読む)。
//!
//! Private Key は Secrets Store の `LINEWORKS_PRIVATE_KEY` の 1 か所だけから読む (bot_configs の `private_key_encrypted` は
//! 読まない)。

use serde::Serialize;

/// JWT の有効期間 (秒)
pub const JWT_TTL_SECS: u64 = 60;

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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alc_worker_crypto::jwt::sign_rs256;
    use rand::SeedableRng;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    use rsa::RsaPrivateKey;
    use std::sync::OnceLock;

    /// テスト用の鍵 (種を固定した乱数から作る = いつも同じ鍵。生成は重いので 1 回だけ。1024 bit = テスト専用の大きさ)
    fn test_key() -> &'static RsaPrivateKey {
        static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
        KEY.get_or_init(|| {
            RsaPrivateKey::new(&mut rand::rngs::StdRng::seed_from_u64(747), 1024).unwrap()
        })
    }

    pub(crate) fn pkcs8_pem() -> String {
        test_key().to_pkcs8_pem(LineEnding::LF).unwrap().to_string()
    }

    #[test]
    fn claims_are_iss_sub_iat_exp() {
        let c = claims("client-1", "sa@example", 1_000);
        assert_eq!(
            serde_json::to_value(&c).unwrap(),
            serde_json::json!({"iss": "client-1", "sub": "sa@example", "iat": 1000, "exp": 1060})
        );
    }

    /// alc-worker-crypto へ切り替える前の実装 (f9f8feb の `jwt::sign_rs256`) が同じ鍵・claim で出した値
    /// (RS256 = PKCS#1 v1.5 の署名は乱数を使わないので、header・payload・署名とも 1 byte も変わらない)
    const BEFORE_SWITCH: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.\
        eyJpc3MiOiJjbGllbnQtNzQ3Iiwic3ViIjoic2EtNzQ3QGV4YW1wbGUiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6MTcwMDAwMDA2MH0.\
        YHiGn06vUSamdxBcIC-85HUulX178PLPAgrfl3VTToMidfO74PA359xLTbHz_JUa8CLgikZ1JZiWvsJ5GLxxejRNbO2Rht1mtlJ2SIxav\
        UBG81YLx7dKZnyu1uo6sM7CwYTYcbd2HTKZZVb-Qlem_fMyYNFyVPKJEpnCczk9RM0";

    #[test]
    fn same_jwt_as_before_switch() {
        let c = claims("client-747", "sa-747@example", 1_700_000_000);
        let pkcs1 = test_key().to_pkcs1_pem(LineEnding::LF).unwrap().to_string();
        let escaped = pkcs8_pem().trim().replace('\n', "\\n");
        for pem in [pkcs8_pem(), pkcs1, escaped] {
            assert_eq!(sign_rs256(&pem, None, &c).unwrap(), BEFORE_SWITCH);
        }
    }
}
