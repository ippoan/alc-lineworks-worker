//! LINE WORKS の API の呼び方 (rust-alc-api の `alc-notify::clients::lineworks` の `issue_token`・`send_text_to_user`・
//! `send_text_to_channel` と同じ要求)。
//!
//! - token: `POST https://auth.worksmobile.com/oauth2/v2.0/token` に form で `assertion` (JWT)・`grant_type`・`client_id`・
//!   `client_secret`・`scope` (送信は `bot`。token の口は [`ALLOWED_SCOPES`] のどれか)
//! - 送信: `POST https://www.worksapis.com/v1.0/bots/{bot_id}/channels/{channel_id}/messages` か
//!   `…/users/{user_id}/messages` に `{"content":{"type":"text","text":…}}`
//!
//! access token は isolate の中で (Client ID, Service Account, scope) ごとに、有効期限の [`TOKEN_EXPIRY_MARGIN_SECS`] 秒前まで
//! 使い回す ([`TokenCache`])。外への HTTP は [`Http`] の trait 越し (worker は `worker::Fetch`、テストは偽物)。
//!
//! エラーの文 ([`SendError`] の `Display`) に載るのは、段の名前・HTTP の status・LINE WORKS が返したエラーの code
//! (英数字と `_.-` の 64 文字まで) だけ。token・secret・本文・応答の本文は載せない。

use std::collections::HashMap;
use std::sync::Mutex;

use futures_util::future::BoxFuture;
use serde::Deserialize;

use crate::jwt;

pub const AUTH_TOKEN_ENDPOINT: &str = "https://auth.worksmobile.com/oauth2/v2.0/token";
pub const BOT_ENDPOINT: &str = "https://www.worksapis.com/v1.0/bots/";
/// 送信に使う scope
pub const SEND_SCOPE: &str = "bot";
/// token の口が出してよい scope (auth-worker が使う値: リッチメニュー = `bot`、MCP の `lineworks_get` = `board.read`・
/// `directory.read`。auth-worker の `lineworks-bot-api.ts`・`lineworks-get-path.ts`)
pub const ALLOWED_SCOPES: [&str; 3] = ["bot", "board.read", "directory.read"];
const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/// 有効期限のこの秒数前からは使わずに取り直す (送信の途中で切れないように)
pub const TOKEN_EXPIRY_MARGIN_SECS: u64 = 60;

/// 外への POST 1 本
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub url: String,
    pub content_type: &'static str,
    /// `Authorization` の値 (`Bearer …`)。token の取得では無い
    pub authorization: Option<String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// 届かなかった (DNS・接続・本文の読み出し)。中身は持たない
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpError;

pub trait Http: Send + Sync {
    fn post(&self, req: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, HttpError>>;
}

/// 呼び先 (本番は [`Endpoints::default`]。テストは偽物の URL)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoints {
    pub token: String,
    /// 末尾 `/` 付き
    pub bots: String,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            token: AUTH_TOKEN_ENDPOINT.to_owned(),
            bots: BOT_ENDPOINT.to_owned(),
        }
    }
}

/// 送り先 (LINE WORKS 側の id)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    /// トークルーム (`lineworks_channels.channel_id`)
    Channel(String),
    /// 個人 (`notify_recipients.lineworks_user_id`)
    User(String),
}

/// 送信に使う bot の設定 (client_secret は復号済み)
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    pub client_id: String,
    pub client_secret: String,
    pub service_account: String,
    pub bot_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError {
    /// Private Key が読めない
    PrivateKey,
    /// 届かなかった (段の名前: `token` / `send`)
    Transport(&'static str),
    /// token の取得が 2xx 以外
    TokenStatus(u16, Option<String>),
    /// token の応答が読めない
    TokenParse,
    /// 送信が 2xx 以外
    SendStatus(u16, Option<String>),
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = |c: &Option<String>| c.as_ref().map(|c| format!(" ({c})")).unwrap_or_default();
        match self {
            Self::PrivateKey => f.write_str("private key invalid"),
            Self::Transport(stage) => write!(f, "HTTP error: {stage}"),
            Self::TokenStatus(s, c) => write!(f, "Token issue failed: HTTP {s}{}", code(c)),
            Self::TokenParse => f.write_str("Token issue failed: parse"),
            Self::SendStatus(s, c) => write!(f, "Send failed: HTTP {s}{}", code(c)),
        }
    }
}

/// application/x-www-form-urlencoded の 1 組ずつ
pub fn form_urlencode(pairs: &[(&str, &str)]) -> String {
    fn enc(s: &str, out: &mut String) {
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                    out.push(b as char)
                }
                b' ' => out.push('+'),
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
    }
    let mut out = String::new();
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        enc(k, &mut out);
        out.push('=');
        enc(v, &mut out);
    }
    out
}

/// 送信の URL (rust と同じく id はそのまま path に入れる)
pub fn message_url(endpoints: &Endpoints, bot_id: &str, dest: &Destination) -> String {
    match dest {
        Destination::Channel(c) => format!("{}{bot_id}/channels/{c}/messages", endpoints.bots),
        Destination::User(u) => format!("{}{bot_id}/users/{u}/messages", endpoints.bots),
    }
}

pub fn message_body(text: &str) -> Vec<u8> {
    serde_json::json!({ "content": { "type": "text", "text": text } })
        .to_string()
        .into_bytes()
}

/// LINE WORKS のエラーの応答から code だけを拾う (`code` か `error`。英数字と `_.-` の 64 文字までのときだけ)
pub fn error_code(body: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let code = v.get("code").or_else(|| v.get("error"))?.as_str()?;
    let ok = !code.is_empty()
        && code.len() <= 64
        && code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
    ok.then(|| code.to_owned())
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: ExpiresIn,
}

/// `expires_in` は数か文字列で来る (rust の `deserialize_expires_in` と同じく両方受ける)
#[derive(Deserialize)]
#[serde(untagged)]
enum ExpiresIn {
    Num(u64),
    Str(String),
}

pub fn parse_token_response(body: &[u8]) -> Option<(String, u64)> {
    let t: TokenResponse = serde_json::from_slice(body).ok()?;
    let expires_in = match t.expires_in {
        ExpiresIn::Num(n) => n,
        ExpiresIn::Str(s) => s.trim().parse().ok()?,
    };
    Some((t.access_token, expires_in))
}

type CacheKey = (String, String, String);

/// isolate の中の access token の置き場 ((Client ID, Service Account, scope) → (token, 期限の UNIX 秒))
#[derive(Default)]
pub struct TokenCache(Mutex<HashMap<CacheKey, (String, u64)>>);

impl TokenCache {
    fn get(&self, key: &CacheKey, now: u64) -> Option<(String, u64)> {
        let map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        map.get(key)
            .filter(|(_, expires_at)| now + TOKEN_EXPIRY_MARGIN_SECS < *expires_at)
            .cloned()
    }

    fn put(&self, key: CacheKey, token: String, expires_at: u64) {
        let mut map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        map.insert(key, (token, expires_at));
    }

    /// 持っている token の数 (テスト用)
    pub fn len(&self) -> usize {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// 呼び出しに要るもの一式
pub struct Client<'a> {
    pub http: &'a dyn Http,
    pub endpoints: &'a Endpoints,
    pub cache: &'a TokenCache,
    pub now: u64,
}

impl Client<'_> {
    /// access token と、その期限 (UNIX 秒)。cache に在ればそれを返す
    pub async fn access_token(
        &self,
        creds: &Credentials,
        private_key_pem: &str,
        scope: &str,
    ) -> Result<(String, u64), SendError> {
        let key = (
            creds.client_id.clone(),
            creds.service_account.clone(),
            scope.to_owned(),
        );
        if let Some(hit) = self.cache.get(&key, self.now) {
            return Ok(hit);
        }
        let private_key =
            jwt::parse_private_key(private_key_pem).map_err(|_| SendError::PrivateKey)?;
        let assertion = jwt::sign_rs256(
            &private_key,
            &jwt::claims(&creds.client_id, &creds.service_account, self.now),
        );
        let form = form_urlencode(&[
            ("assertion", &assertion),
            ("grant_type", GRANT_TYPE),
            ("client_id", &creds.client_id),
            ("client_secret", &creds.client_secret),
            ("scope", scope),
        ]);
        let resp = self
            .http
            .post(HttpRequest {
                url: self.endpoints.token.clone(),
                content_type: "application/x-www-form-urlencoded",
                authorization: None,
                body: form.into_bytes(),
            })
            .await
            .map_err(|_| SendError::Transport("token"))?;
        if !(200..300).contains(&resp.status) {
            return Err(SendError::TokenStatus(resp.status, error_code(&resp.body)));
        }
        let (token, expires_in) = parse_token_response(&resp.body).ok_or(SendError::TokenParse)?;
        let expires_at = self.now + expires_in;
        self.cache.put(key, token.clone(), expires_at);
        Ok((token, expires_at))
    }

    /// テキストを 1 通送る
    pub async fn send_text(
        &self,
        creds: &Credentials,
        private_key_pem: &str,
        dest: &Destination,
        text: &str,
    ) -> Result<(), SendError> {
        let (token, _) = self
            .access_token(creds, private_key_pem, SEND_SCOPE)
            .await?;
        let resp = self
            .http
            .post(HttpRequest {
                url: message_url(self.endpoints, &creds.bot_id, dest),
                content_type: "application/json",
                authorization: Some(format!("Bearer {token}")),
                body: message_body(text),
            })
            .await
            .map_err(|_| SendError::Transport("send"))?;
        if (200..300).contains(&resp.status) {
            Ok(())
        } else {
            Err(SendError::SendStatus(resp.status, error_code(&resp.body)))
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::jwt::tests::pkcs8_pem;
    use std::sync::Mutex as StdMutex;

    /// 偽の HTTP: 受けた要求を記録し、URL の頭で応答を決める (無ければ届かない)
    #[derive(Default)]
    pub(crate) struct FakeHttp {
        pub(crate) routes: Vec<(String, u16, Vec<u8>)>,
        pub(crate) seen: StdMutex<Vec<HttpRequest>>,
    }

    impl FakeHttp {
        pub(crate) fn with(routes: &[(&str, u16, &str)]) -> Self {
            Self {
                routes: routes
                    .iter()
                    .map(|(u, s, b)| ((*u).to_owned(), *s, b.as_bytes().to_vec()))
                    .collect(),
                seen: StdMutex::default(),
            }
        }
    }

    impl Http for FakeHttp {
        fn post(&self, req: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, HttpError>> {
            Box::pin(async move {
                let hit = self
                    .routes
                    .iter()
                    .find(|(u, _, _)| req.url.starts_with(u))
                    .cloned();
                self.seen.lock().unwrap().push(req);
                let (_, status, body) = hit.ok_or(HttpError)?;
                Ok(HttpResponse { status, body })
            })
        }
    }

    pub(crate) fn endpoints() -> Endpoints {
        Endpoints {
            token: "https://lw.test/token".into(),
            bots: "https://lw.test/bots/".into(),
        }
    }

    pub(crate) fn creds() -> Credentials {
        Credentials {
            client_id: "client-1".into(),
            client_secret: "secret &=1".into(),
            service_account: "sa@example".into(),
            bot_id: "bot-1".into(),
        }
    }

    const TOKEN_OK: &str = r#"{"access_token":"tok-1","refresh_token":"r","expires_in":"86400"}"#;

    fn form(req: &HttpRequest) -> Vec<(String, String)> {
        String::from_utf8(req.body.clone())
            .unwrap()
            .split('&')
            .map(|kv| {
                let (k, v) = kv.split_once('=').unwrap();
                (k.to_owned(), v.to_owned())
            })
            .collect()
    }

    #[test]
    fn urls_and_body() {
        let e = Endpoints::default();
        assert_eq!(e.token, "https://auth.worksmobile.com/oauth2/v2.0/token");
        assert_eq!(
            message_url(&e, "b1", &Destination::Channel("ch-1".into())),
            "https://www.worksapis.com/v1.0/bots/b1/channels/ch-1/messages"
        );
        assert_eq!(
            message_url(&e, "b1", &Destination::User("u@x".into())),
            "https://www.worksapis.com/v1.0/bots/b1/users/u@x/messages"
        );
        let body: serde_json::Value = serde_json::from_slice(&message_body("予約 \"1\"")).unwrap();
        assert_eq!(
            body,
            serde_json::json!({"content": {"type": "text", "text": "予約 \"1\""}})
        );
    }

    #[test]
    fn form_encoding() {
        assert_eq!(
            form_urlencode(&[("a", "x y&z=/日"), ("b-._*", "")]),
            "a=x+y%26z%3D%2F%E6%97%A5&b-._*="
        );
    }

    #[test]
    fn token_response_shapes() {
        assert_eq!(
            parse_token_response(TOKEN_OK.as_bytes()),
            Some(("tok-1".into(), 86400))
        );
        assert_eq!(
            parse_token_response(br#"{"access_token":"t","expires_in":30}"#),
            Some(("t".into(), 30))
        );
        assert_eq!(
            parse_token_response(br#"{"access_token":"t","expires_in":"x"}"#),
            None
        );
        assert_eq!(parse_token_response(b"nope"), None);
    }

    #[test]
    fn error_codes() {
        assert_eq!(
            error_code(br#"{"code":"FORBIDDEN","description":"x"}"#),
            Some("FORBIDDEN".into())
        );
        assert_eq!(
            error_code(br#"{"error":"invalid_client"}"#),
            Some("invalid_client".into())
        );
        assert_eq!(error_code(br#"{"code":"has space"}"#), None);
        assert_eq!(error_code(br#"{"code":""}"#), None);
        assert_eq!(
            error_code(format!(r#"{{"code":"{}"}}"#, "A".repeat(65)).as_bytes()),
            None
        );
        assert_eq!(error_code(br#"{"code":1}"#), None);
        assert_eq!(error_code(b"<html>"), None);
    }

    #[test]
    fn error_text_has_no_secrets() {
        let cases = [
            (SendError::PrivateKey, "private key invalid"),
            (SendError::Transport("token"), "HTTP error: token"),
            (
                SendError::TokenStatus(400, Some("invalid_client".into())),
                "Token issue failed: HTTP 400 (invalid_client)",
            ),
            (
                SendError::TokenStatus(500, None),
                "Token issue failed: HTTP 500",
            ),
            (SendError::TokenParse, "Token issue failed: parse"),
            (
                SendError::SendStatus(403, Some("FORBIDDEN".into())),
                "Send failed: HTTP 403 (FORBIDDEN)",
            ),
        ];
        for (e, want) in cases {
            assert_eq!(e.to_string(), want);
        }
    }

    #[tokio::test]
    async fn issues_token_then_sends_and_reuses_token() {
        let http = FakeHttp::with(&[
            ("https://lw.test/token", 200, TOKEN_OK),
            ("https://lw.test/bots/", 201, ""),
        ]);
        let e = endpoints();
        let cache = TokenCache::default();
        let pem = pkcs8_pem();
        let c = Client {
            http: &http,
            endpoints: &e,
            cache: &cache,
            now: 1_000,
        };
        c.send_text(&creds(), &pem, &Destination::Channel("ch-1".into()), "hi")
            .await
            .unwrap();
        c.send_text(&creds(), &pem, &Destination::User("u1".into()), "yo")
            .await
            .unwrap();
        let seen = http.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 3, "token は 1 回だけ");
        assert_eq!(seen[0].url, "https://lw.test/token");
        assert_eq!(seen[0].content_type, "application/x-www-form-urlencoded");
        assert_eq!(seen[0].authorization, None);
        let f = form(&seen[0]);
        let keys: Vec<&str> = f.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            [
                "assertion",
                "grant_type",
                "client_id",
                "client_secret",
                "scope"
            ]
        );
        assert_eq!(
            f[1].1,
            "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer"
        );
        assert_eq!(f[2].1, "client-1");
        assert_eq!(f[3].1, "secret+%26%3D1");
        assert_eq!(f[4].1, "bot");
        assert_eq!(f[0].1.split('.').count(), 3);
        assert_eq!(
            seen[1].url,
            "https://lw.test/bots/bot-1/channels/ch-1/messages"
        );
        assert_eq!(seen[1].authorization.as_deref(), Some("Bearer tok-1"));
        assert_eq!(seen[1].content_type, "application/json");
        assert_eq!(seen[2].url, "https://lw.test/bots/bot-1/users/u1/messages");
        assert_eq!(cache.len(), 1);
    }

    #[tokio::test]
    async fn token_is_reissued_near_expiry_and_per_service_account() {
        let http = FakeHttp::with(&[
            (
                "https://lw.test/token",
                200,
                r#"{"access_token":"t","expires_in":120}"#,
            ),
            ("https://lw.test/bots/", 200, ""),
        ]);
        let e = endpoints();
        let cache = TokenCache::default();
        assert!(cache.is_empty());
        let pem = pkcs8_pem();
        let dest = Destination::User("u".into());
        let tokens = |n: usize| {
            let seen = http.seen.lock().unwrap();
            assert_eq!(seen.iter().filter(|r| r.url.ends_with("/token")).count(), n);
        };
        let at = |now| Client {
            http: &http,
            endpoints: &e,
            cache: &cache,
            now,
        };
        at(0).send_text(&creds(), &pem, &dest, "a").await.unwrap();
        // 期限 120 − 余裕 60 = 60 秒より前は使い回す
        at(59).send_text(&creds(), &pem, &dest, "a").await.unwrap();
        tokens(1);
        at(60).send_text(&creds(), &pem, &dest, "a").await.unwrap();
        tokens(2);
        let mut other = creds();
        other.service_account = "sa2@example".into();
        at(61).send_text(&other, &pem, &dest, "a").await.unwrap();
        tokens(3);
        assert_eq!(cache.len(), 2);
        // scope ごとに別の token。期限は取得した時刻 + expires_in で、cache から返すときも同じ値
        assert_eq!(
            at(70)
                .access_token(&creds(), &pem, "board.read")
                .await
                .unwrap(),
            ("t".into(), 190)
        );
        tokens(4);
        assert_eq!(
            at(100)
                .access_token(&creds(), &pem, "board.read")
                .await
                .unwrap(),
            ("t".into(), 190)
        );
        tokens(4);
        assert_eq!(cache.len(), 3);
        let f = form(http.seen.lock().unwrap().last().unwrap());
        assert_eq!(f[4], ("scope".into(), "board.read".into()));
    }

    async fn run(http: FakeHttp, pem: String) -> (Result<(), SendError>, usize) {
        let e = endpoints();
        let cache = TokenCache::default();
        let c = Client {
            http: &http,
            endpoints: &e,
            cache: &cache,
            now: 0,
        };
        let r = c
            .send_text(&creds(), &pem, &Destination::Channel("c".into()), "x")
            .await;
        (r, cache.len())
    }

    #[tokio::test]
    async fn failures_map_to_send_errors() {
        let pem = pkcs8_pem();
        let (r, n) = run(FakeHttp::with(&[]), pem.clone()).await;
        assert_eq!((r, n), (Err(SendError::Transport("token")), 0));
        let (r, _) = run(FakeHttp::with(&[]), "bad".into()).await;
        assert_eq!(r, Err(SendError::PrivateKey));
        let (r, n) = run(
            FakeHttp::with(&[(
                "https://lw.test/token",
                400,
                r#"{"error":"invalid_client"}"#,
            )]),
            pem.clone(),
        )
        .await;
        assert_eq!(
            (r, n),
            (
                Err(SendError::TokenStatus(400, Some("invalid_client".into()))),
                0
            )
        );
        let (r, n) = run(
            FakeHttp::with(&[("https://lw.test/token", 200, "{}")]),
            pem.clone(),
        )
        .await;
        assert_eq!((r, n), (Err(SendError::TokenParse), 0));
        let (r, n) = run(
            FakeHttp::with(&[("https://lw.test/token", 200, TOKEN_OK)]),
            pem.clone(),
        )
        .await;
        assert_eq!((r, n), (Err(SendError::Transport("send")), 1));
        let (r, _) = run(
            FakeHttp::with(&[
                ("https://lw.test/token", 200, TOKEN_OK),
                ("https://lw.test/bots/", 403, r#"{"code":"FORBIDDEN"}"#),
            ]),
            pem,
        )
        .await;
        assert_eq!(r, Err(SendError::SendStatus(403, Some("FORBIDDEN".into()))));
    }
}
