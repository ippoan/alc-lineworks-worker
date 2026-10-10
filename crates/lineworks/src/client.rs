//! LINE WORKS の API の呼び方 (rust-alc-api の `alc-notify::clients::lineworks` の `issue_token`・`send_text_to_user`・
//! `send_text_to_channel`・`send_image_to_user`・`send_image_to_channel` と同じ要求)。
//!
//! - token: `POST https://auth.worksmobile.com/oauth2/v2.0/token` に form で `assertion` (JWT)・`grant_type`・`client_id`・
//!   `client_secret`・`scope` (送信は `bot`。token の口は [`ALLOWED_SCOPES`] のどれか)
//! - 送信: `POST https://www.worksapis.com/v1.0/bots/{bot_id}/channels/{channel_id}/messages` か
//!   `…/users/{user_id}/messages` に `{"content":{"type":"text","text":…}}` か
//!   `{"content":{"type":"image","originalContentUrl":…,"previewImageUrl":…}}` (画像は URL 渡し。LINE WORKS が取りに行く)
//!
//! - 読み取り (Refs ippoan/rust-alc-api#747。rust の `list_org_users`・`fetch_audit_csv`・`fetch_board_activity_lower_bound`):
//!   `GET https://www.worksapis.com/v1.0/users` (cursor で全ページ、scope `directory.read`)・
//!   `GET …/v1.0/audits/logs/download` (scope `audit.read`。302 の `Location` 先にも `Authorization` を付け直す)・
//!   `GET …/v1.0/boards` → `…/{board}/posts` → `…/{board}/posts/{post}/readers` (scope `board.read`)。
//!   GET はどれもリダイレクトを自動で追わず、[`Client::get`] が手で辿る。`audit.read` は worker の中だけで使い、
//!   token の口の [`ALLOWED_SCOPES`] には入れない (token の cache のキーは scope ごとに別)
//!
//! access token は isolate の中で (Client ID, Service Account, scope) ごとに、有効期限の [`TOKEN_EXPIRY_MARGIN_SECS`] 秒前まで
//! 使い回す ([`TokenCache`])。外への HTTP は [`Http`] の trait 越し (worker は `worker::Fetch`、テストは偽物)。
//!
//! エラーの文 ([`SendError`] の `Display`) に載るのは、段の名前・HTTP の status・LINE WORKS が返したエラーの code
//! (英数字と `_.-` の 64 文字まで) だけ。token・secret・本文・応答の本文は載せない。

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use futures_util::future::BoxFuture;
use serde::{Deserialize, Deserializer, Serialize};

use crate::jwt;

pub const AUTH_TOKEN_ENDPOINT: &str = "https://auth.worksmobile.com/oauth2/v2.0/token";
pub const BOT_ENDPOINT: &str = "https://www.worksapis.com/v1.0/bots/";
/// 送信に使う scope
pub const SEND_SCOPE: &str = "bot";
/// token の口が出してよい scope (auth-worker が使う値: リッチメニュー = `bot`、MCP の `lineworks_get` = `board.read`・
/// `directory.read`。auth-worker の `lineworks-bot-api.ts`・`lineworks-get-path.ts`)
pub const ALLOWED_SCOPES: [&str; 3] = ["bot", "board.read", "directory.read"];
pub const USERS_ENDPOINT: &str = "https://www.worksapis.com/v1.0/users";
pub const AUDIT_LOG_DOWNLOAD_ENDPOINT: &str = "https://www.worksapis.com/v1.0/audits/logs/download";
pub const BOARDS_ENDPOINT: &str = "https://www.worksapis.com/v1.0/boards";
/// 組織のメンバーの一覧に使う scope
pub const DIRECTORY_SCOPE: &str = "directory.read";
/// 監査ログの CSV に使う scope (worker の中だけ。token の口では出さない)
pub const AUDIT_SCOPE: &str = "audit.read";
/// 掲示板の既読に使う scope
pub const BOARD_SCOPE: &str = "board.read";
/// リダイレクトを辿る上限 (rust の `get_with_auth_redirect` の `MAX_HOPS`)
pub const MAX_REDIRECT_HOPS: usize = 5;
/// 見る掲示板の数・掲示板ごとの投稿の数の上限 (rust の `BOARD_ACTIVITY_MAX_BOARDS`・`BOARD_ACTIVITY_MAX_POSTS_PER_BOARD`)
pub const BOARD_ACTIVITY_MAX_BOARDS: usize = 5;
pub const BOARD_ACTIVITY_MAX_POSTS_PER_BOARD: usize = 10;
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
    /// `Location` の値 (GET の 3xx のときだけ見る)
    pub location: Option<String>,
}

/// 届かなかった (DNS・接続・本文の読み出し)。中身は持たない
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpError;

pub trait Http: Send + Sync {
    fn post(&self, req: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, HttpError>>;
    /// `Authorization` 付きの GET。**リダイレクトは追わない** (3xx はそのまま返し、`location` に `Location` を入れる)
    fn get(
        &self,
        url: String,
        authorization: String,
    ) -> BoxFuture<'_, Result<HttpResponse, HttpError>>;
}

/// 呼び先 (本番は [`Endpoints::default`]。テストは偽物の URL)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoints {
    pub token: String,
    /// 末尾 `/` 付き
    pub bots: String,
    /// 以下 3 つは末尾 `/` 無し
    pub users: String,
    pub audit_download: String,
    pub boards: String,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            token: AUTH_TOKEN_ENDPOINT.to_owned(),
            bots: BOT_ENDPOINT.to_owned(),
            users: USERS_ENDPOINT.to_owned(),
            audit_download: AUDIT_LOG_DOWNLOAD_ENDPOINT.to_owned(),
            boards: BOARDS_ENDPOINT.to_owned(),
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

/// 送る中身
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Content<'a> {
    Text(&'a str),
    /// 画像の URL (原寸と preview)
    Image {
        original_url: &'a str,
        preview_url: &'a str,
    },
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
    /// 読み取り (段の名前) が 2xx・3xx 以外
    ReadStatus(&'static str, u16, Option<String>),
    /// 読み取りの応答が読めない
    ReadParse(&'static str),
    /// 3xx に `Location` が無い・https でない・辿る回数が上限を超えた
    Redirect(&'static str),
}

impl SendError {
    /// LINE WORKS が権限 (scope) で断った (rust の `scope_error` と同じく、403 か code に forbidden を含むとき)
    pub fn is_forbidden(&self) -> bool {
        let forbidden = |c: &Option<String>| {
            c.as_deref()
                .is_some_and(|c| c.to_ascii_lowercase().contains("forbidden"))
        };
        match self {
            Self::TokenStatus(s, c) | Self::SendStatus(s, c) | Self::ReadStatus(_, s, c) => {
                *s == 403 || forbidden(c)
            }
            _ => false,
        }
    }
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
            Self::ReadStatus(stage, s, c) => {
                write!(f, "Read {stage} failed: HTTP {s}{}", code(c))
            }
            Self::ReadParse(stage) => write!(f, "Read {stage} failed: parse"),
            Self::Redirect(stage) => write!(f, "Read {stage} failed: redirect"),
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

pub fn message_body(content: Content<'_>) -> Vec<u8> {
    let content = match content {
        Content::Text(text) => serde_json::json!({ "type": "text", "text": text }),
        Content::Image {
            original_url,
            preview_url,
        } => serde_json::json!({
            "type": "image",
            "originalContentUrl": original_url,
            "previewImageUrl": preview_url,
        }),
    };
    serde_json::json!({ "content": content })
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

    /// 1 通送る
    pub async fn send(
        &self,
        creds: &Credentials,
        private_key_pem: &str,
        dest: &Destination,
        content: Content<'_>,
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
                body: message_body(content),
            })
            .await
            .map_err(|_| SendError::Transport("send"))?;
        if (200..300).contains(&resp.status) {
            Ok(())
        } else {
            Err(SendError::SendStatus(resp.status, error_code(&resp.body)))
        }
    }

    /// GET。3xx は `Location` (https だけ) へ同じ `Authorization` を付け直して手で辿る (rust の `get_with_auth_redirect`。
    /// 監査ログのダウンロード URL は別ホストへの 302 で、自動で追うと `Authorization` が落ちて 401 になる)。
    /// 要求は [`MAX_REDIRECT_HOPS`] 回まで
    pub async fn get(
        &self,
        url: String,
        token: &str,
        stage: &'static str,
    ) -> Result<Vec<u8>, SendError> {
        let mut current = url;
        for _ in 0..MAX_REDIRECT_HOPS {
            let resp = self
                .http
                .get(current, format!("Bearer {token}"))
                .await
                .map_err(|_| SendError::Transport(stage))?;
            if (300..400).contains(&resp.status) {
                current = resp
                    .location
                    .filter(|l| l.starts_with("https://"))
                    .ok_or(SendError::Redirect(stage))?;
                continue;
            }
            if !(200..300).contains(&resp.status) {
                return Err(SendError::ReadStatus(
                    stage,
                    resp.status,
                    error_code(&resp.body),
                ));
            }
            return Ok(resp.body);
        }
        Err(SendError::Redirect(stage))
    }

    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        url: String,
        token: &str,
        stage: &'static str,
    ) -> Result<T, SendError> {
        let body = self.get(url, token, stage).await?;
        serde_json::from_slice(&body).map_err(|_| SendError::ReadParse(stage))
    }

    /// 組織のメンバーの一覧 (scope `directory.read`。`responseMetaData.nextCursor` が無くなるまで全ページ。rust の `list_org_users`)
    pub async fn list_org_users(
        &self,
        creds: &Credentials,
        private_key_pem: &str,
    ) -> Result<Vec<LineworksMember>, SendError> {
        let (token, _) = self
            .access_token(creds, private_key_pem, DIRECTORY_SCOPE)
            .await?;
        let mut members = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let url = match &cursor {
                Some(c) => format!(
                    "{}?{}",
                    self.endpoints.users,
                    form_urlencode(&[("cursor", c)])
                ),
                None => self.endpoints.users.clone(),
            };
            let page: UsersResponse = self.get_json(url, &token, "users").await?;
            members.extend(page.users.unwrap_or_default().into_iter().map(member));
            cursor = page.response_meta_data.and_then(|m| m.next_cursor);
            if cursor.is_none() {
                return Ok(members);
            }
        }
    }

    /// 監査ログの CSV (scope `audit.read`。`service` は `auth` / `message`。期間は呼び手が 31 日未満にする。rust の `fetch_audit_csv`)
    pub async fn fetch_audit_csv(
        &self,
        creds: &Credentials,
        private_key_pem: &str,
        service: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<String, SendError> {
        let (token, _) = self
            .access_token(creds, private_key_pem, AUDIT_SCOPE)
            .await?;
        let url = format!(
            "{}?{}",
            self.endpoints.audit_download,
            form_urlencode(&[
                ("service", service),
                ("startTime", &format_audit_time(start)),
                ("endTime", &format_audit_time(end)),
                ("language", "ja_JP"),
            ])
        );
        let bytes = self.get(url, &token, "audit").await?;
        Ok(decode_csv_bytes(&bytes))
    }

    /// 掲示板の既読から「投稿の作成日時以降にアクティブだった」という下限 (user id → 日時。scope `board.read`。
    /// rust の `fetch_board_activity_lower_bound`)。既読の API は日時を返さないので投稿の作成日時を下限にする。
    /// 掲示板は [`BOARD_ACTIVITY_MAX_BOARDS`] 個、掲示板ごとに `since` 以降の投稿を [`BOARD_ACTIVITY_MAX_POSTS_PER_BOARD`] 件まで
    pub async fn fetch_board_activity_lower_bound(
        &self,
        creds: &Credentials,
        private_key_pem: &str,
        since: DateTime<Utc>,
    ) -> Result<HashMap<String, DateTime<Utc>>, SendError> {
        let (token, _) = self
            .access_token(creds, private_key_pem, BOARD_SCOPE)
            .await?;
        let boards: BoardsResponse = self
            .get_json(self.endpoints.boards.clone(), &token, "boards")
            .await?;
        let mut lower_bound: HashMap<String, DateTime<Utc>> = HashMap::new();
        for board in boards
            .boards
            .unwrap_or_default()
            .into_iter()
            .take(BOARD_ACTIVITY_MAX_BOARDS)
        {
            let url = format!(
                "{}/{}/posts?count=40",
                self.endpoints.boards, board.board_id
            );
            let posts: PostsResponse = self.get_json(url, &token, "board posts").await?;
            // 期間の絞り込みは API に無いので、最初のページから since 以降 (作成日時が読めるもの) を拾う
            let recent = posts.posts.unwrap_or_default().into_iter().filter_map(|p| {
                let created = DateTime::parse_from_rfc3339(&p.created_time)
                    .ok()?
                    .with_timezone(&Utc);
                (created >= since).then_some((p.post_id, created))
            });
            for (post_id, created) in recent.take(BOARD_ACTIVITY_MAX_POSTS_PER_BOARD) {
                let url = format!(
                    "{}/{}/posts/{post_id}/readers",
                    self.endpoints.boards, board.board_id
                );
                let readers: ReadersResponse = self.get_json(url, &token, "board readers").await?;
                for r in readers.readers.unwrap_or_default() {
                    if r.is_read {
                        let cur = lower_bound.entry(r.user_id).or_insert(created);
                        *cur = (*cur).max(created);
                    }
                }
            }
        }
        Ok(lower_bound)
    }
}

/// 組織のメンバー (rust の `alc-notify::clients::lineworks::LineworksMember` と同じ JSON)
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LineworksMember {
    pub user_id: String,
    pub user_name: Option<String>,
    pub email: Option<String>,
}

#[derive(Deserialize)]
struct UsersResponse {
    users: Option<Vec<UserEntry>>,
    #[serde(rename = "responseMetaData")]
    response_meta_data: Option<ResponseMetaData>,
}

#[derive(Deserialize)]
struct UserEntry {
    #[serde(rename = "userId")]
    user_id: String,
    #[serde(rename = "userName")]
    user_name: Option<UserName>,
    email: Option<String>,
}

#[derive(Deserialize)]
struct UserName {
    #[serde(rename = "lastName")]
    last_name: Option<String>,
    #[serde(rename = "firstName")]
    first_name: Option<String>,
}

#[derive(Deserialize)]
struct ResponseMetaData {
    #[serde(rename = "nextCursor")]
    next_cursor: Option<String>,
}

/// 表示名は「姓 名」(前後の空白は落とす。`userName` が無ければ `None`。rust と同じ)
fn member(u: UserEntry) -> LineworksMember {
    LineworksMember {
        user_id: u.user_id,
        user_name: u.user_name.map(|n| {
            format!(
                "{} {}",
                n.last_name.unwrap_or_default(),
                n.first_name.unwrap_or_default()
            )
            .trim()
            .to_owned()
        }),
        email: u.email,
    }
}

#[derive(Deserialize)]
struct BoardsResponse {
    boards: Option<Vec<BoardEntry>>,
}

#[derive(Deserialize)]
struct BoardEntry {
    #[serde(rename = "boardId", deserialize_with = "id_string")]
    board_id: String,
}

#[derive(Deserialize)]
struct PostsResponse {
    posts: Option<Vec<PostEntry>>,
}

#[derive(Deserialize)]
struct PostEntry {
    #[serde(rename = "postId", deserialize_with = "id_string")]
    post_id: String,
    #[serde(rename = "createdTime")]
    created_time: String,
}

#[derive(Deserialize)]
struct ReadersResponse {
    readers: Option<Vec<ReaderEntry>>,
}

#[derive(Deserialize)]
struct ReaderEntry {
    #[serde(rename = "userId", deserialize_with = "id_string")]
    user_id: String,
    #[serde(rename = "isRead")]
    is_read: bool,
}

/// 掲示板の API の id は 64bit の JSON の数で来る (rust の `deserialize_id_as_string`。文字列も受ける)
fn id_string<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Id {
        Str(String),
        Num(u64),
    }
    Ok(match Id::deserialize(d)? {
        Id::Str(s) => s,
        Id::Num(n) => n.to_string(),
    })
}

/// 監査ログの API の `YYYY-MM-DDThh:mm:ssTZD`
pub fn format_audit_time(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%:z").to_string()
}

/// CSV の bytes を文字列に (UTF-8 の BOM を落とす。UTF-8 でなければ Shift_JIS として読む。rust の `decode_csv_bytes`)
pub fn decode_csv_bytes(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.trim_start_matches('\u{feff}').to_owned(),
        Err(_) => encoding_rs::SHIFT_JIS.decode(bytes).0.into_owned(),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::jwt::tests::pkcs8_pem;
    use std::sync::Mutex as StdMutex;

    /// 偽の HTTP: 受けた要求を記録し、URL の頭で応答を決める (無ければ届かない)。GET は `gets` の上から順に見る
    #[derive(Default)]
    pub(crate) struct FakeHttp {
        pub(crate) routes: Vec<(String, u16, Vec<u8>)>,
        pub(crate) seen: StdMutex<Vec<HttpRequest>>,
        /// (URL の頭, status, 本文, Location)
        pub(crate) gets: Vec<(String, u16, Vec<u8>, Option<String>)>,
        /// 受けた GET の (URL, Authorization)
        pub(crate) seen_gets: StdMutex<Vec<(String, String)>>,
    }

    impl FakeHttp {
        pub(crate) fn with(routes: &[(&str, u16, &str)]) -> Self {
            Self {
                routes: routes
                    .iter()
                    .map(|(u, s, b)| ((*u).to_owned(), *s, b.as_bytes().to_vec()))
                    .collect(),
                ..Default::default()
            }
        }

        pub(crate) fn on_get(
            mut self,
            url: &str,
            status: u16,
            body: &[u8],
            location: Option<&str>,
        ) -> Self {
            self.gets.push((
                url.to_owned(),
                status,
                body.to_vec(),
                location.map(str::to_owned),
            ));
            self
        }

        pub(crate) fn get_urls(&self) -> Vec<String> {
            self.seen_gets
                .lock()
                .unwrap()
                .iter()
                .map(|(u, _)| u.clone())
                .collect()
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
                Ok(HttpResponse {
                    status,
                    body,
                    location: None,
                })
            })
        }

        fn get(
            &self,
            url: String,
            authorization: String,
        ) -> BoxFuture<'_, Result<HttpResponse, HttpError>> {
            Box::pin(async move {
                let hit = self
                    .gets
                    .iter()
                    .find(|(u, _, _, _)| url.starts_with(u))
                    .cloned();
                self.seen_gets.lock().unwrap().push((url, authorization));
                let (_, status, body, location) = hit.ok_or(HttpError)?;
                Ok(HttpResponse {
                    status,
                    body,
                    location,
                })
            })
        }
    }

    pub(crate) fn endpoints() -> Endpoints {
        Endpoints {
            token: "https://lw.test/token".into(),
            bots: "https://lw.test/bots/".into(),
            users: "https://lw.test/users".into(),
            audit_download: "https://lw.test/audit".into(),
            boards: "https://lw.test/boards".into(),
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
            (
                e.users.as_str(),
                e.audit_download.as_str(),
                e.boards.as_str()
            ),
            (
                "https://www.worksapis.com/v1.0/users",
                "https://www.worksapis.com/v1.0/audits/logs/download",
                "https://www.worksapis.com/v1.0/boards"
            )
        );
        assert_eq!(
            message_url(&e, "b1", &Destination::Channel("ch-1".into())),
            "https://www.worksapis.com/v1.0/bots/b1/channels/ch-1/messages"
        );
        assert_eq!(
            message_url(&e, "b1", &Destination::User("u@x".into())),
            "https://www.worksapis.com/v1.0/bots/b1/users/u@x/messages"
        );
        let body: serde_json::Value =
            serde_json::from_slice(&message_body(Content::Text("予約 \"1\""))).unwrap();
        assert_eq!(
            body,
            serde_json::json!({"content": {"type": "text", "text": "予約 \"1\""}})
        );
        let body: serde_json::Value = serde_json::from_slice(&message_body(Content::Image {
            original_url: "https://img.test/a.png",
            preview_url: "https://img.test/a_s.png",
        }))
        .unwrap();
        assert_eq!(
            body,
            serde_json::json!({"content": {
                "type": "image",
                "originalContentUrl": "https://img.test/a.png",
                "previewImageUrl": "https://img.test/a_s.png",
            }})
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
        c.send(
            &creds(),
            &pem,
            &Destination::Channel("ch-1".into()),
            Content::Text("hi"),
        )
        .await
        .unwrap();
        c.send(
            &creds(),
            &pem,
            &Destination::User("u1".into()),
            Content::Text("yo"),
        )
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
        at(0)
            .send(&creds(), &pem, &dest, Content::Text("a"))
            .await
            .unwrap();
        // 期限 120 − 余裕 60 = 60 秒より前は使い回す
        at(59)
            .send(&creds(), &pem, &dest, Content::Text("a"))
            .await
            .unwrap();
        tokens(1);
        at(60)
            .send(&creds(), &pem, &dest, Content::Text("a"))
            .await
            .unwrap();
        tokens(2);
        let mut other = creds();
        other.service_account = "sa2@example".into();
        at(61)
            .send(&other, &pem, &dest, Content::Text("a"))
            .await
            .unwrap();
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
            .send(
                &creds(),
                &pem,
                &Destination::Channel("c".into()),
                Content::Text("x"),
            )
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

    const NOW: u64 = 1_800_000_000;

    fn token_http() -> FakeHttp {
        FakeHttp::with(&[("https://lw.test/token", 200, TOKEN_OK)])
    }

    fn at<'a>(http: &'a FakeHttp, e: &'a Endpoints, cache: &'a TokenCache) -> Client<'a> {
        Client {
            http,
            endpoints: e,
            cache,
            now: NOW,
        }
    }

    fn scopes(http: &FakeHttp) -> Vec<String> {
        http.seen
            .lock()
            .unwrap()
            .iter()
            .map(|r| form(r).into_iter().find(|(k, _)| k == "scope").unwrap().1)
            .collect()
    }

    /// users: cursor (URL に入れるときは符号化する) で全ページ。表示名は「姓 名」、userName が無ければ null
    #[tokio::test]
    async fn lists_users_across_pages() {
        let http = token_http()
            .on_get(
                "https://lw.test/users?cursor=A%2Bb%3D%2Fc",
                200,
                r#"{"users":[{"userId":"u3","email":null},{"userId":"u4","userName":{"firstName":"花子"}}],"responseMetaData":{}}"#.as_bytes(),
                None,
            )
            .on_get(
                "https://lw.test/users",
                200,
                r#"{"users":[{"userId":"u1","userName":{"lastName":"田中","firstName":"太郎"},"email":"t@x.com"},{"userId":"u2","userName":{}}],"responseMetaData":{"nextCursor":"A+b=/c"}}"#.as_bytes(),
                None,
            );
        let (e, cache) = (endpoints(), TokenCache::default());
        let pem = pkcs8_pem();
        let got = at(&http, &e, &cache)
            .list_org_users(&creds(), &pem)
            .await
            .unwrap();
        let m = |id: &str, name: Option<&str>, email: Option<&str>| LineworksMember {
            user_id: id.into(),
            user_name: name.map(Into::into),
            email: email.map(Into::into),
        };
        assert_eq!(
            got,
            [
                m("u1", Some("田中 太郎"), Some("t@x.com")),
                m("u2", Some(""), None),
                m("u3", None, None),
                m("u4", Some("花子"), None),
            ]
        );
        assert_eq!(
            *http.seen_gets.lock().unwrap(),
            [
                (
                    "https://lw.test/users".to_owned(),
                    "Bearer tok-1".to_owned()
                ),
                (
                    "https://lw.test/users?cursor=A%2Bb%3D%2Fc".to_owned(),
                    "Bearer tok-1".to_owned()
                ),
            ]
        );
        assert_eq!(scopes(&http), ["directory.read"]);
        assert_eq!(
            serde_json::to_value(&got[2]).unwrap(),
            serde_json::json!({"user_id": "u3", "user_name": null, "email": null})
        );
        // 最後のページ (users も responseMetaData も無い)
        let http = token_http().on_get("https://lw.test/users", 200, b"{}", None);
        let got = at(&http, &e, &TokenCache::default())
            .list_org_users(&creds(), &pem)
            .await
            .unwrap();
        assert!(got.is_empty());
    }

    /// 監査ログ: 302 を 2 回辿り、どの要求にも Authorization を付け直す。期間と service は URL に符号化して入れる。
    /// UTF-8 の BOM は落とす。scope は audit.read
    #[tokio::test]
    async fn audit_csv_follows_redirects_with_auth() {
        let start = DateTime::parse_from_rfc3339("2026-08-12T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let end = DateTime::parse_from_rfc3339("2026-09-11T09:30:15Z")
            .unwrap()
            .with_timezone(&Utc);
        let url = "https://lw.test/audit?service=auth&startTime=2026-08-12T00%3A00%3A00%2B00%3A00&endTime=2026-09-11T09%3A30%3A15%2B00%3A00&language=ja_JP";
        let mut csv = vec![0xEF, 0xBB, 0xBF];
        csv.extend_from_slice("メンバー,日時\na@x.com,2026/09/01 09:00:00\n".as_bytes());
        let http = token_http()
            .on_get("https://dl.test/final", 200, &csv, None)
            .on_get(
                "https://dl.test/hop1",
                302,
                b"",
                Some("https://dl.test/final"),
            )
            .on_get(url, 302, b"", Some("https://dl.test/hop1"));
        let (e, cache) = (endpoints(), TokenCache::default());
        let got = at(&http, &e, &cache)
            .fetch_audit_csv(&creds(), &pkcs8_pem(), "auth", start, end)
            .await
            .unwrap();
        assert_eq!(got, "メンバー,日時\na@x.com,2026/09/01 09:00:00\n");
        let seen = http.seen_gets.lock().unwrap().clone();
        assert_eq!(
            seen.iter().map(|(u, _)| u.as_str()).collect::<Vec<_>>(),
            [url, "https://dl.test/hop1", "https://dl.test/final"]
        );
        assert!(seen.iter().all(|(_, a)| a == "Bearer tok-1"));
        assert_eq!(scopes(&http), ["audit.read"]);
    }

    #[test]
    fn csv_bytes_and_times() {
        let (sjis, _, bad) = encoding_rs::SHIFT_JIS.encode("名前,結果\n田中,成功\n");
        assert!(!bad);
        assert_eq!(decode_csv_bytes(&sjis), "名前,結果\n田中,成功\n");
        assert_eq!(decode_csv_bytes(b"a,b\n"), "a,b\n");
        let t = DateTime::parse_from_rfc3339("2026-09-01T00:00:00+09:00")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(format_audit_time(t), "2026-08-31T15:00:00+00:00");
    }

    /// GET の失敗: Location が無い・https でない・辿りすぎ → redirect、2xx・3xx 以外 → status と code、届かない → transport
    #[tokio::test]
    async fn get_failures() {
        let e = endpoints();
        let cases: Vec<(FakeHttp, SendError, usize)> = vec![
            (
                FakeHttp::default().on_get("https://x.test/a", 302, b"", None),
                SendError::Redirect("audit"),
                1,
            ),
            (
                FakeHttp::default().on_get("https://x.test/a", 301, b"", Some("http://x.test/b")),
                SendError::Redirect("audit"),
                1,
            ),
            (
                FakeHttp::default().on_get("https://x.test/a", 307, b"", Some("https://x.test/a")),
                SendError::Redirect("audit"),
                MAX_REDIRECT_HOPS,
            ),
            (
                FakeHttp::default()
                    .on_get(
                        "https://dl.test/",
                        401,
                        br#"{"code":"UNAUTHORIZED","description":"Authentication failed."}"#,
                        None,
                    )
                    .on_get("https://x.test/a", 302, b"", Some("https://dl.test/csv")),
                SendError::ReadStatus("audit", 401, Some("UNAUTHORIZED".into())),
                2,
            ),
            (
                FakeHttp::default().on_get("https://x.test/a", 403, b"forbidden", None),
                SendError::ReadStatus("audit", 403, None),
                1,
            ),
            (FakeHttp::default(), SendError::Transport("audit"), 1),
        ];
        for (http, want, n) in cases {
            let cache = TokenCache::default();
            let got = at(&http, &e, &cache)
                .get("https://x.test/a".into(), "tok", "audit")
                .await;
            assert_eq!(got, Err(want));
            assert_eq!(http.get_urls().len(), n);
        }
        let http = FakeHttp::default().on_get("https://x.test/a", 200, b"nope", None);
        let cache = TokenCache::default();
        let got: Result<BoardsResponse, _> = at(&http, &e, &cache)
            .get_json("https://x.test/a".into(), "tok", "boards")
            .await;
        assert!(matches!(got, Err(SendError::ReadParse("boards"))));
        // token の失敗は GET の前に止まる
        let http = FakeHttp::with(&[("https://lw.test/token", 403, r#"{"error":"forbidden"}"#)]);
        let got = at(&http, &e, &cache)
            .list_org_users(&creds(), &pkcs8_pem())
            .await;
        assert_eq!(
            got,
            Err(SendError::TokenStatus(403, Some("forbidden".into())))
        );
        let got = at(&http, &e, &cache)
            .fetch_audit_csv(
                &creds(),
                &pkcs8_pem(),
                "auth",
                DateTime::<Utc>::default(),
                DateTime::<Utc>::default(),
            )
            .await;
        assert!(matches!(got, Err(SendError::TokenStatus(403, _))));
        let got = at(&http, &e, &cache)
            .fetch_board_activity_lower_bound(&creds(), &pkcs8_pem(), DateTime::<Utc>::default())
            .await;
        assert!(matches!(got, Err(SendError::TokenStatus(403, _))));
        assert!(http.get_urls().is_empty());
    }

    #[test]
    fn read_error_text() {
        let cases = [
            (
                SendError::ReadStatus("users", 403, Some("FORBIDDEN".into())),
                "Read users failed: HTTP 403 (FORBIDDEN)",
            ),
            (SendError::ReadParse("boards"), "Read boards failed: parse"),
            (SendError::Redirect("audit"), "Read audit failed: redirect"),
        ];
        for (e, want) in cases {
            assert_eq!(e.to_string(), want);
        }
        assert!(!SendError::TokenParse.is_forbidden());
        assert!(!SendError::SendStatus(500, Some("x".into())).is_forbidden());
    }

    /// 掲示板: 最初の 5 つの掲示板・掲示板ごとに since 以降の投稿 10 件まで・既読 (isRead) の人だけ。
    /// id は数でも文字列でも受ける。同じ人は新しい投稿の作成日時が残る。scope は board.read
    #[tokio::test]
    async fn board_lower_bound() {
        let now = DateTime::from_timestamp(NOW as i64, 0).unwrap();
        let since = now - chrono::Duration::days(30);
        let day = |d: i64| (now - chrono::Duration::days(d)).to_rfc3339();
        let mut posts: Vec<serde_json::Value> = (1..=11u64)
            .map(|i| serde_json::json!({"postId": 1_000_000_000_000_000_000u64 + i, "createdTime": day(5)}))
            .collect();
        posts.insert(
            0,
            serde_json::json!({"postId": 9, "createdTime": "not-a-time"}),
        );
        posts.insert(
            1,
            serde_json::json!({"postId": 8, "createdTime": "2020-01-01T00:00:00+09:00"}),
        );
        let posts = serde_json::json!({ "posts": posts }).to_string();
        let newer =
            serde_json::json!({"posts": [{"postId": "p1", "createdTime": day(1)}]}).to_string();
        let older =
            serde_json::json!({"posts": [{"postId": "p2", "createdTime": day(20)}]}).to_string();
        let boards = r#"{"boards":[{"boardId":4000000000000000001},{"boardId":"b8"},{"boardId":"b9"},{"boardId":"b10"},{"boardId":"b11"},{"boardId":"b12"}]}"#;
        let http = token_http()
            .on_get(
                "https://lw.test/boards/4000000000000000001/posts/",
                200,
                br#"{"readers":[{"userId":"u1","isRead":true},{"userId":"u2","isRead":false},{"userId":3,"isRead":true}]}"#,
                None,
            )
            .on_get("https://lw.test/boards/4000000000000000001/posts?", 200, posts.as_bytes(), None)
            .on_get("https://lw.test/boards/b8/posts/", 200, br#"{"readers":[{"userId":"u1","isRead":true}]}"#, None)
            .on_get("https://lw.test/boards/b8/posts?", 200, newer.as_bytes(), None)
            .on_get("https://lw.test/boards/b9/posts/", 200, br#"{"readers":[{"userId":"u1","isRead":true}]}"#, None)
            .on_get("https://lw.test/boards/b9/posts?", 200, older.as_bytes(), None)
            .on_get("https://lw.test/boards/b10/posts/p", 200, b"{}", None)
            .on_get("https://lw.test/boards/b10/posts?", 200, newer.as_bytes(), None)
            .on_get("https://lw.test/boards/b11/", 200, b"{}", None)
            .on_get("https://lw.test/boards", 200, boards.as_bytes(), None);
        let (e, cache) = (endpoints(), TokenCache::default());
        let got = at(&http, &e, &cache)
            .fetch_board_activity_lower_bound(&creds(), &pkcs8_pem(), since)
            .await
            .unwrap();
        let want: HashMap<String, DateTime<Utc>> = [
            ("u1".to_owned(), now - chrono::Duration::days(1)),
            ("3".to_owned(), now - chrono::Duration::days(5)),
        ]
        .into();
        assert_eq!(got, want);
        let urls = http.get_urls();
        assert_eq!(
            urls.iter()
                .filter(|u| u.starts_with("https://lw.test/boards/4000000000000000001/posts/"))
                .count(),
            BOARD_ACTIVITY_MAX_POSTS_PER_BOARD
        );
        assert!(urls.contains(
            &"https://lw.test/boards/4000000000000000001/posts/1000000000000000001/readers"
                .to_owned()
        ));
        assert!(
            urls.contains(&"https://lw.test/boards/4000000000000000001/posts?count=40".to_owned())
        );
        // 6 つ目の掲示板は見ない
        assert!(!urls.iter().any(|u| u.contains("/b12/")));
        assert!(!urls
            .iter()
            .any(|u| u.contains("/posts/8/") || u.contains("/posts/9/")));
        assert_eq!(scopes(&http), ["board.read"]);

        // 掲示板が無い・掲示板の一覧の失敗
        let http = token_http().on_get("https://lw.test/boards", 200, b"{}", None);
        let got = at(&http, &e, &TokenCache::default())
            .fetch_board_activity_lower_bound(&creds(), &pkcs8_pem(), since)
            .await
            .unwrap();
        assert!(got.is_empty());
        let http = token_http().on_get("https://lw.test/boards", 403, b"forbidden", None);
        let got = at(&http, &e, &TokenCache::default())
            .fetch_board_activity_lower_bound(&creds(), &pkcs8_pem(), since)
            .await;
        assert_eq!(got, Err(SendError::ReadStatus("boards", 403, None)));
    }
}
