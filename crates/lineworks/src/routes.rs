//! 口は 3 つ。どれも認証は持たない (入口は auth-worker からの Service Binding だけ。wrangler.toml と scripts/check-exposure.sh)。
//!
//! ## `POST /api/internal/lineworks/send` (rust-alc-api の `alc-notify::lineworks_channels::send_text_internal` と同じ契約)
//!
//! - body: `{"channel_id": "<lineworks_channels.id>"}` か `{"recipient_id": "<notify_recipients.id>"}` のどちらか一方と `"text"`
//!   (キー無しと `null` は同じ「未指定」)。読めない body は axum の `Json` の既定の拒否 (rust と同じ)
//! - 応答: 成功は 200 `{"ok":true}`。失敗の status・`error`・`message` の語は rust と同じ
//!   (下の表は README)。502 の `message` だけは、上流の応答の本文を載せず、status と LINE WORKS のエラーの code まで
//! - tenant のヘッダーは見ない (tenant は宛先の行から引く。rust と同じ)
//!
//! ## `POST /api/internal/lineworks/token`
//!
//! auth-worker が LINE WORKS の API を自分で叩くための access token を出す (リッチメニューと MCP の `lineworks_get`。
//! Client Secret と Private Key を auth-worker へ渡さないため)。
//! - tenant は auth-worker が付ける `X-Tenant-ID` (無い・UUID でない → 401。`alc_core_wasm::require_tenant_header`)
//! - body: `{"bot_config_id": "<bot_configs.id>", "scope": "<scope>"}`。scope は [`ALLOWED_SCOPES`] だけ (ほかは 400 `scope_not_allowed`)
//! - その tenant の bot_configs の行だけを読む (別 tenant の id は 404 `bot_config_not_found`)
//! - 応答: 200 `{"access_token": "...", "expires_at": <UNIX 秒>, "bot_id": "..."}`。**Client Secret と Private Key は応答に入れない**
//!
//! ## `POST /api/internal/lineworks/messages` (Refs ippoan/rust-alc-api#747)
//!
//! notify / trouble の worker が、tenant を指定して LINE WORKS の id へ直接送る (Service Binding 専用。auth-worker の
//! alc-internal-proxy には出さない)。
//! - tenant は `X-Tenant-ID` (token の口と同じ layer。無い・UUID でない → 401)
//! - body: `{"bot_config_id": "<bot_configs.id>"?, "to": {"user_id": "…"} | {"channel_id": "…"},
//!   "content": {"type": "text", "text": "…"} | {"type": "image", "original_url": "https://…", "preview_url": "https://…"}}`。
//!   `to` の id は LINE WORKS 側の id (lineworks_channels の行 id ではない)。読めない body は axum の `Json` の既定の拒否
//! - bot: `bot_config_id` があればその tenant のその行 (provider・enabled は見ない。送信の口の channel 宛と同じ)、
//!   無ければ tenant の有効な LINE WORKS の bot のうち名前の順で最初 (rust の trouble・notify の `resolve_lineworks_config` と同じ)。
//!   どちらも無ければ 404 `bot_config_not_found` (別 tenant の id も RLS と `WHERE tenant_id` で見えず 404)
//! - 応答: 成功は 204 (本文なし)。失敗の語は送信の口と同じ (502 の `message` は status と LINE WORKS のエラーの code まで)
//!
//! ログに出すのは固定の語・段の名前・DB のエラーの kind・HTTP の status まで (行 id・本文・token・secret を出さない)。

use std::sync::Arc;

use alc_core_wasm::api_error::{bad_request, internal_error_msg, not_found, ApiError};
use alc_core_wasm::{require_tenant_header, TenantId};
use alc_worker_db::{kind, PgClient};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{middleware, Extension, Json, Router};
use futures_util::lock::Mutex;
use serde::Deserialize;
use uuid::Uuid;

use crate::client::{
    Client, Content, Credentials, Destination, Endpoints, Http, SendError, TokenCache,
    ALLOWED_SCOPES,
};
use crate::pg::{self, BotConfigRow, RecipientRow};
use crate::secret::decrypt_secret;

pub const SEND_PATH: &str = "/api/internal/lineworks/send";
pub const TOKEN_PATH: &str = "/api/internal/lineworks/token";
pub const MESSAGES_PATH: &str = "/api/internal/lineworks/messages";

pub type LogSink = Arc<dyn Fn(&str) + Send + Sync>;
pub type Now = Arc<dyn Fn() -> u64 + Send + Sync>;

#[derive(Clone)]
pub struct SendState {
    pub pg: Arc<Mutex<PgClient>>,
    pub http: Arc<dyn Http>,
    pub endpoints: Arc<Endpoints>,
    pub cache: Arc<TokenCache>,
    /// 今の UNIX 秒
    pub now: Now,
    /// `SSO_ENCRYPTION_KEY` (Secrets Store)。取れなければ `None`
    pub sso_key: Option<Arc<str>>,
    /// `LINEWORKS_PRIVATE_KEY` (Secrets Store、PEM)。取れなければ `None`
    pub private_key: Option<Arc<str>>,
    pub log: LogSink,
}

/// 送信の口は tenant のヘッダーを見ない。token の口と messages の口にだけ tenant の layer を掛ける
pub fn router() -> Router<SendState> {
    let tenant = Router::new()
        .route(TOKEN_PATH, post(issue_token))
        .route(MESSAGES_PATH, post(send_message))
        .route_layer(middleware::from_fn(require_tenant_header));
    Router::new()
        .route(SEND_PATH, post(send_text))
        .merge(tenant)
}

#[derive(Debug, Deserialize)]
pub struct SendBody {
    #[serde(default)]
    pub channel_id: Option<Uuid>,
    #[serde(default)]
    pub recipient_id: Option<Uuid>,
    pub text: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Target {
    Channel(Uuid),
    Recipient(Uuid),
}

/// 宛先の 2 択 (rust の `resolve_send_target` と同じ語)
pub fn resolve_target(
    channel_id: Option<Uuid>,
    recipient_id: Option<Uuid>,
) -> Result<Target, ApiError> {
    match (channel_id, recipient_id) {
        (Some(c), None) => Ok(Target::Channel(c)),
        (None, Some(r)) => Ok(Target::Recipient(r)),
        (Some(_), Some(_)) => Err(bad_request(
            "target_ambiguous",
            "specify exactly one of channel_id / recipient_id",
        )),
        (None, None) => Err(bad_request(
            "target_required",
            "channel_id or recipient_id is required",
        )),
    }
}

#[derive(Debug, Deserialize)]
pub struct TokenBody {
    pub bot_config_id: Uuid,
    pub scope: String,
}

#[derive(Debug, Deserialize)]
pub struct MessagesBody {
    #[serde(default)]
    pub bot_config_id: Option<Uuid>,
    pub to: To,
    pub content: MessageContent,
}

/// 送り先 (LINE WORKS 側の id)。どちらか一方だけ (両方・ほかのキーは読めない body)
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(untagged, deny_unknown_fields)]
pub enum To {
    User { user_id: String },
    Channel { channel_id: String },
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum MessageContent {
    Text {
        text: String,
    },
    Image {
        original_url: String,
        preview_url: String,
    },
}

/// LINE WORKS の id は URL の path にそのまま入れるので、空と path を崩す文字 (`/ ? # %`・空白・制御文字) を断る
pub fn destination(to: To) -> Result<Destination, ApiError> {
    let (id, dest): (String, fn(String) -> Destination) = match to {
        To::User { user_id } => (user_id, Destination::User),
        To::Channel { channel_id } => (channel_id, Destination::Channel),
    };
    let bad = |c: char| matches!(c, '/' | '?' | '#' | '%') || c.is_whitespace() || c.is_control();
    if id.is_empty() || id.chars().any(bad) {
        return Err(bad_request("target_invalid", "to has an invalid id"));
    }
    Ok(dest(id))
}

/// 中身の検証 (text は空白だけを断る。画像の URL は https だけ)
pub fn content(c: &MessageContent) -> Result<Content<'_>, ApiError> {
    match c {
        MessageContent::Text { text } => {
            check_text(text)?;
            Ok(Content::Text(text))
        }
        MessageContent::Image {
            original_url,
            preview_url,
        } => {
            let https = |u: &str| u.len() > "https://".len() && u.starts_with("https://");
            if !(https(original_url) && https(preview_url)) {
                return Err(bad_request(
                    "image_url_invalid",
                    "original_url and preview_url must be https URLs",
                ));
            }
            Ok(Content::Image {
                original_url,
                preview_url,
            })
        }
    }
}

/// token の口の scope の許可リスト
pub fn check_scope(scope: &str) -> Result<(), ApiError> {
    if ALLOWED_SCOPES.contains(&scope) {
        Ok(())
    } else {
        Err(bad_request(
            "scope_not_allowed",
            "scope must be one of bot / board.read / directory.read",
        ))
    }
}

/// 空白だけの本文は送らない (rust と同じ本文)
pub fn check_text(text: &str) -> Result<(), ApiError> {
    if text.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "text_required", "message": "text is empty"})),
        ));
    }
    Ok(())
}

/// recipient 行が LINE WORKS の個人宛として使えるか (rust の `validate_lineworks_recipient` と同じ語と順)
pub fn lineworks_user_id(row: &RecipientRow) -> Result<&str, ApiError> {
    if row.provider != "lineworks" {
        return Err(bad_request(
            "recipient_not_lineworks",
            &format!("recipient provider is {}", row.provider),
        ));
    }
    let user_id = row.lineworks_user_id.as_deref().ok_or_else(|| {
        bad_request(
            "recipient_not_lineworks",
            "recipient has no lineworks_user_id",
        )
    })?;
    if !row.enabled {
        return Err(bad_request("recipient_disabled", "recipient is disabled"));
    }
    Ok(user_id)
}

/// 上流の失敗の応答 (502。rust の `upstream_error` と同じ形で、`message` は [`SendError`] の文)。
/// Private Key が読めないのは上流ではないので 500 `private_key_invalid`
pub fn send_error_response(e: &SendError) -> ApiError {
    match e {
        SendError::PrivateKey => internal_error_msg("private_key_invalid"),
        _ => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": "upstream_error", "message": e.to_string()})),
        ),
    }
}

impl SendState {
    fn fail(&self, stage: &str, e: &tokio_postgres::Error, msg: &str) -> ApiError {
        (self.log)(&format!("lineworks-send: {stage} failed: db ({})", kind(e)));
        internal_error_msg(msg)
    }

    /// bot の設定を復号して送れる形にする (rust の `resolve_bot_config`。鍵の有無はここで見る)
    fn credentials(&self, row: BotConfigRow) -> Result<(Credentials, Arc<str>), ApiError> {
        let Some(sso_key) = self.sso_key.as_deref() else {
            (self.log)("lineworks-send: SSO_ENCRYPTION_KEY not set");
            return Err(internal_error_msg("encryption_key_missing"));
        };
        let client_secret = decrypt_secret(&row.client_secret_encrypted, sso_key).map_err(|e| {
            (self.log)(&format!("lineworks-send: decrypt client_secret: {e}"));
            internal_error_msg("decrypt_failed")
        })?;
        let Some(private_key) = self.private_key.clone() else {
            (self.log)("lineworks-send: LINEWORKS_PRIVATE_KEY not set");
            return Err(internal_error_msg("private_key_missing"));
        };
        Ok((
            Credentials {
                client_id: row.client_id,
                client_secret,
                service_account: row.service_account,
                bot_id: row.bot_id,
            },
            private_key,
        ))
    }

    fn client(&self) -> Client<'_> {
        Client {
            http: self.http.as_ref(),
            endpoints: &self.endpoints,
            cache: &self.cache,
            now: (self.now)(),
        }
    }

    fn upstream(&self, e: SendError) -> ApiError {
        (self.log)(&format!("lineworks-send: {e}"));
        send_error_response(&e)
    }

    async fn deliver(
        &self,
        row: BotConfigRow,
        dest: Destination,
        content: Content<'_>,
    ) -> Result<(), ApiError> {
        let (creds, private_key) = self.credentials(row)?;
        self.client()
            .send(&creds, &private_key, &dest, content)
            .await
            .map_err(|e| self.upstream(e))
    }
}

async fn send_text(
    State(state): State<SendState>,
    Json(body): Json<SendBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_text(&body.text)?;
    let target = resolve_target(body.channel_id, body.recipient_id)?;
    let (bot, dest) = {
        let mut pg = state.pg.lock().await;
        match target {
            Target::Channel(id) => {
                let row = pg::channel_for_send(&mut pg, id)
                    .await
                    .map_err(|e| state.fail("lookup channel", &e, "get_failed"))?
                    .ok_or_else(|| not_found("channel_not_found"))?;
                let bot = pg::bot_config_by_id(&mut pg, row.tenant_id, row.bot_config_id)
                    .await
                    .map_err(|e| state.fail("bot config", &e, "get_bot_config_failed"))?;
                (bot, Destination::Channel(row.channel_id))
            }
            Target::Recipient(id) => {
                let row = pg::recipient_for_send(&mut pg, id)
                    .await
                    .map_err(|e| state.fail("lookup recipient", &e, "get_failed"))?
                    .ok_or_else(|| not_found("recipient_not_found"))?;
                let user_id = lineworks_user_id(&row)?.to_owned();
                let bot = pg::bot_config_for_tenant(&mut pg, row.tenant_id)
                    .await
                    .map_err(|e| state.fail("bot config", &e, "list_bot_configs_failed"))?;
                (bot, Destination::User(user_id))
            }
        }
    };
    let bot = bot.ok_or_else(|| internal_error_msg("bot_config_not_found"))?;
    state.deliver(bot, dest, Content::Text(&body.text)).await?;
    Ok(Json(serde_json::json!({"ok": true})))
}

async fn send_message(
    State(state): State<SendState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Json(body): Json<MessagesBody>,
) -> Result<StatusCode, ApiError> {
    let content = content(&body.content)?;
    let dest = destination(body.to)?;
    let bot = {
        let mut pg = state.pg.lock().await;
        match body.bot_config_id {
            Some(id) => pg::bot_config_by_id(&mut pg, tenant_id, id)
                .await
                .map_err(|e| state.fail("bot config", &e, "get_bot_config_failed"))?,
            None => pg::bot_config_for_tenant(&mut pg, tenant_id)
                .await
                .map_err(|e| state.fail("bot config", &e, "list_bot_configs_failed"))?,
        }
    }
    .ok_or_else(|| not_found("bot_config_not_found"))?;
    state.deliver(bot, dest, content).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn issue_token(
    State(state): State<SendState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    Json(body): Json<TokenBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_scope(&body.scope)?;
    let row = {
        let mut pg = state.pg.lock().await;
        pg::bot_config_by_id(&mut pg, tenant_id, body.bot_config_id)
            .await
            .map_err(|e| state.fail("bot config", &e, "get_bot_config_failed"))?
    }
    .ok_or_else(|| not_found("bot_config_not_found"))?;
    let (creds, private_key) = state.credentials(row)?;
    let (access_token, expires_at) = state
        .client()
        .access_token(&creds, &private_key, &body.scope)
        .await
        .map_err(|e| state.upstream(e))?;
    // 応答に載せるのはこの 3 つだけ (Client Secret・Private Key・Client ID・Service Account は載せない)
    Ok(Json(serde_json::json!({
        "access_token": access_token,
        "expires_at": expires_at,
        "bot_id": creds.bot_id,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(r: ApiError) -> (u16, serde_json::Value) {
        (r.0.as_u16(), r.1 .0)
    }

    #[test]
    fn targets() {
        let (c, r) = (Uuid::from_u128(1), Uuid::from_u128(2));
        assert_eq!(resolve_target(Some(c), None).unwrap(), Target::Channel(c));
        assert_eq!(resolve_target(None, Some(r)).unwrap(), Target::Recipient(r));
        assert_eq!(
            err(resolve_target(Some(c), Some(r)).unwrap_err()),
            (
                400,
                serde_json::json!({"error": "target_ambiguous", "message": "specify exactly one of channel_id / recipient_id"})
            )
        );
        assert_eq!(
            err(resolve_target(None, None).unwrap_err()),
            (
                400,
                serde_json::json!({"error": "target_required", "message": "channel_id or recipient_id is required"})
            )
        );
    }

    #[test]
    fn body_null_is_unspecified() {
        let id = Uuid::from_u128(3);
        let b: SendBody = serde_json::from_value(
            serde_json::json!({"channel_id": null, "recipient_id": id, "text": "hi"}),
        )
        .unwrap();
        assert_eq!(
            resolve_target(b.channel_id, b.recipient_id).unwrap(),
            Target::Recipient(id)
        );
        let b: SendBody =
            serde_json::from_value(serde_json::json!({"channel_id": id, "text": "hi"})).unwrap();
        assert_eq!(
            resolve_target(b.channel_id, b.recipient_id).unwrap(),
            Target::Channel(id)
        );
    }

    #[test]
    fn text() {
        assert!(check_text("x").is_ok());
        for t in ["", "  \n\t"] {
            assert_eq!(
                err(check_text(t).unwrap_err()),
                (
                    400,
                    serde_json::json!({"error": "text_required", "message": "text is empty"})
                )
            );
        }
    }

    fn recipient() -> RecipientRow {
        RecipientRow {
            tenant_id: Uuid::from_u128(9),
            provider: "lineworks".into(),
            lineworks_user_id: Some("lw-user-1".into()),
            enabled: true,
        }
    }

    #[test]
    fn recipients() {
        assert_eq!(lineworks_user_id(&recipient()).unwrap(), "lw-user-1");
        let mut r = recipient();
        r.provider = "line".into();
        assert_eq!(
            err(lineworks_user_id(&r).unwrap_err()),
            (
                400,
                serde_json::json!({"error": "recipient_not_lineworks", "message": "recipient provider is line"})
            )
        );
        let mut r = recipient();
        r.lineworks_user_id = None;
        assert_eq!(
            err(lineworks_user_id(&r).unwrap_err()),
            (
                400,
                serde_json::json!({"error": "recipient_not_lineworks", "message": "recipient has no lineworks_user_id"})
            )
        );
        let mut r = recipient();
        r.enabled = false;
        assert_eq!(
            err(lineworks_user_id(&r).unwrap_err()),
            (
                400,
                serde_json::json!({"error": "recipient_disabled", "message": "recipient is disabled"})
            )
        );
    }

    #[test]
    fn destinations() {
        let user = |s: &str| To::User { user_id: s.into() };
        let channel = |s: &str| To::Channel {
            channel_id: s.into(),
        };
        assert_eq!(
            destination(user("u@example")).unwrap(),
            Destination::User("u@example".into())
        );
        assert_eq!(
            destination(channel("ch-1")).unwrap(),
            Destination::Channel("ch-1".into())
        );
        for bad in ["", "a/b", "a?b", "a#b", "a%2F", "a b", "a\u{1}"] {
            for to in [user(bad), channel(bad)] {
                assert_eq!(
                    err(destination(to).unwrap_err()),
                    (
                        400,
                        serde_json::json!({"error": "target_invalid", "message": "to has an invalid id"})
                    )
                );
            }
        }
    }

    #[test]
    fn contents() {
        let text = MessageContent::Text { text: "hi".into() };
        assert_eq!(content(&text).unwrap(), Content::Text("hi"));
        let blank = MessageContent::Text { text: " ".into() };
        assert_eq!(
            err(content(&blank).unwrap_err()),
            (
                400,
                serde_json::json!({"error": "text_required", "message": "text is empty"})
            )
        );
        let image = |o: &str, p: &str| MessageContent::Image {
            original_url: o.into(),
            preview_url: p.into(),
        };
        assert_eq!(
            content(&image("https://a/1", "https://a/2")).unwrap(),
            Content::Image {
                original_url: "https://a/1",
                preview_url: "https://a/2"
            }
        );
        for (o, p) in [
            ("http://a/1", "https://a/2"),
            ("https://a/1", "ftp://a/2"),
            ("https://", "https://a/2"),
            ("", ""),
        ] {
            assert_eq!(
                err(content(&image(o, p)).unwrap_err()),
                (
                    400,
                    serde_json::json!({"error": "image_url_invalid", "message": "original_url and preview_url must be https URLs"})
                )
            );
        }
    }

    #[test]
    fn messages_body_shapes() {
        let b: MessagesBody = serde_json::from_value(serde_json::json!({
            "to": {"channel_id": "c"},
            "content": {"type": "image", "original_url": "https://a", "preview_url": "https://b"}
        }))
        .unwrap();
        assert_eq!(b.bot_config_id, None);
        assert_eq!(
            b.to,
            To::Channel {
                channel_id: "c".into()
            }
        );
        for bad in [
            serde_json::json!({"to": {"user_id": "u", "channel_id": "c"}, "content": {"type": "text", "text": "x"}}),
            serde_json::json!({"to": {}, "content": {"type": "text", "text": "x"}}),
            serde_json::json!({"to": {"user_id": "u"}, "content": {"type": "file", "url": "x"}}),
            serde_json::json!({"to": {"user_id": "u"}, "content": {"type": "text", "text": "x", "extra": 1}}),
        ] {
            assert!(serde_json::from_value::<MessagesBody>(bad).is_err());
        }
    }

    #[test]
    fn scopes() {
        for s in ["bot", "board.read", "directory.read"] {
            assert!(check_scope(s).is_ok());
        }
        for s in ["", "BOT", "bot board.read", "user.read", "bot "] {
            assert_eq!(
                err(check_scope(s).unwrap_err()),
                (
                    400,
                    serde_json::json!({"error": "scope_not_allowed", "message": "scope must be one of bot / board.read / directory.read"})
                )
            );
        }
    }

    #[test]
    fn send_errors() {
        assert_eq!(
            err(send_error_response(&SendError::PrivateKey)),
            (
                500,
                serde_json::json!({"error": "internal_error", "message": "private_key_invalid"})
            )
        );
        assert_eq!(
            err(send_error_response(&SendError::SendStatus(500, None))),
            (
                502,
                serde_json::json!({"error": "upstream_error", "message": "Send failed: HTTP 500"})
            )
        );
    }
}
