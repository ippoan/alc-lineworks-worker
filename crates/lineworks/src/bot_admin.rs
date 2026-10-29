//! LINE WORKS の Bot 設定の管理の口 (rust-alc-api の `/api/admin/bot/configs` から移した。Refs ippoan/rust-alc-api#680)。
//!
//! 呼ぶのは auth-worker の `/alc-proxy` (nuxt-leave・nuxt-notify の画面) と auth-worker 自身 (管理画面・MCP の
//! `lineworks_get`)。どちらも auth-worker が JWT を検証して `X-Tenant-ID` と `X-User-*` を付け直し、振り分けの表で
//! ここへ流す。契約 (path・body・応答の JSON) は移植元と同じ。
//!
//! | method | path | 応答 |
//! |---|---|---|
//! | GET | `/api/admin/bot/configs` | 200 `{configs:[{id,provider,name,client_id,service_account,bot_id,enabled,created_at,updated_at}]}` (名前の順) |
//! | POST | `/api/admin/bot/configs` | 200 設定の 1 行 (`id` が在れば更新、無ければ作成) / 400 `invalid_body`・`invalid_id` / 404 `bot_config_not_found` / 409 `bot_config_conflict` (同じ provider・bot_id が在る) |
//! | DELETE | `/api/admin/bot/configs` | 204 (body `{id}`。無くても) / 400 `invalid_body`・`invalid_id` |
//! | DELETE | `/api/admin/bot/configs/{id}` | 204 (無くても) / 400 `invalid_id`。nuxt-leave がこの形で呼ぶ (移植元には無く、本番では削除が通っていなかった) |
//! | GET | `/api/admin/bot/configs/export` | 200 `{version:1,exported_at,tenant_id,data:{tenant,bot_configs,…}}` (秘密値は暗号文のまま) / 404 `tenant_not_found` |
//!
//! - tenant は `X-Tenant-ID` (無い・UUID でない → 401)。一覧・保存・削除は **管理者 (`X-User-Role: admin`) だけ** (それ以外・identity が
//!   揃わない → 403 `forbidden`)
//! - export は **開発者だけ**で、開発者の判定 (移植元の `DEVELOPER_EMAILS`) は auth-worker が済ませる。ここは `X-Tenant-ID` の
//!   会社 (= export する会社) だけを見る。auth-worker の振り分けの表は、この path を auth-worker 自身 (admin proxy) からだけ回し、
//!   画面の proxy からは届かない
//! - `client_secret`・`bot_secret` はここで `SSO_ENCRYPTION_KEY` で暗号化して保存する (rust-alc-api と同じ AES-256-GCM。
//!   送信の口が同じ鍵で復号する)。空・省略は「変えない」(作成で client secret が無ければ移植元と同じく空文字の暗号文)。
//!   鍵が無ければ 500 (`message` が `encryption_key_missing`)。DB の失敗は 500 (`message` が `bot_config_failed`)。応答に秘密値は載せない
//! - SQL はすべてその会社の transaction で tenant_id を明示する (移植元は一覧・更新・削除が RLS 任せだった)
//! - export の応答は移植元と同じ形 (`data` の Bot 設定以外の表は空の配列のまま。`exported_at` は秒まで)

use alc_core_wasm::api_error::{bad_request, internal_error_msg, not_found, ApiError};
use alc_core_wasm::{require_tenant_header, AuthUser, TenantId};
use alc_worker_crypto::secret::encrypt_secret;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get};
use axum::{middleware, Extension, Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio_postgres::error::SqlState;
use uuid::Uuid;

use crate::pg::{self, BotAdminInput, BotAdminRow};
use crate::routes::SendState;

pub const BOT_CONFIGS_PATH: &str = "/api/admin/bot/configs";
pub const BOT_CONFIG_PATH: &str = "/api/admin/bot/configs/{id}";
pub const BOT_CONFIGS_EXPORT_PATH: &str = "/api/admin/bot/configs/export";

pub fn bot_admin_router() -> Router<SendState> {
    Router::new()
        .route(
            BOT_CONFIGS_PATH,
            get(list_configs).post(save_config).delete(delete_config),
        )
        .route(BOT_CONFIG_PATH, delete(delete_config_by_path))
        .route(BOT_CONFIGS_EXPORT_PATH, get(export_configs))
        .route_layer(middleware::from_fn(require_tenant_header))
}

#[derive(Debug, Deserialize)]
pub struct SaveBody {
    pub id: Option<String>,
    pub provider: Option<String>,
    pub name: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub service_account: String,
    pub bot_id: String,
    pub enabled: Option<bool>,
    /// LINE WORKS Bot の webhook の署名の検証の鍵 (X-WORKS-Signature の HMAC key)
    pub bot_secret: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeleteBody {
    pub id: String,
}

fn forbidden() -> ApiError {
    (StatusCode::FORBIDDEN, Json(json!({ "error": "forbidden" })))
}

/// 管理者だけ (`X-User-*` が揃い role が admin)
pub fn require_admin(user: Option<&AuthUser>) -> Result<(), ApiError> {
    match user {
        Some(u) if u.role == "admin" => Ok(()),
        _ => Err(forbidden()),
    }
}

fn invalid_body() -> ApiError {
    bad_request("invalid_body", "body の形が違います")
}

pub fn parse_id(s: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(s).map_err(|_| bad_request("invalid_id", "id が UUID ではありません"))
}

/// 空でない秘密値だけを暗号化する (`None`・空は `None` = 変えない)
fn encrypt_if_given(value: Option<&str>, key: &str) -> Result<Option<String>, ApiError> {
    match value.filter(|s| !s.is_empty()) {
        Some(v) => encrypt_secret(v, key)
            .map(Some)
            .map_err(|_| internal_error_msg("encrypt_failed")),
        None => Ok(None),
    }
}

impl SendState {
    fn admin_db_error(&self, stage: &str, e: &tokio_postgres::Error) -> ApiError {
        (self.log)(&format!(
            "bot-admin: {stage} failed: db ({})",
            alc_worker_db::kind(e)
        ));
        internal_error_msg("bot_config_failed")
    }
}

async fn list_configs(
    State(state): State<SendState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    user: Option<Extension<AuthUser>>,
) -> Result<Json<Value>, ApiError> {
    require_admin(user.as_deref())?;
    let rows = pg::bot_admin_list(&mut *state.pg.lock().await, tenant_id)
        .await
        .map_err(|e| state.admin_db_error("list", &e))?;
    Ok(Json(json!({ "configs": rows })))
}

async fn save_config(
    State(state): State<SendState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    user: Option<Extension<AuthUser>>,
    body: Result<Json<SaveBody>, JsonRejection>,
) -> Result<Json<BotAdminRow>, ApiError> {
    require_admin(user.as_deref())?;
    let Json(b) = body.map_err(|_| invalid_body())?;
    let id = b.id.as_deref().map(parse_id).transpose()?;
    let Some(key) = state.sso_key.as_deref() else {
        (state.log)("bot-admin: SSO_ENCRYPTION_KEY not set");
        return Err(internal_error_msg("encryption_key_missing"));
    };
    let mut client_secret_encrypted = encrypt_if_given(b.client_secret.as_deref(), key)?;
    if id.is_none() && client_secret_encrypted.is_none() {
        // 作成の client secret は NOT NULL。移植元と同じく空文字を暗号化して入れる
        client_secret_encrypted =
            Some(encrypt_secret("", key).map_err(|_| internal_error_msg("encrypt_failed"))?);
    }
    let input = BotAdminInput {
        id,
        provider: b.provider.unwrap_or_else(|| "lineworks".to_owned()),
        name: b.name,
        client_id: b.client_id,
        service_account: b.service_account,
        bot_id: b.bot_id,
        enabled: b.enabled.unwrap_or(true),
        client_secret_encrypted,
        bot_secret_encrypted: encrypt_if_given(b.bot_secret.as_deref(), key)?,
    };
    match pg::bot_admin_save(&mut *state.pg.lock().await, tenant_id, input).await {
        Ok(Some(row)) => Ok(Json(row)),
        Ok(None) => Err(not_found("bot_config_not_found")),
        // (provider, bot_id) は会社をまたいで一意 (alc-migrations の 049)。移植元は 500 だった
        Err(e) if e.code() == Some(&SqlState::UNIQUE_VIOLATION) => Err((
            StatusCode::CONFLICT,
            Json(json!({ "error": "bot_config_conflict" })),
        )),
        Err(e) => Err(state.admin_db_error("save", &e)),
    }
}

async fn delete_config(
    State(state): State<SendState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    user: Option<Extension<AuthUser>>,
    body: Result<Json<DeleteBody>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    require_admin(user.as_deref())?;
    let Json(b) = body.map_err(|_| invalid_body())?;
    delete_one(&state, tenant_id, parse_id(&b.id)?).await
}

async fn delete_config_by_path(
    State(state): State<SendState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
    user: Option<Extension<AuthUser>>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_admin(user.as_deref())?;
    delete_one(&state, tenant_id, parse_id(&id)?).await
}

/// その会社の Bot 設定を消す (無くても 204)
async fn delete_one(state: &SendState, tenant_id: Uuid, id: Uuid) -> Result<StatusCode, ApiError> {
    pg::bot_admin_delete(&mut *state.pg.lock().await, tenant_id, id)
        .await
        .map_err(|e| state.admin_db_error("delete", &e))?;
    Ok(StatusCode::NO_CONTENT)
}

/// 開発者向けの export (移植元 `alc-misc::bot_admin::export_configs` と同じ形)。開発者の判定は auth-worker
async fn export_configs(
    State(state): State<SendState>,
    Extension(TenantId(tenant_id)): Extension<TenantId>,
) -> Result<Json<Value>, ApiError> {
    let export = pg::bot_admin_export(&mut *state.pg.lock().await, tenant_id)
        .await
        .map_err(|e| state.admin_db_error("export", &e))?;
    let Some(export) = export else {
        return Err(not_found("tenant_not_found"));
    };
    let exported_at = crate::activity::to_datetime((state.now)()).to_rfc3339();
    Ok(Json(json!({
        "version": 1,
        "exported_at": exported_at,
        "tenant_id": tenant_id.to_string(),
        "data": {
            "tenant": export.tenant,
            "users": [],
            "employees": [],
            "devices": [],
            "tenko_schedules": [],
            "webhook_configs": [],
            "tenant_allowed_emails": [],
            "sso_provider_configs": [],
            "tenko_call_numbers": [],
            "tenko_call_drivers": [],
            "bot_configs": export.configs,
            "notify_line_configs": [],
            "notify_recipients": []
        }
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(role: &str) -> AuthUser {
        AuthUser {
            user_id: Uuid::nil(),
            email: String::new(),
            name: String::new(),
            tenant_id: Uuid::nil(),
            role: role.to_owned(),
            tenant_slug: None,
        }
    }

    #[test]
    fn only_admin_passes() {
        assert!(require_admin(Some(&user("admin"))).is_ok());
        for u in [Some(user("viewer")), Some(user("payroll")), None] {
            let (status, Json(body)) = require_admin(u.as_ref()).unwrap_err();
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(body, json!({ "error": "forbidden" }));
        }
    }

    #[test]
    fn ids_must_be_uuids() {
        assert!(parse_id(&Uuid::new_v4().to_string()).is_ok());
        let (status, Json(body)) = parse_id("x").unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_id");
    }

    #[test]
    fn empty_secret_is_not_encrypted() {
        assert_eq!(encrypt_if_given(None, "k").unwrap(), None);
        assert_eq!(encrypt_if_given(Some(""), "k").unwrap(), None);
        let enc = encrypt_if_given(Some("s"), "k").unwrap().unwrap();
        assert_eq!(
            alc_worker_crypto::secret::decrypt_secret(&enc, "k").unwrap(),
            "s"
        );
    }
}
