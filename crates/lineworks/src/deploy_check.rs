//! 本番デプロイの確認の口 `GET /api/lineworks/deploy-check?to=<LINE WORKS の user_id>[&bot_config_id=]`
//! (Refs ippoan/rust-alc-api#747)。
//!
//! 本番に出したあと、親 (Claude) が auth-worker の verify_eval (GET だけ通る) で 1 回叩くと、新しい版の送信経路で
//! 固定文が **`?to=` の相手の LINE WORKS へ、版ごとに 1 回** 届く (画面のテスト送信の代わり)。
//! - tenant は auth-worker の browser proxy (`/alc-proxy`) が JWT から付け直す `X-Tenant-ID` (呼び手が付けたヘッダーは
//!   proxy が通さない)。無い・UUID でない、または `to` が無い・空 → `no_user`
//! - `to` の形は messages の口と同じ検証 ([`destination`])。崩れていれば `user_not_found`
//! - bot は messages / users の口と同じ選び方 (`bot_config_id` があればその tenant のその行、無ければ tenant の有効な
//!   LINE WORKS の bot のうち名前の順で最初)。無ければ `no_bot`
//! - `to` がその bot の組織のメンバーの一覧 (users の口と同じ。scope `directory.read`) に居なければ送らない (`user_not_found`。
//!   任意の id へ送れる口にしない)
//! - 版は worker の `CF_VERSION_METADATA` の id (と tag)。同じ版・同じ送り先にもう送っていれば送らない (送り先ごとに版 1 回)。
//!   「送った」の記録は [`SentRecord`] 越し (worker は Cache API の `caches.default`。colo ごとの記録なので、別の colo から
//!   叩けば 2 通目が出得る)。版が取れなければ `not_configured`
//! - 送信は送信の口と同じ処理 (bot の設定 → 復号 → JWT → access token → 送信)
//! - 応答: `{"version", "tag", "sent", "reason"}`。reason は `sent` / `already_sent` / `not_configured` / `no_user` /
//!   `no_bot` / `user_not_found` / `send_failed`。送り先が決まらないのは 200、送れない (DB・鍵・LINE WORKS の失敗) は 502。
//!   本文に識別子・エラー文を入れない (`to` も出さない。ログは固定の語と、送信の口と同じ段の語 = HTTP の status と
//!   LINE WORKS のエラーの code まで)

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use futures_util::future::BoxFuture;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::client::{Content, Destination};
use crate::routes::{destination, SendState, To};

pub const DEPLOY_CHECK_PATH: &str = "/api/lineworks/deploy-check";

/// 「この鍵でもう送った」の記録 (worker は Cache API、テストは偽物)。読めない・書けないは「送っていない」扱い。
/// 鍵は [`record_key`] (版・tenant・送り先のハッシュ。URL の path にそのまま入る文字だけ)
pub trait SentRecord: Send + Sync {
    fn sent(&self, key: String) -> BoxFuture<'_, bool>;
    fn record(&self, key: String) -> BoxFuture<'_, ()>;
}

/// 口の材料 (worker がリクエストごとに組み立てる)
#[derive(Clone)]
pub struct DeployCheck {
    /// `CF_VERSION_METADATA` の id (取れなければ空 = `not_configured`)
    pub version: String,
    /// deploy の `--tag` (無ければ空)
    pub tag: String,
    pub record: std::sync::Arc<dyn SentRecord>,
}

#[derive(Debug, Deserialize)]
pub struct DeployCheckQuery {
    /// 送り先の LINE WORKS の user_id
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default)]
    pub bot_config_id: Option<Uuid>,
}

/// 文に入れる版の名前 (tag があれば tag、無ければ版の id の先頭 8 文字)
pub fn label(version: &str, tag: &str) -> String {
    if tag.is_empty() {
        version.chars().take(8).collect()
    } else {
        tag.to_owned()
    }
}

/// 送る固定文
pub fn message(label: &str) -> String {
    format!("alc-lineworks-worker {label} を本番に出しました (デプロイ確認)")
}

/// proxy が付けた `X-Tenant-ID` (無い・UUID でない → `None`)
pub fn tenant_header(headers: &HeaderMap) -> Option<Uuid> {
    headers
        .get("x-tenant-id")?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// 記録の鍵 (送り先ごとに版 1 回)。送り先は SHA-256 の 16 進にして識別子の形のまま置かない
pub fn record_key(version: &str, tenant_id: Uuid, to: &str) -> String {
    let hash: String = Sha256::digest(to.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{version}/{tenant_id}/{hash}")
}

pub(crate) async fn deploy_check(
    State(state): State<SendState>,
    headers: HeaderMap,
    Query(q): Query<DeployCheckQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    let d = &state.deploy;
    let reply = |status: StatusCode, sent: bool, reason: &str| {
        (
            status,
            Json(serde_json::json!({
                "version": d.version,
                "tag": d.tag,
                "sent": sent,
                "reason": reason,
            })),
        )
    };
    if d.version.is_empty() {
        return reply(StatusCode::OK, false, "not_configured");
    }
    let (Some(tenant_id), Some(to)) = (tenant_header(&headers), q.to.filter(|t| !t.is_empty()))
    else {
        return reply(StatusCode::OK, false, "no_user");
    };
    let key = record_key(&d.version, tenant_id, &to);
    let Ok(dest) = destination(To::User { user_id: to }) else {
        return reply(StatusCode::OK, false, "user_not_found");
    };
    if d.record.sent(key.clone()).await {
        return reply(StatusCode::OK, false, "already_sent");
    }
    match send(&state, tenant_id, q.bot_config_id, dest).await {
        Ok(()) => {
            d.record.record(key).await;
            reply(StatusCode::OK, true, "sent")
        }
        Err(Skip::NotSent(reason)) => reply(StatusCode::OK, false, reason),
        Err(Skip::Failed) => {
            (state.log)("lineworks-deploy-check: send failed");
            reply(StatusCode::BAD_GATEWAY, false, "send_failed")
        }
    }
}

/// 送らなかった理由 (送り先が決まらない = 200 の語 / 送れない = 502)
enum Skip {
    NotSent(&'static str),
    Failed,
}

/// bot を選び、送り先がその bot の組織のメンバーに居ることを確かめて、送信の口と同じ処理で送る。
/// 失敗の中身 (ApiError) は捨てる (段のログは各処理が固定の語で出す)
async fn send(
    state: &SendState,
    tenant_id: Uuid,
    bot_config_id: Option<Uuid>,
    dest: Destination,
) -> Result<(), Skip> {
    let bot = state
        .tenant_bot(tenant_id, bot_config_id)
        .await
        .map_err(|(status, _)| {
            if status == StatusCode::NOT_FOUND {
                Skip::NotSent("no_bot")
            } else {
                Skip::Failed
            }
        })?;
    let (creds, private_key) = state.credentials(bot).map_err(|_| Skip::Failed)?;
    let client = state.client();
    let members = client
        .list_org_users(&creds, &private_key)
        .await
        .map_err(|e| {
            (state.log)(&format!("lineworks-read: {e}"));
            Skip::Failed
        })?;
    if !members
        .into_iter()
        .any(|m| dest == Destination::User(m.user_id))
    {
        return Err(Skip::NotSent("user_not_found"));
    }
    let text = message(&label(&state.deploy.version, &state.deploy.tag));
    client
        .send(&creds, &private_key, &dest, Content::Text(&text))
        .await
        .map_err(|e| {
            (state.log)(&format!("lineworks-send: {e}"));
            Skip::Failed
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn tenant_headers() {
        let t = Uuid::from_u128(7);
        let mut h = HeaderMap::new();
        assert_eq!(tenant_header(&h), None);
        h.insert(
            "x-tenant-id",
            HeaderValue::from_str(&format!(" {t} ")).unwrap(),
        );
        assert_eq!(tenant_header(&h), Some(t));
        h.insert("x-tenant-id", HeaderValue::from_static("not-a-uuid"));
        assert_eq!(tenant_header(&h), None);
        h.insert("x-tenant-id", HeaderValue::from_bytes(b"\xff").unwrap());
        assert_eq!(tenant_header(&h), None);
        let q: DeployCheckQuery = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!((q.to, q.bot_config_id), (None, None));
    }

    #[test]
    fn keys_labels_and_message() {
        let key = record_key("v1", Uuid::from_u128(1), "abc");
        assert_eq!(
            key,
            "v1/00000000-0000-0000-0000-000000000001/\
             ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(!key.contains("abc"));
        assert_eq!(label("0123456789abcdef", ""), "01234567");
        assert_eq!(label("0123", ""), "0123");
        assert_eq!(label("0123456789abcdef", "v0.1.4"), "v0.1.4");
        assert_eq!(
            message("v0.1.4"),
            "alc-lineworks-worker v0.1.4 を本番に出しました (デプロイ確認)"
        );
    }
}
