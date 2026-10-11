//! 本番デプロイの確認の口 `GET /api/lineworks/deploy-check` (Refs ippoan/rust-alc-api#747)。
//!
//! 本番に出したあと、親 (Claude) が auth-worker の verify_eval (GET だけ通る) で 1 回叩くと、新しい版の送信経路で
//! 固定文が LINE WORKS へ 1 通届く (画面のテスト送信の代わり)。
//! - 版は worker の `CF_VERSION_METADATA` の id (と tag)。同じ版でもう送っていれば送らない。「送った」の記録は
//!   [`SentRecord`] 越し (worker は Cache API の `caches.default` に版の id を鍵にした 1 件。colo ごとの記録なので、
//!   別の colo から叩けば 2 通目が出得る)
//! - 送り先は env の 3 つ (`DEPLOY_CHECK_TENANT_ID`・`DEPLOY_CHECK_BOT_ID` = bot_configs の bot_id・
//!   `DEPLOY_CHECK_USER_ID` = LINE WORKS の user_id)。値は repo に無い (`wrangler secret put`)。tenant のヘッダーは見ない
//!   (呼び手が誰でも送り先は変わらない)。どれかが無い → 送らずに `not_configured` (staging は入れない)
//! - 送信は送信の口と同じ処理 (bot の設定 → 復号 → JWT → access token → 送信)
//! - 応答: `{"version", "tag", "sent", "reason"}`。reason は `sent` / `already_sent` / `not_configured` / `send_failed`。
//!   送信の失敗は 502 で、本文に識別子・エラー文を入れない (ログも固定の語)

use std::sync::Arc;

use alc_core_wasm::api_error::{not_found, ApiError};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use futures_util::future::BoxFuture;
use uuid::Uuid;

use crate::client::Content;
use crate::pg;
use crate::routes::{destination, SendState, To};

pub const DEPLOY_CHECK_PATH: &str = "/api/lineworks/deploy-check";

/// 「この版でもう送った」の記録 (worker は Cache API、テストは偽物)。読めない・書けないは「送っていない」扱い
pub trait SentRecord: Send + Sync {
    fn sent(&self, version: String) -> BoxFuture<'_, bool>;
    fn record(&self, version: String) -> BoxFuture<'_, ()>;
}

/// 送り先 (env の 3 つ)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeployTarget {
    pub tenant_id: Uuid,
    pub bot_id: String,
    pub user_id: String,
}

impl DeployTarget {
    /// env の 3 つの値から。どれかが無い・空・tenant が UUID でない → `None` (= `not_configured`)
    pub fn from_values(
        tenant_id: Option<String>,
        bot_id: Option<String>,
        user_id: Option<String>,
    ) -> Option<Self> {
        let nonempty = |v: Option<String>| v.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty());
        Some(Self {
            tenant_id: nonempty(tenant_id)?.parse().ok()?,
            bot_id: nonempty(bot_id)?,
            user_id: nonempty(user_id)?,
        })
    }
}

/// 口の材料 (worker がリクエストごとに組み立てる)
#[derive(Clone)]
pub struct DeployCheck {
    /// `CF_VERSION_METADATA` の id (取れなければ空 = `not_configured`)
    pub version: String,
    /// deploy の `--tag` (無ければ空)
    pub tag: String,
    pub target: Option<DeployTarget>,
    pub record: Arc<dyn SentRecord>,
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

pub(crate) async fn deploy_check(
    State(state): State<SendState>,
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
    let Some(target) = d.target.clone().filter(|_| !d.version.is_empty()) else {
        return reply(StatusCode::OK, false, "not_configured");
    };
    if d.record.sent(d.version.clone()).await {
        return reply(StatusCode::OK, false, "already_sent");
    }
    let text = message(&label(&d.version, &d.tag));
    if send(&state, target, &text).await.is_err() {
        (state.log)("lineworks-deploy-check: send failed");
        return reply(StatusCode::BAD_GATEWAY, false, "send_failed");
    }
    d.record.record(d.version.clone()).await;
    reply(StatusCode::OK, true, "sent")
}

/// 送信の口と同じ処理 (bot の設定 → 復号 → token → 送信)。失敗の中身は呼び手が捨てる
async fn send(state: &SendState, target: DeployTarget, text: &str) -> Result<(), ApiError> {
    let dest = destination(To::User {
        user_id: target.user_id,
    })?;
    let bot = {
        let mut pg = state.pg.lock().await;
        pg::lineworks_bot_config_by_bot_id(&mut pg, target.tenant_id, target.bot_id)
            .await
            .map_err(|e| state.fail("bot config", &e, "get_bot_config_failed"))?
    }
    .ok_or_else(|| not_found("bot_config_not_found"))?;
    state.deliver(bot, dest, Content::Text(text)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets() {
        let t = Uuid::from_u128(7);
        let s = |v: &str| Some(v.to_owned());
        assert_eq!(
            DeployTarget::from_values(s(&format!(" {t} ")), s("b"), s("u")),
            Some(DeployTarget {
                tenant_id: t,
                bot_id: "b".into(),
                user_id: "u".into()
            })
        );
        for (a, b, c) in [
            (None, s("b"), s("u")),
            (s(&t.to_string()), None, s("u")),
            (s(&t.to_string()), s("b"), None),
            (s(&t.to_string()), s(" "), s("u")),
            (s(&t.to_string()), s("b"), s("")),
            (s("not-a-uuid"), s("b"), s("u")),
        ] {
            assert_eq!(DeployTarget::from_values(a, b, c), None);
        }
    }

    #[test]
    fn labels_and_message() {
        assert_eq!(label("0123456789abcdef", ""), "01234567");
        assert_eq!(label("0123", ""), "0123");
        assert_eq!(label("0123456789abcdef", "v0.1.4"), "v0.1.4");
        assert_eq!(
            message("v0.1.4"),
            "alc-lineworks-worker v0.1.4 を本番に出しました (デプロイ確認)"
        );
    }
}
