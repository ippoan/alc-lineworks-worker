//! 本番デプロイの確認の口 `GET /api/lineworks/deploy-check[?bot_config_id=]` (Refs ippoan/rust-alc-api#747)。
//!
//! 本番に出したあと、親 (Claude) が auth-worker の verify_eval (GET だけ通る) で 1 回叩くと、新しい版の送信経路で
//! 固定文が**叩いた人 (ログイン中のユーザー本人) の LINE WORKS** へ 1 通届く (画面のテスト送信の代わり)。
//! - 呼び手は auth-worker の browser proxy (`/alc-proxy`)。proxy が JWT から付け直す `X-Tenant-ID` と `X-User-Email` を使う
//!   (呼び手が付けたヘッダーは proxy が通さない)。無い・tenant が UUID でない → `no_user`
//! - bot は messages / users の口と同じ選び方 (`bot_config_id` があればその tenant のその行、無ければ tenant の有効な
//!   LINE WORKS の bot のうち名前の順で最初)。無ければ `no_bot`
//! - 送り先の LINE WORKS の user_id は、その bot で組織のメンバーの一覧 (users の口と同じ。scope `directory.read`) を取り、
//!   メール (大文字小文字は区別しない) が一致する人。居なければ `user_not_found`
//! - 版は worker の `CF_VERSION_METADATA` の id (と tag)。同じ版・同じ人にもう送っていれば送らない (人ごとに版 1 回)。
//!   「送った」の記録は [`SentRecord`] 越し (worker は Cache API の `caches.default`。colo ごとの記録なので、別の colo から
//!   叩けば 2 通目が出得る)。版が取れなければ `not_configured`
//! - 送信は送信の口と同じ処理 (bot の設定 → 復号 → JWT → access token → 送信)
//! - 応答: `{"version", "tag", "sent", "reason"}`。reason は `sent` / `already_sent` / `not_configured` / `no_user` /
//!   `no_bot` / `user_not_found` / `send_failed`。送り先が決まらないのは 200、送れない (DB・鍵・LINE WORKS の失敗) は 502。
//!   本文に識別子・エラー文を入れない (ログは固定の語と、送信の口と同じ段の語 = HTTP の status と LINE WORKS のエラーの code まで)

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use futures_util::future::BoxFuture;
use uuid::Uuid;

use crate::client::Content;
use crate::routes::{destination, SendState, To, UsersQuery};

pub const DEPLOY_CHECK_PATH: &str = "/api/lineworks/deploy-check";

/// 「この鍵でもう送った」の記録 (worker は Cache API、テストは偽物)。読めない・書けないは「送っていない」扱い。
/// 鍵は [`record_key`] (版・tenant・メールの 16 進。URL の path にそのまま入る文字だけ)
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

/// 呼び手 (proxy が付けた `X-Tenant-ID` と `X-User-Email`)。どちらかが無い・空・tenant が UUID でない → `None`
pub fn caller(headers: &HeaderMap) -> Option<(Uuid, String)> {
    let get = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
    };
    let tenant = get("x-tenant-id")?.parse().ok()?;
    Some((tenant, get("x-user-email")?.to_lowercase()))
}

/// 記録の鍵 (人ごとに版 1 回)。メールは 16 進にして識別子の形のまま置かない・URL を崩さない
pub fn record_key(version: &str, tenant_id: Uuid, email: &str) -> String {
    let hex: String = email.bytes().map(|b| format!("{b:02x}")).collect();
    format!("{version}/{tenant_id}/{hex}")
}

pub(crate) async fn deploy_check(
    State(state): State<SendState>,
    headers: HeaderMap,
    Query(q): Query<UsersQuery>,
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
    let Some((tenant_id, email)) = caller(&headers) else {
        return reply(StatusCode::OK, false, "no_user");
    };
    let key = record_key(&d.version, tenant_id, &email);
    if d.record.sent(key.clone()).await {
        return reply(StatusCode::OK, false, "already_sent");
    }
    match send(&state, tenant_id, q.bot_config_id, &email).await {
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

/// bot を選び、その bot で組織のメンバーからメールの一致する人を引いて、送信の口と同じ処理で送る。
/// 失敗の中身 (ApiError) は捨てる (段のログは各処理が固定の語で出す)
async fn send(
    state: &SendState,
    tenant_id: Uuid,
    bot_config_id: Option<Uuid>,
    email: &str,
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
    let user_id = members
        .into_iter()
        .find(|m| {
            m.email
                .as_deref()
                .is_some_and(|e| e.eq_ignore_ascii_case(email))
        })
        .map(|m| m.user_id)
        .ok_or(Skip::NotSent("user_not_found"))?;
    let dest = destination(To::User { user_id }).map_err(|_| Skip::NotSent("user_not_found"))?;
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
    fn callers() {
        let t = Uuid::from_u128(7);
        let headers = |pairs: &[(&'static str, &str)]| {
            let mut h = HeaderMap::new();
            for (k, v) in pairs {
                h.insert(*k, HeaderValue::from_str(v).unwrap());
            }
            h
        };
        assert_eq!(
            caller(&headers(&[
                ("x-tenant-id", &format!(" {t} ")),
                ("x-user-email", " Me@Example.COM ")
            ])),
            Some((t, "me@example.com".into()))
        );
        let ts = t.to_string();
        for pairs in [
            vec![("x-user-email", "me@example.com")],
            vec![("x-tenant-id", ts.as_str())],
            vec![("x-tenant-id", ts.as_str()), ("x-user-email", " ")],
            vec![
                ("x-tenant-id", "not-a-uuid"),
                ("x-user-email", "me@example.com"),
            ],
        ] {
            assert_eq!(caller(&headers(&pairs)), None);
        }
        let mut h = headers(&[("x-tenant-id", &ts)]);
        h.insert("x-user-email", HeaderValue::from_bytes(b"\xff").unwrap());
        assert_eq!(caller(&h), None);
    }

    #[test]
    fn keys_labels_and_message() {
        assert_eq!(
            record_key("v1", Uuid::from_u128(1), "a@B"),
            "v1/00000000-0000-0000-0000-000000000001/614042"
        );
        assert_eq!(label("0123456789abcdef", ""), "01234567");
        assert_eq!(label("0123", ""), "0123");
        assert_eq!(label("0123456789abcdef", "v0.1.4"), "v0.1.4");
        assert_eq!(
            message("v0.1.4"),
            "alc-lineworks-worker v0.1.4 を本番に出しました (デプロイ確認)"
        );
    }
}
