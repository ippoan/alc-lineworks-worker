//! LINE WORKS へのテキスト送信と、auth-worker 向けの access token の Worker `alc-lineworks` (Refs ohishi-exp/rust-leave-worker#1)。crates/lineworks の口
//! (`router`、axum) を workers-rs (`http` / `axum` feature) に載せる。型は ohishi-exp/rust-leave-worker・ippoan/alc-dtako-worker と同じ。
//! DB への経路 (staging = Workers VPC の先の PgBouncer、本番 = Hyperdrive) は [`db::connect`] の 1 か所で出し分ける。
//!
//! **この Worker は呼び手を認証しない。** 本番・staging とも workers.dev を開けず (`workers_dev` / `preview_urls` = false、
//! `routes` を持たない)、入口は auth-worker からの Service Binding だけ (wrangler.toml と scripts/check-exposure.sh が保証する)。
//!
//! 秘密値は Secrets Store から、6 つの口へのリクエストでだけ引く: `SSO_ENCRYPTION_KEY` (client_secret の復号) と
//! `LINEWORKS_PRIVATE_KEY` (JWT の署名。全 bot で共有する 1 本)。LINE WORKS の access token は isolate の中で使い回す。
//!
//! デプロイの確認の口 (`GET /api/lineworks/deploy-check`) の送り先は、auth-worker の browser proxy が付ける
//! `X-Tenant-ID`・`X-User-Email` の本人 (secret は増やさない)。「この版でもう送った」の記録は Cache API の
//! `caches.default` ([`deploy::CacheRecord`])。

// worker 本体は wasm32 専用。native の `cargo build` / `clippy` / `test` (workspace の root で打つもの) では空の crate にして、
// crates/lineworks だけを検査させる
#![cfg(target_arch = "wasm32")]

mod db;
mod deploy;
mod http;
mod tcp;

use std::sync::{Arc, OnceLock};

use axum::body::Body;
use axum::http::{HeaderValue, Response, StatusCode};
use futures_util::lock::Mutex;
use lineworks::activity::ActivityCache;
use lineworks::client::{Endpoints, TokenCache};
use lineworks::{
    router, DeployCheck, LogSink, SendState, DEPLOY_CHECK_PATH, LOGIN_ACTIVITY_PATH, MESSAGES_PATH,
    SEND_PATH, TOKEN_PATH, USERS_PATH,
};
use tower_service::Service;
use worker::{
    console_error, event, Context, Date, Env, HttpRequest, Result, WorkerVersionMetadata,
};

use crate::http::WorkerHttp;

/// client_secret の復号の鍵 (Secrets Store。auth-worker と同じ secret)
const SSO_ENCRYPTION_KEY_BINDING: &str = "SSO_ENCRYPTION_KEY";
/// LINE WORKS の App の Private Key (Secrets Store。正本は GCP Secret Manager の同名の secret)
const LINEWORKS_PRIVATE_KEY_BINDING: &str = "LINEWORKS_PRIVATE_KEY";

/// isolate の中の access token の置き場 (リクエストをまたいで使い回す)
fn token_cache() -> Arc<TokenCache> {
    static CACHE: OnceLock<Arc<TokenCache>> = OnceLock::new();
    CACHE.get_or_init(Arc::default).clone()
}

/// isolate の中のログイン状況の合成の置き場 (監査ログの API を同じ isolate の中で並行に呼ばない・5 分使い回す)
fn activity_cache() -> Arc<ActivityCache> {
    static CACHE: OnceLock<Arc<ActivityCache>> = OnceLock::new();
    CACHE.get_or_init(Arc::default).clone()
}

/// 秘密値を引く口 (ほかの path では Secrets Store を読まない)
const SECRET_PATHS: [&str; 6] = [
    SEND_PATH,
    DEPLOY_CHECK_PATH,
    TOKEN_PATH,
    MESSAGES_PATH,
    USERS_PATH,
    LOGIN_ACTIVITY_PATH,
];

/// 今の UNIX 秒 (JS の Date)
fn now_secs() -> u64 {
    Date::now().as_millis() / 1000
}

/// Secrets Store の値。取れなければ `None` (口が固定の語の 500 にする)
async fn secret(env: &Env, binding: &str) -> Option<Arc<str>> {
    let store = env.secret_store(binding).ok()?;
    match store.get().await {
        Ok(Some(v)) => Some(Arc::from(v)),
        _ => {
            console_error!("lineworks: no {binding} value");
            None
        }
    }
}

fn log_sink() -> LogSink {
    Arc::new(|message| console_error!("{message}"))
}

fn error_response(status: StatusCode, code: &str) -> Response<Body> {
    let mut resp = Response::new(Body::from(format!(r#"{{"error":"{code}"}}"#)));
    *resp.status_mut() = status;
    resp
}

#[event(fetch)]
async fn fetch(req: HttpRequest, env: Env, _ctx: Context) -> Result<Response<Body>> {
    // 全リクエストで routing の前に繋ぐ (ippoan/alc-vein-worker と同じ)
    let pg = match db::connect(&env).await {
        Ok(c) => c,
        Err(db::ConnectError::NotConfigured) => {
            console_error!("lineworks: {}", db::ConnectError::NotConfigured);
            return Ok(error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "database_not_configured",
            ));
        }
        Err(e) => {
            console_error!("lineworks: {e}");
            return Ok(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
            ));
        }
    };
    let path = req.uri().path();
    let (sso_key, private_key) = if SECRET_PATHS.contains(&path) {
        (
            secret(&env, SSO_ENCRYPTION_KEY_BINDING).await,
            secret(&env, LINEWORKS_PRIVATE_KEY_BINDING).await,
        )
    } else {
        (None, None)
    };
    // 版の (id, tag)。binding が取れなければ両方空
    let version = env
        .get_binding::<WorkerVersionMetadata>("CF_VERSION_METADATA")
        .map(|meta| (meta.id(), meta.tag()))
        .unwrap_or_default();
    let state = SendState {
        pg: Arc::new(Mutex::new(pg)),
        http: Arc::new(WorkerHttp),
        endpoints: Arc::new(Endpoints::default()),
        cache: token_cache(),
        activity: activity_cache(),
        now: Arc::new(now_secs),
        sso_key,
        private_key,
        log: log_sink(),
        deploy: DeployCheck {
            version: version.0.clone(),
            tag: version.1.clone(),
            record: Arc::new(deploy::CacheRecord),
        },
    };
    let mut resp = match router().with_state(state).call(req).await {
        Ok(r) => r,
        Err(e) => match e {},
    };
    // どの版が応えたかを応答ヘッダーで分かるようにする。binding が取れなければ何も付けない
    let (id, tag) = version;
    for (name, value) in [("x-worker-version", id), ("x-worker-tag", tag)] {
        if value.is_empty() {
            continue;
        }
        if let Ok(v) = HeaderValue::from_str(&value) {
            resp.headers_mut().insert(name, v);
        }
    }
    Ok(resp)
}
