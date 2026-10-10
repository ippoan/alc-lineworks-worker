//! 実 DB のテストの準備・接続・偽物 (ohishi-exp/rust-leave-worker の tests/support の型)。
//!
//! - **`LINEWORKS_TEST_ADMIN_DATABASE_URL` が未設定なら失敗する** (skip して緑にしない)。値は準備用の superuser の
//!   接続文字列で、**使い捨ての DB (database 名 `postgres`) に向けること** (ロール・schema・全 migration を作る)。表示はしない
//! - 準備の SQL は ippoan/alc-migrations から版を固定して取る (`scripts/ALC_MIGRATIONS_REV`、
//!   `bash scripts/fetch-migrations.sh` が repo 直下の `.alc-migrations/` に取り出す)。流す順は init_local_db.sql →
//!   空の `_sqlx_migrations` → migrations (1 ファイル 1 transaction) → local_app_grants.sql (alc-vein-worker の container/start.sh と同じ)
//! - 本体のテストは、本番の worker と同じ実行用ロール `alc_api_rt` (migration 158。表の所有者ではない・`NOSUPERUSER`・
//!   `NOBYPASSRLS`) で繋ぐ ([`rt_client`] が毎回確かめる)。パスワードは使い捨ての DB 専用の固定の文字列で、秘密ではない
//! - migration を流すのは superuser なので、SECURITY DEFINER の関数の所有者も superuser (RLS を素通りする)。
//!   所有者が RLS の掛かるロールのときの見え方は send_db.rs の `lookup_owner_condition` が別に確かめる

#![allow(dead_code)]

use std::sync::{Arc, Mutex as StdMutex};

use alc_worker_db::PgClient;
use axum::body::Body;
use axum::http::Request;
use axum::Router;
use futures_util::future::BoxFuture;
use futures_util::lock::Mutex;
use lineworks::activity::ActivityCache;
use lineworks::client::{Endpoints, Http, HttpError, HttpRequest, HttpResponse, TokenCache};
use lineworks::secret::encrypt_secret_with_nonce;
use lineworks::{
    router, SendState, LOGIN_ACTIVITY_PATH, MESSAGES_PATH, SEND_PATH, TOKEN_PATH, USERS_PATH,
};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::RsaPrivateKey;
use tokio::sync::OnceCell;
use tokio_postgres::{Client, Config, NoTls};
use tower::ServiceExt;
use uuid::Uuid;

pub const ADMIN_URL_ENV: &str = "LINEWORKS_TEST_ADMIN_DATABASE_URL";
pub const RT_ROLE: &str = "alc_api_rt";
/// bot_configs を読めないロール (DB の失敗の経路を通すため。関数の EXECUTE だけ持つ)
pub const NO_BOT_ROLE: &str = "lw_test_no_bot";
/// 使い捨ての DB 専用 (秘密ではない)
const PASSWORD: &str = "lineworks-test-throwaway";
const SEARCH_PATH: &str = "-c search_path=alc_api,public";
/// 準備を直列にする advisory lock の鍵 (並列に走るテストの binary どうし)
const PREPARE_LOCK: i64 = 1_012_001;

/// テストの暗号化の鍵の材料 (秘密ではない)
pub const SSO_KEY: &str = "lineworks-test-sso-key";
/// テストの「今」(UNIX 秒)
pub const NOW: u64 = 1_800_000_000;

fn migrations_dir() -> std::path::PathBuf {
    let dir = std::path::PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../.alc-migrations"
    ));
    assert!(
        dir.join("migrations").is_dir(),
        ".alc-migrations が無い。先に `bash scripts/fetch-migrations.sh` を流す"
    );
    dir
}

pub fn admin_config() -> Config {
    let url = std::env::var(ADMIN_URL_ENV).unwrap_or_else(|_| {
        panic!("{ADMIN_URL_ENV} が未設定。実 DB のテストは接続先が無ければ失敗させる (skip しない)")
    });
    url.parse()
        .unwrap_or_else(|_| panic!("{ADMIN_URL_ENV} が接続文字列として読めない"))
}

async fn raw_connect(config: &Config) -> Client {
    let (client, connection) = config
        .connect(NoTls)
        .await
        .unwrap_or_else(|_| panic!("{ADMIN_URL_ENV} の DB に繋げない"));
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
}

/// superuser の接続 (準備と、テストの行を作るのだけに使う)
pub async fn admin() -> Client {
    let mut config = admin_config();
    config.options(SEARCH_PATH);
    raw_connect(&config).await
}

/// 準備をプロセスの中で 1 回だけ流す。DB に既に migration 158 の関数が在れば (別の binary が流した) 何もしない
pub async fn prepare() {
    static PREPARED: OnceCell<()> = OnceCell::const_new();
    PREPARED
        .get_or_init(|| async {
            let su = admin().await;
            su.batch_execute(&format!("SELECT pg_advisory_lock({PREPARE_LOCK})"))
                .await
                .unwrap();
            let done = su
                .query_one(
                    "SELECT to_regprocedure('alc_api.lookup_notify_recipient_for_send(uuid)') IS NOT NULL \
                     AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)",
                    &[&NO_BOT_ROLE],
                )
                .await
                .unwrap()
                .get::<_, bool>(0);
            if !done {
                migrate(&su).await;
            }
            su.batch_execute(&format!("SELECT pg_advisory_unlock({PREPARE_LOCK})"))
                .await
                .unwrap();
            eprintln!("[lineworks-db] 実 DB で準備済み (migrations は {})", rev());
        })
        .await;
}

fn rev() -> String {
    std::fs::read_to_string(migrations_dir().join(".rev"))
        .unwrap()
        .trim()
        .to_owned()
}

async fn migrate(su: &Client) {
    let dir = migrations_dir();
    let read = |p: std::path::PathBuf| std::fs::read_to_string(p).unwrap();
    su.batch_execute(&read(dir.join("scripts/init_local_db.sql")))
        .await
        .unwrap();
    su.batch_execute("CREATE TABLE IF NOT EXISTS alc_api._sqlx_migrations (version BIGINT PRIMARY KEY, description TEXT NOT NULL, installed_on TIMESTAMPTZ NOT NULL DEFAULT now(), success BOOLEAN NOT NULL, checksum BYTEA NOT NULL, execution_time BIGINT NOT NULL)")
        .await
        .unwrap();
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(dir.join("migrations"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "sql"))
        .collect();
    files.sort();
    assert!(
        files.iter().any(|f| f
            .file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with("_runtime_role.sql")),
        "取り出した migrations に 158 (alc_api_rt) が無い (scripts/ALC_MIGRATIONS_REV が古い)"
    );
    for file in files {
        let name = file.file_name().unwrap().to_owned();
        if let Err(e) = su
            .batch_execute(&format!("BEGIN;\n{}\n;COMMIT;", read(file)))
            .await
        {
            panic!("migration {name:?}: {:?}", e.code());
        }
    }
    su.batch_execute(&read(dir.join("scripts/local_app_grants.sql")))
        .await
        .unwrap();
    // 実行用ロール (158 が NOLOGIN で作る) と、bot_configs を読めないロール (関数は PUBLIC の EXECUTE で呼べる)
    su.batch_execute(&format!(
        "ALTER ROLE {RT_ROLE} LOGIN PASSWORD '{PASSWORD}';
         CREATE ROLE {NO_BOT_ROLE} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '{PASSWORD}';
         GRANT USAGE ON SCHEMA alc_api TO {NO_BOT_ROLE};"
    ))
    .await
    .unwrap();
}

/// `role` の接続 (worker と同じく `PgClient` に包む)。**superuser / BYPASSRLS / 触る表の所有者なら panic**
pub async fn client_as(role: &str) -> PgClient {
    prepare().await;
    let mut config = admin_config();
    config.user(role).password(PASSWORD);
    let client = raw_connect(&config).await;
    let row = client
        .query_one(
            "SELECT (SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user), \
             (SELECT bool_or(tableowner = current_user) FROM pg_tables WHERE schemaname = 'alc_api' \
              AND tablename IN ('bot_configs', 'lineworks_channels', 'notify_recipients'))",
            &[],
        )
        .await
        .unwrap();
    assert!(!row.get::<_, bool>(0), "RLS を素通りするロールで繋いでいる");
    assert!(!row.get::<_, bool>(1), "表の所有者で繋いでいる");
    PgClient::new(client)
}

pub async fn rt_client() -> PgClient {
    client_as(RT_ROLE).await
}

/// 接続が切れた `alc_api_rt` の接続 (backend を落とした接続)
pub async fn broken_client() -> PgClient {
    let mut pg = rt_client().await;
    let pid: i32 = pg
        .tenant_tx(Uuid::nil(), |tx| {
            Box::pin(async move {
                let row = tx.query_typed_one("SELECT pg_backend_pid()", &[]).await?;
                Ok(row.get::<_, i32>(0))
            })
        })
        .await
        .unwrap();
    let terminated: bool = admin()
        .await
        .query_one("SELECT pg_terminate_backend($1)", &[&pid])
        .await
        .unwrap()
        .get(0);
    assert!(terminated);
    pg
}

/// テストの Private Key (PKCS#8 の PEM。生成は重いので 1 回だけ)
pub fn private_key_pem() -> &'static str {
    static PEM: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PEM.get_or_init(|| {
        RsaPrivateKey::new(&mut rand::thread_rng(), 1024)
            .unwrap()
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .to_string()
    })
}

/// テストの暗号文 (nonce は乱数)
pub fn encrypt(plain: &str) -> String {
    encrypt_secret_with_nonce(plain, SSO_KEY, rand::random())
}

/// tenant を 1 つ作る (superuser で。名前は乱数)
pub async fn tenant() -> Uuid {
    prepare().await;
    let id = Uuid::new_v4();
    admin()
        .await
        .execute(
            "INSERT INTO alc_api.tenants (id, name) VALUES ($1, $2)",
            &[&id, &format!("lineworks-test-{id}")],
        )
        .await
        .unwrap();
    id
}

pub struct Bot {
    pub id: Uuid,
    pub bot_id: String,
    pub client_id: String,
}

/// bot の設定を 1 つ作る。`private_key_encrypted` は鍵ではない文字列 (worker が読まないことを確かめるため)
pub async fn bot(tenant_id: Uuid, name: &str, provider: &str, enabled: bool) -> Bot {
    let bot_id = format!("bot-{}", Uuid::new_v4());
    let client_id = format!("client-{name}");
    let id: Uuid = admin()
        .await
        .query_one(
            "INSERT INTO alc_api.bot_configs (tenant_id, provider, name, client_id, client_secret_encrypted, \
             service_account, private_key_encrypted, bot_id, enabled) \
             VALUES ($1, $2, $3, $4, $5, 'sa@example', 'not-a-key-and-never-read', $6, $7) RETURNING id",
            &[
                &tenant_id,
                &provider,
                &name,
                &client_id,
                &encrypt(&format!("secret-{name}")),
                &bot_id,
                &enabled,
            ],
        )
        .await
        .unwrap()
        .get(0);
    Bot {
        id,
        bot_id,
        client_id,
    }
}

/// tenant の LINE WORKS のチャネルを 1 つ作る。戻り値は (行 id, LINE WORKS の channel id)
pub async fn channel(tenant_id: Uuid, bot_config_id: Uuid, active: bool) -> (Uuid, String) {
    let lw = format!("ch-{}", Uuid::new_v4());
    let id = admin()
        .await
        .query_one(
            "INSERT INTO alc_api.lineworks_channels (tenant_id, bot_config_id, channel_id, active) \
             VALUES ($1, $2, $3, $4) RETURNING id",
            &[&tenant_id, &bot_config_id, &lw, &active],
        )
        .await
        .unwrap()
        .get(0);
    (id, lw)
}

/// 宛先を 1 つ作る。`provider` が `line` なら line_user_id だけ入れる。戻り値は (行 id, LINE WORKS の user id)
pub async fn recipient(tenant_id: Uuid, provider: &str, enabled: bool) -> (Uuid, String) {
    let user = format!("lw-{}", Uuid::new_v4());
    let (lw, line) = if provider == "line" {
        (None, Some(user.clone()))
    } else {
        (Some(user.clone()), None)
    };
    let id = admin()
        .await
        .query_one(
            "INSERT INTO alc_api.notify_recipients (tenant_id, name, provider, lineworks_user_id, line_user_id, enabled) \
             VALUES ($1, 'テスト', $2, $3, $4, $5) RETURNING id",
            &[&tenant_id, &provider, &lw, &line, &enabled],
        )
        .await
        .unwrap()
        .get(0);
    (id, user)
}

/// 偽の LINE WORKS (token の口と送信の口と GET)。受けた要求を記録する
pub struct FakeLineworks {
    pub token_status: u16,
    pub token_body: String,
    pub send_status: u16,
    pub send_body: String,
    /// true なら届かない
    pub unreachable: bool,
    pub seen: StdMutex<Vec<HttpRequest>>,
    /// GET の応答 (URL の頭, status, 本文, Location)。上から順に見て、無ければ届かない
    pub gets: Vec<(String, u16, Vec<u8>, Option<String>)>,
    /// 受けた GET の (URL, Authorization)
    pub seen_gets: StdMutex<Vec<(String, String)>>,
}

impl FakeLineworks {
    pub fn on_get(mut self, url: &str, status: u16, body: &str, location: Option<&str>) -> Self {
        self.gets.push((
            url.to_owned(),
            status,
            body.as_bytes().to_vec(),
            location.map(str::to_owned),
        ));
        self
    }

    pub fn get_urls(&self) -> Vec<String> {
        self.seen_gets
            .lock()
            .unwrap()
            .iter()
            .map(|(u, _)| u.clone())
            .collect()
    }

    /// token を取った scope (順に)
    pub fn token_scopes(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.url == TOKEN_URL)
            .map(|r| {
                String::from_utf8(r.body.clone())
                    .unwrap()
                    .split('&')
                    .find_map(|kv| kv.strip_prefix("scope=").map(str::to_owned))
                    .unwrap()
            })
            .collect()
    }
}

impl Default for FakeLineworks {
    fn default() -> Self {
        Self {
            token_status: 200,
            token_body: r#"{"access_token":"tok-1","refresh_token":"r","expires_in":"86400"}"#
                .into(),
            send_status: 201,
            send_body: String::new(),
            unreachable: false,
            seen: StdMutex::default(),
            gets: Vec::new(),
            seen_gets: StdMutex::default(),
        }
    }
}

pub const TOKEN_URL: &str = "https://lw.test/token";
pub const BOTS_URL: &str = "https://lw.test/bots/";
pub const USERS_URL: &str = "https://lw.test/users";
pub const AUDIT_URL: &str = "https://lw.test/audit";
pub const BOARDS_URL: &str = "https://lw.test/boards";

impl Http for FakeLineworks {
    fn post(&self, req: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, HttpError>> {
        Box::pin(async move {
            let token = req.url == TOKEN_URL;
            self.seen.lock().unwrap().push(req);
            if self.unreachable {
                return Err(HttpError);
            }
            Ok(if token {
                HttpResponse {
                    status: self.token_status,
                    body: self.token_body.clone().into_bytes(),
                    location: None,
                }
            } else {
                HttpResponse {
                    status: self.send_status,
                    body: self.send_body.clone().into_bytes(),
                    location: None,
                }
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
            if self.unreachable {
                return Err(HttpError);
            }
            let (_, status, body, location) = hit.ok_or(HttpError)?;
            Ok(HttpResponse {
                status,
                body,
                location,
            })
        })
    }
}

pub struct App {
    pub router: Router,
    pub http: Arc<FakeLineworks>,
    pub cache: Arc<TokenCache>,
    pub activity: Arc<ActivityCache>,
    pub logs: Arc<StdMutex<Vec<String>>>,
}

pub struct Opts {
    pub sso_key: Option<&'static str>,
    pub private_key: Option<String>,
    pub http: FakeLineworks,
    pub cache: Arc<TokenCache>,
    pub activity: Arc<ActivityCache>,
    /// テストの「今」(UNIX 秒)
    pub now: u64,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            sso_key: Some(SSO_KEY),
            private_key: Some(private_key_pem().to_owned()),
            http: FakeLineworks::default(),
            cache: Arc::default(),
            activity: Arc::default(),
            now: NOW,
        }
    }
}

/// worker の src/lib.rs と同じ組み立て
pub fn build(pg: PgClient, opts: Opts) -> App {
    let now = opts.now;
    let http = Arc::new(opts.http);
    let logs = Arc::new(StdMutex::new(Vec::new()));
    let sink = logs.clone();
    let state = SendState {
        pg: Arc::new(Mutex::new(pg)),
        http: http.clone(),
        endpoints: Arc::new(Endpoints {
            token: TOKEN_URL.into(),
            bots: BOTS_URL.into(),
            users: USERS_URL.into(),
            audit_download: AUDIT_URL.into(),
            boards: BOARDS_URL.into(),
        }),
        cache: opts.cache.clone(),
        activity: opts.activity.clone(),
        now: Arc::new(move || now),
        sso_key: opts.sso_key.map(Arc::from),
        private_key: opts.private_key.map(Arc::from),
        log: Arc::new(move |m: &str| sink.lock().unwrap().push(m.to_owned())),
    };
    App {
        router: router().with_state(state),
        http,
        cache: opts.cache,
        activity: opts.activity,
        logs,
    }
}

pub async fn app(opts: Opts) -> App {
    build(rt_client().await, opts)
}

pub struct Got {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Got {
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

/// 1 リクエストを打つ (`body` はそのままの bytes。content-type は JSON)
pub async fn call_raw(app: &App, method: &str, uri: &str, body: Vec<u8>) -> Got {
    call_with(app, method, uri, None, body).await
}

/// `tenant` が在れば `X-Tenant-ID` を付ける (値はそのままの文字列)
pub async fn call_with(
    app: &App,
    method: &str,
    uri: &str,
    tenant: Option<&str>,
    body: Vec<u8>,
) -> Got {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(t) = tenant {
        b = b.header("X-Tenant-ID", t);
    }
    let req = b.body(Body::from(body)).unwrap();
    let resp = app.router.clone().oneshot(req).await.unwrap();
    let status = resp.status().as_u16();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    Got { status, body }
}

pub async fn send(app: &App, body: serde_json::Value) -> Got {
    call_raw(app, "POST", SEND_PATH, serde_json::to_vec(&body).unwrap()).await
}

/// messages の口を打つ (`tenant` が在れば `X-Tenant-ID` を付ける)
pub async fn messages(app: &App, tenant: Option<&str>, body: serde_json::Value) -> Got {
    call_with(
        app,
        "POST",
        MESSAGES_PATH,
        tenant,
        serde_json::to_vec(&body).unwrap(),
    )
    .await
}

/// token の口を `tenant` のヘッダー付きで打つ
pub async fn token(app: &App, tenant: Uuid, body: serde_json::Value) -> Got {
    call_with(
        app,
        "POST",
        TOKEN_PATH,
        Some(&tenant.to_string()),
        serde_json::to_vec(&body).unwrap(),
    )
    .await
}

/// GET の口を打つ (`tenant` が在れば `X-Tenant-ID` を付ける。`query` は `?` の後ろ)
pub async fn get_path(app: &App, path: &str, tenant: Option<&str>, query: &str) -> Got {
    let uri = if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    };
    call_with(app, "GET", &uri, tenant, Vec::new()).await
}

pub async fn users(app: &App, tenant: Option<&str>, query: &str) -> Got {
    get_path(app, USERS_PATH, tenant, query).await
}

pub async fn login_activity(app: &App, tenant: Option<&str>, query: &str) -> Got {
    get_path(app, LOGIN_ACTIVITY_PATH, tenant, query).await
}
