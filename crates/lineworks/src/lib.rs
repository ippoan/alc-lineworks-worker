//! LINE WORKS へのテキスト送信の口 `POST /api/internal/lineworks/send` と、auth-worker 向けの access token の口
//! `POST /api/internal/lineworks/token` (Refs ohishi-exp/rust-leave-worker#1)。
//! 送信の口は rust-alc-api の同じ口と同じ契約で、送信を Cloud Run から Worker へ移す。
//!
//! - [`routes`] — 口と入力の検証・応答の語 (tenant 指定で LINE WORKS の id へ直接送る `POST /api/internal/lineworks/messages`、
//!   組織のメンバーの `GET /api/internal/lineworks/users`、ログイン状況の `GET /api/internal/lineworks/login-activity` も)
//! - [`pg`] — SQL (宛先の行 id → tenant → bot_configs)
//! - [`jwt`] — Service Account 認証の JWT の claim (Private Key は Secrets Store の 1 か所)
//!
//! client_secret の復号 (rust と同じ AES-256-GCM) と RS256 の署名は ippoan/alc-worker-kit の `alc_worker_crypto` を使う。
//! - [`client`] — LINE WORKS の token・送信・読み取り (users・監査ログ・掲示板)、token の cache (HTTP は trait 越し)
//! - [`activity`] — ログイン状況の集計 (監査ログの CSV・3 つの信号の合成・並び・cache)
//! - [`deploy_check`] — 本番デプロイの確認の口 `GET /api/lineworks/deploy-check` (版が変わったら 1 通だけ送る)

pub mod activity;
pub mod bot_admin;
pub mod client;
pub mod deploy_check;
pub mod jwt;
pub mod pg;
pub mod routes;

pub use deploy_check::{DeployCheck, SentRecord, DEPLOY_CHECK_PATH};
pub use routes::{
    router, LogSink, Now, SendState, LOGIN_ACTIVITY_PATH, MESSAGES_PATH, SECRET_PATHS, SEND_PATH,
    TOKEN_PATH, USERS_PATH,
};
