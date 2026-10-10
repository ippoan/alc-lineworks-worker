//! LINE WORKS へのテキスト送信の口 `POST /api/internal/lineworks/send` と、auth-worker 向けの access token の口
//! `POST /api/internal/lineworks/token` (Refs ohishi-exp/rust-leave-worker#1)。
//! 送信の口は rust-alc-api の同じ口と同じ契約で、送信を Cloud Run から Worker へ移す。
//!
//! - [`routes`] — 口と入力の検証・応答の語
//! - [`pg`] — SQL (宛先の行 id → tenant → bot_configs)
//! - [`secret`] — client_secret の復号 (rust と同じ AES-256-GCM)
//! - [`jwt`] — Service Account 認証の JWT (RS256。Private Key は Secrets Store の 1 か所)
//! - [`client`] — LINE WORKS の token と送信、token の cache (HTTP は trait 越し)

pub mod client;
pub mod jwt;
pub mod pg;
pub mod routes;
pub mod secret;

pub use routes::{router, LogSink, Now, SendState, SEND_PATH, TOKEN_PATH};
