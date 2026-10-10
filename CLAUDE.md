# alc-lineworks-worker

LINE WORKS の Worker `alc-lineworks` (Refs ohishi-exp/rust-leave-worker#1)。型は rust-leave-worker・alc-dtako-worker と同じ。
口は 3 つ: `POST /api/internal/lineworks/send` (rust-alc-api と同じ契約。recipient 宛は `bot_config_id` で bot を指定でき、使えない指定は 400 で名前順に戻さない)・`POST /api/internal/lineworks/token` (auth-worker 向けの access token)・`POST /api/internal/lineworks/messages` (notify / trouble の worker 向け。tenant 指定で text / image を user / channel へ)。
直下 = Worker (wasm 専用)、`crates/lineworks/` = 口・SQL・復号・JWT・LINE WORKS の呼び方。詳細は `README.md`。

## コマンド
```bash
bash scripts/check-exposure.sh && bash scripts/check-exposure-test.sh
cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --target wasm32-unknown-unknown --release -- -D warnings
bash scripts/fetch-migrations.sh   # 版は scripts/ALC_MIGRATIONS_REV
LINEWORKS_TEST_ADMIN_DATABASE_URL=postgresql://postgres:<pw>@127.0.0.1:<port>/postgres cargo test --workspace
worker-build --release && npx wrangler@4.144.0 deploy --dry-run
```
DB テストは使い捨ての postgres:17 へ。URL が無ければ失敗 (skip しない)。接続ロールは `alc_api_rt`。

## 規範
- 公開範囲を弱めない: 本番・staging とも Service Binding だけ (どの env も `workers_dev`/`preview_urls` = false、route 無し)。
  Hyperdrive は本番だけ。`wrangler.toml` の表の順を変えない (新しい表は placement より後)。
- **秘密値を応答・ログに出さない。** Client Secret・Private Key・access token・送信の本文・行 id を出さない。
  token の口の応答は `access_token`・`expires_at`・`bot_id` の 3 つだけ (テストがキーの集合を固定)。
- Private Key は Secrets Store の `LINEWORKS_PRIVATE_KEY` だけ。`bot_configs.private_key_encrypted` を読まない。
- token の口の scope は `client::ALLOWED_SCOPES` だけ。足すときは auth-worker の使う値を確かめる。
- DB は `PgClient::tenant_tx` + `query_typed` 系だけ。SQL は `crates/lineworks/src/pg.rs` の 1 か所。
  名前付き prepared statement 禁止。WHERE に tenant_id も明示する。
- `coverage_100.toml` の登録を外さない。CI の本数 (lib 27・send_db 14) はテストを足したら上げる。
- public repo: ホスト名・tenant UUID・個人情報を書かない。`v*` タグ = 本番 (Tag Release 手動)。
- kit の rev は直下 `Cargo.toml` の 1 か所 (alc-dtako-worker と同じ rev)。
