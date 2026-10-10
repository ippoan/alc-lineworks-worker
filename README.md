# alc-lineworks-worker

LINE WORKS の Bot API を使う Cloudflare Worker `alc-lineworks` (workers-rs + tokio-postgres)。rust-alc-api (Cloud Run) から送信を分ける
(Refs ohishi-exp/rust-leave-worker#1)。**LINE WORKS の App の Private Key は Secrets Store の `LINEWORKS_PRIVATE_KEY` の 1 か所だけ**で、
bot を足すたびに登録画面へ PEM を貼らなくてよくする (bot_configs の `private_key_encrypted` は読まない)。
型は ohishi-exp/rust-leave-worker・ippoan/alc-dtako-worker と同じ。

## 口

入口は auth-worker からの Service Binding だけ (本番・staging とも `workers_dev` / `preview_urls` = false、route 無し。
`scripts/check-exposure.sh` と陰性対照 `check-exposure-test.sh` が CI で検査する)。Worker 自身は呼び手を認証しない。

### `POST /api/internal/lineworks/send`

rust-alc-api の同じ口 (`alc-notify::lineworks_channels::send_text_internal`) と同じ契約。呼び元 (ohishi-exp/rust-leave-worker の cron・
ohishi-exp/nuxt-dtako-admin の dtako-scraper-relay・ippoan/auth-worker の device-notify) は status (2xx か) と失敗の本文しか読まない。

- body: `{"channel_id": "<lineworks_channels.id>", "text": "…"}` か `{"recipient_id": "<notify_recipients.id>", "text": "…"}`
  (キー無しと `null` は同じ「未指定」)。tenant のヘッダーは見ない — tenant は行から引く
- 流れ: 宛先の行 id → SECURITY DEFINER の `alc_api.lookup_lineworks_channel_for_send` (migration 129) / `lookup_notify_recipient_for_send` (130)
  で tenant を引く (`tenant_tx(Uuid::nil())` の中で呼ぶ) → その tenant の `tenant_tx` で bot_configs を読む → `client_secret_encrypted` を
  `SSO_ENCRYPTION_KEY` で復号 → JWT (RS256) → access token (scope `bot`) → 送信
- bot の選び方: channel 宛は行の `bot_config_id`。recipient 宛は tenant の `provider = 'lineworks'` かつ有効な bot のうち `name` の順で最初 (rust と同じ。同名は id の順)
- 送信先: `POST https://www.worksapis.com/v1.0/bots/{bot_id}/channels/{channel_id}/messages` / `…/users/{user_id}/messages`

| status | 本文 | いつ |
|---|---|---|
| 200 | `{"ok":true}` | 送れた |
| 400 | `{"error":"text_required","message":"text is empty"}` | text が空白だけ |
| 400 | `{"error":"target_ambiguous",…}` / `{"error":"target_required",…}` | 宛先が両方 / どちらも無い |
| 400 | `{"error":"recipient_not_lineworks",…}` / `{"error":"recipient_disabled",…}` | recipient が LINE WORKS 宛でない / 無効 |
| 400・415・422 | axum の既定 | body が読めない (rust と同じ) |
| 404 | `{"error":"channel_not_found"}` / `{"error":"recipient_not_found"}` | 行が無い |
| 500 | `{"error":"internal_error","message":"<語>"}` | `get_failed`・`get_bot_config_failed`・`list_bot_configs_failed` (DB)・`bot_config_not_found`・`encryption_key_missing`・`decrypt_failed`・`private_key_missing`・`private_key_invalid` |
| 502 | `{"error":"upstream_error","message":"<文>"}` | LINE WORKS の失敗 |

rust との違い: 502 の `message` は上流の応答の本文を載せず、`Token issue failed: HTTP 401 (invalid_client)` のように status と LINE WORKS の
エラーの code (英数字と `_.-` の 64 文字まで) だけ。Private Key が読めないのは 502 ではなく 500 `private_key_invalid`。
`private_key_missing` は新しい語 (rust は鍵を DB から読んでいた)。

### `POST /api/internal/lineworks/token`

auth-worker のリッチメニューと MCP の `lineworks_get` が LINE WORKS の API を自分で叩くための access token を出す
(Client Secret と Private Key を auth-worker へ渡さないため。rust-alc-api の `GET /api/admin/bot/configs/{id}/secrets` を消すための段)。

- tenant は `X-Tenant-ID` (auth-worker が付ける。無い・UUID でない → 401)。その tenant の bot_configs の行だけを読む (別 tenant の id は 404)
- body: `{"bot_config_id": "<bot_configs.id>", "scope": "<scope>"}`。scope は `bot`・`board.read`・`directory.read` だけ
  (auth-worker の `lineworks-bot-api.ts`・`lineworks-get-path.ts` が使う値。ほかは 400 `scope_not_allowed`)
- 200: `{"access_token": "…", "expires_at": <UNIX 秒>, "bot_id": "…"}`。**この 3 つだけ** (Client Secret・Private Key・Client ID・
  Service Account は返さない。tests/send_db.rs がキーの集合を固定する)
- 失敗: 404 `bot_config_not_found`・500 (送信の口と同じ語)・502 `upstream_error`

### `POST /api/internal/lineworks/messages`

notify / trouble の worker が tenant を指定して LINE WORKS の id へ直接送る口 (Refs ippoan/rust-alc-api#747)。Service Binding 専用で、
auth-worker の alc-internal-proxy の allowlist には載せない。

- tenant は `X-Tenant-ID` (token の口と同じ layer。無い・UUID でない → 401)。その tenant の bot_configs の行だけを読む
- body:
  ```
  { "bot_config_id": "<bot_configs.id>"?,
    "to": { "user_id": "<LINE WORKS の user id>" } | { "channel_id": "<LINE WORKS の channel id>" },
    "content": { "type": "text", "text": "…" }
             | { "type": "image", "original_url": "https://…", "preview_url": "https://…" } }
  ```
  `channel_id` は LINE WORKS 側の id (lineworks_channels の行 id ではない)。画像は URL 渡し (`originalContentUrl` / `previewImageUrl`)
- bot の選び方: `bot_config_id` があればその行 (provider・enabled は見ない)、無ければ tenant の `provider = 'lineworks'` かつ有効な bot の
  うち `name` の順で最初 (rust の alc-trouble・alc-notify の `resolve_lineworks_config` と同じ。送信の口の recipient 宛とも同じ)

| status | 本文 | いつ |
|---|---|---|
| 204 | なし | 送れた |
| 400 | `{"error":"text_required",…}` / `{"error":"target_invalid",…}` / `{"error":"image_url_invalid",…}` | text が空白だけ / id が空か `/ ? # %`・空白を含む / 画像の URL が https でない |
| 401 | — | `X-Tenant-ID` が無い・UUID でない |
| 404 | `{"error":"bot_config_not_found"}` | 指定の bot がその tenant に無い (別 tenant の id も) / 既定の bot が無い |
| 400・415・422 | axum の既定 | body が読めない (`to` に両方のキー・未知の `content.type` 等) |
| 500・502 | 送信の口と同じ | DB・鍵 (`get_bot_config_failed`・`list_bot_configs_failed` ほか) / LINE WORKS の失敗 (本文は載せない) |

### access token の cache

isolate の中で (Client ID, Service Account, scope) ごとに、有効期限の 60 秒前まで使い回す (3 つの口で共有)。

## 配置

| 場所 | 中身 |
|---|---|
| 直下 (`Cargo.toml`・`wrangler.toml`・`src/`) | Worker 本体 (wasm32 専用)。`src/lib.rs` (載せ方・Secrets Store の読み出し・token の cache)・`src/db.rs` (DB への経路)・`src/http.rs` (`worker::Fetch`)・`src/tcp.rs` (VPC の binding) |
| `crates/lineworks/` | `routes` (3 つの口)・`pg` (SQL)・`secret` (復号)・`jwt` (RS256・PKCS#1 / PKCS#8)・`client` (URL・form・token・送信・cache。HTTP は trait 越し) |
| `scripts/` | 公開範囲の検査と陰性対照・`fetch-migrations.sh` (版は `ALC_MIGRATIONS_REV`)・coverage の gate (登録簿は `coverage_100.toml`) |
| `.github/workflows/` | `ci.yml` (検査) / `deploy.yml` (PR = dry-run・main = staging・タグ `v*` = 本番) / `tag-release.yml` (手動のタグ) |

## binding と secret

| binding | 種類 | 本番 | staging |
|---|---|---|---|
| `LINEWORKS_HYPERDRIVE` | Hyperdrive (vein・dtako と共有の設定) | ○ | — |
| `LINEWORKS_DB_VPC` | Workers VPC (vein の staging と共有) | — | ○ |
| `SSO_ENCRYPTION_KEY` | Secrets Store `sso-encryption-key` (auth-worker と同じ) | ○ | ○ |
| `LINEWORKS_PRIVATE_KEY` | Secrets Store `LINEWORKS_PRIVATE_KEY` (正本は GCP Secret Manager の同名) | ○ | ○ |
| `CF_VERSION_METADATA` | version metadata (`x-worker-version` / `x-worker-tag`) | ○ | ○ |

DB への経路は ohishi-exp/rust-leave-worker の `src/db.rs` と同じ (staging = VPC → PgBouncer、本番 = Hyperdrive、ローカル = `--env local` の `DATABASE_URL`)。

## 検査

```bash
bash scripts/check-exposure.sh && bash scripts/check-exposure-test.sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo clippy --locked --target wasm32-unknown-unknown --release -- -D warnings
bash scripts/fetch-migrations.sh
LINEWORKS_TEST_ADMIN_DATABASE_URL=postgresql://postgres:<pw>@127.0.0.1:<port>/postgres cargo llvm-cov --locked -p lineworks --text > cov.txt
bash scripts/check_coverage_100.sh --use-cache cov.txt
worker-build --release
```

- 単体テスト (27 本): 復号 (rust の ring の暗号文を読み、ここの暗号文を rust が読む・固定の値)・PEM の 2 形式と `\n`・JWT の claim と署名の検証・
  URL と form・token の cache (期限・Service Account・scope ごと)・エラーの文・入力の検証と応答の語
- 実 DB (tests/send_db.rs、14 本。接続は実行用ロール `alc_api_rt`): 3 つの口を偽の LINE WORKS で端から端まで。lookup の関数の所有者の条件
  (`lookup_owner_condition`: テストの DB は superuser が所有者で両方引ける。所有者を RLS の掛かるロールにすると FORCE RLS の
  `lineworks_channels` は 0 行・`notify_recipients` は 1 行) も確かめる
- 実 DB のテストは `LINEWORKS_TEST_ADMIN_DATABASE_URL` が無ければ失敗する (skip しない)
