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

- body: `{"channel_id": "<lineworks_channels.id>", "text": "…"}` か `{"recipient_id": "<notify_recipients.id>", "bot_config_id": "<bot_configs.id>"?, "text": "…"}`
  (キー無しと `null` は同じ「未指定」)。tenant のヘッダーは見ない — tenant は行から引く。
  `bot_config_id` は recipient 宛のときだけ (個人宛てに使う bot の指定。channel 宛と一緒だと 400)
- 流れ: 宛先の行 id → SECURITY DEFINER の `alc_api.lookup_lineworks_channel_for_send` (migration 129) / `lookup_notify_recipient_for_send` (130)
  で tenant を引く (`tenant_tx(Uuid::nil())` の中で呼ぶ) → その tenant の `tenant_tx` で bot_configs を読む → `client_secret_encrypted` を
  `SSO_ENCRYPTION_KEY` で復号 → JWT (RS256) → access token (scope `bot`) → 送信
- bot の選び方: channel 宛は行の `bot_config_id`。recipient 宛は `bot_config_id` があればその bot
  (recipient 行から決めた tenant の `provider = 'lineworks'` かつ有効な行だけ。使えなければ 400 で、名前順には戻さず送らない)、無ければ
  tenant の `provider = 'lineworks'` かつ有効な bot のうち `name` の順で最初 (rust と同じ。同名は id の順)
- 送信先: `POST https://www.worksapis.com/v1.0/bots/{bot_id}/channels/{channel_id}/messages` / `…/users/{user_id}/messages`

| status | 本文 | いつ |
|---|---|---|
| 200 | `{"ok":true}` | 送れた |
| 400 | `{"error":"text_required","message":"text is empty"}` | text が空白だけ |
| 400 | `{"error":"target_ambiguous",…}` / `{"error":"target_required",…}` | 宛先が両方 / どちらも無い |
| 400 | `{"error":"recipient_not_lineworks",…}` / `{"error":"recipient_disabled",…}` | recipient が LINE WORKS 宛でない / 無効 |
| 400 | `{"error":"bot_config_not_allowed",…}` / `{"error":"bot_config_unavailable",…}` | channel 宛と `bot_config_id` が一緒 / 指定の bot がその tenant に無い・無効・provider が lineworks でない |
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

### `GET /api/internal/lineworks/users[?bot_config_id=]`

組織のメンバーの一覧 (Refs ippoan/rust-alc-api#747。rust の `alc-notify::clients::lineworks::list_org_users` の移植)。notify の
`GET /notify/lineworks/users` と trouble の `GET /trouble/lineworks/members` を担う worker が Service Binding で呼ぶ
(alc-internal-proxy には載せない)。tenant と bot の選び方は messages の口と同じ。

- `GET https://www.worksapis.com/v1.0/users` を scope `directory.read` で、`responseMetaData.nextCursor` が無くなるまで (cursor は符号化して query へ)
- 200: `[{"user_id": "…", "user_name": "姓 名" | null, "email": "…" | null}]` (rust の `LineworksMember`。notify の `already_registered` は呼び手が足す)

### `GET /api/internal/lineworks/login-activity?days=N[&bot_config_id=]`

ログイン状況 (rust の `alc-notify::lineworks_login_activity` の計算全体。集計は `crates/lineworks/src/activity.rs`)。tenant と bot は users の口と同じ。

- 3 つの信号の一番新しい値: `service=auth` の監査ログ (必須)・`service=message` の監査ログ (best-effort)・掲示板の既読 (投稿の作成日時を下限に。
  掲示板 5 つ・掲示板ごとに投稿 10 件まで。best-effort)。監査ログの窓は now − 30 日 〜 now (31 日ちょうどは LINE WORKS が断る)
- 監査ログのダウンロードは別ホストへの 302。`redirect: "manual"` で受けて `Location` (https だけ) へ `Authorization` を付け直す (5 回まで)
- scope は `directory.read`・`audit.read`・`board.read` を worker の中で取る (token の cache のキーは scope ごと)。**token の口の
  `ALLOWED_SCOPES` には `audit.read` を足さない**
- `days` は既定 3 (負は 0)。`stale` = 記録なし か `days_since_login >= days`。並びは記録なしが先頭、その次はログインが古い順
- 200: `[{"user_id", "user_name", "email", "last_login_at" (RFC3339 | null), "days_since_login" (| null), "stale", "last_login_source" ("auth" | "message" | "board" | null)}]`
- 合成の結果は isolate の中で (tenant, Client ID) ごとに 300 秒使い回す。取る間は lock を握る (監査ログの API を同じ isolate の中で並行に呼ばない)

| status (users・login-activity) | 本文 | いつ |
|---|---|---|
| 200 | 上の配列 | 取れた |
| 400 | axum の既定 | query が読めない (`bot_config_id` が UUID でない・`days` が数でない) |
| 401 / 404 / 500 | messages の口と同じ | `X-Tenant-ID` / bot が無い / DB・鍵 |
| 403 | `{"error":"missing_scope","scope":"directory.read" \| "audit.read","message":"LINE WORKS Developer Console で … scope を追加してください"}` | LINE WORKS が権限で断った (rust と同じ形) |
| 502 | `{"error":"upstream_error","message":"Read users failed: HTTP 500"}` など | LINE WORKS の失敗 (本文は載せない) |
| 502 | `{"error":"csv_columns_not_recognized","message":"member/email column not found"}` | auth の監査ログの見出しが読めない (rust と違い、見出しの中身は載せない) |

### access token の cache

isolate の中で (Client ID, Service Account, scope) ごとに、有効期限の 60 秒前まで使い回す (5 つの口で共有)。

## 配置

| 場所 | 中身 |
|---|---|
| 直下 (`Cargo.toml`・`wrangler.toml`・`src/`) | Worker 本体 (wasm32 専用)。`src/lib.rs` (載せ方・Secrets Store の読み出し・token とログイン状況の cache)・`src/db.rs` (DB への経路)・`src/http.rs` (`worker::Fetch`。GET は `redirect: "manual"`)・`src/tcp.rs` (VPC の binding) |
| `crates/lineworks/` | `routes` (5 つの口)・`pg` (SQL)・`secret` (復号)・`jwt` (RS256・PKCS#1 / PKCS#8)・`client` (URL・form・token・送信・読み取り・cache。HTTP は trait 越し)・`activity` (ログイン状況の集計) |
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

- 単体テスト (47 本): 復号 (rust の ring の暗号文を読み、ここの暗号文を rust が読む・固定の値)・PEM の 2 形式と `\n`・JWT の claim と署名の検証・
  URL と form・token の cache (期限・Service Account・scope ごと)・エラーの文・入力の検証と応答の語・users の全ページ・
  リダイレクトの手での追従と失敗・掲示板の上限・監査ログの CSV (rust の単体テストの期待値)・3 つの信号の合成・しきい値と並び
- 実 DB (tests/send_db.rs、19 本。接続は実行用ロール `alc_api_rt`): 5 つの口を偽の LINE WORKS で端から端まで。lookup の関数の所有者の条件
  (`lookup_owner_condition`: テストの DB は superuser が所有者で両方引ける。所有者を RLS の掛かるロールにすると FORCE RLS の
  `lineworks_channels` は 0 行・`notify_recipients` は 1 行) も確かめる
- 実 DB のテストは `LINEWORKS_TEST_ADMIN_DATABASE_URL` が無ければ失敗する (skip しない)
