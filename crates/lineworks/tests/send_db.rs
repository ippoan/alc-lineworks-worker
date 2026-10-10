//! 3 つの口を、実 DB (`alc_api_rt` で接続) と偽の LINE WORKS で通す。
//! 接続先は `LINEWORKS_TEST_ADMIN_DATABASE_URL` (無ければ失敗する。tests/support)。

mod support;

use std::sync::Arc;

use lineworks::client::TokenCache;
use support::*;
use uuid::Uuid;

/// ログに識別子・本文・秘密値が出ていないこと
fn assert_logs_clean(app: &App, forbidden: &[&str]) {
    let logs = app.logs.lock().unwrap();
    for line in logs.iter() {
        for f in forbidden {
            assert!(!line.contains(f), "ログに出してはいけない値が出た");
        }
        assert!(!line.contains("tok-1"), "ログに token が出た");
        assert!(!line.contains("PRIVATE KEY"), "ログに鍵が出た");
    }
}

fn form_value(body: &[u8], key: &str) -> String {
    String::from_utf8(body.to_vec())
        .unwrap()
        .split('&')
        .find_map(|kv| kv.strip_prefix(&format!("{key}=")).map(str::to_owned))
        .unwrap()
}

/// channel 宛: lookup (FORCE RLS の表) → その tenant の bot_configs → 復号 → token → 送信。
/// token は 2 通目で使い回す。Bot が退出済み (active = false) の行も送る (rust と同じ)。
/// bot_configs の private_key_encrypted (鍵ではない文字列) は読まない
#[tokio::test]
async fn channel_send_end_to_end() {
    let t = tenant().await;
    let b = bot(t, "main", "lineworks", true).await;
    let (row, lw_channel) = channel(t, b.id, true).await;
    let (left_row, left_channel) = channel(t, b.id, false).await;
    let app = app(Opts::default()).await;
    let text = "予約番号は J5JZPEQJ です";

    let got = send(&app, serde_json::json!({"channel_id": row, "text": text})).await;
    assert_eq!(
        (got.status, got.json()),
        (200, serde_json::json!({"ok": true}))
    );
    let got = send(
        &app,
        serde_json::json!({"channel_id": left_row, "text": text}),
    )
    .await;
    assert_eq!(got.status, 200);

    let seen = app.http.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 3, "token 1 回 + 送信 2 回");
    assert_eq!(seen[0].url, TOKEN_URL);
    assert_eq!(form_value(&seen[0].body, "client_id"), b.client_id);
    assert_eq!(form_value(&seen[0].body, "client_secret"), "secret-main");
    assert_eq!(form_value(&seen[0].body, "scope"), "bot");
    assert_eq!(
        seen[1].url,
        format!("{BOTS_URL}{}/channels/{lw_channel}/messages", b.bot_id)
    );
    assert_eq!(seen[1].authorization.as_deref(), Some("Bearer tok-1"));
    let body: serde_json::Value = serde_json::from_slice(&seen[1].body).unwrap();
    assert_eq!(
        body,
        serde_json::json!({"content": {"type": "text", "text": text}})
    );
    assert_eq!(
        seen[2].url,
        format!("{BOTS_URL}{}/channels/{left_channel}/messages", b.bot_id)
    );
    assert_eq!(app.cache.len(), 1);
    assert!(app.logs.lock().unwrap().is_empty());
}

/// recipient 宛: users の path。bot は tenant の有効な lineworks の bot のうち名前の順で最初
/// (無効な bot と provider が line の bot は、名前が前でも選ばない。別 tenant の bot も選ばない)
#[tokio::test]
async fn recipient_send_picks_bot_by_name() {
    let t = tenant().await;
    let other = tenant().await;
    bot(other, "0-other-tenant", "lineworks", true).await;
    bot(t, "1-disabled", "lineworks", false).await;
    bot(t, "2-line", "line", true).await;
    let want = bot(t, "3-first", "lineworks", true).await;
    bot(t, "4-second", "lineworks", true).await;
    let (row, user) = recipient(t, "lineworks", true).await;
    let app = app(Opts::default()).await;

    let got = send(
        &app,
        serde_json::json!({"recipient_id": row, "channel_id": null, "text": "hi"}),
    )
    .await;
    assert_eq!(
        (got.status, got.json()),
        (200, serde_json::json!({"ok": true}))
    );
    let seen = app.http.seen.lock().unwrap().clone();
    assert_eq!(form_value(&seen[0].body, "client_id"), want.client_id);
    assert_eq!(form_value(&seen[0].body, "client_secret"), "secret-3-first");
    assert_eq!(
        seen[1].url,
        format!("{BOTS_URL}{}/users/{user}/messages", want.bot_id)
    );
}

/// recipient 宛 + bot_config_id: 名前順の最初ではなく指定の bot で送る。
/// 使えない指定 (別 tenant・無効・provider 違い・存在しない) は 400 で、名前順に戻さず何も送らない。
/// channel 宛との併用は 400。指定なしは従来どおり名前順の最初
#[tokio::test]
async fn recipient_send_with_bot_config_id() {
    let t = tenant().await;
    let other = tenant().await;
    let first = bot(t, "1-first", "lineworks", true).await;
    let chosen = bot(t, "2-chosen", "lineworks", true).await;
    let disabled = bot(t, "3-disabled", "lineworks", false).await;
    let line = bot(t, "4-line", "line", true).await;
    let foreign = bot(other, "5-foreign", "lineworks", true).await;
    let (row, user) = recipient(t, "lineworks", true).await;
    let (ch, _) = channel(t, first.id, true).await;
    let app = app(Opts::default()).await;

    let got = send(
        &app,
        serde_json::json!({"recipient_id": row, "bot_config_id": chosen.id, "text": "hi"}),
    )
    .await;
    assert_eq!(
        (got.status, got.json()),
        (200, serde_json::json!({"ok": true}))
    );
    let seen = app.http.seen.lock().unwrap().clone();
    assert_eq!(form_value(&seen[0].body, "client_id"), chosen.client_id);
    assert_eq!(
        seen[1].url,
        format!("{BOTS_URL}{}/users/{user}/messages", chosen.bot_id)
    );
    app.http.seen.lock().unwrap().clear();

    let unavailable = serde_json::json!({
        "error": "bot_config_unavailable",
        "message": "bot_config_id is not an enabled lineworks bot of the tenant"
    });
    for id in [foreign.id, disabled.id, line.id, Uuid::new_v4()] {
        let got = send(
            &app,
            serde_json::json!({"recipient_id": row, "bot_config_id": id, "text": "hi"}),
        )
        .await;
        assert_eq!((got.status, got.json()), (400, unavailable.clone()));
    }
    let got = send(
        &app,
        serde_json::json!({"channel_id": ch, "bot_config_id": chosen.id, "text": "hi"}),
    )
    .await;
    assert_eq!(
        (got.status, got.json()),
        (
            400,
            serde_json::json!({"error": "bot_config_not_allowed", "message": "bot_config_id is only for recipient_id"})
        )
    );
    assert!(app.http.seen.lock().unwrap().is_empty());

    // 指定なし・null は従来どおり名前順の最初
    for body in [
        serde_json::json!({"recipient_id": row, "text": "hi"}),
        serde_json::json!({"recipient_id": row, "bot_config_id": null, "text": "hi"}),
    ] {
        let got = send(&app, body).await;
        assert_eq!(got.status, 200);
        let seen = app.http.seen.lock().unwrap().clone();
        assert_eq!(
            seen.last().unwrap().url,
            format!("{BOTS_URL}{}/users/{user}/messages", first.bot_id)
        );
    }
}

/// lookup の 2 関数を、実行用ロール alc_api_rt が tenant を設定しない状態 (nil UUID) で呼べること・
/// 関数の所有者の条件で見え方が変わること。
/// - テストの DB は superuser が migration を流すので、関数の所有者は superuser (RLS を素通りする) → 両方 1 行
/// - 所有者を RLS の掛かるロール (alc_api_app = NOSUPERUSER・NOBYPASSRLS) にすると、FORCE RLS の lineworks_channels
///   (migration 102) は 0 行、FORCE を外した notify_recipients (119) は所有者として 1 行 (表の所有者も本番と同じく alc_api_app に
///   する。transaction は戻す)
#[tokio::test]
async fn lookup_owner_condition() {
    let t = tenant().await;
    let b = bot(t, "main", "lineworks", true).await;
    let (ch, _) = channel(t, b.id, true).await;
    let (rc, _) = recipient(t, "lineworks", true).await;
    let su = admin().await;
    let row = su
        .query_one(
            "SELECT r.rolsuper, r.rolbypassrls, \
             (SELECT relforcerowsecurity FROM pg_class WHERE oid = 'alc_api.lineworks_channels'::regclass), \
             (SELECT relforcerowsecurity FROM pg_class WHERE oid = 'alc_api.notify_recipients'::regclass) \
             FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner \
             WHERE p.oid = 'alc_api.lookup_lineworks_channel_for_send(uuid)'::regprocedure",
            &[],
        )
        .await
        .unwrap();
    let facts: (bool, bool, bool, bool) = (row.get(0), row.get(1), row.get(2), row.get(3));
    assert_eq!(
        facts,
        (true, true, true, false),
        "所有者 superuser・channels は FORCE・recipients は FORCE なし"
    );

    // 実行用ロールで、worker と同じ関数 (tenant_tx(nil) の中) を呼ぶ
    let mut pg = rt_client().await;
    let c = lineworks::pg::channel_for_send(&mut pg, ch)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((c.tenant_id, c.bot_config_id), (t, b.id));
    let r = lineworks::pg::recipient_for_send(&mut pg, rc)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((r.tenant_id, r.enabled), (t, true));
    let none = lineworks::pg::channel_for_send(&mut pg, Uuid::new_v4())
        .await
        .unwrap();
    assert!(none.is_none());

    // 所有者を RLS の掛かるロールにした場合 (本番で migration を流すロールが superuser でも BYPASSRLS でもないときの形)
    su.batch_execute(
        "BEGIN; \
         ALTER FUNCTION alc_api.lookup_lineworks_channel_for_send(uuid) OWNER TO alc_api_app; \
         ALTER FUNCTION alc_api.lookup_notify_recipient_for_send(uuid) OWNER TO alc_api_app; \
         ALTER TABLE alc_api.lineworks_channels OWNER TO alc_api_app; \
         ALTER TABLE alc_api.notify_recipients OWNER TO alc_api_app; \
         SET LOCAL ROLE alc_api_rt; \
         SELECT set_config('app.current_tenant_id', '00000000-0000-0000-0000-000000000000', true);",
    )
    .await
    .unwrap();
    let n_ch: i64 = su
        .query_one(
            "SELECT count(*) FROM alc_api.lookup_lineworks_channel_for_send($1)",
            &[&ch],
        )
        .await
        .unwrap()
        .get(0);
    let n_rc: i64 = su
        .query_one(
            "SELECT count(*) FROM alc_api.lookup_notify_recipient_for_send($1)",
            &[&rc],
        )
        .await
        .unwrap()
        .get(0);
    su.batch_execute("ROLLBACK").await.unwrap();
    assert_eq!((n_ch, n_rc), (0, 1));
}

/// 行が無い → 404。recipient の行の検証 → 400 (rust と同じ語)
#[tokio::test]
async fn not_found_and_recipient_checks() {
    let t = tenant().await;
    bot(t, "main", "lineworks", true).await;
    let (line, _) = recipient(t, "line", true).await;
    let (disabled, _) = recipient(t, "lineworks", false).await;
    let app = app(Opts::default()).await;
    let cases = [
        (
            serde_json::json!({"channel_id": Uuid::new_v4(), "text": "x"}),
            404,
            serde_json::json!({"error": "channel_not_found"}),
        ),
        (
            serde_json::json!({"recipient_id": Uuid::new_v4(), "text": "x"}),
            404,
            serde_json::json!({"error": "recipient_not_found"}),
        ),
        (
            serde_json::json!({"recipient_id": line, "text": "x"}),
            400,
            serde_json::json!({"error": "recipient_not_lineworks", "message": "recipient provider is line"}),
        ),
        (
            serde_json::json!({"recipient_id": disabled, "text": "x"}),
            400,
            serde_json::json!({"error": "recipient_disabled", "message": "recipient is disabled"}),
        ),
    ];
    for (body, status, want) in cases {
        let got = send(&app, body).await;
        assert_eq!((got.status, got.json()), (status, want));
    }
    assert!(app.http.seen.lock().unwrap().is_empty());
}

/// bot の設定が引けない → 500 bot_config_not_found。channel の行が別 tenant の bot を指していても読まない
#[tokio::test]
async fn bot_config_missing() {
    let t = tenant().await;
    let other = tenant().await;
    let foreign = bot(other, "foreign", "lineworks", true).await;
    let (ch, _) = channel(t, foreign.id, true).await;
    let (rc, _) = recipient(t, "lineworks", true).await;
    let app = app(Opts::default()).await;
    for body in [
        serde_json::json!({"channel_id": ch, "text": "x"}),
        serde_json::json!({"recipient_id": rc, "text": "x"}),
    ] {
        let got = send(&app, body).await;
        assert_eq!(
            (got.status, got.json()),
            (
                500,
                serde_json::json!({"error": "internal_error", "message": "bot_config_not_found"})
            )
        );
    }
    assert!(app.http.seen.lock().unwrap().is_empty());
}

/// 鍵の欠け・誤り → 500 と固定の語 (LINE WORKS へは何も送らない)
#[tokio::test]
async fn secrets_missing_or_bad() {
    let t = tenant().await;
    let b = bot(t, "main", "lineworks", true).await;
    let (ch, _) = channel(t, b.id, true).await;
    let body = serde_json::json!({"channel_id": ch, "text": "x"});
    let cases = [
        (
            Opts {
                sso_key: None,
                ..Default::default()
            },
            "encryption_key_missing",
        ),
        (
            Opts {
                sso_key: Some("wrong-key"),
                ..Default::default()
            },
            "decrypt_failed",
        ),
        (
            Opts {
                private_key: None,
                ..Default::default()
            },
            "private_key_missing",
        ),
        (
            Opts {
                private_key: Some(broken_pem()),
                ..Default::default()
            },
            "private_key_invalid",
        ),
    ];
    for (opts, want) in cases {
        let app = app(opts).await;
        let got = send(&app, body.clone()).await;
        assert_eq!(
            (got.status, got.json()),
            (
                500,
                serde_json::json!({"error": "internal_error", "message": want})
            )
        );
        assert_eq!(app.http.seen.lock().unwrap().len(), 0);
        assert_logs_clean(
            &app,
            &[&ch.to_string(), &t.to_string(), "secret-main", SSO_KEY],
        );
        assert_eq!(app.logs.lock().unwrap().len(), 1);
    }
}

/// LINE WORKS の失敗 → 502 upstream_error (message は status と code だけ。応答の本文は載せない)
#[tokio::test]
async fn upstream_failures() {
    let t = tenant().await;
    let b = bot(t, "main", "lineworks", true).await;
    let (ch, _) = channel(t, b.id, true).await;
    let body = serde_json::json!({"channel_id": ch, "text": "本文"});
    let cases = [
        (
            FakeLineworks {
                token_status: 401,
                token_body: r#"{"error":"invalid_client","error_description":"secret-main"}"#
                    .into(),
                ..Default::default()
            },
            "Token issue failed: HTTP 401 (invalid_client)",
        ),
        (
            FakeLineworks {
                token_body: "{}".into(),
                ..Default::default()
            },
            "Token issue failed: parse",
        ),
        (
            FakeLineworks {
                send_status: 403,
                send_body: r#"{"code":"FORBIDDEN","description":"bot is not in channel"}"#.into(),
                ..Default::default()
            },
            "Send failed: HTTP 403 (FORBIDDEN)",
        ),
        (
            FakeLineworks {
                unreachable: true,
                ..Default::default()
            },
            "HTTP error: token",
        ),
    ];
    for (http, want) in cases {
        let app = app(Opts {
            http,
            ..Default::default()
        })
        .await;
        let got = send(&app, body.clone()).await;
        assert_eq!(
            (got.status, got.json()),
            (
                502,
                serde_json::json!({"error": "upstream_error", "message": want})
            )
        );
        assert_eq!(
            *app.logs.lock().unwrap(),
            [format!("lineworks-send: {want}")]
        );
        assert_logs_clean(&app, &[&ch.to_string(), "本文", "secret-main"]);
    }
}

/// 入力の誤り (DB を引く前に止まる) と、口の外
#[tokio::test]
async fn input_errors() {
    let app = app(Opts::default()).await;
    let id = Uuid::new_v4();
    let cases = [
        (
            serde_json::json!({"channel_id": id, "text": "  "}),
            serde_json::json!({"error": "text_required", "message": "text is empty"}),
        ),
        (
            serde_json::json!({"channel_id": id, "recipient_id": id, "text": "x"}),
            serde_json::json!({"error": "target_ambiguous", "message": "specify exactly one of channel_id / recipient_id"}),
        ),
        (
            serde_json::json!({"channel_id": null, "recipient_id": null, "text": "x"}),
            serde_json::json!({"error": "target_required", "message": "channel_id or recipient_id is required"}),
        ),
    ];
    for (body, want) in cases {
        let got = send(&app, body).await;
        assert_eq!((got.status, got.json()), (400, want));
    }
    // body が読めない (axum の Json の既定の拒否。rust と同じ)
    assert_eq!(
        call_raw(&app, "POST", lineworks::SEND_PATH, b"{".to_vec())
            .await
            .status,
        400
    );
    assert_eq!(
        call_raw(
            &app,
            "POST",
            lineworks::SEND_PATH,
            br#"{"channel_id":"x","text":"a"}"#.to_vec()
        )
        .await
        .status,
        422
    );
    assert_eq!(
        call_raw(
            &app,
            "POST",
            lineworks::SEND_PATH,
            br#"{"channel_id":null}"#.to_vec()
        )
        .await
        .status,
        422
    );
    assert_eq!(
        call_raw(&app, "GET", lineworks::SEND_PATH, vec![])
            .await
            .status,
        405
    );
    assert_eq!(
        call_raw(&app, "POST", "/api/internal/lineworks/other", vec![])
            .await
            .status,
        404
    );
    assert!(app.http.seen.lock().unwrap().is_empty());
}

/// DB の失敗 → 500 と固定の語。ログは段の名前と kind だけ
#[tokio::test]
async fn db_failures() {
    let t = tenant().await;
    let b = bot(t, "main", "lineworks", true).await;
    let (ch, _) = channel(t, b.id, true).await;
    let (rc, _) = recipient(t, "lineworks", true).await;

    // 切れた接続: lookup の段
    for (body, stage) in [
        (
            serde_json::json!({"channel_id": ch, "text": "x"}),
            "lookup channel",
        ),
        (
            serde_json::json!({"recipient_id": rc, "text": "x"}),
            "lookup recipient",
        ),
    ] {
        let app = build(broken_client().await, Opts::default());
        let got = send(&app, body).await;
        assert_eq!(
            (got.status, got.json()),
            (
                500,
                serde_json::json!({"error": "internal_error", "message": "get_failed"})
            )
        );
        let logs = app.logs.lock().unwrap().clone();
        assert_eq!(logs.len(), 1);
        assert!(
            logs[0].starts_with(&format!("lineworks-send: {stage} failed: db (")),
            "{logs:?}"
        );
        assert_logs_clean(&app, &[&ch.to_string(), &rc.to_string()]);
    }

    // bot_configs を読めないロール: lookup は通り、bot の段で 42501
    for (body, want) in [
        (
            serde_json::json!({"channel_id": ch, "text": "x"}),
            "get_bot_config_failed",
        ),
        (
            serde_json::json!({"recipient_id": rc, "text": "x"}),
            "list_bot_configs_failed",
        ),
    ] {
        let app = build(client_as(NO_BOT_ROLE).await, Opts::default());
        let got = send(&app, body).await;
        assert_eq!(
            (got.status, got.json()),
            (
                500,
                serde_json::json!({"error": "internal_error", "message": want})
            )
        );
        assert_eq!(
            *app.logs.lock().unwrap(),
            ["lineworks-send: bot config failed: db (42501)"]
        );
    }

    // recipient 宛 + bot 指定の段
    let app = build(client_as(NO_BOT_ROLE).await, Opts::default());
    let got = send(
        &app,
        serde_json::json!({"recipient_id": rc, "bot_config_id": b.id, "text": "x"}),
    )
    .await;
    assert_eq!(
        (got.status, got.json()),
        (
            500,
            serde_json::json!({"error": "internal_error", "message": "get_bot_config_failed"})
        )
    );

    // token の口
    let app = build(broken_client().await, Opts::default());
    let got = token(
        &app,
        t,
        serde_json::json!({"bot_config_id": b.id, "scope": "bot"}),
    )
    .await;
    assert_eq!(
        (got.status, got.json()),
        (
            500,
            serde_json::json!({"error": "internal_error", "message": "get_bot_config_failed"})
        )
    );
}

/// token の口: 応答は access_token・expires_at・bot_id の 3 つだけ (Client Secret・Private Key は入らない)。
/// scope ごとに取り、同じ scope は使い回す (送信の口と同じ cache)
#[tokio::test]
async fn token_issue() {
    let t = tenant().await;
    let b = bot(t, "main", "lineworks", true).await;
    let (ch, _) = channel(t, b.id, true).await;
    let cache = Arc::new(TokenCache::default());
    let app = app(Opts {
        cache: cache.clone(),
        ..Default::default()
    })
    .await;

    for scope in ["bot", "board.read", "directory.read", "board.read"] {
        let got = token(
            &app,
            t,
            serde_json::json!({"bot_config_id": b.id, "scope": scope}),
        )
        .await;
        assert_eq!(got.status, 200);
        let v = got.json();
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["access_token", "bot_id", "expires_at"]);
        assert_eq!(
            v,
            serde_json::json!({"access_token": "tok-1", "expires_at": NOW + 86400, "bot_id": b.bot_id})
        );
        let text = String::from_utf8(got.body.clone()).unwrap();
        for secret in [
            "secret-main",
            "PRIVATE KEY",
            "not-a-key",
            &b.client_id,
            "sa@example",
        ] {
            assert!(!text.contains(secret), "応答に秘密値が出た");
        }
    }
    let scopes: Vec<String> = app
        .http
        .seen
        .lock()
        .unwrap()
        .iter()
        .map(|r| form_value(&r.body, "scope"))
        .collect();
    assert_eq!(scopes, ["bot", "board.read", "directory.read"]);
    // 送信の口は同じ cache の bot の token を使い回す
    let got = send(&app, serde_json::json!({"channel_id": ch, "text": "x"})).await;
    assert_eq!(got.status, 200);
    assert_eq!(app.http.seen.lock().unwrap().len(), 4);
    assert_eq!(cache.len(), 3);
}

/// token の口の誤り
#[tokio::test]
async fn token_errors() {
    let t = tenant().await;
    let other = tenant().await;
    let b = bot(t, "main", "lineworks", true).await;
    let foreign = bot(other, "foreign", "lineworks", true).await;
    let app = app(Opts::default()).await;
    let body = |id: Uuid, scope: &str| {
        serde_json::to_vec(&serde_json::json!({"bot_config_id": id, "scope": scope})).unwrap()
    };

    // tenant のヘッダーが無い・UUID でない → 401
    assert_eq!(
        call_with(&app, "POST", lineworks::TOKEN_PATH, None, body(b.id, "bot"))
            .await
            .status,
        401
    );
    assert_eq!(
        call_with(
            &app,
            "POST",
            lineworks::TOKEN_PATH,
            Some("x"),
            body(b.id, "bot")
        )
        .await
        .status,
        401
    );
    // 別 tenant の bot・無い bot → 404
    for id in [foreign.id, Uuid::new_v4()] {
        let got = token(
            &app,
            t,
            serde_json::json!({"bot_config_id": id, "scope": "bot"}),
        )
        .await;
        assert_eq!(
            (got.status, got.json()),
            (404, serde_json::json!({"error": "bot_config_not_found"}))
        );
    }
    // 許可していない scope → 400
    let got = token(
        &app,
        t,
        serde_json::json!({"bot_config_id": b.id, "scope": "user.read"}),
    )
    .await;
    assert_eq!(
        (got.status, got.json()),
        (
            400,
            serde_json::json!({"error": "scope_not_allowed", "message": "scope must be one of bot / board.read / directory.read"})
        )
    );
    // body が読めない
    let got = call_with(
        &app,
        "POST",
        lineworks::TOKEN_PATH,
        Some(&t.to_string()),
        br#"{"bot_config_id":"x"}"#.to_vec(),
    )
    .await;
    assert_eq!(got.status, 422);
    assert!(app.http.seen.lock().unwrap().is_empty());
    // 鍵が無い・上流の失敗
    let app = app_with(Opts {
        sso_key: None,
        ..Default::default()
    })
    .await;
    let got = token(
        &app,
        t,
        serde_json::json!({"bot_config_id": b.id, "scope": "bot"}),
    )
    .await;
    assert_eq!(
        (got.status, got.json()),
        (
            500,
            serde_json::json!({"error": "internal_error", "message": "encryption_key_missing"})
        )
    );
    let app = app_with(Opts {
        http: FakeLineworks {
            token_status: 400,
            ..Default::default()
        },
        ..Default::default()
    })
    .await;
    let got = token(
        &app,
        t,
        serde_json::json!({"bot_config_id": b.id, "scope": "bot"}),
    )
    .await;
    assert_eq!(
        (got.status, got.json()),
        (
            502,
            serde_json::json!({"error": "upstream_error", "message": "Token issue failed: HTTP 400"})
        )
    );
}

/// messages の口: text / image × user / channel の 4 通り。bot_config_id が無ければ tenant の有効な lineworks の bot の
/// うち名前の順で最初 (無効・provider が line・別 tenant の bot は選ばない)、在ればその行 (無効な bot でも送る)。
/// 応答は 204 で本文なし。LINE WORKS への要求の URL と本文、token が bot ごとに 1 回であることまで見る
#[tokio::test]
async fn messages_text_and_image_to_user_and_channel() {
    let t = tenant().await;
    let other = tenant().await;
    bot(other, "0-other-tenant", "lineworks", true).await;
    bot(t, "1-disabled", "lineworks", false).await;
    bot(t, "2-line", "line", true).await;
    let first = bot(t, "3-first", "lineworks", true).await;
    let second = bot(t, "4-second", "lineworks", false).await;
    let app = app(Opts::default()).await;
    let tid = t.to_string();
    let text = serde_json::json!({"type": "text", "text": "点検の結果です"});
    let image = serde_json::json!({
        "type": "image",
        "original_url": "https://img.test/a.png",
        "preview_url": "https://img.test/a_s.png",
    });
    let cases = [
        (None, serde_json::json!({"user_id": "u@example"}), &text),
        (
            Some(second.id),
            serde_json::json!({"channel_id": "ch-9"}),
            &image,
        ),
        (None, serde_json::json!({"channel_id": "ch-1"}), &text),
        (
            Some(second.id),
            serde_json::json!({"user_id": "u2"}),
            &image,
        ),
    ];
    for (bot_config_id, to, content) in &cases {
        let mut body = serde_json::json!({"to": to, "content": content});
        if let Some(id) = bot_config_id {
            body["bot_config_id"] = serde_json::json!(id);
        }
        let got = messages(&app, Some(&tid), body).await;
        assert_eq!((got.status, got.body.len()), (204, 0));
    }

    let seen = app.http.seen.lock().unwrap().clone();
    let sends: Vec<_> = seen.iter().filter(|r| r.url != TOKEN_URL).collect();
    let tokens: Vec<_> = seen.iter().filter(|r| r.url == TOKEN_URL).collect();
    assert_eq!(tokens.len(), 2, "bot ごとに token 1 回");
    assert_eq!(form_value(&tokens[0].body, "client_id"), first.client_id);
    assert_eq!(
        form_value(&tokens[0].body, "client_secret"),
        "secret-3-first"
    );
    assert_eq!(form_value(&tokens[1].body, "client_id"), second.client_id);
    let text_body = serde_json::json!({"content": {"type": "text", "text": "点検の結果です"}});
    let image_body = serde_json::json!({"content": {
        "type": "image",
        "originalContentUrl": "https://img.test/a.png",
        "previewImageUrl": "https://img.test/a_s.png",
    }});
    let want = [
        (
            format!("{BOTS_URL}{}/users/u@example/messages", first.bot_id),
            &text_body,
        ),
        (
            format!("{BOTS_URL}{}/channels/ch-9/messages", second.bot_id),
            &image_body,
        ),
        (
            format!("{BOTS_URL}{}/channels/ch-1/messages", first.bot_id),
            &text_body,
        ),
        (
            format!("{BOTS_URL}{}/users/u2/messages", second.bot_id),
            &image_body,
        ),
    ];
    assert_eq!(sends.len(), 4);
    for (req, (url, body)) in sends.iter().zip(want.iter()) {
        assert_eq!(&req.url, url);
        assert_eq!(req.content_type, "application/json");
        assert_eq!(req.authorization.as_deref(), Some("Bearer tok-1"));
        let got: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
        assert_eq!(&got, *body);
    }
    assert!(app.logs.lock().unwrap().is_empty());
}

/// messages の口の誤り: tenant のヘッダー (401)・別 tenant / 無い bot と既定の bot が無い tenant (404)・
/// 入力 (400 / 422)・上流 (502。本文は載せない)。LINE WORKS へは上流の場合だけ届く
#[tokio::test]
async fn messages_errors() {
    let t = tenant().await;
    let other = tenant().await;
    let empty = tenant().await;
    bot(empty, "line-only", "line", true).await;
    bot(t, "main", "lineworks", true).await;
    let foreign = bot(other, "foreign", "lineworks", true).await;
    let app = app(Opts::default()).await;
    let ok =
        serde_json::json!({"to": {"user_id": "u1"}, "content": {"type": "text", "text": "本文"}});

    // tenant のヘッダーが無い・UUID でない → 401 (token の口と同じ layer)
    for tenant in [None, Some("x")] {
        assert_eq!(messages(&app, tenant, ok.clone()).await.status, 401);
    }
    // 別 tenant の bot (RLS + WHERE tenant_id で見えない)・無い bot・既定の bot が無い tenant → 404
    let mut foreign_body = ok.clone();
    foreign_body["bot_config_id"] = serde_json::json!(foreign.id);
    let mut missing_body = ok.clone();
    missing_body["bot_config_id"] = serde_json::json!(Uuid::new_v4());
    for (tenant, body) in [(t, foreign_body), (t, missing_body), (empty, ok.clone())] {
        let got = messages(&app, Some(&tenant.to_string()), body).await;
        assert_eq!(
            (got.status, got.json()),
            (404, serde_json::json!({"error": "bot_config_not_found"}))
        );
    }
    // 入力の誤り (DB を引く前に止まる)
    let tid = t.to_string();
    let cases = [
        (
            serde_json::json!({"to": {"user_id": "a/b"}, "content": {"type": "text", "text": "x"}}),
            serde_json::json!({"error": "target_invalid", "message": "to has an invalid id"}),
        ),
        (
            serde_json::json!({"to": {"channel_id": ""}, "content": {"type": "text", "text": "x"}}),
            serde_json::json!({"error": "target_invalid", "message": "to has an invalid id"}),
        ),
        (
            serde_json::json!({"to": {"user_id": "u"}, "content": {"type": "text", "text": " "}}),
            serde_json::json!({"error": "text_required", "message": "text is empty"}),
        ),
        (
            serde_json::json!({"to": {"user_id": "u"}, "content": {"type": "image", "original_url": "http://a/1", "preview_url": "https://a/2"}}),
            serde_json::json!({"error": "image_url_invalid", "message": "original_url and preview_url must be https URLs"}),
        ),
    ];
    for (body, want) in cases {
        let got = messages(&app, Some(&tid), body).await;
        assert_eq!((got.status, got.json()), (400, want));
    }
    for body in [
        serde_json::json!({"to": {"user_id": "u", "channel_id": "c"}, "content": {"type": "text", "text": "x"}}),
        serde_json::json!({"to": {"user_id": "u"}, "content": {"type": "file"}}),
        serde_json::json!({"to": {"user_id": "u"}, "content": {"type": "text", "text": "x"}, "bot_config_id": "x"}),
    ] {
        assert_eq!(messages(&app, Some(&tid), body).await.status, 422);
    }
    assert!(app.http.seen.lock().unwrap().is_empty());

    // 上流の失敗 → 502 (status と code だけ。応答の本文・宛先・本文はログにも出さない)
    let app = app_with(Opts {
        http: FakeLineworks {
            send_status: 403,
            send_body: r#"{"code":"FORBIDDEN","description":"u1 secret"}"#.into(),
            ..Default::default()
        },
        ..Default::default()
    })
    .await;
    let got = messages(&app, Some(&tid), ok).await;
    assert_eq!(
        (got.status, got.json()),
        (
            502,
            serde_json::json!({"error": "upstream_error", "message": "Send failed: HTTP 403 (FORBIDDEN)"})
        )
    );
    assert_eq!(
        *app.logs.lock().unwrap(),
        ["lineworks-send: Send failed: HTTP 403 (FORBIDDEN)"]
    );
    assert_logs_clean(&app, &["u1", "本文", &tid, "secret-main"]);
}

/// messages の口の DB の失敗 (bot_configs を読めないロール) → 500 と固定の語
#[tokio::test]
async fn messages_db_failures() {
    let t = tenant().await;
    let b = bot(t, "main", "lineworks", true).await;
    let base =
        serde_json::json!({"to": {"user_id": "u1"}, "content": {"type": "text", "text": "x"}});
    let mut by_id = base.clone();
    by_id["bot_config_id"] = serde_json::json!(b.id);
    for (body, want) in [
        (by_id, "get_bot_config_failed"),
        (base, "list_bot_configs_failed"),
    ] {
        let app = build(client_as(NO_BOT_ROLE).await, Opts::default());
        let got = messages(&app, Some(&t.to_string()), body).await;
        assert_eq!(
            (got.status, got.json()),
            (
                500,
                serde_json::json!({"error": "internal_error", "message": want})
            )
        );
        assert_eq!(
            *app.logs.lock().unwrap(),
            ["lineworks-send: bot config failed: db (42501)"]
        );
        assert!(app.http.seen.lock().unwrap().is_empty());
    }
}

async fn app_with(opts: Opts) -> App {
    app(opts).await
}

/// 中身の無い偽の PEM (区切りの行は実行時に組み立てる — ソースに鍵の形の文字列を置かない)
fn broken_pem() -> String {
    let d = "-".repeat(5);
    format!("{d}BEGIN PRIVATE KEY{d}\nAAAA\n{d}END PRIVATE KEY{d}")
}
