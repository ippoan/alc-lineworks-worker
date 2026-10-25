//! 6 つの口を、実 DB (`alc_api_rt` で接続) と偽の LINE WORKS で通す。
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

// ---- users / login-activity (Refs ippoan/rust-alc-api#747) ----

const USERS_PAGE_1: &str = r#"{"users":[{"userId":"u1","userName":{"lastName":"田中","firstName":"太郎"},"email":"a@x.com"},{"userId":"u2","userName":{"lastName":"鈴木"},"email":"B@x.com"}],"responseMetaData":{"nextCursor":"c+1="}}"#;
const USERS_PAGE_2: &str = r#"{"users":[{"userId":"u3","email":"c@x.com"},{"userId":"u4","email":"d@x.com"},{"userId":"u5","email":"e@x.com"}],"responseMetaData":{}}"#;

/// users の 2 ページを返す偽の LINE WORKS
fn with_users(http: FakeLineworks) -> FakeLineworks {
    http.on_get(
        &format!("{USERS_URL}?cursor=c%2B1%3D"),
        200,
        USERS_PAGE_2,
        None,
    )
    .on_get(USERS_URL, 200, USERS_PAGE_1, None)
}

/// `NOW` の `d` 日前 (秒は `NOW` と同じ)
fn days_ago(d: u64) -> chrono::DateTime<chrono::Utc> {
    lineworks::activity::to_datetime(NOW - d * 86_400)
}

/// 監査ログの API の時刻の形 (URL に入る前)
fn audit_time(t: chrono::DateTime<chrono::Utc>) -> String {
    lineworks::client::form_urlencode(&[("t", &lineworks::client::format_audit_time(t))])[2..]
        .to_owned()
}

/// users の口: bot_config_id が無ければ既定の bot、在ればその bot で token (scope directory.read) を取り、
/// cursor で 2 ページ取って rust の `LineworksMember` の形で返す
#[tokio::test]
async fn users_pages_and_bot_selection() {
    let t = tenant().await;
    let other = tenant().await;
    bot(other, "0-other-tenant", "lineworks", true).await;
    bot(t, "1-disabled", "lineworks", false).await;
    let first = bot(t, "3-first", "lineworks", true).await;
    let second = bot(t, "4-second", "lineworks", false).await;
    let app = app(Opts {
        http: with_users(FakeLineworks::default()),
        ..Default::default()
    })
    .await;
    let tid = t.to_string();

    let got = users(&app, Some(&tid), "").await;
    assert_eq!(
        (got.status, got.json()),
        (
            200,
            serde_json::json!([
                {"user_id": "u1", "user_name": "田中 太郎", "email": "a@x.com"},
                {"user_id": "u2", "user_name": "鈴木", "email": "B@x.com"},
                {"user_id": "u3", "user_name": null, "email": "c@x.com"},
                {"user_id": "u4", "user_name": null, "email": "d@x.com"},
                {"user_id": "u5", "user_name": null, "email": "e@x.com"},
            ])
        )
    );
    let got = users(&app, Some(&tid), &format!("bot_config_id={}", second.id)).await;
    assert_eq!(got.status, 200);

    let seen = app.http.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2, "bot ごとに token 1 回");
    assert_eq!(form_value(&seen[0].body, "client_id"), first.client_id);
    assert_eq!(form_value(&seen[1].body, "client_id"), second.client_id);
    assert_eq!(
        app.http.token_scopes(),
        ["directory.read", "directory.read"]
    );
    let gets = app.http.seen_gets.lock().unwrap().clone();
    assert_eq!(gets.len(), 4);
    assert_eq!(gets[0].0, USERS_URL);
    assert_eq!(gets[1].0, format!("{USERS_URL}?cursor=c%2B1%3D"));
    assert!(gets.iter().all(|(_, a)| a == "Bearer tok-1"));
    assert!(app.logs.lock().unwrap().is_empty());
}

/// users の口の誤り: 401・404 (別 tenant の bot = RLS + WHERE tenant_id)・400 (query が読めない)・
/// LINE WORKS が権限で断った 403 `missing_scope`・ほかの上流の失敗 502 (本文は載せない)・DB の失敗 500
#[tokio::test]
async fn users_errors() {
    let t = tenant().await;
    let other = tenant().await;
    let empty = tenant().await;
    let b = bot(t, "main", "lineworks", true).await;
    let foreign = bot(other, "foreign", "lineworks", true).await;
    let app = app(Opts::default()).await;
    let tid = t.to_string();

    for tenant in [None, Some("x")] {
        assert_eq!(users(&app, tenant, "").await.status, 401);
        assert_eq!(login_activity(&app, tenant, "days=3").await.status, 401);
    }
    for (tenant, q) in [
        (t, format!("bot_config_id={}", foreign.id)),
        (t, format!("bot_config_id={}", Uuid::new_v4())),
        (empty, String::new()),
    ] {
        for got in [
            users(&app, Some(&tenant.to_string()), &q).await,
            login_activity(&app, Some(&tenant.to_string()), &q).await,
        ] {
            assert_eq!(
                (got.status, got.json()),
                (404, serde_json::json!({"error": "bot_config_not_found"}))
            );
        }
    }
    assert_eq!(users(&app, Some(&tid), "bot_config_id=x").await.status, 400);
    assert_eq!(
        login_activity(&app, Some(&tid), "days=abc").await.status,
        400
    );
    assert!(app.http.seen.lock().unwrap().is_empty());
    assert!(app.http.seen_gets.lock().unwrap().is_empty());

    let secret_body = r#"{"code":"FORBIDDEN","description":"u1 a@x.com"}"#;
    let cases = [
        (
            FakeLineworks::default().on_get(USERS_URL, 403, secret_body, None),
            403,
            serde_json::json!({"error": "missing_scope", "scope": "directory.read", "message": "LINE WORKS Developer Console で directory.read scope を追加してください"}),
            "lineworks-read: Read users failed: HTTP 403 (FORBIDDEN)",
        ),
        (
            FakeLineworks::default().on_get(USERS_URL, 500, "<html>a@x.com</html>", None),
            502,
            serde_json::json!({"error": "upstream_error", "message": "Read users failed: HTTP 500"}),
            "lineworks-read: Read users failed: HTTP 500",
        ),
        (
            FakeLineworks::default().on_get(USERS_URL, 200, "a@x.com", None),
            502,
            serde_json::json!({"error": "upstream_error", "message": "Read users failed: parse"}),
            "lineworks-read: Read users failed: parse",
        ),
        (
            FakeLineworks {
                unreachable: true,
                ..Default::default()
            },
            502,
            serde_json::json!({"error": "upstream_error", "message": "HTTP error: token"}),
            "lineworks-read: HTTP error: token",
        ),
    ];
    for (http, status, body, log) in cases {
        let app = app_with(Opts {
            http,
            ..Default::default()
        })
        .await;
        for got in [
            users(&app, Some(&tid), "").await,
            login_activity(&app, Some(&tid), "").await,
        ] {
            assert_eq!((got.status, got.json()), (status, body.clone()));
        }
        assert_eq!(*app.logs.lock().unwrap(), [log, log]);
        assert_logs_clean(&app, &["u1", "a@x.com", &tid, "secret-main"]);
    }

    // DB の失敗 (bot_configs を読めないロール)
    for (q, want) in [
        (format!("bot_config_id={}", b.id), "get_bot_config_failed"),
        (String::new(), "list_bot_configs_failed"),
    ] {
        let app = build(client_as(NO_BOT_ROLE).await, Opts::default());
        for got in [
            users(&app, Some(&tid), &q).await,
            login_activity(&app, Some(&tid), &q).await,
        ] {
            assert_eq!(
                (got.status, got.json()),
                (
                    500,
                    serde_json::json!({"error": "internal_error", "message": want})
                )
            );
        }
        assert!(app.http.seen.lock().unwrap().is_empty());
    }
}

/// login-activity の偽の LINE WORKS: users 2 ページ・auth の監査ログ (別ホストへ 302 を 2 回)・message の監査ログ・掲示板
fn activity_http() -> FakeLineworks {
    // auth: a@ 1 日前 (JST の時刻の形) / B@ 5 日前と 10 日前 (新しい方) / c@ は失敗だけ
    let jst = |d| (days_ago(d) + chrono::Duration::hours(9)).format("%Y/%m/%d %H:%M:%S");
    let auth = format!(
        "説明,メンバー,日時,IPアドレス,ログイン方法,サービスタイプ\n\
         ログインに成功しました,田中太郎 (A@x.com),{},1.2.3.4,パスワード,ブラウザ\n\
         ログインに成功しました,鈴木 (b@x.com),{},1.2.3.4,パスワード,モバイルアプリ\n\
         ログインに成功しました,鈴木 (b@x.com),{},1.2.3.4,パスワード,モバイルアプリ\n\
         ログインに失敗しました (エラーコード: 401),c (c@x.com),{},1.2.3.4,パスワード,ブラウザ\n",
        jst(1),
        days_ago(10).to_rfc3339(),
        days_ago(5).to_rfc3339(),
        days_ago(2).to_rfc3339(),
    );
    // message: c@ 2 日前、a@ 4 日前 (auth の方が新しい)
    let message = format!(
        "日時,送信者,受信者,チャンネルID,イベント\n{},c (c@x.com),a (a@x.com),ch,送信\n{},a (a@x.com),c (c@x.com),ch,送信\n",
        days_ago(2).to_rfc3339(),
        days_ago(4).to_rfc3339(),
    );
    let posts = serde_json::json!({"posts": [
        {"postId": 1_000_000_000_000_000_001u64, "createdTime": days_ago(7).to_rfc3339()},
        {"postId": 2, "createdTime": days_ago(40).to_rfc3339()},
    ]})
    .to_string();
    with_users(FakeLineworks::default())
        .on_get("https://dl.test/final", 200, &auth, None)
        .on_get("https://dl.test/hop", 302, "", Some("https://dl.test/final"))
        .on_get(
            &format!("{AUDIT_URL}?service=auth&"),
            302,
            "",
            Some("https://dl.test/hop"),
        )
        .on_get(&format!("{AUDIT_URL}?service=message&"), 200, &message, None)
        .on_get(
            &format!("{BOARDS_URL}/4000000000000000001/posts/1000000000000000001/readers"),
            200,
            r#"{"readers":[{"userId":"u4","isRead":true},{"userId":"u5","isRead":false},{"userId":"u9","isRead":true}]}"#,
            None,
        )
        .on_get(
            &format!("{BOARDS_URL}/4000000000000000001/posts?count=40"),
            200,
            &posts,
            None,
        )
        .on_get(
            BOARDS_URL,
            200,
            r#"{"boards":[{"boardId":4000000000000000001}]}"#,
            None,
        )
}

/// login-activity: 3 つの信号の合成・`days` のしきい値・並び (記録なしが先頭、その次は古い順)・JSON の形・
/// 監査ログの窓 (now − 30 日 〜 now) とリダイレクトの Authorization の付け直し・cache (5 分の間は監査ログを取り直さない)
#[tokio::test]
async fn login_activity_end_to_end() {
    let t = tenant().await;
    bot(t, "main", "lineworks", true).await;
    let activity = Arc::new(lineworks::activity::ActivityCache::default());
    let app = app(Opts {
        http: activity_http(),
        activity: activity.clone(),
        ..Default::default()
    })
    .await;
    let tid = t.to_string();

    let got = login_activity(&app, Some(&tid), "days=3").await;
    assert_eq!(got.status, 200);
    let entry = |user_id: &str,
                 name: Option<&str>,
                 email: &str,
                 days: Option<u64>,
                 stale: bool,
                 source: Option<&str>| {
        serde_json::json!({
            "user_id": user_id,
            "user_name": name,
            "email": email,
            "last_login_at": days.map(|d| days_ago(d).to_rfc3339()),
            "days_since_login": days,
            "stale": stale,
            "last_login_source": source,
        })
    };
    assert_eq!(
        got.json(),
        serde_json::json!([
            entry("u5", None, "e@x.com", None, true, None),
            entry("u4", None, "d@x.com", Some(7), true, Some("board")),
            entry("u2", Some("鈴木"), "B@x.com", Some(5), true, Some("auth")),
            entry("u3", None, "c@x.com", Some(2), false, Some("message")),
            entry(
                "u1",
                Some("田中 太郎"),
                "a@x.com",
                Some(1),
                false,
                Some("auth")
            ),
        ])
    );

    let gets = app.http.seen_gets.lock().unwrap().clone();
    let auth_url = format!(
        "{AUDIT_URL}?service=auth&startTime={}&endTime={}&language=ja_JP",
        audit_time(days_ago(30)),
        audit_time(days_ago(0)),
    );
    let urls: Vec<&str> = gets.iter().map(|(u, _)| u.as_str()).collect();
    assert_eq!(
        urls[2..5],
        [
            auth_url.as_str(),
            "https://dl.test/hop",
            "https://dl.test/final"
        ],
        "監査ログの窓は 30 日、302 を辿る"
    );
    assert!(urls[5].starts_with(&format!("{AUDIT_URL}?service=message&startTime=")));
    assert!(gets.iter().all(|(_, a)| a == "Bearer tok-1"));
    assert_eq!(
        app.http.token_scopes(),
        ["directory.read", "audit.read", "board.read"]
    );
    assert!(app.logs.lock().unwrap().is_empty());
    assert_eq!(activity.count().await, 1);

    // days の既定は 3、負は 0 (記録のある人も全員 stale)。5 分の間は監査ログ・掲示板を取り直さない (users は毎回)
    let n = gets.len();
    let got = login_activity(&app, Some(&tid), "").await;
    let stale: Vec<bool> = got
        .json()
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["stale"].as_bool().unwrap())
        .collect();
    assert_eq!(stale, [true, true, true, false, false]);
    let got = login_activity(&app, Some(&tid), "days=-5").await;
    assert!(got
        .json()
        .as_array()
        .unwrap()
        .iter()
        .all(|e| e["stale"] == true));
    let urls = app.http.get_urls();
    assert_eq!(urls.len(), n + 4);
    assert!(urls[n..].iter().all(|u| u.starts_with(USERS_URL)));

    // 299 秒後は cache から、300 秒たつと取り直す
    let before = app_with(Opts {
        http: activity_http(),
        activity: activity.clone(),
        now: NOW + 299,
        ..Default::default()
    })
    .await;
    assert_eq!(login_activity(&before, Some(&tid), "").await.status, 200);
    assert!(!before
        .http
        .get_urls()
        .iter()
        .any(|u| u.starts_with(AUDIT_URL)));
    let later = app_with(Opts {
        http: activity_http(),
        activity,
        now: NOW + 300,
        ..Default::default()
    })
    .await;
    assert_eq!(login_activity(&later, Some(&tid), "").await.status, 200);
    assert!(later
        .http
        .get_urls()
        .iter()
        .any(|u| u.starts_with(AUDIT_URL)));
}

/// login-activity の誤り: auth の監査ログ (必須) の失敗は口の失敗 (403 `missing_scope` audit.read / 502 / CSV の見出し)。
/// message と掲示板は best-effort (固定の語をログに残して auth だけで返す)。記録なしの人だけでも 200
#[tokio::test]
async fn login_activity_errors() {
    let t = tenant().await;
    bot(t, "main", "lineworks", true).await;
    let tid = t.to_string();
    let auth = format!("{AUDIT_URL}?service=auth&");
    let message = format!("{AUDIT_URL}?service=message&");
    let cases = [
        (
            with_users(FakeLineworks::default()).on_get(
                &auth,
                403,
                r#"{"code":"FORBIDDEN"}"#,
                None,
            ),
            403,
            serde_json::json!({"error": "missing_scope", "scope": "audit.read", "message": "LINE WORKS Developer Console で audit.read scope を追加してください"}),
            "lineworks-read: Read audit failed: HTTP 403 (FORBIDDEN)",
        ),
        (
            with_users(FakeLineworks::default())
                .on_get(&auth, 302, "", Some("https://dl.test/x"))
                .on_get(
                    "https://dl.test/x",
                    401,
                    r#"{"code":"UNAUTHORIZED","description":"a@x.com"}"#,
                    None,
                ),
            502,
            serde_json::json!({"error": "upstream_error", "message": "Read audit failed: HTTP 401 (UNAUTHORIZED)"}),
            "lineworks-read: Read audit failed: HTTP 401 (UNAUTHORIZED)",
        ),
        (
            with_users(FakeLineworks::default()).on_get(&auth, 302, "", None),
            502,
            serde_json::json!({"error": "upstream_error", "message": "Read audit failed: redirect"}),
            "lineworks-read: Read audit failed: redirect",
        ),
        (
            with_users(FakeLineworks::default()).on_get(&auth, 200, "a@x.com,u1\n1,2\n", None),
            502,
            serde_json::json!({"error": "csv_columns_not_recognized", "message": "member/email column not found"}),
            "lineworks-read: auth audit csv: member/email column not found",
        ),
    ];
    for (http, status, body, log) in cases {
        let app = app_with(Opts {
            http,
            ..Default::default()
        })
        .await;
        let got = login_activity(&app, Some(&tid), "days=3").await;
        assert_eq!((got.status, got.json()), (status, body));
        assert_eq!(*app.logs.lock().unwrap(), [log]);
        assert_logs_clean(&app, &["u1", "a@x.com", &tid]);
    }

    // best-effort: message が読めない CSV・掲示板が 403 → auth だけ。message が 500・掲示板が無い → auth だけ
    let auth_csv = format!("メンバー,日時\na@x.com,{}\n", days_ago(1).to_rfc3339());
    for (http, logs) in [
        (
            with_users(FakeLineworks::default())
                .on_get(&auth, 200, &auth_csv, None)
                .on_get(&message, 200, "x,y\n", None)
                .on_get(BOARDS_URL, 403, "forbidden", None),
            vec![
                "lineworks-read: message audit skipped: member/email column not found",
                "lineworks-read: board activity skipped: Read boards failed: HTTP 403",
            ],
        ),
        (
            with_users(FakeLineworks::default())
                .on_get(&auth, 200, &auth_csv, None)
                .on_get(&message, 500, "a@x.com", None)
                .on_get(BOARDS_URL, 200, "{}", None),
            vec!["lineworks-read: message audit skipped: Read audit failed: HTTP 500"],
        ),
    ] {
        let app = app_with(Opts {
            http,
            ..Default::default()
        })
        .await;
        let got = login_activity(&app, Some(&tid), "days=3").await;
        assert_eq!(got.status, 200);
        let rows = got.json();
        let rows = rows.as_array().unwrap();
        assert_eq!(rows.len(), 5);
        assert_eq!(
            rows.iter()
                .filter(|r| r["last_login_source"] == "auth")
                .count(),
            1
        );
        assert!(rows[..4].iter().all(|r| r["last_login_at"].is_null()));
        assert_eq!(*app.logs.lock().unwrap(), logs);
        assert_logs_clean(&app, &["u1", "a@x.com", &tid]);
    }
}

// ---- deploy-check (Refs ippoan/rust-alc-api#747) ----

/// proxy が付け直すヘッダーの代わり (名前, 値)
type Headers = Vec<(&'static str, String)>;

fn deploy_reply(version: &str, tag: &str, sent: bool, reason: &str) -> serde_json::Value {
    serde_json::json!({"version": version, "tag": tag, "sent": sent, "reason": reason})
}

/// `?to=` の相手に版ごと 1 回: tenant (`X-Tenant-ID`) の既定の bot (名前順の最初) で組織のメンバーを取り、`to` が居れば
/// 固定文を送り、(版, tenant, to のハッシュ) を記録する。同じ版・同じ相手の 2 回目は送らない。別の相手はまた送る。
/// 別の版 (tag 付き) はまた送り、文は tag。`bot_config_id` を付ければその bot。メールのヘッダーは見ない
#[tokio::test]
async fn deploy_check_sends_once_per_target_and_version() {
    let t = tenant().await;
    let first = bot(t, "1-first", "lineworks", true).await;
    let second = bot(t, "2-second", "lineworks", true).await;
    let record = Arc::new(FakeRecord::default());
    let tid = t.to_string();
    let app = app(Opts {
        http: with_users(FakeLineworks::default()),
        record: record.clone(),
        ..Opts::default()
    })
    .await;
    let me = [("X-Tenant-ID", tid.as_str()), ("X-User-Email", "z@x.com")];

    let got = deploy_check(&app, &me, "to=u2").await;
    assert_eq!(
        (got.status, got.json()),
        (200, deploy_reply("0123456789abcdef", "", true, "sent"))
    );
    let seen = app.http.seen.lock().unwrap().clone();
    assert_eq!(
        seen.len(),
        3,
        "token 2 回 (directory.read・bot) + 送信 1 回"
    );
    assert_eq!(form_value(&seen[0].body, "client_id"), first.client_id);
    assert_eq!(app.http.token_scopes(), ["directory.read", "bot"]);
    assert_eq!(
        seen[2].url,
        format!("{BOTS_URL}{}/users/u2/messages", first.bot_id)
    );
    let body: serde_json::Value = serde_json::from_slice(&seen[2].body).unwrap();
    assert_eq!(
        body,
        serde_json::json!({"content": {"type": "text", "text": "alc-lineworks-worker 01234567 を本番に出しました (デプロイ確認)"}})
    );
    let key = |v: &str, to: &str| lineworks::deploy_check::record_key(v, t, to);
    assert_eq!(
        *record.versions.lock().unwrap(),
        [key("0123456789abcdef", "u2")]
    );

    let got = deploy_check(&app, &me, "to=u2").await;
    assert_eq!(
        (got.status, got.json()),
        (
            200,
            deploy_reply("0123456789abcdef", "", false, "already_sent")
        )
    );
    assert_eq!(app.http.seen.lock().unwrap().len(), 3, "2 回目は送らない");

    // 別の相手 (同じ版)
    let got = deploy_check(&app, &me, "to=u5").await;
    assert_eq!(got.json()["reason"], "sent");
    let seen = app.http.seen.lock().unwrap().clone();
    assert_eq!(
        seen.last().unwrap().url,
        format!("{BOTS_URL}{}/users/u5/messages", first.bot_id)
    );

    // 新しい版 (同じ記録を持つ別の isolate)・bot を指定
    let app = app_with(Opts {
        http: with_users(FakeLineworks::default()),
        record: record.clone(),
        version: ("fedcba9876543210".into(), "v0.1.4".into()),
        ..Opts::default()
    })
    .await;
    let got = deploy_check(&app, &me, &format!("to=u2&bot_config_id={}", second.id)).await;
    assert_eq!(
        (got.status, got.json()),
        (
            200,
            deploy_reply("fedcba9876543210", "v0.1.4", true, "sent")
        )
    );
    let seen = app.http.seen.lock().unwrap().clone();
    assert_eq!(form_value(&seen[0].body, "client_id"), second.client_id);
    assert_eq!(
        seen[2].url,
        format!("{BOTS_URL}{}/users/u2/messages", second.bot_id)
    );
    let body: serde_json::Value = serde_json::from_slice(&seen[2].body).unwrap();
    assert_eq!(
        body["content"]["text"],
        "alc-lineworks-worker v0.1.4 を本番に出しました (デプロイ確認)"
    );
    assert_eq!(
        *record.versions.lock().unwrap(),
        [
            key("0123456789abcdef", "u2"),
            key("0123456789abcdef", "u5"),
            key("fedcba9876543210", "u2"),
        ]
    );
    assert!(app.logs.lock().unwrap().is_empty());
}

/// 送り先が決まらない → 200 sent=false と理由語 (記録しない・送らない・ログも出さない):
/// 版が取れない = not_configured / tenant か `to` が無い (空も) = no_user / tenant に使える bot が無い (別 tenant の bot の指定も) =
/// no_bot / `to` が組織のメンバーに居ない・形が崩れている = user_not_found
#[tokio::test]
async fn deploy_check_not_sent() {
    let t = tenant().await;
    let empty = tenant().await;
    let other = tenant().await;
    bot(t, "main", "lineworks", true).await;
    bot(empty, "off", "lineworks", false).await;
    let foreign = bot(other, "foreign", "lineworks", true).await;
    let (tid, eid) = (t.to_string(), empty.to_string());
    let tenant_of = |id: &str| vec![("X-Tenant-ID", id.to_owned())];
    let users = || with_users(FakeLineworks::default());
    let cases: Vec<(Opts, Headers, String, &str)> = vec![
        (
            Opts {
                version: (String::new(), String::new()),
                ..Opts::default()
            },
            tenant_of(&tid),
            "to=u2".into(),
            "not_configured",
        ),
        (Opts::default(), vec![], "to=u2".into(), "no_user"),
        (Opts::default(), tenant_of(&tid), String::new(), "no_user"),
        (Opts::default(), tenant_of(&tid), "to=".into(), "no_user"),
        (Opts::default(), tenant_of(&eid), "to=u2".into(), "no_bot"),
        (
            Opts::default(),
            tenant_of(&tid),
            format!("to=u2&bot_config_id={}", foreign.id),
            "no_bot",
        ),
        (
            Opts {
                http: users(),
                ..Opts::default()
            },
            tenant_of(&tid),
            "to=u9".into(),
            "user_not_found",
        ),
        (
            Opts {
                http: users(),
                ..Opts::default()
            },
            tenant_of(&tid),
            "to=u%2F2".into(),
            "user_not_found",
        ),
    ];
    for (opts, headers, query, reason) in cases {
        let version = opts.version.0.clone();
        let app = app_with(opts).await;
        let headers: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let got = deploy_check(&app, &headers, &query).await;
        assert_eq!(
            (got.status, got.json()),
            (200, deploy_reply(&version, "", false, reason))
        );
        assert!(
            app.http
                .seen
                .lock()
                .unwrap()
                .iter()
                .all(|r| r.url == TOKEN_URL),
            "送信はしない"
        );
        assert!(app.record.versions.lock().unwrap().is_empty());
        assert!(app.logs.lock().unwrap().is_empty());
    }
}

/// 送れない → 502 send_failed (本文は 4 つのキーだけ・識別子もエラー文も `to` も無い・ログは固定の語と段の語)。記録しないので
/// 次の呼び出しでまた試す。組織のメンバーが取れない (権限・上流)・送信の失敗・DB の失敗・鍵が無い
#[tokio::test]
async fn deploy_check_send_failed() {
    let t = tenant().await;
    let b = bot(t, "main", "lineworks", true).await;
    let tid = t.to_string();
    let send_failed = deploy_reply("0123456789abcdef", "", false, "send_failed");
    let fixed = "lineworks-deploy-check: send failed";
    let cases: Vec<(bool, Opts, Vec<&str>)> = vec![
        (
            true,
            Opts {
                http: FakeLineworks::default().on_get(USERS_URL, 403, "", None),
                ..Opts::default()
            },
            vec!["lineworks-read: Read users failed: HTTP 403", fixed],
        ),
        (
            true,
            Opts {
                http: with_users(FakeLineworks {
                    send_status: 500,
                    ..FakeLineworks::default()
                }),
                ..Opts::default()
            },
            vec!["lineworks-send: Send failed: HTTP 500", fixed],
        ),
        (
            false,
            Opts::default(),
            vec!["lineworks-send: bot config failed: db (42501)", fixed],
        ),
        (
            true,
            Opts {
                sso_key: None,
                ..Opts::default()
            },
            vec!["lineworks-send: SSO_ENCRYPTION_KEY not set", fixed],
        ),
    ];
    for (rt, opts, logs) in cases {
        let pg = if rt {
            rt_client().await
        } else {
            client_as(NO_BOT_ROLE).await
        };
        let app = build(pg, opts);
        let got = deploy_check(&app, &[("X-Tenant-ID", &tid)], "to=u2").await;
        assert_eq!((got.status, got.json()), (502, send_failed.clone()));
        assert!(!String::from_utf8_lossy(&got.body).contains("u2"));
        assert_eq!(*app.logs.lock().unwrap(), logs);
        assert!(app.record.versions.lock().unwrap().is_empty());
        assert_logs_clean(&app, &[&tid, &b.bot_id, "u2"]);
    }
}

// ---------- Bot 設定の管理の口 (Refs ippoan/rust-alc-api#680) ----------

const BOT_CONFIGS: &str = "/api/admin/bot/configs";

/// proxy が付け直すヘッダー付きで Bot 設定の口を打つ (`role` が `None` なら `X-User-*` を付けない)
async fn bot_admin(
    app: &App,
    method: &str,
    tenant: Option<Uuid>,
    role: Option<&str>,
    body: Option<serde_json::Value>,
) -> Got {
    bot_admin_at(app, BOT_CONFIGS, method, tenant, role, body).await
}

async fn bot_admin_at(
    app: &App,
    uri: &str,
    method: &str,
    tenant: Option<Uuid>,
    role: Option<&str>,
    body: Option<serde_json::Value>,
) -> Got {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(t) = tenant {
        b = b.header("X-Tenant-ID", t.to_string());
    }
    if let Some(r) = role {
        b = b
            .header("X-User-ID", Uuid::new_v4().to_string())
            .header("X-User-Email", "admin@example.test")
            .header("X-User-Role", r);
    }
    let body = body.map_or_else(Vec::new, |v| serde_json::to_vec(&v).unwrap());
    let resp = app
        .router
        .clone()
        .oneshot(b.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    Got { status, body }
}

async fn secrets_of(id: &str) -> (String, Option<String>) {
    let row = admin()
        .await
        .query_one(
            "SELECT client_secret_encrypted, bot_secret_encrypted FROM alc_api.bot_configs WHERE id = $1",
            &[&Uuid::parse_str(id).unwrap()],
        )
        .await
        .unwrap();
    (row.get(0), row.get(1))
}

fn bot_body(name: &str) -> serde_json::Value {
    let u = Uuid::new_v4();
    serde_json::json!({
        "name": name,
        "client_id": format!("cid-{name}-{u}"),
        "client_secret": "plain-client-secret",
        "service_account": "sa@example",
        "bot_id": format!("bot-{name}-{u}"),
        "bot_secret": "plain-bot-secret",
    })
}

/// 作成 → 一覧 → 更新 (秘密値は空なら変えない) → 削除。秘密値は暗号化して保存し、応答に載せない
#[tokio::test]
async fn bot_admin_create_list_update_delete() {
    let app = app(Opts::default()).await;
    let (t, other) = (tenant().await, tenant().await);

    let got = bot_admin(&app, "POST", Some(t), Some("admin"), Some(bot_body("b"))).await;
    assert_eq!(got.status, 200);
    let row = got.json();
    let mut keys: Vec<_> = row.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "bot_id",
            "client_id",
            "created_at",
            "enabled",
            "id",
            "name",
            "provider",
            "service_account",
            "updated_at"
        ]
    );
    assert_eq!(row["provider"], "lineworks");
    assert_eq!(row["enabled"], true);
    assert!(
        !got.body.windows(5).any(|w| w == b"plain"),
        "秘密値を返さない"
    );
    let id = row["id"].as_str().unwrap().to_owned();
    let (cs, bs) = secrets_of(&id).await;
    assert_eq!(decrypt(&cs), "plain-client-secret");
    assert_eq!(decrypt(bs.as_deref().unwrap()), "plain-bot-secret");

    // 一覧は自分の会社の行だけ (名前の順)
    bot(t, "a-first", "lineworks", true).await;
    bot(other, "z-other", "lineworks", true).await;
    let list = bot_admin(&app, "GET", Some(t), Some("admin"), None).await;
    assert_eq!(list.status, 200);
    let names: Vec<_> = list.json()["configs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(names, ["a-first", "b"]);

    // 更新: 秘密値が空なら変えない
    let mut upd = bot_body("b2");
    upd["id"] = serde_json::json!(id);
    upd["client_secret"] = serde_json::json!("");
    upd["bot_secret"] = serde_json::Value::Null;
    upd["enabled"] = serde_json::json!(false);
    let got = bot_admin(&app, "POST", Some(t), Some("admin"), Some(upd.clone())).await;
    assert_eq!(got.status, 200);
    assert_eq!(got.json()["name"], "b2");
    assert_eq!(got.json()["enabled"], false);
    assert_eq!(secrets_of(&id).await, (cs.clone(), bs.clone()));
    // 秘密値付きの更新は差し替える
    upd["client_secret"] = serde_json::json!("new-client");
    upd["bot_secret"] = serde_json::json!("new-bot");
    assert_eq!(
        bot_admin(&app, "POST", Some(t), Some("admin"), Some(upd.clone()))
            .await
            .status,
        200
    );
    let (cs2, bs2) = secrets_of(&id).await;
    assert_eq!(decrypt(&cs2), "new-client");
    assert_eq!(decrypt(&bs2.unwrap()), "new-bot");

    // 他社の path (tenant) からは更新も削除もできない
    let got = bot_admin(&app, "POST", Some(other), Some("admin"), Some(upd)).await;
    assert_eq!(got.status, 404);
    assert_eq!(got.json()["error"], "bot_config_not_found");
    let del = serde_json::json!({ "id": id });
    assert_eq!(
        bot_admin(
            &app,
            "DELETE",
            Some(other),
            Some("admin"),
            Some(del.clone())
        )
        .await
        .status,
        204
    );
    assert_eq!(secrets_of(&id).await.0, cs2, "他社からは消えない");
    // 自分の会社から消す (無くても 204)
    let got = bot_admin(&app, "DELETE", Some(t), Some("admin"), Some(del.clone())).await;
    assert_eq!(got.status, 204);
    assert!(got.body.is_empty());
    let n: i64 = admin()
        .await
        .query_one(
            "SELECT count(*) FROM alc_api.bot_configs WHERE id = $1",
            &[&Uuid::parse_str(&id).unwrap()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(n, 0);
    assert_eq!(
        bot_admin(&app, "DELETE", Some(t), Some("admin"), Some(del))
            .await
            .status,
        204
    );
    assert!(app.logs.lock().unwrap().is_empty());
}

/// 作成で client secret が無ければ空文字の暗号文 (移植元と同じ)、bot secret は NULL のまま。provider・enabled を受ける
#[tokio::test]
async fn bot_admin_create_without_secrets() {
    let app = app(Opts::default()).await;
    let t = tenant().await;
    let mut b = bot_body("n");
    b["client_secret"] = serde_json::Value::Null;
    b["bot_secret"] = serde_json::json!("");
    b["provider"] = serde_json::json!("lineworks");
    b["enabled"] = serde_json::json!(false);
    let got = bot_admin(&app, "POST", Some(t), Some("admin"), Some(b)).await;
    assert_eq!(got.status, 200);
    assert_eq!(got.json()["enabled"], false);
    let (cs, bs) = secrets_of(got.json()["id"].as_str().unwrap()).await;
    assert_eq!(decrypt(&cs), "");
    assert_eq!(bs, None);

    // 同じ provider・bot_id は会社をまたいで 409 (行は作らない)
    let other = tenant().await;
    let mut dup = bot_body("dup");
    dup["bot_id"] = got.json()["bot_id"].clone();
    let res = bot_admin(&app, "POST", Some(other), Some("admin"), Some(dup)).await;
    assert_eq!(res.status, 409);
    assert_eq!(
        res.json(),
        serde_json::json!({ "error": "bot_config_conflict" })
    );
    let list = bot_admin(&app, "GET", Some(other), Some("admin"), None).await;
    assert_eq!(list.json(), serde_json::json!({ "configs": [] }));
}

/// tenant 無しは 401、管理者でない・identity が無いは 403、形の違う body・id は 400、鍵が無ければ 500
#[tokio::test]
async fn bot_admin_rejections() {
    let app = app(Opts::default()).await;
    let t = tenant().await;
    for method in ["GET", "POST", "DELETE"] {
        assert_eq!(
            bot_admin(&app, method, None, Some("admin"), None)
                .await
                .status,
            401,
            "{method}"
        );
        for role in [Some("viewer"), None] {
            let got = bot_admin(&app, method, Some(t), role, Some(bot_body("x"))).await;
            assert_eq!(got.status, 403, "{method} {role:?}");
            assert_eq!(got.json(), serde_json::json!({ "error": "forbidden" }));
        }
    }
    for (method, body, code) in [
        ("POST", serde_json::json!({ "name": "x" }), "invalid_body"),
        (
            "POST",
            {
                let mut b = bot_body("x");
                b["id"] = serde_json::json!("x");
                b
            },
            "invalid_id",
        ),
        ("DELETE", serde_json::json!({}), "invalid_body"),
        ("DELETE", serde_json::json!({ "id": "x" }), "invalid_id"),
    ] {
        let got = bot_admin(&app, method, Some(t), Some("admin"), Some(body.clone())).await;
        assert_eq!(got.status, 400, "{method} {body}");
        assert_eq!(got.json()["error"], code, "{method} {body}");
    }
    let no_key = app_with_key(None).await;
    let got = bot_admin(&no_key, "POST", Some(t), Some("admin"), Some(bot_body("x"))).await;
    assert_eq!(got.status, 500);
    assert_eq!(
        got.json(),
        serde_json::json!({"error": "internal_error", "message": "encryption_key_missing"})
    );
    assert_eq!(
        *no_key.logs.lock().unwrap(),
        ["bot-admin: SSO_ENCRYPTION_KEY not set"]
    );
}

async fn app_with_key(key: Option<&'static str>) -> App {
    app(Opts {
        sso_key: key,
        ..Opts::default()
    })
    .await
}

/// DB の失敗は 500 `bot_config_failed` で、ログは段と kind だけ
#[tokio::test]
async fn bot_admin_db_failure_is_500() {
    let app = build(broken_client().await, Opts::default());
    let t = Uuid::new_v4();
    for (method, body) in [
        ("GET", None),
        ("POST", Some(bot_body("x"))),
        ("DELETE", Some(serde_json::json!({ "id": Uuid::new_v4() }))),
    ] {
        let got = bot_admin(&app, method, Some(t), Some("admin"), body).await;
        assert_eq!(got.status, 500, "{method}");
        assert_eq!(
            got.json(),
            serde_json::json!({"error": "internal_error", "message": "bot_config_failed"}),
            "{method}"
        );
    }
    let logs = app.logs.lock().unwrap().clone();
    assert_eq!(logs.len(), 3);
    for (log, stage) in logs.iter().zip(["list", "save", "delete"]) {
        assert!(
            log.starts_with(&format!("bot-admin: {stage} failed: db (")),
            "{log}"
        );
    }
}

fn decrypt(enc: &str) -> String {
    alc_worker_crypto::secret::decrypt_secret(enc, SSO_KEY).unwrap()
}

/// nuxt-leave の形の削除 `DELETE /api/admin/bot/configs/{id}`: 他社の id は消さず、自分の会社の id を消す (無くても 204)。
/// 管理者だけ・id の形
#[tokio::test]
async fn bot_admin_delete_by_path() {
    let app = app(Opts::default()).await;
    let (t, other) = (tenant().await, tenant().await);
    let b = bot(t, "by-path", "lineworks", true).await;
    let path = format!("{BOT_CONFIGS}/{}", b.id);
    assert_eq!(
        bot_admin_at(&app, &path, "DELETE", Some(t), Some("viewer"), None)
            .await
            .status,
        403
    );
    assert_eq!(
        bot_admin_at(&app, &path, "DELETE", Some(other), Some("admin"), None)
            .await
            .status,
        204
    );
    let count = || async {
        let n: i64 = admin()
            .await
            .query_one(
                "SELECT count(*) FROM alc_api.bot_configs WHERE id = $1",
                &[&b.id],
            )
            .await
            .unwrap()
            .get(0);
        n
    };
    assert_eq!(count().await, 1, "他社からは消えない");
    let got = bot_admin_at(&app, &path, "DELETE", Some(t), Some("admin"), None).await;
    assert_eq!(got.status, 204);
    assert!(got.body.is_empty());
    assert_eq!(count().await, 0);
    let got = bot_admin_at(
        &app,
        &format!("{BOT_CONFIGS}/x"),
        "DELETE",
        Some(t),
        Some("admin"),
        None,
    )
    .await;
    assert_eq!(got.status, 400);
    assert_eq!(got.json()["error"], "invalid_id");
}
