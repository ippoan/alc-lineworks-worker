//! LINE WORKS のログイン状況の集計 (rust-alc-api の `alc-notify::lineworks_login_activity` の `get_login_activity`・
//! `get_or_fetch_login_activity` と、`clients::lineworks::parse_login_audit_csv` の移植。Refs ippoan/rust-alc-api#747)。
//!
//! 最終アクティブ日時は 3 つの信号のうち一番新しいもの (分かっている下限):
//! 1. `service=auth` の監査ログ (明示のログイン。**これだけは必須** で、失敗は口の失敗)
//! 2. `service=message` の監査ログ (トークの送信。best-effort)
//! 3. 掲示板の既読 (既読の投稿の作成日時を下限にする。best-effort)
//!
//! 2 と 3 の失敗はログに固定の語を残して捨てる。監査ログの窓は [`AUDIT_WINDOW_DAYS`] 日 (API の上限 31 日ちょうどは
//! LINE WORKS に断られる)。`days` は窓の中で「N 日以上ログインなし」を決めるしきい値。
//!
//! 監査ログの API は「並行して呼び出さないでください」とある。isolate の中で [`ActivityCache`] の lock を握ったまま取り、
//! (tenant, Client ID) ごとに [`CACHE_TTL_SECS`] 秒使い回す (rust の `CACHE_TTL_SECS` と同じ。isolate をまたいでは効かない)。

use std::collections::HashMap;

use chrono::{DateTime, Duration, FixedOffset, NaiveDateTime, TimeZone, Utc};
use futures_util::lock::Mutex;
use serde::Serialize;
use uuid::Uuid;

use crate::client::{Client, Credentials, LineworksMember, SendError};

/// 監査ログを取る窓 (日)。31 ちょうどは LINE WORKS が `LIMIT_EXCEEDED` で断る (rust の 2026-09-11 の実測)
pub const AUDIT_WINDOW_DAYS: i64 = 30;
/// 合成の結果を使い回す秒数
pub const CACHE_TTL_SECS: u64 = 300;
/// `days` が無いときのしきい値
pub const DEFAULT_DAYS: i64 = 3;

/// email (小文字) → その信号の最終日時
pub type LastLoginByEmail = HashMap<String, DateTime<Utc>>;

/// 1 人分の行 (rust の `LoginActivityEntry` と同じ JSON)
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoginActivityEntry {
    pub user_id: String,
    pub user_name: Option<String>,
    pub email: Option<String>,
    /// RFC3339。記録なしは `null`
    pub last_login_at: Option<String>,
    /// 記録なしは `null`
    pub days_since_login: Option<i64>,
    /// 記録なし、または `days` 日以上ログインなし
    pub stale: bool,
    /// `last_login_at` を出した信号 (`auth` / `message` / `board`)。記録なしは `null`
    pub last_login_source: Option<&'static str>,
}

/// 3 つの信号の合成 (`combined`) と、信号ごとの内訳 (`last_login_source` を決めるため)
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CombinedActivity {
    pub combined: LastLoginByEmail,
    pub auth: LastLoginByEmail,
    pub message: LastLoginByEmail,
    pub board: LastLoginByEmail,
}

/// 集計の失敗 (必須の auth の監査ログだけ)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivityError {
    /// 取れなかった
    Upstream(SendError),
    /// CSV の見出しが読めない (固定の語。見出しの中身は載せない)
    Csv(&'static str),
}

type CacheKey = (Uuid, String);

/// isolate の中の合成の結果の置き場 ((tenant, Client ID) → (取った時刻の UNIX 秒, 結果))
#[derive(Default)]
pub struct ActivityCache(Mutex<HashMap<CacheKey, (u64, CombinedActivity)>>);

impl ActivityCache {
    /// 持っている結果の数 (テスト用)
    pub async fn count(&self) -> usize {
        self.0.lock().await.len()
    }
}

pub fn to_datetime(unix_secs: u64) -> DateTime<Utc> {
    i64::try_from(unix_secs)
        .ok()
        .and_then(|s| DateTime::from_timestamp(s, 0))
        .unwrap_or_default()
}

/// cache に新しい結果があればそれを、無ければ lock を握ったまま取る (同じ isolate の中で監査ログの API を並行に呼ばない)
pub async fn get_or_fetch(
    cache: &ActivityCache,
    tenant_id: Uuid,
    client: &Client<'_>,
    creds: &Credentials,
    private_key_pem: &str,
    members: &[LineworksMember],
    log: &(dyn Fn(&str) + Send + Sync),
) -> Result<CombinedActivity, ActivityError> {
    let mut guard = cache.0.lock().await;
    let key = (tenant_id, creds.client_id.clone());
    if let Some((fetched_at, activity)) = guard.get(&key) {
        if client.now.saturating_sub(*fetched_at) < CACHE_TTL_SECS {
            return Ok(activity.clone());
        }
    }
    let activity = fetch(client, creds, private_key_pem, members, log).await?;
    guard.insert(key, (client.now, activity.clone()));
    Ok(activity)
}

async fn fetch(
    client: &Client<'_>,
    creds: &Credentials,
    pem: &str,
    members: &[LineworksMember],
    log: &(dyn Fn(&str) + Send + Sync),
) -> Result<CombinedActivity, ActivityError> {
    let now = to_datetime(client.now);
    let start = now - Duration::days(AUDIT_WINDOW_DAYS);

    let auth_csv = client
        .fetch_audit_csv(creds, pem, "auth", start, now)
        .await
        .map_err(ActivityError::Upstream)?;
    let auth = parse_login_audit_csv(&auth_csv).map_err(ActivityError::Csv)?;

    let message = match client
        .fetch_audit_csv(creds, pem, "message", start, now)
        .await
    {
        Ok(csv) => parse_login_audit_csv(&csv).unwrap_or_else(|e| {
            log(&format!("lineworks-read: message audit skipped: {e}"));
            HashMap::new()
        }),
        Err(e) => {
            log(&format!("lineworks-read: message audit skipped: {e}"));
            HashMap::new()
        }
    };

    let board = match client
        .fetch_board_activity_lower_bound(creds, pem, start)
        .await
    {
        Ok(by_user_id) => {
            let email_by_user_id: HashMap<&str, &str> = members
                .iter()
                .filter_map(|m| m.email.as_deref().map(|e| (m.user_id.as_str(), e)))
                .collect();
            by_user_id
                .into_iter()
                .filter_map(|(user_id, dt)| {
                    email_by_user_id
                        .get(user_id.as_str())
                        .map(|e| (e.to_lowercase(), dt))
                })
                .collect()
        }
        Err(e) => {
            log(&format!("lineworks-read: board activity skipped: {e}"));
            HashMap::new()
        }
    };

    Ok(combine_activity(auth, message, board))
}

/// 3 つを email ごとに一番新しい値へ合成し、内訳もそのまま持つ
pub fn combine_activity(
    auth: LastLoginByEmail,
    message: LastLoginByEmail,
    board: LastLoginByEmail,
) -> CombinedActivity {
    let mut combined = auth.clone();
    merge_keep_latest(&mut combined, message.clone());
    merge_keep_latest(&mut combined, board.clone());
    CombinedActivity {
        combined,
        auth,
        message,
        board,
    }
}

/// 合成の値と等しい信号を auth → message → board の順に探す (同じ時刻なら auth > message > board)
pub fn activity_source(activity: &CombinedActivity, email: &str) -> Option<&'static str> {
    let latest = activity.combined.get(email)?;
    [
        ("auth", &activity.auth),
        ("message", &activity.message),
        ("board", &activity.board),
    ]
    .into_iter()
    .find(|(_, signal)| signal.get(email) == Some(latest))
    .map(|(source, _)| source)
}

/// 同じキーは新しい方を残す
pub fn merge_keep_latest(base: &mut LastLoginByEmail, other: LastLoginByEmail) {
    for (email, dt) in other {
        let cur = base.entry(email).or_insert(dt);
        *cur = (*cur).max(dt);
    }
}

/// メンバーごとの行。「記録なし」が先頭、その次はログインが古い順 (同じなら members の順。rust と同じ)
pub fn entries(
    members: Vec<LineworksMember>,
    activity: &CombinedActivity,
    now: DateTime<Utc>,
    days: i64,
) -> Vec<LoginActivityEntry> {
    let mut entries: Vec<LoginActivityEntry> = members
        .into_iter()
        .map(|m| {
            let email = m.email.as_ref().map(|e| e.to_lowercase());
            let last = email
                .as_ref()
                .and_then(|e| activity.combined.get(e).copied());
            let days_since_login = last.map(|dt| (now - dt).num_days());
            LoginActivityEntry {
                last_login_source: email.as_deref().and_then(|e| activity_source(activity, e)),
                last_login_at: last.map(|dt| dt.to_rfc3339()),
                stale: days_since_login.is_none_or(|d| d >= days),
                days_since_login,
                user_id: m.user_id,
                user_name: m.user_name,
                email: m.email,
            }
        })
        .collect();
    entries.sort_by(|a, b| match (a.days_since_login, b.days_since_login) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Less,
        (Some(_), None) => std::cmp::Ordering::Greater,
        (Some(x), Some(y)) => y.cmp(&x),
    });
    entries
}

/// 監査ログの CSV を email ごとの「成功した行の最終日時」にする (rust の `parse_login_audit_csv`)。
///
/// - `service=auth`: `説明,メンバー,日時,IPアドレス,ログイン方法,サービスタイプ`。メンバーは `表示名 (email)`。
///   成否は「説明」の文 (「成功」を含むか)
/// - `service=message`: `日時,送信者,受信者,チャンネルID,イベント`。人の列は「送信者」。成否の列は無く全行が有効
///
/// 人・日時の列が見つからなければ `Err` (黙って空にしない)。誤りの語は固定 (見出しの中身は載せない)
pub fn parse_login_audit_csv(csv_text: &str) -> Result<LastLoginByEmail, &'static str> {
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(csv_text.as_bytes());
    // &str から読むので UTF-8 の誤りは起きず、flexible なので列の数の誤りも起きない (読めない行は飛ばす)
    let headers = rdr.headers().cloned().unwrap_or_default();
    let member_idx = find_column(
        &headers,
        &[
            "メンバー",
            "member",
            "送信者",
            "sender",
            "メール",
            "email",
            "mail",
        ],
    )
    .ok_or("member/email column not found")?;
    let datetime_idx = find_column(&headers, &["日時", "datetime", "time", "date"])
        .ok_or("datetime column not found")?;
    let result_idx = find_column(&headers, &["結果", "result", "説明", "description"]);

    let mut last: LastLoginByEmail = HashMap::new();
    for row in rdr.records().flatten() {
        if let Some(idx) = result_idx {
            if !row.get(idx).is_some_and(is_success_result) {
                continue;
            }
        }
        let Some(email) = row
            .get(member_idx)
            .and_then(extract_email_from_member_field)
        else {
            continue;
        };
        let Some(dt) = row.get(datetime_idx).and_then(parse_audit_datetime) else {
            continue;
        };
        let cur = last.entry(email.to_lowercase()).or_insert(dt);
        *cur = (*cur).max(dt);
    }
    Ok(last)
}

/// 見出しからキーワード (部分一致・大文字小文字を見ない) を含む最初の列
fn find_column(headers: &csv::StringRecord, keywords: &[&str]) -> Option<usize> {
    headers.iter().position(|h| {
        let h = h.to_lowercase();
        keywords.iter().any(|k| h.contains(&k.to_lowercase()))
    })
}

/// `表示名 (email)` の括弧の中、無ければ素の email。`@` が無ければ `None`
pub fn extract_email_from_member_field(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if let Some(open) = raw.rfind('(') {
        if let Some(close) = raw[open + 1..].find(')') {
            let inner = raw[open + 1..open + 1 + close].trim();
            if inner.contains('@') {
                return Some(inner.to_owned());
            }
        }
    }
    raw.contains('@').then(|| raw.to_owned())
}

/// 「説明」(か「結果」) がログインの成功を表すか
pub fn is_success_result(value: &str) -> bool {
    let v = value.trim();
    v.contains("成功") || v.eq_ignore_ascii_case("success") || v.eq_ignore_ascii_case("OK")
}

/// 「日時」の値。タイムゾーン付き (RFC3339) を先に、無ければ JST の時刻として読む
pub fn parse_audit_datetime(raw: &str) -> Option<DateTime<Utc>> {
    let raw = raw.trim();
    if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
        return Some(dt.with_timezone(&Utc));
    }
    let jst = FixedOffset::east_opt(9 * 3600)?;
    [
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M",
        "%Y-%m-%d %H:%M",
    ]
    .into_iter()
    .find_map(|fmt| NaiveDateTime::parse_from_str(raw, fmt).ok())
    .and_then(|naive| jst.from_local_datetime(&naive).single())
    .map(|dt| dt.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(days_ago: i64) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-09-11T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
            - Duration::days(days_ago)
    }

    fn one(email: &str, dt: DateTime<Utc>) -> LastLoginByEmail {
        HashMap::from([(email.to_owned(), dt)])
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn audit_window_stays_under_the_31_day_api_limit() {
        // 31 ちょうどは LINE WORKS に断られる (失敗の文を別の行に置くと、古い toolchain の coverage がその行を未実行と数える)
        assert!(AUDIT_WINDOW_DAYS < 31);
        assert_eq!((CACHE_TTL_SECS, DEFAULT_DAYS), (300, 3));
    }

    #[test]
    fn csv_keeps_latest_success_per_email() {
        let csv = "説明,メンバー,日時,IPアドレス,ログイン方法,サービスタイプ\n\
                    ログインに成功しました,山田太郎 (a@x.com),2026/09/01 09:00:00,1.2.3.4,パスワード,ブラウザ\n\
                    ログインに成功しました,山田太郎 (a@x.com),2026/09/03 10:30:00,1.2.3.4,パスワード,モバイルアプリ\n\
                    ログインに成功しました,山田太郎 (a@x.com),2026/09/02 10:30:00,1.2.3.4,パスワード,モバイルアプリ\n\
                    ログインに失敗しました (エラーコード: 401),鈴木花子 (b@x.com),2026/09/02 08:00:00,5.6.7.8,パスワード,ブラウザ\n\
                    ログインに成功しました,部署 (営業部),2026/09/02 08:00:00,5.6.7.8,パスワード,ブラウザ\n\
                    ログインに成功しました,c@x.com,not-a-date,5.6.7.8,パスワード,ブラウザ\n";
        let result = parse_login_audit_csv(csv).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result["a@x.com"].to_rfc3339(), "2026-09-03T01:30:00+00:00");
    }

    #[test]
    fn csv_variants() {
        // 大文字小文字・前後の空白
        let r = parse_login_audit_csv(
            "説明,メンバー,日時\nログインに成功しました, 山田太郎 (A@X.com) ,2026/09/01 09:00:00\n",
        )
        .unwrap();
        assert!(r.contains_key("a@x.com"));
        // 素の email
        let r = parse_login_audit_csv(
            "説明,メンバー,日時\nログインに成功しました,a@x.com,2026/09/01 09:00:00\n",
        )
        .unwrap();
        assert!(r.contains_key("a@x.com"));
        // service=message: 送信者の列だけ (受信者は拾わない)、成否の列が無いので全行が有効
        let r = parse_login_audit_csv(
            "日時,送信者,受信者,チャンネルID,イベント\n\
             2026/09/01 09:00:00,山田太郎 (a@x.com),鈴木花子 (b@x.com),c1,送信\n",
        )
        .unwrap();
        assert_eq!(r.keys().collect::<Vec<_>>(), ["a@x.com"]);
        // 成否の列が無い見出し
        let r = parse_login_audit_csv("メンバー,日時\n山田太郎 (a@x.com),2026/09/01 09:00:00\n")
            .unwrap();
        assert!(r.contains_key("a@x.com"));
        // 英語の見出し・列が足りない行
        let r = parse_login_audit_csv(
            "DateTime,Email,Result\n2026-09-01T00:00:00+09:00,a@x.com,Success\n2026-09-02\n",
        )
        .unwrap();
        assert_eq!(r["a@x.com"].to_rfc3339(), "2026-08-31T15:00:00+00:00");
    }

    #[test]
    fn csv_fails_loudly_on_unrecognized_headers() {
        assert_eq!(
            parse_login_audit_csv("col_a,col_b\n1,2\n"),
            Err("member/email column not found")
        );
        assert_eq!(
            parse_login_audit_csv("メンバー,col_b\n1,2\n"),
            Err("datetime column not found")
        );
        assert_eq!(
            parse_login_audit_csv(""),
            Err("member/email column not found")
        );
        // 閉じない引用符は行の終わりまでを 1 つの値として読む (日時が読めないので数えない)
        assert_eq!(
            parse_login_audit_csv("メンバー,日時\n\"a@x.com,2026\n").map(|m| m.len()),
            Ok(0)
        );
    }

    #[test]
    fn member_field() {
        let e = extract_email_from_member_field;
        assert_eq!(
            e("山田太郎 (demo@example.com)").as_deref(),
            Some("demo@example.com")
        );
        assert_eq!(e("demo@example.com").as_deref(), Some("demo@example.com"));
        assert_eq!(e("山田太郎 (営業部)"), None);
        assert_eq!(e("山田太郎 (営業部"), None);
        assert_eq!(e("山田太郎"), None);
        assert_eq!(e(""), None);
    }

    #[test]
    fn success_result() {
        for ok in ["成功", "ログインに成功しました", " success ", "OK"] {
            assert!(is_success_result(ok));
        }
        for ng in [
            "失敗",
            "ログインに失敗しました (エラーコード: 401)",
            "failure",
        ] {
            assert!(!is_success_result(ng));
        }
    }

    #[test]
    fn audit_datetime() {
        let p = |s| parse_audit_datetime(s).map(|d| d.to_rfc3339());
        assert_eq!(
            p("2026-09-01T00:00:00+09:00").as_deref(),
            Some("2026-08-31T15:00:00+00:00")
        );
        assert_eq!(
            p("2026/09/01 09:00:00").as_deref(),
            Some("2026-09-01T00:00:00+00:00")
        );
        assert_eq!(
            p("2026-09-01 09:00").as_deref(),
            Some("2026-09-01T00:00:00+00:00")
        );
        assert_eq!(p("not-a-date"), None);
        assert_eq!(p(""), None);
    }

    #[test]
    fn merge_keeps_newer() {
        let mut base = one("a@x.com", at(10));
        merge_keep_latest(
            &mut base,
            HashMap::from([("a@x.com".into(), at(2)), ("b@x.com".into(), at(5))]),
        );
        assert_eq!((base["a@x.com"], base["b@x.com"]), (at(2), at(5)));
        merge_keep_latest(&mut base, one("a@x.com", at(20)));
        assert_eq!(base["a@x.com"], at(2), "古い方では上書きしない");
    }

    #[test]
    fn combine_keeps_per_signal_breakdown() {
        let auth = one("a@x.com", at(10));
        let message = HashMap::from([("a@x.com".into(), at(5)), ("b@x.com".into(), at(3))]);
        let board = HashMap::from([("a@x.com".into(), at(20)), ("c@x.com".into(), at(1))]);
        let a = combine_activity(auth.clone(), message.clone(), board.clone());
        assert_eq!(
            (
                a.combined["a@x.com"],
                a.combined["b@x.com"],
                a.combined["c@x.com"]
            ),
            (at(5), at(3), at(1))
        );
        assert_eq!((&a.auth, &a.message, &a.board), (&auth, &message, &board));
        assert_eq!(activity_source(&a, "a@x.com"), Some("message"));
        assert_eq!(activity_source(&a, "b@x.com"), Some("message"));
        assert_eq!(activity_source(&a, "c@x.com"), Some("board"));
    }

    #[test]
    fn sources() {
        let e = "demo@example.com";
        let none = HashMap::new;
        let src = |a, m, b| activity_source(&combine_activity(a, m, b), e);
        assert_eq!(src(one(e, at(3)), none(), none()), Some("auth"));
        assert_eq!(src(one(e, at(10)), one(e, at(2)), none()), Some("message"));
        assert_eq!(
            src(one(e, at(10)), one(e, at(5)), one(e, at(1))),
            Some("board")
        );
        assert_eq!(src(one("other@example.com", at(1)), none(), none()), None);
        assert_eq!(src(one(e, at(4)), one(e, at(4)), none()), Some("auth"));
    }

    fn m(id: &str, email: Option<&str>) -> LineworksMember {
        LineworksMember {
            user_id: id.into(),
            user_name: Some(format!("名前 {id}")),
            email: email.map(Into::into),
        }
    }

    #[test]
    fn entries_threshold_and_order() {
        let activity = combine_activity(
            HashMap::from([("a@x.com".into(), at(1)), ("b@x.com".into(), at(3))]),
            one("c@x.com", at(10)),
            HashMap::new(),
        );
        let members = vec![
            m("a", Some("A@x.com")),
            m("none-1", None),
            m("b", Some("b@x.com")),
            m("c", Some("c@x.com")),
            m("none-2", Some("z@x.com")),
        ];
        let got = entries(members, &activity, at(0), 3);
        let order: Vec<_> = got
            .iter()
            .map(|e| (e.user_id.as_str(), e.days_since_login, e.stale))
            .collect();
        assert_eq!(
            order,
            [
                ("none-1", None, true),
                ("none-2", None, true),
                ("c", Some(10), true),
                ("b", Some(3), true),
                ("a", Some(1), false),
            ]
        );
        assert_eq!(
            serde_json::to_value(&got[4]).unwrap(),
            serde_json::json!({
                "user_id": "a",
                "user_name": "名前 a",
                "email": "A@x.com",
                "last_login_at": "2026-09-10T00:00:00+00:00",
                "days_since_login": 1,
                "stale": false,
                "last_login_source": "auth",
            })
        );
        assert_eq!(got[2].last_login_source, Some("message"));
        assert_eq!(
            serde_json::to_value(&got[0]).unwrap(),
            serde_json::json!({
                "user_id": "none-1",
                "user_name": "名前 none-1",
                "email": null,
                "last_login_at": null,
                "days_since_login": null,
                "stale": true,
                "last_login_source": null,
            })
        );
        // days = 0 なら記録のある人も全員 stale。半端な時間は切り捨て
        let got = entries(
            vec![m("a", Some("a@x.com"))],
            &activity,
            at(1) + Duration::hours(23),
            0,
        );
        assert_eq!((got[0].days_since_login, got[0].stale), (Some(0), true));
    }

    #[test]
    fn unix_seconds() {
        assert_eq!(to_datetime(0).to_rfc3339(), "1970-01-01T00:00:00+00:00");
        assert_eq!(to_datetime(u64::MAX), DateTime::<Utc>::default());
    }
}
