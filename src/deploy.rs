//! デプロイの確認の口の「この版でもう送った」の記録 ([`SentRecord`]) の Workers での実装。
//! Cache API の `caches.default` に、版の id を鍵にした 1 件を置く (KV・DB は使わない)。
//! colo ごとの記録なので、別の colo から叩けば 2 通目が出得る (許容)。読めない・書けないは「送っていない」扱い。
//!
//! JS の値で `Send` でないので `SendFuture` で包む (src/http.rs と同じ)。wasm 専用で、CI のテストと coverage の gate の外。

use futures_util::future::BoxFuture;
use lineworks::SentRecord;
use worker::send::SendFuture;
use worker::{console_error, Cache, Response};

/// 鍵の URL の頭 (Cache API の鍵は URL。予約済みの TLD `.invalid` で、外へは出ない)
const KEY_PREFIX: &str = "https://deploy-check.invalid/alc-lineworks/";
/// 記録を残す長さ (1 年。追い出されたら 2 通目が出得る)
const MAX_AGE: &str = "max-age=31536000";

pub struct CacheRecord;

fn key(version: &str) -> String {
    format!("{KEY_PREFIX}{version}")
}

impl SentRecord for CacheRecord {
    fn sent(&self, version: String) -> BoxFuture<'_, bool> {
        Box::pin(SendFuture::new(async move {
            matches!(Cache::default().get(key(&version), true).await, Ok(Some(_)))
        }))
    }

    fn record(&self, version: String) -> BoxFuture<'_, ()> {
        Box::pin(SendFuture::new(async move {
            let put = async {
                let mut resp = Response::ok("sent")?;
                resp.headers_mut().set("Cache-Control", MAX_AGE)?;
                Cache::default().put(key(&version), resp).await
            };
            if put.await.is_err() {
                console_error!("lineworks-deploy-check: record failed");
            }
        }))
    }
}
