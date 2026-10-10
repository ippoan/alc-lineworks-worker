//! crates/lineworks の [`Http`] の Workers での実装 (`worker::Fetch` で外へ POST する)。
//!
//! 値と future は JS の値で `Send` でないので、`worker::send` の `SendFuture` で包む (Workers は単一 thread)。
//! エラーは中身を持たない [`HttpError`] に落とす (URL・ヘッダー・ランタイムの生のエラー文をログに出さない)。
//!
//! このファイルは wasm 専用で、CI のテストと coverage の gate の外 (確かめるのは staging / 本番の実物)。

use futures_util::future::BoxFuture;
use lineworks::client::{Http, HttpError, HttpRequest, HttpResponse};
use wasm_bindgen::JsValue;
use worker::send::SendFuture;
use worker::{Fetch, Headers, Method, Request, RequestInit};

/// LINE WORKS の応答の本文の上限 (token・エラーの応答は小さい)
const BODY_LIMIT: usize = 1024 * 1024;

pub struct WorkerHttp;

impl Http for WorkerHttp {
    fn post(&self, req: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, HttpError>> {
        Box::pin(SendFuture::new(async move {
            let headers = Headers::new();
            headers
                .set("Content-Type", req.content_type)
                .map_err(|_| HttpError)?;
            if let Some(auth) = &req.authorization {
                headers.set("Authorization", auth).map_err(|_| HttpError)?;
            }
            let body = body_value(&req.body);
            let mut init = RequestInit::new();
            init.with_method(Method::Post)
                .with_headers(headers)
                .with_body(Some(body));
            let request = Request::new_with_init(&req.url, &init).map_err(|_| HttpError)?;
            let mut resp = Fetch::Request(request)
                .send()
                .await
                .map_err(|_| HttpError)?;
            let status = resp.status_code();
            let bytes = resp.bytes().await.map_err(|_| HttpError)?;
            if bytes.len() > BODY_LIMIT {
                return Err(HttpError);
            }
            Ok(HttpResponse {
                status,
                body: bytes,
            })
        }))
    }
}

/// 本文 (form と JSON。どちらも UTF-8 の文字列)
fn body_value(body: &[u8]) -> JsValue {
    JsValue::from_str(&String::from_utf8_lossy(body))
}
