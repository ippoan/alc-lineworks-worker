//! crates/lineworks の [`Http`] の Workers での実装 (`worker::Fetch` で外へ POST・GET する)。
//! GET は `redirect: "manual"` で、3xx をそのまま返す (`Location` は crates/lineworks の `Client::get` が
//! `Authorization` を付け直して辿る。自動で追うと別ホストへの 302 で `Authorization` が落ちる)。
//!
//! 値と future は JS の値で `Send` でないので、`worker::send` の `SendFuture` で包む (Workers は単一 thread)。
//! エラーは中身を持たない [`HttpError`] に落とす (URL・ヘッダー・ランタイムの生のエラー文をログに出さない)。
//!
//! このファイルは wasm 専用で、CI のテストと coverage の gate の外 (確かめるのは staging / 本番の実物)。

use futures_util::future::BoxFuture;
use lineworks::client::{Http, HttpError, HttpRequest, HttpResponse};
use wasm_bindgen::JsValue;
use worker::send::SendFuture;
use worker::{Fetch, Headers, Method, Request, RequestInit, RequestRedirect};

/// LINE WORKS の応答の本文の上限 (token・エラーの応答は小さい)
const BODY_LIMIT: usize = 1024 * 1024;
/// GET の本文の上限 (監査ログの CSV は 30 日分の全員のログイン・送信で大きくなる)
const GET_BODY_LIMIT: usize = 32 * 1024 * 1024;

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
                location: None,
            })
        }))
    }

    fn get(
        &self,
        url: String,
        authorization: String,
    ) -> BoxFuture<'_, Result<HttpResponse, HttpError>> {
        Box::pin(SendFuture::new(async move {
            let headers = Headers::new();
            headers
                .set("Authorization", &authorization)
                .map_err(|_| HttpError)?;
            let mut init = RequestInit::new();
            init.with_method(Method::Get)
                .with_headers(headers)
                .with_redirect(RequestRedirect::Manual);
            let request = Request::new_with_init(&url, &init).map_err(|_| HttpError)?;
            let mut resp = Fetch::Request(request)
                .send()
                .await
                .map_err(|_| HttpError)?;
            let status = resp.status_code();
            if (300..400).contains(&status) {
                let location = resp.headers().get("Location").map_err(|_| HttpError)?;
                return Ok(HttpResponse {
                    status,
                    body: Vec::new(),
                    location,
                });
            }
            let bytes = resp.bytes().await.map_err(|_| HttpError)?;
            if bytes.len() > GET_BODY_LIMIT {
                return Err(HttpError);
            }
            Ok(HttpResponse {
                status,
                body: bytes,
                location: None,
            })
        }))
    }
}

/// 本文 (form と JSON。どちらも UTF-8 の文字列)
fn body_value(body: &[u8]) -> JsValue {
    JsValue::from_str(&String::from_utf8_lossy(body))
}
