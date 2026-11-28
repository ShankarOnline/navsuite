//! HTTP routes for the phone drop page.
//!
//! Public: `/`, `/app.js`, `/app.css`, `/icon.svg`, `/join?k=CODE`.
//! Everything under `/api/` requires the device cookie (401 otherwise);
//! mutating requests additionally require the `X-Drop: 1` header (CSRF).

use crate::{CHUNK_SIZE, DropFile, Inner, JoinError, Phone, SYSTEM, util};
use axum::body::Body;
use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRequestParts, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header, request::Parts};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

pub(crate) const COOKIE: &str = "nsdrop";
const INDEX_HTML: &str = include_str!("../assets/index.html");
const APP_JS: &str = include_str!("../assets/app.js");
const APP_CSS: &str = include_str!("../assets/app.css");
const ICON_SVG: &str = include_str!("../assets/icon.svg");

type St = State<Arc<Inner>>;

pub(crate) fn router(inner: Arc<Inner>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(|| async { asset(APP_JS, "text/javascript; charset=utf-8") }))
        .route("/app.css", get(|| async { asset(APP_CSS, "text/css; charset=utf-8") }))
        .route("/icon.svg", get(|| async { asset(ICON_SVG, "image/svg+xml") }))
        .route("/join", get(join))
        .route("/api/me", get(me).post(set_name))
        .route("/api/leave", post(leave))
        .route("/api/inbox", get(inbox))
        .route("/api/upload", post(create_upload))
        .route("/api/upload/{id}", get(upload_status).put(put_chunk).delete(cancel_upload))
        .route("/api/files/{id}", get(download).delete(dismiss))
        .layer(DefaultBodyLimit::max(CHUNK_SIZE as usize + (1 << 20)))
        .layer(axum::middleware::map_response(security_headers))
        .with_state(inner)
}

async fn security_headers(mut r: Response) -> Response {
    let h = r.headers_mut();
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'"),
    );
    h.entry(header::CACHE_CONTROL).or_insert(HeaderValue::from_static("no-store"));
    r
}

fn asset(body: &'static str, ctype: &'static str) -> Response {
    ([(header::CONTENT_TYPE, ctype), (header::CACHE_CONTROL, "no-cache")], body).into_response()
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

fn err(status: u16, msg: impl Into<String>) -> Response {
    let s = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (s, Json(json!({ "error": msg.into() }))).into_response()
}

fn message_page(status: StatusCode, title: &str, text: &str) -> Response {
    let esc = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    let html = format!(
        "<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">\
         <link rel=stylesheet href=/app.css><title>{t}</title><main class=msg><h1>{t}</h1><p>{x}</p>\
         <p><a class=btn href=/>Open drop page</a></p></main></html>",
        t = esc(title),
        x = esc(text)
    );
    (status, Html(html)).into_response()
}

/// Client IP from the connection (absent in unit tests unless inserted).
pub(crate) struct ClientIp(pub Option<IpAddr>);

impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = std::convert::Infallible;
    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        Ok(ClientIp(parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip())))
    }
}

fn cookie_token(h: &HeaderMap) -> Option<String> {
    h.get_all(header::COOKIE).iter().filter_map(|v| v.to_str().ok()).find_map(|v| {
        v.split(';').find_map(|kv| {
            let (k, val) = kv.trim().split_once('=')?;
            (k == COOKIE && !val.is_empty()).then(|| val.to_string())
        })
    })
}

/// A joined device, authenticated by cookie.
pub(crate) struct Device(pub Phone);

impl FromRequestParts<Arc<Inner>> for Device {
    type Rejection = Response;
    async fn from_request_parts(parts: &mut Parts, inner: &Arc<Inner>) -> Result<Self, Self::Rejection> {
        let ip = parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip());
        let phone = cookie_token(&parts.headers)
            .and_then(|t| inner.auth(&t, ip))
            .ok_or_else(|| err(401, "not joined: scan the QR code on the computer"))?;
        let safe = matches!(parts.method, Method::GET | Method::HEAD);
        if !safe && parts.headers.get("x-drop").and_then(|v| v.to_str().ok()) != Some("1") {
            return Err(err(403, "missing X-Drop header"));
        }
        Ok(Device(phone))
    }
}

fn set_cookie(token: &str, tls: bool, max_age: u64) -> HeaderValue {
    let secure = if tls { "; Secure" } else { "" };
    HeaderValue::from_str(&format!("{COOKIE}={token}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Strict{secure}"))
        .unwrap_or(HeaderValue::from_static(""))
}

#[derive(Deserialize)]
struct JoinQ {
    k: Option<String>,
}

async fn join(State(inner): St, ClientIp(ip): ClientIp, headers: HeaderMap, Query(q): Query<JoinQ>) -> Response {
    let Some(k) = q.k.filter(|k| !k.trim().is_empty()) else {
        return Redirect::to("/").into_response();
    };
    if cookie_token(&headers).and_then(|t| inner.auth(&t, ip)).is_some() {
        return Redirect::to("/").into_response();
    }
    if !inner.join_allowed(ip) {
        return message_page(StatusCode::TOO_MANY_REQUESTS, "Too many attempts", "Wait a few minutes and scan a new QR code.");
    }
    let ua = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("");
    match inner.join(&k, ua, ip) {
        Ok((_, token)) => {
            let mut r = Redirect::to("/?welcome=1").into_response();
            r.headers_mut().insert(header::SET_COOKIE, set_cookie(&token, inner.tls, 400 * 24 * 3600));
            r
        }
        Err(JoinError::BadCode) => message_page(
            StatusCode::FORBIDDEN,
            "Code expired",
            "This join code has expired or was already used. Show a new QR code on the computer and scan it again.",
        ),
        Err(JoinError::Full) => message_page(
            StatusCode::FORBIDDEN,
            "Too many phones",
            "This computer already has the maximum number of phones. Remove one in narada first.",
        ),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Peer {
    id: String,
    name: String,
    platform: String,
}

async fn me(State(inner): St, Device(me): Device) -> Response {
    let peers: Vec<Peer> = inner
        .phones()
        .into_iter()
        .filter(|p| p.id != me.id)
        .map(|p| Peer { id: p.id, name: p.name, platform: p.platform })
        .collect();
    Json(json!({
        "me": me,
        "computer": { "id": SYSTEM, "name": inner.cfg.device_name },
        "peers": peers,
        "chunkSize": CHUNK_SIZE,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct NameBody {
    name: String,
}

async fn set_name(State(inner): St, Device(me): Device, Json(b): Json<NameBody>) -> Response {
    if inner.rename(&me.id, &b.name) {
        Json(json!({ "ok": true })).into_response()
    } else {
        err(400, "invalid name")
    }
}

async fn leave(State(inner): St, Device(me): Device) -> Response {
    inner.forget(&me.id);
    let mut r = Json(json!({ "ok": true })).into_response();
    r.headers_mut().insert(header::SET_COOKIE, set_cookie("", inner.tls, 0));
    r
}

/// File as shown to a phone (no server path).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FileView {
    id: String,
    name: String,
    size: u64,
    sha256: String,
    from: String,
    from_name: String,
    received: u64,
    expires: u64,
}

fn view(inner: &Inner, f: &DropFile) -> FileView {
    let from_name = if f.from == SYSTEM {
        inner.cfg.device_name.clone()
    } else {
        inner.phones().into_iter().find(|p| p.id == f.from).map(|p| p.name).unwrap_or_else(|| "a phone".into())
    };
    FileView {
        id: f.id.clone(),
        name: f.name.clone(),
        size: f.size,
        sha256: f.sha256.clone(),
        from: f.from.clone(),
        from_name,
        received: f.received,
        expires: f.received + inner.expiry_ms(),
    }
}

async fn inbox(State(inner): St, Device(me): Device) -> Response {
    let mut files: Vec<FileView> = inner.inbox(&me.id).iter().map(|f| view(&inner, f)).collect();
    files.sort_by_key(|f| std::cmp::Reverse(f.received));
    Json(json!({ "files": files })).into_response()
}

#[derive(Deserialize)]
struct CreateBody {
    name: String,
    size: u64,
    to: String,
}

async fn create_upload(State(inner): St, Device(me): Device, Json(b): Json<CreateBody>) -> Response {
    let up = match inner.create_upload(&me.id, &b.name, b.size, &b.to).await {
        Ok(u) => u,
        Err((s, m)) => return err(s, m),
    };
    if up.size == 0 {
        inner.end_chunk(&up.id, 0, true);
        return match inner.finish_upload(&up.id).await {
            Ok(f) => Json(json!({ "id": up.id, "received": 0, "size": 0, "done": true, "sha256": f.sha256 })).into_response(),
            Err(e) => err(500, e),
        };
    }
    Json(json!({ "id": up.id, "received": 0, "size": up.size, "done": false })).into_response()
}

async fn upload_status(State(inner): St, Device(me): Device, Path(id): Path<String>) -> Response {
    match inner.upload(&id, &me.id) {
        Some(u) => Json(json!({ "id": u.id, "received": u.received, "size": u.size })).into_response(),
        None => err(404, "unknown upload"),
    }
}

async fn cancel_upload(State(inner): St, Device(me): Device, Path(id): Path<String>) -> Response {
    if inner.cancel_upload(&id, &me.id) {
        Json(json!({ "ok": true })).into_response()
    } else {
        err(404, "unknown upload")
    }
}

#[derive(Deserialize)]
struct OffsetQ {
    offset: u64,
}

async fn put_chunk(
    State(inner): St,
    Device(me): Device,
    Path(id): Path<String>,
    Query(q): Query<OffsetQ>,
    body: Body,
) -> Response {
    let up = match inner.begin_chunk(&id, &me.id, q.offset) {
        Ok(u) => u,
        Err((404, _)) => return err(404, "unknown upload"),
        Err((s, received)) => {
            let s = StatusCode::from_u16(s).unwrap_or(StatusCode::CONFLICT);
            return (s, Json(json!({ "error": "offset mismatch", "received": received }))).into_response();
        }
    };
    let offset = q.offset;
    let mut written: u64 = 0;
    let result: Result<(), (u16, String)> = async {
        let mut f = tokio::fs::OpenOptions::new()
            .write(true)
            .open(&up.path)
            .await
            .map_err(|e| (500, e.to_string()))?;
        // Drop bytes past `offset` left by an interrupted chunk.
        f.set_len(offset).await.map_err(|e| (500, e.to_string()))?;
        f.seek(std::io::SeekFrom::Start(offset)).await.map_err(|e| (500, e.to_string()))?;
        let mut stream = body.into_data_stream();
        let mut last_emit = 0u64;
        let res = async {
            while let Some(frame) = stream.next().await {
                let bytes = frame.map_err(|e| (400, format!("upload interrupted: {e}")))?;
                if offset + written + bytes.len() as u64 > up.size {
                    return Err((400, "more data than announced".to_string()));
                }
                f.write_all(&bytes).await.map_err(|e| (500, e.to_string()))?;
                written += bytes.len() as u64;
                if written - last_emit >= 1 << 20 {
                    last_emit = written;
                    inner.progress(&up, offset + written);
                }
            }
            Ok(())
        }
        .await;
        f.flush().await.map_err(|e| (500, e.to_string()))?;
        res
    }
    .await;
    let received = offset + written;
    let complete = result.is_ok() && received == up.size;
    inner.end_chunk(&id, received, complete);
    if let Err((s, m)) = result {
        return (StatusCode::from_u16(s).unwrap_or(StatusCode::BAD_REQUEST), Json(json!({ "error": m, "received": received })))
            .into_response();
    }
    inner.progress(&up, received);
    if !complete {
        return Json(json!({ "received": received, "done": false })).into_response();
    }
    match inner.finish_upload(&id).await {
        Ok(f) => Json(json!({ "received": received, "done": true, "sha256": f.sha256, "name": f.name })).into_response(),
        Err(e) => err(500, e),
    }
}

/// Body stream that reports when the last byte of the file was sent.
struct PickupStream {
    inner: tokio_util::io::ReaderStream<tokio::io::Take<tokio::fs::File>>,
    left: u64,
    on_done: Option<Box<dyn FnOnce() + Send>>,
}

impl Stream for PickupStream {
    type Item = std::io::Result<axum::body::Bytes>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let r = Pin::new(&mut self.inner).poll_next(cx);
        if let Poll::Ready(Some(Ok(b))) = &r {
            self.left = self.left.saturating_sub(b.len() as u64);
        }
        r
    }
}

impl Drop for PickupStream {
    // hyper stops polling once Content-Length bytes were sent, so completion is
    // detected when the body is dropped with every byte handed to the connection.
    fn drop(&mut self) {
        if self.left == 0
            && let Some(f) = self.on_done.take()
        {
            f();
        }
    }
}

async fn download(State(inner): St, Device(me): Device, Path(id): Path<String>, headers: HeaderMap) -> Response {
    let Some(f) = inner.file(&id).filter(|f| f.to == me.id) else {
        return err(404, "no such file");
    };
    let mut file = match tokio::fs::File::open(&f.path).await {
        Ok(x) => x,
        Err(_) => return err(410, "file is gone"),
    };
    let len = match file.metadata().await {
        Ok(m) => m.len(),
        Err(e) => return err(500, e.to_string()),
    };
    let range_h = headers.get(header::RANGE).and_then(|v| v.to_str().ok());
    // If-Range with a different validator: send the whole file.
    let if_range_ok = headers
        .get(header::IF_RANGE)
        .and_then(|v| v.to_str().ok())
        .is_none_or(|v| v.trim_matches('"') == f.sha256);
    let range = match util::parse_range(range_h.filter(|_| if_range_ok), len) {
        Ok(r) => r,
        Err(()) => {
            return (StatusCode::RANGE_NOT_SATISFIABLE, [(header::CONTENT_RANGE, format!("bytes */{len}"))]).into_response();
        }
    };
    let (start, end) = range.unwrap_or((0, len.saturating_sub(1)));
    let count = if len == 0 { 0 } else { end - start + 1 };
    if start > 0 && file.seek(std::io::SeekFrom::Start(start)).await.is_err() {
        return err(500, "seek failed");
    }
    use tokio::io::AsyncReadExt;
    let reaches_end = len == 0 || end + 1 == len;
    let i2 = inner.clone();
    let id2 = f.id.clone();
    let on_done: Option<Box<dyn FnOnce() + Send>> = reaches_end.then(|| Box::new(move || i2.picked_up(&id2)) as _);
    let stream = PickupStream {
        inner: tokio_util::io::ReaderStream::with_capacity(file.take(count), 256 * 1024),
        left: count,
        on_done,
    };
    let mut r = Response::new(Body::from_stream(stream));
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(count));
    h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    if let Ok(v) = HeaderValue::from_str(&format!("\"{}\"", f.sha256)) {
        h.insert(header::ETAG, v);
    }
    if let Ok(v) = HeaderValue::from_str(&util::content_disposition(&f.name)) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    if range.is_some() {
        *r.status_mut() = StatusCode::PARTIAL_CONTENT;
        if let Ok(v) = HeaderValue::from_str(&format!("bytes {start}-{end}/{len}")) {
            r.headers_mut().insert(header::CONTENT_RANGE, v);
        }
    }
    r
}

async fn dismiss(State(inner): St, Device(me): Device, Path(id): Path<String>) -> Response {
    if inner.file(&id).is_some_and(|f| f.to == me.id) {
        inner.remove_file(&id);
        Json(json!({ "ok": true })).into_response()
    } else {
        err(404, "no such file")
    }
}
