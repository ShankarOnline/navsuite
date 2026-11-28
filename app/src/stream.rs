//! Media streaming (play media and music in the window, like a local player).
//!
//! The window is Chromium (WebView2/WKWebView/WebKitGTK), so its built-in media engine decodes the
//! common formats. This module only feeds it bytes: a localhost HTTP server that streams any vfs
//! file — local, SMB or SFTP — with byte-range support, so the player can seek without downloading
//! the whole file first. It also reads music tags and cover art with the `lofty` crate.
//!
//! The server binds to 127.0.0.1 only and checks a random per-session token, so nothing off the
//! machine can reach it and other pages cannot read arbitrary files.

use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use lofty::prelude::*;
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use vfs::{Loc, Vfs};

const CHUNK: u64 = 512 * 1024;
/// Enough of a file to hold tags and most embedded cover art.
const TAG_BYTES: usize = 3 * 1024 * 1024;

#[derive(Clone)]
struct Ctx {
    vfs: Arc<Vfs>,
    token: String,
}

pub struct MediaServer {
    port: u16,
    token: String,
}

impl MediaServer {
    pub async fn start(vfs: Arc<Vfs>) -> Result<Arc<Self>, String> {
        let token = random_token();
        let ctx = Ctx { vfs, token: token.clone() };
        let app = axum::Router::new()
            .route("/f", get(serve_file))
            .route("/meta", get(serve_meta))
            .route("/cover", get(serve_cover))
            .with_state(ctx);
        let listener = tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(Arc::new(Self { port, token }))
    }

    /// `http://127.0.0.1:<port>/…?t=<token>` — the base the UI builds media URLs from.
    pub fn base(&self) -> MediaBase {
        MediaBase { url: format!("http://127.0.0.1:{}", self.port), token: self.token.clone() }
    }
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MediaBase {
    pub url: String,
    pub token: String,
}

fn random_token() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut s = String::new();
    for _ in 0..4 {
        let h = std::collections::hash_map::RandomState::new().build_hasher().finish();
        s.push_str(&format!("{h:016x}"));
    }
    s
}

#[derive(Deserialize)]
struct Q {
    t: String,
    u: String,
}

#[allow(clippy::result_large_err)]
fn check(ctx: &Ctx, q: &Q) -> Result<Loc, Response> {
    if q.t != ctx.token {
        return Err((StatusCode::FORBIDDEN, "bad token").into_response());
    }
    Loc::parse(&q.u).map_err(|e| (StatusCode::BAD_REQUEST, e.message).into_response())
}

fn content_type(name: &str) -> HeaderValue {
    let m = mime_guess::from_path(name).first_or_octet_stream();
    HeaderValue::from_str(m.as_ref()).unwrap_or(HeaderValue::from_static("application/octet-stream"))
}

/// Parse a single-range `Range: bytes=start-end` header against a known length.
fn parse_range(headers: &HeaderMap, len: u64) -> Option<(u64, u64)> {
    let raw = headers.get(header::RANGE)?.to_str().ok()?;
    let spec = raw.strip_prefix("bytes=")?;
    let (a, b) = spec.split_once('-')?;
    let (start, end) = if a.is_empty() {
        // Suffix range: last N bytes.
        let n = b.parse::<u64>().ok()?;
        (len.saturating_sub(n), len - 1)
    } else {
        let start = a.parse::<u64>().ok()?;
        let end = if b.is_empty() { len - 1 } else { b.parse::<u64>().ok()?.min(len - 1) };
        (start, end)
    };
    if start > end || start >= len { None } else { Some((start, end)) }
}

async fn serve_file(State(ctx): State<Ctx>, headers: HeaderMap, Query(q): Query<Q>) -> Response {
    let loc = match check(&ctx, &q) {
        Ok(l) => l,
        Err(r) => return r,
    };
    let entry = match ctx.vfs.stat(&loc).await {
        Ok(e) => e,
        Err(e) => return (StatusCode::NOT_FOUND, e.message).into_response(),
    };
    let len = entry.size.unwrap_or(0);
    let handle = match ctx.vfs.open_read(&loc).await {
        Ok(h) => h,
        Err(e) => return (StatusCode::BAD_GATEWAY, e.message).into_response(),
    };

    let (start, end, status) = match parse_range(&headers, len) {
        Some((s, e)) => (s, e, StatusCode::PARTIAL_CONTENT),
        None => (0, len.saturating_sub(1), StatusCode::OK),
    };
    let span = if len == 0 { 0 } else { end - start + 1 };

    // Stream the span in chunks, reading each on demand so remote files never load whole into memory.
    let stream = futures::stream::unfold((handle, start, end), |(handle, pos, end)| async move {
        if pos > end {
            let _ = handle.close().await;
            return None;
        }
        let want = ((end - pos + 1).min(CHUNK)) as usize;
        match handle.read_at(pos, want).await {
            Ok(bytes) if !bytes.is_empty() => {
                let next = pos + bytes.len() as u64;
                Some((Ok::<_, std::io::Error>(bytes), (handle, next, end)))
            }
            Ok(_) => None,
            Err(e) => Some((Err(std::io::Error::other(e.message)), (handle, end + 1, end))),
        }
    });

    let mut resp = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type(&entry.name))
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CONTENT_LENGTH, span)
        .header(header::CACHE_CONTROL, "no-store");
    if status == StatusCode::PARTIAL_CONTENT {
        resp = resp.header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{len}"));
    }
    resp.body(Body::from_stream(stream)).unwrap()
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct Meta {
    title: Option<String>,
    artist: Option<String>,
    album: Option<String>,
    genre: Option<String>,
    track: Option<u32>,
    duration_secs: Option<f64>,
    has_cover: bool,
    kind: String, // "audio" | "video"
}

#[allow(clippy::result_large_err)]
async fn read_head(ctx: &Ctx, loc: &Loc, limit: usize) -> Result<(Vec<u8>, String), Response> {
    let entry = ctx.vfs.stat(loc).await.map_err(|e| (StatusCode::NOT_FOUND, e.message).into_response())?;
    let handle = ctx.vfs.open_read(loc).await.map_err(|e| (StatusCode::BAD_GATEWAY, e.message).into_response())?;
    let mut buf = Vec::new();
    let mut off = 0u64;
    while buf.len() < limit {
        match handle.read_at(off, 256 * 1024).await {
            Ok(b) if !b.is_empty() => {
                off += b.len() as u64;
                buf.extend_from_slice(&b);
            }
            _ => break,
        }
    }
    let _ = handle.close().await;
    Ok((buf, entry.name))
}

async fn serve_meta(State(ctx): State<Ctx>, Query(q): Query<Q>) -> Response {
    let loc = match check(&ctx, &q) {
        Ok(l) => l,
        Err(r) => return r,
    };
    let (buf, name) = match read_head(&ctx, &loc, TAG_BYTES).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let is_video = mime_guess::from_path(&name).first().map(|m| m.type_() == "video").unwrap_or(false);
    let mut meta = Meta { kind: if is_video { "video" } else { "audio" }.into(), ..Default::default() };
    // Tag parsing is pure CPU on an in-memory buffer; keep it off the async worker.
    let parsed = tokio::task::spawn_blocking(move || parse_tags(buf)).await.ok().flatten();
    if let Some(t) = parsed {
        meta.title = t.title;
        meta.artist = t.artist;
        meta.album = t.album;
        meta.genre = t.genre;
        meta.track = t.track;
        meta.duration_secs = t.duration_secs;
        meta.has_cover = t.has_cover;
    }
    if meta.title.is_none() {
        meta.title = Some(name.rsplit_once('.').map(|(a, _)| a).unwrap_or(&name).to_string());
    }
    axum::Json(meta).into_response()
}

struct Tags {
    title: Option<String>,
    artist: Option<String>,
    album: Option<String>,
    genre: Option<String>,
    track: Option<u32>,
    duration_secs: Option<f64>,
    has_cover: bool,
}

fn parse_tags(buf: Vec<u8>) -> Option<Tags> {
    let probe = lofty::probe::Probe::new(Cursor::new(buf)).guess_file_type().ok()?;
    let file = probe.read().ok()?;
    let dur = file.properties().duration();
    let tag = file.primary_tag().or_else(|| file.first_tag());
    Some(Tags {
        title: tag.and_then(|t| t.title().map(|s| s.to_string())),
        artist: tag.and_then(|t| t.artist().map(|s| s.to_string())),
        album: tag.and_then(|t| t.album().map(|s| s.to_string())),
        genre: tag.and_then(|t| t.genre().map(|s| s.to_string())),
        track: tag.and_then(|t| t.track()),
        duration_secs: if dur.as_secs() > 0 { Some(dur.as_secs_f64()) } else { None },
        has_cover: tag.map(|t| !t.pictures().is_empty()).unwrap_or(false),
    })
}

async fn serve_cover(State(ctx): State<Ctx>, Query(q): Query<Q>) -> Response {
    let loc = match check(&ctx, &q) {
        Ok(l) => l,
        Err(r) => return r,
    };
    let (buf, _) = match read_head(&ctx, &loc, TAG_BYTES).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let pic = tokio::task::spawn_blocking(move || {
        let probe = lofty::probe::Probe::new(Cursor::new(buf)).guess_file_type().ok()?;
        let file = probe.read().ok()?;
        let tag = file.primary_tag().or_else(|| file.first_tag())?;
        let p = tag.pictures().first()?;
        Some((p.mime_type().map(|m| m.to_string()).unwrap_or_else(|| "image/jpeg".into()), p.data().to_vec()))
    })
    .await
    .ok()
    .flatten();
    match pic {
        Some((mime, data)) => (
            [(header::CONTENT_TYPE, mime), (header::CACHE_CONTROL, "max-age=3600".into())],
            data,
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "no cover").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn ranges() {
        let h = |v: &str| {
            let mut m = HeaderMap::new();
            m.insert(header::RANGE, HeaderValue::from_str(v).unwrap());
            m
        };
        assert_eq!(parse_range(&h("bytes=0-99"), 1000), Some((0, 99)));
        assert_eq!(parse_range(&h("bytes=500-"), 1000), Some((500, 999)));
        assert_eq!(parse_range(&h("bytes=-100"), 1000), Some((900, 999)));
        assert_eq!(parse_range(&h("bytes=990-5000"), 1000), Some((990, 999)));
        assert_eq!(parse_range(&h("bytes=1000-1001"), 1000), None);
        assert_eq!(parse_range(&h("bytes=50-10"), 1000), None);
        assert_eq!(parse_range(&HeaderMap::new(), 1000), None);
    }

    /// Start the server over a temp file and fetch a byte range with a raw HTTP/1.1 request.
    #[tokio::test]
    async fn streams_a_range() {
        let dir = std::env::temp_dir().join(format!("narada-stream-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("clip.bin");
        let data: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        std::fs::write(&file, &data).unwrap();

        let vfs = Arc::new(Vfs::new(dir.join("state")));
        let server = MediaServer::start(vfs).await.unwrap();
        let base = server.base();
        let uri = Loc::local(file.to_str().unwrap()).unwrap().to_uri();

        let addr = base.url.trim_start_matches("http://");
        let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let path = format!(
            "/f?t={}&u={}",
            base.token,
            percent_encoding::utf8_percent_encode(&uri, percent_encoding::NON_ALPHANUMERIC)
        );
        let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nRange: bytes=1000-1099\r\nConnection: close\r\n\r\n");
        sock.write_all(req.as_bytes()).await.unwrap();
        let mut resp = Vec::new();
        sock.read_to_end(&mut resp).await.unwrap();

        let text = String::from_utf8_lossy(&resp).to_lowercase();
        assert!(text.starts_with("http/1.1 206"), "expected 206, got: {}", &text[..text.len().min(40)]);
        assert!(text.contains("content-range: bytes 1000-1099/5000"));
        let body_start = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert_eq!(&resp[body_start..], &data[1000..=1099]);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
