use super::*;
use axum::body::{Body, Bytes};
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode, header};
use http_body_util::BodyExt;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

const IPHONE_UA: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148";
const ANDROID_UA: &str = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/124 Mobile Safari/537.36";

struct T {
    _dir: tempfile::TempDir,
    inner: Arc<Inner>,
    app: axum::Router,
    events: Arc<Mutex<Vec<DropEvent>>>,
    cfg: DropConfig,
}

fn setup() -> T {
    let dir = tempfile::tempdir().unwrap();
    let cfg = DropConfig {
        port: 0,
        data_dir: dir.path().join("drop"),
        device_name: "Test PC".into(),
        expiry_hours: 24,
        tls: None,
    };
    let events = Arc::new(Mutex::new(Vec::new()));
    let ev = events.clone();
    let inner = Inner::load(cfg.clone(), Arc::new(move |e| ev.lock().unwrap().push(e))).unwrap();
    let app = web::router(inner.clone());
    T { _dir: dir, inner, app, events, cfg }
}

struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl Resp {
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

async fn send(app: &axum::Router, req: Request<Body>) -> Resp {
    let r = app.clone().oneshot(req).await.unwrap();
    let status = r.status();
    let headers = r.headers().clone();
    let body = r.into_body().collect().await.unwrap().to_bytes();
    Resp { status, headers, body }
}

fn get(uri: &str, cookie: Option<&str>) -> Request<Body> {
    let mut b = Request::get(uri);
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, format!("{}={c}", web::COOKIE));
    }
    b.body(Body::empty()).unwrap()
}

fn with_body(method: &str, uri: &str, cookie: &str, ctype: &str, body: impl Into<Body>) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::COOKIE, format!("{}={cookie}", web::COOKIE))
        .header("x-drop", "1")
        .header(header::CONTENT_TYPE, ctype)
        .body(body.into())
        .unwrap()
}

fn json_req(method: &str, uri: &str, cookie: &str, v: serde_json::Value) -> Request<Body> {
    with_body(method, uri, cookie, "application/json", v.to_string())
}

/// Join via a fresh ticket; returns (cookie token, phone id).
async fn join(t: &T, ua: &str) -> (String, String) {
    let (code, _) = t.inner.new_ticket();
    let r = send(
        &t.app,
        Request::get(format!("/join?k={}-{}", &code[..4], code[4..].to_lowercase()))
            .header(header::USER_AGENT, ua)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let sc = r.headers.get(header::SET_COOKIE).unwrap().to_str().unwrap().to_string();
    assert!(sc.contains("HttpOnly") && sc.contains("SameSite=Strict"), "{sc}");
    let token = sc.split(';').next().unwrap().split_once('=').unwrap().1.to_string();
    let me = send(&t.app, get("/api/me", Some(&token))).await.json();
    (token, me["me"]["id"].as_str().unwrap().to_string())
}

#[tokio::test]
async fn join_flow_and_cookie_auth() {
    let t = setup();
    // Not joined: API is 401, page shell is public.
    assert_eq!(send(&t.app, get("/api/me", None)).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(send(&t.app, get("/api/inbox", Some("bogus"))).await.status, StatusCode::UNAUTHORIZED);
    let page = send(&t.app, get("/", None)).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&page.body).contains("/app.js"));
    assert_eq!(send(&t.app, get("/app.js", None)).await.status, StatusCode::OK);

    let (code, _) = t.inner.new_ticket();
    let r = send(
        &t.app,
        Request::get(format!("/join?k={code}")).header(header::USER_AGENT, IPHONE_UA).body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.headers.get(header::LOCATION).unwrap(), "/?welcome=1");
    let sc = r.headers.get(header::SET_COOKIE).unwrap().to_str().unwrap();
    let token = sc.split(';').next().unwrap().split_once('=').unwrap().1.to_string();
    assert_eq!(token.len(), 64);

    let me = send(&t.app, get("/api/me", Some(&token))).await;
    assert_eq!(me.status, StatusCode::OK);
    let j = me.json();
    assert_eq!(j["me"]["name"], "iPhone");
    assert_eq!(j["me"]["platform"], "ios");
    assert_eq!(j["computer"]["name"], "Test PC");
    assert!(matches!(t.events.lock().unwrap()[0], DropEvent::PhoneJoined(_)));

    // One-time code: second use fails.
    let again = send(&t.app, get(&format!("/join?k={code}"), None)).await;
    assert_eq!(again.status, StatusCode::FORBIDDEN);

    // Mutations need the X-Drop header.
    let no_hdr = Request::post("/api/me")
        .header(header::COOKIE, format!("nsdrop={token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"name":"x"}"#))
        .unwrap();
    assert_eq!(send(&t.app, no_hdr).await.status, StatusCode::FORBIDDEN);
    let r = send(&t.app, json_req("POST", "/api/me", &token, serde_json::json!({"name": "  Ana's iPhone "}))).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(t.inner.phones()[0].name, "Ana's iPhone");

    // Only the token hash is persisted.
    t.inner.save().await;
    let state = std::fs::read_to_string(t.cfg.data_dir.join("state.json")).unwrap();
    assert!(!state.contains(&token));
    assert!(state.contains(&util::sha256_hex(token.as_bytes())));

    // Second phone gets an Android default name and sees the first as a peer.
    let (tok2, _) = join(&t, ANDROID_UA).await;
    let j = send(&t.app, get("/api/me", Some(&tok2))).await.json();
    assert_eq!(j["me"]["name"], "Android phone");
    assert_eq!(j["peers"][0]["name"], "Ana's iPhone");

    // Forgetting a phone revokes its cookie.
    let id = t.inner.phones()[0].id.clone();
    t.inner.forget(&id);
    assert_eq!(send(&t.app, get("/api/me", Some(&token))).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn join_rate_limit_and_max_phones() {
    let t = setup();
    let ip: std::net::SocketAddr = "192.168.1.77:5000".parse().unwrap();
    let mut last = StatusCode::OK;
    for _ in 0..=JOIN_LIMIT {
        let mut req = get("/join?k=AAAAAAAA", None);
        req.extensions_mut().insert(ConnectInfo(ip));
        last = send(&t.app, req).await.status;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);

    for _ in 0..MAX_PHONES {
        join(&t, IPHONE_UA).await;
    }
    let names: Vec<String> = t.inner.phones().into_iter().map(|p| p.name).collect();
    assert_eq!(names[1], "iPhone 2");
    let (code, _) = t.inner.new_ticket();
    assert_eq!(t.inner.join(&code, "", None).unwrap_err(), JoinError::Full);
}

fn sha(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

#[tokio::test]
async fn chunked_upload_resume_and_sha256() {
    let t = setup();
    let (tok, me) = join(&t, IPHONE_UA).await;
    let data: Vec<u8> = (0..(3 * 1024 * 1024 + 5)).map(|i| (i * 7 % 251) as u8).collect();
    let r = send(
        &t.app,
        json_req("POST", "/api/upload", &tok, serde_json::json!({"name": "../../etc/IMG 1.jpg", "size": data.len(), "to": "system"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let id = r.json()["id"].as_str().unwrap().to_string();
    let put = |off: usize, end: usize| {
        with_body("PUT", &format!("/api/upload/{id}?offset={off}"), &tok, "application/octet-stream", data[off..end].to_vec())
    };

    let r = send(&t.app, put(0, 1 << 20)).await;
    assert_eq!(r.json()["received"], 1 << 20);
    assert_eq!(r.json()["done"], false);

    // Wrong offset -> 409 telling the client where to resume.
    let r = send(&t.app, put(0, 10)).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(r.json()["received"], 1 << 20);

    // Resume query.
    let r = send(&t.app, get(&format!("/api/upload/{id}"), Some(&tok))).await;
    assert_eq!(r.json()["received"], 1 << 20);
    assert_eq!(r.json()["size"], data.len());

    // Other devices cannot see or write this upload.
    let (tok2, _) = join(&t, ANDROID_UA).await;
    assert_eq!(send(&t.app, get(&format!("/api/upload/{id}"), Some(&tok2))).await.status, StatusCode::NOT_FOUND);

    // Too much data is rejected.
    let mut big = data[1 << 20..].to_vec();
    big.push(0);
    let r = send(
        &t.app,
        with_body("PUT", &format!("/api/upload/{id}?offset={}", 1 << 20), &tok, "application/octet-stream", big),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let resume = r.json()["received"].as_u64().unwrap() as usize;
    assert!(resume >= 1 << 20 && resume <= data.len());

    let r = send(&t.app, put(resume, data.len())).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json());
    let j = r.json();
    assert_eq!(j["done"], true);
    assert_eq!(j["sha256"], sha(&data));

    let inbox = t.inner.inbox(SYSTEM);
    assert_eq!(inbox.len(), 1);
    let f = &inbox[0];
    assert_eq!(f.name, "IMG 1.jpg");
    assert_eq!(f.from, me);
    assert_eq!(f.size, data.len() as u64);
    assert!(f.path.starts_with(std::path::absolute(t.cfg.data_dir.join("inbox").join(SYSTEM)).unwrap()));
    assert_eq!(std::fs::read(&f.path).unwrap(), data);
    {
        let ev = t.events.lock().unwrap();
        assert!(ev.iter().any(|e| matches!(e, DropEvent::UploadProgress { .. })));
        assert!(ev.iter().any(|e| matches!(e, DropEvent::FileReceived(x) if x.id == f.id)));
    }

    // Same name again gets a unique file name; empty files complete at once.
    let r = send(&t.app, json_req("POST", "/api/upload", &tok, serde_json::json!({"name": "IMG 1.jpg", "size": 0, "to": "system"}))).await;
    assert_eq!(r.json()["done"], true);
    assert_eq!(r.json()["sha256"], sha(b""));
    let names: Vec<String> = t.inner.inbox(SYSTEM).into_iter().map(|f| f.name).collect();
    assert!(names.contains(&"IMG 1 (2).jpg".to_string()), "{names:?}");

    // Unknown recipient.
    let r = send(&t.app, json_req("POST", "/api/upload", &tok, serde_json::json!({"name": "a", "size": 1, "to": "nope"}))).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn phone_to_phone_delivery_and_delete_after_pickup() {
    let t = setup();
    let (tok_a, id_a) = join(&t, IPHONE_UA).await;
    let (tok_b, id_b) = join(&t, ANDROID_UA).await;
    let data = b"hello from phone A, this is a test file".to_vec();
    let r = send(&t.app, json_req("POST", "/api/upload", &tok_a, serde_json::json!({"name": "note.txt", "size": data.len(), "to": id_b}))).await;
    let up = r.json()["id"].as_str().unwrap().to_string();
    let r = send(&t.app, with_body("PUT", &format!("/api/upload/{up}?offset=0"), &tok_a, "application/octet-stream", data.clone())).await;
    assert_eq!(r.json()["done"], true);

    // Only B sees it.
    assert_eq!(send(&t.app, get("/api/inbox", Some(&tok_a))).await.json()["files"].as_array().unwrap().len(), 0);
    let inbox = send(&t.app, get("/api/inbox", Some(&tok_b))).await.json();
    let files = inbox["files"].as_array().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["fromName"], "iPhone");
    assert_eq!(files[0]["from"], id_a.as_str());
    assert!(files[0].get("path").is_none());
    let fid = files[0]["id"].as_str().unwrap().to_string();
    let path = t.inner.file(&fid).unwrap().path;

    // A cannot download B's file.
    assert_eq!(send(&t.app, get(&format!("/api/files/{fid}"), Some(&tok_a))).await.status, StatusCode::NOT_FOUND);

    // Partial download (Range) keeps the file.
    let mut req = get(&format!("/api/files/{fid}"), Some(&tok_b));
    req.headers_mut().insert(header::RANGE, "bytes=0-9".parse().unwrap());
    let r = send(&t.app, req).await;
    assert_eq!(r.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(&r.body[..], &data[..10]);
    assert_eq!(r.headers.get(header::CONTENT_RANGE).unwrap(), &format!("bytes 0-9/{}", data.len()));
    assert!(r.headers.get(header::CONTENT_DISPOSITION).unwrap().to_str().unwrap().starts_with("attachment"));
    assert!(t.inner.file(&fid).is_some());

    // Resume to the end -> picked up -> deleted.
    let mut req = get(&format!("/api/files/{fid}"), Some(&tok_b));
    req.headers_mut().insert(header::RANGE, "bytes=10-".parse().unwrap());
    let r = send(&t.app, req).await;
    assert_eq!(r.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(&r.body[..], &data[10..]);
    assert!(t.inner.file(&fid).is_none());
    assert!(t.events.lock().unwrap().iter().any(|e| matches!(e, DropEvent::FilePickedUp(f) if f.id == fid)));
    for _ in 0..50 {
        if !path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!path.exists());
    assert_eq!(send(&t.app, get(&format!("/api/files/{fid}"), Some(&tok_b))).await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn send_to_phone_expiry_sweep_and_dismiss() {
    let t = setup();
    let (tok, id) = join(&t, IPHONE_UA).await;
    let src = t.cfg.data_dir.join("src.bin");
    std::fs::write(&src, b"computer to phone").unwrap();
    let f = t.inner.send_to_phone(&id, &src).await.unwrap();
    assert_eq!(f.from, SYSTEM);
    assert_eq!(f.sha256, sha(b"computer to phone"));
    assert!(src.exists(), "source must be copied, not moved");
    assert!(t.inner.send_to_phone("nope", &src).await.is_err());

    // A system-inbox file must survive the sweep.
    let (sys_up, _) = (t.inner.create_upload(&id, "keep.txt", 0, SYSTEM).await.unwrap(), ());
    t.inner.end_chunk(&sys_up.id, 0, true);
    t.inner.finish_upload(&sys_up.id).await.unwrap();

    assert_eq!(t.inner.sweep(util::now_ms()), 0);
    assert_eq!(t.inner.inbox(&id).len(), 1);
    let later = util::now_ms() + 25 * 3_600_000;
    assert_eq!(t.inner.sweep(later), 1);
    assert!(t.inner.inbox(&id).is_empty());
    assert_eq!(t.inner.inbox(SYSTEM).len(), 1);

    // Dismiss from the phone.
    let f2 = t.inner.send_to_phone(&id, &src).await.unwrap();
    let r = send(&t.app, with_body("DELETE", &format!("/api/files/{}", f2.id), &tok, "text/plain", "")).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(t.inner.inbox(&id).is_empty());
}

#[tokio::test]
async fn state_survives_restart() {
    let t = setup();
    let (tok, id) = join(&t, IPHONE_UA).await;
    let src = t.cfg.data_dir.join("src.bin");
    std::fs::write(&src, b"x").unwrap();
    t.inner.send_to_phone(&id, &src).await.unwrap();
    t.inner.save().await;

    let inner2 = Inner::load(t.cfg.clone(), Arc::new(|_| {})).unwrap();
    assert_eq!(inner2.phones().len(), 1);
    assert_eq!(inner2.inbox(&id).len(), 1);
    let app2 = web::router(inner2);
    assert_eq!(send(&app2, get("/api/me", Some(&tok))).await.status, StatusCode::OK);
}

#[test]
fn ticket_urls_and_qr() {
    assert_eq!(base_url("192.168.1.5", 8765, false), "http://192.168.1.5:8765");
    assert_eq!(base_url("192.168.1.5:9000", 8765, true), "https://192.168.1.5:9000");
    assert_eq!(base_url("http://pc.local:8765/", 1, false), "http://pc.local:8765");
    assert_eq!(base_url("fe80::1", 8765, false), "http://[fe80::1]:8765");
    let svg = qr_svg("http://192.168.1.5:8765/join?k=ABCDEFGH");
    assert!(svg.contains("<svg") && svg.contains("</svg>"));
    for u in local_urls(8765) {
        assert!(u.starts_with("http://") && u.ends_with(":8765"), "{u}");
    }
}

#[tokio::test]
async fn real_server_serves_pages() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let dir = tempfile::tempdir().unwrap();
    let cfg = DropConfig { port: 0, data_dir: dir.path().to_path_buf(), ..Default::default() };
    let srv = DropServer::start(cfg, Arc::new(|_| {})).await.unwrap();
    let t = srv.new_join_ticket("127.0.0.1");
    assert!(t.url.starts_with(&format!("http://127.0.0.1:{}/join?k=", srv.port())));
    assert_eq!(t.code.len(), 9);
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", srv.port())).await.unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    let out = String::from_utf8_lossy(&out);
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    assert!(out.contains("Choose photos or files"));
    srv.stop().await;
}
