//! dropsrv: AirDrop-style phone drop page (features PH1-PH5).
//!
//! The computer runs a small HTTP(S) server; phones join by scanning a QR
//! code (one-time key, 10 minutes) and get a long-lived HttpOnly cookie. From
//! the page a phone can send files to this computer or to another joined
//! phone, and download files sent to it. Phones need no app.
//!
//! Storage layout under `data_dir`:
//! * `state.json`            joined phones (token hashes only) + pending files
//! * `inbox/system/...`      files for this computer (kept until the app moves them)
//! * `inbox/<phone id>/...`  files for a phone (deleted after pickup or expiry)
//! * `partial/<upload id>`   in-progress uploads

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

mod util;
mod web;

pub use util::sanitize_file_name;

/// Recipient id for "this computer".
pub const SYSTEM: &str = "system";
/// Maximum number of joined phones.
pub const MAX_PHONES: usize = 20;
/// Join tickets are valid for 10 minutes.
pub const TICKET_TTL: Duration = Duration::from_secs(600);
/// Upload chunk size used by the page.
pub const CHUNK_SIZE: u64 = 8 * 1024 * 1024;
/// Keep this much disk space free when accepting uploads.
const DISK_MARGIN: u64 = 64 * 1024 * 1024;
/// Max concurrent unfinished uploads.
const MAX_UPLOADS: usize = 64;
/// /join attempts allowed per client IP per window.
const JOIN_LIMIT: u32 = 10;
const JOIN_WINDOW: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsFiles {
    pub cert_pem: PathBuf,
    pub key_pem: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DropConfig {
    pub port: u16,
    pub data_dir: PathBuf,
    pub device_name: String,
    pub expiry_hours: u64,
    pub tls: Option<TlsFiles>,
}

impl Default for DropConfig {
    fn default() -> Self {
        Self {
            port: 8765,
            data_dir: PathBuf::from("navsuite-drop"),
            device_name: "This computer".into(),
            expiry_hours: 24,
            tls: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinTicket {
    /// Human-typable one-time code, e.g. "K7P4-QXZ2" (also embedded in the URL).
    pub code: String,
    /// URL encoded in the QR code: `<base>/join?k=<code>`.
    pub url: String,
    /// QR code as a standalone SVG document.
    pub qr_svg: String,
    /// Expiry, unix milliseconds.
    pub expires: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Phone {
    pub id: String,
    pub name: String,
    /// "ios" | "android" | "other"
    pub platform: String,
    pub ip: String,
    /// Unix milliseconds.
    pub joined: u64,
    /// Unix milliseconds.
    pub last_seen: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DropFile {
    pub id: String,
    pub name: String,
    pub size: u64,
    pub sha256: String,
    /// "system" or a phone id.
    pub from: String,
    /// "system" or a phone id.
    pub to: String,
    /// Unix milliseconds.
    pub received: u64,
    /// Absolute path of the stored file.
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum DropEvent {
    PhoneJoined(Phone),
    /// A completed upload (to this computer or to a phone).
    FileReceived(DropFile),
    /// A phone downloaded a file completely (it has been deleted).
    FilePickedUp(DropFile),
    UploadProgress { id: String, name: String, bytes: u64, total: u64 },
}

pub type Emit = Arc<dyn Fn(DropEvent) + Send + Sync>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PhoneRec {
    #[serde(flatten)]
    phone: Phone,
    token_sha256: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Persist {
    phones: Vec<PhoneRec>,
    files: Vec<DropFile>,
}

#[derive(Debug, Clone)]
struct Upload {
    id: String,
    name: String,
    size: u64,
    from: String,
    to: String,
    received: u64,
    path: PathBuf,
    busy: bool,
    touched: u64,
}

struct Mem {
    persist: Persist,
    tickets: HashMap<String, Instant>,
    join_attempts: HashMap<IpAddr, (Instant, u32)>,
    uploads: HashMap<String, Upload>,
}

pub(crate) struct Inner {
    cfg: DropConfig,
    emit: Emit,
    mem: Mutex<Mem>,
    dirty: tokio::sync::Notify,
    tls: bool,
}

fn lock(m: &Mutex<Mem>) -> MutexGuard<'_, Mem> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Inner {
    /// Load state from disk (blocking; called once at start / in tests).
    pub(crate) fn load(cfg: DropConfig, emit: Emit) -> Result<Arc<Self>, String> {
        let dd = &cfg.data_dir;
        for d in [dd.join("inbox").join(SYSTEM), dd.join("partial")] {
            std::fs::create_dir_all(&d).map_err(|e| format!("create {}: {e}", d.display()))?;
        }
        // Unfinished uploads are not resumable across restarts.
        if let Ok(rd) = std::fs::read_dir(dd.join("partial")) {
            for e in rd.flatten() {
                let _ = std::fs::remove_file(e.path());
            }
        }
        let persist: Persist = match std::fs::read(dd.join("state.json")) {
            Ok(b) => serde_json::from_slice(&b).unwrap_or_default(),
            Err(_) => Persist::default(),
        };
        let mut persist = persist;
        persist.files.retain(|f| f.path.exists());
        Ok(Arc::new(Self {
            tls: cfg.tls.is_some(),
            cfg,
            emit,
            mem: Mutex::new(Mem {
                persist,
                tickets: HashMap::new(),
                join_attempts: HashMap::new(),
                uploads: HashMap::new(),
            }),
            dirty: tokio::sync::Notify::new(),
        }))
    }

    fn mem(&self) -> MutexGuard<'_, Mem> {
        lock(&self.mem)
    }

    fn mark_dirty(&self) {
        self.dirty.notify_one();
    }

    fn emit(&self, e: DropEvent) {
        (self.emit)(e);
    }

    fn expiry_ms(&self) -> u64 {
        self.cfg.expiry_hours.max(1) * 3_600_000
    }

    fn state_json(&self) -> Vec<u8> {
        serde_json::to_vec_pretty(&self.mem().persist).unwrap_or_default()
    }

    /// Write state.json atomically (async, off the runtime's worker via tokio::fs).
    pub(crate) async fn save(&self) {
        let data = self.state_json();
        let dir = &self.cfg.data_dir;
        let tmp = dir.join("state.json.tmp");
        if tokio::fs::write(&tmp, data).await.is_ok() {
            let _ = tokio::fs::rename(&tmp, dir.join("state.json")).await;
        }
    }

    fn inbox_dir(&self, recipient: &str) -> PathBuf {
        self.cfg.data_dir.join("inbox").join(recipient)
    }

    // ----- tickets & joining -------------------------------------------------

    pub(crate) fn new_ticket(&self) -> (String, u64) {
        let code = util::random_code();
        let mut m = self.mem();
        let now = Instant::now();
        m.tickets.retain(|_, exp| *exp > now);
        m.tickets.insert(code.clone(), now + TICKET_TTL);
        (code, util::now_ms() + TICKET_TTL.as_millis() as u64)
    }

    /// Count a join attempt from `ip`; false if rate-limited.
    pub(crate) fn join_allowed(&self, ip: Option<IpAddr>) -> bool {
        let Some(ip) = ip else { return true };
        let mut m = self.mem();
        let now = Instant::now();
        let e = m.join_attempts.entry(ip).or_insert((now, 0));
        if now.duration_since(e.0) > JOIN_WINDOW {
            *e = (now, 0);
        }
        e.1 += 1;
        e.1 <= JOIN_LIMIT
    }

    /// Consume a one-time code and register a phone. Returns (phone, token).
    pub(crate) fn join(&self, code: &str, ua: &str, ip: Option<IpAddr>) -> Result<(Phone, String), JoinError> {
        let code = util::normalize_code(code);
        let token = util::random_hex(32);
        let phone = {
            let mut m = self.mem();
            let now = Instant::now();
            match m.tickets.get(&code) {
                Some(exp) if *exp > now => {}
                _ => return Err(JoinError::BadCode),
            }
            if m.persist.phones.len() >= MAX_PHONES {
                return Err(JoinError::Full);
            }
            m.tickets.remove(&code);
            let (platform, base) = util::sniff_user_agent(ua);
            let mut name = base.to_string();
            let mut n = 2;
            while m.persist.phones.iter().any(|p| p.phone.name == name) {
                name = format!("{base} {n}");
                n += 1;
            }
            let t = util::now_ms();
            let phone = Phone {
                id: util::random_hex(8),
                name,
                platform: platform.into(),
                ip: ip.map(|i| i.to_string()).unwrap_or_default(),
                joined: t,
                last_seen: t,
            };
            m.persist.phones.push(PhoneRec {
                phone: phone.clone(),
                token_sha256: util::sha256_hex(token.as_bytes()),
            });
            phone
        };
        self.mark_dirty();
        self.emit(DropEvent::PhoneJoined(phone.clone()));
        Ok((phone, token))
    }

    /// Look up a device by cookie token; refreshes last_seen / ip.
    pub(crate) fn auth(&self, token: &str, ip: Option<IpAddr>) -> Option<Phone> {
        let h = util::sha256_hex(token.as_bytes());
        let mut m = self.mem();
        let rec = m.persist.phones.iter_mut().find(|p| p.token_sha256 == h)?;
        rec.phone.last_seen = util::now_ms();
        if let Some(ip) = ip {
            rec.phone.ip = ip.to_string();
        }
        Some(rec.phone.clone())
    }

    pub(crate) fn phones(&self) -> Vec<Phone> {
        self.mem().persist.phones.iter().map(|p| p.phone.clone()).collect()
    }

    pub(crate) fn rename(&self, id: &str, name: &str) -> bool {
        let name: String = name.trim().chars().filter(|c| !c.is_control()).take(40).collect();
        if name.is_empty() {
            return false;
        }
        let ok = {
            let mut m = self.mem();
            match m.persist.phones.iter_mut().find(|p| p.phone.id == id) {
                Some(p) => {
                    p.phone.name = name;
                    true
                }
                None => false,
            }
        };
        if ok {
            self.mark_dirty();
        }
        ok
    }

    pub(crate) fn forget(&self, id: &str) {
        let files: Vec<DropFile> = {
            let mut m = self.mem();
            m.persist.phones.retain(|p| p.phone.id != id);
            let (gone, keep): (Vec<_>, Vec<_>) = m.persist.files.drain(..).partition(|f| f.to == id);
            m.persist.files = keep;
            m.uploads.retain(|_, u| u.from != id && u.to != id);
            gone
        };
        remove_files(files.into_iter().map(|f| f.path).collect());
        let dir = self.inbox_dir(id);
        remove_dir_later(dir);
        self.mark_dirty();
    }

    // ----- files -------------------------------------------------------------

    pub(crate) fn inbox(&self, recipient: &str) -> Vec<DropFile> {
        self.mem().persist.files.iter().filter(|f| f.to == recipient).cloned().collect()
    }

    pub(crate) fn file(&self, id: &str) -> Option<DropFile> {
        self.mem().persist.files.iter().find(|f| f.id == id).cloned()
    }

    pub(crate) fn remove_file(&self, id: &str) -> Option<DropFile> {
        let f = {
            let mut m = self.mem();
            let i = m.persist.files.iter().position(|f| f.id == id)?;
            m.persist.files.remove(i)
        };
        remove_files(vec![f.path.clone()]);
        self.mark_dirty();
        Some(f)
    }

    /// Called when a recipient phone finished downloading `id`.
    pub(crate) fn picked_up(&self, id: &str) {
        let is_phone = self.file(id).is_some_and(|f| f.to != SYSTEM);
        if is_phone && let Some(f) = self.remove_file(id) {
            self.emit(DropEvent::FilePickedUp(f));
        }
    }

    fn is_recipient(&self, to: &str) -> bool {
        to == SYSTEM || self.mem().persist.phones.iter().any(|p| p.phone.id == to)
    }

    fn check_space(&self, size: u64) -> Result<(), String> {
        if let Some(free) = util::free_space(&self.cfg.data_dir)
            && free < size.saturating_add(DISK_MARGIN)
        {
            return Err(format!("not enough disk space on the computer ({} MiB free)", free / (1024 * 1024)));
        }
        Ok(())
    }

    /// Move a finished file into the recipient's inbox and record it.
    /// Blocking file operations run via tokio::fs / spawn_blocking.
    async fn store(&self, src: &Path, name: &str, size: u64, from: &str, to: &str, copy: bool) -> Result<DropFile, String> {
        let dir = self.inbox_dir(to);
        tokio::fs::create_dir_all(&dir).await.map_err(|e| e.to_string())?;
        let safe = util::sanitize_file_name(name);
        let (src2, dir2) = (src.to_path_buf(), dir.clone());
        let (dest, sha) = tokio::task::spawn_blocking(move || -> std::io::Result<(PathBuf, String)> {
            let sha = util::sha256_file(&src2)?;
            let dest = util::unique_path(&dir2, &safe);
            if copy {
                std::fs::copy(&src2, &dest)?;
            } else if std::fs::rename(&src2, &dest).is_err() {
                std::fs::copy(&src2, &dest)?;
                let _ = std::fs::remove_file(&src2);
            }
            Ok((dest, sha))
        })
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
        let name = dest.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let f = DropFile {
            id: util::random_hex(8),
            name,
            size,
            sha256: sha,
            from: from.into(),
            to: to.into(),
            received: util::now_ms(),
            path: std::path::absolute(&dest).unwrap_or(dest),
        };
        self.mem().persist.files.push(f.clone());
        self.mark_dirty();
        self.emit(DropEvent::FileReceived(f.clone()));
        Ok(f)
    }

    pub(crate) async fn send_to_phone(&self, phone_id: &str, src: &Path) -> Result<DropFile, String> {
        if phone_id == SYSTEM || !self.is_recipient(phone_id) {
            return Err("unknown phone".into());
        }
        let meta = tokio::fs::metadata(src).await.map_err(|e| format!("{}: {e}", src.display()))?;
        if !meta.is_file() {
            return Err(format!("{} is not a file", src.display()));
        }
        self.check_space(meta.len())?;
        let name = src.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into());
        self.store(src, &name, meta.len(), SYSTEM, phone_id, true).await
    }

    // ----- uploads -----------------------------------------------------------

    pub(crate) async fn create_upload(&self, from: &str, name: &str, size: u64, to: &str) -> Result<Upload, (u16, String)> {
        if to == from || !self.is_recipient(to) {
            return Err((400, "unknown recipient".into()));
        }
        self.check_space(size).map_err(|e| (507, e))?;
        let id = util::random_hex(12);
        let path = self.cfg.data_dir.join("partial").join(&id);
        tokio::fs::write(&path, b"").await.map_err(|e| (500, e.to_string()))?;
        let up = Upload {
            id: id.clone(),
            name: util::sanitize_file_name(name),
            size,
            from: from.into(),
            to: to.into(),
            received: 0,
            path,
            busy: false,
            touched: util::now_ms(),
        };
        {
            let mut m = self.mem();
            if m.uploads.len() >= MAX_UPLOADS {
                return Err((429, "too many unfinished uploads".into()));
            }
            m.uploads.insert(id.clone(), up.clone());
        }
        Ok(up)
    }

    pub(crate) fn upload(&self, id: &str, from: &str) -> Option<Upload> {
        self.mem().uploads.get(id).filter(|u| u.from == from).cloned()
    }

    /// Mark an upload busy for writing at `offset`; returns it or an error status.
    pub(crate) fn begin_chunk(&self, id: &str, from: &str, offset: u64) -> Result<Upload, (u16, u64)> {
        let mut m = self.mem();
        let u = m.uploads.get_mut(id).filter(|u| u.from == from).ok_or((404, 0))?;
        if u.busy || offset != u.received || u.received >= u.size {
            return Err((409, u.received));
        }
        u.busy = true;
        u.touched = util::now_ms();
        Ok(u.clone())
    }

    /// Record progress after a chunk; `keep_busy` when the upload is complete
    /// (so no further chunk can race with `finish_upload`).
    pub(crate) fn end_chunk(&self, id: &str, received: u64, keep_busy: bool) {
        if let Some(u) = self.mem().uploads.get_mut(id) {
            u.busy = keep_busy;
            u.received = received;
            u.touched = util::now_ms();
        }
    }

    pub(crate) fn progress(&self, u: &Upload, bytes: u64) {
        self.emit(DropEvent::UploadProgress {
            id: u.id.clone(),
            name: u.name.clone(),
            bytes,
            total: u.size,
        });
    }

    /// Upload complete: hash, move into the inbox, forget the upload.
    pub(crate) async fn finish_upload(&self, id: &str) -> Result<DropFile, String> {
        let u = self.mem().uploads.remove(id).ok_or("upload vanished")?;
        if !self.is_recipient(&u.to) {
            let _ = tokio::fs::remove_file(&u.path).await;
            return Err("recipient left".into());
        }
        self.store(&u.path, &u.name, u.size, &u.from, &u.to, false).await
    }

    pub(crate) fn cancel_upload(&self, id: &str, from: &str) -> bool {
        let u = {
            let mut m = self.mem();
            match m.uploads.get(id) {
                Some(u) if u.from == from && !u.busy => m.uploads.remove(id),
                _ => None,
            }
        };
        match u {
            Some(u) => {
                remove_files(vec![u.path]);
                true
            }
            None => false,
        }
    }

    // ----- housekeeping ------------------------------------------------------

    /// Delete expired phone files and stale uploads as of `now` (unix ms).
    pub(crate) fn sweep(&self, now: u64) -> usize {
        let exp = self.expiry_ms();
        let (files, partials) = {
            let mut m = self.mem();
            let t = Instant::now();
            m.tickets.retain(|_, e| *e > t);
            m.join_attempts.retain(|_, (s, _)| t.duration_since(*s) < JOIN_WINDOW);
            let (gone, keep): (Vec<_>, Vec<_>) = m
                .persist
                .files
                .drain(..)
                .partition(|f| f.to != SYSTEM && f.received.saturating_add(exp) <= now);
            m.persist.files = keep;
            let stale: Vec<String> = m
                .uploads
                .values()
                .filter(|u| !u.busy && u.touched.saturating_add(exp) <= now)
                .map(|u| u.id.clone())
                .collect();
            let partials: Vec<PathBuf> = stale.iter().filter_map(|id| m.uploads.remove(id)).map(|u| u.path).collect();
            (gone, partials)
        };
        let n = files.len();
        remove_files(files.into_iter().map(|f| f.path).chain(partials).collect());
        self.mark_dirty();
        n
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum JoinError {
    BadCode,
    Full,
}

/// Delete files without blocking the async runtime.
fn remove_files(paths: Vec<PathBuf>) {
    if paths.is_empty() {
        return;
    }
    let job = move || {
        for p in paths {
            let _ = std::fs::remove_file(p);
        }
    };
    match tokio::runtime::Handle::try_current() {
        Ok(h) => {
            h.spawn_blocking(job);
        }
        Err(_) => job(),
    }
}

fn remove_dir_later(dir: PathBuf) {
    let job = move || {
        let _ = std::fs::remove_dir_all(dir);
    };
    match tokio::runtime::Handle::try_current() {
        Ok(h) => {
            h.spawn_blocking(job);
        }
        Err(_) => job(),
    }
}

/// The running drop server. Cheap to share as `Arc<DropServer>`.
pub struct DropServer {
    inner: Arc<Inner>,
    port: u16,
    handle: axum_server::Handle<SocketAddr>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

fn bind(port: u16) -> Result<TcpListener, String> {
    if port == 0 {
        return TcpListener::bind(("0.0.0.0", 0)).map_err(|e| e.to_string());
    }
    let mut last = String::new();
    for p in port..port.saturating_add(20) {
        match TcpListener::bind(("0.0.0.0", p)) {
            Ok(l) => return Ok(l),
            Err(e) => last = format!("port {p}: {e}"),
        }
    }
    Err(format!("no free port near {port} ({last})"))
}

fn tls_config(t: &TlsFiles) -> Result<axum_server::tls_rustls::RustlsConfig, String> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&t.cert_pem)
        .map_err(|e| format!("{}: {e}", t.cert_pem.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("{}: {e}", t.cert_pem.display()))?;
    let key = PrivateKeyDer::from_pem_file(&t.key_pem).map_err(|e| format!("{}: {e}", t.key_pem.display()))?;
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| e.to_string())?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(cfg)))
}

impl DropServer {
    /// Start serving on 0.0.0.0:`cfg.port` (or the next free port).
    pub async fn start(cfg: DropConfig, emit: Arc<dyn Fn(DropEvent) + Send + Sync>) -> Result<Arc<Self>, String> {
        let tls = match &cfg.tls {
            Some(t) => {
                let t = t.clone();
                Some(tokio::task::spawn_blocking(move || tls_config(&t)).await.map_err(|e| e.to_string())??)
            }
            None => None,
        };
        let port_req = cfg.port;
        let (inner, listener) = tokio::task::spawn_blocking(move || -> Result<_, String> {
            let inner = Inner::load(cfg, emit)?;
            let l = bind(port_req)?;
            Ok((inner, l))
        })
        .await
        .map_err(|e| e.to_string())??;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let app = web::router(inner.clone()).into_make_service_with_connect_info::<SocketAddr>();
        let handle = axum_server::Handle::new();
        let h2 = handle.clone();
        let server = match tls {
            Some(tc) => {
                let s = axum_server::from_tcp_rustls(listener, tc).map_err(|e| e.to_string())?.handle(h2);
                tokio::spawn(async move {
                    let _ = s.serve(app).await;
                })
            }
            None => {
                let s = axum_server::from_tcp(listener).map_err(|e| e.to_string())?.handle(h2);
                tokio::spawn(async move {
                    let _ = s.serve(app).await;
                })
            }
        };
        // Persist on change (debounced) and sweep expired files every minute.
        let i2 = inner.clone();
        let saver = tokio::spawn(async move {
            loop {
                i2.dirty.notified().await;
                tokio::time::sleep(Duration::from_millis(300)).await;
                i2.save().await;
            }
        });
        let i3 = inner.clone();
        let sweeper = tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(60));
            loop {
                iv.tick().await;
                i3.sweep(util::now_ms());
            }
        });
        Ok(Arc::new(Self {
            inner,
            port,
            handle,
            tasks: Mutex::new(vec![server, saver, sweeper]),
        }))
    }

    /// Create a one-time join ticket (valid 10 minutes). `host` is an IP or
    /// host name (optionally with port), or a full base URL.
    pub fn new_join_ticket(&self, host: &str) -> JoinTicket {
        let (code, expires) = self.inner.new_ticket();
        let base = base_url(host, self.port, self.inner.tls);
        let url = format!("{base}/join?k={code}");
        JoinTicket {
            code: format!("{}-{}", &code[..4], &code[4..]),
            qr_svg: qr_svg(&url),
            url,
            expires,
        }
    }

    pub fn phones(&self) -> Vec<Phone> {
        self.inner.phones()
    }

    pub fn rename_phone(&self, id: &str, name: &str) {
        self.inner.rename(id, name);
    }

    /// Remove a phone: its cookie stops working and its pending files are deleted.
    pub fn forget_phone(&self, id: &str) {
        self.inner.forget(id);
    }

    /// Files waiting for `recipient` ("system" or a phone id).
    pub fn inbox(&self, recipient: &str) -> Vec<DropFile> {
        self.inner.inbox(recipient)
    }

    /// Copy `src` into a phone's inbox.
    pub async fn send_to_phone(&self, phone_id: &str, src: &Path) -> Result<DropFile, String> {
        self.inner.send_to_phone(phone_id, src).await
    }

    /// Forget a file and delete it from disk if it is still there (call after
    /// moving a system-inbox file elsewhere, or to cancel a phone delivery).
    pub fn delete_file(&self, id: &str) {
        self.inner.remove_file(id);
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn is_tls(&self) -> bool {
        self.inner.tls
    }

    /// Candidate base URLs (one per LAN / tailnet IPv4) with the right scheme.
    pub fn local_urls(&self) -> Vec<String> {
        urls(self.port, self.inner.tls)
    }

    pub async fn stop(&self) {
        self.handle.graceful_shutdown(Some(Duration::from_secs(2)));
        let tasks: Vec<_> = std::mem::take(&mut *self.tasks.lock().unwrap_or_else(|p| p.into_inner()));
        for t in tasks.iter().skip(1) {
            t.abort();
        }
        if let Some(server) = tasks.into_iter().next() {
            let _ = tokio::time::timeout(Duration::from_secs(3), server).await;
        }
        self.inner.save().await;
    }
}

fn base_url(host: &str, port: u16, tls: bool) -> String {
    let h = host.trim().trim_end_matches('/');
    if h.contains("://") {
        return h.to_string();
    }
    let scheme = if tls { "https" } else { "http" };
    let has_port = if h.starts_with('[') { h.contains("]:") } else { h.matches(':').count() == 1 };
    if has_port {
        format!("{scheme}://{h}")
    } else if h.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("{scheme}://[{h}]:{port}")
    } else {
        format!("{scheme}://{h}:{port}")
    }
}

fn qr_svg(data: &str) -> String {
    match qrcode::QrCode::with_error_correction_level(data.as_bytes(), qrcode::EcLevel::M) {
        Ok(code) => code
            .render::<qrcode::render::svg::Color<'_>>()
            .min_dimensions(256, 256)
            .quiet_zone(true)
            .build(),
        Err(_) => String::new(),
    }
}

/// Rank addresses: private LAN first, then tailnet (100.64/10), then the rest;
/// virtual adapters (Hyper-V, WSL, Docker, VMs) last.
fn rank(name: &str, ip: std::net::Ipv4Addr) -> u8 {
    let n = name.to_ascii_lowercase();
    let virt = ["vethernet", "docker", "br-", "veth", "virtualbox", "vmware", "vmnet", "hyper-v", "wsl", "utun", "zt"]
        .iter()
        .any(|v| n.contains(v));
    let o = ip.octets();
    let base = if o[0] == 100 && (64..128).contains(&o[1]) {
        1
    } else if ip.is_private() {
        0
    } else {
        2
    };
    if virt && !n.contains("tailscale") { base + 10 } else { base }
}

fn urls(port: u16, tls: bool) -> Vec<String> {
    let scheme = if tls { "https" } else { "http" };
    let mut v: Vec<(u8, String)> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| !i.is_loopback() && i.is_oper_up())
        .filter_map(|i| match i.ip() {
            IpAddr::V4(a) if !a.is_link_local() && !a.is_unspecified() => Some((rank(&i.name, a), format!("{scheme}://{a}:{port}"))),
            _ => None,
        })
        .collect();
    v.sort();
    v.dedup_by(|a, b| a.1 == b.1);
    v.into_iter().map(|(_, u)| u).collect()
}

/// `http://<each LAN/tailnet IPv4>:port`, best candidates first (for choosing
/// the QR host). Use [`DropServer::local_urls`] to get `https` when TLS is on.
pub fn local_urls(port: u16) -> Vec<String> {
    urls(port, false)
}

#[cfg(test)]
mod tests;
