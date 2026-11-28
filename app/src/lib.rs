//! Narada: one window for files and networks.
//!
//! This crate is the Tauri shell. The real work lives in the workspace crates:
//! netscan (discovery and system records), vfs (one file layer for local, SMB and SFTP),
//! xfer (the transfer queue with SHA-256 checks), dropsrv (the phone drop page) and
//! probe (ping, traceroute, port, DNS and HTTP checks).

mod settings;
mod stream;
mod term;

use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager, State};
use vfs::{Loc, Vfs, VfsError};

struct App {
    settings: Mutex<settings::Settings>,
    vfs: Arc<Vfs>,
    queue: Arc<xfer::Queue>,
    terms: term::Terminals,
    drop: tokio::sync::Mutex<Option<Arc<dropsrv::DropServer>>>,
    scan: Mutex<Option<Arc<AtomicBool>>>,
    records: Mutex<Vec<netscan::SystemRecord>>,
    probes: Mutex<HashMap<u32, Arc<AtomicBool>>>,
    next_probe: AtomicU32,
    media: tokio::sync::Mutex<Option<Arc<stream::MediaServer>>>,
}

type Res<T> = Result<T, String>;
type FsRes<T> = Result<T, VfsError>;
type DkRes<T> = Result<T, disks::DiskError>;

fn disk_io(e: impl std::fmt::Display) -> disks::DiskError {
    disks::DiskError::Io { message: e.to_string() }
}

/// The elevated raw-disk helper (DB5): re-launched as `narada --disk-helper <pipe> <token>`.
/// It never returns; this is called from `main` before the window starts.
pub fn disk_helper(args: &[String]) -> ! {
    disks::helper_main(args)
}

fn other(msg: impl Into<String>) -> VfsError {
    VfsError::other(msg)
}

fn parse(loc: &str) -> FsRes<Loc> {
    Loc::parse(loc)
}

/* ---------------- settings ---------------- */

#[tauri::command]
fn settings_get(app: State<'_, App>) -> settings::Settings {
    app.settings.lock().unwrap().clone()
}

#[tauri::command]
fn settings_set(app: State<'_, App>, settings: settings::Settings) -> Res<()> {
    settings::save(&settings)?;
    *app.settings.lock().unwrap() = settings;
    Ok(())
}

/* ---------------- network ---------------- */

#[derive(Serialize, Clone)]
#[serde(tag = "type", rename_all = "camelCase")]
enum UiScanEvent {
    TailnetError { message: String },
    Done { systems: usize, millis: u64, cancelled: bool },
}

fn records_path() -> std::path::PathBuf {
    settings::data_dir().join("records.json")
}

/// Records from the last session, all marked offline until a scan sees them again.
fn load_records() -> Vec<netscan::SystemRecord> {
    let mut list: Vec<netscan::SystemRecord> =
        std::fs::read(records_path()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    for r in &mut list {
        r.online = false;
    }
    list
}

#[tauri::command]
fn records_get(app: State<'_, App>) -> Vec<netscan::SystemRecord> {
    app.records.lock().unwrap().clone()
}

#[tauri::command]
fn scan_cancel(app: State<'_, App>) {
    if let Some(c) = app.scan.lock().unwrap().as_ref() {
        c.store(true, Ordering::Relaxed);
    }
}

#[tauri::command]
async fn scan_start(handle: AppHandle) -> Res<()> {
    let app = handle.state::<App>();
    let cancel = {
        let mut slot = app.scan.lock().unwrap();
        if slot.is_some() {
            return Ok(()); // already scanning
        }
        let c = Arc::new(AtomicBool::new(false));
        *slot = Some(c.clone());
        c
    };
    let h = handle.clone();
    tauri::async_runtime::spawn(async move {
        run_scan(h.clone(), cancel).await;
        *h.state::<App>().scan.lock().unwrap() = None;
    });
    Ok(())
}

/// Tailnet first, then the LAN: running both sweeps at once starves the tailnet's relayed connects.
async fn run_scan(handle: AppHandle, cancel: Arc<AtomicBool>) {
    let started = Instant::now();
    let previous = handle.state::<App>().records.lock().unwrap().clone();
    let lan: Arc<Mutex<Vec<netscan::Host>>> = Default::default();
    let tail_hosts: Arc<Mutex<Vec<netscan::Host>>> = Default::default();
    let tail_status: Arc<Mutex<Option<netscan::TailnetStatus>>> = Default::default();
    let ssh = Arc::new(tokio::task::spawn_blocking(netscan::ssh_hosts).await.unwrap_or_default());
    let last_emit = Arc::new(Mutex::new(Instant::now() - Duration::from_secs(1)));

    let remerge = {
        let (handle, lan, tail_hosts, tail_status, ssh, previous) =
            (handle.clone(), lan.clone(), tail_hosts.clone(), tail_status.clone(), ssh.clone(), previous.clone());
        move |force: bool| {
            let mut last = last_emit.lock().unwrap();
            if !force && last.elapsed() < Duration::from_millis(600) {
                return;
            }
            *last = Instant::now();
            let lan = lan.lock().unwrap().clone();
            let th = tail_hosts.lock().unwrap().clone();
            let ts = tail_status.lock().unwrap().clone();
            let mut merged = netscan::merge(&lan, &th, ts.as_ref(), &ssh);
            // Keep systems seen before but not this time, as offline, so labels and history survive.
            for old in &previous {
                if !merged.iter().any(|r| r.id == old.id) {
                    let mut o = old.clone();
                    o.online = false;
                    merged.push(o);
                }
            }
            *handle.state::<App>().records.lock().unwrap() = merged.clone();
            let _ = handle.emit("records://update", &merged);
        }
    };
    let remerge = Arc::new(remerge);

    let host_sink = |list: Arc<Mutex<Vec<netscan::Host>>>, handle: AppHandle, remerge: Arc<dyn Fn(bool) + Send + Sync>| -> netscan::Emit {
        Arc::new(move |ev: netscan::ScanEvent| match ev {
            netscan::ScanEvent::Host { host } => {
                let mut l = list.lock().unwrap();
                match l.iter_mut().find(|h| h.ip == host.ip) {
                    Some(h) => *h = *host,
                    None => l.push(*host),
                }
                drop(l);
                remerge(false);
            }
            netscan::ScanEvent::Done { .. } => {}
            other => {
                let _ = handle.emit("scan://event", &other);
            }
        })
    };

    let opts = netscan::ScanOptions::default();
    let emit_tail = host_sink(tail_hosts.clone(), handle.clone(), remerge.clone());
    match netscan::scan_tailnet(opts.clone(), cancel.clone(), emit_tail).await {
        Ok((status, hosts)) => {
            *tail_status.lock().unwrap() = Some(status);
            let mut th = tail_hosts.lock().unwrap();
            for h in hosts {
                if !th.iter().any(|x| x.ip == h.ip) {
                    th.push(h);
                }
            }
        }
        Err(message) => {
            let _ = handle.emit("scan://event", UiScanEvent::TailnetError { message });
        }
    }
    remerge(true);

    if !cancel.load(Ordering::Relaxed) {
        let emit_lan = host_sink(lan.clone(), handle.clone(), remerge.clone());
        let hosts = netscan::scan(opts, cancel.clone(), emit_lan).await;
        *lan.lock().unwrap() = hosts;
    }
    remerge(true);

    let records = handle.state::<App>().records.lock().unwrap().clone();
    if let Ok(bytes) = serde_json::to_vec(&records) {
        let _ = std::fs::write(records_path(), bytes);
    }
    let _ = handle.emit(
        "scan://event",
        UiScanEvent::Done {
            systems: records.iter().filter(|r| r.online).count(),
            millis: started.elapsed().as_millis() as u64,
            cancelled: cancel.load(Ordering::Relaxed),
        },
    );
}

/// The localhost base + token the UI uses to stream and read tags for a media file.
#[tauri::command]
async fn media_base(handle: AppHandle) -> Res<stream::MediaBase> {
    let app = handle.state::<App>();
    {
        let g = app.media.lock().await;
        if let Some(s) = g.as_ref() {
            return Ok(s.base());
        }
    }
    let server = stream::MediaServer::start(app.vfs.clone()).await?;
    let base = server.base();
    *app.media.lock().await = Some(server);
    Ok(base)
}

#[tauri::command]
async fn open_url(url: String) -> Res<()> {
    tokio::task::spawn_blocking(move || netscan::open_target(&url)).await.map_err(|e| e.to_string())?
}

/* ---------------- files ---------------- */

#[tauri::command]
async fn fs_roots(app: State<'_, App>) -> FsRes<Vec<vfs::Entry>> {
    Ok(app.vfs.roots().await)
}

#[tauri::command]
async fn fs_list(app: State<'_, App>, loc: String) -> FsRes<Vec<vfs::Entry>> {
    app.vfs.list(&parse(&loc)?).await
}

#[tauri::command]
async fn fs_stat(app: State<'_, App>, loc: String) -> FsRes<vfs::Entry> {
    app.vfs.stat(&parse(&loc)?).await
}

#[tauri::command]
fn fs_normalize(loc: String) -> FsRes<String> {
    Ok(parse(&loc)?.to_uri())
}

#[tauri::command]
fn fs_parent(loc: String) -> FsRes<Option<String>> {
    Ok(parse(&loc)?.parent().map(|p| p.to_uri()))
}

#[tauri::command]
fn fs_join(loc: String, name: String) -> FsRes<String> {
    if name.contains(['/', '\\']) || name == ".." || name == "." || name.trim().is_empty() {
        return Err(other("A name can't contain slashes"));
    }
    Ok(parse(&loc)?.join(&name).to_uri())
}

#[tauri::command]
fn fs_forms(loc: String) -> FsRes<Vec<vfs::PathForm>> {
    Ok(parse(&loc)?.forms())
}

#[tauri::command]
async fn fs_preview(app: State<'_, App>, loc: String, max_bytes: usize) -> FsRes<vfs::Preview> {
    app.vfs.preview(&parse(&loc)?, max_bytes.min(32 * 1024 * 1024)).await
}

#[tauri::command]
async fn fs_mkdir(app: State<'_, App>, loc: String) -> FsRes<()> {
    app.vfs.mkdir(&parse(&loc)?).await
}

#[tauri::command]
async fn fs_rename(app: State<'_, App>, from: String, to: String) -> FsRes<()> {
    app.vfs.rename(&parse(&from)?, &parse(&to)?).await
}

#[tauri::command]
async fn fs_remove(app: State<'_, App>, loc: String, recursive: bool) -> FsRes<vfs::RemoveOutcome> {
    app.vfs.remove(&parse(&loc)?, recursive).await
}

#[tauri::command]
async fn fs_set_credentials(app: State<'_, App>, host: String, user: String, password: String) -> FsRes<()> {
    app.vfs.set_credentials(&host, &user, &password).await
}

#[tauri::command]
async fn fs_trust_host_key(app: State<'_, App>, host: String, port: u16, key: String) -> FsRes<()> {
    app.vfs.trust_host_key(&host, port, &key).await
}

/// Hand a file or folder to the OS (E2). Remote files that the OS can't open directly are copied
/// to a temporary folder first.
#[tauri::command]
async fn fs_open_system(app: State<'_, App>, loc: String) -> FsRes<()> {
    let l = parse(&loc)?;
    let native = l.forms().into_iter().find(|f| f.label.starts_with("Local path") || f.label.starts_with("UNC") || f.label.starts_with("Mount"));
    let target = match native {
        Some(f) => f.value,
        None => {
            let entry = app.vfs.stat(&l).await?;
            if entry.is_dir {
                return Err(other("This folder is on another system; browse it here, or open a terminal on it."));
            }
            let size = entry.size.unwrap_or(0);
            if size > 512 * 1024 * 1024 {
                return Err(other("This file is over 512 MB; copy it to this computer first."));
            }
            let dir = std::env::temp_dir().join("narada-open");
            std::fs::create_dir_all(&dir).map_err(|e| other(e.to_string()))?;
            let dest = dir.join(&entry.name);
            let fh = app.vfs.open_read(&l).await?;
            let mut out = Vec::with_capacity(size as usize);
            let mut off = 0u64;
            loop {
                let chunk = fh.read_at(off, 4 * 1024 * 1024).await?;
                if chunk.is_empty() {
                    break;
                }
                off += chunk.len() as u64;
                out.extend_from_slice(&chunk);
            }
            fh.close().await?;
            std::fs::write(&dest, out).map_err(|e| other(e.to_string()))?;
            dest.to_string_lossy().into_owned()
        }
    };
    tokio::task::spawn_blocking(move || netscan::open_target(&target)).await.map_err(|e| other(e.to_string()))?.map_err(other)
}

/// Reveal a local file or folder in the OS file manager, selected (E2: "Show in folder").
#[tauri::command]
async fn fs_reveal(loc: String) -> FsRes<()> {
    let l = parse(&loc)?;
    let native = l.forms().into_iter().find(|f| f.label.starts_with("Local path") || f.label.starts_with("UNC") || f.label.starts_with("Mount"));
    match native {
        Some(f) => tokio::task::spawn_blocking(move || netscan::reveal(&f.value)).await.map_err(|e| other(e.to_string()))?.map_err(other),
        None => Err(other("This item isn't on a local disk; browse to its folder here instead.")),
    }
}

/* ---------------- drives and dual boot ---------------- */

#[tauri::command]
async fn disks_list() -> DkRes<Vec<disks::Disk>> {
    tokio::task::spawn_blocking(disks::list_disks).await.map_err(disk_io)?
}

#[tauri::command]
async fn disks_mount(partition_id: String, read_only: bool) -> DkRes<String> {
    tokio::task::spawn_blocking(move || disks::mount(&partition_id, read_only)).await.map_err(disk_io)?
}

#[tauri::command]
async fn disks_unmount(partition_id: String) -> DkRes<()> {
    tokio::task::spawn_blocking(move || disks::unmount(&partition_id)).await.map_err(disk_io)?
}

#[tauri::command]
async fn disks_eject(disk_id: String) -> DkRes<()> {
    tokio::task::spawn_blocking(move || disks::eject(&disk_id)).await.map_err(disk_io)?
}

#[tauri::command]
fn disks_is_elevated() -> bool {
    disks::is_elevated()
}

/// Optional startup view, from the NAVSUITE_START_VIEW env var (used for testing a panel directly).
#[tauri::command]
fn start_view() -> String {
    std::env::var("NAVSUITE_START_VIEW").unwrap_or_default()
}

/// Browse a partition the OS hasn't mounted, through the built-in read-only reader (DB5, DB6).
/// Opened per call: fine for occasional browsing, and it keeps the reader off the main thread.
#[tauri::command]
async fn disks_raw_list(partition: disks::Partition, path: String) -> DkRes<Vec<disks::RawEntry>> {
    tokio::task::spawn_blocking(move || {
        let fs = disks::RawFs::open(&partition)?;
        fs.list(&path)
    })
    .await
    .map_err(disk_io)?
}

/// Copy a file off an unmounted partition to a temp file, then hand it to the normal pipeline.
#[tauri::command]
async fn disks_raw_fetch(partition: disks::Partition, path: String) -> Res<String> {
    let name = path.rsplit('/').next().unwrap_or("file").to_string();
    let bytes = tokio::task::spawn_blocking(move || -> DkRes<Vec<u8>> {
        let fs = disks::RawFs::open(&partition)?;
        let info = fs.stat(&path)?;
        let mut out = Vec::with_capacity(info.size as usize);
        let mut off = 0u64;
        loop {
            let chunk = fs.read_at(&path, off, 4 * 1024 * 1024)?;
            if chunk.is_empty() {
                break;
            }
            off += chunk.len() as u64;
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e: disks::DiskError| format!("{e:?}"))?;
    let dir = std::env::temp_dir().join("narada-raw");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let dest = dir.join(&name);
    std::fs::write(&dest, bytes).map_err(|e| e.to_string())?;
    Ok(dest.to_string_lossy().into_owned())
}

/* ---------------- transfers ---------------- */

#[tauri::command]
async fn xfer_plan(app: State<'_, App>, sources: Vec<String>, dest: String, op: String) -> FsRes<xfer::Plan> {
    let src = sources.iter().map(|s| parse(s)).collect::<FsRes<Vec<_>>>()?;
    let op = if op.eq_ignore_ascii_case("move") { xfer::Op::Move } else { xfer::Op::Copy };
    app.queue.plan(src, parse(&dest)?, op).await
}

#[tauri::command]
fn xfer_enqueue(app: State<'_, App>, plan: xfer::Plan, resolutions: HashMap<String, xfer::Resolution>, verify: bool, manifest: bool) -> String {
    app.queue.enqueue(plan, resolutions, xfer::JobOptions { verify, write_manifest: manifest })
}

#[tauri::command]
fn xfer_jobs(app: State<'_, App>) -> Vec<xfer::JobStatus> {
    app.queue.jobs()
}
#[tauri::command]
fn xfer_pause(app: State<'_, App>, id: String) {
    app.queue.pause(&id)
}
#[tauri::command]
fn xfer_resume(app: State<'_, App>, id: String) {
    app.queue.resume(&id)
}
#[tauri::command]
fn xfer_cancel(app: State<'_, App>, id: String) {
    app.queue.cancel(&id)
}
#[tauri::command]
fn xfer_retry(app: State<'_, App>, id: String) {
    app.queue.retry(&id)
}
#[tauri::command]
fn xfer_pause_all(app: State<'_, App>) {
    app.queue.pause_all()
}
#[tauri::command]
fn xfer_resume_all(app: State<'_, App>) {
    app.queue.resume_all()
}
#[tauri::command]
fn xfer_clear_finished(app: State<'_, App>) {
    app.queue.clear_finished()
}

/* ---------------- terminal ---------------- */

#[tauri::command]
fn term_shells() -> Vec<term::Shell> {
    term::shells()
}

#[tauri::command]
fn term_spawn(handle: AppHandle, app: State<'_, App>, start: term::Start) -> Res<u32> {
    let default_shell = app.settings.lock().unwrap().default_shell.clone();
    let (h1, h2) = (handle.clone(), handle.clone());
    app.terms.spawn(start, &default_shell, move |d| { let _ = h1.emit("term://data", d); }, move |x| { let _ = h2.emit("term://exit", x); })
}

#[tauri::command]
fn term_write(app: State<'_, App>, id: u32, data: String) -> Res<()> {
    app.terms.write(id, &data)
}

#[tauri::command]
fn term_resize(app: State<'_, App>, id: u32, cols: u16, rows: u16) -> Res<()> {
    app.terms.resize(id, cols, rows)
}

#[tauri::command]
fn term_close(app: State<'_, App>, id: u32) {
    app.terms.close(id)
}

/// Quote a location for a shell, converting SMB URLs to the path that shell can use.
#[tauri::command]
fn term_quote(shell: String, path: String) -> String {
    let native = Loc::parse(&path)
        .ok()
        .and_then(|l| l.forms().into_iter().find(|f| f.label.starts_with("Local path") || f.label.starts_with("UNC") || f.label.starts_with("Mount")).map(|f| f.value))
        .unwrap_or(path);
    term::quote_for(&shell, &native)
}

/* ---------------- probes ---------------- */

#[derive(Serialize, Clone)]
struct ProbeMsg {
    id: u32,
    event: probe::ProbeEvent,
}

#[tauri::command]
fn probe_run(handle: AppHandle, app: State<'_, App>, target: String, kind: probe::ProbeKind) -> u32 {
    let id = app.next_probe.fetch_add(1, Ordering::Relaxed) + 1;
    let cancel = Arc::new(AtomicBool::new(false));
    app.probes.lock().unwrap().insert(id, cancel.clone());
    let h = handle.clone();
    let emit: Arc<dyn Fn(probe::ProbeEvent) + Send + Sync> = Arc::new(move |event| {
        let _ = h.emit("probe://event", ProbeMsg { id, event });
    });
    tauri::async_runtime::spawn(async move {
        // run() passes every event, the final Done included, to emit.
        let _ = probe::run(&target, kind, cancel, emit).await;
        handle.state::<App>().probes.lock().unwrap().remove(&id);
    });
    id
}

#[tauri::command]
fn probe_cancel(app: State<'_, App>, id: u32) {
    if let Some(c) = app.probes.lock().unwrap().get(&id) {
        c.store(true, Ordering::Relaxed);
    }
}

/* ---------------- phones ---------------- */

async fn drop_server(app: &App) -> Res<Arc<dropsrv::DropServer>> {
    app.drop.lock().await.clone().ok_or_else(|| "The phone drop page is turned off in Settings.".to_string())
}

#[tauri::command]
async fn drop_phones(app: State<'_, App>) -> Res<Vec<dropsrv::Phone>> {
    Ok(drop_server(&app).await?.phones())
}

#[tauri::command]
async fn drop_inbox(app: State<'_, App>) -> Res<Vec<dropsrv::DropFile>> {
    Ok(drop_server(&app).await?.inbox("system"))
}

#[tauri::command]
async fn drop_urls(app: State<'_, App>) -> Res<Vec<String>> {
    let srv = drop_server(&app).await?;
    Ok(dropsrv::local_urls(srv.port()))
}

#[tauri::command]
async fn drop_ticket(app: State<'_, App>, base: String) -> Res<dropsrv::JoinTicket> {
    let srv = drop_server(&app).await?;
    let host = base.split("://").nth(1).unwrap_or(&base).split(['/', ':']).next().unwrap_or("").to_string();
    Ok(srv.new_join_ticket(&host))
}

#[tauri::command]
async fn drop_send(app: State<'_, App>, phone_id: String, loc: String) -> Res<dropsrv::DropFile> {
    let srv = drop_server(&app).await?;
    let l = Loc::parse(&loc).map_err(|e| e.message)?;
    let native = l
        .forms()
        .into_iter()
        .find(|f| f.label.starts_with("Local path") || f.label.starts_with("UNC") || f.label.starts_with("Mount"))
        .map(|f| f.value)
        .ok_or("Only files on this computer or a mounted share can be sent to a phone for now.")?;
    srv.send_to_phone(&phone_id, std::path::Path::new(&native)).await
}

#[tauri::command]
async fn drop_rename_phone(app: State<'_, App>, id: String, name: String) -> Res<()> {
    drop_server(&app).await?.rename_phone(&id, &name);
    Ok(())
}

#[tauri::command]
async fn drop_forget_phone(app: State<'_, App>, id: String) -> Res<()> {
    drop_server(&app).await?.forget_phone(&id);
    Ok(())
}

async fn start_drop(handle: AppHandle) {
    let s = handle.state::<App>().settings.lock().unwrap().clone();
    if !s.drop_enabled {
        return;
    }
    let device_name = dns_lookup_hostname();
    let cfg = dropsrv::DropConfig {
        port: s.drop_port,
        data_dir: settings::data_dir().join("drop"),
        device_name,
        expiry_hours: s.drop_expiry_hours,
        tls: None,
    };
    let h = handle.clone();
    let emit: Arc<dyn Fn(dropsrv::DropEvent) + Send + Sync> = Arc::new(move |ev| {
        let _ = h.emit("drop://event", &ev);
    });
    match dropsrv::DropServer::start(cfg, emit).await {
        Ok(srv) => {
            let _ = handle.emit("log://line", format!("Phone drop page on port {}", srv.port()));
            *handle.state::<App>().drop.lock().await = Some(srv);
        }
        Err(e) => {
            let _ = handle.emit("log://line", format!("Phone drop page could not start: {e}"));
        }
    }
}

fn dns_lookup_hostname() -> String {
    std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).unwrap_or_else(|_| "This computer".into())
}

/* ---------------- background scans ---------------- */

async fn scan_timer(handle: AppHandle) {
    loop {
        let mins = handle.state::<App>().settings.lock().unwrap().scan_interval_min;
        let wait = if mins == 0 { 60 } else { mins as u64 * 60 };
        tokio::time::sleep(Duration::from_secs(wait)).await;
        if mins > 0 {
            let _ = scan_start(handle.clone()).await;
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let data = settings::data_dir();
    let vfs = Arc::new(Vfs::new(data.join("vfs")));
    tauri::Builder::default()
        .setup(move |app| {
            let handle = app.handle().clone();
            let h = handle.clone();
            let emit: Arc<dyn Fn(xfer::XferEvent) + Send + Sync> = Arc::new(move |ev| {
                let _ = h.emit("xfer://event", &ev);
            });
            let queue = xfer::Queue::new(vfs.clone(), data.join("transfers"), emit);
            app.manage(App {
                settings: Mutex::new(settings::load()),
                vfs: vfs.clone(),
                queue,
                terms: term::Terminals::default(),
                drop: tokio::sync::Mutex::new(None),
                scan: Mutex::new(None),
                records: Mutex::new(load_records()),
                probes: Mutex::new(HashMap::new()),
                next_probe: AtomicU32::new(0),
                media: tokio::sync::Mutex::new(None),
            });
            tauri::async_runtime::spawn(start_drop(handle.clone()));
            tauri::async_runtime::spawn(scan_timer(handle));
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::Destroyed = event {
                window.state::<App>().terms.close_all();
            }
        })
        .invoke_handler(tauri::generate_handler![
            settings_get, settings_set,
            records_get, scan_start, scan_cancel, open_url, media_base,
            disks_list, disks_mount, disks_unmount, disks_eject, disks_is_elevated, disks_raw_list, disks_raw_fetch, start_view,
            fs_roots, fs_list, fs_stat, fs_normalize, fs_parent, fs_join, fs_forms, fs_preview, fs_mkdir, fs_rename,
            fs_remove, fs_set_credentials, fs_trust_host_key, fs_open_system, fs_reveal,
            xfer_plan, xfer_enqueue, xfer_jobs, xfer_pause, xfer_resume, xfer_cancel, xfer_retry, xfer_pause_all,
            xfer_resume_all, xfer_clear_finished,
            term_shells, term_spawn, term_write, term_resize, term_close, term_quote,
            probe_run, probe_cancel,
            drop_phones, drop_inbox, drop_urls, drop_ticket, drop_send, drop_rename_phone, drop_forget_phone,
        ])
        .run(tauri::generate_context!())
        .expect("error while running narada");
}
