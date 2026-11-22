//! Elevated raw-read helper (Windows) and its client.
//!
//! The normal (non-admin) app creates a named pipe `\\.\pipe\<name>` and starts
//! itself elevated via `ShellExecuteExW("runas", exe, "--disk-helper <name> <token>")`.
//! The elevated helper connects to that pipe as a client, the app sends the
//! token first, and from then on the helper serves read-only RawFs requests as
//! JSON lines. The pipe is created by the app with `FILE_FLAG_FIRST_PIPE_INSTANCE`
//! and `PIPE_REJECT_REMOTE_CLIENTS`; the app verifies the connecting process id
//! is the helper it spawned, and the helper refuses to do anything before the
//! token matches. The helper only opens `\\.\PhysicalDriveN` devices, read-only.

use crate::rawfs::{RawEntry, RawFs, RawProbe, probe_raw};
use crate::{Disk, DiskError, FsType, Partition, apply_probe};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "op", rename_all = "camelCase")]
pub(crate) enum Request {
    #[serde(rename_all = "camelCase")]
    Hello { token: String },
    #[serde(rename_all = "camelCase")]
    Open { raw_path: String, offset: u64, size: u64, fs: Option<FsType> },
    #[serde(rename_all = "camelCase")]
    Probe { raw_path: String, offset: u64, size: u64 },
    #[serde(rename_all = "camelCase")]
    List { handle: u32, path: String },
    #[serde(rename_all = "camelCase")]
    Stat { handle: u32, path: String },
    #[serde(rename_all = "camelCase")]
    ReadAt { handle: u32, path: String, offset: u64, len: usize },
    #[serde(rename_all = "camelCase")]
    Close { handle: u32 },
    Shutdown,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct Envelope {
    id: u64,
    #[serde(flatten)]
    req: Request,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct Response {
    id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    ok: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    err: Option<DiskError>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenOk {
    handle: u32,
    fs: FsType,
}

/// Constant-time-ish comparison for the token.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn token_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Raw paths the Windows helper will open: `\\.\PhysicalDriveN` only.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn windows_raw_path_allowed(p: &str) -> bool {
    p.strip_prefix(r"\\.\PhysicalDrive")
        .is_some_and(|n| !n.is_empty() && n.len() <= 3 && n.bytes().all(|b| b.is_ascii_digit()))
}

/// Serve requests until EOF/shutdown. The first line must be a `hello` with the token.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
pub(crate) fn serve(
    reader: impl Read,
    mut writer: impl Write,
    token: &str,
    allowed: &dyn Fn(&str) -> bool,
) -> Result<(), DiskError> {
    let mut lines = BufReader::new(reader).lines();
    let first = lines.next().ok_or(DiskError::NotFound)?.map_err(DiskError::from)?;
    let env: Envelope = serde_json::from_str(&first).map_err(DiskError::io)?;
    let ok = matches!(&env.req, Request::Hello { token: t } if token_eq(t, token));
    if !ok {
        return Err(DiskError::io("bad helper token"));
    }
    write_line(&mut writer, &Response { id: env.id, ok: Some(serde_json::Value::Bool(true)), err: None })?;

    let mut handles: HashMap<u32, RawFs> = HashMap::new();
    let mut next = 1u32;
    for line in lines {
        let line = line.map_err(DiskError::from)?;
        if line.trim().is_empty() {
            continue;
        }
        let env: Envelope = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(e) => return Err(DiskError::io(format!("bad request: {e}"))),
        };
        let id = env.id;
        let shutdown = matches!(env.req, Request::Shutdown);
        let result = handle(env.req, &mut handles, &mut next, allowed);
        let resp = match result {
            Ok(v) => Response { id, ok: Some(v), err: None },
            Err(e) => Response { id, ok: None, err: Some(e) },
        };
        write_line(&mut writer, &resp)?;
        if shutdown {
            break;
        }
    }
    Ok(())
}

#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn handle(
    req: Request,
    handles: &mut HashMap<u32, RawFs>,
    next: &mut u32,
    allowed: &dyn Fn(&str) -> bool,
) -> Result<serde_json::Value, DiskError> {
    fn to<T: Serialize>(v: &T) -> serde_json::Value {
        serde_json::to_value(v).unwrap_or(serde_json::Value::Null)
    }
    match req {
        Request::Hello { .. } => Ok(serde_json::Value::Bool(true)),
        Request::Shutdown => Ok(serde_json::Value::Bool(true)),
        Request::Open { raw_path, offset, size, fs } => {
            if !allowed(&raw_path) {
                return Err(DiskError::unsupported("raw path not allowed"));
            }
            let r = RawFs::open_raw(&raw_path, offset, size, fs)?;
            let h = *next;
            *next += 1;
            let fs = r.fs_type();
            handles.insert(h, r);
            Ok(to(&OpenOk { handle: h, fs }))
        }
        Request::Probe { raw_path, offset, size } => {
            if !allowed(&raw_path) {
                return Err(DiskError::unsupported("raw path not allowed"));
            }
            Ok(to(&probe_raw(&raw_path, offset, size)?))
        }
        Request::List { handle, path } => {
            let r = handles.get(&handle).ok_or(DiskError::NotFound)?;
            Ok(to(&r.list(&path)?))
        }
        Request::Stat { handle, path } => {
            let r = handles.get(&handle).ok_or(DiskError::NotFound)?;
            Ok(to(&r.stat(&path)?))
        }
        Request::ReadAt { handle, path, offset, len } => {
            let r = handles.get(&handle).ok_or(DiskError::NotFound)?;
            let data = r.read_at(&path, offset, len)?;
            Ok(serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(data)))
        }
        Request::Close { handle } => {
            handles.remove(&handle);
            Ok(serde_json::Value::Bool(true))
        }
    }
}

fn write_line<T: Serialize>(w: &mut impl Write, v: &T) -> Result<(), DiskError> {
    let mut s = serde_json::to_string(v).map_err(DiskError::io)?;
    s.push('\n');
    w.write_all(s.as_bytes()).map_err(DiskError::from)?;
    w.flush().map_err(DiskError::from)
}

/// Entry point for `navsuite --disk-helper <pipe-name> <token>` (pass the full
/// `std::env::args()` list). Never returns. Exit codes: 0 ok, 2 bad args/token,
/// 3 pipe error, 4 unsupported OS.
pub fn helper_main(args: &[String]) -> ! {
    let pos = args.iter().position(|a| a == "--disk-helper");
    let (Some(name), Some(token)) = (pos.and_then(|i| args.get(i + 1)), pos.and_then(|i| args.get(i + 2))) else {
        eprintln!("usage: --disk-helper <pipe-name> <token>");
        std::process::exit(2);
    };
    #[cfg(windows)]
    {
        if !crate::windows::valid_pipe_name(name) {
            std::process::exit(2);
        }
        let pipe = match crate::windows::open_pipe_client(name) {
            Ok(p) => p,
            Err(_) => std::process::exit(3),
        };
        let reader = match pipe.try_clone() {
            Ok(r) => r,
            Err(_) => std::process::exit(3),
        };
        match serve(reader, pipe, token, &windows_raw_path_allowed) {
            Ok(()) => std::process::exit(0),
            Err(DiskError::Io { message }) if message == "bad helper token" => std::process::exit(2),
            Err(_) => std::process::exit(3),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (name, token);
        eprintln!("--disk-helper is only used on Windows; mount read-only instead");
        std::process::exit(4);
    }
}

type Conn = (BufReader<Box<dyn Read + Send>>, Box<dyn Write + Send>);

/// Client for the elevated helper. Thread-safe; requests are serialized.
pub struct HelperClient {
    conn: Mutex<Conn>,
    ids: AtomicU64,
    #[cfg(windows)]
    process: Option<crate::windows::OwnedHandle>,
}

impl std::fmt::Debug for HelperClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HelperClient")
    }
}

impl HelperClient {
    /// Start `exe_path --disk-helper <pipe> <token>` elevated (UAC prompt) and
    /// connect. `Err(NeedsAdmin)` if the user declines the prompt.
    /// Unsupported on Linux/macOS (mount read-only via [`crate::mount`] instead).
    pub fn spawn_elevated(exe_path: &std::path::Path) -> Result<Arc<HelperClient>, DiskError> {
        #[cfg(windows)]
        {
            let token = random_hex(16)?;
            let name = format!("navsuite-disk-{}", random_hex(8)?);
            let (pipe, process) = crate::windows::spawn_helper(exe_path, &name, &token)?;
            let reader = pipe.try_clone().map_err(DiskError::from)?;
            let client = HelperClient {
                conn: Mutex::new((BufReader::new(Box::new(reader)), Box::new(pipe))),
                ids: AtomicU64::new(1),
                process: Some(process),
            };
            client.call(Request::Hello { token })?;
            Ok(Arc::new(client))
        }
        #[cfg(not(windows))]
        {
            let _ = exe_path;
            Err(DiskError::unsupported("the elevated helper is Windows-only; mount the partition read-only instead"))
        }
    }

    /// Connect over arbitrary streams (used by tests; sends the hello/token).
    #[cfg(test)]
    pub(crate) fn over_streams(
        reader: Box<dyn Read + Send>,
        writer: Box<dyn Write + Send>,
        token: &str,
    ) -> Result<Arc<HelperClient>, DiskError> {
        let client = HelperClient {
            conn: Mutex::new((BufReader::new(reader), writer)),
            ids: AtomicU64::new(1),
            #[cfg(windows)]
            process: None,
        };
        client.call(Request::Hello { token: token.to_string() })?;
        Ok(Arc::new(client))
    }

    fn call(&self, req: Request) -> Result<serde_json::Value, DiskError> {
        let id = self.ids.fetch_add(1, Ordering::Relaxed);
        let mut g = self.conn.lock().map_err(|_| DiskError::io("helper connection poisoned"))?;
        let (r, w) = &mut *g;
        write_line(w, &Envelope { id, req })?;
        let mut line = String::new();
        if r.read_line(&mut line).map_err(DiskError::from)? == 0 {
            return Err(DiskError::io("helper exited"));
        }
        let resp: Response = serde_json::from_str(&line).map_err(DiskError::io)?;
        if resp.id != id {
            return Err(DiskError::io("helper protocol out of sync"));
        }
        match (resp.ok, resp.err) {
            (_, Some(e)) => Err(e),
            (Some(v), None) => Ok(v),
            (None, None) => Err(DiskError::io("empty helper response")),
        }
    }

    fn call_as<T: for<'de> Deserialize<'de>>(&self, req: Request) -> Result<T, DiskError> {
        serde_json::from_value(self.call(req)?).map_err(DiskError::io)
    }

    /// Probe a partition raw in the helper (fs, label, OS, hibernation).
    pub fn probe(&self, p: &Partition) -> Result<RawProbe, DiskError> {
        self.call_as(Request::Probe { raw_path: p.raw_path.clone(), offset: p.offset, size: p.size })
    }

    /// Probe every partition flagged `needs_admin` and apply the results.
    pub fn refine(&self, disks: &mut [Disk]) {
        for p in disks.iter_mut().flat_map(|d| d.partitions.iter_mut()).filter(|p| p.needs_admin) {
            if let Ok(probe) = self.probe(p) {
                apply_probe(p, &probe);
            }
        }
    }

    /// Open a partition's file system in the helper.
    pub fn open(self: &Arc<Self>, p: &Partition) -> Result<RemoteFs, DiskError> {
        self.open_raw(&p.raw_path, p.offset, p.size, Some(p.fs))
    }

    pub fn open_raw(self: &Arc<Self>, raw_path: &str, offset: u64, size: u64, fs: Option<FsType>) -> Result<RemoteFs, DiskError> {
        let ok: OpenOk = self.call_as(Request::Open { raw_path: raw_path.to_string(), offset, size, fs })?;
        Ok(RemoteFs { client: Arc::clone(self), handle: ok.handle, fs: ok.fs })
    }

    /// Ask the helper to exit.
    pub fn shutdown(&self) {
        let _ = self.call(Request::Shutdown);
    }
}

impl Drop for HelperClient {
    fn drop(&mut self) {
        #[cfg(windows)]
        if self.process.is_some() {
            // Best effort; the helper also exits when the pipe closes.
            let id = self.ids.fetch_add(1, Ordering::Relaxed);
            if let Ok(mut g) = self.conn.lock() {
                let _ = write_line(&mut g.1, &Envelope { id, req: Request::Shutdown });
            }
        }
    }
}

/// A file system opened in the elevated helper; same calls as [`RawFs`].
#[derive(Debug)]
pub struct RemoteFs {
    client: Arc<HelperClient>,
    handle: u32,
    fs: FsType,
}

impl RemoteFs {
    pub fn fs_type(&self) -> FsType {
        self.fs
    }
    pub fn list(&self, path: &str) -> Result<Vec<RawEntry>, DiskError> {
        self.client.call_as(Request::List { handle: self.handle, path: path.to_string() })
    }
    pub fn stat(&self, path: &str) -> Result<RawEntry, DiskError> {
        self.client.call_as(Request::Stat { handle: self.handle, path: path.to_string() })
    }
    pub fn read_at(&self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>, DiskError> {
        let s: String = self.client.call_as(Request::ReadAt { handle: self.handle, path: path.to_string(), offset, len })?;
        base64::engine::general_purpose::STANDARD.decode(s).map_err(DiskError::io)
    }
}

impl Drop for RemoteFs {
    fn drop(&mut self) {
        let _ = self.client.call(Request::Close { handle: self.handle });
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn random_hex(bytes: usize) -> Result<String, DiskError> {
    let mut b = vec![0u8; bytes];
    getrandom::fill(&mut b).map_err(|e| DiskError::io(format!("random: {e}")))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}
