//! SFTP backend: russh + russh-sftp, pooled sessions, OpenSSH-compatible
//! auth (agent, default keys, stored password) and known_hosts checking.

use crate::creds::Creds;
use crate::error::{ErrorKind, Result, VfsError};
use crate::local::RawEntry;
use crate::{Loc, WriteMode};
use russh::client;
use russh::keys::agent::AgentIdentity;
use russh::keys::agent::client::AgentClient;
use russh::keys::{HashAlg, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
use russh_sftp::client::SftpSession;
use russh_sftp::client::error::Error as SftpError;
use russh_sftp::protocol::{FileAttributes, OpenFlags, StatusCode};
use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

// ---------------------------------------------------------------- ssh config

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct HostConfig {
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_files: Vec<String>,
}

fn glob_match(pat: &str, s: &str) -> bool {
    fn rec(p: &[u8], s: &[u8]) -> bool {
        match (p.first(), s.first()) {
            (None, None) => true,
            (Some(b'*'), _) => rec(&p[1..], s) || (!s.is_empty() && rec(p, &s[1..])),
            (Some(b'?'), Some(_)) => rec(&p[1..], &s[1..]),
            (Some(a), Some(b)) if a.eq_ignore_ascii_case(b) => rec(&p[1..], &s[1..]),
            _ => false,
        }
    }
    rec(pat.as_bytes(), s.as_bytes())
}

fn host_matches(patterns: &[String], host: &str) -> bool {
    let mut hit = false;
    for p in patterns {
        if let Some(neg) = p.strip_prefix('!') {
            if glob_match(neg, host) {
                return false;
            }
        } else if glob_match(p, host) {
            hit = true;
        }
    }
    hit
}

/// Minimal ~/.ssh/config reader: Host blocks with HostName, User, Port,
/// IdentityFile; first value wins (like OpenSSH). Match blocks are skipped.
pub(crate) fn parse_ssh_config(text: &str, host: &str) -> HostConfig {
    let mut cfg = HostConfig::default();
    let mut active = true; // lines before the first Host apply to all
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, val) = match line.find(|c: char| c.is_whitespace() || c == '=') {
            Some(i) => (
                &line[..i],
                line[i..]
                    .trim_start_matches(|c: char| c.is_whitespace() || c == '=')
                    .trim(),
            ),
            None => (line, ""),
        };
        let val = val.trim_matches('"');
        match key.to_ascii_lowercase().as_str() {
            "host" => {
                let pats: Vec<String> = val
                    .split_whitespace()
                    .map(|s| s.trim_matches('"').to_string())
                    .collect();
                active = host_matches(&pats, host);
            }
            "match" => active = false,
            _ if !active => {}
            "hostname" if cfg.hostname.is_none() => cfg.hostname = Some(val.replace("%h", host)),
            "user" if cfg.user.is_none() => cfg.user = Some(val.to_string()),
            "port" if cfg.port.is_none() => cfg.port = val.parse().ok(),
            "identityfile" => cfg.identity_files.push(val.to_string()),
            _ => {}
        }
    }
    cfg
}

fn ssh_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".ssh"))
}

fn expand_tilde(p: &str, user: &str, host: &str) -> PathBuf {
    let p = p
        .replace("%u", user)
        .replace("%r", user)
        .replace("%h", host);
    let p = if let Some(home) = dirs::home_dir() {
        p.replace("%d", &home.to_string_lossy())
    } else {
        p
    };
    if let Some(rest) = p.strip_prefix("~/").or_else(|| p.strip_prefix("~\\"))
        && let Some(h) = dirs::home_dir()
    {
        return h.join(rest);
    }
    PathBuf::from(p)
}

fn local_username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "root".into())
}

#[derive(Debug, Clone)]
pub(crate) struct Target {
    pub alias: String,
    pub hostname: String,
    pub port: u16,
    pub user: String,
    pub identity_files: Vec<PathBuf>,
}

impl Target {
    fn key(&self) -> String {
        format!(
            "{}@{}:{}",
            self.user,
            self.hostname.to_ascii_lowercase(),
            self.port
        )
    }
}

pub(crate) fn resolve(host: &str, port: Option<u16>, user: Option<&str>) -> Target {
    let text = ssh_dir()
        .and_then(|d| std::fs::read_to_string(d.join("config")).ok())
        .unwrap_or_default();
    let cfg = parse_ssh_config(&text, host);
    let user = user
        .map(str::to_string)
        .or(cfg.user)
        .unwrap_or_else(local_username);
    let hostname = cfg.hostname.unwrap_or_else(|| host.to_string());
    let identity_files = cfg
        .identity_files
        .iter()
        .map(|f| expand_tilde(f, &user, &hostname))
        .collect();
    Target {
        alias: host.to_string(),
        hostname,
        port: port.or(cfg.port).unwrap_or(22),
        user,
        identity_files,
    }
}

// ---------------------------------------------------------------- host keys

#[derive(Debug, Clone)]
enum KeyIssue {
    Unknown {
        fingerprint: String,
        key_openssh: String,
    },
    Changed {
        fingerprint: String,
        file: PathBuf,
        line: usize,
    },
}

struct Client {
    host: String,
    port: u16,
    known_files: Vec<PathBuf>,
    issue: Arc<Mutex<Option<KeyIssue>>>,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        let key: PublicKey = match server {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
            PublicKeyOrCertificate::Certificate(c) => PublicKey::new(c.public_key().clone(), ""),
        };
        let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
        for f in &self.known_files {
            match russh::keys::check_known_hosts_path(&self.host, self.port, &key, f) {
                Ok(true) => return Ok(true),
                Ok(false) => {}
                Err(russh::keys::Error::KeyChanged { line }) => {
                    *self.issue.lock().unwrap() = Some(KeyIssue::Changed {
                        fingerprint,
                        file: f.clone(),
                        line,
                    });
                    return Ok(false);
                }
                Err(_) => {}
            }
        }
        let key_openssh = key.to_openssh().unwrap_or_default();
        *self.issue.lock().unwrap() = Some(KeyIssue::Unknown {
            fingerprint,
            key_openssh,
        });
        Ok(false)
    }
}

// ---------------------------------------------------------------- errors

fn map_russh(e: russh::Error, what: &str) -> VfsError {
    use russh::Error as E;
    match e {
        E::IO(io) => VfsError::from(io).context(what),
        E::Disconnect
        | E::HUP
        | E::ConnectionTimeout
        | E::KeepaliveTimeout
        | E::InactivityTimeout
        | E::SendError
        | E::RecvError
        | E::Elapsed(_) => VfsError::offline(format!("{what}: connection lost ({e})")),
        e => VfsError::other(format!("{what}: {e}")),
    }
}

pub(crate) fn map_sftp(e: SftpError, path: &str) -> VfsError {
    match e {
        SftpError::Status(s) => {
            let kind = match s.status_code {
                StatusCode::NoSuchFile => ErrorKind::NotFound,
                StatusCode::PermissionDenied => ErrorKind::PermissionDenied,
                StatusCode::OpUnsupported => ErrorKind::Unsupported,
                StatusCode::NoConnection | StatusCode::ConnectionLost => ErrorKind::Offline,
                _ => ErrorKind::Other,
            };
            let msg = if s.error_message.is_empty() {
                s.status_code.to_string()
            } else {
                s.error_message
            };
            VfsError::new(kind, format!("{path}: {msg}"))
        }
        SftpError::IO(m) => VfsError::offline(format!("{path}: {m}")),
        SftpError::Timeout => VfsError::offline(format!("{path}: SFTP request timed out")),
        SftpError::UnexpectedBehavior(m) if m.contains("SendError") || m.contains("RecvError") => {
            VfsError::offline(format!("{path}: connection lost"))
        }
        e => VfsError::other(format!("{path}: {e}")),
    }
}

// ---------------------------------------------------------------- pool

pub(crate) struct Conn {
    handle: client::Handle<Client>,
    pub sftp: SftpSession,
}

impl Conn {
    fn alive(&self) -> bool {
        !self.handle.is_closed()
    }
}

type Slot = Arc<tokio::sync::Mutex<Option<Arc<Conn>>>>;

pub(crate) struct SftpPool {
    app_known_hosts: PathBuf,
    slots: Mutex<HashMap<String, Slot>>,
}

/// Path as sent to the server: `~` -> `.`, `~/x` -> `x`.
pub(crate) fn remote_path(loc: &Loc) -> String {
    if loc.path == "~" {
        ".".into()
    } else if let Some(r) = loc.path.strip_prefix("~/") {
        r.to_string()
    } else {
        loc.path.clone()
    }
}

#[cfg(unix)]
async fn agent()
-> Option<AgentClient<Box<dyn russh::keys::agent::client::AgentStream + Send + Unpin>>> {
    std::env::var_os("SSH_AUTH_SOCK")?;
    let a = tokio::time::timeout(Duration::from_secs(2), AgentClient::connect_env())
        .await
        .ok()?
        .ok()?;
    Some(a.dynamic())
}

#[cfg(windows)]
async fn agent()
-> Option<AgentClient<Box<dyn russh::keys::agent::client::AgentStream + Send + Unpin>>> {
    let a = tokio::time::timeout(
        Duration::from_secs(2),
        AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent"),
    )
    .await
    .ok()?
    .ok()?;
    Some(a.dynamic())
}

#[cfg(not(any(unix, windows)))]
async fn agent()
-> Option<AgentClient<Box<dyn russh::keys::agent::client::AgentStream + Send + Unpin>>> {
    None
}

impl SftpPool {
    pub fn new(data_dir: &Path) -> SftpPool {
        SftpPool {
            app_known_hosts: data_dir.join("known_hosts"),
            slots: Mutex::new(HashMap::new()),
        }
    }

    fn known_files(&self) -> Vec<PathBuf> {
        let mut v = Vec::new();
        if let Some(d) = ssh_dir() {
            v.push(d.join("known_hosts"));
        }
        v.push(self.app_known_hosts.clone());
        v
    }

    pub async fn trust(&self, host: &str, port: u16, key_openssh: &str) -> Result<()> {
        let key = PublicKey::from_openssh(key_openssh.trim())
            .map_err(|e| VfsError::other(format!("invalid host key: {e}")))?;
        let t = resolve(host, Some(port), None);
        let path = self.app_known_hosts.clone();
        let hostname = t.hostname;
        tokio::task::spawn_blocking(move || {
            russh::keys::known_hosts::learn_known_hosts_path(&hostname, port, &key, &path)
                .map_err(|e| VfsError::other(format!("could not record host key: {e}")))
        })
        .await?
    }

    /// Drop pooled sessions for a host (e.g. after the credentials changed).
    pub fn forget_host(&self, host: &str) {
        let h = host.to_ascii_lowercase();
        let t = resolve(host, None, None).hostname.to_ascii_lowercase();
        self.slots.lock().unwrap().retain(|k, _| {
            let kh = k.split_once('@').map(|x| x.1).unwrap_or(k);
            let kh = kh.rsplit_once(':').map(|x| x.0).unwrap_or(kh);
            kh != h && kh != t
        });
    }

    fn target(loc: &Loc) -> Result<Target> {
        let host = loc
            .host
            .as_deref()
            .ok_or_else(|| VfsError::other("sftp location without host"))?;
        Ok(resolve(host, loc.port, loc.user.as_deref()))
    }

    async fn get(&self, t: &Target, creds: &Creds) -> Result<Arc<Conn>> {
        let slot = self
            .slots
            .lock()
            .unwrap()
            .entry(t.key())
            .or_default()
            .clone();
        let mut g = slot.lock().await;
        if let Some(c) = g.as_ref()
            && c.alive()
        {
            return Ok(c.clone());
        }
        *g = None;
        let c = Arc::new(self.connect(t, creds).await?);
        *g = Some(c.clone());
        Ok(c)
    }

    fn invalidate(&self, t: &Target) {
        self.slots.lock().unwrap().remove(&t.key());
    }

    async fn connect(&self, t: &Target, creds: &Creds) -> Result<Conn> {
        let what = format!("{}:{}", t.hostname, t.port);
        let tcp = match tokio::time::timeout(
            CONNECT_TIMEOUT,
            tokio::net::TcpStream::connect((t.hostname.as_str(), t.port)),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(VfsError::offline(format!("{what}: {e}"))),
            Err(_) => {
                return Err(VfsError::offline(format!(
                    "{what}: no answer within {}s",
                    CONNECT_TIMEOUT.as_secs()
                )));
            }
        };
        let _ = tcp.set_nodelay(true);
        let issue = Arc::new(Mutex::new(None));
        let handler = Client {
            host: t.hostname.clone(),
            port: t.port,
            known_files: self.known_files(),
            issue: issue.clone(),
        };
        let config = client::Config {
            inactivity_timeout: None,
            keepalive_interval: Some(Duration::from_secs(15)),
            keepalive_max: 3,
            nodelay: true,
            ..Default::default()
        };
        let res = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            client::connect_stream(Arc::new(config), tcp, handler),
        )
        .await;
        let mut handle = match res {
            Err(_) => {
                return Err(VfsError::offline(format!(
                    "{what}: SSH handshake timed out"
                )));
            }
            Ok(Ok(h)) => h,
            Ok(Err(e)) => {
                return Err(match issue.lock().unwrap().take() {
                    Some(KeyIssue::Unknown {
                        fingerprint,
                        key_openssh,
                    }) => VfsError::new(
                        ErrorKind::HostKeyUnknown {
                            host: t.alias.clone(),
                            port: t.port,
                            fingerprint: fingerprint.clone(),
                            key_openssh,
                        },
                        format!(
                            "The authenticity of host {what} can't be established. Key fingerprint is {fingerprint}."
                        ),
                    ),
                    Some(KeyIssue::Changed {
                        fingerprint,
                        file,
                        line,
                    }) => VfsError::conflict(format!(
                        "HOST KEY FOR {what} HAS CHANGED (now {fingerprint}; recorded in {} line {line}). \
                         This could be a man-in-the-middle attack. Connection refused.",
                        file.display()
                    )),
                    None => map_russh(e, &what),
                });
            }
        };
        tokio::time::timeout(HANDSHAKE_TIMEOUT, self.authenticate(&mut handle, t, creds))
            .await
            .map_err(|_| VfsError::offline(format!("{what}: authentication timed out")))??;
        let chan = handle
            .channel_open_session()
            .await
            .map_err(|e| map_russh(e, &what))?;
        chan.request_subsystem(true, "sftp")
            .await
            .map_err(|e| map_russh(e, &what))?;
        let sftp = SftpSession::new(chan.into_stream())
            .await
            .map_err(|e| map_sftp(e, &what))?;
        sftp.set_timeout(30);
        Ok(Conn { handle, sftp })
    }

    async fn authenticate(
        &self,
        h: &mut client::Handle<Client>,
        t: &Target,
        creds: &Creds,
    ) -> Result<()> {
        let what = format!("{}@{}", t.user, t.hostname);
        let rsa_hash = h.best_supported_rsa_hash().await.ok().flatten().flatten();

        // 1. ssh-agent
        if let Some(mut ag) = agent().await
            && let Ok(Ok(ids)) =
                tokio::time::timeout(Duration::from_secs(3), ag.request_identities()).await
        {
            for id in ids {
                let AgentIdentity::PublicKey { key, .. } = &id else {
                    continue;
                };
                let hash = if key.algorithm().is_rsa() {
                    rsa_hash
                } else {
                    None
                };
                if let Ok(r) = h
                    .authenticate_publickey_with(t.user.clone(), key.clone(), hash, &mut ag)
                    .await
                    && r.success()
                {
                    return Ok(());
                }
                if h.is_closed() {
                    return Err(VfsError::offline(format!(
                        "{what}: connection closed during authentication"
                    )));
                }
            }
        }

        // 2. unencrypted key files
        let mut files = t.identity_files.clone();
        if let Some(d) = ssh_dir() {
            for n in ["id_ed25519", "id_ecdsa", "id_rsa"] {
                files.push(d.join(n));
            }
        }
        files.dedup();
        for f in files {
            let ff = f.clone();
            let key = tokio::task::spawn_blocking(move || {
                if ff.is_file() {
                    russh::keys::load_secret_key(&ff, None).ok()
                } else {
                    None
                }
            })
            .await
            .ok()
            .flatten();
            let Some(key) = key else { continue };
            let hash = if key.algorithm().is_rsa() {
                rsa_hash
            } else {
                None
            };
            match h
                .authenticate_publickey(
                    t.user.clone(),
                    PrivateKeyWithHashAlg::new(Arc::new(key), hash),
                )
                .await
            {
                Ok(r) if r.success() => return Ok(()),
                Ok(_) => {}
                Err(e) => return Err(map_russh(e, &what)),
            }
        }

        // 3. stored password (password, then keyboard-interactive)
        let pw = match creds.password(&t.alias, &t.user).await {
            Some(p) => Some(p),
            None if t.alias != t.hostname => creds.password(&t.hostname, &t.user).await,
            None => None,
        };
        if let Some(pw) = pw {
            match h.authenticate_password(t.user.clone(), pw.clone()).await {
                Ok(r) if r.success() => return Ok(()),
                Ok(_) => {}
                Err(e) => return Err(map_russh(e, &what)),
            }
            use russh::client::KeyboardInteractiveAuthResponse as K;
            let mut resp = h
                .authenticate_keyboard_interactive_start(t.user.clone(), None)
                .await;
            for _ in 0..5 {
                match resp {
                    Ok(K::Success) => return Ok(()),
                    Ok(K::InfoRequest { prompts, .. }) => {
                        let answers = prompts.iter().map(|_| pw.clone()).collect();
                        resp = h.authenticate_keyboard_interactive_respond(answers).await;
                    }
                    _ => break,
                }
            }
            return Err(VfsError::new(
                ErrorKind::AuthRequired {
                    host: t.alias.clone(),
                    user: Some(t.user.clone()),
                },
                format!("{what}: the stored password was rejected"),
            ));
        }
        Err(VfsError::new(
            ErrorKind::AuthRequired {
                host: t.alias.clone(),
                user: Some(t.user.clone()),
            },
            format!("{what}: no SSH key was accepted; a password is needed"),
        ))
    }

    /// Run `f` on a pooled session; on a transient failure reconnect once and retry.
    pub async fn run<T, F, Fut>(&self, loc: &Loc, creds: &Creds, f: F) -> Result<T>
    where
        F: Fn(Arc<Conn>) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let t = Self::target(loc)?;
        let c = self.get(&t, creds).await?;
        match f(c.clone()).await {
            Err(e) if e.is_transient() || !c.alive() => {
                self.invalidate(&t);
                let c = self.get(&t, creds).await?;
                f(c).await
            }
            r => r,
        }
    }
}

// ---------------------------------------------------------------- operations

fn raw_from_attrs(name: String, a: &FileAttributes) -> RawEntry {
    let is_dir = a.is_dir();
    RawEntry {
        hidden: name.starts_with('.'),
        size: if is_dir { None } else { a.size },
        modified: a.mtime.map(|t| t as i64 * 1000),
        is_dir,
        is_link: a.is_symlink(),
        name,
    }
}

pub(crate) async fn list(c: Arc<Conn>, path: String) -> Result<Vec<RawEntry>> {
    let rd = c
        .sftp
        .read_dir(path.clone())
        .await
        .map_err(|e| map_sftp(e, &path))?;
    let mut out = Vec::new();
    for ent in rd {
        let name = ent.file_name().to_string();
        let md = ent.metadata();
        let mut raw = raw_from_attrs(name.clone(), &md);
        if raw.is_link {
            let full = if path.ends_with('/') {
                format!("{path}{name}")
            } else {
                format!("{path}/{name}")
            };
            if let Ok(t) = c.sftp.metadata(full).await {
                raw.is_dir = t.is_dir();
                raw.size = if raw.is_dir { None } else { t.size };
                raw.modified = t.mtime.map(|t| t as i64 * 1000).or(raw.modified);
            }
        }
        out.push(raw);
    }
    Ok(out)
}

pub(crate) async fn stat(c: Arc<Conn>, path: String, name: String) -> Result<RawEntry> {
    let l = c
        .sftp
        .symlink_metadata(path.clone())
        .await
        .map_err(|e| map_sftp(e, &path))?;
    let mut raw = raw_from_attrs(name, &l);
    if raw.is_link
        && let Ok(t) = c.sftp.metadata(path).await
    {
        raw.is_dir = t.is_dir();
        raw.size = if raw.is_dir { None } else { t.size };
    }
    Ok(raw)
}

pub(crate) async fn canonicalize(c: Arc<Conn>, path: String) -> Result<String> {
    c.sftp
        .canonicalize(path.clone())
        .await
        .map(|s| s.to_string())
        .map_err(|e| map_sftp(e, &path))
}

pub(crate) async fn mkdir_p(c: Arc<Conn>, path: String) -> Result<()> {
    let mut missing = Vec::new();
    let mut cur = path.clone();
    loop {
        match c.sftp.metadata(cur.clone()).await {
            Ok(m) if m.is_dir() => break,
            Ok(_) => {
                return Err(VfsError::conflict(format!(
                    "{cur} exists and is not a folder"
                )));
            }
            Err(_) => {
                missing.push(cur.clone());
                match cur.rfind('/') {
                    Some(0) | None => break,
                    Some(i) => cur.truncate(i),
                }
            }
        }
    }
    for d in missing.into_iter().rev() {
        if let Err(e) = c.sftp.create_dir(d.clone()).await {
            // raced with someone else, or a parent we could not stat: re-check
            if !c
                .sftp
                .metadata(d.clone())
                .await
                .map(|m| m.is_dir())
                .unwrap_or(false)
            {
                return Err(map_sftp(e, &d));
            }
        }
    }
    Ok(())
}

pub(crate) async fn rename(c: Arc<Conn>, from: String, to: String, overwrite: bool) -> Result<()> {
    let exists = c.sftp.symlink_metadata(to.clone()).await.is_ok();
    if exists && !overwrite {
        return Err(VfsError::conflict(format!("{to} already exists")));
    }
    if exists {
        match c.sftp.posix_rename(from.clone(), to.clone()).await {
            Ok(true) => return Ok(()),
            Ok(false) => {
                let _ = c.sftp.remove_file(to.clone()).await;
            }
            Err(e) => return Err(map_sftp(e, &from)),
        }
    }
    c.sftp
        .rename(from.clone(), to)
        .await
        .map_err(|e| map_sftp(e, &from))
}

pub(crate) async fn remove(c: Arc<Conn>, path: String, recursive: bool) -> Result<()> {
    let md = c
        .sftp
        .symlink_metadata(path.clone())
        .await
        .map_err(|e| map_sftp(e, &path))?;
    if !md.is_dir() {
        return c
            .sftp
            .remove_file(path.clone())
            .await
            .map_err(|e| map_sftp(e, &path));
    }
    if !recursive {
        return c
            .sftp
            .remove_dir(path.clone())
            .await
            .map_err(|e| map_sftp(e, &path));
    }
    // depth-first, iterative
    let mut stack = vec![(path.clone(), false)];
    while let Some((dir, visited)) = stack.pop() {
        if visited {
            c.sftp
                .remove_dir(dir.clone())
                .await
                .map_err(|e| map_sftp(e, &dir))?;
            continue;
        }
        stack.push((dir.clone(), true));
        let rd = c
            .sftp
            .read_dir(dir.clone())
            .await
            .map_err(|e| map_sftp(e, &dir))?;
        for ent in rd {
            let p = format!("{}/{}", dir.trim_end_matches('/'), ent.file_name());
            let m = ent.metadata();
            if m.is_dir() && !m.is_symlink() {
                stack.push((p, false));
            } else {
                c.sftp
                    .remove_file(p.clone())
                    .await
                    .map_err(|e| map_sftp(e, &p))?;
            }
        }
    }
    Ok(())
}

pub(crate) async fn free_space(c: Arc<Conn>, path: String) -> Result<Option<u64>> {
    let s = c
        .sftp
        .fs_info(path.clone())
        .await
        .map_err(|e| map_sftp(e, &path))?;
    Ok(s.map(|s| s.blocks_avail.saturating_mul(s.fragment_size)))
}

/// An open remote file. Keeps its session alive.
pub struct SftpFile {
    _conn: Arc<Conn>,
    path: String,
    file: tokio::sync::Mutex<Option<russh_sftp::client::fs::File>>,
}

impl std::fmt::Debug for SftpFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SftpFile")
            .field("path", &self.path)
            .finish()
    }
}

fn closed(path: &str) -> VfsError {
    VfsError::other(format!("{path}: file already closed"))
}

impl SftpFile {
    pub(crate) async fn open(
        c: Arc<Conn>,
        path: String,
        write: Option<WriteMode>,
    ) -> Result<SftpFile> {
        let flags = match write {
            None => OpenFlags::READ,
            Some(WriteMode::Create) => {
                OpenFlags::READ | OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUDE
            }
            Some(WriteMode::Truncate) => {
                OpenFlags::READ | OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE
            }
            Some(WriteMode::ResumeAt(_)) => OpenFlags::READ | OpenFlags::WRITE | OpenFlags::CREATE,
        };
        if write.is_none() {
            let md = c
                .sftp
                .metadata(path.clone())
                .await
                .map_err(|e| map_sftp(e, &path))?;
            if md.is_dir() {
                return Err(VfsError::other(format!("{path} is a folder")));
            }
        }
        let f = c
            .sftp
            .open_with_flags(path.clone(), flags)
            .await
            .map_err(|e| {
                let e = map_sftp(e, &path);
                // OpenSSH reports EXCLUDE collisions as a generic failure
                if matches!(write, Some(WriteMode::Create)) && e.kind == ErrorKind::Other {
                    VfsError::conflict(e.message)
                } else {
                    e
                }
            })?;
        let me = SftpFile {
            _conn: c,
            path,
            file: tokio::sync::Mutex::new(Some(f)),
        };
        if let Some(WriteMode::ResumeAt(off)) = write {
            let len = me.len().await?;
            if len < off {
                return Err(VfsError::conflict(format!(
                    "{} is shorter ({len}) than the resume offset {off}",
                    me.path
                )));
            }
            if len > off {
                me.set_len(off).await?;
            }
        }
        Ok(me)
    }

    pub(crate) async fn read_at(&self, off: u64, len: usize) -> Result<Vec<u8>> {
        let mut g = self.file.lock().await;
        let f = g.as_mut().ok_or_else(|| closed(&self.path))?;
        f.seek(std::io::SeekFrom::Start(off))
            .await
            .map_err(|e| VfsError::from(e).context(&self.path))?;
        let mut buf = vec![0u8; len];
        let mut got = 0;
        while got < len {
            let n = f
                .read(&mut buf[got..])
                .await
                .map_err(|e| VfsError::from(e).context(&self.path))?;
            if n == 0 {
                break;
            }
            got += n;
        }
        buf.truncate(got);
        Ok(buf)
    }

    pub(crate) async fn write_at(&self, off: u64, data: &[u8]) -> Result<()> {
        let mut g = self.file.lock().await;
        let f = g.as_mut().ok_or_else(|| closed(&self.path))?;
        f.seek(std::io::SeekFrom::Start(off))
            .await
            .map_err(|e| VfsError::from(e).context(&self.path))?;
        f.write_all(data)
            .await
            .map_err(|e| VfsError::from(e).context(&self.path))?;
        f.flush()
            .await
            .map_err(|e| VfsError::from(e).context(&self.path))
    }

    pub(crate) async fn len(&self) -> Result<u64> {
        let g = self.file.lock().await;
        let f = g.as_ref().ok_or_else(|| closed(&self.path))?;
        Ok(f.metadata()
            .await
            .map_err(|e| map_sftp(e, &self.path))?
            .len())
    }

    pub(crate) async fn set_len(&self, n: u64) -> Result<()> {
        let g = self.file.lock().await;
        let f = g.as_ref().ok_or_else(|| closed(&self.path))?;
        let attrs = FileAttributes {
            size: Some(n),
            ..Default::default()
        };
        f.set_metadata(attrs)
            .await
            .map_err(|e| map_sftp(e, &self.path))
    }

    pub(crate) async fn close(&self) -> Result<()> {
        let f = self.file.lock().await.take();
        if let Some(mut f) = f {
            f.flush()
                .await
                .map_err(|e| VfsError::from(e).context(&self.path))?;
            f.close()
                .await
                .map_err(|e| VfsError::from(e).context(&self.path))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_config() {
        let text = "\
# global
User fallback
Host pi raspberry*
    HostName 192.168.1.50
    User pi
    Port 2222
    IdentityFile ~/.ssh/pi_ed25519
Host !nope *.lan
    User lanuser
Host *
    User other
    IdentityFile ~/.ssh/id_work
";
        let c = parse_ssh_config(text, "pi");
        assert_eq!(c.hostname.as_deref(), Some("192.168.1.50"));
        assert_eq!(c.user.as_deref(), Some("fallback")); // first value wins, like OpenSSH
        assert_eq!(c.port, Some(2222));
        assert_eq!(
            c.identity_files,
            vec!["~/.ssh/pi_ed25519", "~/.ssh/id_work"]
        );
        let c = parse_ssh_config("Host raspberry*\n  Port=2200\n", "raspberrypi");
        assert_eq!(c.port, Some(2200));
        let c = parse_ssh_config("Host !nope *.lan\n User lanuser\n", "box.lan");
        assert_eq!(c.user.as_deref(), Some("lanuser"));
        let c = parse_ssh_config("Host !nope *.lan\n User lanuser\n", "nope");
        assert_eq!(c.user, None);
        assert!(glob_match("ra?pberry*", "RASPBERRYPI"));
        assert!(!glob_match("a*b", "ac"));
    }

    #[test]
    fn remote_paths() {
        assert_eq!(remote_path(&Loc::parse("sftp://h").unwrap()), ".");
        assert_eq!(remote_path(&Loc::parse("sftp://h/~/a/b").unwrap()), "a/b");
        assert_eq!(remote_path(&Loc::parse("sftp://h/etc").unwrap()), "/etc");
    }

    #[tokio::test]
    async fn unreachable_host_fails_fast() {
        // TEST-NET-1 address: never routable, so the connect must time out.
        let dir = tempfile::tempdir().unwrap();
        let pool = SftpPool::new(dir.path());
        let creds = Creds::new(dir.path());
        let loc = Loc::parse("sftp://nobody@192.0.2.1/x").unwrap();
        let t0 = std::time::Instant::now();
        let r = pool
            .run(&loc, &creds, |c| async move {
                stat(c, "/x".into(), "x".into()).await
            })
            .await;
        assert!(
            t0.elapsed() < Duration::from_secs(12),
            "took {:?}",
            t0.elapsed()
        );
        assert_eq!(r.unwrap_err().kind, ErrorKind::Offline);
    }
}
