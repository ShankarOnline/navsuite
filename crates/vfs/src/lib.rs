//! vfs: one file layer for local disks, SMB shares and SFTP.
//!
//! Everything is addressed with [`Loc`]; [`Vfs`] dispatches to the backend.
//! - Local: std::fs on the blocking pool (long paths, hidden attributes).
//! - SMB: Windows uses the OS client through UNC paths (plus NetShareEnum /
//!   WNetAddConnection2W); macOS/Linux use shares the OS has mounted.
//! - SFTP: russh + russh-sftp with pooled sessions.

mod creds;
mod error;
mod loc;
mod local;
mod sftp;
mod smb;
#[cfg(windows)]
mod win;

pub use error::{ErrorKind, Result, VfsError};
pub use loc::{Loc, PathForm, Scheme};
pub use local::LocalFile;
pub use sftp::SftpFile;

use base64::Engine;
use local::RawEntry;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EntryKind {
    Dir,
    File,
    Drive,
    Share,
    Link,
}

/// One row of a listing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub name: String,
    /// `Loc::to_uri()` of this entry.
    pub loc: String,
    pub is_dir: bool,
    pub size: Option<u64>,
    /// Unix time in milliseconds.
    pub modified: Option<i64>,
    pub hidden: bool,
    pub is_link: bool,
    pub kind: EntryKind,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Preview {
    pub mime: String,
    pub bytes_base64: String,
    pub truncated: bool,
    pub size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveOutcome {
    /// True if the item went to the system trash (local files), false if it was deleted.
    pub trashed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WriteMode {
    /// Create a new file; `Conflict` if it exists.
    Create,
    /// Create or truncate.
    Truncate,
    /// Open existing (or create) without truncating, then cut it to this length.
    /// Fails with `Conflict` if the file is shorter than the offset.
    ResumeAt(u64),
}

/// An open file on any backend.
#[derive(Debug)]
pub enum FileHandle {
    Local(LocalFile),
    Sftp(Box<SftpFile>),
}

impl FileHandle {
    /// Read up to `len` bytes at `off` (shorter only at end of file).
    pub async fn read_at(&self, off: u64, len: usize) -> Result<Vec<u8>> {
        match self {
            FileHandle::Local(f) => f.read_at(off, len).await,
            FileHandle::Sftp(f) => f.read_at(off, len).await,
        }
    }
    pub async fn write_at(&self, off: u64, data: &[u8]) -> Result<()> {
        match self {
            FileHandle::Local(f) => f.write_at(off, data.to_vec()).await,
            FileHandle::Sftp(f) => f.write_at(off, data).await,
        }
    }
    pub async fn len(&self) -> Result<u64> {
        match self {
            FileHandle::Local(f) => f.len().await,
            FileHandle::Sftp(f) => f.len().await,
        }
    }
    pub async fn is_empty(&self) -> Result<bool> {
        Ok(self.len().await? == 0)
    }
    pub async fn set_len(&self, n: u64) -> Result<()> {
        match self {
            FileHandle::Local(f) => f.set_len(n).await,
            FileHandle::Sftp(f) => f.set_len(n).await,
        }
    }
    /// Flush (local: fsync data) and close.
    pub async fn close(&self) -> Result<()> {
        match self {
            FileHandle::Local(f) => f.close(true).await,
            FileHandle::Sftp(f) => f.close().await,
        }
    }
}

enum Route {
    Local(PathBuf),
    /// `smb://host` without a share: list shares.
    SmbShares(String),
    Sftp,
}

/// SMB context needed to turn access errors into AuthRequired (Windows).
struct SmbCtx {
    #[cfg_attr(not(windows), allow(dead_code))]
    host: String,
    #[cfg_attr(not(windows), allow(dead_code))]
    user: Option<String>,
    #[cfg_attr(not(windows), allow(dead_code))]
    had_creds: bool,
}

/// The file layer. Cheap to share behind `Arc`.
pub struct Vfs {
    creds: creds::Creds,
    sftp: sftp::SftpPool,
    #[cfg(windows)]
    smb: smb::session::SmbSessions,
}

fn entry_for(loc: &Loc, raw: RawEntry) -> Entry {
    let child = loc.join(&raw.name);
    entry_at(&child, raw)
}

fn entry_at(loc: &Loc, raw: RawEntry) -> Entry {
    let kind = if raw.is_link {
        EntryKind::Link
    } else if raw.is_dir {
        if loc.is_root() && loc.scheme == Scheme::Local {
            EntryKind::Drive
        } else if loc.scheme == Scheme::Smb && loc.share().is_some() && loc.smb_rest().is_empty() {
            EntryKind::Share
        } else {
            EntryKind::Dir
        }
    } else {
        EntryKind::File
    };
    Entry {
        name: raw.name,
        loc: loc.to_uri(),
        is_dir: raw.is_dir,
        size: raw.size,
        modified: raw.modified,
        hidden: raw.hidden,
        is_link: raw.is_link,
        kind,
    }
}

fn sniff_mime(name: &str, bytes: &[u8]) -> String {
    if let Some(m) = mime_guess::from_path(name).first() {
        return m.essence_str().to_string();
    }
    let text = match std::str::from_utf8(bytes) {
        Ok(_) => true,
        // a multi-byte char cut off at the end of the sample is fine
        Err(e) => e.error_len().is_none() && bytes.len() - e.valid_up_to() < 4,
    };
    if text && !bytes.contains(&0) {
        "text/plain".into()
    } else {
        "application/octet-stream".into()
    }
}

impl Vfs {
    /// `data_dir` holds the app's known_hosts and the host->user map.
    pub fn new(data_dir: PathBuf) -> Vfs {
        let _ = std::fs::create_dir_all(&data_dir);
        Vfs {
            creds: creds::Creds::new(&data_dir),
            sftp: sftp::SftpPool::new(&data_dir),
            #[cfg(windows)]
            smb: Default::default(),
        }
    }

    async fn route(&self, loc: &Loc) -> Result<(Route, Option<SmbCtx>)> {
        match loc.scheme {
            Scheme::Local => Ok((Route::Local(local::native(&loc.path)), None)),
            Scheme::Sftp => Ok((Route::Sftp, None)),
            Scheme::Smb => {
                let host = loc
                    .host
                    .clone()
                    .ok_or_else(|| VfsError::other("smb location without host"))?;
                #[cfg(windows)]
                {
                    if loc.port.is_some() {
                        return Err(VfsError::unsupported(
                            "Windows SMB client does not support custom ports",
                        ));
                    }
                    self.smb.ensure_reachable(&host).await?;
                    let had_creds = self
                        .smb
                        .ensure_session(&self.creds, &host, loc.share())
                        .await?;
                    let ctx = SmbCtx {
                        user: loc.user.clone().or_else(|| self.creds.user_for(&host)),
                        host: host.clone(),
                        had_creds,
                    };
                    match loc.share() {
                        None => Ok((Route::SmbShares(host), Some(ctx))),
                        Some(_) => {
                            let unc = loc.unc().unwrap_or_default();
                            let unc = if loc.smb_rest().is_empty() {
                                format!("{unc}\\")
                            } else {
                                unc
                            };
                            Ok((Route::Local(local::native(&unc)), Some(ctx)))
                        }
                    }
                }
                #[cfg(not(windows))]
                {
                    let ctx = SmbCtx {
                        host: host.clone(),
                        user: loc.user.clone(),
                        had_creds: false,
                    };
                    match loc.share() {
                        None => Ok((Route::SmbShares(host), Some(ctx))),
                        Some(_) => match smb::mounted_path(loc) {
                            Some(p) => Ok((Route::Local(p), Some(ctx))),
                            #[cfg(unix)]
                            None => Err(smb::not_mounted(loc)),
                            #[cfg(not(unix))]
                            None => Err(VfsError::unsupported("SMB is not supported on this OS")),
                        },
                    }
                }
            }
        }
    }

    fn fix<T>(ctx: &Option<SmbCtx>, r: Result<T>) -> Result<T> {
        #[cfg(windows)]
        if let (Some(c), Err(e)) = (ctx, &r) {
            return Err(smb::session::map_err(
                e.clone(),
                &c.host,
                c.user.clone(),
                c.had_creds,
            ));
        }
        #[cfg(not(windows))]
        let _ = ctx;
        r
    }

    /// Sidebar roots: drives (Windows), `/`, home, mounted volumes.
    pub async fn roots(&self) -> Vec<Entry> {
        tokio::task::spawn_blocking(|| {
            let mut out = Vec::new();
            #[cfg(windows)]
            for d in win::drives() {
                let letter = d.root.trim_end_matches('\\').to_string();
                out.push(Entry {
                    name: format!("{} ({letter})", d.label),
                    loc: d.root.clone(),
                    is_dir: true,
                    size: None,
                    modified: None,
                    hidden: false,
                    is_link: false,
                    kind: EntryKind::Drive,
                });
                let _ = d.kind;
            }
            #[cfg(windows)]
            if let Some(h) = dirs::home_dir() {
                out.push(Entry {
                    name: "Home".into(),
                    loc: h.to_string_lossy().into_owned(),
                    is_dir: true,
                    size: None,
                    modified: None,
                    hidden: false,
                    is_link: false,
                    kind: EntryKind::Dir,
                });
            }
            #[cfg(unix)]
            for (label, p, is_drive) in local::unix_roots() {
                out.push(Entry {
                    name: label,
                    loc: p.to_string_lossy().into_owned(),
                    is_dir: true,
                    size: None,
                    modified: None,
                    hidden: false,
                    is_link: false,
                    kind: if is_drive {
                        EntryKind::Drive
                    } else {
                        EntryKind::Dir
                    },
                });
            }
            out
        })
        .await
        .unwrap_or_default()
    }

    pub async fn list(&self, loc: &Loc) -> Result<Vec<Entry>> {
        let (route, ctx) = self.route(loc).await?;
        let raws = match route {
            Route::Local(p) => Self::fix(&ctx, local::list(p).await)?,
            Route::SmbShares(host) => return Self::fix(&ctx, self.list_shares(loc, host).await),
            Route::Sftp => {
                let path = sftp::remote_path(loc);
                self.sftp
                    .run(loc, &self.creds, |c| sftp::list(c, path.clone()))
                    .await?
            }
        };
        let mut v: Vec<Entry> = raws.into_iter().map(|r| entry_for(loc, r)).collect();
        v.sort_by(|a, b| {
            b.is_dir
                .cmp(&a.is_dir)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        Ok(v)
    }

    async fn list_shares(&self, loc: &Loc, host: String) -> Result<Vec<Entry>> {
        #[cfg(windows)]
        let names: Vec<String> = {
            let h = host.clone();
            tokio::time::timeout(
                std::time::Duration::from_secs(15),
                tokio::task::spawn_blocking(move || win::shares(&h)),
            )
            .await
            .map_err(|_| VfsError::offline(format!("{host}: listing shares timed out")))???
            .into_iter()
            .map(|(n, _)| n)
            .collect()
        };
        #[cfg(unix)]
        let names: Vec<String> = {
            let h = host.clone();
            let n = tokio::task::spawn_blocking(move || smb::mounted_shares(&h)).await?;
            if n.is_empty() {
                return Err(VfsError::unsupported(format!(
                    "No shares from {host} are mounted. On this OS navsuite uses SMB shares mounted by the system \
                     (Finder Cmd+K, file manager, or mount.cifs)."
                )));
            }
            n
        };
        #[cfg(not(any(windows, unix)))]
        let names: Vec<String> = {
            let _ = host;
            return Err(VfsError::unsupported("SMB is not supported on this OS"));
        };
        Ok(names
            .into_iter()
            .map(|n| {
                let l = loc.join(&n);
                Entry {
                    name: n,
                    loc: l.to_uri(),
                    is_dir: true,
                    size: None,
                    modified: None,
                    hidden: false,
                    is_link: false,
                    kind: EntryKind::Share,
                }
            })
            .collect())
    }

    pub async fn stat(&self, loc: &Loc) -> Result<Entry> {
        let (route, ctx) = self.route(loc).await?;
        let raw = match route {
            Route::Local(p) => Self::fix(&ctx, local::stat(p, loc.name()).await)?,
            Route::SmbShares(_) => RawEntry {
                name: loc.name(),
                is_dir: true,
                size: None,
                modified: None,
                hidden: false,
                is_link: false,
            },
            Route::Sftp => {
                let path = sftp::remote_path(loc);
                let name = loc.name();
                self.sftp
                    .run(loc, &self.creds, |c| {
                        sftp::stat(c, path.clone(), name.clone())
                    })
                    .await?
            }
        };
        Ok(entry_at(loc, raw))
    }

    /// Does the location exist? (`Ok(false)` only for NotFound.)
    pub async fn exists(&self, loc: &Loc) -> Result<bool> {
        match self.stat(loc).await {
            Ok(_) => Ok(true),
            Err(e) if e.kind == ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Resolve `~` (SFTP home) to an absolute path; other locations unchanged.
    pub async fn canonicalize(&self, loc: &Loc) -> Result<Loc> {
        if loc.scheme != Scheme::Sftp || !loc.path.starts_with('~') {
            return Ok(loc.clone());
        }
        let path = sftp::remote_path(loc);
        let abs = self
            .sftp
            .run(loc, &self.creds, |c| sftp::canonicalize(c, path.clone()))
            .await?;
        Ok(Loc {
            path: abs,
            ..loc.clone()
        })
    }

    /// Everything below `loc` (not including it), parents before children.
    /// Symlinked folders are listed but not descended into.
    pub async fn walk(&self, loc: &Loc) -> Result<Vec<Entry>> {
        let mut out = Vec::new();
        let mut stack = vec![loc.clone()];
        while let Some(dir) = stack.pop() {
            let entries = self.list(&dir).await?;
            let mut subdirs = Vec::new();
            for e in entries {
                if e.is_dir && !e.is_link {
                    subdirs.push(dir.join(&e.name));
                }
                out.push(e);
            }
            stack.extend(subdirs.into_iter().rev());
        }
        Ok(out)
    }

    pub async fn read_at(&self, loc: &Loc, offset: u64, len: usize) -> Result<Vec<u8>> {
        let h = self.open_read(loc).await?;
        let r = h.read_at(offset, len).await;
        let _ = h.close().await;
        r
    }

    /// First `max_bytes` of a file, base64-encoded, with a MIME guess.
    pub async fn preview(&self, loc: &Loc, max_bytes: usize) -> Result<Preview> {
        let h = self.open_read(loc).await?;
        let size = h.len().await?;
        let bytes = h.read_at(0, max_bytes.min(size as usize)).await;
        let _ = h.close().await;
        let bytes = bytes?;
        Ok(Preview {
            mime: sniff_mime(&loc.name(), &bytes),
            truncated: (bytes.len() as u64) < size,
            bytes_base64: base64::engine::general_purpose::STANDARD.encode(&bytes),
            size,
        })
    }

    /// Create a folder (and missing parents). Succeeds if it already exists.
    pub async fn mkdir(&self, loc: &Loc) -> Result<()> {
        let (route, ctx) = self.route(loc).await?;
        match route {
            Route::Local(p) => Self::fix(&ctx, local::mkdir(p).await),
            Route::SmbShares(_) => Err(VfsError::unsupported("cannot create a share")),
            Route::Sftp => {
                let path = sftp::remote_path(loc);
                self.sftp
                    .run(loc, &self.creds, |c| sftp::mkdir_p(c, path.clone()))
                    .await
            }
        }
    }

    /// Rename / move within one backend. `Conflict` if `to` exists.
    pub async fn rename(&self, from: &Loc, to: &Loc) -> Result<()> {
        self.rename_impl(from, to, false).await
    }

    /// Like `rename`, but replaces an existing file at `to`.
    pub async fn rename_over(&self, from: &Loc, to: &Loc) -> Result<()> {
        self.rename_impl(from, to, true).await
    }

    async fn rename_impl(&self, from: &Loc, to: &Loc, overwrite: bool) -> Result<()> {
        let (ra, ca) = self.route(from).await?;
        let (rb, _) = self.route(to).await?;
        match (ra, rb) {
            (Route::Local(a), Route::Local(b)) => {
                Self::fix(&ca, local::rename(a, b, overwrite).await)
            }
            (Route::Sftp, Route::Sftp)
                if loc::eq_host(&from.host, &to.host)
                    && from.port == to.port
                    && from.user == to.user =>
            {
                let (a, b) = (sftp::remote_path(from), sftp::remote_path(to));
                self.sftp
                    .run(from, &self.creds, |c| {
                        sftp::rename(c, a.clone(), b.clone(), overwrite)
                    })
                    .await
            }
            _ => Err(VfsError::unsupported(
                "rename across different locations is not possible; copy instead",
            )),
        }
    }

    /// Delete. Local items go to the system trash; remote ones are deleted permanently.
    pub async fn remove(&self, loc: &Loc, recursive: bool) -> Result<RemoveOutcome> {
        self.remove_impl(loc, recursive, loc.scheme == Scheme::Local)
            .await
    }

    /// Delete without using the trash, on any backend.
    pub async fn delete_permanently(&self, loc: &Loc, recursive: bool) -> Result<()> {
        self.remove_impl(loc, recursive, false).await.map(|_| ())
    }

    async fn remove_impl(&self, loc: &Loc, recursive: bool, trash: bool) -> Result<RemoveOutcome> {
        if loc.is_root() {
            return Err(VfsError::new(
                ErrorKind::PermissionDenied,
                "refusing to delete a root",
            ));
        }
        let (route, ctx) = self.route(loc).await?;
        match route {
            Route::Local(p) => Self::fix(&ctx, local::remove(p, recursive, trash).await)
                .map(|trashed| RemoveOutcome { trashed }),
            Route::SmbShares(_) => Err(VfsError::unsupported("cannot delete a share")),
            Route::Sftp => {
                let path = sftp::remote_path(loc);
                self.sftp
                    .run(loc, &self.creds, |c| {
                        sftp::remove(c, path.clone(), recursive)
                    })
                    .await?;
                Ok(RemoveOutcome { trashed: false })
            }
        }
    }

    /// Bytes available to the user at `loc`, if the backend can tell.
    pub async fn free_space(&self, loc: &Loc) -> Option<u64> {
        let (route, _) = self.route(loc).await.ok()?;
        match route {
            Route::Local(p) => tokio::task::spawn_blocking(move || local::free_space_blocking(&p))
                .await
                .ok()
                .flatten(),
            Route::SmbShares(_) => None,
            Route::Sftp => {
                let path = sftp::remote_path(loc);
                self.sftp
                    .run(loc, &self.creds, |c| sftp::free_space(c, path.clone()))
                    .await
                    .ok()
                    .flatten()
            }
        }
    }

    /// Can `a` be moved to `b` with a cheap rename?
    pub async fn same_volume(&self, a: &Loc, b: &Loc) -> bool {
        let (Ok((ra, _)), Ok((rb, _))) = (self.route(a).await, self.route(b).await) else {
            return false;
        };
        match (ra, rb) {
            (Route::Local(x), Route::Local(y)) => {
                tokio::task::spawn_blocking(move || local::same_volume_blocking(&x, &y))
                    .await
                    .unwrap_or(false)
            }
            (Route::Sftp, Route::Sftp) => {
                loc::eq_host(&a.host, &b.host) && a.port == b.port && a.user == b.user
            }
            _ => false,
        }
    }

    pub async fn open_read(&self, loc: &Loc) -> Result<FileHandle> {
        let (route, ctx) = self.route(loc).await?;
        match route {
            Route::Local(p) => {
                Self::fix(&ctx, LocalFile::open_read(p).await).map(FileHandle::Local)
            }
            Route::SmbShares(_) => Err(VfsError::other("not a file")),
            Route::Sftp => {
                let path = sftp::remote_path(loc);
                self.sftp
                    .run(loc, &self.creds, |c| SftpFile::open(c, path.clone(), None))
                    .await
                    .map(|f| FileHandle::Sftp(Box::new(f)))
            }
        }
    }

    pub async fn open_write(&self, loc: &Loc, mode: WriteMode) -> Result<FileHandle> {
        let (route, ctx) = self.route(loc).await?;
        match route {
            Route::Local(p) => {
                Self::fix(&ctx, LocalFile::open_write(p, mode).await).map(FileHandle::Local)
            }
            Route::SmbShares(_) => Err(VfsError::other("not a file")),
            Route::Sftp => {
                let path = sftp::remote_path(loc);
                self.sftp
                    .run(loc, &self.creds, |c| {
                        SftpFile::open(c, path.clone(), Some(mode))
                    })
                    .await
                    .map(|f| FileHandle::Sftp(Box::new(f)))
            }
        }
    }

    /// Store a password in the OS keyring (account `user@host`) and drop
    /// pooled sessions so the next access uses it.
    pub async fn set_credentials(&self, host: &str, user: &str, password: &str) -> Result<()> {
        self.creds.set(host, user, password).await?;
        self.sftp.forget_host(host);
        #[cfg(windows)]
        self.smb.forget(host);
        Ok(())
    }

    /// Remove the stored password for `host` (the given user, or the last one stored).
    pub async fn forget_credentials(&self, host: &str, user: Option<&str>) -> Result<()> {
        self.creds.forget(host, user).await?;
        self.sftp.forget_host(host);
        #[cfg(windows)]
        self.smb.forget(host);
        Ok(())
    }

    /// Accept an SSH host key (from `ErrorKind::HostKeyUnknown`) into the
    /// app-owned known_hosts file.
    pub async fn trust_host_key(&self, host: &str, port: u16, key_openssh: &str) -> Result<()> {
        self.sftp.trust(host, port, key_openssh).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vfs(dir: &std::path::Path) -> Vfs {
        Vfs::new(dir.join("data"))
    }

    #[tokio::test]
    async fn local_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let v = vfs(tmp.path());
        let root = Loc::local(tmp.path().to_string_lossy()).unwrap();
        let d = root.join("sub dir");
        v.mkdir(&d).await.unwrap();
        v.mkdir(&d).await.unwrap(); // idempotent
        let f = d.join("hello.txt");
        let h = v.open_write(&f, WriteMode::Create).await.unwrap();
        h.write_at(0, b"hello ").await.unwrap();
        h.write_at(6, b"world").await.unwrap();
        assert_eq!(h.len().await.unwrap(), 11);
        h.close().await.unwrap();
        assert_eq!(
            v.open_write(&f, WriteMode::Create).await.unwrap_err().kind,
            ErrorKind::Conflict
        );
        assert_eq!(v.read_at(&f, 6, 100).await.unwrap(), b"world");

        // resume: cut to 6 and append
        let h = v.open_write(&f, WriteMode::ResumeAt(6)).await.unwrap();
        assert_eq!(h.len().await.unwrap(), 6);
        h.write_at(6, b"there").await.unwrap();
        h.close().await.unwrap();
        assert_eq!(v.read_at(&f, 0, 100).await.unwrap(), b"hello there");
        assert_eq!(
            v.open_write(&f, WriteMode::ResumeAt(99))
                .await
                .unwrap_err()
                .kind,
            ErrorKind::Conflict
        );

        let p = v.preview(&f, 5).await.unwrap();
        assert_eq!(p.mime, "text/plain");
        assert!(p.truncated);
        assert_eq!(p.size, 11);
        assert_eq!(p.bytes_base64, "aGVsbG8=");

        let list = v.list(&d).await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "hello.txt");
        assert_eq!(list[0].size, Some(11));
        assert_eq!(list[0].kind, EntryKind::File);
        assert_eq!(Loc::parse(&list[0].loc).unwrap(), f);
        let st = v.stat(&d).await.unwrap();
        assert!(st.is_dir);
        assert_eq!(st.kind, EntryKind::Dir);

        let g = d.join("renamed.txt");
        v.rename(&f, &g).await.unwrap();
        assert!(!v.exists(&f).await.unwrap());
        assert!(v.exists(&g).await.unwrap());
        // rename onto an existing file is a conflict; rename_over replaces
        let h = v.open_write(&f, WriteMode::Truncate).await.unwrap();
        h.write_at(0, b"x").await.unwrap();
        h.close().await.unwrap();
        assert_eq!(
            v.rename(&f, &g).await.unwrap_err().kind,
            ErrorKind::Conflict
        );
        v.rename_over(&f, &g).await.unwrap();
        assert_eq!(v.read_at(&g, 0, 10).await.unwrap(), b"x");

        let walked = v.walk(&root).await.unwrap();
        assert!(walked.iter().any(|e| e.name == "renamed.txt"));

        assert_eq!(
            v.remove(&d, false).await.unwrap_err().kind,
            ErrorKind::Conflict
        );
        v.delete_permanently(&d, true).await.unwrap();
        assert!(!v.exists(&d).await.unwrap());
        assert_eq!(v.stat(&d).await.unwrap_err().kind, ErrorKind::NotFound);
        assert!(v.free_space(&root).await.unwrap() > 0);
        assert!(v.same_volume(&root, &root.join("x")).await);
    }

    #[tokio::test]
    async fn trash_local() {
        let tmp = tempfile::tempdir().unwrap();
        let v = vfs(tmp.path());
        let f = Loc::local(tmp.path().to_string_lossy())
            .unwrap()
            .join("trash-me.txt");
        v.open_write(&f, WriteMode::Create)
            .await
            .unwrap()
            .close()
            .await
            .unwrap();
        match v.remove(&f, false).await {
            Ok(o) => assert!(o.trashed),
            // headless CI without a trash implementation
            Err(e) => eprintln!("trash unavailable: {e}"),
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn long_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let v = vfs(tmp.path());
        let mut d = Loc::local(tmp.path().to_string_lossy()).unwrap();
        for _ in 0..6 {
            d = d.join(&"d".repeat(50));
        }
        assert!(d.path.len() > 260);
        v.mkdir(&d).await.unwrap();
        let f = d.join("f.bin");
        let h = v.open_write(&f, WriteMode::Create).await.unwrap();
        h.write_at(0, b"ok").await.unwrap();
        h.close().await.unwrap();
        assert_eq!(v.list(&d).await.unwrap().len(), 1);
        v.delete_permanently(
            &Loc::local(tmp.path().to_string_lossy())
                .unwrap()
                .join(&"d".repeat(50)),
            true,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn roots_not_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let r = vfs(tmp.path()).roots().await;
        assert!(!r.is_empty());
        for e in &r {
            Loc::parse(&e.loc).unwrap();
        }
    }

    #[test]
    fn mime() {
        assert_eq!(sniff_mime("a.png", b""), "image/png");
        assert_eq!(sniff_mime("README", b"hello"), "text/plain");
        assert_eq!(sniff_mime("blob", &[0, 1, 2]), "application/octet-stream");
    }

    #[test]
    fn error_serialization() {
        let e = VfsError::new(
            ErrorKind::HostKeyUnknown {
                host: "h".into(),
                port: 22,
                fingerprint: "SHA256:x".into(),
                key_openssh: "k".into(),
            },
            "m",
        );
        let j = serde_json::to_string(&e).unwrap();
        assert_eq!(
            j,
            r#"{"kind":{"type":"hostKeyUnknown","host":"h","port":22,"fingerprint":"SHA256:x","keyOpenssh":"k"},"message":"m"}"#
        );
        let back: VfsError = serde_json::from_str(&j).unwrap();
        assert_eq!(back, e);
    }
}
