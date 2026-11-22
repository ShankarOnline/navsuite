//! Local file system backend (also used for SMB on Windows via UNC paths and
//! for SMB shares mounted by the OS on macOS/Linux). All std::fs calls run on
//! the blocking pool.

use crate::error::{Result, VfsError};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub(crate) struct RawEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: Option<u64>,
    pub modified: Option<i64>,
    pub hidden: bool,
    pub is_link: bool,
}

/// Turn a normalised native path into something the OS accepts, adding the
/// Windows verbatim prefix for long paths.
pub(crate) fn native(p: &str) -> PathBuf {
    #[cfg(windows)]
    {
        if p.len() > 240 && !p.starts_with(r"\\?\") {
            if let Some(rest) = p.strip_prefix(r"\\") {
                return PathBuf::from(format!(r"\\?\UNC\{rest}"));
            }
            return PathBuf::from(format!(r"\\?\{p}"));
        }
    }
    PathBuf::from(p)
}

pub(crate) fn unix_ms(t: std::io::Result<SystemTime>) -> Option<i64> {
    let t = t.ok()?;
    Some(match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_millis() as i64,
        Err(e) => -(e.duration().as_millis() as i64),
    })
}

#[cfg(windows)]
fn is_hidden(_name: &str, md: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    md.file_attributes() & 0x2 != 0 // FILE_ATTRIBUTE_HIDDEN
}

#[cfg(not(windows))]
fn is_hidden(name: &str, _md: &fs::Metadata) -> bool {
    name.starts_with('.')
}

fn raw_from(name: String, path: &Path, lmd: &fs::Metadata) -> RawEntry {
    let is_link = lmd.file_type().is_symlink();
    // Follow links for type/size; a dangling link is reported as a file.
    let md = if is_link {
        fs::metadata(path).ok()
    } else {
        None
    };
    let md_ref = md.as_ref().unwrap_or(lmd);
    let is_dir = md_ref.is_dir();
    RawEntry {
        hidden: is_hidden(&name, lmd),
        size: if is_dir { None } else { Some(md_ref.len()) },
        modified: unix_ms(md_ref.modified()),
        is_dir,
        is_link,
        name,
    }
}

pub(crate) fn list_blocking(dir: &Path) -> Result<Vec<RawEntry>> {
    let rd = fs::read_dir(dir).map_err(|e| VfsError::from(e).context(dir.display()))?;
    let mut out = Vec::new();
    for ent in rd {
        let Ok(ent) = ent else { continue };
        let name = ent.file_name().to_string_lossy().into_owned();
        let Ok(lmd) = ent.metadata() else { continue };
        out.push(raw_from(name, &ent.path(), &lmd));
    }
    Ok(out)
}

pub(crate) fn stat_blocking(p: &Path, name: String) -> Result<RawEntry> {
    let lmd = fs::symlink_metadata(p).map_err(|e| VfsError::from(e).context(p.display()))?;
    Ok(raw_from(name, p, &lmd))
}

pub(crate) async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(f).await?
}

pub(crate) async fn list(p: PathBuf) -> Result<Vec<RawEntry>> {
    blocking(move || list_blocking(&p)).await
}

pub(crate) async fn stat(p: PathBuf, name: String) -> Result<RawEntry> {
    blocking(move || stat_blocking(&p, name)).await
}

pub(crate) async fn mkdir(p: PathBuf) -> Result<()> {
    blocking(move || {
        if p.is_dir() {
            return Ok(());
        }
        fs::create_dir_all(&p).map_err(|e| VfsError::from(e).context(p.display()))
    })
    .await
}

pub(crate) async fn rename(from: PathBuf, to: PathBuf, overwrite: bool) -> Result<()> {
    blocking(move || {
        if !overwrite && fs::symlink_metadata(&to).is_ok() {
            // Allow case-only renames of the same entry on case-insensitive file systems.
            let same = from
                .to_string_lossy()
                .eq_ignore_ascii_case(&to.to_string_lossy());
            if !same {
                return Err(VfsError::conflict(format!(
                    "{} already exists",
                    to.display()
                )));
            }
        }
        fs::rename(&from, &to).map_err(|e| VfsError::from(e).context(from.display()))
    })
    .await
}

/// Remove a file or folder. `use_trash` moves it to the OS trash.
/// Returns whether it was trashed.
pub(crate) async fn remove(p: PathBuf, recursive: bool, use_trash: bool) -> Result<bool> {
    blocking(move || {
        let md = fs::symlink_metadata(&p).map_err(|e| VfsError::from(e).context(p.display()))?;
        let is_dir = md.is_dir();
        if is_dir
            && !recursive
            && fs::read_dir(&p)
                .map(|mut r| r.next().is_some())
                .unwrap_or(false)
        {
            return Err(VfsError::conflict(format!("{} is not empty", p.display())));
        }
        if use_trash {
            trash::delete(&p).map_err(|e| {
                VfsError::other(format!("could not move {} to trash: {e}", p.display()))
            })?;
            return Ok(true);
        }
        let r = if is_dir {
            if recursive {
                fs::remove_dir_all(&p)
            } else {
                fs::remove_dir(&p)
            }
        } else {
            fs::remove_file(&p)
        };
        r.map_err(|e| VfsError::from(e).context(p.display()))?;
        Ok(false)
    })
    .await
}

fn existing_ancestor(p: &Path) -> Option<PathBuf> {
    let mut cur = Some(p);
    while let Some(c) = cur {
        if c.exists() {
            return Some(c.to_path_buf());
        }
        cur = c.parent();
    }
    None
}

pub(crate) fn free_space_blocking(p: &Path) -> Option<u64> {
    let p = existing_ancestor(p)?;
    #[cfg(windows)]
    {
        crate::win::disk_free(&p)
    }
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let c = CString::new(p.as_os_str().as_bytes()).ok()?;
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: c is a valid NUL-terminated path, st is a valid out pointer.
        if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
            return None;
        }
        #[allow(clippy::unnecessary_cast)]
        Some(st.f_bavail as u64 * st.f_frsize as u64)
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = p;
        None
    }
}

/// Are both paths on the same volume (so `rename` is a cheap move)?
pub(crate) fn same_volume_blocking(a: &Path, b: &Path) -> bool {
    let (Some(a), Some(b)) = (existing_ancestor(a), existing_ancestor(b)) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match (fs::metadata(&a), fs::metadata(&b)) {
            (Ok(x), Ok(y)) => x.dev() == y.dev(),
            _ => false,
        }
    }
    #[cfg(windows)]
    {
        crate::win::volume_root(&a)
            .zip(crate::win::volume_root(&b))
            .is_some_and(|(x, y)| x.eq_ignore_ascii_case(&y))
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = (a, b);
        false
    }
}

/// An open local file. Positioned I/O only, so it can be shared.
#[derive(Debug, Clone)]
pub struct LocalFile {
    file: Arc<fs::File>,
}

#[cfg(unix)]
fn pread(f: &fs::File, buf: &mut [u8], off: u64) -> std::io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(f, buf, off)
}
#[cfg(windows)]
fn pread(f: &fs::File, buf: &mut [u8], off: u64) -> std::io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(f, buf, off)
}
#[cfg(unix)]
fn pwrite(f: &fs::File, buf: &[u8], off: u64) -> std::io::Result<usize> {
    std::os::unix::fs::FileExt::write_at(f, buf, off)
}
#[cfg(windows)]
fn pwrite(f: &fs::File, buf: &[u8], off: u64) -> std::io::Result<usize> {
    std::os::windows::fs::FileExt::seek_write(f, buf, off)
}

impl LocalFile {
    pub(crate) async fn open_read(p: PathBuf) -> Result<LocalFile> {
        blocking(move || {
            let f = fs::File::open(&p).map_err(|e| VfsError::from(e).context(p.display()))?;
            if f.metadata().map(|m| m.is_dir()).unwrap_or(false) {
                return Err(VfsError::other(format!("{} is a folder", p.display())));
            }
            Ok(LocalFile { file: Arc::new(f) })
        })
        .await
    }

    pub(crate) async fn open_write(p: PathBuf, mode: crate::WriteMode) -> Result<LocalFile> {
        blocking(move || {
            let mut o = fs::OpenOptions::new();
            o.write(true).read(true);
            match mode {
                crate::WriteMode::Create => o.create_new(true),
                crate::WriteMode::Truncate => o.create(true).truncate(true),
                crate::WriteMode::ResumeAt(_) => o.create(true).truncate(false),
            };
            let f = o
                .open(&p)
                .map_err(|e| VfsError::from(e).context(p.display()))?;
            if let crate::WriteMode::ResumeAt(off) = mode {
                let len = f.metadata()?.len();
                if len < off {
                    return Err(VfsError::conflict(format!(
                        "{} is shorter ({len} bytes) than the resume offset {off}",
                        p.display()
                    )));
                }
                if len > off {
                    f.set_len(off)?;
                }
            }
            Ok(LocalFile { file: Arc::new(f) })
        })
        .await
    }

    pub(crate) async fn read_at(&self, off: u64, len: usize) -> Result<Vec<u8>> {
        let f = self.file.clone();
        blocking(move || {
            let mut buf = vec![0u8; len];
            let mut got = 0;
            while got < len {
                match pread(&f, &mut buf[got..], off + got as u64) {
                    Ok(0) => break,
                    Ok(n) => got += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e.into()),
                }
            }
            buf.truncate(got);
            Ok(buf)
        })
        .await
    }

    pub(crate) async fn write_at(&self, off: u64, data: Vec<u8>) -> Result<()> {
        let f = self.file.clone();
        blocking(move || {
            let mut done = 0;
            while done < data.len() {
                match pwrite(&f, &data[done..], off + done as u64) {
                    Ok(0) => return Err(VfsError::other("write returned 0 bytes")),
                    Ok(n) => done += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e.into()),
                }
            }
            Ok(())
        })
        .await
    }

    pub(crate) async fn len(&self) -> Result<u64> {
        let f = self.file.clone();
        blocking(move || Ok(f.metadata()?.len())).await
    }

    pub(crate) async fn set_len(&self, n: u64) -> Result<()> {
        let f = self.file.clone();
        blocking(move || Ok(f.set_len(n)?)).await
    }

    pub(crate) async fn close(&self, flush: bool) -> Result<()> {
        if flush {
            let f = self.file.clone();
            blocking(move || Ok(f.sync_data()?)).await?;
        }
        Ok(())
    }
}

/// Roots shown in the sidebar on macOS / Linux.
#[cfg(unix)]
pub(crate) fn unix_roots() -> Vec<(String, PathBuf, bool)> {
    // (label, path, is_drive)
    let mut out: Vec<(String, PathBuf, bool)> = vec![("/".into(), PathBuf::from("/"), true)];
    if let Some(h) = dirs::home_dir() {
        out.push(("Home".into(), h, false));
    }
    #[cfg(target_os = "macos")]
    let dirs_to_scan: Vec<PathBuf> = vec![PathBuf::from("/Volumes")];
    #[cfg(not(target_os = "macos"))]
    let dirs_to_scan: Vec<PathBuf> = {
        let user = std::env::var("USER").unwrap_or_default();
        let mut v = vec![PathBuf::from("/mnt"), PathBuf::from("/media")];
        if !user.is_empty() {
            v.push(PathBuf::from(format!("/media/{user}")));
            v.push(PathBuf::from(format!("/run/media/{user}")));
        }
        v
    };
    for d in dirs_to_scan {
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(lmd) = fs::symlink_metadata(&p) else {
                continue;
            };
            // macOS: "/Volumes/Macintosh HD" is a symlink to "/"
            if lmd.file_type().is_symlink() {
                continue;
            }
            if !lmd.is_dir() || out.iter().any(|(_, x, _)| x == &p) {
                continue;
            }
            // /media/<user> itself is just a container
            #[cfg(not(target_os = "macos"))]
            if d == Path::new("/media")
                && e.file_name() == std::ffi::OsStr::new(&std::env::var("USER").unwrap_or_default())
            {
                continue;
            }
            out.push((e.file_name().to_string_lossy().into_owned(), p, true));
        }
    }
    out
}
