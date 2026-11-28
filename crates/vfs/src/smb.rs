//! SMB routing.
//!
//! - Windows: SMB locations become UNC paths handled by the local backend, so
//!   the OS SMB client (and its sessions, Kerberos, signing…) does the work.
//!   Stored credentials are applied with WNetAddConnection2W; share listing
//!   uses NetShareEnum.
//! - macOS / Linux: shares mounted by the OS (Finder, gvfs, mount.cifs) are
//!   used through their mount point. Unmounted shares return `Unsupported`:
//!   the pure-Rust `smb` crate pins pre-release crypto crates that cannot be
//!   resolved together with russh in one Cargo.lock.

use crate::Loc;
use std::path::PathBuf;

/// Local path at which the OS has this share mounted, if any.
pub(crate) fn mounted_path(loc: &Loc) -> Option<PathBuf> {
    let host = loc.host.as_deref()?;
    let share = loc.share()?;
    let base = mount_point(host, share)?;
    let mut p = base;
    for c in loc.smb_rest() {
        p.push(c);
    }
    Some(p)
}

#[cfg(windows)]
fn mount_point(host: &str, share: &str) -> Option<PathBuf> {
    let want = format!(r"\\{host}\{share}");
    for d in crate::win::drives() {
        if let Some(r) = d.remote
            && r.trim_end_matches('\\').eq_ignore_ascii_case(&want)
        {
            return Some(PathBuf::from(d.root));
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn mount_point(host: &str, share: &str) -> Option<PathBuf> {
    use std::ffi::{CStr, CString};
    use std::os::unix::ffi::OsStrExt;
    let rd = std::fs::read_dir("/Volumes").ok()?;
    for e in rd.flatten() {
        let p = e.path();
        let Ok(c) = CString::new(p.as_os_str().as_bytes()) else {
            continue;
        };
        let mut st: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: valid path and out pointer.
        if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
            continue;
        }
        // SAFETY: statfs fills NUL-terminated fixed arrays.
        let fstype = unsafe { CStr::from_ptr(st.f_fstypename.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        let from = unsafe { CStr::from_ptr(st.f_mntfromname.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        if fstype != "smbfs" {
            continue;
        }
        if smb_source_matches(&from, host, share) {
            return Some(p);
        }
    }
    None
}

#[cfg(all(unix, not(target_os = "macos")))]
fn mount_point(host: &str, share: &str) -> Option<PathBuf> {
    if let Ok(m) = std::fs::read_to_string("/proc/mounts") {
        for line in m.lines() {
            let mut it = line.split_whitespace();
            let (Some(src), Some(dst), Some(fstype)) = (it.next(), it.next(), it.next()) else {
                continue;
            };
            if !matches!(fstype, "cifs" | "smb3" | "smbfs") {
                continue;
            }
            if smb_source_matches(&unescape_mount(src), host, share) {
                return Some(PathBuf::from(unescape_mount(dst)));
            }
        }
    }
    // GNOME gvfs
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    let gvfs = PathBuf::from(format!("/run/user/{uid}/gvfs"));
    if let Ok(rd) = std::fs::read_dir(&gvfs) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().to_lowercase();
            if n.starts_with("smb-share:")
                && n.contains(&format!("server={}", host.to_lowercase()))
                && n.contains(&format!("share={}", share.to_lowercase()))
            {
                return Some(e.path());
            }
        }
    }
    None
}

#[cfg(not(any(windows, unix)))]
fn mount_point(_host: &str, _share: &str) -> Option<PathBuf> {
    None
}

#[cfg(all(unix, not(target_os = "macos")))]
fn unescape_mount(s: &str) -> String {
    s.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\134", "\\")
}

/// `//[user@]host/share` (or with backslashes) matches host & share?
#[cfg(unix)]
fn smb_source_matches(src: &str, host: &str, share: &str) -> bool {
    let s = src.replace('\\', "/");
    let s = s.trim_start_matches('/');
    let s = s.rsplit_once('@').map(|(_, r)| r).unwrap_or(s);
    let mut parts = s.split('/');
    let h = parts.next().unwrap_or("");
    let sh = parts.next().unwrap_or("");
    let sh = percent_encoding::percent_decode_str(sh).decode_utf8_lossy();
    h.eq_ignore_ascii_case(host) && sh.eq_ignore_ascii_case(share)
}

/// Shares from `host` that the OS has mounted (non-Windows share listing).
#[cfg(unix)]
pub(crate) fn mounted_shares(host: &str) -> Vec<String> {
    let mut out = Vec::new();
    #[cfg(target_os = "macos")]
    {
        if let Ok(rd) = std::fs::read_dir("/Volumes") {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if mount_point(host, &name).is_some() {
                    out.push(name);
                }
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        if let Ok(m) = std::fs::read_to_string("/proc/mounts") {
            for line in m.lines() {
                let mut it = line.split_whitespace();
                let (Some(src), Some(_), Some(fstype)) = (it.next(), it.next(), it.next()) else {
                    continue;
                };
                if !matches!(fstype, "cifs" | "smb3" | "smbfs") {
                    continue;
                }
                let src = unescape_mount(src).replace('\\', "/");
                let s = src.trim_start_matches('/');
                let mut p = s.split('/');
                if p.next().is_some_and(|h| h.eq_ignore_ascii_case(host))
                    && let Some(sh) = p.next()
                {
                    out.push(sh.to_string());
                }
            }
        }
        // SAFETY: getuid has no preconditions.
        let uid = unsafe { libc::getuid() };
        if let Ok(rd) = std::fs::read_dir(format!("/run/user/{uid}/gvfs")) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().into_owned();
                if let Some(rest) = n.strip_prefix("smb-share:") {
                    let kv: std::collections::HashMap<&str, &str> =
                        rest.split(',').filter_map(|p| p.split_once('=')).collect();
                    if kv
                        .get("server")
                        .is_some_and(|s| s.eq_ignore_ascii_case(host))
                        && let Some(sh) = kv.get("share")
                    {
                        out.push(sh.to_string());
                    }
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(unix)]
pub(crate) fn not_mounted(loc: &Loc) -> crate::VfsError {
    crate::VfsError::unsupported(format!(
        "{} is not mounted. On this OS narada reads SMB shares through the system mount: \
         connect it in Finder (Cmd+K) / your file manager, or mount it with mount.cifs, then retry.",
        loc.to_uri()
    ))
}

/// Windows: reachability probe + session setup with stored credentials.
#[cfg(windows)]
pub(crate) mod session {
    use crate::creds::Creds;
    use crate::error::{ErrorKind, Result, VfsError};
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    #[derive(Default)]
    pub(crate) struct SmbSessions {
        reach: Mutex<HashMap<String, (Instant, bool)>>,
        connected: Mutex<HashSet<String>>,
    }

    impl SmbSessions {
        /// Fail fast (≤4 s) if nothing answers on 445/139.
        pub async fn ensure_reachable(&self, host: &str) -> Result<()> {
            let key = host.to_ascii_lowercase();
            if let Some((t, ok)) = self.reach.lock().unwrap().get(&key).copied() {
                let ttl = if ok {
                    Duration::from_secs(60)
                } else {
                    Duration::from_secs(5)
                };
                if t.elapsed() < ttl {
                    return if ok {
                        Ok(())
                    } else {
                        Err(VfsError::offline(format!("{host} is not reachable (SMB)")))
                    };
                }
            }
            let h = host.to_string();
            let probe = async move {
                for port in [445u16, 139] {
                    if let Ok(Ok(_)) = tokio::time::timeout(
                        Duration::from_secs(2),
                        tokio::net::TcpStream::connect((h.as_str(), port)),
                    )
                    .await
                    {
                        return true;
                    }
                }
                false
            };
            let ok = tokio::time::timeout(Duration::from_secs(4), probe)
                .await
                .unwrap_or(false);
            self.reach.lock().unwrap().insert(key, (Instant::now(), ok));
            if ok {
                Ok(())
            } else {
                Err(VfsError::offline(format!("{host} is not reachable (SMB)")))
            }
        }

        pub fn forget(&self, host: &str) {
            let pre = format!(r"\\{}\", host.to_ascii_lowercase());
            self.connected
                .lock()
                .unwrap()
                .retain(|r| !r.starts_with(&pre));
        }

        /// If credentials are stored for `host`, open a session to `remote` once.
        /// Returns true if stored credentials exist.
        pub async fn ensure_session(
            &self,
            creds: &Creds,
            host: &str,
            share: Option<&str>,
        ) -> Result<bool> {
            let Some(user) = creds.user_for(host) else {
                return Ok(false);
            };
            let remote = format!(r"\\{}\{}", host, share.unwrap_or("IPC$"));
            if self
                .connected
                .lock()
                .unwrap()
                .contains(&remote.to_ascii_lowercase())
            {
                return Ok(true);
            }
            let Some(pw) = creds.password(host, &user).await else {
                return Ok(false);
            };
            let (r, u) = (remote.clone(), user.clone());
            let res = tokio::time::timeout(
                Duration::from_secs(15),
                tokio::task::spawn_blocking(move || crate::win::wnet_connect(&r, &u, &pw)),
            )
            .await
            .map_err(|_| VfsError::offline(format!("{remote}: timed out")))??;
            res?;
            self.connected
                .lock()
                .unwrap()
                .insert(remote.to_ascii_lowercase());
            Ok(true)
        }
    }

    /// Translate access errors on an SMB path into AuthRequired where it makes sense.
    pub(crate) fn map_err(
        e: VfsError,
        host: &str,
        user: Option<String>,
        had_creds: bool,
    ) -> VfsError {
        // io::Error's Display ends with "(os error N)"; recover N.
        let code = e
            .message
            .rsplit_once("(os error ")
            .and_then(|(_, r)| r.trim_end_matches(')').parse::<u32>().ok())
            .unwrap_or(0);
        if crate::win::is_auth_error(code) || (crate::win::is_access_denied(code) && !had_creds) {
            return VfsError::new(
                ErrorKind::AuthRequired {
                    host: host.to_string(),
                    user,
                },
                e.message,
            );
        }
        e
    }
}
