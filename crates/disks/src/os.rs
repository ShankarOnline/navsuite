//! DB10: detect OS installs on a mounted directory or through a [`RawFs`].

use crate::detect::ntfs_hiberfil_is_hibernated;
use crate::{OsInstall, OsKind, Partition};
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Minimal read-only file access used by OS detection. Paths are relative to the
/// file system root and use `/` separators.
pub(crate) trait Probe {
    /// `Some(true)` = directory, `Some(false)` = file, `None` = missing.
    fn kind(&self, path: &str) -> Option<bool>;
    fn read_at(&self, path: &str, offset: u64, len: usize) -> Option<Vec<u8>>;
    /// Names of sub-directories (not symlinks/junctions).
    fn subdirs(&self, path: &str) -> Vec<String>;
}

/// Probe over a mounted directory; resolves path components case-insensitively
/// (NTFS mounted on Linux/macOS may be case-sensitive).
pub(crate) struct DirProbe<'a>(pub &'a Path);

impl DirProbe<'_> {
    fn resolve(&self, rel: &str) -> Option<PathBuf> {
        let mut cur = self.0.to_path_buf();
        for comp in rel.split('/').filter(|c| !c.is_empty()) {
            let exact = cur.join(comp);
            if std::fs::symlink_metadata(&exact).is_ok() {
                cur = exact;
                continue;
            }
            let found = std::fs::read_dir(&cur).ok()?.flatten().find(|e| {
                e.file_name().to_string_lossy().eq_ignore_ascii_case(comp)
            })?;
            cur = found.path();
        }
        Some(cur)
    }
}

impl Probe for DirProbe<'_> {
    fn kind(&self, path: &str) -> Option<bool> {
        let p = self.resolve(path)?;
        std::fs::metadata(p).ok().map(|m| m.is_dir())
    }
    fn read_at(&self, path: &str, offset: u64, len: usize) -> Option<Vec<u8>> {
        let mut f = std::fs::File::open(self.resolve(path)?).ok()?;
        f.seek(SeekFrom::Start(offset)).ok()?;
        let mut buf = Vec::with_capacity(len.min(1 << 20));
        f.take(len as u64).read_to_end(&mut buf).ok()?;
        Some(buf)
    }
    fn subdirs(&self, path: &str) -> Vec<String> {
        let Some(p) = self.resolve(path) else { return Vec::new() };
        let Ok(rd) = std::fs::read_dir(p) else { return Vec::new() };
        let mut v: Vec<String> = rd
            .flatten()
            .filter(|e| e.file_type().map(|t| t.is_dir() && !t.is_symlink()).unwrap_or(false))
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        v.sort_by_key(|s| s.to_lowercase());
        v
    }
}

/// Detect an OS install whose root is the mounted directory `root`.
pub fn detect_os_in_dir(root: &Path) -> Option<OsInstall> {
    detect_os(&DirProbe(root))
}

pub(crate) fn detect_os(p: &dyn Probe) -> Option<OsInstall> {
    if p.kind("Windows/System32") == Some(true)
        && p.kind("Windows/System32/ntoskrnl.exe") == Some(false)
    {
        let version = pe_product_version(p, "Windows/System32/ntoskrnl.exe");
        let name = windows_name(version.as_deref());
        const SKIP: [&str; 5] = ["public", "default", "default user", "all users", "wdagutilityaccount"];
        let users = p
            .subdirs("Users")
            .into_iter()
            .filter(|u| {
                let l = u.to_lowercase();
                !SKIP.contains(&l.as_str()) && !l.starts_with("defaultuser")
            })
            .collect();
        return Some(OsInstall { kind: OsKind::Windows, name, version, users });
    }
    if let Some(plist) = p.read_at("System/Library/CoreServices/SystemVersion.plist", 0, 64 * 1024) {
        let text = String::from_utf8_lossy(&plist);
        let name = plist_string(&text, "ProductName").unwrap_or_else(|| "macOS".into());
        let version = plist_string(&text, "ProductVersion");
        let users = p
            .subdirs("Users")
            .into_iter()
            .filter(|u| !u.starts_with('.') && u != "Shared" && u != "Guest")
            .collect();
        return Some(OsInstall { kind: OsKind::Macos, name, version, users });
    }
    let osr = p
        .read_at("etc/os-release", 0, 16 * 1024)
        .or_else(|| p.read_at("usr/lib/os-release", 0, 16 * 1024));
    if let Some(osr) = osr {
        let text = String::from_utf8_lossy(&osr);
        let field = |k: &str| {
            text.lines().find_map(|l| {
                let v = l.strip_prefix(k)?.strip_prefix('=')?;
                Some(v.trim().trim_matches('"').trim_matches('\'').to_string())
            })
        };
        let name = field("PRETTY_NAME").or_else(|| field("NAME")).unwrap_or_else(|| "Linux".into());
        let version = field("VERSION_ID");
        let users = p.subdirs("home").into_iter().filter(|u| u != "lost+found").collect();
        return Some(OsInstall { kind: OsKind::Linux, name, version, users });
    }
    None
}

fn windows_name(version: Option<&str>) -> String {
    let parts: Vec<u32> = version
        .unwrap_or("")
        .split('.')
        .filter_map(|s| s.parse().ok())
        .collect();
    match parts.as_slice() {
        [10, 0, build, ..] if *build >= 22000 => "Windows 11".into(),
        [10, ..] => "Windows 10".into(),
        [6, 3, ..] => "Windows 8.1".into(),
        [6, 2, ..] => "Windows 8".into(),
        [6, 1, ..] => "Windows 7".into(),
        _ => "Windows".into(),
    }
}

/// Very small XML plist reader: `<key>K</key><string>V</string>`.
fn plist_string(text: &str, key: &str) -> Option<String> {
    let k = format!("<key>{key}</key>");
    let rest = &text[text.find(&k)? + k.len()..];
    let start = rest.find("<string>")? + "<string>".len();
    let end = rest[start..].find("</string>")?;
    // The value must be the very next element.
    if rest[..start - "<string>".len()].trim().is_empty() {
        Some(rest[start..start + end].trim().to_string())
    } else {
        None
    }
}

/// Read the product version from a PE file's VS_FIXEDFILEINFO (in .rsrc).
pub(crate) fn pe_product_version(p: &dyn Probe, path: &str) -> Option<String> {
    let hdr = p.read_at(path, 0, 4096)?;
    if hdr.get(..2)? != b"MZ" {
        return None;
    }
    let rd32 = |b: &[u8], o: usize| -> Option<u32> {
        Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
    };
    let rd16 = |b: &[u8], o: usize| -> Option<u16> {
        Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
    };
    let pe = rd32(&hdr, 0x3c)? as usize;
    if hdr.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let nsec = rd16(&hdr, pe + 6)? as usize;
    let opt = rd16(&hdr, pe + 20)? as usize;
    let table = pe + 24 + opt;
    for i in 0..nsec.min(96) {
        let s = table + i * 40;
        if hdr.get(s..s + 5)? != b".rsrc" {
            continue;
        }
        let raw_size = rd32(&hdr, s + 16)? as usize;
        let raw_ptr = u64::from(rd32(&hdr, s + 20)?);
        let data = p.read_at(path, raw_ptr, raw_size.min(8 << 20))?;
        let sig = [0xBD, 0x04, 0xEF, 0xFE];
        let pos = data.windows(4).position(|w| w == sig)?;
        let ms = rd32(&data, pos + 16)?;
        let ls = rd32(&data, pos + 20)?;
        return Some(format!("{}.{}.{}.{}", ms >> 16, ms & 0xffff, ls >> 16, ls & 0xffff));
    }
    None
}

/// `hiberfil.sys` check on a mounted NTFS volume.
pub(crate) fn mounted_hiberfil_hibernated(root: &Path) -> bool {
    DirProbe(root)
        .read_at("hiberfil.sys", 0, 4)
        .is_some_and(|h| ntfs_hiberfil_is_hibernated(&h))
}

/// A shortcut to a user's folder inside an OS install.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UserFolder {
    /// e.g. "alice — Documents" or "bob (home)".
    pub label: String,
    /// Host path when the partition is mounted, else a path inside the
    /// partition's file system for [`crate::RawFs`] (e.g. "/home/bob").
    pub path: String,
    /// True when `path` is a RawFs path rather than a host path.
    pub raw: bool,
}

/// User folders of the OS install on `partition` (DB10): Windows
/// `Users\<name>\{Desktop,Documents,Downloads,Pictures}`, Linux `/home/<name>`,
/// macOS `/Users/<name>`. For mounted partitions only existing folders are returned.
pub fn user_folders(partition: &Partition) -> Vec<UserFolder> {
    let Some(os) = &partition.os else { return Vec::new() };
    let mut rels: Vec<(String, String)> = Vec::new();
    for u in &os.users {
        match os.kind {
            OsKind::Windows => {
                for sub in ["Desktop", "Documents", "Downloads", "Pictures"] {
                    rels.push((format!("{u} — {sub}"), format!("Users/{u}/{sub}")));
                }
            }
            OsKind::Linux => rels.push((format!("{u} (home)"), format!("home/{u}"))),
            OsKind::Macos => rels.push((format!("{u} (home)"), format!("Users/{u}"))),
        }
    }
    match &partition.mount {
        Some(m) => {
            let root = Path::new(m);
            rels.into_iter()
                .filter_map(|(label, rel)| {
                    let p = DirProbe(root).resolve(&rel)?;
                    p.is_dir().then(|| UserFolder { label, path: p.to_string_lossy().into_owned(), raw: false })
                })
                .collect()
        }
        None => rels
            .into_iter()
            .map(|(label, rel)| UserFolder { label, path: format!("/{rel}"), raw: true })
            .collect(),
    }
}
