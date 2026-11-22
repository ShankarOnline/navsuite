//! `Loc`: the canonical location type passed between the app and the UI.

use crate::error::{Result, VfsError};
use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Scheme {
    Local,
    Smb,
    Sftp,
}

/// A location on a local disk, an SMB share or an SFTP server.
///
/// Path conventions:
/// - `Local`: a native absolute path, `C:\dir\file` (drive paths are always
///   normalised to backslashes, root `C:\`) or `/dir/file` (root `/`).
/// - `Smb`: `/share/dir/file` with forward slashes; `/` is the host itself
///   (listing it lists the shares).
/// - `Sftp`: an absolute `/dir/file`, or `~` / `~/dir` relative to the login
///   directory (resolve with `Vfs::canonicalize`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Loc {
    pub scheme: Scheme,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub path: String,
}

/// One way of writing a location, for "Copy path as…".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PathForm {
    pub label: String,
    pub value: String,
}

/// Characters escaped inside the path part of the URIs we produce. Only `%`
/// is strictly needed for a lossless round trip; spaces stay readable.
const URI_PATH: &AsciiSet = &CONTROLS.add(b'%');
/// For userinfo, also escape the delimiters.
const URI_USER: &AsciiSet = &CONTROLS.add(b'%').add(b'@').add(b':').add(b'/');
/// For `file://` URLs given to other programs: RFC 3986-ish path escaping.
const FILE_URL: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'[')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

fn bad(s: &str, why: &str) -> VfsError {
    VfsError::new(
        crate::ErrorKind::Other,
        format!("cannot parse location '{s}': {why}"),
    )
}

fn decode(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

fn is_drive_path(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 2
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
        && (b.len() == 2 || b[2] == b'\\' || b[2] == b'/')
}

/// Split into components on `/` and `\`, dropping empties and `.`, resolving `..`.
fn components(s: &str, backslash_too: bool) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let parts: Box<dyn Iterator<Item = &str>> = if backslash_too {
        Box::new(s.split(['/', '\\']))
    } else {
        Box::new(s.split('/'))
    };
    for p in parts {
        match p {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            p => out.push(p.to_string()),
        }
    }
    out
}

fn win_local(s: &str) -> String {
    let drive = s[..1].to_ascii_uppercase();
    let comps = components(&s[2..], true);
    format!("{drive}:\\{}", comps.join("\\"))
}

fn unix_local(s: &str) -> String {
    format!("/{}", components(s, false).join("/"))
}

fn home_dir_string() -> Result<String> {
    dirs::home_dir()
        .map(|h| h.to_string_lossy().into_owned())
        .ok_or_else(|| VfsError::not_found("no home directory"))
}

impl Loc {
    pub fn local(path: impl AsRef<str>) -> Result<Loc> {
        let p = path.as_ref();
        let norm = if is_drive_path(p) {
            win_local(p)
        } else if p.starts_with('/') {
            unix_local(p)
        } else {
            return Err(bad(p, "not an absolute path"));
        };
        Ok(Loc {
            scheme: Scheme::Local,
            host: None,
            port: None,
            user: None,
            path: norm,
        })
    }

    fn smb(host: &str, user: Option<String>, port: Option<u16>, path: &str) -> Result<Loc> {
        if host.is_empty() {
            return Err(bad(path, "missing host"));
        }
        let comps = components(path, true);
        Ok(Loc {
            scheme: Scheme::Smb,
            host: Some(host.to_string()),
            port: port.filter(|p| *p != 445),
            user,
            path: format!("/{}", comps.join("/")),
        })
    }

    fn sftp(host: &str, user: Option<String>, port: Option<u16>, path: &str) -> Result<Loc> {
        if host.is_empty() {
            return Err(bad(path, "missing host"));
        }
        let path = if path.is_empty() || path == "~" || path == "/~" {
            "~".to_string()
        } else if let Some(rest) = path.strip_prefix("/~/").or_else(|| path.strip_prefix("~/")) {
            let c = components(rest, false);
            if c.is_empty() {
                "~".to_string()
            } else {
                format!("~/{}", c.join("/"))
            }
        } else if path.starts_with('/') {
            unix_local(path)
        } else {
            // scp-style relative path: relative to the login directory
            let c = components(path, false);
            if c.is_empty() {
                "~".to_string()
            } else {
                format!("~/{}", c.join("/"))
            }
        };
        Ok(Loc {
            scheme: Scheme::Sftp,
            host: Some(host.to_string()),
            port: port.filter(|p| *p != 22),
            user,
            path,
        })
    }

    /// Parse any of the supported location spellings (see crate docs).
    pub fn parse(input: &str) -> Result<Loc> {
        let s = input.trim();
        if s.is_empty() {
            return Err(bad(s, "empty"));
        }
        let lower = s.to_ascii_lowercase();
        for (prefix, scheme) in [
            ("smb://", Scheme::Smb),
            ("cifs://", Scheme::Smb),
            ("sftp://", Scheme::Sftp),
            ("ssh://", Scheme::Sftp),
            ("scp://", Scheme::Sftp),
        ] {
            if lower.starts_with(prefix) {
                return Self::parse_url(s, &s[prefix.len()..], scheme);
            }
        }
        if lower.starts_with("file://") {
            let rest = &s[7..];
            if let Some(p) = rest.strip_prefix('/') {
                let p = decode(p);
                return if is_drive_path(&p) {
                    Loc::local(&p)
                } else {
                    Loc::local(format!("/{p}"))
                };
            }
            let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
            let path = decode(path);
            if host.eq_ignore_ascii_case("localhost") {
                return if is_drive_path(&path) {
                    Loc::local(&path)
                } else {
                    Loc::local(format!("/{path}"))
                };
            }
            return Loc::smb(&decode(host), None, None, &path);
        }
        if let Some(rest) = s
            .strip_prefix(r"\\?\UNC\")
            .or_else(|| s.strip_prefix(r"\\.\UNC\"))
        {
            return Self::parse_unc(rest);
        }
        if let Some(rest) = s.strip_prefix(r"\\?\").or_else(|| s.strip_prefix(r"\\.\")) {
            return Loc::local(rest);
        }
        if s.starts_with(r"\\") || s.starts_with("//") {
            return Self::parse_unc(&s[2..]);
        }
        if is_drive_path(s) || s.starts_with('/') {
            return Loc::local(s);
        }
        if s == "~" {
            return Loc::local(home_dir_string()?);
        }
        if let Some(rest) = s.strip_prefix("~/").or_else(|| s.strip_prefix("~\\")) {
            let home = home_dir_string()?;
            let sep = if is_drive_path(&home) { '\\' } else { '/' };
            return Loc::local(format!("{home}{sep}{rest}"));
        }
        // scp form: user@host:path (also [v6]:path is not supported here)
        if let Some(colon) = s.find(':') {
            let (lhs, rhs) = (&s[..colon], &s[colon + 1..]);
            if let Some((user, host)) = lhs.rsplit_once('@')
                && !user.is_empty()
                && !host.is_empty()
                && !lhs.contains(['/', '\\'])
            {
                return Loc::sftp(host, Some(user.to_string()), None, rhs);
            }
        }
        Err(bad(s, "unrecognised form"))
    }

    fn parse_unc(rest: &str) -> Result<Loc> {
        let rest = rest.trim_start_matches(['\\', '/']);
        let (host, path) = match rest.find(['\\', '/']) {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        Loc::smb(host, None, None, path)
    }

    fn parse_url(orig: &str, rest: &str, scheme: Scheme) -> Result<Loc> {
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, authority),
        };
        let user = userinfo
            .map(|u| u.split_once(':').map(|(a, _)| a).unwrap_or(u))
            .filter(|u| !u.is_empty())
            .map(decode);
        let (host, port) = if let Some(v6) = hostport.strip_prefix('[') {
            let (h, after) = v6.split_once(']').ok_or_else(|| bad(orig, "unclosed ["))?;
            let port = match after.strip_prefix(':') {
                Some(p) if !p.is_empty() => {
                    Some(p.parse::<u16>().map_err(|_| bad(orig, "bad port"))?)
                }
                _ => None,
            };
            (h.to_string(), port)
        } else {
            match hostport.rsplit_once(':') {
                Some((h, p)) if !p.is_empty() => (
                    h.to_string(),
                    Some(p.parse::<u16>().map_err(|_| bad(orig, "bad port"))?),
                ),
                Some((h, _)) => (h.to_string(), None),
                None => (hostport.to_string(), None),
            }
        };
        let host = decode(&host);
        let path = decode(path);
        match scheme {
            Scheme::Smb => Loc::smb(&host, user, port, &path),
            Scheme::Sftp => Loc::sftp(&host, user, port, &path),
            Scheme::Local => unreachable!(),
        }
    }

    fn is_win(&self) -> bool {
        self.scheme == Scheme::Local && is_drive_path(&self.path)
    }

    fn host_str(&self) -> String {
        let h = self.host.as_deref().unwrap_or("");
        if h.contains(':') {
            format!("[{h}]")
        } else {
            h.to_string()
        }
    }

    fn authority(&self) -> String {
        let mut a = String::new();
        if let Some(u) = &self.user {
            a.push_str(&utf8_percent_encode(u, URI_USER).to_string());
            a.push('@');
        }
        a.push_str(&self.host_str());
        if let Some(p) = self.port {
            a.push_str(&format!(":{p}"));
        }
        a
    }

    /// Canonical string: native path for local, `smb://host/share/path`,
    /// `sftp://user@host[:port]/path` (home-relative paths as `/~/…`).
    pub fn to_uri(&self) -> String {
        match self.scheme {
            Scheme::Local => self.path.clone(),
            Scheme::Smb => {
                let p = if self.path == "/" {
                    String::new()
                } else {
                    utf8_percent_encode(&self.path, URI_PATH).to_string()
                };
                format!("smb://{}{}", self.authority(), p)
            }
            Scheme::Sftp => {
                let p = if self.path.starts_with('~') {
                    format!("/{}", self.path)
                } else {
                    self.path.clone()
                };
                format!(
                    "sftp://{}{}",
                    self.authority(),
                    utf8_percent_encode(&p, URI_PATH)
                )
            }
        }
    }

    /// Path components below the root (drive / share host / `/` / `~`).
    fn comps(&self) -> Vec<&str> {
        match self.scheme {
            Scheme::Local if self.is_win() => self.path[3..]
                .split('\\')
                .filter(|c| !c.is_empty())
                .collect(),
            Scheme::Sftp if self.path.starts_with('~') => self.path[1..]
                .split('/')
                .filter(|c| !c.is_empty())
                .collect(),
            _ => self.path.split('/').filter(|c| !c.is_empty()).collect(),
        }
    }

    fn with_comps(&self, comps: &[&str]) -> Loc {
        let path = match self.scheme {
            Scheme::Local if self.is_win() => format!("{}\\{}", &self.path[..2], comps.join("\\")),
            Scheme::Sftp if self.path.starts_with('~') => {
                if comps.is_empty() {
                    "~".into()
                } else {
                    format!("~/{}", comps.join("/"))
                }
            }
            _ => format!("/{}", comps.join("/")),
        };
        Loc {
            path,
            ..self.clone()
        }
    }

    pub fn parent(&self) -> Option<Loc> {
        let mut c = self.comps();
        if c.is_empty() {
            return None;
        }
        c.pop();
        Some(self.with_comps(&c))
    }

    /// Append one name (or a `/`-separated relative path).
    pub fn join(&self, name: &str) -> Loc {
        let backslash =
            self.scheme != Scheme::Sftp && !(self.scheme == Scheme::Local && !self.is_win());
        let mut owned: Vec<String> = self.comps().iter().map(|s| s.to_string()).collect();
        owned.extend(components(name, backslash));
        let refs: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
        self.with_comps(&refs)
    }

    /// Last path component; for roots, the drive (`C:`), host, `/` or `~`.
    pub fn name(&self) -> String {
        if let Some(last) = self.comps().last() {
            return last.to_string();
        }
        match self.scheme {
            Scheme::Local if self.is_win() => self.path[..2].to_string(),
            Scheme::Smb => self.host.clone().unwrap_or_default(),
            _ => self.path.clone(),
        }
    }

    pub fn is_root(&self) -> bool {
        self.comps().is_empty()
    }

    /// SMB only: the share name, if the location is inside one.
    pub fn share(&self) -> Option<&str> {
        if self.scheme != Scheme::Smb {
            return None;
        }
        self.path.split('/').find(|c| !c.is_empty())
    }

    /// SMB only: path inside the share with backslashes (may be empty).
    pub(crate) fn smb_rest(&self) -> Vec<&str> {
        self.comps().into_iter().skip(1).collect()
    }

    /// SMB only: `\\host\share\path`.
    pub fn unc(&self) -> Option<String> {
        if self.scheme != Scheme::Smb {
            return None;
        }
        let mut s = format!(r"\\{}", self.host.as_deref().unwrap_or(""));
        for c in self.comps() {
            s.push('\\');
            s.push_str(c);
        }
        Some(s)
    }

    /// True if `other` is this location or lies below it (same host/scheme).
    pub fn contains(&self, other: &Loc) -> bool {
        if self.scheme != other.scheme
            || !eq_host(&self.host, &other.host)
            || self.port != other.port
            || (self.scheme == Scheme::Sftp && self.user != other.user)
        {
            return false;
        }
        let ci = self.is_win() || self.scheme == Scheme::Smb;
        let a = self.comps();
        let b = other.comps();
        if self.is_win()
            && !self.path[..2].eq_ignore_ascii_case(&other.path[..2.min(other.path.len())])
        {
            return false;
        }
        if self.scheme == Scheme::Sftp && self.path.starts_with('~') != other.path.starts_with('~')
        {
            return false;
        }
        a.len() <= b.len()
            && a.iter().zip(b.iter()).all(|(x, y)| {
                if ci {
                    x.eq_ignore_ascii_case(y)
                } else {
                    x == y
                }
            })
    }

    /// Alternative spellings for "Copy path as…".
    pub fn forms(&self) -> Vec<PathForm> {
        let f = |label: &str, value: String| PathForm {
            label: label.into(),
            value,
        };
        let mut out = Vec::new();
        match self.scheme {
            Scheme::Local => {
                out.push(f("Path", self.path.clone()));
                out.push(f("Quoted path", format!("\"{}\"", self.path)));
                let url_path = if self.is_win() {
                    format!("/{}", self.path.replace('\\', "/"))
                } else {
                    self.path.clone()
                };
                out.push(f(
                    "File URL",
                    format!("file://{}", utf8_percent_encode(&url_path, FILE_URL)),
                ));
            }
            Scheme::Smb => {
                let unc = self.unc().unwrap_or_default();
                out.push(f("UNC path", unc.clone()));
                out.push(f("Quoted UNC path", format!("\"{unc}\"")));
                out.push(f("SMB URL", self.to_uri()));
                if let Some(p) = crate::smb::mounted_path(self) {
                    out.push(f("Mounted path", p.to_string_lossy().into_owned()));
                }
            }
            Scheme::Sftp => {
                out.push(f("SFTP URL", self.to_uri()));
                let user = self
                    .user
                    .as_ref()
                    .map(|u| format!("{u}@"))
                    .unwrap_or_default();
                let host = self.host_str();
                let scp_path = self
                    .path
                    .strip_prefix("~/")
                    .map(str::to_string)
                    .unwrap_or_else(|| {
                        if self.path == "~" {
                            String::new()
                        } else {
                            self.path.clone()
                        }
                    });
                match self.port {
                    Some(p) => out.push(f(
                        "scp",
                        format!(
                            "scp://{user}{host}:{p}/{}",
                            scp_path.trim_start_matches('/')
                        ),
                    )),
                    None => out.push(f("scp", format!("{user}{host}:{scp_path}"))),
                }
                let port = self.port.map(|p| format!(" -p {p}")).unwrap_or_default();
                out.push(f(
                    "ssh command",
                    format!("ssh{port} {user}{}", self.host.as_deref().unwrap_or("")),
                ));
            }
        }
        out
    }
}

pub(crate) fn eq_host(a: &Option<String>, b: &Option<String>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        (None, None) => true,
        _ => false,
    }
}

impl std::fmt::Display for Loc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_uri())
    }
}

impl std::str::FromStr for Loc {
    type Err = VfsError;
    fn from_str(s: &str) -> Result<Loc> {
        Loc::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Loc {
        Loc::parse(s).unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    #[test]
    fn local_windows_forms() {
        assert_eq!(p(r"C:\x\y").path, r"C:\x\y");
        assert_eq!(p("c:/x/y/").path, r"C:\x\y");
        assert_eq!(p("C:").path, r"C:\");
        assert_eq!(p(r"C:\a\.\b\..\c").path, r"C:\a\c");
        assert_eq!(p(r"\\?\C:\long\p").path, r"C:\long\p");
        assert_eq!(
            p("file:///C:/Program%20Files/x").path,
            r"C:\Program Files\x"
        );
        let l = p(r"C:\x\y");
        assert_eq!(l.parent().unwrap().path, r"C:\x");
        assert_eq!(l.parent().unwrap().parent().unwrap().path, r"C:\");
        assert!(p(r"C:\").parent().is_none());
        assert!(p(r"C:\").is_root());
        assert_eq!(p(r"C:\").name(), "C:");
        assert_eq!(l.name(), "y");
        assert_eq!(p(r"C:\").join("a").join("b c").path, r"C:\a\b c");
        assert_eq!(p(r"C:\a").join("b/c").path, r"C:\a\b\c");
        assert_eq!(l.to_uri(), r"C:\x\y");
        assert_eq!(p(&l.to_uri()), l);
    }

    #[test]
    fn local_unix_forms() {
        let l = p("/home/x/");
        assert_eq!(l.path, "/home/x");
        assert_eq!(l.scheme, Scheme::Local);
        assert_eq!(p("file:///home/x").path, "/home/x");
        assert_eq!(p("file://localhost/home/a%20b").path, "/home/a b");
        assert_eq!(p("/").parent(), None);
        assert_eq!(l.parent().unwrap().path, "/home");
        assert_eq!(p("/").join("etc").path, "/etc");
        assert!(Loc::parse("//").is_err());
        assert_eq!(p(&l.to_uri()), l);
    }

    #[test]
    fn home() {
        let h = dirs::home_dir().unwrap();
        let l = p("~");
        assert_eq!(l.scheme, Scheme::Local);
        assert_eq!(std::path::PathBuf::from(&l.path), h);
        let d = p("~/Documents");
        assert_eq!(d.parent().unwrap(), l);
        assert_eq!(d.name(), "Documents");
    }

    #[test]
    fn smb_forms() {
        let a = p(r"\\nas\media\Movies\x.mkv");
        let b = p("//nas/media/Movies/x.mkv");
        let c = p("smb://nas/media/Movies/x.mkv");
        let d = p("file://nas/media/Movies/x.mkv");
        let e = p(r"\\?\UNC\nas\media\Movies\x.mkv");
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_eq!(a, d);
        assert_eq!(a, e);
        assert_eq!(a.host.as_deref(), Some("nas"));
        assert_eq!(a.path, "/media/Movies/x.mkv");
        assert_eq!(a.to_uri(), "smb://nas/media/Movies/x.mkv");
        assert_eq!(a.share(), Some("media"));
        assert_eq!(a.unc().unwrap(), r"\\nas\media\Movies\x.mkv");
        let u = p("smb://bob@nas/share%20x/a%2520b");
        assert_eq!(u.user.as_deref(), Some("bob"));
        assert_eq!(u.path, "/share x/a%20b");
        assert_eq!(p(&u.to_uri()), u);
        let root = p("smb://nas");
        assert_eq!(root.path, "/");
        assert!(root.is_root());
        assert_eq!(root.name(), "nas");
        assert_eq!(root.to_uri(), "smb://nas");
        assert_eq!(p("//nas/media").parent().unwrap(), root);
        assert_eq!(root.join("media").to_uri(), "smb://nas/media");
        assert_eq!(p("smb://nas:445/x").port, None);
    }

    #[test]
    fn sftp_forms() {
        let a = p("sftp://pi@raspberrypi:2222/home/pi/x");
        assert_eq!(a.scheme, Scheme::Sftp);
        assert_eq!(a.user.as_deref(), Some("pi"));
        assert_eq!(a.port, Some(2222));
        assert_eq!(a.path, "/home/pi/x");
        assert_eq!(a.to_uri(), "sftp://pi@raspberrypi:2222/home/pi/x");
        assert_eq!(p(&a.to_uri()), a);
        assert_eq!(p("ssh://pi@raspberrypi:2222/home/pi/x"), a);
        let s = p("pi@raspberrypi:/etc/hosts");
        assert_eq!(s.path, "/etc/hosts");
        assert_eq!(s.port, None);
        let r = p("pi@raspberrypi:notes/a.txt");
        assert_eq!(r.path, "~/notes/a.txt");
        assert_eq!(r.to_uri(), "sftp://pi@raspberrypi/~/notes/a.txt");
        assert_eq!(p(&r.to_uri()), r);
        assert_eq!(r.parent().unwrap().parent().unwrap().path, "~");
        assert!(p("sftp://h").is_root());
        assert_eq!(p("sftp://h").path, "~");
        assert_eq!(p("sftp://h:22/").port, None);
        assert_eq!(p("sftp://h/").path, "/");
        let v6 = p("sftp://u@[fe80::1]:2200/tmp");
        assert_eq!(v6.host.as_deref(), Some("fe80::1"));
        assert_eq!(v6.to_uri(), "sftp://u@[fe80::1]:2200/tmp");
        let at = p("sftp://me%40corp.com@h/x");
        assert_eq!(at.user.as_deref(), Some("me@corp.com"));
        assert_eq!(p(&at.to_uri()), at);
    }

    #[test]
    fn rejects() {
        assert!(Loc::parse("").is_err());
        assert!(Loc::parse("relative/path").is_err());
        assert!(Loc::parse("sftp://").is_err());
    }

    #[test]
    fn contains() {
        assert!(p(r"C:\a").contains(&p(r"c:\A\b")));
        assert!(!p(r"C:\a").contains(&p(r"C:\ab")));
        assert!(p("/a").contains(&p("/a/b")));
        assert!(!p("/a").contains(&p("/A/b")));
        assert!(p("smb://nas/x").contains(&p(r"\\NAS\X\y")));
        assert!(!p("smb://nas/x").contains(&p("smb://other/x/y")));
    }

    #[test]
    fn forms() {
        let l = p(r"C:\a b\c");
        let v: Vec<String> = l.forms().into_iter().map(|f| f.value).collect();
        assert_eq!(
            v,
            vec![
                r"C:\a b\c".to_string(),
                "\"C:\\a b\\c\"".into(),
                "file:///C:/a%20b/c".into()
            ]
        );
        let s = p("smb://nas/media/x y");
        let v: Vec<String> = s.forms().into_iter().map(|f| f.value).collect();
        assert_eq!(v[0], r"\\nas\media\x y");
        assert!(v.contains(&"smb://nas/media/x y".to_string()));
        let f = p("sftp://pi@pi.local/etc/hosts").forms();
        let v: Vec<String> = f.into_iter().map(|f| f.value).collect();
        assert_eq!(
            v,
            vec![
                "sftp://pi@pi.local/etc/hosts",
                "pi@pi.local:/etc/hosts",
                "ssh pi@pi.local"
            ]
        );
        let f = p("sftp://pi@h:2222/x").forms();
        assert_eq!(f[2].value, "ssh -p 2222 pi@h");
        // every form we produce for URL schemes parses back to the same Loc
        assert_eq!(
            p(&p("sftp://pi@pi.local/etc/hosts").forms()[1].value),
            p("sftp://pi@pi.local/etc/hosts")
        );
        assert_eq!(p(&l.forms()[2].value), l);
        assert_eq!(p(&s.forms()[0].value), s);
    }
}
