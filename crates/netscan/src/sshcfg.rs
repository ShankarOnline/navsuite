//! Hosts the user already knows via SSH: `~/.ssh/config` and `~/.ssh/known_hosts`.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct SshHost {
    /// The name used with `ssh <alias>`.
    pub alias: String,
    /// The real host name / IP (HostName, or the alias when not set).
    pub host_name: String,
    pub user: Option<String>,
    pub port: Option<u16>,
    /// "config" | "known_hosts"
    pub source: String,
}

fn home() -> Option<PathBuf> {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).or_else(|| std::env::var_os("HOME")).map(PathBuf::from)
}

/// Hosts from ~/.ssh/config (concrete Host entries) and ~/.ssh/known_hosts (unhashed entries).
/// Blocking but tiny (two small files).
pub fn ssh_hosts() -> Vec<SshHost> {
    let Some(dir) = home().map(|h| h.join(".ssh")) else { return Vec::new() };
    let mut hosts = Vec::new();
    if let Ok(t) = std::fs::read_to_string(dir.join("config")) {
        hosts = parse_config(&t, &dir, 0);
    }
    if let Ok(t) = std::fs::read_to_string(dir.join("known_hosts")) {
        for k in parse_known_hosts(&t) {
            let dup = hosts.iter().any(|h| h.host_name.eq_ignore_ascii_case(&k.host_name) || h.alias.eq_ignore_ascii_case(&k.host_name));
            if !dup {
                hosts.push(k);
            }
        }
    }
    hosts
}

/// Split a config line into (keyword lowercase, value). Accepts `Key value` and `Key=value`.
fn keyword(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let i = line.find(|c: char| c.is_whitespace() || c == '=')?;
    let value = line[i..].trim_start_matches(|c: char| c.is_whitespace() || c == '=').trim();
    Some((line[..i].to_ascii_lowercase(), value.trim_matches('"').to_string()))
}

fn expand(path: &str, base: &Path) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(h) = home()
    {
        return h.join(rest);
    }
    let p = PathBuf::from(path);
    if p.is_absolute() { p } else { base.join(p) }
}

/// Files matched by an Include argument: a literal path, or `dir/*` / `dir/*.conf` style patterns.
fn include_files(pattern: &str, base: &Path) -> Vec<PathBuf> {
    let p = expand(pattern, base);
    let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    if !name.contains('*') {
        return vec![p];
    }
    let (prefix, suffix) = name.split_once('*').unwrap_or(("", ""));
    let mut files: Vec<PathBuf> = p
        .parent()
        .and_then(|d| std::fs::read_dir(d).ok())
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|f| f.is_file() && f.file_name().is_some_and(|n| n.to_string_lossy().starts_with(prefix) && n.to_string_lossy().ends_with(suffix)))
        .collect();
    files.sort();
    files
}

/// Parse an ssh_config. `base` resolves relative Include paths (~/.ssh).
pub(crate) fn parse_config(text: &str, base: &Path, depth: u8) -> Vec<SshHost> {
    let mut out: Vec<SshHost> = Vec::new();
    // Indices into `out` the current Host block applies to (empty inside Match or wildcard blocks).
    let mut current: Vec<usize> = Vec::new();
    for line in text.lines() {
        let Some((key, value)) = keyword(line) else { continue };
        match key.as_str() {
            "host" => {
                current.clear();
                for pat in value.split_whitespace() {
                    if pat.contains(['*', '?', '!']) {
                        continue;
                    }
                    current.push(out.len());
                    out.push(SshHost { alias: pat.to_string(), host_name: pat.to_string(), source: "config".into(), ..Default::default() });
                }
            }
            "match" => current.clear(),
            "include" if depth < 4 => {
                for pat in value.split_whitespace() {
                    for f in include_files(pat, base) {
                        if let Ok(t) = std::fs::read_to_string(&f) {
                            for h in parse_config(&t, base, depth + 1) {
                                if !out.iter().any(|o| o.alias == h.alias) {
                                    out.push(h);
                                }
                            }
                        }
                    }
                }
            }
            // ssh uses the first value it sees for each keyword.
            "hostname" => {
                for &i in &current {
                    if out[i].host_name == out[i].alias {
                        out[i].host_name = value.replace("%h", &out[i].alias);
                    }
                }
            }
            "user" => current.iter().for_each(|&i| {
                out[i].user.get_or_insert_with(|| value.clone());
            }),
            "port" => current.iter().for_each(|&i| {
                if out[i].port.is_none() {
                    out[i].port = value.parse().ok();
                }
            }),
            _ => {}
        }
    }
    out
}

/// Parse known_hosts. Hashed (`|1|`) and marker (`@cert-authority`/`@revoked`) lines are skipped;
/// `[host]:port` is unwrapped.
pub(crate) fn parse_known_hosts(text: &str) -> Vec<SshHost> {
    let mut out: Vec<SshHost> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('@') || line.starts_with('|') {
            continue;
        }
        let Some(hosts) = line.split_whitespace().next() else { continue };
        for h in hosts.split(',') {
            if h.starts_with('|') || h.contains(['*', '?', '!']) {
                continue;
            }
            let (host, port) = match h.strip_prefix('[').and_then(|r| r.split_once("]:")) {
                Some((host, port)) => (host.to_string(), port.parse().ok()),
                None => (h.to_string(), None),
            };
            if !out.iter().any(|o| o.host_name == host && o.port == port) {
                out.push(SshHost { alias: host.clone(), host_name: host, user: None, port, source: "known_hosts".into() });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config() {
        let t = "# comment\nHost aur.archlinux.org\n  IdentityFile ~/.ssh/aur\n  User aur\n\
                 Host pi pi4\n    HostName 192.168.1.40\n    User=pi\n    Port 2222\n    User ignored\n\
                 Host *.internal *\n    User wild\n\
                 Match host foo\n    User nope\n\
                 Host nas\n  hostname nas.lan\n";
        let h = parse_config(t, Path::new("."), 0);
        assert_eq!(h.len(), 4);
        assert_eq!(h[0], SshHost { alias: "aur.archlinux.org".into(), host_name: "aur.archlinux.org".into(), user: Some("aur".into()), port: None, source: "config".into() });
        assert_eq!((h[1].alias.as_str(), h[1].host_name.as_str(), h[1].user.as_deref(), h[1].port), ("pi", "192.168.1.40", Some("pi"), Some(2222)));
        assert_eq!(h[2].alias, "pi4");
        assert_eq!(h[2].host_name, "192.168.1.40");
        assert_eq!((h[3].host_name.as_str(), h[3].user.as_deref()), ("nas.lan", None));
    }

    #[test]
    fn known_hosts() {
        let t = "100.100.100.2 ssh-ed25519 AAAA\n100.100.100.2 ssh-rsa AAAA\n\
                 github.com,140.82.112.3 ssh-ed25519 AAAA\n[gitlab.local]:2222 ssh-ed25519 AAAA\n\
                 |1|abc=|def= ssh-ed25519 AAAA\n@revoked bad.example ssh-rsa AAAA\n";
        let h = parse_known_hosts(t);
        let names: Vec<_> = h.iter().map(|x| (x.host_name.as_str(), x.port)).collect();
        assert_eq!(names, vec![("100.100.100.2", None), ("github.com", None), ("140.82.112.3", None), ("gitlab.local", Some(2222))]);
    }
}
