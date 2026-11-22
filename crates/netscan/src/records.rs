//! System records: one entry per physical/virtual machine, however many ways we can reach it.
//!
//! A Mac seen on the LAN (ARP + Bonjour), on the tailnet (Tailscale) and in `~/.ssh/known_hosts`
//! becomes one [`SystemRecord`] with a channel for each route to it.
//!
//! Join rules (any one joins two observations): same MAC; same tailnet node; same normalised
//! name (NetBIOS, mDNS without `.local`, DNS short name, MagicDNS short name, ssh HostName;
//! case-insensitive); same IP. A MAC seen on several LAN IPs (Wi-Fi extenders doing proxy ARP,
//! routers answering for others) is treated as ambiguous and not used for joining or as an id.

use crate::sshcfg::SshHost;
use crate::tailnet::{TailPeer, TailnetStatus};
use crate::{Host, Service};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NameSource {
    pub name: String,
    /// device | netbios | mdns | dns | tailscale | magicdns | ssh
    pub source: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Channel {
    /// lan | tailscale | bonjour | netbios | smb | ssh | sftp | ftp | printer | web | cast | rdp | vnc
    pub kind: String,
    /// Something openable: `smb://10.0.0.5/`, `ssh://pi@pi.lan`, `http://10.0.0.1:8080/`, or a bare address.
    pub address: String,
    pub label: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SystemRecord {
    /// Stable id: MAC, else `ts:<nodeid>`, else `name:<lowercase name>`, else `ip:<ip>`.
    pub id: String,
    /// User-assigned label (filled in by the app; always None from `merge`).
    pub label: Option<String>,
    /// Best display name.
    pub name: String,
    pub names: Vec<NameSource>,
    pub ips: Vec<String>,
    pub mac: Option<String>,
    pub kind: String,
    pub online: bool,
    /// Unix ms: now when online, else Tailscale's last-seen time when known.
    pub last_seen: Option<u64>,
    pub channels: Vec<Channel>,
    pub services: Vec<Service>,
    pub is_self: bool,
}

/// Suffixes that make a DNS name "local", so only its first label matters.
const LOCAL_SUFFIXES: &[&str] = &["local", "lan", "home", "localdomain", "home.arpa", "internal", "intranet", "domain", "router", "fritz.box"];

/// Normalise a host name for joining. None for IPs and meaningless names.
pub(crate) fn norm_name(raw: &str) -> Option<String> {
    let n = raw.trim().trim_end_matches('.').to_lowercase();
    if n.is_empty() || n.parse::<IpAddr>().is_ok() || n == "localhost" || n == "unknown" {
        return None;
    }
    match n.split_once('.') {
        None => Some(n),
        Some((first, rest)) if LOCAL_SUFFIXES.contains(&rest) || rest.ends_with(".ts.net") || rest == "ts.net" || rest.ends_with(".beta.tailscale.net") => {
            (!first.is_empty()).then(|| first.to_string())
        }
        Some(_) => Some(n),
    }
}

#[derive(Clone, Copy)]
enum Obs<'a> {
    Lan(&'a Host),
    Tail(&'a Host),
    Peer(&'a TailPeer),
    Ssh(&'a SshHost),
}

struct Dsu(Vec<usize>);
impl Dsu {
    fn find(&mut self, x: usize) -> usize {
        let p = self.0[x];
        if p == x {
            return x;
        }
        let r = self.find(p);
        self.0[x] = r;
        r
    }
    fn union(&mut self, a: usize, b: usize) {
        let (a, b) = (self.find(a), self.find(b));
        if a != b {
            self.0[a.max(b)] = a.min(b);
        }
    }
}

/// Merge everything we know into one record per system.
pub fn merge(lan: &[Host], tail_hosts: &[Host], tail: Option<&TailnetStatus>, ssh: &[SshHost]) -> Vec<SystemRecord> {
    let peers: Vec<&TailPeer> = tail.map(|t| std::iter::once(&t.self_node).filter(|s| !s.id.is_empty()).chain(t.peers.iter()).collect()).unwrap_or_default();
    let mut obs: Vec<Obs> = Vec::new();
    obs.extend(lan.iter().map(Obs::Lan));
    obs.extend(tail_hosts.iter().map(Obs::Tail));
    obs.extend(peers.iter().map(|p| Obs::Peer(p)));
    obs.extend(ssh.iter().map(Obs::Ssh));

    let mut mac_count: HashMap<&str, usize> = HashMap::new();
    for h in lan {
        if let Some(m) = &h.mac {
            *mac_count.entry(m.as_str()).or_default() += 1;
        }
    }
    let unambiguous = |m: &Option<String>| m.as_deref().filter(|m| mac_count.get(m).copied().unwrap_or(0) <= 1).map(str::to_string);
    let peer_by_ip = |ip: &str| peers.iter().find(|p| p.ips.iter().any(|i| i == ip)).copied();

    // Join keys per observation.
    let keys: Vec<Vec<String>> = obs
        .iter()
        .map(|o| {
            let mut k = Vec::new();
            let name = |k: &mut Vec<String>, n: &Option<String>| {
                if let Some(n) = n.as_deref().and_then(norm_name) {
                    k.push(format!("name:{n}"));
                }
            };
            match o {
                Obs::Lan(h) => {
                    if let Some(m) = unambiguous(&h.mac) {
                        k.push(format!("mac:{m}"));
                    }
                    if h.is_self {
                        k.push("self".into());
                    }
                    name(&mut k, &h.netbios_name);
                    name(&mut k, &h.mdns_name);
                    name(&mut k, &h.hostname);
                    k.push(format!("ip:{}", h.ip));
                }
                Obs::Tail(h) => {
                    if let Some(p) = peer_by_ip(&h.ip) {
                        k.push(format!("node:{}", p.id));
                    }
                    name(&mut k, &h.hostname);
                    k.push(format!("ip:{}", h.ip));
                }
                Obs::Peer(p) => {
                    k.push(format!("node:{}", p.id));
                    if p.is_self {
                        k.push("self".into());
                    }
                    name(&mut k, &Some(p.dns_name.clone()));
                    name(&mut k, &Some(p.host_name.clone()));
                    k.extend(p.ips.iter().map(|i| format!("ip:{i}")));
                }
                Obs::Ssh(s) => {
                    if s.host_name.parse::<IpAddr>().is_ok() {
                        k.push(format!("ip:{}", s.host_name));
                    } else {
                        name(&mut k, &Some(s.host_name.clone()));
                    }
                }
            }
            k
        })
        .collect();

    let mut dsu = Dsu((0..obs.len()).collect());
    let mut owner: HashMap<&str, usize> = HashMap::new();
    for (i, ks) in keys.iter().enumerate() {
        for k in ks {
            match owner.get(k.as_str()) {
                Some(&j) => dsu.union(i, j),
                None => {
                    owner.insert(k, i);
                }
            }
        }
    }
    let mut groups: Vec<(usize, Vec<Obs>)> = Vec::new();
    for (i, o) in obs.iter().enumerate() {
        let root = dsu.find(i);
        match groups.iter_mut().find(|(r, _)| *r == root) {
            Some((_, g)) => g.push(*o),
            None => groups.push((root, vec![*o])),
        }
    }

    let now = now_ms();
    let mut records: Vec<SystemRecord> = groups.into_iter().map(|(_, g)| build(&g, &unambiguous, now)).collect();
    records.sort_by(|a, b| b.is_self.cmp(&a.is_self).then(b.online.cmp(&a.online)).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    records
}

fn build(group: &[Obs], unambiguous: &dyn Fn(&Option<String>) -> Option<String>, now: u64) -> SystemRecord {
    let lan: Vec<&Host> = group.iter().filter_map(|o| if let Obs::Lan(h) = o { Some(*h) } else { None }).collect();
    let tail: Vec<&Host> = group.iter().filter_map(|o| if let Obs::Tail(h) = o { Some(*h) } else { None }).collect();
    let peers: Vec<&TailPeer> = group.iter().filter_map(|o| if let Obs::Peer(p) = o { Some(*p) } else { None }).collect();
    let ssh: Vec<&SshHost> = group.iter().filter_map(|o| if let Obs::Ssh(s) = o { Some(*s) } else { None }).collect();

    // Names.
    let mut names: Vec<NameSource> = Vec::new();
    let mut add_name = |n: &str, source: &str| {
        let n = n.trim().trim_end_matches('.');
        if !n.is_empty() && n.parse::<IpAddr>().is_err() && !names.iter().any(|x| x.name.eq_ignore_ascii_case(n)) {
            names.push(NameSource { name: n.to_string(), source: source.into() });
        }
    };
    for h in &lan {
        for (n, source) in [(&h.device_name, "device"), (&h.netbios_name, "netbios"), (&h.mdns_name, "mdns"), (&h.hostname, "dns")] {
            if let Some(n) = n {
                add_name(n, source);
            }
        }
    }
    for p in &peers {
        add_name(&p.host_name, "tailscale");
        add_name(&p.dns_name, "magicdns");
    }
    for h in &tail {
        if let Some(n) = &h.hostname {
            add_name(n, "magicdns");
        }
    }
    for s in &ssh {
        add_name(&s.alias, "ssh");
        add_name(&s.host_name, "ssh");
    }

    // IPs.
    let mut ips: Vec<String> = Vec::new();
    let mut add_ip = |ip: &str| {
        if !ips.iter().any(|i| i == ip) {
            ips.push(ip.to_string());
        }
    };
    lan.iter().for_each(|h| add_ip(&h.ip));
    peers.iter().flat_map(|p| p.ips.iter()).for_each(|i| add_ip(i));
    tail.iter().for_each(|h| add_ip(&h.ip));
    ssh.iter().filter(|s| s.host_name.parse::<IpAddr>().is_ok()).for_each(|s| add_ip(&s.host_name));

    let short = |n: &str| n.trim_end_matches('.').trim_end_matches(".local").split('.').next().unwrap_or(n).to_string();
    let first = |f: &dyn Fn(&Host) -> Option<String>| lan.iter().find_map(|h| f(h));
    let name = first(&|h| h.device_name.clone())
        .or_else(|| peers.first().map(|p| p.host_name.clone()).filter(|n| !n.is_empty()))
        .or_else(|| first(&|h| h.netbios_name.clone()))
        .or_else(|| first(&|h| h.mdns_name.as_deref().map(short)))
        .or_else(|| first(&|h| h.hostname.as_deref().filter(|n| n.parse::<IpAddr>().is_err()).map(short)))
        .or_else(|| tail.iter().find_map(|h| h.hostname.as_deref().map(short)))
        .or_else(|| ssh.first().map(|s| s.alias.clone()))
        .or_else(|| ips.first().cloned())
        .unwrap_or_default();

    let is_self = lan.iter().any(|h| h.is_self) || peers.iter().any(|p| p.is_self);
    let online = is_self || !lan.is_empty() || !tail.is_empty() || peers.iter().any(|p| p.online);
    let last_seen = if online { Some(now) } else { peers.iter().filter_map(|p| p.last_seen.as_deref().and_then(parse_rfc3339_ms)).max() };

    let kind = lan
        .iter()
        .chain(tail.iter())
        .map(|h| h.kind.as_str())
        .find(|k| *k != "device")
        .map(str::to_string)
        .or_else(|| peers.first().map(|p| kind_from_os(&p.os).to_string()))
        .unwrap_or_else(|| if ssh.is_empty() { "device" } else { "server" }.to_string());
    // Tailscale knows the real OS: a Linux box running Samba + xrdp is not a Windows PC.
    let kind = match (kind.as_str(), peers.first().map(|p| kind_from_os(&p.os))) {
        ("windows" | "computer" | "server", Some(k @ ("windows" | "computer" | "server"))) => k.to_string(),
        _ => kind,
    };

    // Services (LAN first; the same kind+port over the tailnet is the same service).
    let mut services: Vec<Service> = Vec::new();
    for s in lan.iter().chain(tail.iter()).flat_map(|h| h.services.iter()) {
        if !services.iter().any(|x| x.kind == s.kind && x.port == s.port && x.proto == s.proto) {
            services.push(s.clone());
        }
    }

    // Channels.
    let ssh_user = ssh.iter().find_map(|s| s.user.clone());
    let mut channels: Vec<Channel> = Vec::new();
    let mut ch = |kind: &str, address: String, label: String| {
        if !channels.iter().any(|c| c.kind == kind && c.address == address) {
            channels.push(Channel { kind: kind.into(), address, label });
        }
    };
    for h in &lan {
        ch("lan", h.ip.clone(), format!("LAN {}{}", h.ip, h.interface.as_deref().map(|i| format!(" ({i})")).unwrap_or_default()));
    }
    for p in &peers {
        let addr = if p.dns_name.is_empty() { p.ipv4().map(|i| i.to_string()).unwrap_or_default() } else { p.dns_name.clone() };
        if !addr.is_empty() {
            let ip = p.ipv4().map(|i| format!(" {i}")).unwrap_or_default();
            ch("tailscale", addr, format!("Tailscale{ip}{}", if p.online { "" } else { " (offline)" }));
        }
    }
    for h in &lan {
        if let Some(m) = &h.mdns_name {
            ch("bonjour", m.trim_end_matches('.').to_string(), format!("Bonjour {}", m.trim_end_matches('.')));
        }
        if let Some(n) = &h.netbios_name {
            ch("netbios", n.clone(), format!("NetBIOS {n}{}", h.workgroup.as_deref().map(|w| format!(" ({w})")).unwrap_or_default()));
        }
    }
    let lan_targets = lan.iter().map(|h| (h.ip.clone(), &h.services, "LAN"));
    let tail_targets = tail.iter().map(|h| {
        let addr = peers.iter().find(|p| p.ips.contains(&h.ip) && !p.dns_name.is_empty()).map(|p| p.dns_name.clone()).unwrap_or_else(|| h.ip.clone());
        (addr, &h.services, "Tailscale")
    });
    for (addr, svcs, via) in lan_targets.chain(tail_targets) {
        for s in svcs.iter() {
            for (kind, address, what) in service_channels(&addr, s, ssh_user.as_deref()) {
                ch(kind, address, format!("{what} via {via}"));
            }
        }
    }
    for s in &ssh {
        let user = s.user.as_deref().map(|u| format!("{u}@")).unwrap_or_default();
        let port = s.port.filter(|p| *p != 22).map(|p| format!(":{p}")).unwrap_or_default();
        let from = if s.source == "config" { format!("ssh config: {}", s.alias) } else { "known_hosts".into() };
        ch("ssh", format!("ssh://{user}{}{port}", s.host_name), format!("SSH ({from})"));
        ch("sftp", format!("sftp://{user}{}{port}", s.host_name), format!("SFTP ({from})"));
    }

    let mac = lan.iter().find_map(|h| h.mac.clone());
    let join_name = lan
        .iter()
        .flat_map(|h| [&h.netbios_name, &h.mdns_name, &h.hostname])
        .find_map(|n| n.as_deref().and_then(norm_name))
        .or_else(|| ssh.iter().find_map(|s| norm_name(&s.host_name)))
        .or_else(|| norm_name(&name));
    let id = lan
        .iter()
        .find_map(|h| unambiguous(&h.mac))
        .or_else(|| peers.first().map(|p| format!("ts:{}", p.id)))
        .or_else(|| join_name.map(|n| format!("name:{n}")))
        .unwrap_or_else(|| format!("ip:{}", ips.first().cloned().unwrap_or_default()));

    SystemRecord { id, label: None, name, names, ips, mac, kind, online, last_seen, channels, services, is_self }
}

/// Channels offered by one service at `addr`: (kind, openable address, description).
fn service_channels(addr: &str, s: &Service, user: Option<&str>) -> Vec<(&'static str, String, String)> {
    let port = s.port;
    let p = |default: u16| if port == default || port == 0 { String::new() } else { format!(":{port}") };
    let user = user.map(|u| format!("{u}@")).unwrap_or_default();
    match s.kind.as_str() {
        "smb" => vec![("smb", format!("smb://{addr}/"), "Files (SMB)".into())],
        "ssh" => vec![
            ("ssh", format!("ssh://{user}{addr}{}", p(22)), "SSH".into()),
            ("sftp", format!("sftp://{user}{addr}{}", p(22)), "SFTP".into()),
        ],
        "sftp" => vec![("sftp", format!("sftp://{user}{addr}{}", p(22)), "SFTP".into())],
        "ftp" => vec![("ftp", format!("ftp://{addr}{}/", p(21)), "FTP".into())],
        "ipp" => vec![("printer", format!("http://{addr}:{port}/"), "Printer".into())],
        "printer" => vec![("printer", format!("http://{addr}/"), "Printer".into())],
        "http" | "https" | "plex" | "webdav" => {
            let scheme = if s.kind == "https" { "https" } else { "http" };
            let default = if scheme == "https" { 443 } else { 80 };
            let path = if s.kind == "plex" { "web" } else { "" };
            vec![("web", format!("{scheme}://{addr}{}/{path}", p(default)), s.label.clone())]
        }
        "googlecast" | "airplay" | "dlna" => vec![("cast", addr.to_string(), s.label.clone())],
        "rdp" => vec![("rdp", format!("rdp://full%20address=s:{addr}:{port}"), "Remote Desktop".into())],
        "vnc" => vec![("vnc", format!("vnc://{addr}{}", p(5900)), "Screen sharing (VNC)".into())],
        _ => Vec::new(),
    }
}

fn kind_from_os(os: &str) -> &'static str {
    match os.to_lowercase().as_str() {
        "windows" => "windows",
        "macos" => "computer",
        "linux" | "freebsd" | "openbsd" => "server",
        "ios" | "android" => "phone",
        "tvos" => "media",
        _ => "device",
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Parse an RFC 3339 timestamp (`2026-11-20T08:15:00.123Z`, `...+05:30`) to unix ms.
pub(crate) fn parse_rfc3339_ms(s: &str) -> Option<u64> {
    let s = s.trim();
    let num = |a: usize, b: usize| s.get(a..b)?.parse::<i64>().ok();
    let (y, mo, d, h, mi, sec) = (num(0, 4)?, num(5, 7)?, num(8, 10)?, num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !matches!(s.as_bytes().get(10), Some(b'T' | b't' | b' ')) {
        return None;
    }
    let mut rest = &s[19..];
    let mut ms = 0i64;
    if let Some(frac) = rest.strip_prefix('.') {
        let digits = frac.find(|c: char| !c.is_ascii_digit()).unwrap_or(frac.len());
        let f = &frac[..digits];
        ms = format!("{:0<3}", &f[..f.len().min(3)]).parse().ok()?;
        rest = &frac[digits..];
    }
    let offset_min = match rest {
        "Z" | "z" | "" => 0,
        o if o.len() == 6 => {
            let sign = if o.starts_with('-') { -1 } else { 1 };
            sign * (o.get(1..3)?.parse::<i64>().ok()? * 60 + o.get(4..6)?.parse::<i64>().ok()?)
        }
        _ => return None,
    };
    // Days from civil (Howard Hinnant).
    let (y2, m2) = if mo <= 2 { (y - 1, mo + 9) } else { (y, mo - 3) };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * m2 + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + h * 3600 + mi * 60 + sec - offset_min * 60;
    u64::try_from(secs * 1000 + ms).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc(kind: &str, port: u16) -> Service {
        Service { kind: kind.into(), label: kind.into(), port, proto: "tcp".into(), source: "tcp".into(), ..Default::default() }
    }

    fn peer(id: &str, host: &str, ip: &str, online: bool) -> TailPeer {
        TailPeer {
            id: id.into(),
            host_name: host.into(),
            dns_name: format!("{}.example.ts.net", host.to_lowercase()),
            ips: vec![ip.into()],
            os: "macOS".into(),
            online,
            last_seen: (!online).then(|| "2026-11-20T08:15:00Z".into()),
            ..Default::default()
        }
    }

    fn status(self_node: TailPeer, peers: Vec<TailPeer>) -> TailnetStatus {
        TailnetStatus { self_node: TailPeer { is_self: true, ..self_node }, peers, magic_dns_suffix: Some("example.ts.net".into()), backend_state: "Running".into() }
    }

    #[test]
    fn names_normalise() {
        assert_eq!(norm_name("Example-MacBook-Pro.local.").as_deref(), Some("example-macbook-pro"));
        assert_eq!(norm_name("nas.lan").as_deref(), Some("nas"));
        assert_eq!(norm_name("pi.example.ts.net").as_deref(), Some("pi"));
        assert_eq!(norm_name("aur.archlinux.org").as_deref(), Some("aur.archlinux.org"));
        assert_eq!(norm_name("DESKTOP-AB12").as_deref(), Some("desktop-ab12"));
        assert_eq!(norm_name("10.0.0.1"), None);
        assert_eq!(norm_name("localhost"), None);
    }

    #[test]
    fn mac_on_lan_and_tailnet_is_one_record() {
        let lan = vec![Host {
            ip: "192.168.1.36".into(),
            mac: Some("ec:93:7d:a4:4b:d9".into()),
            mdns_name: Some("Example-MacBook-Pro.local".into()),
            device_name: Some("Example MacBook Pro".into()),
            kind: "computer".into(),
            services: vec![svc("ssh", 22), svc("smb", 445)],
            ..Default::default()
        }];
        let tail_hosts = vec![Host { ip: "100.100.100.2".into(), hostname: Some("example-macbook-pro.example.ts.net".into()), kind: "computer".into(), services: vec![svc("ssh", 22), svc("vnc", 5900)], ..Default::default() }];
        let st = status(peer("nSelf", "Example-Desktop", "100.100.100.1", true), vec![peer("nMac", "Example-MacBook-Pro", "100.100.100.2", true)]);
        let ssh = vec![SshHost { alias: "100.100.100.2".into(), host_name: "100.100.100.2".into(), user: None, port: None, source: "known_hosts".into() }];
        let recs = merge(&lan, &tail_hosts, Some(&st), &ssh);
        assert_eq!(recs.len(), 2, "{recs:#?}"); // the Mac, and this machine (tailnet self)
        let mac = recs.iter().find(|r| r.id == "ec:93:7d:a4:4b:d9").expect("mac record");
        assert_eq!(mac.name, "Example MacBook Pro");
        assert!(mac.online);
        assert_eq!(mac.ips, vec!["192.168.1.36", "100.100.100.2"]);
        let kinds: Vec<&str> = mac.channels.iter().map(|c| c.kind.as_str()).collect();
        for k in ["lan", "tailscale", "bonjour", "smb", "ssh", "sftp", "vnc"] {
            assert!(kinds.contains(&k), "missing {k} in {kinds:?}");
        }
        assert!(mac.channels.iter().any(|c| c.address == "smb://192.168.1.36/"));
        assert!(mac.channels.iter().any(|c| c.address == "ssh://example-macbook-pro.example.ts.net"));
        assert!(mac.channels.iter().any(|c| c.kind == "tailscale" && c.address == "example-macbook-pro.example.ts.net"));
        // ssh appears on both networks but once in services.
        assert_eq!(mac.services.iter().filter(|s| s.kind == "ssh").count(), 1);
        assert_eq!(mac.services.len(), 3);
    }

    #[test]
    fn self_joins_tailnet_self() {
        let lan = vec![Host { ip: "192.168.1.31".into(), is_self: true, netbios_name: Some("DESKTOP-EXAMPLE".into()), kind: "windows".into(), ..Default::default() }];
        let st = status(TailPeer { os: "windows".into(), ..peer("nSelf", "Example-Desktop", "100.100.100.1", true) }, vec![]);
        let recs = merge(&lan, &[], Some(&st), &[]);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].is_self);
        assert_eq!(recs[0].kind, "windows");
        assert_eq!(recs[0].ips, vec!["192.168.1.31", "100.100.100.1"]);
    }

    #[test]
    fn shared_mac_does_not_merge() {
        let h = |ip: &str| Host { ip: ip.into(), mac: Some("aa:bb:cc:dd:ee:01".into()), kind: "device".into(), ..Default::default() };
        let recs = merge(&[h("10.0.0.40"), h("10.0.0.104"), h("10.0.0.108")], &[], None, &[]);
        assert_eq!(recs.len(), 3);
        assert!(recs.iter().all(|r| r.id.starts_with("ip:")));
    }

    #[test]
    fn offline_peer_and_ssh_config() {
        let st = status(peer("nSelf", "me", "100.1.1.1", true), vec![peer("nDesk", "ExampleDesk", "100.100.175.72", false)]);
        let ssh = vec![
            SshHost { alias: "desk".into(), host_name: "exampledesk".into(), user: Some("user".into()), port: Some(2222), source: "config".into() },
            SshHost { alias: "nas".into(), host_name: "10.0.0.9".into(), user: Some("admin".into()), port: None, source: "config".into() },
        ];
        let lan = vec![Host { ip: "10.0.0.9".into(), netbios_name: Some("NAS".into()), kind: "nas".into(), services: vec![svc("smb", 445)], ..Default::default() }];
        let recs = merge(&lan, &[], Some(&st), &ssh);
        assert_eq!(recs.len(), 3, "{recs:#?}");
        let desk = recs.iter().find(|r| r.id == "ts:nDesk").unwrap();
        assert!(!desk.online);
        assert_eq!(desk.last_seen, parse_rfc3339_ms("2026-11-20T08:15:00Z"));
        assert!(desk.channels.iter().any(|c| c.address == "ssh://user@exampledesk:2222"));
        assert!(desk.channels.iter().any(|c| c.kind == "tailscale" && c.label.contains("offline")));
        let nas = recs.iter().find(|r| r.id == "name:nas").unwrap();
        assert!(nas.channels.iter().any(|c| c.address == "ssh://admin@10.0.0.9"));
        assert!(nas.channels.iter().any(|c| c.address == "smb://10.0.0.9/"));
        // Self record sorts first.
        assert!(recs[0].is_self);
    }

    #[test]
    fn distinct_hosts_stay_apart() {
        let a = Host { ip: "10.0.0.2".into(), netbios_name: Some("ALPHA".into()), kind: "windows".into(), ..Default::default() };
        let b = Host { ip: "10.0.0.3".into(), mdns_name: Some("beta.local".into()), kind: "computer".into(), ..Default::default() };
        let c = Host { ip: "10.0.0.4".into(), hostname: Some("alpha.lan".into()), kind: "device".into(), ..Default::default() };
        let recs = merge(&[a, b, c], &[], None, &[]);
        assert_eq!(recs.len(), 2); // ALPHA (NetBIOS) and alpha.lan (DNS) are the same machine
        let alpha = recs.iter().find(|r| r.id == "name:alpha").unwrap();
        assert_eq!(alpha.ips, vec!["10.0.0.2", "10.0.0.4"]);
    }

    #[test]
    fn rfc3339() {
        assert_eq!(parse_rfc3339_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339_ms("2026-11-20T08:15:00Z"), Some(1_795_162_500_000));
        assert_eq!(parse_rfc3339_ms("2026-11-20T13:45:00.5+05:30"), Some(1_795_162_500_500));
        assert_eq!(parse_rfc3339_ms("garbage"), None);
    }
}
