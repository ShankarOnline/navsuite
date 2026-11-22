//! Tailscale: the peers of this machine's tailnet, via `tailscale status --json`.
//!
//! The local API is only reachable through the CLI portably (it's a named pipe on Windows and a
//! unix socket elsewhere, with per-OS auth), so we run the CLI that ships with every install.

use crate::{Emit, Host, Registry, ScanOptions};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TailPeer {
    /// Stable node ID, e.g. `nbjdoRLT7B21CNTRL`.
    pub id: String,
    pub host_name: String,
    /// MagicDNS name without the trailing dot, e.g. `nas.tail1234.ts.net`.
    pub dns_name: String,
    /// Tailnet addresses (IPv4 first).
    pub ips: Vec<String>,
    pub os: String,
    pub online: bool,
    /// RFC 3339; None when never seen / not reported.
    pub last_seen: Option<String>,
    /// This peer is the exit node currently in use.
    pub exit_node: bool,
    /// This peer offers itself as an exit node.
    pub exit_node_option: bool,
    pub key_expiry: Option<String>,
    pub is_self: bool,
    /// Subnet routes this peer advertises (and that are approved).
    pub routes: Vec<String>,
}

impl TailPeer {
    /// First label of the MagicDNS name (falls back to the host name), lowercase.
    pub fn short_name(&self) -> String {
        let n = if self.dns_name.is_empty() { &self.host_name } else { &self.dns_name };
        n.split('.').next().unwrap_or("").to_lowercase()
    }

    pub fn ipv4(&self) -> Option<Ipv4Addr> {
        self.ips.iter().find_map(|i| i.parse().ok())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TailnetStatus {
    pub self_node: TailPeer,
    pub peers: Vec<TailPeer>,
    pub magic_dns_suffix: Option<String>,
    /// Running | Stopped | NeedsLogin | Starting | NoState ...
    pub backend_state: String,
}

/// Minimum connect timeout for tailnet probes.
const TAILNET_TIMEOUT_MS: u64 = 3000;

fn find_cli() -> Option<PathBuf> {
    if let Some(p) = crate::cmd::which("tailscale") {
        return Some(p);
    }
    let candidates: &[&str] = if cfg!(windows) {
        &["C:\\Program Files\\Tailscale\\tailscale.exe", "C:\\Program Files (x86)\\Tailscale\\tailscale.exe"]
    } else if cfg!(target_os = "macos") {
        &["/Applications/Tailscale.app/Contents/MacOS/Tailscale", "/opt/homebrew/bin/tailscale", "/usr/local/bin/tailscale"]
    } else {
        &["/usr/bin/tailscale", "/usr/local/bin/tailscale", "/usr/sbin/tailscale", "/snap/bin/tailscale"]
    };
    candidates.iter().map(PathBuf::from).find(|p| p.is_file())
}

/// Ask the local Tailscale client for the tailnet. Err when Tailscale isn't installed or its daemon isn't running.
pub async fn tailnet_status() -> Result<TailnetStatus, String> {
    let cli = find_cli().ok_or("Tailscale is not installed (the tailscale command was not found)")?;
    let out = crate::cmd::run(&cli, &["status", "--json"], Duration::from_secs(8)).await?;
    let text = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() && !text.trim_start().starts_with('{') {
        let err = String::from_utf8_lossy(&out.stderr);
        let first = err.lines().find(|l| !l.trim().is_empty()).unwrap_or("no output");
        return Err(format!("Tailscale is not running: {first}"));
    }
    parse_status(&text)
}

fn s(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").to_string()
}

fn strs(v: &Value, k: &str) -> Vec<String> {
    v.get(k).and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default()
}

/// Tailscale reports "never" as the zero time.
fn time(v: &Value, k: &str) -> Option<String> {
    let t = s(v, k);
    (!t.is_empty() && !t.starts_with("0001-")).then_some(t)
}

fn peer(v: &Value, is_self: bool) -> TailPeer {
    let mut ips = strs(v, "TailscaleIPs");
    ips.sort_by_key(|i| i.contains(':')); // IPv4 first
    TailPeer {
        id: s(v, "ID"),
        host_name: s(v, "HostName"),
        dns_name: s(v, "DNSName").trim_end_matches('.').to_string(),
        ips,
        os: s(v, "OS"),
        online: v.get("Online").and_then(Value::as_bool).unwrap_or(false),
        last_seen: time(v, "LastSeen"),
        exit_node: v.get("ExitNode").and_then(Value::as_bool).unwrap_or(false),
        exit_node_option: v.get("ExitNodeOption").and_then(Value::as_bool).unwrap_or(false),
        key_expiry: time(v, "KeyExpiry"),
        is_self,
        routes: strs(v, "PrimaryRoutes"),
    }
}

/// Parse `tailscale status --json`.
pub(crate) fn parse_status(text: &str) -> Result<TailnetStatus, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("unexpected tailscale output: {e}"))?;
    let self_node = v.get("Self").map(|s| peer(s, true)).unwrap_or_default();
    let mut peers: Vec<TailPeer> = v.get("Peer").and_then(Value::as_object).map(|m| m.values().map(|p| peer(p, false)).collect()).unwrap_or_default();
    peers.sort_by(|a, b| b.online.cmp(&a.online).then_with(|| a.host_name.to_lowercase().cmp(&b.host_name.to_lowercase())));
    let suffix = v.get("CurrentTailnet").map(|t| s(t, "MagicDNSSuffix")).filter(|x| !x.is_empty()).or_else(|| Some(s(&v, "MagicDNSSuffix")).filter(|x| !x.is_empty()));
    Ok(TailnetStatus { self_node, peers, magic_dns_suffix: suffix, backend_state: s(&v, "BackendState") })
}

/// Read the tailnet, then port-probe every online peer (see [`probe_tailnet`]).
pub async fn scan_tailnet(opts: ScanOptions, cancel: Arc<AtomicBool>, emit: Emit) -> Result<(TailnetStatus, Vec<Host>), String> {
    let status = tailnet_status().await?;
    let hosts = probe_tailnet(&status, &opts, cancel, emit).await;
    Ok((status, hosts))
}

/// Port-probe each online peer's IPv4 tailnet address with [`crate::PORTS`]. Hosts have source
/// "tailscale", interface "Tailscale" and `hostname` = MagicDNS name. Self is skipped. The connect timeout is at least 3 s and peers with no open port are tried twice.
pub async fn probe_tailnet(status: &TailnetStatus, opts: &ScanOptions, cancel: Arc<AtomicBool>, emit: Emit) -> Vec<Host> {
    let reg = Registry::new(Vec::new(), emit);
    let mut ips = Vec::new();
    for p in status.peers.iter().filter(|p| p.online) {
        let Some(ip) = p.ipv4() else { continue };
        ips.push(ip);
        reg.update(ip, |h| {
            h.hostname = Some(if p.dns_name.is_empty() { p.host_name.clone() } else { p.dns_name.clone() });
            h.interface = Some("Tailscale".into());
            h.add_source("tailscale");
        });
    }
    // Tailnet paths can be relayed (DERP) and the first packet may wait for path setup, so allow
    // a much longer connect timeout than on the LAN. There are few peers, so this stays quick.
    let opts = ScanOptions { probe_timeout_ms: opts.probe_timeout_ms.max(TAILNET_TIMEOUT_MS), ..opts.clone() };
    crate::probe::probe_registry(&reg, &ips, &opts, &cancel, "tcp", 2).await;
    reg.all()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "Version": "1.104.4", "BackendState": "Running",
      "Self": { "ID": "nSelf1CNTRL", "HostName": "Shankars-Window", "DNSName": "shankars-window.tail85ff9a.ts.net.",
        "OS": "windows", "TailscaleIPs": ["fd7a:115c:a1e0::8c32:c779", "100.119.199.120"], "Online": true,
        "ExitNode": false, "ExitNodeOption": false, "LastSeen": "0001-01-01T00:00:00Z", "KeyExpiry": "2027-03-25T16:00:35Z" },
      "MagicDNSSuffix": "tail85ff9a.ts.net",
      "CurrentTailnet": { "Name": "me@example.com", "MagicDNSSuffix": "tail85ff9a.ts.net", "MagicDNSEnabled": true },
      "Peer": {
        "nodekey:aa": { "ID": "nDesk", "HostName": "ShankarDesk", "DNSName": "shankardesk.tail85ff9a.ts.net.", "OS": "linux",
          "TailscaleIPs": ["100.100.175.72", "fd7a:115c:a1e0::fc32:af49"], "Online": false, "LastSeen": "2026-11-20T08:15:00Z",
          "ExitNodeOption": true, "PrimaryRoutes": ["192.168.50.0/24"] },
        "nodekey:bb": { "ID": "nMac", "HostName": "Shankars-MacBook-Pro", "DNSName": "shankars-macbook-pro.tail85ff9a.ts.net.",
          "OS": "macOS", "TailscaleIPs": ["100.93.52.114"], "Online": true, "ExitNode": true }
      }
    }"#;

    #[test]
    fn parse_sample() {
        let st = parse_status(SAMPLE).unwrap();
        assert_eq!(st.backend_state, "Running");
        assert_eq!(st.magic_dns_suffix.as_deref(), Some("tail85ff9a.ts.net"));
        assert!(st.self_node.is_self);
        assert_eq!(st.self_node.ips[0], "100.119.199.120");
        assert_eq!(st.self_node.last_seen, None);
        assert_eq!(st.self_node.short_name(), "shankars-window");
        assert_eq!(st.peers.len(), 2);
        let mac = &st.peers[0]; // online first
        assert_eq!((mac.host_name.as_str(), mac.online, mac.exit_node), ("Shankars-MacBook-Pro", true, true));
        assert_eq!(mac.dns_name, "shankars-macbook-pro.tail85ff9a.ts.net");
        let desk = &st.peers[1];
        assert_eq!(desk.routes, vec!["192.168.50.0/24"]);
        assert!(desk.exit_node_option && !desk.online);
        assert_eq!(desk.last_seen.as_deref(), Some("2026-11-20T08:15:00Z"));
        assert_eq!(desk.ipv4(), Some(Ipv4Addr::new(100, 100, 175, 72)));
        assert!(parse_status("not json").is_err());
    }
}
