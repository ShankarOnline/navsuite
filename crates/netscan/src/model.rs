use serde::{Deserialize, Serialize};

/// A system found on the local network, with everything the scan learned about it.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct Host {
    pub ip: String,
    pub mac: Option<String>,
    /// Reverse-DNS name (may come from DNS, LLMNR or NetBIOS, as the OS resolver sees it).
    pub hostname: Option<String>,
    /// Bonjour/mDNS host name, e.g. `nas.local`.
    pub mdns_name: Option<String>,
    pub netbios_name: Option<String>,
    pub workgroup: Option<String>,
    /// Friendly device name (UPnP friendlyName, mDNS instance name).
    pub device_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    /// computer | windows | server | printer | router | nas | media | phone | iot | device
    pub kind: String,
    pub is_self: bool,
    pub is_gateway: bool,
    /// The local interface (name) this host was seen on.
    pub interface: Option<String>,
    pub services: Vec<Service>,
    /// How the host was found: arp, tcp, mdns, ssdp, netbios, self.
    pub sources: Vec<String>,
}

impl Host {
    /// The best human name for the host.
    pub fn display_name(&self) -> String {
        self.device_name
            .clone()
            .or_else(|| self.netbios_name.clone())
            .or_else(|| self.mdns_name.as_ref().map(|n| n.trim_end_matches('.').trim_end_matches(".local").to_string()))
            .or_else(|| self.hostname.clone())
            .unwrap_or_else(|| self.ip.clone())
    }

    pub fn add_source(&mut self, s: &str) {
        if !self.sources.iter().any(|x| x == s) {
            self.sources.push(s.to_string());
        }
    }

    /// Add or merge a service (same kind + port = same service).
    pub fn add_service(&mut self, svc: Service) {
        if let Some(existing) = self
            .services
            .iter_mut()
            .find(|s| s.kind == svc.kind && s.port == svc.port && s.proto == svc.proto)
        {
            if existing.name.is_none() {
                existing.name = svc.name;
            }
            if existing.url.is_none() {
                existing.url = svc.url;
            }
            if !existing.source.split('+').any(|p| p == svc.source) {
                existing.source = format!("{}+{}", existing.source, svc.source);
            }
            for (k, v) in svc.details {
                if !existing.details.iter().any(|(ek, _)| *ek == k) {
                    existing.details.push((k, v));
                }
            }
        } else {
            self.services.push(svc);
            self.services.sort_by(|a, b| a.port.cmp(&b.port).then(a.kind.cmp(&b.kind)));
        }
    }

    pub fn has(&self, kind: &str) -> bool {
        self.services.iter().any(|s| s.kind == kind)
    }

    /// Guess what sort of device this is from what it offers.
    pub fn classify(&mut self) {
        let m = format!(
            "{} {} {}",
            self.manufacturer.as_deref().unwrap_or(""),
            self.model.as_deref().unwrap_or(""),
            self.device_name.as_deref().unwrap_or("")
        )
        .to_lowercase();
        self.kind = if self.is_gateway {
            "router"
        } else if (m.contains("printer") || self.has("printer") || self.has("ipp")) && !self.has("ssh") && !self.has("rdp") && !self.has("smb") {
            // Computers sharing a printer (CUPS, Windows) also offer IPP/LPD; real printers rarely offer SSH/SMB/RDP.
            "printer"
        } else if m.contains("synology") || m.contains("qnap") || m.contains("nas") || (self.has("smb") && (self.has("afp") || self.has("nfs"))) {
            "nas"
        } else if self.has("googlecast") || self.has("airplay") || self.has("spotify") || self.has("dlna") || m.contains("tv") || m.contains("speaker") {
            "media"
        } else if self.has("companion") || m.contains("iphone") || m.contains("ipad") || m.contains("android") {
            "phone"
        } else if self.has("rdp") || self.has("msrpc") || (self.has("smb") && self.netbios_name.is_some()) {
            "windows"
        } else if self.has("smb") || self.has("ssh") {
            if self.has("http") || self.has("https") { "server" } else { "computer" }
        } else if self.has("homekit") || self.has("mqtt") || self.has("matter") {
            "iot"
        } else if self.is_self {
            "computer"
        } else {
            "device"
        }
        .to_string();
    }
}

/// Something a host offers on the network.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    /// Short machine kind: http, https, smb, ssh, rdp, ftp, vnc, printer, ipp, dns, nfs, afp, upnp, googlecast, ...
    pub kind: String,
    /// Human label, e.g. "Web page (HTTPS)".
    pub label: String,
    pub port: u16,
    /// tcp | udp
    pub proto: String,
    /// How it was found: tcp, mdns, ssdp (joined with + when several agree).
    pub source: String,
    /// Instance name (mDNS) or friendly name (UPnP).
    pub name: Option<String>,
    /// Something the user can open, if any.
    pub url: Option<String>,
    pub details: Vec<(String, String)>,
}

/// An SMB share on a host.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Share {
    pub name: String,
    /// disk | printer | ipc | special
    pub kind: String,
    pub remark: String,
    /// UNC path on Windows (\\host\share), smb:// URL elsewhere.
    pub path: String,
}

/// Streamed while a scan runs.
#[derive(Serialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ScanEvent {
    Started { subnets: Vec<String> },
    Host { host: Box<Host> },
    Progress { phase: String, done: u32, total: u32 },
    Log { message: String },
    Done { hosts: usize, millis: u64, cancelled: bool },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ScanOptions {
    /// TCP connect timeout per probe.
    pub probe_timeout_ms: u64,
    /// Concurrent TCP probes.
    pub concurrency: usize,
    /// How long to listen for mDNS answers.
    pub mdns_secs: u64,
    /// How long to listen for SSDP answers.
    pub ssdp_secs: u64,
    /// Largest subnet swept per interface (prefix length). /24 = 254 addresses.
    pub min_prefix: u8,
    /// Include virtual adapters (Hyper-V, WSL, VirtualBox, VPN).
    pub include_virtual: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self { probe_timeout_ms: 600, concurrency: 384, mdns_secs: 6, ssdp_secs: 4, min_prefix: 24, include_virtual: false }
    }
}
