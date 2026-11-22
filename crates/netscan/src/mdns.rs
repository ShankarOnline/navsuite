//! mDNS / DNS-SD (Bonjour) browsing: enumerate service types, then browse each one.

use crate::{Registry, Service};
use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;

const META: &str = "_services._dns-sd._udp.local.";

/// Types browsed even if nobody answers the meta query.
const COMMON: &[&str] = &[
    "_smb._tcp.local.", "_ssh._tcp.local.", "_sftp-ssh._tcp.local.", "_http._tcp.local.", "_ipp._tcp.local.",
    "_googlecast._tcp.local.", "_airplay._tcp.local.", "_device-info._tcp.local.", "_workstation._tcp.local.",
];

/// Map a DNS-SD type (`_ipp._tcp.local.`) to (service kind, label). None = no user-facing service
/// (the type still contributes names/TXT data).
pub(crate) fn service_kind(ty: &str) -> Option<(&'static str, &'static str)> {
    let name = ty.split('.').next().unwrap_or("");
    Some(match name {
        "_smb" => ("smb", "File sharing (SMB)"),
        "_ssh" => ("ssh", "Secure shell (SSH)"),
        "_sftp-ssh" => ("sftp", "SFTP file transfer"),
        "_ftp" => ("ftp", "File transfer (FTP)"),
        "_http" => ("http", "Web page"),
        "_https" => ("https", "Web page (HTTPS)"),
        "_ipp" => ("ipp", "Printer (IPP)"),
        "_ipps" => ("ipp", "Printer (IPP over TLS)"),
        "_printer" => ("printer", "Printer (LPD)"),
        "_pdl-datastream" => ("printer", "Printer (raw / JetDirect)"),
        "_scanner" | "_uscan" | "_uscans" => ("scanner", "Scanner"),
        "_googlecast" => ("googlecast", "Google Cast"),
        "_airplay" => ("airplay", "AirPlay"),
        "_raop" => ("airplay", "AirPlay audio"),
        "_spotify-connect" => ("spotify", "Spotify Connect"),
        "_companion-link" => ("companion", "Apple device"),
        "_afpovertcp" => ("afp", "Apple file sharing (AFP)"),
        "_nfs" => ("nfs", "NFS file sharing"),
        "_webdav" => ("webdav", "WebDAV"),
        "_webdavs" => ("webdav", "WebDAV (HTTPS)"),
        "_rfb" => ("vnc", "Screen sharing (VNC)"),
        "_rdp" => ("rdp", "Remote Desktop"),
        "_hap" => ("homekit", "HomeKit accessory"),
        "_matter" | "_matterc" => ("matter", "Matter device"),
        "_mqtt" => ("mqtt", "MQTT broker"),
        "_adb" | "_adb-tls-connect" => ("adb", "Android debugging (ADB)"),
        "_home-assistant" => ("http", "Home Assistant"),
        "_plexmediasvr" => ("plex", "Plex Media Server"),
        "_daap" => ("media", "Music library (DAAP)"),
        "_device-info" | "_workstation" | "_sleep-proxy" => return None,
        _ => return None,
    })
}

/// Browse for `secs` seconds, feeding everything resolved into the registry.
pub(crate) async fn browse(reg: Arc<Registry>, secs: u64, cancel: Arc<AtomicBool>) {
    let daemon = match ServiceDaemon::new() {
        Ok(d) => d,
        Err(e) => {
            reg.log(format!("mDNS unavailable: {e}"));
            return;
        }
    };
    let deadline = Instant::now() + Duration::from_secs(secs.max(1));
    let seen: Arc<Mutex<HashSet<String>>> = Arc::default();
    let mut tasks = Vec::new();
    let start_browse = |ty: &str, tasks: &mut Vec<tokio::task::JoinHandle<()>>| {
        if !seen.lock().unwrap().insert(ty.to_string()) {
            return;
        }
        if let Ok(rx) = daemon.browse(ty) {
            let reg = reg.clone();
            let cancel = cancel.clone();
            tasks.push(tokio::spawn(async move {
                while !cancel.load(Ordering::Relaxed) {
                    match tokio::time::timeout_at(deadline, rx.recv_async()).await {
                        Ok(Ok(ServiceEvent::ServiceResolved(svc))) => apply(&reg, &svc),
                        Ok(Ok(_)) => {}
                        _ => break,
                    }
                }
            }));
        }
    };
    for ty in COMMON {
        start_browse(ty, &mut tasks);
    }
    if let Ok(meta) = daemon.browse(META) {
        while !cancel.load(Ordering::Relaxed) {
            match tokio::time::timeout_at(deadline, meta.recv_async()).await {
                Ok(Ok(ServiceEvent::ServiceFound(_, ty))) => {
                    let ty = if ty.ends_with('.') { ty } else { format!("{ty}.") };
                    if ty.ends_with(".local.") && ty.starts_with('_') {
                        start_browse(&ty, &mut tasks);
                    }
                }
                Ok(Ok(_)) => {}
                _ => break,
            }
        }
    }
    for t in tasks {
        let _ = t.await;
    }
    let _ = daemon.shutdown();
    reg.progress("mdns", 1, 1);
}

fn apply(reg: &Registry, svc: &ResolvedService) {
    let instance = mdns_sd::instance_name_unescaped(&svc.fullname);
    let instance = instance.strip_suffix(&format!(".{}", svc.ty_domain)).unwrap_or(&instance).to_string();
    let txt = |k: &str| svc.txt_properties.get_property_val_str(k).map(str::trim).filter(|v| !v.is_empty()).map(str::to_string);
    // Cast devices put the friendly name in `fn`; AirPlay audio instances look like `AABBCC@Name`.
    let friendly = txt("fn").or_else(|| friendly_instance(&svc.ty_domain, &instance));
    // A printer queue shared by a computer ("HP LaserJet @ desk") describes the printer, not the host.
    let shared_queue = PRINTER_TYPES.iter().any(|p| svc.ty_domain.starts_with(p)) && instance.contains(" @ ");
    let model = if shared_queue { None } else { txt("model").or_else(|| txt("md")).or_else(|| txt("usb_MDL")).or_else(|| txt("ty")).or_else(|| txt("am")) };
    let manufacturer = if shared_queue { None } else { txt("usb_MFG").or_else(|| txt("manufacturer")) };
    let host = svc.host.trim_end_matches('.').to_string();
    let kind = service_kind(&svc.ty_domain);
    let proto = if svc.ty_domain.contains("._udp.") { "udp" } else { "tcp" };
    let is_info = svc.ty_domain.starts_with("_device-info.") || svc.ty_domain.starts_with("_workstation.");

    for addr in &svc.addresses {
        let IpAddr::V4(ip) = addr.to_ip_addr() else { continue };
        if ip.is_link_local() || (!reg.nets.is_empty() && reg.net_for(ip).is_none()) {
            continue;
        }
        reg.update(ip, |h| {
            if !host.is_empty() {
                h.mdns_name.get_or_insert_with(|| host.clone());
            }
            if !is_info && h.device_name.is_none() {
                h.device_name = friendly.clone();
            }
            if h.model.is_none() {
                h.model = model.clone();
            }
            if h.manufacturer.is_none() {
                h.manufacturer = manufacturer.clone();
            }
            // Port 0 means "not offered" (CUPS advertises _printer._tcp that way).
            if let Some((kind, label)) = kind.filter(|_| svc.port != 0) {
                let url = match kind {
                    "http" | "https" => {
                        let path = txt("path").unwrap_or_else(|| "/".into());
                        let path = if path.starts_with('/') { path } else { format!("/{path}") };
                        Some(format!("{kind}://{ip}:{}{path}", svc.port))
                    }
                    "ipp" => Some(format!("http://{ip}:{}/", svc.port)),
                    _ => None,
                };
                let mut details = Vec::new();
                for p in svc.txt_properties.iter().take(16) {
                    if !p.val_str().is_empty() && p.val_str().len() < 120 {
                        details.push((p.key().to_string(), p.val_str().to_string()));
                    }
                }
                h.add_service(Service {
                    kind: kind.into(),
                    label: label.into(),
                    port: svc.port,
                    proto: proto.into(),
                    source: "mdns".into(),
                    name: Some(instance.clone()),
                    url,
                    details,
                });
            }
            h.add_source("mdns");
        });
    }
}

const PRINTER_TYPES: &[&str] = &["_ipp.", "_ipps.", "_printer.", "_pdl-datastream."];

/// The instance name as a device name, when it plausibly is one.
pub(crate) fn friendly_instance(ty: &str, instance: &str) -> Option<String> {
    let mut name = instance.trim();
    if ty.starts_with("_raop.") {
        name = name.split_once('@').map(|(_, n)| n.trim()).unwrap_or(name);
    }
    // A printer queue shared by a computer ("HP LaserJet @ desk") names the printer, not the host.
    if PRINTER_TYPES.iter().any(|p| ty.starts_with(p)) && name.contains(" @ ") {
        return None;
    }
    // Opaque ids (UUIDs, hex serials) are not names.
    let hexish = name.chars().all(|c| c.is_ascii_hexdigit() || c == '-' || c == ':');
    if name.is_empty() || (hexish && name.len() >= 12) {
        return None;
    }
    Some(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_names() {
        assert_eq!(friendly_instance("_raop._tcp.local.", "A1B2C3D4E5F6@Living Room").as_deref(), Some("Living Room"));
        assert_eq!(friendly_instance("_ipp._tcp.local.", "HP LaserJet @ shankars-2"), None);
        assert_eq!(friendly_instance("_ipp._tcp.local.", "Brother DCP-T426W").as_deref(), Some("Brother DCP-T426W"));
        assert_eq!(friendly_instance("_hap._tcp.local.", "4B2708FF-77B1-453F-A558-E5A2C9F57751"), None);
        assert_eq!(friendly_instance("_smb._tcp.local.", " NAS ").as_deref(), Some("NAS"));
    }

    #[test]
    fn kinds() {
        assert_eq!(service_kind("_smb._tcp.local.").map(|k| k.0), Some("smb"));
        assert_eq!(service_kind("_ipps._tcp.local.").map(|k| k.0), Some("ipp"));
        assert_eq!(service_kind("_device-info._tcp.local."), None);
        assert_eq!(service_kind("_weird._tcp.local."), None);
    }
}
