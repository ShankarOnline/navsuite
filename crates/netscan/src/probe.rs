//! TCP connect probes of well-known service ports. Plain `connect()` only: no raw packets, no admin rights.

use crate::{Emit, Registry, ScanOptions, Service};
use futures::StreamExt;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

/// Ports probed on every address: (port, service kind, human label).
pub const PORTS: &[(u16, &str, &str)] = &[
    (21, "ftp", "File transfer (FTP)"),
    (22, "ssh", "Secure shell (SSH)"),
    (23, "telnet", "Telnet"),
    (53, "dns", "DNS server"),
    (80, "http", "Web page"),
    (135, "msrpc", "Windows RPC"),
    (139, "netbios", "NetBIOS session"),
    (443, "https", "Web page (HTTPS)"),
    (445, "smb", "File sharing (SMB)"),
    (515, "printer", "Printer (LPD)"),
    (548, "afp", "Apple file sharing (AFP)"),
    (554, "rtsp", "Camera / media stream (RTSP)"),
    (631, "ipp", "Printer (IPP)"),
    (1883, "mqtt", "MQTT broker"),
    (2049, "nfs", "NFS file sharing"),
    (2869, "upnp", "UPnP / DLNA"),
    (3000, "http", "Web app (port 3000)"),
    (3389, "rdp", "Remote Desktop"),
    (5000, "http", "Web app (port 5000)"),
    (5001, "https", "Web app (HTTPS, port 5001)"),
    (5555, "adb", "Android debugging (ADB)"),
    (5900, "vnc", "Screen sharing (VNC)"),
    (7000, "airplay", "AirPlay"),
    (8000, "http", "Web app (port 8000)"),
    (8008, "http", "Web (port 8008)"),
    (8009, "googlecast", "Google Cast"),
    (8080, "http", "Web app (port 8080)"),
    (8123, "http", "Home Assistant"),
    (8443, "https", "Web app (HTTPS, port 8443)"),
    (8888, "http", "Web app (port 8888)"),
    (9000, "http", "Web app (port 9000)"),
    (9090, "https", "Web console (port 9090)"),
    (9100, "printer", "Printer (raw / JetDirect)"),
    (32400, "plex", "Plex Media Server"),
    (49152, "upnp", "UPnP"),
    (62078, "companion", "iPhone / iPad sync"),
];

/// A service entry for an open port.
pub(crate) fn service_for(ip: Ipv4Addr, port: u16, kind: &str, label: &str, source: &str) -> Service {
    let url = match kind {
        "http" => Some(if port == 80 { format!("http://{ip}/") } else { format!("http://{ip}:{port}/") }),
        "https" => Some(if port == 443 { format!("https://{ip}/") } else { format!("https://{ip}:{port}/") }),
        "ipp" => Some(format!("http://{ip}:631/")),
        "plex" => Some(format!("http://{ip}:{port}/web")),
        _ => None,
    };
    Service { kind: kind.into(), label: label.into(), port, proto: "tcp".into(), source: source.into(), name: None, url, details: Vec::new() }
}

/// Ports tried on every address of a subnet first; the rest of [`PORTS`] only on addresses that
/// turned out to be alive (an open port, an ARP entry, or an mDNS/SSDP answer).
const QUICK_PORTS: &[u16] = &[22, 53, 80, 135, 139, 443, 445, 8009, 8080, 62078];

type Target = (Ipv4Addr, (u16, &'static str, &'static str));

/// Probe every (ip, port) target with bounded concurrency, recording open ports in the registry.
async fn probe_targets(targets: Vec<Target>, opts: &ScanOptions, cancel: &Arc<AtomicBool>, phase: &str, reg: &Arc<Registry>, source: &'static str) {
    let total = targets.len() as u32;
    let done = AtomicU32::new(0);
    let timeout = Duration::from_millis(opts.probe_timeout_ms.max(50));
    let step = (total / 100).max(1);
    futures::stream::iter(targets)
        .for_each_concurrent(opts.concurrency.max(1), |(ip, (port, kind, label))| {
            let done = &done;
            async move {
                if cancel.load(Ordering::Relaxed) {
                    return;
                }
                let addr = SocketAddr::from((ip, port));
                if let Ok(Ok(stream)) = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
                    drop(stream);
                    reg.update(ip, |h| {
                        h.add_service(service_for(ip, port, kind, label, source));
                        h.add_source(source);
                    });
                }
                let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                if d.is_multiple_of(step) || d == total {
                    reg.progress(phase, d, total);
                }
            }
        })
        .await;
}

fn targets(ips: &[Ipv4Addr], keep: impl Fn(u16) -> bool + Copy) -> Vec<Target> {
    ips.iter().flat_map(|&ip| PORTS.iter().filter(move |p| keep(p.0)).map(move |p| (ip, *p))).collect()
}

/// Sweep every address of every local subnet (narrowed to `opts.min_prefix`), in two phases:
/// a few common ports everywhere, then all of [`PORTS`] on the addresses that are alive.
pub(crate) async fn sweep(reg: Arc<Registry>, opts: &ScanOptions, cancel: Arc<AtomicBool>) {
    let mut ips: Vec<Ipv4Addr> = reg.nets.iter().flat_map(|n| n.sweep_hosts(opts.min_prefix)).collect();
    ips.sort();
    ips.dedup();
    reg.log(format!("Probing {} addresses on {} common ports", ips.len(), QUICK_PORTS.len()));
    probe_targets(targets(&ips, |p| QUICK_PORTS.contains(&p)), opts, &cancel, "ports", &reg, "tcp").await;
    if cancel.load(Ordering::Relaxed) {
        return;
    }
    // The first phase made the OS resolve every address, so the neighbour table now lists the live ones.
    let arp = tokio::task::spawn_blocking(crate::arp::read_table).await.unwrap_or_default();
    let mut live: Vec<Ipv4Addr> = reg.ips().into_iter().chain(arp.into_iter().map(|(ip, _)| ip)).filter(|ip| ips.binary_search(ip).is_ok()).collect();
    live.sort();
    live.dedup();
    reg.log(format!("{} live addresses: probing {} more ports each", live.len(), PORTS.len() - QUICK_PORTS.len()));
    probe_targets(targets(&live, |p| !QUICK_PORTS.contains(&p)), opts, &cancel, "ports", &reg, "tcp").await;
}

/// Port-probe an explicit list of hosts (e.g. tailnet peers) on all of [`PORTS`]. Every listed IP
/// becomes a host, even with no open port. Streams `ScanEvent::Host` through `emit` and returns the hosts.
pub async fn probe_hosts(ips: Vec<Ipv4Addr>, opts: &ScanOptions, cancel: Arc<AtomicBool>, emit: Emit) -> Vec<crate::Host> {
    let reg = Registry::new(Vec::new(), emit);
    probe_registry(&reg, &ips, opts, &cancel, "tcp", 1).await;
    reg.all()
}

/// Probe `ips` on all ports; with `passes > 1`, hosts that showed nothing are tried again
/// (slow or relayed paths often drop the first burst of connects).
pub(crate) async fn probe_registry(reg: &Arc<Registry>, ips: &[Ipv4Addr], opts: &ScanOptions, cancel: &Arc<AtomicBool>, source: &'static str, passes: u8) {
    for &ip in ips {
        reg.update(ip, |_| {});
    }
    let mut todo = ips.to_vec();
    for _ in 0..passes.max(1) {
        if todo.is_empty() || cancel.load(Ordering::Relaxed) {
            break;
        }
        probe_targets(targets(&todo, |_| true), opts, cancel, "ports", reg, source).await;
        let found = reg.all();
        todo.retain(|ip| found.iter().any(|h| h.ip == ip.to_string() && h.services.is_empty()));
    }
}
