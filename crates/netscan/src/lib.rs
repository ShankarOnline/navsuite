//! netscan: discovers the systems on the local network and the services they offer.
//!
//! One scan combines several sources, because no single one sees everything:
//! - the OS neighbour (ARP) table,
//! - a TCP connect sweep of well-known service ports across each local subnet,
//! - mDNS / DNS-SD (Bonjour) browsing,
//! - SSDP / UPnP discovery (with the device description fetched for names),
//! - NetBIOS name queries (Windows names and workgroups),
//! - reverse DNS.
//!
//! Results stream out as [`ScanEvent`]s so a UI can show hosts as they appear.
//! [`tailnet`] adds Tailscale peers, [`sshcfg`] the hosts in `~/.ssh`, and [`records::merge`]
//! folds all of it into one [`SystemRecord`] per machine.

mod arp;
mod cmd;
mod iface;
mod launch;
mod mdns;
mod model;
mod netbios;
mod probe;
pub mod records;
mod shares;
pub mod sshcfg;
mod ssdp;
pub mod tailnet;

pub use iface::{LocalNet, local_networks};
pub use launch::{launch_service, open_target, reveal, service_target};
pub use model::*;
pub use probe::{PORTS, probe_hosts};
pub use records::{Channel, NameSource, SystemRecord, merge};
pub use shares::list_shares;
pub use sshcfg::{SshHost, ssh_hosts};
pub use tailnet::{TailPeer, TailnetStatus, probe_tailnet, scan_tailnet, tailnet_status};

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub type Emit = Arc<dyn Fn(ScanEvent) + Send + Sync>;

/// Shared, thread-safe view of what the scan has found so far.
pub(crate) struct Registry {
    hosts: Mutex<BTreeMap<Ipv4Addr, Host>>,
    nets: Vec<LocalNet>,
    emit: Emit,
}

impl Registry {
    fn new(nets: Vec<LocalNet>, emit: Emit) -> Arc<Self> {
        Arc::new(Self { hosts: Mutex::new(BTreeMap::new()), nets, emit })
    }

    /// Apply a change to a host (creating it if new) and stream the result.
    pub(crate) fn update(&self, ip: Ipv4Addr, f: impl FnOnce(&mut Host)) {
        if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() || ip.is_loopback() {
            return;
        }
        let snapshot = {
            let mut hosts = self.hosts.lock().unwrap();
            let host = hosts.entry(ip).or_insert_with(|| Host {
                ip: ip.to_string(),
                interface: self.net_for(ip).map(|n| n.iface.clone()),
                kind: "device".into(),
                ..Default::default()
            });
            f(host);
            host.classify();
            host.clone()
        };
        (self.emit)(ScanEvent::Host { host: Box::new(snapshot) });
    }

    pub(crate) fn net_for(&self, ip: Ipv4Addr) -> Option<&LocalNet> {
        self.nets.iter().find(|n| n.contains(ip))
    }

    pub(crate) fn ips(&self) -> Vec<Ipv4Addr> {
        self.hosts.lock().unwrap().keys().copied().collect()
    }

    pub(crate) fn progress(&self, phase: &str, done: u32, total: u32) {
        (self.emit)(ScanEvent::Progress { phase: phase.into(), done, total });
    }

    pub(crate) fn log(&self, message: impl Into<String>) {
        (self.emit)(ScanEvent::Log { message: message.into() });
    }

    fn all(&self) -> Vec<Host> {
        self.hosts.lock().unwrap().values().cloned().collect()
    }
}

/// Run a full scan. `emit` receives events as hosts are found; the final host list is also returned.
pub async fn scan(opts: ScanOptions, cancel: Arc<AtomicBool>, emit: Emit) -> Vec<Host> {
    let started = Instant::now();
    let nets = local_networks(opts.include_virtual);
    emit(ScanEvent::Started { subnets: nets.iter().map(|n| format!("{}/{} ({})", n.ip, n.prefix, n.iface)).collect() });
    let reg = Registry::new(nets.clone(), emit.clone());
    if nets.is_empty() {
        reg.log("No active IPv4 network interface found.");
    }

    // This machine and its gateways.
    let me = dns_lookup::get_hostname().ok();
    for n in &nets {
        let me = me.clone();
        reg.update(n.ip, |h| {
            h.is_self = true;
            h.mac = h.mac.take().or(n.mac.clone());
            h.netbios_name = h.netbios_name.take().or(me.clone().map(|m| m.to_uppercase()));
            h.add_source("self");
        });
        if let Some(gw) = n.gateway {
            let gmac = n.gateway_mac.clone();
            reg.update(gw, |h| {
                h.is_gateway = true;
                h.mac = h.mac.take().or(gmac);
                h.add_source("route");
            });
        }
    }

    // What the OS already knows about neighbours.
    read_arp(&reg).await;

    // Active discovery, all at once.
    if !cancel.load(Ordering::Relaxed) {
        let mdns_reg = reg.clone();
        let mdns_cancel = cancel.clone();
        let mdns_secs = opts.mdns_secs;
        let mdns = tokio::spawn(async move { mdns::browse(mdns_reg, mdns_secs, mdns_cancel).await });
        let (_, _) = tokio::join!(probe::sweep(reg.clone(), &opts, cancel.clone()), ssdp::discover(reg.clone(), opts.ssdp_secs, cancel.clone()));
        let _ = mdns.await;
    }

    // Names for everything found.
    if !cancel.load(Ordering::Relaxed) {
        let ips = reg.ips();
        tokio::join!(netbios::query_all(reg.clone(), &ips, cancel.clone()), reverse_dns(reg.clone(), &ips));
        read_arp(&reg).await; // the sweep filled the ARP cache: pick up MACs
    }

    let hosts = reg.all();
    emit(ScanEvent::Done { hosts: hosts.len(), millis: started.elapsed().as_millis() as u64, cancelled: cancel.load(Ordering::Relaxed) });
    hosts
}

async fn read_arp(reg: &Arc<Registry>) {
    let entries = tokio::task::spawn_blocking(arp::read_table).await.unwrap_or_default();
    for (ip, mac) in entries {
        // Only neighbours on our own subnets: ARP tables also hold multicast and stale entries.
        if reg.net_for(ip).is_some() {
            reg.update(ip, |h| {
                h.mac = Some(mac.clone());
                h.add_source("arp");
            });
        }
    }
}

async fn reverse_dns(reg: Arc<Registry>, ips: &[Ipv4Addr]) {
    let total = ips.len() as u32;
    let mut tasks = Vec::new();
    for &ip in ips {
        tasks.push(tokio::spawn(async move {
            let lookup = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&IpAddr::V4(ip)).ok());
            let name = tokio::time::timeout(Duration::from_secs(3), lookup).await.ok().and_then(|r| r.ok()).flatten();
            (ip, name)
        }));
    }
    let mut done = 0;
    for t in tasks {
        if let Ok((ip, Some(name))) = t.await {
            // The resolver echoes the address back when it has no name.
            if name != ip.to_string() {
                reg.update(ip, |h| h.hostname = Some(name));
            }
        }
        done += 1;
        reg.progress("names", done, total);
    }
}
