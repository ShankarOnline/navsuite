//! Run a full discovery on this machine and print what was found.
//!
//! `cargo run -p netscan --example scan --release`

use netscan::{Emit, ScanEvent, ScanOptions};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

#[tokio::main]
async fn main() {
    let started = Instant::now();
    let cancel = Arc::new(AtomicBool::new(false));
    let events = Arc::new(AtomicUsize::new(0));
    let ev = events.clone();
    let emit: Emit = Arc::new(move |e: ScanEvent| {
        ev.fetch_add(1, Ordering::Relaxed);
        match e {
            ScanEvent::Started { subnets } => println!("scanning: {}", subnets.join(", ")),
            ScanEvent::Log { message } => println!("  .. {message}"),
            ScanEvent::Done { hosts, millis, cancelled } => println!("LAN scan done: {hosts} hosts in {millis} ms (cancelled: {cancelled})"),
            _ => {}
        }
    });
    let opts = ScanOptions::default();

    let ssh = tokio::task::spawn_blocking(netscan::ssh_hosts);
    // Tailnet first, then the LAN: run together, the LAN sweep's burst of connects starves the
    // (often relayed) tailnet connects and they time out.
    let t = Instant::now();
    let tail = netscan::scan_tailnet(opts.clone(), cancel.clone(), emit.clone()).await;
    let tail_time = t.elapsed();
    let lan = netscan::scan(opts.clone(), cancel.clone(), emit.clone()).await;
    let ssh = ssh.await.unwrap_or_default();

    println!("\n== LAN hosts ({}) ==", lan.len());
    for h in &lan {
        let svcs: Vec<String> = h.services.iter().map(|s| format!("{}:{}", s.kind, s.port)).collect();
        println!(
            "{:<15} {:<17} {:<8} {:<28} [{}] via {}",
            h.ip,
            h.mac.as_deref().unwrap_or("-"),
            h.kind,
            h.display_name(),
            svcs.join(" "),
            h.sources.join("+")
        );
    }

    let (status, tail_hosts) = match tail {
        Ok((s, hosts)) => {
            println!("\n== Tailnet ({}, {} peers, {} online, probed in {:.1}s) ==", s.backend_state, s.peers.len(), s.peers.iter().filter(|p| p.online).count(), tail_time.as_secs_f32());
            for p in &s.peers {
                println!("{:<24} {:<16} {:<8} online={} {}", p.host_name, p.ipv4().map(|i| i.to_string()).unwrap_or_default(), p.os, p.online, p.last_seen.as_deref().unwrap_or(""));
            }
            (Some(s), hosts)
        }
        Err(e) => {
            println!("\n== Tailnet: {e}");
            (None, Vec::new())
        }
    };

    for h in &tail_hosts {
        let svcs: Vec<String> = h.services.iter().map(|s| format!("{}:{}", s.kind, s.port)).collect();
        println!("  probed {:<16} {:<40} [{}]", h.ip, h.hostname.as_deref().unwrap_or("-"), svcs.join(" "));
    }

    println!("\n== SSH hosts ({}) ==", ssh.len());
    for s in &ssh {
        println!("{:<24} {:<24} user={:<8} port={:?} ({})", s.alias, s.host_name, s.user.as_deref().unwrap_or("-"), s.port, s.source);
    }

    let records = netscan::merge(&lan, &tail_hosts, status.as_ref(), &ssh);
    println!("\n== Systems ({}) ==", records.len());
    for r in &records {
        let ch: Vec<String> = r.channels.iter().map(|c| c.kind.clone()).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
        println!("{:<28} {:<8} online={:<5} id={:<24} ips={} channels={}", r.name, r.kind, r.online, r.id, r.ips.join(","), ch.join(","));
    }
    println!("\n{} events, total {:.1}s", events.load(Ordering::Relaxed), started.elapsed().as_secs_f32());
}
