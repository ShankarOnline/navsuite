//! Ping and traceroute on top of the native ICMP engines, with a fallback to
//! the system tools.

use crate::{Emit, ProbeEvent, cancelled, done, line, resolve, reverse, sleep_cancel, system};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

#[cfg(unix)]
use crate::unix::Pinger;
#[cfg(windows)]
use crate::win::Pinger;

/// Outcome of a single echo request.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Echo {
    Reply { from: Ipv4Addr, rtt: f64, ttl: Option<u8> },
    Exceeded { from: Ipv4Addr, rtt: f64 },
    Unreachable { from: Ipv4Addr, rtt: f64 },
    Timeout,
}

#[cfg(any(unix, windows))]
fn open_native() -> std::io::Result<Arc<Pinger>> {
    Pinger::open().map(Arc::new)
}

#[cfg(any(unix, windows))]
async fn echo(p: &Arc<Pinger>, dst: Ipv4Addr, ttl: u8, seq: u16, timeout: Duration) -> Result<Echo, String> {
    let p = p.clone();
    let r3 = |v: f64| (v * 1000.0).round() / 1000.0;
    let e = tokio::task::spawn_blocking(move || p.echo(dst, ttl, seq, timeout))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    Ok(match e {
        Echo::Reply { from, rtt, ttl } => Echo::Reply { from, rtt: r3(rtt), ttl },
        Echo::Exceeded { from, rtt } => Echo::Exceeded { from, rtt: r3(rtt) },
        Echo::Unreachable { from, rtt } => Echo::Unreachable { from, rtt: r3(rtt) },
        Echo::Timeout => Echo::Timeout,
    })
}

fn fmt_ms(v: f64) -> String {
    if v < 10.0 { format!("{v:.2}") } else { format!("{v:.1}") }
}

pub(crate) fn ping_summary(sent: u32, rtts: &[f64]) -> (bool, String) {
    let recv = rtts.len() as u32;
    let loss = if sent == 0 { 0.0 } else { 100.0 * f64::from(sent - recv) / f64::from(sent) };
    let mut s = format!("{sent} sent, {recv} received, {loss:.0}% loss");
    if !rtts.is_empty() {
        let min = rtts.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = rtts.iter().cloned().fold(0.0, f64::max);
        let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;
        s.push_str(&format!(", rtt min/avg/max = {}/{}/{} ms", fmt_ms(min), fmt_ms(avg), fmt_ms(max)));
    }
    (recv > 0, s)
}

pub(crate) async fn ping(target: &str, count: u32, cancel: &Arc<AtomicBool>, emit: &Emit) -> ProbeEvent {
    let ip = match resolve(target).await {
        Ok(ip) => ip,
        Err(e) => return done(false, e),
    };
    line(emit, format!("PING {target} ({ip})"));
    let IpAddr::V4(v4) = ip else {
        return system::ping(ip, count, cancel, emit).await;
    };
    let pinger = match open_native() {
        Ok(p) => p,
        Err(e) => {
            line(emit, format!("native ICMP unavailable ({e}); using system ping"));
            return system::ping(ip, count, cancel, emit).await;
        }
    };
    let mut rtts = Vec::new();
    let mut sent = 0;
    for seq in 0..count {
        if cancelled(cancel) {
            break;
        }
        let t0 = Instant::now();
        sent += 1;
        let ev = match echo(&pinger, v4, 64, seq as u16, Duration::from_secs(2)).await {
            Ok(Echo::Reply { from, rtt, ttl }) => {
                rtts.push(rtt);
                ProbeEvent::Reply { seq, addr: from.to_string(), rtt_ms: Some(rtt), ttl }
            }
            Ok(Echo::Unreachable { from, .. }) => {
                line(emit, format!("seq {seq}: destination unreachable (from {from})"));
                ProbeEvent::Reply { seq, addr: from.to_string(), rtt_ms: None, ttl: None }
            }
            Ok(Echo::Exceeded { from, .. }) => {
                line(emit, format!("seq {seq}: TTL exceeded (from {from})"));
                ProbeEvent::Reply { seq, addr: from.to_string(), rtt_ms: None, ttl: None }
            }
            Ok(Echo::Timeout) => ProbeEvent::Reply { seq, addr: v4.to_string(), rtt_ms: None, ttl: None },
            Err(e) => return done(false, format!("ping failed: {e}")),
        };
        emit(ev);
        if seq + 1 < count && sleep_cancel(Duration::from_secs(1).saturating_sub(t0.elapsed()), cancel).await {
            break;
        }
    }
    let (ok, mut s) = ping_summary(sent, &rtts);
    if cancelled(cancel) {
        s.push_str(" (cancelled)");
    }
    done(ok, s)
}

pub(crate) async fn traceroute(target: &str, max_hops: u8, cancel: &Arc<AtomicBool>, emit: &Emit) -> ProbeEvent {
    let ip = match resolve(target).await {
        Ok(ip) => ip,
        Err(e) => return done(false, e),
    };
    line(emit, format!("traceroute to {target} ({ip}), {max_hops} hops max"));
    let IpAddr::V4(v4) = ip else {
        return system::traceroute(ip, max_hops, cancel, emit).await;
    };
    let pinger = match open_native() {
        Ok(p) => p,
        Err(e) => {
            line(emit, format!("native ICMP unavailable ({e}); using system traceroute"));
            return system::traceroute(ip, max_hops, cancel, emit).await;
        }
    };
    let mut seq: u16 = 1000;
    for ttl in 1..=max_hops {
        if cancelled(cancel) {
            return done(false, format!("cancelled after {} hops", ttl - 1));
        }
        let mut rtts = Vec::new();
        let mut addr: Option<Ipv4Addr> = None;
        let mut reached = false;
        let mut unreachable = false;
        for _ in 0..3 {
            if cancelled(cancel) {
                break;
            }
            seq = seq.wrapping_add(1);
            match echo(&pinger, v4, ttl, seq, Duration::from_millis(1500)).await {
                Ok(Echo::Reply { from, rtt, .. }) => {
                    reached = true;
                    addr.get_or_insert(from);
                    rtts.push(Some(rtt));
                }
                Ok(Echo::Exceeded { from, rtt }) => {
                    addr.get_or_insert(from);
                    rtts.push(Some(rtt));
                }
                Ok(Echo::Unreachable { from, rtt }) => {
                    unreachable = true;
                    addr.get_or_insert(from);
                    rtts.push(Some(rtt));
                }
                Ok(Echo::Timeout) => rtts.push(None),
                Err(e) => return done(false, format!("traceroute failed: {e}")),
            }
        }
        let name = match addr {
            Some(a) => reverse(IpAddr::V4(a), Duration::from_millis(800)).await,
            None => None,
        };
        emit(ProbeEvent::Hop {
            n: ttl,
            addr: addr.map(|a| a.to_string()),
            name,
            rtt_ms: rtts,
        });
        if reached {
            return done(true, format!("reached {ip} in {ttl} hops"));
        }
        if unreachable {
            return done(false, format!("destination unreachable at hop {ttl}"));
        }
    }
    done(false, format!("{ip} not reached within {max_hops} hops"))
}
