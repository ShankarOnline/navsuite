//! probe: network probes for the details pane (feature E6).
//!
//! `run` executes one probe (ping, traceroute, TCP port check, DNS lookup or
//! HTTP fetch) against a host, streaming [`ProbeEvent`]s through `emit` and
//! returning the final [`ProbeEvent::Done`].
//!
//! Ping and traceroute use native ICMP without admin rights:
//! * Windows: `IcmpCreateFile` / `IcmpSendEcho2` (iphlpapi).
//! * macOS / Linux: unprivileged ICMP datagram sockets (`SOCK_DGRAM` +
//!   `IPPROTO_ICMP`). If the socket cannot be opened (e.g. Linux with a
//!   restrictive `net.ipv4.ping_group_range`) the system `ping` /
//!   `traceroute` binaries are used and their output parsed.
//!
//! IPv6 targets always use the system tools.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

mod dns;
mod http;
pub mod icmp;
mod ping;
pub mod parse;
mod system;
mod tcp;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod win;

/// Which probe to run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum ProbeKind {
    Ping { count: u32 },
    Traceroute { max_hops: u8 },
    Port { port: u16 },
    Dns,
    Http { url: Option<String> },
}

/// Streamed probe output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum ProbeEvent {
    /// Free-form text line (headers, raw tool output, banners, ...).
    Line { text: String },
    /// One echo reply; `rtt_ms == None` means the request timed out.
    Reply {
        seq: u32,
        addr: String,
        rtt_ms: Option<f64>,
        ttl: Option<u8>,
    },
    /// One traceroute hop; one `rtt_ms` entry per probe (`None` = `*`).
    Hop {
        n: u8,
        addr: Option<String>,
        name: Option<String>,
        rtt_ms: Vec<Option<f64>>,
    },
    /// Final event; also the return value of [`run`].
    Done { ok: bool, summary: String },
}

pub type Emit = Arc<dyn Fn(ProbeEvent) + Send + Sync>;

pub(crate) fn done(ok: bool, summary: impl Into<String>) -> ProbeEvent {
    ProbeEvent::Done {
        ok,
        summary: summary.into(),
    }
}

pub(crate) fn line(emit: &Emit, text: impl Into<String>) {
    emit(ProbeEvent::Line { text: text.into() });
}

/// Run a probe. Every event (including the final `Done`) is passed to `emit`;
/// the `Done` event is also returned. Setting `cancel` stops the probe at the
/// next reply / hop boundary.
pub async fn run(
    target: &str,
    kind: ProbeKind,
    cancel: Arc<AtomicBool>,
    emit: Arc<dyn Fn(ProbeEvent) + Send + Sync>,
) -> ProbeEvent {
    let target = target.trim().to_string();
    let result = if target.is_empty() {
        done(false, "no target given")
    } else {
        match kind {
            ProbeKind::Ping { count } => ping::ping(&target, count.clamp(1, 1000), &cancel, &emit).await,
            ProbeKind::Traceroute { max_hops } => {
                ping::traceroute(&target, max_hops.clamp(1, 64), &cancel, &emit).await
            }
            ProbeKind::Port { port } => tcp::port(&target, port, &cancel, &emit).await,
            ProbeKind::Dns => dns::dns(&target, &emit).await,
            ProbeKind::Http { url } => http::http(&target, url, &cancel, &emit).await,
        }
    };
    emit(result.clone());
    result
}

/// Strip brackets from IPv6 literals ("[fe80::1]") and any trailing port-less junk.
pub(crate) fn host_part(target: &str) -> &str {
    let t = target.trim();
    t.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(t)
}

/// Resolve a host name to addresses (IPv4 first). Runs in a blocking thread.
pub(crate) async fn resolve_all(target: &str) -> Result<Vec<IpAddr>, String> {
    let host = host_part(target).to_string();
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let h = host.clone();
    let res = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking(move || dns_lookup::lookup_host(&h).map(|i| i.collect::<Vec<_>>())),
    )
    .await;
    let mut ips = match res {
        Err(_) => return Err(format!("resolving {host} timed out")),
        Ok(Err(e)) => return Err(format!("resolver task failed: {e}")),
        Ok(Ok(Err(e))) => return Err(format!("cannot resolve {host}: {e:?}")),
        Ok(Ok(Ok(v))) => v,
    };
    let mut seen = Vec::new();
    ips.retain(|ip| {
        if seen.contains(ip) {
            false
        } else {
            seen.push(*ip);
            true
        }
    });
    ips.sort_by_key(|ip| !ip.is_ipv4());
    if ips.is_empty() {
        return Err(format!("{host} has no addresses"));
    }
    Ok(ips)
}

pub(crate) async fn resolve(target: &str) -> Result<IpAddr, String> {
    resolve_all(target).await.map(|v| v[0])
}

/// Reverse lookup with a timeout; `None` if no PTR record (or it timed out).
pub(crate) async fn reverse(ip: IpAddr, timeout: Duration) -> Option<String> {
    let r = tokio::time::timeout(
        timeout,
        tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip)),
    )
    .await;
    match r {
        Ok(Ok(Ok(name))) if name != ip.to_string() && !name.is_empty() => Some(name),
        _ => None,
    }
}

/// Sleep for `d`, waking early if `cancel` is set. Returns true if cancelled.
pub(crate) async fn sleep_cancel(d: Duration, cancel: &AtomicBool) -> bool {
    let step = Duration::from_millis(50);
    let mut left = d;
    while !left.is_zero() {
        if cancel.load(Ordering::Relaxed) {
            return true;
        }
        let s = left.min(step);
        tokio::time::sleep(s).await;
        left = left.saturating_sub(s);
    }
    cancel.load(Ordering::Relaxed)
}

pub(crate) fn cancelled(cancel: &AtomicBool) -> bool {
    cancel.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_shapes() {
        let k: ProbeKind = serde_json::from_str(r#"{"kind":"traceroute","maxHops":8}"#).unwrap();
        assert_eq!(k, ProbeKind::Traceroute { max_hops: 8 });
        let e = ProbeEvent::Reply {
            seq: 1,
            addr: "1.2.3.4".into(),
            rtt_ms: Some(1.5),
            ttl: Some(64),
        };
        let s = serde_json::to_string(&e).unwrap();
        assert_eq!(s, r#"{"type":"reply","seq":1,"addr":"1.2.3.4","rttMs":1.5,"ttl":64}"#);
    }

    #[test]
    fn host_part_strips_brackets() {
        assert_eq!(host_part("[::1]"), "::1");
        assert_eq!(host_part(" example.com "), "example.com");
    }
}
