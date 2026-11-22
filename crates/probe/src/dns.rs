//! Forward + reverse DNS lookups via the system resolver (dns-lookup).

use crate::{Emit, ProbeEvent, done, host_part, line, resolve_all, reverse};
use std::net::IpAddr;
use std::time::Duration;

pub(crate) async fn dns(target: &str, emit: &Emit) -> ProbeEvent {
    let host = host_part(target);
    if let Ok(ip) = host.parse::<IpAddr>() {
        line(emit, format!("reverse lookup {ip}"));
        return match reverse(ip, Duration::from_secs(5)).await {
            Some(name) => {
                line(emit, format!("PTR {name}"));
                // Confirm the forward record matches (forward-confirmed rDNS).
                if let Ok(ips) = resolve_all(&name).await {
                    let fwd = ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ");
                    line(emit, format!("{name} -> {fwd}"));
                }
                done(true, format!("{ip} is {name}"))
            }
            None => done(false, format!("{ip} has no PTR record")),
        };
    }
    line(emit, format!("forward lookup {host}"));
    let ips = match resolve_all(host).await {
        Ok(v) => v,
        Err(e) => return done(false, e),
    };
    for ip in &ips {
        let rr = if ip.is_ipv4() { "A" } else { "AAAA" };
        let ptr = reverse(*ip, Duration::from_secs(2)).await;
        match ptr {
            Some(p) => line(emit, format!("{rr} {ip}  (PTR {p})")),
            None => line(emit, format!("{rr} {ip}")),
        }
    }
    let list = ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ");
    done(true, format!("{host} -> {list}"))
}
