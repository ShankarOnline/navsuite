//! Fallback: run the system `ping` / `traceroute` / `tracert` and translate
//! their output into probe events. Used for IPv6 targets and when the native
//! ICMP socket cannot be opened.

use crate::parse::{PingLine, parse_ping_line, parse_trace_line};
use crate::ping::ping_summary;
use crate::{Emit, ProbeEvent, cancelled, done, line, reverse};
use std::net::IpAddr;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

fn command(prog: &str) -> Command {
    let mut c = Command::new(prog);
    c.stdout(Stdio::piped()).stderr(Stdio::piped()).stdin(Stdio::null()).kill_on_drop(true);
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        c.creation_flags(CREATE_NO_WINDOW);
    }
    // Force untranslated output where the tool honours the locale.
    c.env("LC_ALL", "C");
    c
}

fn ping_cmd(ip: IpAddr, count: u32) -> Command {
    let n = count.to_string();
    let s = ip.to_string();
    if cfg!(windows) {
        let mut c = command("ping");
        c.args(["-n", &n, "-w", "2000"]);
        if ip.is_ipv6() {
            c.arg("-6");
        }
        c.arg(&s);
        c
    } else if cfg!(target_os = "macos") && ip.is_ipv6() {
        let mut c = command("ping6");
        c.args(["-c", &n, &s]);
        c
    } else {
        let mut c = command("ping");
        c.args(["-c", &n, &s]);
        c
    }
}

fn trace_cmd(ip: IpAddr, max_hops: u8) -> Command {
    let m = max_hops.to_string();
    let s = ip.to_string();
    if cfg!(windows) {
        let mut c = command("tracert");
        c.args(["-d", "-w", "1500", "-h", &m]);
        if ip.is_ipv6() {
            c.arg("-6");
        }
        c.arg(&s);
        c
    } else if cfg!(target_os = "macos") && ip.is_ipv6() {
        let mut c = command("traceroute6");
        c.args(["-n", "-m", &m, &s]);
        c
    } else {
        let mut c = command("traceroute");
        c.args(["-n", "-q", "3", "-w", "2", "-m", &m, &s]);
        c
    }
}

struct Running {
    child: tokio::process::Child,
    lines: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
}

impl Running {
    fn spawn(mut cmd: Command) -> Result<Self, String> {
        let mut child = cmd.spawn().map_err(|e| e.to_string())?;
        let stdout = child.stdout.take().ok_or("no stdout")?;
        Ok(Self { child, lines: BufReader::new(stdout).lines() })
    }

    /// Next stdout line; `None` at EOF or when cancelled (child is killed).
    async fn next(&mut self, cancel: &AtomicBool) -> Option<String> {
        loop {
            if cancelled(cancel) {
                let _ = self.child.kill().await;
                return None;
            }
            match tokio::time::timeout(Duration::from_millis(200), self.lines.next_line()).await {
                Err(_) => continue,
                Ok(Ok(Some(l))) => return Some(l),
                Ok(Ok(None)) | Ok(Err(_)) => {
                    let _ = self.child.wait().await;
                    return None;
                }
            }
        }
    }
}

pub(crate) async fn ping(ip: IpAddr, count: u32, cancel: &Arc<AtomicBool>, emit: &Emit) -> ProbeEvent {
    let mut run = match Running::spawn(ping_cmd(ip, count)) {
        Ok(r) => r,
        Err(e) => return done(false, format!("system ping unavailable: {e}")),
    };
    let mut rtts = Vec::new();
    let mut seq = 0u32;
    let mut sent = 0u32;
    while let Some(l) = run.next(cancel).await {
        if !l.trim().is_empty() {
            line(emit, l.trim_end());
        }
        match parse_ping_line(&l) {
            Some(PingLine::Reply { seq: s, addr, rtt_ms, ttl }) => {
                let s = s.unwrap_or(seq);
                seq = s + 1;
                sent += 1;
                if let Some(r) = rtt_ms {
                    rtts.push(r);
                }
                emit(ProbeEvent::Reply { seq: s, addr, rtt_ms, ttl });
            }
            Some(PingLine::Timeout) => {
                emit(ProbeEvent::Reply { seq, addr: ip.to_string(), rtt_ms: None, ttl: None });
                seq += 1;
                sent += 1;
            }
            None => {}
        }
    }
    // Unix ping does not print every lost packet; count them from the request.
    let sent = if cancelled(cancel) { sent } else { sent.max(count) };
    let (ok, mut s) = ping_summary(sent, &rtts);
    if cancelled(cancel) {
        s.push_str(" (cancelled)");
    }
    done(ok, s)
}

pub(crate) async fn traceroute(ip: IpAddr, max_hops: u8, cancel: &Arc<AtomicBool>, emit: &Emit) -> ProbeEvent {
    let mut run = match Running::spawn(trace_cmd(ip, max_hops)) {
        Ok(r) => r,
        Err(e) => return done(false, format!("system traceroute unavailable: {e}")),
    };
    let target = ip.to_string();
    let mut last = 0u8;
    let mut reached = false;
    while let Some(l) = run.next(cancel).await {
        let Some(h) = parse_trace_line(&l) else {
            if !l.trim().is_empty() {
                line(emit, l.trim_end());
            }
            continue;
        };
        let name = match h.addr.as_deref().and_then(|a| a.parse().ok()) {
            Some(a) => reverse(a, Duration::from_millis(800)).await,
            None => None,
        };
        last = h.n;
        reached |= h.addr.as_deref() == Some(target.as_str());
        emit(ProbeEvent::Hop { n: h.n, addr: h.addr, name, rtt_ms: h.rtt_ms });
    }
    if reached {
        done(true, format!("reached {ip} in {last} hops"))
    } else if cancelled(cancel) {
        done(false, format!("cancelled after {last} hops"))
    } else {
        done(false, format!("{ip} not reached within {max_hops} hops"))
    }
}
