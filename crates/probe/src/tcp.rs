//! TCP port check with banner grab.

use crate::{Emit, ProbeEvent, cancelled, done, line, resolve};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// Printable rendering of a banner: first line, control chars dropped, capped.
pub(crate) fn clean_banner(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    let first = s.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    let mut out: String = first.chars().filter(|c| !c.is_control()).take(200).collect();
    out = out.trim().to_string();
    out
}

pub(crate) async fn port(target: &str, port: u16, cancel: &Arc<AtomicBool>, emit: &Emit) -> ProbeEvent {
    let ip = match resolve(target).await {
        Ok(ip) => ip,
        Err(e) => return done(false, e),
    };
    let addr = SocketAddr::new(ip, port);
    line(emit, format!("connecting to {addr} ..."));
    let t0 = Instant::now();
    let res = tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(addr)).await;
    let ms = t0.elapsed().as_secs_f64() * 1000.0;
    let mut stream = match res {
        Err(_) => return done(false, format!("port {port} filtered (no response in 3 s)")),
        Ok(Err(e)) if e.kind() == ErrorKind::ConnectionRefused => {
            return done(false, format!("port {port} closed (connection refused, {ms:.1} ms)"));
        }
        Ok(Err(e)) => return done(false, format!("port {port} filtered/unreachable: {e}")),
        Ok(Ok(s)) => s,
    };
    line(emit, format!("port {port} open, connected in {ms:.1} ms"));
    if cancelled(cancel) {
        return done(true, format!("port {port} open"));
    }
    let mut buf = vec![0u8; 1024];
    let banner = match tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => Some(clean_banner(&buf[..n])),
        _ => None,
    };
    match banner.filter(|b| !b.is_empty()) {
        Some(b) => {
            line(emit, format!("banner: {b}"));
            done(true, format!("port {port} open ({ms:.1} ms) - {b}"))
        }
        None => done(true, format!("port {port} open ({ms:.1} ms), no banner")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_cleanup() {
        assert_eq!(clean_banner(b"SSH-2.0-OpenSSH_9.6\r\n"), "SSH-2.0-OpenSSH_9.6");
        assert_eq!(clean_banner(b"\r\n220 ftp ready\x07\r\nmore"), "220 ftp ready");
    }

    #[tokio::test]
    async fn open_and_closed_ports() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let (mut s, _) = l.accept().await.unwrap();
            s.write_all(b"220 hello\r\n").await.unwrap();
        });
        let emit: Emit = Arc::new(|_| {});
        let c = Arc::new(AtomicBool::new(false));
        match port("127.0.0.1", p, &c, &emit).await {
            ProbeEvent::Done { ok, summary } => {
                assert!(ok);
                assert!(summary.contains("220 hello"), "{summary}");
            }
            e => panic!("{e:?}"),
        }
        // Port 1 on loopback is almost certainly closed.
        match port("127.0.0.1", 1, &c, &emit).await {
            ProbeEvent::Done { ok, .. } => assert!(!ok),
            e => panic!("{e:?}"),
        }
    }
}
