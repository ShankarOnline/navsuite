//! Manual probe runner: `cargo run -p probe --example probe_cli -- <target> <ping N|trace N|port P|dns|http [url]>`
use probe::{ProbeKind, run};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let target = a.first().cloned().unwrap_or_else(|| "127.0.0.1".into());
    let arg = |i: usize| a.get(i).cloned();
    let kind = match a.get(1).map(String::as_str).unwrap_or("ping") {
        "trace" => ProbeKind::Traceroute { max_hops: arg(2).and_then(|v| v.parse().ok()).unwrap_or(8) },
        "port" => ProbeKind::Port { port: arg(2).and_then(|v| v.parse().ok()).unwrap_or(80) },
        "dns" => ProbeKind::Dns,
        "http" => ProbeKind::Http { url: arg(2) },
        _ => ProbeKind::Ping { count: arg(2).and_then(|v| v.parse().ok()).unwrap_or(4) },
    };
    let emit = Arc::new(|e| println!("{}", serde_json::to_string(&e).unwrap()));
    run(&target, kind, Arc::new(AtomicBool::new(false)), emit).await;
}
