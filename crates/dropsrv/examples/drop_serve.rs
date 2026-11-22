//! Manual test server: `cargo run -p dropsrv --example drop_serve -- <data_dir> [port] [cert.pem key.pem]`
//! Prints the join URL / code and writes the QR code to <data_dir>/join-qr.svg.
use dropsrv::{DropConfig, DropServer};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let mut a = std::env::args().skip(1);
    let data_dir = a.next().unwrap_or_else(|| "drop-data".into()).into();
    let port = a.next().and_then(|p| p.parse().ok()).unwrap_or(8765);
    let tls = match (a.next(), a.next()) {
        (Some(c), Some(k)) => Some(dropsrv::TlsFiles { cert_pem: c.into(), key_pem: k.into() }),
        _ => None,
    };
    let cfg = DropConfig { port, data_dir, device_name: "Dev PC".into(), tls, ..Default::default() };
    let dd = cfg.data_dir.clone();
    let srv = DropServer::start(cfg, Arc::new(|e| println!("event: {}", serde_json::to_string(&e).unwrap())))
        .await
        .expect("start");
    let urls = srv.local_urls();
    println!("listening on port {}; urls: {urls:?}", srv.port());
    let host = urls.first().cloned().unwrap_or_else(|| format!("127.0.0.1:{}", srv.port()));
    let t = srv.new_join_ticket(&host);
    std::fs::write(dd.join("join-qr.svg"), &t.qr_svg).unwrap();
    println!("join: {} (code {})", t.url, t.code);
    let local = srv.new_join_ticket("127.0.0.1");
    println!("local join: {}", local.url);
    tokio::signal::ctrl_c().await.ok();
    srv.stop().await;
}
