//! SSDP / UPnP discovery: M-SEARCH, then fetch each device description for its names.

use crate::{Registry, Service};
use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::Instant;

const MSEARCH: &str = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n";
const MAX_BODY: usize = 256 * 1024;

#[derive(Default)]
struct Seen {
    locations: Vec<String>,
    server: Option<String>,
}

pub(crate) async fn discover(reg: Arc<Registry>, secs: u64, cancel: Arc<AtomicBool>) {
    let deadline = Instant::now() + Duration::from_secs(secs.max(1));
    let found: Arc<Mutex<BTreeMap<Ipv4Addr, Seen>>> = Arc::default();
    // One socket per local address so every interface gets the multicast query.
    let mut binds: Vec<Ipv4Addr> = reg.nets.iter().map(|n| n.ip).collect();
    if binds.is_empty() {
        binds.push(Ipv4Addr::UNSPECIFIED);
    }
    let mut tasks = Vec::new();
    for bind in binds {
        let found = found.clone();
        let cancel = cancel.clone();
        tasks.push(tokio::spawn(async move {
            let Ok(sock) = UdpSocket::bind((bind, 0)).await else { return };
            let _ = sock.set_multicast_ttl_v4(2);
            let dest: SocketAddr = ([239, 255, 255, 250], 1900).into();
            for _ in 0..2 {
                let _ = sock.send_to(MSEARCH.as_bytes(), dest).await;
            }
            let mut buf = vec![0u8; 4096];
            while !cancel.load(Ordering::Relaxed) {
                match tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await {
                    Ok(Ok((n, SocketAddr::V4(from)))) => {
                        let h = parse_headers(&String::from_utf8_lossy(&buf[..n]));
                        let mut f = found.lock().unwrap();
                        let e = f.entry(*from.ip()).or_default();
                        if let Some(loc) = h.get("location")
                            && !e.locations.contains(loc)
                            && e.locations.len() < 4
                        {
                            e.locations.push(loc.clone());
                        }
                        if e.server.is_none() {
                            e.server = h.get("server").cloned();
                        }
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }));
    }
    for t in tasks {
        let _ = t.await;
    }
    let found = std::mem::take(&mut *found.lock().unwrap());
    let total = found.len() as u32;
    let mut fetches = Vec::new();
    for (ip, seen) in found {
        if !reg.nets.is_empty() && reg.net_for(ip).is_none() {
            continue;
        }
        let reg = reg.clone();
        fetches.push(tokio::spawn(async move {
            reg.update(ip, |h| h.add_source("ssdp"));
            for loc in &seen.locations {
                // Only fetch descriptions served by the device that answered.
                let Some((host, port, _)) = split_url(loc) else { continue };
                if host != ip.to_string() {
                    continue;
                }
                let Some(xml) = http_get(loc, Duration::from_secs(3)).await else { continue };
                let d = parse_description(&xml);
                reg.update(ip, |h| {
                    if h.device_name.is_none() {
                        h.device_name = d.friendly_name.clone();
                    }
                    if h.manufacturer.is_none() {
                        h.manufacturer = d.manufacturer.clone();
                    }
                    if h.model.is_none() {
                        h.model = d.model_name.clone();
                    }
                    let mut details = vec![("location".to_string(), loc.clone())];
                    if let Some(t) = &d.device_type {
                        details.push(("deviceType".into(), t.clone()));
                    }
                    if let Some(s) = &seen.server {
                        details.push(("server".into(), s.clone()));
                    }
                    let media = d.device_type.as_deref().is_some_and(|t| t.contains("MediaRenderer") || t.contains("MediaServer"));
                    h.add_service(Service {
                        kind: if media { "dlna" } else { "upnp" }.into(),
                        label: if media { "Media device (DLNA)" } else { "UPnP device" }.into(),
                        port,
                        proto: "tcp".into(),
                        source: "ssdp".into(),
                        name: d.friendly_name.clone(),
                        url: d.presentation_url.as_ref().map(|p| absolute(loc, p)),
                        details,
                    });
                });
            }
        }));
    }
    let mut done = 0;
    for f in fetches {
        let _ = f.await;
        done += 1;
        reg.progress("ssdp", done, total);
    }
}

/// Parse SSDP/HTTP response headers into lowercase-keyed map (first line skipped).
pub(crate) fn parse_headers(text: &str) -> HashMap<String, String> {
    text.lines()
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect()
}

#[derive(Default, Debug, PartialEq)]
pub(crate) struct Description {
    pub friendly_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model_name: Option<String>,
    pub device_type: Option<String>,
    pub presentation_url: Option<String>,
}

pub(crate) fn parse_description(xml: &str) -> Description {
    Description {
        friendly_name: xml_tag(xml, "friendlyName"),
        manufacturer: xml_tag(xml, "manufacturer"),
        model_name: xml_tag(xml, "modelName"),
        device_type: xml_tag(xml, "deviceType"),
        presentation_url: xml_tag(xml, "presentationURL"),
    }
}

/// Text of the first `<tag>` (ignoring attributes), entity-decoded and trimmed.
pub(crate) fn xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}");
    let mut from = 0;
    while let Some(i) = xml[from..].find(&open) {
        let start = from + i + open.len();
        let after = xml[start..].chars().next()?;
        if after == '>' || after.is_whitespace() {
            let body_start = start + xml[start..].find('>')? + 1;
            let end = body_start + xml[body_start..].find(&format!("</{tag}>"))?;
            let v = unescape(xml[body_start..end].trim());
            return (!v.is_empty()).then_some(v);
        }
        from = start;
    }
    None
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&#39;", "'").replace("&amp;", "&")
}

/// Split `http://host[:port]/path` into (host, port, path).
pub(crate) fn split_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("http://")?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().ok()?),
        None => (hostport, 80),
    };
    Some((host.to_string(), port, path))
}

fn absolute(base: &str, p: &str) -> String {
    if p.starts_with("http://") || p.starts_with("https://") {
        return p.to_string();
    }
    match split_url(base) {
        Some((h, port, _)) => format!("http://{h}:{port}/{}", p.trim_start_matches('/')),
        None => p.to_string(),
    }
}

/// Minimal HTTP/1.1 GET (plain http only), enough for UPnP description documents.
pub(crate) async fn http_get(url: &str, timeout: Duration) -> Option<String> {
    let (host, port, path) = split_url(url)?;
    let fut = async {
        let mut s = TcpStream::connect((host.as_str(), port)).await.ok()?;
        let req = format!("GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\nUser-Agent: navsuite/0.1 UPnP/1.1\r\nAccept: */*\r\n\r\n");
        s.write_all(req.as_bytes()).await.ok()?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let n = s.read(&mut chunk).await.ok()?;
            if n == 0 || buf.len() > MAX_BODY {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        parse_http_response(&buf)
    };
    tokio::time::timeout(timeout, fut).await.ok().flatten()
}

/// Split an HTTP response into its body (decoding chunked transfer encoding). Only 2xx bodies.
pub(crate) fn parse_http_response(buf: &[u8]) -> Option<String> {
    let split = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&buf[..split]);
    let status = head.lines().next()?.split_whitespace().nth(1)?;
    if !status.starts_with('2') {
        return None;
    }
    let body = &buf[split + 4..];
    let chunked = parse_headers(&head).get("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    let body = if chunked { dechunk(body) } else { body.to_vec() };
    Some(String::from_utf8_lossy(&body).into_owned())
}

fn dechunk(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(eol) = b.windows(2).position(|w| w == b"\r\n") {
        let size_txt = String::from_utf8_lossy(&b[..eol]);
        let Ok(size) = usize::from_str_radix(size_txt.split(';').next().unwrap_or("").trim(), 16) else { break };
        b = &b[eol + 2..];
        if size == 0 || size > b.len() {
            out.extend_from_slice(&b[..size.min(b.len())]);
            break;
        }
        out.extend_from_slice(&b[..size]);
        b = b.get(size + 2..).unwrap_or(&[]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers() {
        let r = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://192.168.1.1:49152/rootDesc.xml\r\nSERVER: Linux/5.4 UPnP/1.0 MiniUPnPd/2.2\r\nST: upnp:rootdevice\r\n\r\n";
        let h = parse_headers(r);
        assert_eq!(h["location"], "http://192.168.1.1:49152/rootDesc.xml");
        assert_eq!(h["server"], "Linux/5.4 UPnP/1.0 MiniUPnPd/2.2");
        assert_eq!(split_url(&h["location"]), Some(("192.168.1.1".into(), 49152, "/rootDesc.xml".into())));
        assert_eq!(split_url("http://10.0.0.2"), Some(("10.0.0.2".into(), 80, "/".into())));
    }

    #[test]
    fn description_xml() {
        let x = r#"<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>
            <deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
            <friendlyName>Living Room TV &amp; Sound</friendlyName>
            <manufacturer>Samsung Electronics</manufacturer>
            <manufacturerURL>http://www.samsung.com</manufacturerURL>
            <modelName lang="en">QE55Q80</modelName>
            <presentationURL>/index.html</presentationURL>
            <deviceList><device><friendlyName>inner</friendlyName></device></deviceList>
            </device></root>"#;
        let d = parse_description(x);
        assert_eq!(d.friendly_name.as_deref(), Some("Living Room TV & Sound"));
        assert_eq!(d.manufacturer.as_deref(), Some("Samsung Electronics"));
        assert_eq!(d.model_name.as_deref(), Some("QE55Q80"));
        assert!(d.device_type.unwrap().contains("MediaRenderer"));
        assert_eq!(absolute("http://10.0.0.5:8080/desc.xml", "/index.html"), "http://10.0.0.5:8080/index.html");
        assert_eq!(xml_tag("<a><b>x</b></a>", "c"), None);
    }

    #[test]
    fn http_bodies() {
        let r = b"HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\n\r\n<root/>";
        assert_eq!(parse_http_response(r).as_deref(), Some("<root/>"));
        let c = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n<roo\r\n3\r\nt/>\r\n0\r\n\r\n";
        assert_eq!(parse_http_response(c).as_deref(), Some("<root/>"));
        assert_eq!(parse_http_response(b"HTTP/1.1 404 Not Found\r\n\r\nnope"), None);
    }
}
