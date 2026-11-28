//! HTTP(S) GET probe: status, Server header, page title, timing.

use crate::{Emit, ProbeEvent, cancelled, done, host_part, line};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

const MAX_BODY: usize = 512 * 1024;

/// Decode the handful of entities that commonly appear in titles.
fn decode_entities(s: &str) -> String {
    let mut out = s
        .replace("&amp;", "\u{0}AMP\u{0}")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ");
    out = out.replace("\u{0}AMP\u{0}", "&");
    out
}

/// Extract `<title>` text from HTML (case-insensitive, attributes allowed,
/// whitespace collapsed, basic entities decoded).
pub fn extract_title(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let mut from = 0;
    let start = loop {
        let i = lower[from..].find("<title")? + from;
        let after = lower.as_bytes().get(i + 6).copied();
        // Reject e.g. "<titlebar>".
        if matches!(after, Some(b'>') | Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'\r')) {
            break i;
        }
        from = i + 6;
    };
    let open_end = lower[start..].find('>')? + start + 1;
    let close = lower[open_end..].find("</title").map(|i| i + open_end).unwrap_or(lower.len());
    let raw = &html[open_end..close];
    let collapsed = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let t = decode_entities(&collapsed);
    let t = t.trim();
    if t.is_empty() { None } else { Some(t.chars().take(300).collect()) }
}

fn urls_for(target: &str, url: Option<String>) -> Vec<String> {
    if let Some(u) = url.filter(|u| !u.trim().is_empty()) {
        let u = u.trim().to_string();
        return if u.contains("://") { vec![u] } else { vec![format!("http://{u}"), format!("https://{u}")] };
    }
    if target.contains("://") {
        return vec![target.to_string()];
    }
    let h = host_part(target);
    let h = if h.contains(':') && h.parse::<std::net::Ipv6Addr>().is_ok() { format!("[{h}]") } else { h.to_string() };
    vec![format!("http://{h}/"), format!("https://{h}/")]
}

pub(crate) async fn http(target: &str, url: Option<String>, cancel: &Arc<AtomicBool>, emit: &Emit) -> ProbeEvent {
    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(4))
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent(concat!("narada-probe/", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(c) => c,
        Err(e) => return done(false, format!("http client: {e}")),
    };
    let candidates = urls_for(target, url);
    let mut last_err = String::new();
    for (i, u) in candidates.iter().enumerate() {
        if cancelled(cancel) {
            return done(false, "cancelled");
        }
        line(emit, format!("GET {u}"));
        let t0 = Instant::now();
        let mut resp = match client.get(u).send().await {
            Ok(r) => r,
            Err(e) => {
                last_err = format!("{u}: {e}");
                line(emit, format!("failed: {e}"));
                // Only fall through to https when the connection itself failed.
                if e.is_connect() && i + 1 < candidates.len() {
                    continue;
                }
                return done(false, last_err);
            }
        };
        let head_ms = t0.elapsed().as_secs_f64() * 1000.0;
        let status = resp.status();
        let final_url = resp.url().to_string();
        let server = resp
            .headers()
            .get(reqwest::header::SERVER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let ctype = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        line(emit, format!("HTTP {} ({head_ms:.0} ms)", status));
        if final_url != *u {
            line(emit, format!("redirected to {final_url}"));
        }
        if let Some(s) = &server {
            line(emit, format!("Server: {s}"));
        }
        if !ctype.is_empty() {
            line(emit, format!("Content-Type: {ctype}"));
        }
        let mut body = Vec::new();
        while body.len() < MAX_BODY && !cancelled(cancel) {
            match resp.chunk().await {
                Ok(Some(c)) => body.extend_from_slice(&c),
                _ => break,
            }
        }
        let total_ms = t0.elapsed().as_secs_f64() * 1000.0;
        let title = extract_title(&String::from_utf8_lossy(&body));
        if let Some(t) = &title {
            line(emit, format!("Title: {t}"));
        }
        let mut summary = format!("{} {}", status.as_u16(), status.canonical_reason().unwrap_or(""));
        summary = summary.trim().to_string();
        if let Some(t) = &title {
            summary.push_str(&format!(" - \"{t}\""));
        }
        if let Some(s) = &server {
            summary.push_str(&format!(" [{s}]"));
        }
        summary.push_str(&format!(" in {total_ms:.0} ms"));
        return done(status.is_success() || status.is_redirection(), summary);
    }
    done(false, last_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn titles() {
        assert_eq!(extract_title("<html><head><TITLE>Router  Login</TITLE>").as_deref(), Some("Router Login"));
        assert_eq!(
            extract_title("<title id=\"t\">\n  A &amp; B &lt;admin&gt;\n</title>").as_deref(),
            Some("A & B <admin>")
        );
        assert_eq!(extract_title("<titlebar>x</titlebar><title>Real</title>").as_deref(), Some("Real"));
        assert_eq!(extract_title("<title></title>"), None);
        assert_eq!(extract_title("no title here"), None);
        assert_eq!(extract_title("<title>unterminated").as_deref(), Some("unterminated"));
    }

    #[test]
    fn url_candidates() {
        assert_eq!(urls_for("10.0.0.1", None), vec!["http://10.0.0.1/", "https://10.0.0.1/"]);
        assert_eq!(urls_for("fe80::1", None)[0], "http://[fe80::1]/");
        assert_eq!(urls_for("x", Some("https://x:8443/a".into())), vec!["https://x:8443/a"]);
    }
}
