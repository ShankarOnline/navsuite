//! Parsers for the text output of system `ping` / `traceroute` / `tracert`
//! (Windows, macOS, Linux iputils / traceroute), used by the fallback path.

use std::net::IpAddr;

/// One parsed ping output line.
#[derive(Debug, Clone, PartialEq)]
pub enum PingLine {
    Reply {
        seq: Option<u32>,
        addr: String,
        rtt_ms: Option<f64>,
        ttl: Option<u8>,
    },
    Timeout,
}

/// Value after `key` (case-insensitive) up to whitespace, e.g. `ttl=64` -> "64".
fn kv<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let lower = line.to_ascii_lowercase();
    let idx = lower.find(key)?;
    let rest = &line[idx + key.len()..];
    let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
    Some(&rest[..end])
}

fn parse_ms(v: &str) -> Option<f64> {
    let v = v.trim_end_matches("ms").trim();
    if let Some(lt) = v.strip_prefix('<') {
        // "<1ms": report half of the bound.
        return lt.parse::<f64>().ok().map(|x| x / 2.0);
    }
    v.parse().ok()
}

fn clean_addr(a: &str) -> String {
    let a = a.trim().trim_end_matches(':');
    // "host (1.2.3.4)" -> "1.2.3.4"
    if let (Some(o), Some(c)) = (a.find('('), a.rfind(')'))
        && o < c
    {
        return a[o + 1..c].to_string();
    }
    a.trim_matches(|c| c == '[' || c == ']').to_string()
}

pub fn parse_ping_line(line: &str) -> Option<PingLine> {
    let l = line.trim();
    let lower = l.to_ascii_lowercase();
    if lower.starts_with("request timed out") || lower.starts_with("request timeout") || lower.contains("destination host unreachable") {
        return Some(PingLine::Timeout);
    }
    // Windows: "Reply from 127.0.0.1: bytes=32 time<1ms TTL=128"
    if let Some(rest) = l.strip_prefix("Reply from ") {
        let colon = rest.find(": ")?;
        let addr = clean_addr(&rest[..colon]);
        let rtt = kv(rest, "time=").or_else(|| kv(rest, "time")).and_then(parse_ms);
        let ttl = kv(rest, "ttl=").and_then(|v| v.parse().ok());
        if rtt.is_none() {
            // "Reply from x: Destination host unreachable."
            return Some(PingLine::Timeout);
        }
        return Some(PingLine::Reply { seq: None, addr, rtt_ms: rtt, ttl });
    }
    // Unix: "64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.045 ms"
    if let Some(i) = l.find(" bytes from ") {
        let rest = &l[i + " bytes from ".len()..];
        let colon = rest.find(": ")?;
        let addr = clean_addr(&rest[..colon]);
        let seq = kv(rest, "icmp_seq=").or_else(|| kv(rest, "seq=")).and_then(|v| v.parse().ok());
        let ttl = kv(rest, "ttl=").or_else(|| kv(rest, "hlim=")).and_then(|v| v.parse().ok());
        let rtt = kv(rest, "time=").and_then(parse_ms);
        return Some(PingLine::Reply { seq, addr, rtt_ms: rtt, ttl });
    }
    None
}

/// One parsed traceroute hop line.
#[derive(Debug, Clone, PartialEq)]
pub struct HopLine {
    pub n: u8,
    pub addr: Option<String>,
    pub rtt_ms: Vec<Option<f64>>,
}

/// Parses Unix `traceroute -n` and Windows `tracert -d` hop lines:
/// ` 1  192.168.1.1  0.512 ms  0.480 ms  0.470 ms`
/// ` 2  * * *`
/// `  1    <1 ms    <1 ms    <1 ms  192.168.1.1`
/// `  3     *        *        *     Request timed out.`
pub fn parse_trace_line(line: &str) -> Option<HopLine> {
    let toks: Vec<&str> = line.split_whitespace().collect();
    let n: u8 = toks.first()?.parse().ok()?;
    let mut addr = None;
    let mut rtts = Vec::new();
    let mut i = 1;
    while i < toks.len() {
        let t = toks[i];
        if t == "*" {
            rtts.push(None);
        } else if let Some(v) = t.strip_suffix("ms").filter(|v| !v.is_empty()).and_then(parse_ms) {
            rtts.push(Some(v)); // "12ms"
        } else if toks.get(i + 1) == Some(&"ms") {
            if let Some(v) = parse_ms(t) {
                rtts.push(Some(v));
                i += 1;
            }
        } else {
            let cand = t.trim_matches(|c| c == '(' || c == ')' || c == '[' || c == ']');
            if addr.is_none() && cand.parse::<IpAddr>().is_ok() {
                addr = Some(cand.to_string());
            }
        }
        i += 1;
    }
    if rtts.is_empty() && addr.is_none() {
        return None;
    }
    Some(HopLine { n, addr, rtt_ms: rtts })
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIN_PING: &str = "\r
Pinging 127.0.0.1 with 32 bytes of data:\r
Reply from 127.0.0.1: bytes=32 time<1ms TTL=128\r
Reply from 192.168.1.1: bytes=32 time=12ms TTL=64\r
Request timed out.\r
Reply from 192.168.1.50: Destination host unreachable.\r
\r
Ping statistics for 127.0.0.1:\r
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),\r
";

    const MAC_PING: &str = "PING 1.1.1.1 (1.1.1.1): 56 data bytes
64 bytes from 1.1.1.1: icmp_seq=0 ttl=57 time=11.874 ms
64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.115 ms
Request timeout for icmp_seq 2

--- 1.1.1.1 ping statistics ---
3 packets transmitted, 2 packets received, 33.3% packet loss
round-trip min/avg/max/stddev = 11.874/11.994/12.115/0.121 ms";

    const LINUX_PING: &str = "PING one.one.one.one (1.1.1.1) 56(84) bytes of data.
64 bytes from one.one.one.one (1.1.1.1): icmp_seq=1 ttl=57 time=10.9 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time=11.2 ms
64 bytes from ::1: icmp_seq=3 ttl=64 time=0.031 ms

--- one.one.one.one ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms";

    fn all(s: &str) -> Vec<PingLine> {
        s.lines().filter_map(parse_ping_line).collect()
    }

    #[test]
    fn windows_ping() {
        let v = all(WIN_PING);
        assert_eq!(v.len(), 4);
        assert_eq!(
            v[0],
            PingLine::Reply { seq: None, addr: "127.0.0.1".into(), rtt_ms: Some(0.5), ttl: Some(128) }
        );
        assert_eq!(
            v[1],
            PingLine::Reply { seq: None, addr: "192.168.1.1".into(), rtt_ms: Some(12.0), ttl: Some(64) }
        );
        assert_eq!(v[2], PingLine::Timeout);
        assert_eq!(v[3], PingLine::Timeout);
    }

    #[test]
    fn mac_ping() {
        let v = all(MAC_PING);
        assert_eq!(v.len(), 3);
        assert_eq!(v[2], PingLine::Timeout);
        assert_eq!(
            v[1],
            PingLine::Reply { seq: Some(1), addr: "1.1.1.1".into(), rtt_ms: Some(12.115), ttl: Some(57) }
        );
    }

    #[test]
    fn linux_ping() {
        let v = all(LINUX_PING);
        assert_eq!(v.len(), 3);
        assert_eq!(
            v[0],
            PingLine::Reply { seq: Some(1), addr: "1.1.1.1".into(), rtt_ms: Some(10.9), ttl: Some(57) }
        );
        if let PingLine::Reply { addr, .. } = &v[2] {
            assert_eq!(addr, "::1");
        } else {
            panic!()
        }
    }

    const WIN_TRACE: &str = "
Tracing route to 1.1.1.1 over a maximum of 8 hops

  1    <1 ms    <1 ms    <1 ms  192.168.1.1
  2     8 ms     7 ms     9 ms  100.64.0.1
  3     *        *        *     Request timed out.
  4    12 ms     *       11 ms  1.1.1.1

Trace complete.";

    const LINUX_TRACE: &str = "traceroute to 1.1.1.1 (1.1.1.1), 8 hops max, 60 byte packets
 1  192.168.1.1  0.512 ms  0.480 ms  0.470 ms
 2  * * *
 3  10.0.0.1  1.204 ms * 10.0.0.9  1.311 ms
 4  1.1.1.1  10.1 ms !H  10.2 ms  10.3 ms";

    const MAC_TRACE: &str = "traceroute to 1.1.1.1 (1.1.1.1), 8 hops max, 52 byte packets
 1  192.168.0.1  2.381 ms  1.950 ms  1.874 ms
 2  * 10.20.0.1  9.112 ms  8.876 ms";

    fn hops(s: &str) -> Vec<HopLine> {
        s.lines().filter_map(parse_trace_line).collect()
    }

    #[test]
    fn windows_tracert() {
        let h = hops(WIN_TRACE);
        assert_eq!(h.len(), 4);
        assert_eq!(h[0], HopLine { n: 1, addr: Some("192.168.1.1".into()), rtt_ms: vec![Some(0.5); 3] });
        assert_eq!(h[2], HopLine { n: 3, addr: None, rtt_ms: vec![None; 3] });
        assert_eq!(h[3].rtt_ms, vec![Some(12.0), None, Some(11.0)]);
        assert_eq!(h[3].addr.as_deref(), Some("1.1.1.1"));
    }

    #[test]
    fn linux_traceroute() {
        let h = hops(LINUX_TRACE);
        assert_eq!(h.len(), 4);
        assert_eq!(h[0].rtt_ms, vec![Some(0.512), Some(0.48), Some(0.47)]);
        assert_eq!(h[1], HopLine { n: 2, addr: None, rtt_ms: vec![None; 3] });
        assert_eq!(h[2].addr.as_deref(), Some("10.0.0.1"));
        assert_eq!(h[2].rtt_ms, vec![Some(1.204), None, Some(1.311)]);
        assert_eq!(h[3].rtt_ms.len(), 3);
    }

    #[test]
    fn mac_traceroute() {
        let h = hops(MAC_TRACE);
        assert_eq!(h.len(), 2);
        assert_eq!(h[1].addr.as_deref(), Some("10.20.0.1"));
        assert_eq!(h[1].rtt_ms, vec![None, Some(9.112), Some(8.876)]);
    }
}
