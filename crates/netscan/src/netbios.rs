//! NetBIOS node-status (NBSTAT) queries on UDP 137: Windows/Samba machine names and workgroups.

use crate::Registry;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::Instant;

/// Build an NBSTAT request for the wildcard name `*`.
pub(crate) fn nbstat_request(id: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(50);
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    p.push(0x20);
    let mut name = [0u8; 16];
    name[0] = b'*';
    for b in name {
        p.push(b'A' + (b >> 4));
        p.push(b'A' + (b & 0x0f));
    }
    p.push(0x00);
    p.extend_from_slice(&[0x00, 0x21, 0x00, 0x01]); // NBSTAT, IN
    p
}

#[derive(Debug, PartialEq, Default)]
pub(crate) struct NodeStatus {
    /// (name, suffix, is_group)
    pub names: Vec<(String, u8, bool)>,
    pub mac: Option<String>,
}

impl NodeStatus {
    /// The machine name: unique name with suffix 0x00 (workstation service), else 0x20 (server).
    pub fn machine_name(&self) -> Option<String> {
        let find = |suffix| self.names.iter().find(|(_, s, g)| *s == suffix && !*g).map(|(n, ..)| n.clone());
        find(0x00).or_else(|| find(0x20))
    }

    /// The workgroup/domain: group name with suffix 0x00.
    pub fn workgroup(&self) -> Option<String> {
        self.names.iter().find(|(n, s, g)| *s == 0x00 && *g && !n.starts_with("\u{1}\u{2}__MSBROWSE__")).map(|(n, ..)| n.clone())
    }
}

/// Parse an NBSTAT response packet.
pub(crate) fn parse_response(p: &[u8]) -> Option<NodeStatus> {
    if p.len() < 12 || p[2] & 0x80 == 0 {
        return None; // not a response
    }
    let ancount = u16::from_be_bytes([p[6], p[7]]);
    if ancount == 0 {
        return None;
    }
    // Skip the answer name (labels or a compression pointer).
    let mut i = 12;
    loop {
        let len = *p.get(i)? as usize;
        if len == 0 {
            i += 1;
            break;
        }
        if len & 0xc0 == 0xc0 {
            i += 2;
            break;
        }
        i += 1 + len;
    }
    let rtype = u16::from_be_bytes([*p.get(i)?, *p.get(i + 1)?]);
    if rtype != 0x21 {
        return None;
    }
    i += 2 + 2 + 4 + 2; // type, class, ttl, rdlength
    let count = *p.get(i)? as usize;
    i += 1;
    let mut st = NodeStatus::default();
    for _ in 0..count {
        let e = p.get(i..i + 18)?;
        let name = String::from_utf8_lossy(&e[..15]).trim_end_matches([' ', '\0']).to_string();
        let group = e[16] & 0x80 != 0;
        st.names.push((name, e[15], group));
        i += 18;
    }
    if let Some(m) = p.get(i..i + 6) {
        st.mac = crate::arp::normalize_mac(&format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5]));
    }
    Some(st)
}

/// Query every IP (twice, to ride out packet loss), listening ~2 s for answers.
pub(crate) async fn query_all(reg: Arc<Registry>, ips: &[Ipv4Addr], cancel: Arc<AtomicBool>) {
    if ips.is_empty() {
        return;
    }
    let Ok(sock) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await else { return };
    let wanted: HashMap<Ipv4Addr, u16> = ips.iter().enumerate().map(|(i, ip)| (*ip, i as u16)).collect();
    let mut answered: HashMap<Ipv4Addr, NodeStatus> = HashMap::new();
    let mut buf = vec![0u8; 2048];
    for round in 0..2 {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        for (ip, id) in &wanted {
            if !answered.contains_key(ip) {
                let _ = sock.send_to(&nbstat_request(*id), SocketAddr::from((*ip, 137))).await;
            }
        }
        let deadline = Instant::now() + Duration::from_millis(if round == 0 { 1200 } else { 800 });
        while let Ok(r) = tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await {
            let Ok((n, SocketAddr::V4(from))) = r else { continue };
            if wanted.contains_key(from.ip())
                && let Some(st) = parse_response(&buf[..n])
            {
                answered.insert(*from.ip(), st);
            }
        }
    }
    let total = answered.len() as u32;
    for (done, (ip, st)) in answered.into_iter().enumerate() {
        reg.update(ip, |h| {
            if let Some(n) = st.machine_name() {
                h.netbios_name = Some(n);
            }
            if h.workgroup.is_none() {
                h.workgroup = st.workgroup();
            }
            if h.mac.is_none() {
                h.mac = st.mac.clone();
            }
            h.add_source("netbios");
        });
        reg.progress("netbios", done as u32 + 1, total);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_layout() {
        let r = nbstat_request(0x1234);
        assert_eq!(r.len(), 50);
        assert_eq!(&r[..2], &[0x12, 0x34]);
        assert_eq!(&r[12..15], b"\x20CK");
        assert_eq!(&r[46..], &[0x00, 0x21, 0x00, 0x01]);
    }

    fn entry(name: &str, suffix: u8, group: bool) -> Vec<u8> {
        let mut e = format!("{name:<15}").into_bytes();
        e.push(suffix);
        e.extend_from_slice(&[if group { 0x84 } else { 0x04 }, 0x00]);
        e
    }

    #[test]
    fn parse_node_status() {
        let mut p = vec![0x12, 0x34, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        p.extend_from_slice(&nbstat_request(0)[12..46]); // the name
        p.extend_from_slice(&[0x00, 0x21, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x00]);
        let entries = [entry("DESKTOP-AB12", 0x00, false), entry("WORKGROUP", 0x00, true), entry("DESKTOP-AB12", 0x20, false), entry("WORKGROUP", 0x1e, true)];
        p.push(entries.len() as u8);
        for e in &entries {
            p.extend_from_slice(e);
        }
        p.extend_from_slice(&[0x98, 0xba, 0x5f, 0x37, 0x6f, 0xf0]);
        let st = parse_response(&p).unwrap();
        assert_eq!(st.names.len(), 4);
        assert_eq!(st.machine_name().as_deref(), Some("DESKTOP-AB12"));
        assert_eq!(st.workgroup().as_deref(), Some("WORKGROUP"));
        assert_eq!(st.mac.as_deref(), Some("98:ba:5f:37:6f:f0"));
        // Truncated packets are rejected, not panicked on.
        assert!(parse_response(&p[..60]).is_none());
        assert!(parse_response(&p[..5]).is_none());
    }
}
