//! The OS neighbour (ARP) table: IPv4 address -> MAC for hosts we have talked to recently.
//!
//! Windows: GetIpNetTable2 (native). Linux: /proc/net/arp. macOS/BSD: `arp -an`.

use std::net::Ipv4Addr;

/// Read the neighbour table. Incomplete, broadcast and multicast entries are skipped.
/// Blocking: call from `spawn_blocking`.
pub(crate) fn read_table() -> Vec<(Ipv4Addr, String)> {
    let mut v = platform_table();
    v.retain(|(ip, _)| !ip.is_multicast() && !ip.is_broadcast() && !ip.is_unspecified() && !ip.is_loopback());
    v.sort();
    v.dedup();
    v
}

#[cfg(windows)]
fn platform_table() -> Vec<(Ipv4Addr, String)> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIpNetTable2, MIB_IPNET_TABLE2};
    use windows_sys::Win32::Networking::WinSock::{AF_INET, NlnsIncomplete, NlnsUnreachable};

    let mut out = Vec::new();
    let mut table: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();
    // SAFETY: GetIpNetTable2 allocates the table; we only read NumEntries rows and free it with FreeMibTable.
    unsafe {
        if GetIpNetTable2(AF_INET, &mut table) != 0 || table.is_null() {
            return out;
        }
        let n = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), n);
        for row in rows {
            if row.State == NlnsIncomplete || row.State == NlnsUnreachable || row.PhysicalAddressLength != 6 {
                continue;
            }
            if row.Address.si_family != AF_INET {
                continue;
            }
            let ip = Ipv4Addr::from(row.Address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes());
            let p = &row.PhysicalAddress;
            let mac = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", p[0], p[1], p[2], p[3], p[4], p[5]);
            if let Some(mac) = normalize_mac(&mac) {
                out.push((ip, mac));
            }
        }
        FreeMibTable(table as *const _);
    }
    out
}

#[cfg(target_os = "linux")]
fn platform_table() -> Vec<(Ipv4Addr, String)> {
    std::fs::read_to_string("/proc/net/arp").map(|t| parse_proc_arp(&t)).unwrap_or_default()
}

#[cfg(all(unix, not(target_os = "linux")))]
fn platform_table() -> Vec<(Ipv4Addr, String)> {
    let arp = ["/usr/sbin/arp", "/sbin/arp"].into_iter().map(std::path::Path::new).find(|p| p.exists());
    let Some(arp) = arp else { return Vec::new() };
    match crate::cmd::run_blocking(arp, &["-an"], std::time::Duration::from_secs(5)) {
        Ok(out) => parse_arp_an(&String::from_utf8_lossy(&out.stdout)),
        Err(_) => Vec::new(),
    }
}

#[cfg(not(any(windows, unix)))]
fn platform_table() -> Vec<(Ipv4Addr, String)> {
    Vec::new()
}

/// Normalise a MAC to `aa:bb:cc:dd:ee:ff`. Accepts `:` or `-` separators and 1-digit octets
/// (macOS prints `0:1a:2b:...`). Returns None for zero, broadcast and multicast addresses.
pub(crate) fn normalize_mac(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.trim().split([':', '-']).collect();
    if parts.len() != 6 {
        return None;
    }
    let mut b = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || p.len() > 2 {
            return None;
        }
        b[i] = u8::from_str_radix(p, 16).ok()?;
    }
    if b == [0; 6] || b == [0xff; 6] || b[0] & 1 == 1 {
        return None;
    }
    Some(format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", b[0], b[1], b[2], b[3], b[4], b[5]))
}

/// Parse Linux `/proc/net/arp`:
/// `IP address  HW type  Flags  HW address  Mask  Device`. Flags 0x0 = incomplete.
#[allow(dead_code)]
pub(crate) fn parse_proc_arp(text: &str) -> Vec<(Ipv4Addr, String)> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 4 || f[2] == "0x0" {
                return None;
            }
            Some((f[0].parse().ok()?, normalize_mac(f[3])?))
        })
        .collect()
}

/// Parse BSD/macOS `arp -an`: `? (192.168.1.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]`.
#[allow(dead_code)]
pub(crate) fn parse_arp_an(text: &str) -> Vec<(Ipv4Addr, String)> {
    text.lines()
        .filter_map(|l| {
            let open = l.find('(')?;
            let close = l[open..].find(')')? + open;
            let ip: Ipv4Addr = l[open + 1..close].parse().ok()?;
            let rest = l[close..].strip_prefix(") at ")?;
            let mac = rest.split_whitespace().next()?;
            Some((ip, normalize_mac(mac)?))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_normalisation() {
        assert_eq!(normalize_mac("98-BA-5F-37-6F-F0").as_deref(), Some("98:ba:5f:37:6f:f0"));
        assert_eq!(normalize_mac("0:1a:2b:3:4:5").as_deref(), Some("00:1a:2b:03:04:05"));
        assert_eq!(normalize_mac("ff:ff:ff:ff:ff:ff"), None);
        assert_eq!(normalize_mac("01:00:5e:00:00:fb"), None);
        assert_eq!(normalize_mac("00:00:00:00:00:00"), None);
        assert_eq!(normalize_mac("(incomplete)"), None);
    }

    #[test]
    fn proc_net_arp() {
        let t = "IP address       HW type     Flags       HW address            Mask     Device\n\
                 192.168.1.1      0x1         0x2         a4:2b:b0:11:22:33     *        eth0\n\
                 192.168.1.50     0x1         0x0         00:00:00:00:00:00     *        eth0\n\
                 192.168.1.60     0x1         0x2         dc:a6:32:aa:bb:cc     *        wlan0\n";
        let v = parse_proc_arp(t);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0], ("192.168.1.1".parse().unwrap(), "a4:2b:b0:11:22:33".into()));
        assert_eq!(v[1].1, "dc:a6:32:aa:bb:cc");
    }

    #[test]
    fn bsd_arp_an() {
        let t = "? (192.168.1.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]\n\
                 ? (192.168.1.7) at (incomplete) on en0 ifscope [ethernet]\n\
                 ? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n\
                 ? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]\n\
                 nas.lan (192.168.1.20) at 0:11:32:ab:cd:ef on en0 ifscope [ethernet]\n";
        let v = parse_arp_an(t);
        assert_eq!(v, vec![
            ("192.168.1.1".parse().unwrap(), "00:11:22:33:44:55".to_string()),
            ("192.168.1.20".parse().unwrap(), "00:11:32:ab:cd:ef".to_string()),
        ]);
    }
}
