//! Local IPv4 networks worth scanning.

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// One IPv4 address of a local interface, with the subnet it is on.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LocalNet {
    /// Interface display name (friendly name on Windows).
    pub iface: String,
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub gateway: Option<Ipv4Addr>,
    pub mac: Option<String>,
    pub gateway_mac: Option<String>,
}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 { 0 } else { u32::MAX << (32 - prefix.min(32) as u32) }
}

impl LocalNet {
    /// Whether `ip` is on this subnet.
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let m = mask(self.prefix);
        u32::from(ip) & m == u32::from(self.ip) & m
    }

    /// Host addresses to sweep: the subnet, narrowed to at most `/min_prefix` around our own address
    /// (so a /16 is swept as the /24 we are in). Network and broadcast addresses are excluded.
    pub fn sweep_hosts(&self, min_prefix: u8) -> Vec<Ipv4Addr> {
        let prefix = self.prefix.max(min_prefix.clamp(16, 30));
        if prefix > 30 {
            return Vec::new();
        }
        let m = mask(prefix);
        let net = u32::from(self.ip) & m;
        let bcast = net | !m;
        (net + 1..bcast).map(Ipv4Addr::from).collect()
    }
}

/// Words in interface names/descriptions that mark virtual adapters (hypervisors, containers, VPNs).
const VIRTUAL_HINTS: &[&str] = &[
    "virtual", "vethernet", "hyper-v", "vmware", "vbox", "virtualbox", "wsl", "docker", "veth", "virbr", "br-",
    "tailscale", "wireguard", "zerotier", "openvpn", "tap-windows", "utun", "npcap", "loopback", "vmnet",
];

/// Active, non-loopback IPv4 networks. Virtual adapters (and Tailscale/CGNAT 100.64/10 addresses) are
/// left out unless `include_virtual` is set. Blocking but fast.
pub fn local_networks(include_virtual: bool) -> Vec<LocalNet> {
    let mut out = Vec::new();
    for i in netdev::get_interfaces() {
        if i.is_loopback() || !i.is_up() || i.ipv4.is_empty() {
            continue;
        }
        let names = format!("{} {} {}", i.name, i.friendly_name.as_deref().unwrap_or(""), i.description.as_deref().unwrap_or("")).to_lowercase();
        let is_virtual = !i.is_physical() || i.is_tun() || VIRTUAL_HINTS.iter().any(|h| names.contains(h));
        if is_virtual && !include_virtual {
            continue;
        }
        let mac = i.mac_addr.and_then(|m| crate::arp::normalize_mac(&m.address()));
        let (gateway, gateway_mac) = match &i.gateway {
            Some(g) => (g.ipv4.first().copied(), crate::arp::normalize_mac(&g.mac_addr.address())),
            None => (None, None),
        };
        for net in &i.ipv4 {
            let ip = net.addr();
            let cgnat = ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64;
            if ip.is_link_local() || ip.is_loopback() || (cgnat && !include_virtual) || net.prefix_len() > 30 {
                continue;
            }
            let ln = LocalNet {
                iface: i.friendly_name.clone().unwrap_or_else(|| i.name.clone()),
                ip,
                prefix: net.prefix_len(),
                gateway: None,
                mac: mac.clone(),
                gateway_mac: None,
            };
            let gw = gateway.filter(|g| ln.contains(*g));
            out.push(LocalNet { gateway: gw, gateway_mac: gw.and(gateway_mac.clone()), ..ln });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(ip: &str, prefix: u8) -> LocalNet {
        LocalNet { iface: "eth0".into(), ip: ip.parse().unwrap(), prefix, gateway: None, mac: None, gateway_mac: None }
    }

    #[test]
    fn contains_and_sweep() {
        let n = net("192.168.1.37", 24);
        assert!(n.contains("192.168.1.200".parse().unwrap()));
        assert!(!n.contains("192.168.2.1".parse().unwrap()));
        let h = n.sweep_hosts(24);
        assert_eq!(h.len(), 254);
        assert_eq!(h[0], Ipv4Addr::new(192, 168, 1, 1));
        // A /16 is narrowed to our /24.
        let big = net("10.1.5.9", 16);
        let h = big.sweep_hosts(24);
        assert_eq!((h.len(), h[0]), (254, Ipv4Addr::new(10, 1, 5, 1)));
        assert_eq!(net("10.0.0.1", 0).sweep_hosts(24).len(), 254);
        assert!(net("10.0.0.1", 31).sweep_hosts(24).is_empty());
    }
}
