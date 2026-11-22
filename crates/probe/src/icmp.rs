//! ICMPv4 packet helpers (pure functions, used by the Unix datagram-socket
//! engine and covered by unit tests on every platform).

use std::net::Ipv4Addr;

pub const ECHO_REPLY: u8 = 0;
pub const DEST_UNREACHABLE: u8 = 3;
pub const ECHO_REQUEST: u8 = 8;
pub const TIME_EXCEEDED: u8 = 11;

/// RFC 1071 internet checksum.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (pairs, rest) = data.as_chunks::<2>();
    for c in pairs {
        sum += u32::from(u16::from_be_bytes(*c));
    }
    if let [b] = rest {
        sum += u32::from(*b) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build an ICMP echo request (type 8) with a valid checksum.
pub fn build_echo_request(ident: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(8 + payload.len());
    p.extend_from_slice(&[ECHO_REQUEST, 0, 0, 0]);
    p.extend_from_slice(&ident.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(payload);
    let c = checksum(&p);
    p[2..4].copy_from_slice(&c.to_be_bytes());
    p
}

/// What an incoming ICMP datagram means for our probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parsed {
    EchoReply { ident: u16, seq: u16 },
    /// Time exceeded / unreachable quoting one of our echo requests.
    Error { icmp_type: u8, code: u8, ident: u16, seq: u16 },
}

/// Parsed datagram plus the TTL/source taken from a leading IPv4 header,
/// when the kernel included one (macOS does, Linux does not).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Incoming {
    pub msg: Parsed,
    pub ip_ttl: Option<u8>,
    pub ip_src: Option<Ipv4Addr>,
}

/// If `buf` starts with an IPv4 header, return (header length, ttl, source).
fn ip_header(buf: &[u8]) -> Option<(usize, u8, Ipv4Addr)> {
    if buf.len() >= 20 && buf[0] >> 4 == 4 {
        let ihl = usize::from(buf[0] & 0x0f) * 4;
        if ihl >= 20 && buf.len() >= ihl {
            return Some((ihl, buf[8], Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15])));
        }
    }
    None
}

/// Parse a received datagram (with or without leading IPv4 header).
pub fn parse_incoming(buf: &[u8]) -> Option<Incoming> {
    // ICMP types we care about are 0, 3, 11 -> first byte never has 0x4 high nibble.
    let (icmp, ip_ttl, ip_src) = match ip_header(buf) {
        Some((ihl, ttl, src)) => (&buf[ihl..], Some(ttl), Some(src)),
        None => (buf, None, None),
    };
    if icmp.len() < 8 {
        return None;
    }
    let t = icmp[0];
    let msg = match t {
        ECHO_REPLY => Parsed::EchoReply {
            ident: u16::from_be_bytes([icmp[4], icmp[5]]),
            seq: u16::from_be_bytes([icmp[6], icmp[7]]),
        },
        DEST_UNREACHABLE | TIME_EXCEEDED => {
            let inner = &icmp[8..];
            let (ihl, _, _) = ip_header(inner)?;
            let q = &inner[ihl..];
            if q.len() < 8 || q[0] != ECHO_REQUEST {
                return None;
            }
            Parsed::Error {
                icmp_type: t,
                code: icmp[1],
                ident: u16::from_be_bytes([q[4], q[5]]),
                seq: u16::from_be_bytes([q[6], q[7]]),
            }
        }
        _ => return None,
    };
    Some(Incoming { msg, ip_ttl, ip_src })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_known_vector() {
        // Example from RFC 1071 section 3: words 0001 f203 f4f5 f6f7 -> sum ddf2, checksum 220d
        assert_eq!(checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]), 0x220d);
        // Odd length is padded with zero.
        assert_eq!(checksum(&[0xff]), !0xff00u16);
    }

    #[test]
    fn echo_request_verifies() {
        let p = build_echo_request(0x1234, 7, b"navsuite-probe");
        assert_eq!(p[0], ECHO_REQUEST);
        assert_eq!(&p[4..8], &[0x12, 0x34, 0, 7]);
        // A packet including its checksum sums to zero.
        assert_eq!(checksum(&p), 0);
    }

    fn ipv4_header(src: [u8; 4], ttl: u8) -> Vec<u8> {
        let mut h = vec![0x45, 0, 0, 0, 0, 0, 0, 0, ttl, 1, 0, 0];
        h.extend_from_slice(&src);
        h.extend_from_slice(&[10, 0, 0, 2]);
        h
    }

    #[test]
    fn parse_reply_without_ip_header() {
        let mut r = build_echo_request(9, 3, b"x");
        r[0] = ECHO_REPLY;
        let inc = parse_incoming(&r).unwrap();
        assert_eq!(inc.msg, Parsed::EchoReply { ident: 9, seq: 3 });
        assert_eq!(inc.ip_ttl, None);
    }

    #[test]
    fn parse_reply_with_ip_header() {
        let mut r = build_echo_request(9, 3, b"x");
        r[0] = ECHO_REPLY;
        let mut pkt = ipv4_header([1, 1, 1, 1], 57);
        pkt.extend_from_slice(&r);
        let inc = parse_incoming(&pkt).unwrap();
        assert_eq!(inc.msg, Parsed::EchoReply { ident: 9, seq: 3 });
        assert_eq!(inc.ip_ttl, Some(57));
        assert_eq!(inc.ip_src, Some(Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn parse_time_exceeded() {
        let orig = build_echo_request(0xbeef, 42, b"payload");
        let mut te = vec![TIME_EXCEEDED, 0, 0, 0, 0, 0, 0, 0];
        te.extend(ipv4_header([10, 0, 0, 2], 1));
        te.extend_from_slice(&orig[..8]);
        let mut pkt = ipv4_header([192, 168, 1, 1], 64);
        pkt.extend(te);
        let inc = parse_incoming(&pkt).unwrap();
        assert_eq!(
            inc.msg,
            Parsed::Error { icmp_type: TIME_EXCEEDED, code: 0, ident: 0xbeef, seq: 42 }
        );
        assert_eq!(inc.ip_src, Some(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn parse_rejects_junk() {
        assert!(parse_incoming(&[0, 0, 0]).is_none());
        assert!(parse_incoming(&[13, 0, 0, 0, 0, 0, 0, 0]).is_none());
    }
}
