//! Unix ICMP engine: unprivileged ICMP datagram socket
//! (`socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)`).
//!
//! * macOS: received datagrams include the IPv4 header; ICMP errors (time
//!   exceeded, unreachable) are delivered on the normal receive path, so we
//!   match them by the quoted identifier + sequence.
//! * Linux: the kernel strips the IP header, rewrites the identifier to the
//!   socket's "port" and only delivers matching echo replies. ICMP errors
//!   arrive on the socket error queue (`IP_RECVERR` / `MSG_ERRQUEUE`); the
//!   reply TTL comes from an `IP_TTL` control message (`IP_RECVTTL`).

use crate::icmp::{self, Parsed};
use crate::ping::Echo;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

pub(crate) struct Pinger {
    sock: Socket,
    ident: u16,
}

const PAYLOAD: &[u8; 32] = b"navsuite-probe-abcdefghijklmnopq";

#[cfg(any(target_os = "linux", target_os = "android"))]
const LINUX: bool = true;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const LINUX: bool = false;

fn setsockopt_int(fd: i32, level: i32, name: i32, val: i32) -> io::Result<()> {
    // SAFETY: valid fd, pointer to a live c_int of the declared size.
    let r = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (&val as *const i32).cast(),
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if r == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

impl Pinger {
    pub(crate) fn open() -> io::Result<Self> {
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?;
        let fd = sock.as_raw_fd();
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_RECVERR, 1)?;
        }
        // Best effort: ask for the TTL of received packets.
        let _ = setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_RECVTTL, 1);
        let ident = (std::process::id() as u16) ^ 0x5a5a;
        Ok(Self { sock, ident })
    }

    pub(crate) fn echo(&self, dst: Ipv4Addr, ttl: u8, seq: u16, timeout: Duration) -> io::Result<Echo> {
        self.sock.set_ttl_v4(u32::from(ttl))?;
        let pkt = icmp::build_echo_request(self.ident, seq, PAYLOAD);
        let start = Instant::now();
        self.sock
            .send_to(&pkt, &SockAddr::from(SocketAddrV4::new(dst, 0)))?;
        let fd = self.sock.as_raw_fd();
        loop {
            let left = timeout.saturating_sub(start.elapsed());
            if left.is_zero() {
                return Ok(Echo::Timeout);
            }
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let ms = left.as_millis().clamp(1, i32::MAX as u128) as i32;
            // SAFETY: one valid pollfd.
            let r = unsafe { libc::poll(&mut pfd, 1, ms) };
            if r < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if r == 0 {
                return Ok(Echo::Timeout);
            }
            let rtt = start.elapsed().as_secs_f64() * 1000.0;
            if LINUX && pfd.revents & libc::POLLERR != 0 {
                if let Some(e) = self.read_errqueue(seq, rtt)? {
                    return Ok(e);
                }
                continue;
            }
            if pfd.revents & libc::POLLIN != 0 {
                let (buf, from, cmsg_ttl) = recv(fd, 0)?;
                let Some(inc) = icmp::parse_incoming(&buf) else { continue };
                let src = inc.ip_src.or(from).unwrap_or(dst);
                // macOS does not filter by identifier: check it ourselves.
                let ours = |ident: u16, s: u16| s == seq && (LINUX || ident == self.ident);
                match inc.msg {
                    Parsed::EchoReply { ident, seq: s } if ours(ident, s) => {
                        return Ok(Echo::Reply {
                            from: src,
                            rtt,
                            ttl: inc.ip_ttl.or(cmsg_ttl),
                        });
                    }
                    Parsed::Error { icmp_type, ident, seq: s, .. } if ours(ident, s) => {
                        return Ok(if icmp_type == icmp::TIME_EXCEEDED {
                            Echo::Exceeded { from: src, rtt }
                        } else {
                            Echo::Unreachable { from: src, rtt }
                        });
                    }
                    _ => continue,
                }
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn read_errqueue(&self, seq: u16, rtt: f64) -> io::Result<Option<Echo>> {
        let fd = self.sock.as_raw_fd();
        let mut data = [0u8; 512];
        let mut ctrl = [0u8; 512];
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: data.len(),
        };
        // SAFETY: zeroed msghdr is a valid "empty" value; we fill the pointers below.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctrl.as_mut_ptr().cast();
        msg.msg_controllen = ctrl.len() as _;
        // SAFETY: msg points at live buffers.
        let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT) };
        if n < 0 {
            let e = io::Error::last_os_error();
            return if e.kind() == io::ErrorKind::WouldBlock { Ok(None) } else { Err(e) };
        }
        let n = n as usize;
        // The payload is our original ICMP echo request (identifier rewritten by the kernel).
        if n >= 8 && u16::from_be_bytes([data[6], data[7]]) != seq {
            return Ok(None);
        }
        // SAFETY: standard CMSG iteration over the control buffer the kernel filled.
        unsafe {
            let mut c = libc::CMSG_FIRSTHDR(&msg);
            while !c.is_null() {
                if (*c).cmsg_level == libc::IPPROTO_IP && (*c).cmsg_type == libc::IP_RECVERR {
                    let ee = libc::CMSG_DATA(c) as *const libc::sock_extended_err;
                    let ee_v = std::ptr::read_unaligned(ee);
                    if ee_v.ee_origin != libc::SO_EE_ORIGIN_ICMP {
                        return Ok(None);
                    }
                    let off = ee.add(1) as *const libc::sockaddr_in;
                    let sin = std::ptr::read_unaligned(off);
                    let from = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                    return Ok(Some(if ee_v.ee_type == icmp::TIME_EXCEEDED {
                        Echo::Exceeded { from, rtt }
                    } else {
                        Echo::Unreachable { from, rtt }
                    }));
                }
                c = libc::CMSG_NXTHDR(&msg, c);
            }
        }
        Ok(None)
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn read_errqueue(&self, _seq: u16, _rtt: f64) -> io::Result<Option<Echo>> {
        Ok(None)
    }
}

/// recvmsg wrapper returning (datagram, source address, TTL control message).
fn recv(fd: i32, flags: i32) -> io::Result<(Vec<u8>, Option<Ipv4Addr>, Option<u8>)> {
    let mut data = vec![0u8; 2048];
    let mut ctrl = [0u8; 256];
    // SAFETY: zeroed sockaddr_in / msghdr are valid; pointers refer to live buffers.
    unsafe {
        let mut sin: libc::sockaddr_in = std::mem::zeroed();
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: data.len(),
        };
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = (&mut sin as *mut libc::sockaddr_in).cast();
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctrl.as_mut_ptr().cast();
        msg.msg_controllen = ctrl.len() as _;
        let n = libc::recvmsg(fd, &mut msg, flags);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        data.truncate(n as usize);
        let from = (msg.msg_namelen as usize >= std::mem::size_of::<libc::sockaddr_in>()
            && i32::from(sin.sin_family) == libc::AF_INET)
            .then(|| Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)));
        let mut ttl = None;
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::IPPROTO_IP
                && ((*c).cmsg_type == libc::IP_TTL || (*c).cmsg_type == libc::IP_RECVTTL)
            {
                let p = libc::CMSG_DATA(c);
                // Linux sends an int; BSD/macOS send a single byte.
                let len = (*c).cmsg_len as usize;
                ttl = Some(if LINUX && len >= libc::CMSG_LEN(4) as usize {
                    std::ptr::read_unaligned(p as *const i32) as u8
                } else {
                    *p
                });
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
        Ok((data, from, ttl))
    }
}
