//! Windows ICMP engine: iphlpapi `IcmpSendEcho2` (no admin rights needed).

use crate::ping::Echo;
use std::io;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ICMP_ECHO_REPLY, IP_DEST_HOST_UNREACHABLE, IP_DEST_NET_UNREACHABLE, IP_DEST_PORT_UNREACHABLE,
    IP_DEST_PROT_UNREACHABLE, IP_OPTION_INFORMATION, IP_REQ_TIMED_OUT, IP_SUCCESS,
    IP_TTL_EXPIRED_REASSEM, IP_TTL_EXPIRED_TRANSIT, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho2,
};

pub(crate) struct Pinger {
    handle: HANDLE,
}

// The ICMP handle may be used from any thread; calls are serialised by the
// caller (one outstanding echo at a time).
unsafe impl Send for Pinger {}
unsafe impl Sync for Pinger {}

impl Drop for Pinger {
    fn drop(&mut self) {
        // SAFETY: handle came from IcmpCreateFile and is closed exactly once.
        unsafe {
            IcmpCloseHandle(self.handle);
        }
    }
}

const PAYLOAD: &[u8; 32] = b"navsuite-probe-abcdefghijklmnopq";

impl Pinger {
    pub(crate) fn open() -> io::Result<Self> {
        // SAFETY: plain FFI call without arguments.
        let handle = unsafe { IcmpCreateFile() };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { handle })
    }

    pub(crate) fn echo(&self, dst: Ipv4Addr, ttl: u8, _seq: u16, timeout: Duration) -> io::Result<Echo> {
        let opts = IP_OPTION_INFORMATION {
            Ttl: ttl,
            Tos: 0,
            Flags: 0,
            OptionsSize: 0,
            OptionsData: std::ptr::null_mut(),
        };
        // Reply buffer: one ICMP_ECHO_REPLY + payload + 8 bytes for an ICMP error + slack.
        let mut buf = vec![0u8; std::mem::size_of::<ICMP_ECHO_REPLY>() + PAYLOAD.len() + 8 + 64];
        let dest = u32::from_ne_bytes(dst.octets());
        let ms = timeout.as_millis().clamp(1, u32::MAX as u128) as u32;
        let start = Instant::now();
        // SAFETY: synchronous call (no event / APC); all pointers are valid for
        // the duration of the call and sizes match the buffers.
        let n = unsafe {
            IcmpSendEcho2(
                self.handle,
                std::ptr::null_mut(),
                None,
                std::ptr::null(),
                dest,
                PAYLOAD.as_ptr().cast(),
                PAYLOAD.len() as u16,
                &opts,
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
                ms,
            )
        };
        let elapsed = start.elapsed().as_secs_f64() * 1000.0;
        // SAFETY: buffer is at least size_of::<ICMP_ECHO_REPLY>() and zero-initialised;
        // read_unaligned avoids alignment assumptions on the Vec<u8>.
        let reply: ICMP_ECHO_REPLY = unsafe { std::ptr::read_unaligned(buf.as_ptr().cast()) };
        let status = if n == 0 {
            // SAFETY: plain FFI call.
            let err = unsafe { GetLastError() };
            // Some Windows builds return 0 for TTL-expired but still fill the reply.
            if reply.Address != 0 && reply.Status != IP_SUCCESS {
                reply.Status
            } else {
                err
            }
        } else {
            reply.Status
        };
        let from = Ipv4Addr::from(reply.Address.to_ne_bytes());
        // Windows only reports whole milliseconds; prefer our own timer but never
        // report less than the kernel's figure.
        let rtt = elapsed.max(f64::from(reply.RoundTripTime)).min(f64::from(ms));
        Ok(match status {
            IP_SUCCESS => Echo::Reply {
                from,
                rtt,
                ttl: Some(reply.Options.Ttl),
            },
            IP_TTL_EXPIRED_TRANSIT | IP_TTL_EXPIRED_REASSEM => Echo::Exceeded { from, rtt },
            IP_DEST_HOST_UNREACHABLE | IP_DEST_NET_UNREACHABLE | IP_DEST_PORT_UNREACHABLE
            | IP_DEST_PROT_UNREACHABLE => {
                if reply.Address == 0 {
                    Echo::Timeout
                } else {
                    Echo::Unreachable { from, rtt }
                }
            }
            IP_REQ_TIMED_OUT => Echo::Timeout,
            11050 /* IP_GENERAL_FAILURE */ => Echo::Timeout,
            other => return Err(io::Error::other(format!("ICMP status {other}"))),
        })
    }
}
