//! Listing the SMB shares a host offers.
//!
//! Windows: NetShareEnum (native, uses the current user's credentials / null session).
//! Elsewhere: `smbclient -L //host -N -g` when Samba's client is installed.

use crate::Share;

/// List the shares on `host` (IP or name).
pub async fn list_shares(host: &str) -> Result<Vec<Share>, String> {
    let host = host.trim().trim_start_matches('\\').trim_start_matches("smb://").trim_end_matches('/').to_string();
    if host.is_empty() || host.starts_with('-') || host.contains(['/', '\\', ' ']) {
        return Err(format!("invalid host name: {host:?}"));
    }
    platform_list(host).await
}

#[cfg(windows)]
async fn platform_list(host: String) -> Result<Vec<Share>, String> {
    tokio::task::spawn_blocking(move || net_share_enum(&host)).await.map_err(|e| e.to_string())?
}

#[cfg(windows)]
fn net_share_enum(host: &str) -> Result<Vec<Share>, String> {
    use windows_sys::Win32::NetworkManagement::NetManagement::NetApiBufferFree;
    use windows_sys::Win32::Storage::FileSystem::{NetShareEnum, SHARE_INFO_1};

    let server: Vec<u16> = format!("\\\\{host}").encode_utf16().chain(Some(0)).collect();
    let mut buf: *mut u8 = std::ptr::null_mut();
    let (mut read, mut total, mut resume) = (0u32, 0u32, 0u32);
    // SAFETY: NetShareEnum allocates `buf` as an array of `read` SHARE_INFO_1; freed with NetApiBufferFree.
    let status = unsafe { NetShareEnum(server.as_ptr(), 1, &mut buf, u32::MAX, &mut read, &mut total, &mut resume) };
    if status != 0 && status != 234 {
        if !buf.is_null() {
            unsafe { NetApiBufferFree(buf as *const _) };
        }
        return Err(match status {
            5 => format!("Access denied listing shares on {host} (sign in to it first)"),
            53 => format!("{host} was not found or does not offer SMB"),
            1115 | 1219 => format!("Could not list shares on {host}: credentials conflict (error {status})"),
            _ => format!("Could not list shares on {host} (error {status})"),
        });
    }
    let mut out = Vec::new();
    if !buf.is_null() {
        unsafe {
            let rows = std::slice::from_raw_parts(buf as *const SHARE_INFO_1, read as usize);
            for r in rows {
                let name = wide(r.shi1_netname);
                let kind = share_kind(r.shi1_type);
                out.push(Share { path: format!("\\\\{host}\\{name}"), name, kind: kind.into(), remark: wide(r.shi1_remark) });
            }
            NetApiBufferFree(buf as *const _);
        }
    }
    Ok(out)
}

#[cfg(windows)]
unsafe fn wide(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: NetShareEnum hands back NUL-terminated wide strings.
    unsafe {
        let len = (0..).take_while(|&i| *p.add(i) != 0).count();
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

#[allow(dead_code)]
fn share_kind(t: u32) -> &'static str {
    if t & 0xff == 3 {
        return "ipc";
    }
    if t & 0x8000_0000 != 0 {
        return "special"; // ADMIN$, C$ ...
    }
    match t & 0xff {
        0 => "disk",
        1 => "printer",
        3 => "ipc",
        _ => "special",
    }
}

#[cfg(not(windows))]
async fn platform_list(host: String) -> Result<Vec<Share>, String> {
    let smbclient = crate::cmd::which("smbclient")
        .or_else(|| ["/usr/bin/smbclient", "/opt/homebrew/bin/smbclient", "/usr/local/bin/smbclient"].iter().map(std::path::PathBuf::from).find(|p| p.exists()))
        .ok_or_else(|| "Listing shares needs Samba's smbclient (e.g. `sudo apt install smbclient` or `brew install samba`); you can still open smb://host directly.".to_string())?;
    let target = format!("//{host}");
    let out = crate::cmd::run(&smbclient, &["-L", &target, "-N", "-g"], std::time::Duration::from_secs(10)).await?;
    let text = String::from_utf8_lossy(&out.stdout);
    let shares = parse_smbclient(&host, &text);
    if shares.is_empty() && !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let msg = err.lines().chain(text.lines()).find(|l| !l.trim().is_empty()).unwrap_or("unknown error");
        return Err(format!("smbclient could not list {host}: {msg}"));
    }
    Ok(shares)
}

/// Parse `smbclient -g` output: `Disk|name|comment`, `IPC|IPC$|...`, `Printer|...`.
#[allow(dead_code)]
pub(crate) fn parse_smbclient(host: &str, text: &str) -> Vec<Share> {
    text.lines()
        .filter_map(|l| {
            let mut f = l.splitn(3, '|');
            let kind = match f.next()? {
                "Disk" => "disk",
                "IPC" => "ipc",
                "Printer" => "printer",
                _ => return None,
            };
            let name = f.next()?.to_string();
            let kind = if kind == "disk" && name.ends_with('$') { "special" } else { kind };
            Some(Share { path: format!("smb://{host}/{name}"), name, kind: kind.into(), remark: f.next().unwrap_or("").to_string() })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smbclient_output() {
        let t = "Disk|public|Public files\nIPC|IPC$|IPC Service (Samba 4.17)\nDisk|print$|Printer Drivers\nPrinter|laser|HP LaserJet\nWorkgroup|WORKGROUP|NAS\n";
        let s = parse_smbclient("nas", t);
        assert_eq!(s.len(), 4);
        assert_eq!((s[0].name.as_str(), s[0].kind.as_str(), s[0].path.as_str()), ("public", "disk", "smb://nas/public"));
        assert_eq!(s[2].kind, "special");
        assert_eq!(s[3].kind, "printer");
        assert_eq!(share_kind(0), "disk");
        assert_eq!(share_kind(0x8000_0003), "ipc");
        assert_eq!(share_kind(0x8000_0000), "special");
        assert_eq!(share_kind(3), "ipc");
    }
}
