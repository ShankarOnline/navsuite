//! Windows-native helpers: drives, volume labels, free space, SMB shares and
//! SMB sessions (WNet). Everything here is blocking; callers use spawn_blocking.
#![cfg(windows)]

use crate::error::{ErrorKind, Result, VfsError};
use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::Path;
use windows_sys::Win32::NetworkManagement::NetManagement::{
    MAX_PREFERRED_LENGTH, NetApiBufferFree,
};
use windows_sys::Win32::NetworkManagement::WNet::{
    CONNECT_TEMPORARY, NETRESOURCEW, RESOURCETYPE_ANY, WNetAddConnection2W, WNetGetConnectionW,
};
use windows_sys::Win32::Storage::FileSystem::{
    GetDiskFreeSpaceExW, GetDriveTypeW, GetLogicalDriveStringsW, GetVolumeInformationW,
    GetVolumePathNameW, NetShareEnum, SHARE_INFO_1,
};

const DRIVE_REMOVABLE: u32 = 2;
const DRIVE_REMOTE: u32 = 4;
const DRIVE_CDROM: u32 = 5;
const ERROR_MORE_DATA: u32 = 234;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_INVALID_PASSWORD: u32 = 86;
const ERROR_LOGON_FAILURE: u32 = 1326;
const ERROR_SESSION_CREDENTIAL_CONFLICT: u32 = 1219;
const ERROR_ACCOUNT_RESTRICTION: u32 = 1327;
const ERROR_PASSWORD_EXPIRED: u32 = 1330;
const ERROR_ACCOUNT_DISABLED: u32 = 1331;
const ERROR_LOGON_TYPE_NOT_GRANTED: u32 = 1385;
const ERROR_ACCOUNT_LOCKED_OUT: u32 = 1909;

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(Some(0))
        .collect()
}

fn wide_path(p: &Path) -> Vec<u16> {
    p.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn from_wide(buf: &[u16]) -> String {
    let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    OsString::from_wide(&buf[..n])
        .to_string_lossy()
        .into_owned()
}

/// SAFETY: p must be null or point at a NUL-terminated UTF-16 string.
unsafe fn from_pwstr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0;
    // SAFETY: caller guarantees NUL termination.
    unsafe {
        while *p.add(n) != 0 {
            n += 1;
        }
        from_wide(std::slice::from_raw_parts(p, n))
    }
}

/// Is this Win32 error code an authentication failure?
pub(crate) fn is_auth_error(code: u32) -> bool {
    matches!(
        code,
        ERROR_INVALID_PASSWORD
            | ERROR_LOGON_FAILURE
            | ERROR_ACCOUNT_RESTRICTION
            | ERROR_PASSWORD_EXPIRED
            | ERROR_ACCOUNT_DISABLED
            | ERROR_LOGON_TYPE_NOT_GRANTED
            | ERROR_ACCOUNT_LOCKED_OUT
    )
}

pub(crate) fn is_access_denied(code: u32) -> bool {
    code == ERROR_ACCESS_DENIED
}

#[derive(Debug, Clone)]
pub(crate) struct Drive {
    pub root: String, // "C:\"
    pub label: String,
    pub remote: Option<String>,
    pub kind: u32,
}

/// Remote name (`\\host\share`) a drive letter (`"Z:"`) is mapped to.
pub(crate) fn drive_remote_name(letter: &str) -> Option<String> {
    let local = wide(letter);
    let mut buf = vec![0u16; 1024];
    let mut len = buf.len() as u32;
    // SAFETY: buffers are valid for the sizes passed.
    let r = unsafe { WNetGetConnectionW(local.as_ptr(), buf.as_mut_ptr(), &mut len) };
    if r == 0 { Some(from_wide(&buf)) } else { None }
}

pub(crate) fn drives() -> Vec<Drive> {
    let mut buf = vec![0u16; 512];
    // SAFETY: buffer valid for its length.
    let n = unsafe { GetLogicalDriveStringsW(buf.len() as u32, buf.as_mut_ptr()) } as usize;
    if n == 0 || n > buf.len() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for root in buf[..n].split(|&c| c == 0).filter(|s| !s.is_empty()) {
        let root_s = from_wide(root);
        let wroot = wide(&root_s);
        // SAFETY: wroot is NUL terminated.
        let kind = unsafe { GetDriveTypeW(wroot.as_ptr()) };
        let letter = root_s.trim_end_matches('\\').to_string();
        let mut label = String::new();
        let mut remote = None;
        if kind == DRIVE_REMOTE {
            // Don't touch the volume: a disconnected network drive can block for seconds.
            remote = drive_remote_name(&letter);
            if let Some(r) = &remote {
                label = r
                    .trim_start_matches('\\')
                    .rsplit('\\')
                    .next()
                    .unwrap_or("")
                    .to_string();
            }
        } else if kind != DRIVE_CDROM && kind != DRIVE_REMOVABLE {
            let mut name = vec![0u16; 261];
            // SAFETY: buffers valid; optional out params null.
            let ok = unsafe {
                GetVolumeInformationW(
                    wroot.as_ptr(),
                    name.as_mut_ptr(),
                    name.len() as u32,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    0,
                )
            };
            if ok != 0 {
                label = from_wide(&name);
            }
        }
        if label.is_empty() {
            label = match kind {
                DRIVE_REMOVABLE => "Removable Disk".into(),
                DRIVE_CDROM => "CD Drive".into(),
                DRIVE_REMOTE => "Network Drive".into(),
                _ => "Local Disk".into(),
            };
        }
        out.push(Drive {
            root: root_s,
            label,
            remote,
            kind,
        });
    }
    out
}

pub(crate) fn disk_free(p: &Path) -> Option<u64> {
    let mut s = p.as_os_str().to_os_string();
    if !s.to_string_lossy().ends_with('\\') {
        s.push("\\");
    }
    let w: Vec<u16> = s.encode_wide().chain(Some(0)).collect();
    let mut avail = 0u64;
    // SAFETY: w is NUL terminated; optional out params null.
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            w.as_ptr(),
            &mut avail,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok != 0 { Some(avail) } else { None }
}

/// Mount point of the volume containing `p` (`C:\`, `\\host\share\`, or a mounted folder).
pub(crate) fn volume_root(p: &Path) -> Option<String> {
    let w = wide_path(p);
    let mut buf = vec![0u16; 1024];
    // SAFETY: buffers valid for the lengths passed.
    let ok = unsafe { GetVolumePathNameW(w.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
    if ok != 0 { Some(from_wide(&buf)) } else { None }
}

/// Disk shares (no admin `$` shares) on `host`, via NetShareEnum level 1.
pub(crate) fn shares(host: &str) -> Result<Vec<(String, String)>> {
    let server = wide(&format!(r"\\{host}"));
    let mut out = Vec::new();
    let mut resume: u32 = 0;
    loop {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut read = 0u32;
        let mut total = 0u32;
        // SAFETY: all out pointers valid; buffer freed with NetApiBufferFree below.
        let r = unsafe {
            NetShareEnum(
                server.as_ptr(),
                1,
                &mut buf,
                MAX_PREFERRED_LENGTH,
                &mut read,
                &mut total,
                &mut resume,
            )
        };
        if r != 0 && r != ERROR_MORE_DATA {
            if !buf.is_null() {
                // SAFETY: buf was allocated by NetShareEnum.
                unsafe { NetApiBufferFree(buf as *const _) };
            }
            return Err(share_error(host, r));
        }
        if !buf.is_null() {
            // SAFETY: NetShareEnum returned `read` SHARE_INFO_1 entries at buf.
            let items =
                unsafe { std::slice::from_raw_parts(buf as *const SHARE_INFO_1, read as usize) };
            for it in items {
                // STYPE_DISKTREE = 0 in the low bits; STYPE_SPECIAL (0x80000000) = admin shares
                if it.shi1_type & 0xff != 0 || it.shi1_type & 0x8000_0000 != 0 {
                    continue;
                }
                // SAFETY: strings returned by NetShareEnum are NUL terminated.
                let (name, remark) =
                    unsafe { (from_pwstr(it.shi1_netname), from_pwstr(it.shi1_remark)) };
                if name.ends_with('$') {
                    continue;
                }
                out.push((name, remark));
            }
            // SAFETY: buf was allocated by NetShareEnum.
            unsafe { NetApiBufferFree(buf as *const _) };
        }
        if r != ERROR_MORE_DATA {
            break;
        }
    }
    out.sort_by_key(|a| a.0.to_lowercase());
    Ok(out)
}

fn share_error(host: &str, code: u32) -> VfsError {
    let io = std::io::Error::from_raw_os_error(code as i32);
    if is_auth_error(code) || is_access_denied(code) {
        return VfsError::new(
            ErrorKind::AuthRequired {
                host: host.to_string(),
                user: None,
            },
            format!("{host}: {io}"),
        );
    }
    VfsError::from(io).context(host)
}

/// Open an SMB session to `remote` (`\\host\share` or `\\host\IPC$`) with
/// explicit credentials. No drive letter is assigned.
pub(crate) fn wnet_connect(remote: &str, user: &str, password: &str) -> Result<()> {
    let mut wremote = wide(remote);
    let wuser = wide(user);
    let wpass = wide(password);
    let nr = NETRESOURCEW {
        dwScope: 0,
        dwType: RESOURCETYPE_ANY,
        dwDisplayType: 0,
        dwUsage: 0,
        lpLocalName: std::ptr::null_mut(),
        lpRemoteName: wremote.as_mut_ptr(),
        lpComment: std::ptr::null_mut(),
        lpProvider: std::ptr::null_mut(),
    };
    // SAFETY: all strings NUL terminated and alive for the call.
    let r = unsafe { WNetAddConnection2W(&nr, wpass.as_ptr(), wuser.as_ptr(), CONNECT_TEMPORARY) };
    match r {
        0 => Ok(()),
        // Already connected with (possibly other) credentials: use that session.
        ERROR_SESSION_CREDENTIAL_CONFLICT => Ok(()),
        c => {
            let io = std::io::Error::from_raw_os_error(c as i32);
            let host = remote
                .trim_start_matches('\\')
                .split('\\')
                .next()
                .unwrap_or("")
                .to_string();
            if is_auth_error(c) || is_access_denied(c) {
                Err(VfsError::new(
                    ErrorKind::AuthRequired {
                        host,
                        user: Some(user.to_string()),
                    },
                    format!("{remote}: {io}"),
                ))
            } else {
                Err(VfsError::from(io).context(remote))
            }
        }
    }
}
