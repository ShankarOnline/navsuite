//! Opening a found service in the right app: browser, file manager, SSH client, VNC viewer...

use crate::{Host, Service};

/// Open a URL or path with the OS default handler (ShellExecuteW / `open` / `xdg-open`).
pub fn open_target(target: &str) -> Result<(), String> {
    let target = target.trim();
    if target.is_empty() || target.starts_with('-') || target.contains(['\0', '\n', '\r']) {
        return Err(format!("refusing to open {target:?}"));
    }
    platform_open(target)
}

#[cfg(windows)]
fn platform_open(target: &str) -> Result<(), String> {
    use windows_sys::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE};
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let w = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
    let (verb, file) = (w("open"), w(target));
    // ShellExecuteW hands off to shell extensions (e.g. the browser that opens an .html file),
    // which need COM initialized on the calling thread. Without this the call can return success
    // yet nothing actually launches. We run on a pooled blocking thread, so initialize it here.
    let hr = unsafe { CoInitializeEx(std::ptr::null(), (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32) };
    let inited = hr == 0 || hr == 1; // S_OK or S_FALSE (already initialized on this thread)
    // SAFETY: all strings are NUL-terminated and outlive the call.
    let r = unsafe { ShellExecuteW(std::ptr::null_mut(), verb.as_ptr(), file.as_ptr(), std::ptr::null(), std::ptr::null(), SW_SHOWNORMAL) };
    if inited {
        unsafe { CoUninitialize() };
    }
    // ShellExecute returns a value > 32 on success.
    if r as isize > 32 { Ok(()) } else { Err(format!("Windows could not open {target} (error {})", r as isize)) }
}

/// Open the OS file manager with `path` selected (E2: "Show in folder").
pub fn reveal(path: &str) -> Result<(), String> {
    let p = path.trim();
    if p.is_empty() || p.contains(['\0', '\n', '\r']) {
        return Err(format!("refusing to reveal {p:?}"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        if p.contains('"') {
            return Err("path contains a quote".into());
        }
        return std::process::Command::new("explorer.exe")
            .raw_arg(format!("/select,\"{p}\""))
            .spawn()
            .map(|_| ())
            .map_err(|e| format!("could not open Explorer: {e}"));
    }
    #[cfg(target_os = "macos")]
    {
        return spawn_detached("open", &["-R", p]);
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let parent = std::path::Path::new(p).parent().map(|x| x.to_string_lossy().into_owned()).unwrap_or_else(|| "/".into());
        return spawn_detached("xdg-open", &[&parent]);
    }
    #[cfg(not(any(windows, unix)))]
    {
        Err("reveal is not supported on this OS".into())
    }
}

#[cfg(target_os = "macos")]
fn platform_open(target: &str) -> Result<(), String> {
    spawn_detached("open", &[target])
}

#[cfg(all(unix, not(target_os = "macos")))]
fn platform_open(target: &str) -> Result<(), String> {
    spawn_detached("xdg-open", &[target])
}

#[cfg(not(any(windows, unix)))]
fn platform_open(target: &str) -> Result<(), String> {
    Err(format!("opening {target} is not supported on this OS"))
}

#[allow(dead_code)]
fn spawn_detached(program: &str, args: &[&str]) -> Result<(), String> {
    let mut child = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("could not run {program}: {e}"))?;
    // Reap it in the background so it doesn't linger as a zombie.
    std::thread::spawn(move || child.wait());
    Ok(())
}

/// The URL/path that opens `svc` on `host`, if the service is something one can open.
pub fn service_target(host: &Host, svc: &Service) -> Option<String> {
    if let Some(u) = &svc.url {
        return Some(u.clone());
    }
    let ip = &host.ip;
    let port = svc.port;
    Some(match svc.kind.as_str() {
        "http" | "plex" => format!("http://{ip}:{port}/"),
        "https" => format!("https://{ip}:{port}/"),
        "ipp" | "printer" => format!("http://{ip}:{}/", if svc.kind == "ipp" { port } else { 80 }),
        "smb" | "netbios" => smb_target(ip),
        "ssh" | "sftp" => format!("{}://{ip}{}", svc.kind, if port == 22 || port == 0 { String::new() } else { format!(":{port}") }),
        "ftp" => format!("ftp://{ip}:{port}/"),
        "vnc" => format!("vnc://{ip}:{port}"),
        "rdp" => rdp_target(ip, port),
        "afp" => format!("afp://{ip}/"),
        "nfs" => format!("nfs://{ip}/"),
        "webdav" => format!("http://{ip}:{port}/"),
        _ => return None,
    })
}

fn smb_target(ip: &str) -> String {
    if cfg!(windows) { format!("\\\\{ip}\\") } else { format!("smb://{ip}/") }
}

fn rdp_target(ip: &str, port: u16) -> String {
    // Windows has no rdp:// handler; macOS' Windows App understands this URL form.
    format!("rdp://full%20address=s:{ip}:{port}")
}

/// Open `svc` on `host` in the appropriate app.
pub fn launch_service(host: &Host, svc: &Service) -> Result<(), String> {
    #[cfg(windows)]
    {
        // Windows has no default handlers for ssh:// or rdp://; use the built-in clients.
        if host.ip.parse::<std::net::IpAddr>().is_ok() {
            match svc.kind.as_str() {
                "rdp" => return spawn_console("mstsc.exe", &[&format!("/v:{}:{}", host.ip, svc.port)], false),
                "ssh" => return spawn_console("ssh.exe", &["-p", &svc.port.to_string(), &host.ip], true),
                _ => {}
            }
        }
    }
    let target = service_target(host, svc).ok_or_else(|| format!("{} on {} has nothing to open", svc.label, host.display_name()))?;
    open_target(&target)
}

#[cfg(windows)]
fn spawn_console(program: &str, args: &[&str], new_console: bool) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
    let mut cmd = std::process::Command::new(program);
    cmd.args(args);
    if new_console {
        cmd.creation_flags(CREATE_NEW_CONSOLE);
    }
    cmd.spawn().map(|_| ()).map_err(|e| format!("could not start {program}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets() {
        let h = Host { ip: "192.168.1.9".into(), ..Default::default() };
        let s = |kind: &str, port| Service { kind: kind.into(), port, ..Default::default() };
        assert_eq!(service_target(&h, &s("https", 8443)).unwrap(), "https://192.168.1.9:8443/");
        assert_eq!(service_target(&h, &s("ssh", 22)).unwrap(), "ssh://192.168.1.9");
        assert_eq!(service_target(&h, &s("vnc", 5900)).unwrap(), "vnc://192.168.1.9:5900");
        assert_eq!(service_target(&h, &s("ipp", 631)).unwrap(), "http://192.168.1.9:631/");
        assert!(service_target(&h, &s("googlecast", 8009)).is_none());
        assert!(open_target("-rf").is_err());
    }
}
