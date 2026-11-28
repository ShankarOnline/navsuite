//! Built-in terminal (E5, E11, E13): PTY sessions with the shell the user picks.
//!
//! Each session is a real pseudo-terminal (ConPTY on Windows, openpty elsewhere) running the
//! chosen shell, in a folder or on a remote system over ssh. Output streams to the UI as
//! `term://data` events; the UI renders it with xterm.js.

use base64::Engine;
use portable_pty::{CommandBuilder, MasterPty, PtySize, native_pty_system};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Mutex;

/// A shell the user can pick for a terminal tab.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Shell {
    pub id: String,
    pub name: String,
    pub program: String,
    pub args: Vec<String>,
}

/// Where a new terminal should start.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct Start {
    /// Shell id from `shells()`; empty = the default shell.
    #[serde(default)]
    pub shell: String,
    /// Local or UNC folder to start in.
    pub cwd: Option<String>,
    /// Open a shell on this host over ssh instead (user@host).
    pub ssh: Option<String>,
    pub ssh_port: Option<u16>,
    /// Folder on the ssh host to change to.
    pub remote_dir: Option<String>,
    pub cols: u16,
    pub rows: u16,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Data {
    pub id: u32,
    /// Raw output bytes, base64 (the UI decodes them so split UTF-8 sequences survive).
    pub b64: String,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Exit {
    pub id: u32,
}

struct Session {
    master: Box<dyn MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    child: Box<dyn portable_pty::Child + Send + Sync>,
}

#[derive(Default)]
pub struct Terminals {
    next: Mutex<u32>,
    sessions: Mutex<HashMap<u32, Session>>,
}

fn which(program: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    let exts: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT").unwrap_or(".EXE;.CMD;.BAT".into()).split(';').map(|s| s.to_lowercase()).collect()
    } else {
        vec![String::new()]
    };
    for dir in std::env::split_paths(&path) {
        for ext in &exts {
            let p = dir.join(format!("{program}{ext}"));
            if p.is_file() {
                return Some(p.to_string_lossy().into_owned());
            }
        }
    }
    None
}

fn shell(id: &str, name: &str, program: String, args: &[&str]) -> Shell {
    Shell { id: id.into(), name: name.into(), program, args: args.iter().map(|s| s.to_string()).collect() }
}

/// The shells installed on this machine, most likely default first.
pub fn shells() -> Vec<Shell> {
    let mut out = Vec::new();
    #[cfg(windows)]
    {
        if let Some(p) = which("pwsh") {
            out.push(shell("pwsh", "PowerShell 7", p, &["-NoLogo"]));
        }
        if let Some(p) = which("powershell") {
            out.push(shell("powershell", "Windows PowerShell", p, &["-NoLogo"]));
        }
        if let Some(p) = which("cmd") {
            out.push(shell("cmd", "Command Prompt", p, &[]));
        }
        for p in [r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files (x86)\Git\bin\bash.exe"] {
            if Path::new(p).is_file() {
                out.push(shell("gitbash", "Git Bash", p.into(), &["--login", "-i"]));
                break;
            }
        }
        if let Some(p) = which("wsl") {
            out.push(shell("wsl", "WSL", p, &[]));
        }
    }
    #[cfg(not(windows))]
    {
        let user_shell = std::env::var("SHELL").ok();
        let mut seen = std::collections::HashSet::new();
        let listed = std::fs::read_to_string("/etc/shells").unwrap_or_default();
        let mut candidates: Vec<String> = user_shell.into_iter().collect();
        candidates.extend(listed.lines().map(str::trim).filter(|l| l.starts_with('/')).map(String::from));
        for p in candidates {
            let name = Path::new(&p).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            if name.is_empty() || !seen.insert(name.clone()) || !Path::new(&p).is_file() {
                continue;
            }
            out.push(shell(&name, &name, p, &["-l"]));
        }
    }
    out
}

/// Quote a path for the shell that will receive it (E13: drag into terminal).
pub fn quote_for(shell_id: &str, path: &str) -> String {
    match shell_id {
        "cmd" => format!("\"{path}\""),
        "pwsh" | "powershell" => format!("'{}'", path.replace('\'', "''")),
        _ => {
            let p = if shell_id == "gitbash" { path.replace('\\', "/") } else { path.to_string() };
            format!("'{}'", p.replace('\'', r"'\''"))
        }
    }
}

fn is_unc(p: &str) -> bool {
    p.starts_with(r"\\") || p.starts_with("//")
}

impl Terminals {
    pub fn spawn(&self, start: Start, default_shell: &str, on_data: impl Fn(Data) + Send + 'static, on_exit: impl Fn(Exit) + Send + 'static) -> Result<u32, String> {
        let all = shells();
        let wanted = if start.shell.is_empty() { default_shell } else { start.shell.as_str() };
        let sh = all.iter().find(|s| s.id == wanted).or(all.first()).cloned().ok_or("No shell found on this system")?;

        let mut cmd;
        if let Some(target) = &start.ssh {
            // A shell on a remote system: the system ssh client inside the PTY, so keys, agent and
            // known_hosts work exactly as in the user's own terminal.
            let ssh = which("ssh").ok_or("The ssh client is not installed")?;
            cmd = CommandBuilder::new(ssh);
            cmd.arg("-t");
            if let Some(port) = start.ssh_port {
                cmd.arg("-p");
                cmd.arg(port.to_string());
            }
            cmd.arg(target);
            if let Some(dir) = &start.remote_dir {
                let q = format!("'{}'", dir.replace('\'', r"'\''"));
                cmd.arg(format!("cd {q} 2>/dev/null; exec \"${{SHELL:-sh}}\" -l"));
            }
        } else {
            cmd = CommandBuilder::new(&sh.program);
            let cwd = start.cwd.clone().filter(|c| !c.is_empty());
            match (&cwd, sh.id.as_str()) {
                // cmd.exe refuses a UNC current directory; pushd maps a temporary drive letter.
                (Some(c), "cmd") if is_unc(c) => {
                    cmd.arg("/K");
                    cmd.arg(format!("pushd \"{c}\""));
                }
                (Some(c), "wsl") => {
                    for a in &sh.args {
                        cmd.arg(a);
                    }
                    cmd.arg("--cd");
                    cmd.arg(c);
                }
                (Some(c), _) => {
                    for a in &sh.args {
                        cmd.arg(a);
                    }
                    if Path::new(c).is_dir() {
                        cmd.cwd(c);
                    }
                }
                (None, _) => {
                    for a in &sh.args {
                        cmd.arg(a);
                    }
                    if let Some(home) = dirs::home_dir() {
                        cmd.cwd(home);
                    }
                }
            }
        }
        cmd.env("TERM", "xterm-256color");
        cmd.env("COLORTERM", "truecolor");

        let size = PtySize { rows: start.rows.max(5), cols: start.cols.max(20), pixel_width: 0, pixel_height: 0 };
        let pair = native_pty_system().openpty(size).map_err(|e| e.to_string())?;
        let child = pair.slave.spawn_command(cmd).map_err(|e| format!("Could not start {}: {e}", sh.name))?;
        drop(pair.slave);
        let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
        let writer = pair.master.take_writer().map_err(|e| e.to_string())?;

        let id = {
            let mut n = self.next.lock().unwrap();
            *n += 1;
            *n
        };
        self.sessions.lock().unwrap().insert(id, Session { master: pair.master, writer, child });

        std::thread::Builder::new()
            .name(format!("term-{id}"))
            .spawn(move || {
                let mut buf = [0u8; 16 * 1024];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => on_data(Data { id, b64: base64::engine::general_purpose::STANDARD.encode(&buf[..n]) }),
                    }
                }
                on_exit(Exit { id });
            })
            .map_err(|e| e.to_string())?;
        Ok(id)
    }

    pub fn write(&self, id: u32, data: &str) -> Result<(), String> {
        let mut s = self.sessions.lock().unwrap();
        let sess = s.get_mut(&id).ok_or("Terminal closed")?;
        sess.writer.write_all(data.as_bytes()).and_then(|_| sess.writer.flush()).map_err(|e| e.to_string())
    }

    pub fn resize(&self, id: u32, cols: u16, rows: u16) -> Result<(), String> {
        let s = self.sessions.lock().unwrap();
        let sess = s.get(&id).ok_or("Terminal closed")?;
        sess.master.resize(PtySize { rows: rows.max(5), cols: cols.max(20), pixel_width: 0, pixel_height: 0 }).map_err(|e| e.to_string())
    }

    pub fn close(&self, id: u32) {
        if let Some(mut sess) = self.sessions.lock().unwrap().remove(&id) {
            let _ = sess.child.kill();
        }
    }

    pub fn close_all(&self) {
        let ids: Vec<u32> = self.sessions.lock().unwrap().keys().copied().collect();
        for id in ids {
            self.close(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting() {
        assert_eq!(quote_for("cmd", r"C:\a b"), r#""C:\a b""#);
        assert_eq!(quote_for("pwsh", "it's"), "'it''s'");
        assert_eq!(quote_for("bash", "it's"), r"'it'\''s'");
        assert_eq!(quote_for("gitbash", r"C:\x"), "'C:/x'");
    }

    #[test]
    fn finds_a_shell() {
        assert!(!shells().is_empty());
    }

    #[test]
    fn spawns_default_shell_and_reads_output() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::time::Duration;
        let terms = Terminals::default();
        let got = Arc::new(AtomicBool::new(false));
        let g = got.clone();
        let start = Start { cols: 80, rows: 24, ..Default::default() };
        let id = terms
            .spawn(start, "", move |_d| g.store(true, Ordering::Relaxed), move |_e| {})
            .expect("spawn should succeed");
        assert!(id > 0);
        // A real shell prints a prompt within a second.
        for _ in 0..40 {
            if got.load(Ordering::Relaxed) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        terms.close(id);
        assert!(got.load(Ordering::Relaxed), "no output from the spawned shell");
    }
}
