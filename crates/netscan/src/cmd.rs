//! Running external tools (used only where no native API is reasonable): with a timeout,
//! never popping up a console window on Windows.

use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::time::{Duration, Instant};

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Run `program args...` asynchronously, killing it if it runs longer than `timeout`.
pub(crate) async fn run(program: &Path, args: &[&str], timeout: Duration) -> Result<Output, String> {
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    let child = cmd.spawn().map_err(|e| format!("could not run {}: {e}", program.display()))?;
    match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(Ok(out)) => Ok(out),
        Ok(Err(e)) => Err(format!("{} failed: {e}", program.display())),
        Err(_) => Err(format!("{} timed out after {}s", program.display(), timeout.as_secs())),
    }
}

/// Blocking variant for code already running on a blocking thread.
#[allow(dead_code)] // used on some platforms only
pub(crate) fn run_blocking(program: &Path, args: &[&str], timeout: Duration) -> Result<Output, String> {
    let mut cmd = std::process::Command::new(program);
    cmd.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let mut child = cmd.spawn().map_err(|e| format!("could not run {}: {e}", program.display()))?;
    // Drain stdout on a thread so a chatty child can't block on a full pipe.
    let mut stdout = child.stdout.take();
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(s) = stdout.as_mut() {
            let _ = std::io::Read::read_to_end(s, &mut buf);
        }
        buf
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{} timed out", program.display()));
            }
            Err(e) => return Err(format!("{} failed: {e}", program.display())),
        }
    };
    let mut stderr = Vec::new();
    if let Some(mut s) = child.stderr.take() {
        let _ = std::io::Read::read_to_end(&mut s, &mut stderr);
    }
    Ok(Output { status, stdout: reader.join().unwrap_or_default(), stderr })
}

/// Find an executable on PATH (adds `.exe` on Windows).
pub(crate) fn which(name: &str) -> Option<PathBuf> {
    let file = if cfg!(windows) && !name.ends_with(".exe") { format!("{name}.exe") } else { name.to_string() };
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join(&file)).find(|p| p.is_file())
}
