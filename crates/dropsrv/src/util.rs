//! Small helpers: randomness, hashing, file-name sanitising, user-agent
//! sniffing, free disk space, time.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// `n` random bytes from the OS CSPRNG, hex encoded.
pub fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).expect("OS random source unavailable");
    hex::encode(b)
}

/// Human-friendly join code alphabet (no 0/O/1/I).
const CODE_ALPHABET: &[u8; 32] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

/// 8-character code (40 bits) from the OS CSPRNG.
pub fn random_code() -> String {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).expect("OS random source unavailable");
    b.iter().map(|x| CODE_ALPHABET[usize::from(x & 31)] as char).collect()
}

/// Normalise user-typed join codes: uppercase, drop separators.
pub fn normalize_code(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// SHA-256 of a file, streaming. Blocking: call from `spawn_blocking`.
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

const RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Make an uploaded file name safe on every OS: last path component only,
/// no control or reserved characters, no leading/trailing dots or spaces,
/// no Windows device names, at most 180 bytes (keeping the extension).
pub fn sanitize_file_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let mut s: String = base
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*') {
                '_'
            } else {
                c
            }
        })
        .collect();
    s = s.trim_matches(|c: char| c == '.' || c.is_whitespace()).to_string();
    if s.is_empty() {
        return "file".into();
    }
    let stem = s.split('.').next().unwrap_or("").trim().to_ascii_uppercase();
    if RESERVED.contains(&stem.as_str()) {
        s = format!("_{s}");
    }
    const MAX: usize = 180;
    if s.len() > MAX {
        let (stem, ext) = match s.rfind('.') {
            Some(i) if s.len() - i <= 16 => (s[..i].to_string(), s[i..].to_string()),
            _ => (s.clone(), String::new()),
        };
        let mut cut = MAX - ext.len();
        while !stem.is_char_boundary(cut) {
            cut -= 1;
        }
        s = format!("{}{}", &stem[..cut], ext);
    }
    s
}

/// `dir/name`, or `dir/name (2).ext` etc. if taken.
pub fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    if !p.exists() {
        return p;
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    for n in 2..10_000 {
        let p = dir.join(format!("{stem} ({n}){ext}"));
        if !p.exists() {
            return p;
        }
    }
    dir.join(format!("{stem}-{}{ext}", random_hex(4)))
}

/// Platform + default device name from a User-Agent header.
pub fn sniff_user_agent(ua: &str) -> (&'static str, &'static str) {
    if ua.contains("iPhone") || ua.contains("iPod") {
        ("ios", "iPhone")
    } else if ua.contains("iPad") {
        ("ios", "iPad")
    } else if ua.contains("Android") {
        if ua.contains("Mobile") {
            ("android", "Android phone")
        } else {
            ("android", "Android tablet")
        }
    } else {
        ("other", "Browser")
    }
}

/// Bytes available to this user on the volume holding `path`.
#[cfg(windows)]
pub fn free_space(path: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let mut avail: u64 = 0;
    // SAFETY: NUL-terminated wide path; out pointer valid; others may be null.
    let ok = unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut avail, std::ptr::null_mut(), std::ptr::null_mut()) };
    (ok != 0).then_some(avail)
}

#[cfg(unix)]
pub fn free_space(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: zeroed statvfs is valid; c is NUL-terminated.
    unsafe {
        let mut st: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c.as_ptr(), &mut st) != 0 {
            return None;
        }
        #[allow(clippy::unnecessary_cast)]
        Some(st.f_bavail as u64 * st.f_frsize as u64)
    }
}

#[cfg(not(any(unix, windows)))]
pub fn free_space(_path: &Path) -> Option<u64> {
    None
}

/// RFC 6266 / 5987 Content-Disposition value for a download.
pub fn content_disposition(name: &str) -> String {
    use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
    let ascii: String = name
        .chars()
        .map(|c| if c.is_ascii() && !c.is_ascii_control() && c != '"' && c != '\\' { c } else { '_' })
        .collect();
    format!(
        "attachment; filename=\"{ascii}\"; filename*=UTF-8''{}",
        utf8_percent_encode(name, NON_ALPHANUMERIC)
    )
}

/// Parse a single `bytes=a-b` / `bytes=a-` / `bytes=-n` range against `len`.
/// Returns inclusive (start, end), `Err(())` if unsatisfiable, `Ok(None)` if absent/unsupported.
#[allow(clippy::result_unit_err)]
pub fn parse_range(h: Option<&str>, len: u64) -> Result<Option<(u64, u64)>, ()> {
    let Some(h) = h else { return Ok(None) };
    let Some(spec) = h.trim().strip_prefix("bytes=") else { return Ok(None) };
    if spec.contains(',') {
        return Ok(None); // multi-range: serve whole file
    }
    let (a, b) = spec.split_once('-').ok_or(())?;
    let (a, b) = (a.trim(), b.trim());
    if len == 0 {
        return Err(());
    }
    let (start, end) = if a.is_empty() {
        let n: u64 = b.parse().map_err(|_| ())?;
        if n == 0 {
            return Err(());
        }
        (len.saturating_sub(n), len - 1)
    } else {
        let s: u64 = a.parse().map_err(|_| ())?;
        let e = if b.is_empty() { len - 1 } else { b.parse::<u64>().map_err(|_| ())?.min(len - 1) };
        (s, e)
    };
    if start > end || start >= len {
        return Err(());
    }
    Ok(Some((start, end)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize() {
        assert_eq!(sanitize_file_name("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_file_name("..\\..\\Windows\\win.ini"), "win.ini");
        assert_eq!(sanitize_file_name("C:\\x\\a<b>c?.txt"), "a_b_c_.txt");
        assert_eq!(sanitize_file_name(".."), "file");
        assert_eq!(sanitize_file_name("  .hidden  "), "hidden");
        assert_eq!(sanitize_file_name(""), "file");
        assert_eq!(sanitize_file_name("CON.txt"), "_CON.txt");
        assert_eq!(sanitize_file_name("nul"), "_nul");
        assert_eq!(sanitize_file_name("a\u{0}b\nc.jpg"), "a_b_c.jpg");
        assert_eq!(sanitize_file_name("IMG_0001.HEIC"), "IMG_0001.HEIC");
        assert_eq!(sanitize_file_name("फ़ोटो 1.png"), "फ़ोटो 1.png");
        let long = format!("{}.jpeg", "é".repeat(200));
        let s = sanitize_file_name(&long);
        assert!(s.len() <= 180 && s.ends_with(".jpeg"), "{s}");
    }

    #[test]
    fn ua() {
        let ios = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15";
        assert_eq!(sniff_user_agent(ios), ("ios", "iPhone"));
        let and = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/120 Mobile Safari/537.36";
        assert_eq!(sniff_user_agent(and), ("android", "Android phone"));
        assert_eq!(sniff_user_agent("curl/8"), ("other", "Browser"));
    }

    #[test]
    fn ranges() {
        assert_eq!(parse_range(None, 10), Ok(None));
        assert_eq!(parse_range(Some("bytes=0-"), 10), Ok(Some((0, 9))));
        assert_eq!(parse_range(Some("bytes=4-6"), 10), Ok(Some((4, 6))));
        assert_eq!(parse_range(Some("bytes=-3"), 10), Ok(Some((7, 9))));
        assert_eq!(parse_range(Some("bytes=5-100"), 10), Ok(Some((5, 9))));
        assert_eq!(parse_range(Some("bytes=10-"), 10), Err(()));
        assert_eq!(parse_range(Some("bytes=0-1,4-5"), 10), Ok(None));
    }

    #[test]
    fn codes() {
        let c = random_code();
        assert_eq!(c.len(), 8);
        assert_eq!(normalize_code(&format!("{}-{}", &c[..4], &c[4..]).to_lowercase()), c);
        assert_eq!(random_hex(16).len(), 32);
    }

    #[test]
    fn disposition() {
        assert_eq!(
            content_disposition("a b\"é.txt"),
            "attachment; filename=\"a b__.txt\"; filename*=UTF-8''a%20b%22%C3%A9%2Etxt"
        );
    }
}
