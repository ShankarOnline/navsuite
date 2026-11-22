//! Serializable error type shared by every backend.

use serde::{Deserialize, Serialize};
use std::fmt;

/// What went wrong, in a form the UI can act on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ErrorKind {
    NotFound,
    PermissionDenied,
    /// The host wants credentials (none stored, or the stored ones were refused).
    #[serde(rename_all = "camelCase")]
    AuthRequired {
        host: String,
        user: Option<String>,
    },
    /// SSH host key not in any known_hosts file. Show the fingerprint and call
    /// `Vfs::trust_host_key(host, port, key_openssh)` if the user accepts it.
    #[serde(rename_all = "camelCase")]
    HostKeyUnknown {
        host: String,
        port: u16,
        fingerprint: String,
        key_openssh: String,
    },
    /// Host unreachable, connection dropped or timed out. Transient: worth retrying.
    Offline,
    Unsupported,
    /// Target already exists (or a host key changed, see message).
    Conflict,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VfsError {
    pub kind: ErrorKind,
    pub message: String,
}

pub type Result<T> = std::result::Result<T, VfsError>;

impl VfsError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
    pub fn not_found(m: impl Into<String>) -> Self {
        Self::new(ErrorKind::NotFound, m)
    }
    pub fn unsupported(m: impl Into<String>) -> Self {
        Self::new(ErrorKind::Unsupported, m)
    }
    pub fn offline(m: impl Into<String>) -> Self {
        Self::new(ErrorKind::Offline, m)
    }
    pub fn conflict(m: impl Into<String>) -> Self {
        Self::new(ErrorKind::Conflict, m)
    }
    pub fn other(m: impl Into<String>) -> Self {
        Self::new(ErrorKind::Other, m)
    }
    /// True for errors where retrying later may succeed (network trouble).
    pub fn is_transient(&self) -> bool {
        matches!(self.kind, ErrorKind::Offline)
    }
    /// Prefix the message with some context (usually the path).
    pub fn context(mut self, ctx: impl fmt::Display) -> Self {
        self.message = format!("{ctx}: {}", self.message);
        self
    }
}

impl fmt::Display for VfsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for VfsError {}

/// Windows error codes / errno values that mean "the network is the problem".
fn os_code_is_network(code: i32) -> bool {
    #[cfg(windows)]
    {
        // ERROR_NETNAME_DELETED 64, ERROR_UNEXP_NET_ERR 59, ERROR_BAD_NETPATH 53,
        // ERROR_SEM_TIMEOUT 121, ERROR_NETWORK_UNREACHABLE 1231, ERROR_HOST_UNREACHABLE 1232,
        // ERROR_CONNECTION_ABORTED 1236, ERROR_NOT_CONNECTED 2250, ERROR_NETWORK_BUSY 54,
        // ERROR_REM_NOT_LIST 51, ERROR_DEV_NOT_EXIST 55
        matches!(
            code,
            51 | 53 | 54 | 55 | 59 | 64 | 121 | 1231 | 1232 | 1236 | 2250
        )
    }
    #[cfg(unix)]
    {
        matches!(
            code,
            libc::ENETDOWN
                | libc::ENETUNREACH
                | libc::EHOSTUNREACH
                | libc::EHOSTDOWN
                | libc::ETIMEDOUT
                | libc::ECONNRESET
                | libc::ECONNABORTED
                | libc::ENOTCONN
                | libc::EPIPE
        )
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = code;
        false
    }
}

impl From<std::io::Error> for VfsError {
    fn from(e: std::io::Error) -> Self {
        use std::io::ErrorKind as K;
        let kind = match e.kind() {
            K::NotFound => ErrorKind::NotFound,
            K::PermissionDenied => ErrorKind::PermissionDenied,
            K::AlreadyExists => ErrorKind::Conflict,
            K::Unsupported => ErrorKind::Unsupported,
            K::TimedOut
            | K::ConnectionRefused
            | K::ConnectionReset
            | K::ConnectionAborted
            | K::NotConnected
            | K::BrokenPipe
            | K::UnexpectedEof
            | K::HostUnreachable
            | K::NetworkUnreachable
            | K::NetworkDown => ErrorKind::Offline,
            _ if e.raw_os_error().is_some_and(os_code_is_network) => ErrorKind::Offline,
            _ => ErrorKind::Other,
        };
        VfsError::new(kind, e.to_string())
    }
}

impl From<tokio::task::JoinError> for VfsError {
    fn from(e: tokio::task::JoinError) -> Self {
        VfsError::other(format!("background task failed: {e}"))
    }
}

impl From<tokio::time::error::Elapsed> for VfsError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        VfsError::offline("timed out")
    }
}
