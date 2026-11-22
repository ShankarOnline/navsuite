//! disks — drives, partitions, mount/eject and read-only raw file system access.
//!
//! * [`list_disks`] enumerates physical disks and their partitions (DB1), detects
//!   file systems by reading superblocks/boot sectors where the OS lets us, flags
//!   system/EFI/recovery partitions, hibernated NTFS (DB4) and OS installs (DB10),
//!   and attaches an [`Access`] policy (DB3).
//! * [`mount`], [`unmount`], [`eject`] (DB2) use native APIs: Win32 volume APIs +
//!   Configuration Manager on Windows, UDisks2 over D-Bus on Linux, and `diskutil`
//!   on macOS (documented fallback).
//! * [`RawFs`] (DB5/DB6) is a read-only view of an ext2/3/4 or NTFS partition read
//!   directly from the raw device. Raw access usually needs admin/root; on Windows
//!   the app can run [`helper_main`] elevated and talk to it via [`HelperClient`].
//!
//! Nothing in this crate writes to a partition or a raw device.

mod detect;
mod helper;
mod os;
mod policy;
mod rawdev;
mod rawfs;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

use serde::{Deserialize, Serialize};
use std::fmt;

pub use detect::{detect_fs, fs_from_gpt_type, fs_from_mbr_type, ntfs_hiberfil_is_hibernated};
pub use helper::{HelperClient, RemoteFs, helper_main};
pub use os::{UserFolder, detect_os_in_dir, user_folders};
pub use policy::{HIBERNATED_REASON, policy};
pub use rawfs::{MAX_READ, RawEntry, RawFs, RawProbe, probe_partition};

/// How a disk is attached.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Bus {
    Usb,
    Sata,
    Nvme,
    Sd,
    Scsi,
    Virtual,
    Other,
}

/// File system (or partition content) type.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub enum FsType {
    Ntfs,
    Ext2,
    Ext3,
    Ext4,
    Fat12,
    Fat16,
    Fat32,
    ExFat,
    HfsPlus,
    Apfs,
    Swap,
    Lvm,
    Bitlocker,
    Luks,
    Btrfs,
    Xfs,
    Refs,
    /// A Linux data partition whose exact file system could not be read
    /// (partition type says Linux, but the superblock was not accessible).
    Linux,
    Unknown,
}

impl FsType {
    pub fn is_ext(self) -> bool {
        matches!(self, FsType::Ext2 | FsType::Ext3 | FsType::Ext4)
    }
    pub fn is_fat(self) -> bool {
        matches!(self, FsType::Fat12 | FsType::Fat16 | FsType::Fat32 | FsType::ExFat)
    }
    /// Whether `RawFs` can read this type.
    pub fn raw_readable(self) -> bool {
        self.is_ext() || matches!(self, FsType::Ntfs | FsType::Linux)
    }
}

/// Access policy for a partition (DB3).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Access {
    ReadWrite,
    ReadOnly { reason: String },
}

impl Access {
    pub fn is_read_only(&self) -> bool {
        matches!(self, Access::ReadOnly { .. })
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum OsKind {
    Windows,
    Linux,
    Macos,
}

/// An operating system installation found on a partition (DB10).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OsInstall {
    pub kind: OsKind,
    /// e.g. "Windows 11", "Ubuntu 24.04.1 LTS", "macOS".
    pub name: String,
    /// e.g. "10.0.26100.2454", "24.04", "15.1".
    pub version: Option<String>,
    /// User account folder names (Public/Default/Shared etc. excluded).
    pub users: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Disk {
    /// Windows "disk0" (= PhysicalDrive0), Linux "sda"/"nvme0n1", macOS "disk0".
    pub id: String,
    pub model: String,
    pub bus: Bus,
    pub removable: bool,
    /// Bytes.
    pub size: u64,
    /// "gpt", "mbr" or "none".
    pub partition_style: String,
    /// Device path for raw reads, e.g. `\\.\PhysicalDrive0`, `/dev/sda`, `/dev/rdisk0`.
    pub raw_path: String,
    pub partitions: Vec<Partition>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Partition {
    /// Stable within a boot: Windows "disk0p3", Linux "sda1"/"nvme0n1p2", macOS "disk0s2".
    pub id: String,
    pub disk_id: String,
    /// 1-based partition number (0 = file system on the whole, unpartitioned disk).
    pub number: u32,
    pub label: Option<String>,
    pub fs: FsType,
    /// Bytes.
    pub size: u64,
    /// Free bytes, if mounted.
    pub free: Option<u64>,
    /// Primary mount point / drive letter (e.g. "C:\\", "/", "/Volumes/USB").
    pub mount: Option<String>,
    /// All mount points / drive letters.
    pub mounts: Vec<String>,
    /// Holds the currently running OS.
    pub is_system: bool,
    pub is_efi: bool,
    pub is_recovery: bool,
    /// NTFS with a hibernation / Fast Startup image (hiberfil.sys "hibr"/"wake").
    pub hibernated: bool,
    /// NTFS volume dirty flag set ($Volume) — only known when read raw.
    pub dirty: bool,
    pub os: Option<OsInstall>,
    pub access: Access,
    /// Device to open for raw reads (Windows: the physical drive, read at `offset`;
    /// Linux/macOS: the partition device, `offset` = 0).
    pub raw_path: String,
    /// Byte offset of the partition within `raw_path`.
    pub offset: u64,
    /// Windows volume GUID path (`\\?\Volume{…}\`), if any.
    pub volume: Option<String>,
    /// GPT type GUID (lowercase) or MBR type as "0x83".
    pub part_type: String,
    /// True when superblock/boot-sector probing was denied (not elevated), so
    /// fs/os/hibernation information may be incomplete.
    pub needs_admin: bool,
}

/// Errors. Serialized as `{ "type": "needsAdmin" }`, `{ "type": "busy", "processes": [...] }`, ...
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum DiskError {
    NeedsAdmin,
    NotFound,
    Unsupported { message: String },
    Busy { processes: Vec<String> },
    Io { message: String },
}

impl fmt::Display for DiskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiskError::NeedsAdmin => f.write_str("administrator rights are required"),
            DiskError::NotFound => f.write_str("not found"),
            DiskError::Unsupported { message } => write!(f, "unsupported: {message}"),
            DiskError::Busy { processes } if processes.is_empty() => {
                f.write_str("the drive is in use")
            }
            DiskError::Busy { processes } => {
                write!(f, "the drive is in use by: {}", processes.join(", "))
            }
            DiskError::Io { message } => f.write_str(message),
        }
    }
}

impl std::error::Error for DiskError {}

impl DiskError {
    pub(crate) fn unsupported(m: impl Into<String>) -> Self {
        DiskError::Unsupported { message: m.into() }
    }
    pub(crate) fn io(m: impl fmt::Display) -> Self {
        DiskError::Io { message: m.to_string() }
    }
}

impl From<std::io::Error> for DiskError {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::PermissionDenied => DiskError::NeedsAdmin,
            std::io::ErrorKind::NotFound => DiskError::NotFound,
            _ => DiskError::io(e),
        }
    }
}

/// List every disk and partition (DB1). Blocking; call from `spawn_blocking`.
pub fn list_disks() -> Result<Vec<Disk>, DiskError> {
    #[cfg(windows)]
    let mut disks = windows::list_disks()?;
    #[cfg(target_os = "linux")]
    let mut disks = linux::list_disks()?;
    #[cfg(target_os = "macos")]
    let mut disks = macos::list_disks()?;
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    let mut disks: Vec<Disk> = Vec::new();

    for d in &mut disks {
        for p in &mut d.partitions {
            enrich_partition(p);
        }
    }
    Ok(disks)
}

/// Fill in OS/hibernation info and the access policy for a partition whose
/// basic fields (fs, mount, flags) are known. Exposed so the app can re-run it
/// after refining a partition through the elevated helper.
pub fn enrich_partition(p: &mut Partition) {
    if let Some(m) = p.mount.clone() {
        let root = std::path::Path::new(&m);
        if p.os.is_none() {
            p.os = os::detect_os_in_dir(root);
        }
        if p.fs == FsType::Ntfs && !p.is_system && !p.hibernated {
            p.hibernated = os::mounted_hiberfil_hibernated(root);
        }
    }
    p.access = policy(p);
}

/// Apply the result of a raw probe (in-process or via the helper) to a partition.
pub fn apply_probe(p: &mut Partition, probe: &RawProbe) {
    if probe.fs != FsType::Unknown {
        p.fs = probe.fs;
    }
    if p.label.is_none() {
        p.label = probe.label.clone();
    }
    p.hibernated |= probe.hibernated;
    p.dirty |= probe.dirty;
    if p.os.is_none() {
        p.os = probe.os.clone();
    }
    p.needs_admin = false;
    p.access = policy(p);
}

pub(crate) fn find_partition(id: &str) -> Result<(Disk, Partition), DiskError> {
    for d in list_disks()? {
        if let Some(p) = d.partitions.iter().find(|p| p.id == id) {
            let p = p.clone();
            return Ok((d, p));
        }
    }
    Err(DiskError::NotFound)
}

/// Mount a partition (DB2). Returns the mount point / drive letter.
///
/// `read_only` is forced on when [`policy`] says the partition is read-only.
/// Linux (UDisks2) and macOS (`diskutil mount readOnly`) honour it at OS level.
/// Windows has no per-mount read-only switch, so a drive letter is assigned and
/// read-only is enforced by the app via [`Partition::access`]; hibernated/dirty
/// NTFS and foreign file systems are refused on Windows.
pub fn mount(partition_id: &str, read_only: bool) -> Result<String, DiskError> {
    let (_disk, p) = find_partition(partition_id)?;
    if let Some(m) = &p.mount {
        return Ok(m.clone());
    }
    let read_only = read_only || p.access.is_read_only();
    #[cfg(windows)]
    return windows::mount(&p, read_only);
    #[cfg(target_os = "linux")]
    return linux::mount(&p, read_only);
    #[cfg(target_os = "macos")]
    return macos::mount(&p, read_only);
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = read_only;
        Err(DiskError::unsupported("mounting is not supported on this OS"))
    }
}

/// Unmount a partition (DB2). Refuses the running system's partition.
pub fn unmount(partition_id: &str) -> Result<(), DiskError> {
    let (_disk, p) = find_partition(partition_id)?;
    if p.is_system {
        return Err(DiskError::unsupported("refusing to unmount the running system"));
    }
    if p.mount.is_none() {
        return Ok(());
    }
    #[cfg(windows)]
    return windows::unmount(&p);
    #[cfg(target_os = "linux")]
    return linux::unmount(&p);
    #[cfg(target_os = "macos")]
    return macos::unmount(&p);
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    Err(DiskError::unsupported("unmounting is not supported on this OS"))
}

/// Safely eject a removable disk (DB2): flush, dismount every volume, then
/// eject/power off. Returns `DiskError::Busy` with holder processes when refused.
pub fn eject(disk_id: &str) -> Result<(), DiskError> {
    let disk = list_disks()?
        .into_iter()
        .find(|d| d.id == disk_id)
        .ok_or(DiskError::NotFound)?;
    check_ejectable(&disk)?;
    #[cfg(windows)]
    return windows::eject(&disk);
    #[cfg(target_os = "linux")]
    return linux::eject(&disk);
    #[cfg(target_os = "macos")]
    return macos::eject(&disk);
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    Err(DiskError::unsupported("eject is not supported on this OS"))
}

/// Eject is only offered for removable/USB/SD disks that don't hold the running OS.
pub fn check_ejectable(disk: &Disk) -> Result<(), DiskError> {
    if disk.partitions.iter().any(|p| p.is_system) {
        return Err(DiskError::unsupported("this disk holds the running system"));
    }
    if !(disk.removable || matches!(disk.bus, Bus::Usb | Bus::Sd)) {
        return Err(DiskError::unsupported("only removable drives can be ejected"));
    }
    Ok(())
}

/// Whether the current process has admin/root rights (raw device access).
pub fn is_elevated() -> bool {
    #[cfg(windows)]
    return windows::is_elevated();
    #[cfg(unix)]
    // SAFETY: geteuid has no preconditions.
    return unsafe { libc_geteuid() } == 0;
    #[cfg(not(any(windows, unix)))]
    false
}

#[cfg(unix)]
unsafe extern "C" {
    #[link_name = "geteuid"]
    fn libc_geteuid() -> u32;
}

#[cfg(test)]
mod tests;
