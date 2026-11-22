//! macOS backend via `diskutil … -plist` (documented fallback instead of
//! DiskArbitration FFI): list, `mount readOnly`, `unmount`, `eject`.

use crate::detect::fs_from_gpt_type;
use crate::{Access, Bus, Disk, DiskError, FsType, Partition, apply_probe};
use plist::{Dictionary, Value};
use std::process::Command;

const DISKUTIL: &str = "/usr/sbin/diskutil";

fn diskutil(args: &[&str]) -> Result<std::process::Output, DiskError> {
    Command::new(DISKUTIL).args(args).output().map_err(DiskError::from)
}

fn plist_of(args: &[&str]) -> Option<Dictionary> {
    let out = diskutil(args).ok()?;
    if !out.status.success() {
        return None;
    }
    Value::from_reader(std::io::Cursor::new(out.stdout)).ok()?.into_dictionary()
}

fn s<'a>(d: &'a Dictionary, k: &str) -> Option<&'a str> {
    d.get(k).and_then(Value::as_string).filter(|v| !v.is_empty())
}
fn u(d: &Dictionary, k: &str) -> Option<u64> {
    d.get(k).and_then(Value::as_unsigned_integer)
}
fn b(d: &Dictionary, k: &str) -> bool {
    d.get(k).and_then(Value::as_boolean).unwrap_or(false)
}

fn fs_from_info(info: &Dictionary) -> FsType {
    let t = s(info, "FilesystemType").unwrap_or("").to_ascii_lowercase();
    let personality = s(info, "FilesystemUserVisibleName").unwrap_or("").to_ascii_lowercase();
    match t.as_str() {
        "apfs" => FsType::Apfs,
        "hfs" => FsType::HfsPlus,
        "exfat" => FsType::ExFat,
        "ntfs" => FsType::Ntfs,
        "msdos" if personality.contains("fat12") => FsType::Fat12,
        "msdos" if personality.contains("fat16") => FsType::Fat16,
        "msdos" => FsType::Fat32,
        _ => match s(info, "Content").unwrap_or("") {
            "Apple_APFS" => FsType::Apfs,
            "Apple_HFS" => FsType::HfsPlus,
            "Linux" | "Linux Filesystem" => FsType::Linux,
            "Linux_Swap" | "Linux Swap" => FsType::Swap,
            "Linux_LVM" => FsType::Lvm,
            c => fs_from_gpt_type(c).fs,
        },
    }
}

fn bus_of(info: &Dictionary) -> Bus {
    match s(info, "BusProtocol").unwrap_or("") {
        "USB" => Bus::Usb,
        "SATA" => Bus::Sata,
        "PCI-Express" | "Apple Fabric" | "NVMe" => Bus::Nvme,
        "Secure Digital" => Bus::Sd,
        "Disk Image" | "Virtual Interface" => Bus::Virtual,
        "SAS" | "SCSI" => Bus::Scsi,
        _ => Bus::Other,
    }
}

fn partition_from(disk_id: &str, id: &str, info: &Dictionary) -> Partition {
    let content = s(info, "Content").unwrap_or("").to_string();
    let hint = fs_from_gpt_type(&content);
    let mount = s(info, "MountPoint").map(str::to_string);
    let is_efi = hint.efi || content == "EFI";
    let is_recovery = hint.recovery || content == "Apple_Boot" || s(info, "APFSRole") == Some("Recovery");
    let number = id.rsplit('s').next().and_then(|n| n.parse().ok()).unwrap_or(0);
    Partition {
        id: id.to_string(),
        disk_id: disk_id.to_string(),
        number,
        label: s(info, "VolumeName").map(str::to_string),
        fs: fs_from_info(info),
        size: u(info, "Size").or_else(|| u(info, "TotalSize")).unwrap_or(0),
        free: mount.as_ref().and(u(info, "APFSContainerFree").or_else(|| u(info, "FreeSpace"))),
        is_system: matches!(mount.as_deref(), Some("/") | Some("/System/Volumes/Data")),
        mounts: mount.iter().cloned().collect(),
        mount,
        is_efi,
        is_recovery,
        hibernated: false,
        dirty: false,
        os: None,
        access: Access::ReadWrite,
        raw_path: format!("/dev/r{id}"),
        offset: 0,
        volume: s(info, "VolumeUUID").map(str::to_string),
        part_type: content,
        needs_admin: false,
    }
}

pub(crate) fn list_disks() -> Result<Vec<Disk>, DiskError> {
    let list = plist_of(&["list", "-plist"]).ok_or_else(|| DiskError::io("diskutil list failed"))?;
    let entries = list.get("AllDisksAndPartitions").and_then(Value::as_array).cloned().unwrap_or_default();
    let mut disks = Vec::new();
    for e in entries.iter().filter_map(Value::as_dictionary) {
        let Some(id) = s(e, "DeviceIdentifier") else { continue };
        let info = plist_of(&["info", "-plist", id]).unwrap_or_default();
        let children: Vec<&Dictionary> = e
            .get("Partitions")
            .and_then(Value::as_array)
            .into_iter()
            .chain(e.get("APFSVolumes").and_then(Value::as_array))
            .flatten()
            .filter_map(Value::as_dictionary)
            .collect();
        let mut parts = Vec::new();
        for c in children {
            let Some(pid) = s(c, "DeviceIdentifier") else { continue };
            let pinfo = plist_of(&["info", "-plist", pid]).unwrap_or_else(|| c.clone());
            let mut p = partition_from(id, pid, &pinfo);
            // A snapshot of this volume mounted at "/" means it's the running system.
            if let Some(snaps) = c.get("MountedSnapshots").and_then(Value::as_array)
                && snaps.iter().filter_map(Value::as_dictionary).any(|d| s(d, "SnapshotMountPoint") == Some("/"))
            {
                p.is_system = true;
                p.mount.get_or_insert_with(|| "/".into());
            }
            if p.mount.is_none() && p.fs.raw_readable() {
                match crate::rawfs::probe_partition(&p) {
                    Ok(probe) => apply_probe(&mut p, &probe),
                    Err(DiskError::NeedsAdmin) => p.needs_admin = true,
                    Err(_) => {}
                }
            }
            parts.push(p);
        }
        let apfs_container = e.contains_key("APFSPhysicalStores");
        disks.push(Disk {
            id: id.to_string(),
            model: if apfs_container {
                "APFS Container".into()
            } else {
                s(&info, "MediaName").or(s(&info, "IORegistryEntryName")).unwrap_or("").to_string()
            },
            bus: if apfs_container { Bus::Virtual } else { bus_of(&info) },
            removable: b(&info, "Removable") || b(&info, "RemovableMedia") || b(&info, "Ejectable"),
            size: u(e, "Size").or_else(|| u(&info, "Size")).unwrap_or(0),
            partition_style: match s(e, "Content") {
                Some("GUID_partition_scheme") => "gpt",
                Some("FDisk_partition_scheme") => "mbr",
                _ => "none",
            }
            .into(),
            raw_path: format!("/dev/r{id}"),
            partitions: parts,
        });
    }
    Ok(disks)
}

fn fail(out: &std::process::Output) -> DiskError {
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    let procs = dissenters(&text);
    if !procs.is_empty() || text.contains("dissented") || text.contains("in use") {
        DiskError::Busy { processes: procs }
    } else if text.contains("Not privileged") || text.contains("not permitted") {
        DiskError::NeedsAdmin
    } else {
        DiskError::io(text.trim().to_string())
    }
}

/// "… dissented by PID 123 (/Applications/Foo.app/Contents/MacOS/Foo)" -> "Foo (pid 123)".
pub(crate) fn dissenters(text: &str) -> Vec<String> {
    let mut v = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find("PID ") {
        rest = &rest[i + 4..];
        let pid: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if pid.is_empty() {
            continue;
        }
        let name = rest
            .find('(')
            .zip(rest.find(')'))
            .filter(|(a, b)| a < b)
            .map(|(a, b)| rest[a + 1..b].rsplit('/').next().unwrap_or("").to_string())
            .unwrap_or_default();
        v.push(if name.is_empty() { format!("pid {pid}") } else { format!("{name} (pid {pid})") });
    }
    v
}

pub(crate) fn mount(p: &Partition, read_only: bool) -> Result<String, DiskError> {
    let args: Vec<&str> = if read_only { vec!["mount", "readOnly", &p.id] } else { vec!["mount", &p.id] };
    let out = diskutil(&args)?;
    if !out.status.success() {
        return Err(fail(&out));
    }
    plist_of(&["info", "-plist", &p.id])
        .and_then(|i| s(&i, "MountPoint").map(str::to_string))
        .ok_or_else(|| DiskError::io("mounted, but no mount point reported"))
}

pub(crate) fn unmount(p: &Partition) -> Result<(), DiskError> {
    let out = diskutil(&["unmount", &p.id])?;
    if out.status.success() { Ok(()) } else { Err(fail(&out)) }
}

pub(crate) fn eject(disk: &Disk) -> Result<(), DiskError> {
    let out = diskutil(&["eject", &disk.id])?;
    if out.status.success() { Ok(()) } else { Err(fail(&out)) }
}

#[cfg(test)]
mod tests {
    #[test]
    fn dissenter_parsing() {
        let t = "Unmount of disk4 failed: at least one volume could not be unmounted\n\
                 Unmount was dissented by PID 812 (/Applications/Preview.app/Contents/MacOS/Preview)";
        assert_eq!(super::dissenters(t), vec!["Preview (pid 812)".to_string()]);
    }
}
