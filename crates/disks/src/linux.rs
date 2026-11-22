//! Linux backend: sysfs + the udev database (readable without root) for
//! listing, /proc/self/mountinfo for mounts, UDisks2 over D-Bus (zbus) for
//! mount/unmount/eject — no root needed for removable media under polkit.

use crate::detect::{fs_from_gpt_type, fs_from_mbr_type};
use crate::{Access, Bus, Disk, DiskError, FsType, Partition, apply_probe};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

fn read(p: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

/// `E:KEY=VALUE` lines from /run/udev/data/b<maj>:<min>.
fn udev_props(devnum: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    if let Some(s) = read(format!("/run/udev/data/b{devnum}")) {
        for l in s.lines() {
            if let Some((k, v)) = l.strip_prefix("E:").and_then(|r| r.split_once('=')) {
                m.insert(k.to_string(), v.to_string());
            }
        }
    }
    m
}

/// Decode udev's `\x20` escapes (ID_FS_LABEL_ENC).
fn udev_unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && b[i + 1] == b'x'
            && let Ok(v) = u8::from_str_radix(&s[i + 2..i + 4], 16)
        {
            out.push(v);
            i += 4;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// mountinfo escapes space/tab/newline/backslash as octal.
fn mount_unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 4], 8)
        {
            out.push(v);
            i += 4;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// device kernel name -> mount points ("/" first if present).
pub(crate) fn parse_mountinfo(text: &str) -> HashMap<String, Vec<String>> {
    let mut m: HashMap<String, Vec<String>> = HashMap::new();
    for l in text.lines() {
        let f: Vec<&str> = l.split(' ').collect();
        let Some(sep) = f.iter().position(|x| *x == "-") else { continue };
        let (Some(mp), Some(src)) = (f.get(4), f.get(sep + 2)) else { continue };
        // Only the subvolume/bind root "/" is the device's real mount.
        if f.get(3) != Some(&"/") && !src.starts_with("/dev/") {
            continue;
        }
        if let Some(dev) = src.strip_prefix("/dev/") {
            let real = fs::canonicalize(src).ok();
            let name = real
                .as_deref()
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| dev.rsplit('/').next().unwrap_or(dev).to_string());
            let v = m.entry(name).or_default();
            let mp = mount_unescape(mp);
            if !v.contains(&mp) {
                if mp == "/" { v.insert(0, mp) } else { v.push(mp) }
            }
        }
    }
    m
}

fn fs_from_udev(p: &HashMap<String, String>) -> FsType {
    match p.get("ID_FS_TYPE").map(String::as_str) {
        Some("ext2") => FsType::Ext2,
        Some("ext3") => FsType::Ext3,
        Some("ext4") => FsType::Ext4,
        Some("vfat") => match p.get("ID_FS_VERSION").map(String::as_str) {
            Some("FAT12") => FsType::Fat12,
            Some("FAT16") => FsType::Fat16,
            _ => FsType::Fat32,
        },
        Some("exfat") => FsType::ExFat,
        Some("ntfs") | Some("ntfs3") => FsType::Ntfs,
        Some("hfsplus") => FsType::HfsPlus,
        Some("apfs") => FsType::Apfs,
        Some("swap") => FsType::Swap,
        Some("LVM2_member") => FsType::Lvm,
        Some("crypto_LUKS") => FsType::Luks,
        Some("BitLocker") => FsType::Bitlocker,
        Some("btrfs") => FsType::Btrfs,
        Some("xfs") => FsType::Xfs,
        Some("refs") => FsType::Refs,
        _ => FsType::Unknown,
    }
}

fn statvfs_free(path: &str) -> Option<u64> {
    let c = std::ffi::CString::new(path).ok()?;
    // SAFETY: valid C string and out struct.
    unsafe {
        let mut s: libc::statvfs = std::mem::zeroed();
        (libc::statvfs(c.as_ptr(), &mut s) == 0).then(|| s.f_bavail as u64 * s.f_frsize as u64)
    }
}

fn bus_of(name: &str, sys: &Path, props: &HashMap<String, String>) -> Bus {
    let real = fs::canonicalize(sys).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    if real.contains("/usb") || props.get("ID_BUS").is_some_and(|b| b == "usb") {
        Bus::Usb
    } else if name.starts_with("nvme") {
        Bus::Nvme
    } else if name.starts_with("mmcblk") {
        Bus::Sd
    } else if real.contains("/virtio") || name.starts_with("vd") || name.starts_with("xvd") {
        Bus::Virtual
    } else if real.contains("/ata") {
        Bus::Sata
    } else if name.starts_with("sd") {
        Bus::Scsi
    } else {
        Bus::Other
    }
}

pub(crate) fn list_disks() -> Result<Vec<Disk>, DiskError> {
    let mounts = parse_mountinfo(&read("/proc/self/mountinfo").unwrap_or_default());
    let mut disks = Vec::new();
    let mut names: Vec<String> = fs::read_dir("/sys/block")?
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| {
            !["loop", "ram", "zram", "dm-", "sr", "md", "nbd", "fd"].iter().any(|p| n.starts_with(p))
                && !n.contains("boot")
                && !n.contains("rpmb")
        })
        .collect();
    names.sort();
    for name in names {
        let sys = Path::new("/sys/block").join(&name);
        let size = read(sys.join("size")).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0) * 512;
        if size == 0 {
            continue;
        }
        let dprops = udev_props(&read(sys.join("dev")).unwrap_or_default());
        let model = {
            let vendor = read(sys.join("device/vendor")).unwrap_or_default();
            let model = read(sys.join("device/model")).or_else(|| read(sys.join("device/name"))).unwrap_or_default();
            [vendor, model].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" ")
        };
        let bus = bus_of(&name, &sys, &dprops);
        let removable = read(sys.join("removable")).as_deref() == Some("1");
        let style = match dprops.get("ID_PART_TABLE_TYPE").map(String::as_str) {
            Some("gpt") => "gpt",
            Some("dos") => "mbr",
            _ => "none",
        };
        let mut pnames: Vec<(u32, String)> = fs::read_dir(&sys)?
            .flatten()
            .filter_map(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                let num = read(e.path().join("partition"))?.parse().ok()?;
                Some((num, n))
            })
            .collect();
        pnames.sort();
        let whole_disk_fs = pnames.is_empty() && dprops.contains_key("ID_FS_TYPE");
        if whole_disk_fs {
            pnames.push((0, name.clone()));
        }
        let mut parts = Vec::new();
        for (number, pname) in pnames {
            let psys = if number == 0 { sys.clone() } else { sys.join(&pname) };
            let props = if number == 0 { dprops.clone() } else { udev_props(&read(psys.join("dev")).unwrap_or_default()) };
            let psize = read(psys.join("size")).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0) * 512;
            let part_type = props.get("ID_PART_ENTRY_TYPE").cloned().unwrap_or_default();
            let hint = match part_type.strip_prefix("0x") {
                Some(hex) => u8::from_str_radix(hex, 16).map(fs_from_mbr_type).unwrap_or(fs_from_mbr_type(0)),
                None => fs_from_gpt_type(&part_type),
            };
            if hint.container {
                continue;
            }
            let mut fs = fs_from_udev(&props);
            if fs == FsType::Unknown {
                fs = hint.fs;
            }
            let label = props
                .get("ID_FS_LABEL_ENC")
                .map(|s| udev_unescape(s))
                .or_else(|| props.get("ID_FS_LABEL").cloned())
                .filter(|s| !s.is_empty());
            let pm = mounts.get(&pname).cloned().unwrap_or_default();
            let mount = pm.first().cloned();
            let mut p = Partition {
                id: pname.clone(),
                disk_id: name.clone(),
                number,
                label,
                fs,
                size: psize,
                free: mount.as_deref().and_then(statvfs_free),
                is_system: pm.iter().any(|m| m == "/"),
                mount,
                mounts: pm,
                is_efi: hint.efi,
                is_recovery: hint.recovery,
                hibernated: false,
                dirty: false,
                os: None,
                access: Access::ReadWrite,
                raw_path: format!("/dev/{pname}"),
                offset: 0,
                volume: None,
                part_type,
                needs_admin: false,
            };
            // Raw probe for unmounted ext*/NTFS (OS + hibernation) or unknown types.
            if p.mount.is_none() && (p.fs.raw_readable() || p.fs == FsType::Unknown) && !p.is_efi {
                match crate::rawfs::probe_partition(&p) {
                    Ok(probe) => apply_probe(&mut p, &probe),
                    Err(DiskError::NeedsAdmin) => p.needs_admin = true,
                    Err(_) => {}
                }
            }
            parts.push(p);
        }
        disks.push(Disk {
            id: name.clone(),
            model,
            bus,
            removable,
            size,
            partition_style: style.into(),
            raw_path: format!("/dev/{name}"),
            partitions: parts,
        });
    }
    Ok(disks)
}

// ---- UDisks2 ------------------------------------------------------------------

const UDISKS: &str = "org.freedesktop.UDisks2";

/// D-Bus object path element escaping used by UDisks2 (non-alnum -> _XX).
fn udisks_block_path(name: &str) -> String {
    let mut s = String::from("/org/freedesktop/UDisks2/block_devices/");
    for b in name.bytes() {
        if b.is_ascii_alphanumeric() {
            s.push(b as char);
        } else {
            s.push_str(&format!("_{b:02x}"));
        }
    }
    s
}

fn dbus_err(e: zbus::Error) -> DiskError {
    let msg = e.to_string();
    if msg.contains("NotAuthorized") || msg.contains("AccessDenied") {
        DiskError::NeedsAdmin
    } else if msg.contains("DeviceBusy") || msg.contains("target is busy") {
        DiskError::Busy { processes: Vec::new() }
    } else if msg.contains("UnknownObject") || msg.contains("UnknownMethod") {
        DiskError::NotFound
    } else {
        DiskError::io(format!("UDisks2: {msg}"))
    }
}

fn proxy<'a>(conn: &'a zbus::blocking::Connection, path: &'a str, iface: &'a str) -> Result<zbus::blocking::Proxy<'a>, DiskError> {
    zbus::blocking::Proxy::new(conn, UDISKS, path, iface).map_err(dbus_err)
}

type Opts<'a> = HashMap<&'a str, zbus::zvariant::Value<'a>>;

pub(crate) fn mount(p: &Partition, read_only: bool) -> Result<String, DiskError> {
    let conn = zbus::blocking::Connection::system().map_err(dbus_err)?;
    let path = udisks_block_path(&p.id);
    let fsp = proxy(&conn, &path, "org.freedesktop.UDisks2.Filesystem")?;
    let mut opts: Opts = HashMap::new();
    if read_only {
        opts.insert("options", zbus::zvariant::Value::from("ro"));
    }
    fsp.call::<_, _, String>("Mount", &(opts,)).map_err(dbus_err)
}

fn unmount_one(conn: &zbus::blocking::Connection, p: &Partition) -> Result<(), DiskError> {
    let path = udisks_block_path(&p.id);
    let fsp = proxy(conn, &path, "org.freedesktop.UDisks2.Filesystem")?;
    let opts: Opts = HashMap::new();
    fsp.call::<_, _, ()>("Unmount", &(opts,)).map_err(|e| match dbus_err(e) {
        DiskError::Busy { .. } => DiskError::Busy { processes: holders(&p.mounts) },
        other => other,
    })
}

pub(crate) fn unmount(p: &Partition) -> Result<(), DiskError> {
    let conn = zbus::blocking::Connection::system().map_err(dbus_err)?;
    unmount_one(&conn, p)
}

pub(crate) fn eject(disk: &Disk) -> Result<(), DiskError> {
    let conn = zbus::blocking::Connection::system().map_err(dbus_err)?;
    for p in disk.partitions.iter().filter(|p| p.mount.is_some()) {
        unmount_one(&conn, p)?;
    }
    let bpath = udisks_block_path(&disk.id);
    let block = proxy(&conn, &bpath, "org.freedesktop.UDisks2.Block")?;
    let drive: zbus::zvariant::OwnedObjectPath = block.get_property("Drive").map_err(dbus_err)?;
    let dpath = drive.as_str().to_string();
    if dpath == "/" {
        return Err(DiskError::NotFound);
    }
    let dp = proxy(&conn, &dpath, "org.freedesktop.UDisks2.Drive")?;
    let opts: Opts = HashMap::new();
    if dp.get_property::<bool>("Ejectable").unwrap_or(false) {
        dp.call::<_, _, ()>("Eject", &(opts,)).map_err(dbus_err)?;
    }
    if dp.get_property::<bool>("CanPowerOff").unwrap_or(false) {
        let opts: Opts = HashMap::new();
        dp.call::<_, _, ()>("PowerOff", &(opts,)).map_err(dbus_err)?;
    }
    Ok(())
}

/// Processes (that we can see) with open files or cwd under any of `mounts`.
fn holders(mounts: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir("/proc") else { return out };
    for e in rd.flatten() {
        let pid = e.file_name().to_string_lossy().into_owned();
        if !pid.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let under = |t: &Path| {
            let t = t.to_string_lossy();
            mounts.iter().any(|m| t == m.as_str() || t.starts_with(&format!("{}/", m.trim_end_matches('/'))))
        };
        let mut hit = fs::read_link(e.path().join("cwd")).is_ok_and(|t| under(&t));
        if !hit && let Ok(fds) = fs::read_dir(e.path().join("fd")) {
            hit = fds.flatten().any(|fd| fs::read_link(fd.path()).is_ok_and(|t| under(&t)));
        }
        if hit {
            let comm = read(e.path().join("comm")).unwrap_or_default();
            out.push(format!("{comm} (pid {pid})"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn mountinfo_parsing() {
        let t = "22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/nonexistent2 rw\n\
                 30 22 8:17 / /media/me/My\\040USB rw - vfat /dev/nonexistent17 rw\n";
        let m = super::parse_mountinfo(t);
        assert_eq!(m["nonexistent2"], vec!["/".to_string()]);
        assert_eq!(m["nonexistent17"], vec!["/media/me/My USB".to_string()]);
        assert_eq!(super::udisks_block_path("sda1"), "/org/freedesktop/UDisks2/block_devices/sda1");
        assert_eq!(super::udev_unescape("My\\x20Disk"), "My Disk");
    }
}
