//! Windows backend: physical drives via IOCTLs (no WMI), volumes via the Win32
//! volume APIs, mount points via SetVolumeMountPointW, eject via
//! FSCTL_LOCK/DISMOUNT + CM_Request_Device_EjectW, and the elevated helper pipe.
//!
//! Every handle opened on a disk for listing uses desired access 0 (metadata
//! only). Raw reads go through `rawdev` (GENERIC_READ). Only `eject` opens a
//! *removable* volume with write access, solely to flush/lock/dismount it.

use crate::detect::{fs_from_gpt_type, fs_from_mbr_type, guid_to_string};
use crate::{Bus, Disk, DiskError, FsType, Partition, apply_probe};
use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::{offset_of, size_of};
use std::os::windows::io::FromRawHandle;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Devices::DeviceAndDriverInstallation::*;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::{TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation, GetTokenInformation};
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::EventLog::*;
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::Ioctl::*;
use windows_sys::Win32::System::Pipes::*;
use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::UI::Shell::{SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wide(b: &[u16]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf16_lossy(&b[..end])
}

fn last_error() -> u32 {
    // SAFETY: no preconditions.
    unsafe { GetLastError() }
}

fn win_err(what: &str) -> DiskError {
    let code = last_error();
    match code {
        ERROR_ACCESS_DENIED => DiskError::NeedsAdmin,
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => DiskError::NotFound,
        _ => DiskError::io(format!("{what}: {}", std::io::Error::from_raw_os_error(code as i32))),
    }
}

/// Closes a Win32 handle on drop.
pub(crate) struct OwnedHandle(HANDLE);
// SAFETY: kernel handles may be used from any thread.
unsafe impl Send for OwnedHandle {}
unsafe impl Sync for OwnedHandle {}
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: we own the handle.
            unsafe { CloseHandle(self.0) };
        }
    }
}

fn open(path: &str, access: u32) -> Option<OwnedHandle> {
    let w = wide(path);
    // SAFETY: valid NUL-terminated path; other args are plain values.
    let h = unsafe {
        CreateFileW(w.as_ptr(), access, FILE_SHARE_READ | FILE_SHARE_WRITE, null(), OPEN_EXISTING, 0, null_mut())
    };
    (h != INVALID_HANDLE_VALUE).then_some(OwnedHandle(h))
}

/// DeviceIoControl into a byte buffer, growing it on ERROR_INSUFFICIENT_BUFFER/MORE_DATA.
fn ioctl(h: &OwnedHandle, code: u32, input: &[u8], mut cap: usize) -> Option<Vec<u8>> {
    for _ in 0..6 {
        let mut out = vec![0u8; cap];
        let mut ret = 0u32;
        // SAFETY: buffers are valid for the given sizes.
        let ok = unsafe {
            DeviceIoControl(
                h.0,
                code,
                if input.is_empty() { null() } else { input.as_ptr().cast() },
                input.len() as u32,
                out.as_mut_ptr().cast(),
                cap as u32,
                &mut ret,
                null_mut(),
            )
        };
        if ok != 0 {
            out.truncate(ret as usize);
            return Some(out);
        }
        match last_error() {
            ERROR_INSUFFICIENT_BUFFER | ERROR_MORE_DATA => cap *= 4,
            _ => return None,
        }
    }
    None
}

fn ioctl_none(h: &OwnedHandle, code: u32, input: &[u8]) -> bool {
    let mut ret = 0u32;
    // SAFETY: input valid for len; no output.
    unsafe {
        DeviceIoControl(
            h.0,
            code,
            if input.is_empty() { null() } else { input.as_ptr().cast() },
            input.len() as u32,
            null_mut(),
            0,
            &mut ret,
            null_mut(),
        ) != 0
    }
}

fn read_struct<T: Copy>(buf: &[u8], off: usize) -> Option<T> {
    if buf.len() < off + size_of::<T>() {
        return None;
    }
    // SAFETY: bounds checked; read_unaligned handles alignment; T is plain data.
    Some(unsafe { std::ptr::read_unaligned(buf.as_ptr().add(off).cast::<T>()) })
}

fn as_bytes<T>(v: &T) -> &[u8] {
    // SAFETY: viewing a plain-data struct as bytes.
    unsafe { std::slice::from_raw_parts((v as *const T).cast::<u8>(), size_of::<T>()) }
}

fn guid_str(g: &windows_sys::core::GUID) -> String {
    let mut b = [0u8; 16];
    b[..4].copy_from_slice(&g.data1.to_le_bytes());
    b[4..6].copy_from_slice(&g.data2.to_le_bytes());
    b[6..8].copy_from_slice(&g.data3.to_le_bytes());
    b[8..].copy_from_slice(&g.data4);
    guid_to_string(&b)
}

pub(crate) fn is_elevated() -> bool {
    let mut token: HANDLE = null_mut();
    // SAFETY: pseudo-handle for current process; token handle closed below.
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let token = OwnedHandle(token);
        let mut e = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token.0,
            TokenElevation,
            (&mut e as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        );
        ok != 0 && e.TokenIsElevated != 0
    }
}

struct DiskInfo {
    model: String,
    bus: Bus,
    removable: bool,
    size: u64,
}

#[allow(non_upper_case_globals)]
fn bus_from(t: i32) -> Bus {
    match t {
        BusTypeUsb => Bus::Usb,
        BusTypeSata | BusTypeAta | BusTypeAtapi => Bus::Sata,
        BusTypeNvme => Bus::Nvme,
        BusTypeSd | BusTypeMmc => Bus::Sd,
        BusTypeScsi | BusTypeSas | BusTypeRAID | BusTypeiScsi | BusTypeFibre => Bus::Scsi,
        BusTypeVirtual | BusTypeFileBackedVirtual | BusTypeSpaces => Bus::Virtual,
        _ => Bus::Other,
    }
}

fn ascii_at(buf: &[u8], off: u32) -> String {
    if off == 0 || off as usize >= buf.len() {
        return String::new();
    }
    let s = &buf[off as usize..];
    let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    String::from_utf8_lossy(&s[..end]).trim().to_string()
}

fn disk_info(h: &OwnedHandle) -> DiskInfo {
    let q = STORAGE_PROPERTY_QUERY {
        PropertyId: StorageDeviceProperty,
        QueryType: PropertyStandardQuery,
        AdditionalParameters: [0],
    };
    let (mut model, mut bus, mut removable) = (String::new(), Bus::Other, false);
    if let Some(buf) = ioctl(h, IOCTL_STORAGE_QUERY_PROPERTY, as_bytes(&q), 1024)
        && let Some(d) = read_struct::<STORAGE_DEVICE_DESCRIPTOR>(&buf, 0)
    {
        let vendor = ascii_at(&buf, d.VendorIdOffset);
        let product = ascii_at(&buf, d.ProductIdOffset);
        model = [vendor, product].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" ");
        bus = bus_from(d.BusType);
        removable = d.RemovableMedia;
    }
    let size = ioctl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, &[], 256)
        .and_then(|b| read_struct::<DISK_GEOMETRY_EX>(&b, 0))
        .map(|g| g.DiskSize as u64)
        .unwrap_or(0);
    DiskInfo { model, bus, removable, size }
}

const GENERIC_GPT_NAMES: [&str; 5] =
    ["basic data partition", "efi system partition", "microsoft reserved partition", "primary", "logical"];

fn layout(h: &OwnedHandle, disk_id: &str, raw_path: &str) -> (String, Vec<Partition>) {
    let mut parts = Vec::new();
    let Some(buf) = ioctl(h, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, &[], 48 + 144 * 64) else {
        return ("none".into(), parts);
    };
    let Some(hdr) = read_struct::<DRIVE_LAYOUT_INFORMATION_EX>(&buf, 0) else {
        return ("none".into(), parts);
    };
    let style = match hdr.PartitionStyle as i32 {
        PARTITION_STYLE_MBR => "mbr",
        PARTITION_STYLE_GPT => "gpt",
        _ => "none",
    };
    let first = offset_of!(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry);
    let stride = size_of::<PARTITION_INFORMATION_EX>();
    for i in 0..hdr.PartitionCount as usize {
        let Some(pe) = read_struct::<PARTITION_INFORMATION_EX>(&buf, first + i * stride) else { break };
        if pe.PartitionLength <= 0 {
            continue;
        }
        let (hint, part_type, gpt_name) = match pe.PartitionStyle {
            PARTITION_STYLE_GPT => {
                // SAFETY: style says the Gpt union member is active.
                let g = unsafe { pe.Anonymous.Gpt };
                let t = guid_str(&g.PartitionType);
                (fs_from_gpt_type(&t), t, from_wide(&g.Name))
            }
            PARTITION_STYLE_MBR => {
                // SAFETY: style says the Mbr union member is active.
                let m = unsafe { pe.Anonymous.Mbr };
                if m.PartitionType == 0 {
                    continue;
                }
                (fs_from_mbr_type(m.PartitionType), format!("0x{:02x}", m.PartitionType), String::new())
            }
            _ => (fs_from_mbr_type(0), String::new(), String::new()),
        };
        if hint.container || (pe.PartitionNumber == 0 && style != "none") {
            continue;
        }
        let label = (!gpt_name.is_empty() && !GENERIC_GPT_NAMES.contains(&gpt_name.to_lowercase().as_str()))
            .then_some(gpt_name);
        let number = pe.PartitionNumber;
        parts.push(Partition {
            id: format!("{disk_id}p{number}"),
            disk_id: disk_id.to_string(),
            number,
            label,
            fs: hint.fs,
            size: pe.PartitionLength as u64,
            free: None,
            mount: None,
            mounts: Vec::new(),
            is_system: false,
            is_efi: hint.efi,
            is_recovery: hint.recovery,
            hibernated: false,
            dirty: false,
            os: None,
            access: crate::Access::ReadWrite,
            raw_path: raw_path.to_string(),
            offset: pe.StartingOffset as u64,
            volume: None,
            part_type,
            needs_admin: false,
        });
    }
    (style.into(), parts)
}

struct VolInfo {
    guid_path: String,
    mounts: Vec<String>,
    label: Option<String>,
    fs: Option<String>,
    free: Option<u64>,
}

/// (disk number, starting offset) -> volume.
fn volumes() -> HashMap<(u32, u64), VolInfo> {
    let mut map = HashMap::new();
    let mut name = [0u16; 512];
    // SAFETY: buffer valid for its length.
    let find = unsafe { FindFirstVolumeW(name.as_mut_ptr(), name.len() as u32) };
    if find == INVALID_HANDLE_VALUE {
        return map;
    }
    loop {
        let guid_path = from_wide(&name);
        if let Some(info) = volume_info(&guid_path) {
            map.insert(info.0, info.1);
        }
        // SAFETY: find handle valid; buffer valid.
        if unsafe { FindNextVolumeW(find, name.as_mut_ptr(), name.len() as u32) } == 0 {
            break;
        }
    }
    // SAFETY: handle from FindFirstVolumeW.
    unsafe { FindVolumeClose(find) };
    map
}

fn volume_info(guid_path: &str) -> Option<((u32, u64), VolInfo)> {
    let h = open(guid_path.trim_end_matches('\\'), 0)?;
    let buf = ioctl(&h, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, &[], size_of::<VOLUME_DISK_EXTENTS>() + 8 * 24)?;
    let n = read_struct::<u32>(&buf, 0)?;
    if n != 1 {
        return None; // spanned/striped volumes are not mapped to a single partition
    }
    let ext = read_struct::<DISK_EXTENT>(&buf, offset_of!(VOLUME_DISK_EXTENTS, Extents))?;
    drop(h);

    let gw = wide(guid_path);
    let mut paths = vec![0u16; 1024];
    let mut len = 0u32;
    // SAFETY: buffers valid.
    let mut mounts = Vec::new();
    if unsafe { GetVolumePathNamesForVolumeNameW(gw.as_ptr(), paths.as_mut_ptr(), paths.len() as u32, &mut len) } != 0 {
        for s in paths[..len as usize].split(|&c| c == 0) {
            if !s.is_empty() {
                mounts.push(String::from_utf16_lossy(s));
            }
        }
    }
    let mut label = [0u16; 261];
    let mut fsname = [0u16; 261];
    // SAFETY: buffers valid.
    let ok = unsafe {
        GetVolumeInformationW(
            gw.as_ptr(),
            label.as_mut_ptr(),
            label.len() as u32,
            null_mut(),
            null_mut(),
            null_mut(),
            fsname.as_mut_ptr(),
            fsname.len() as u32,
        )
    } != 0;
    let free = if mounts.is_empty() {
        None
    } else {
        let mut avail = 0u64;
        // SAFETY: out pointer valid.
        (unsafe { GetDiskFreeSpaceExW(gw.as_ptr(), &mut avail, null_mut(), null_mut()) } != 0).then_some(avail)
    };
    let label = ok.then(|| from_wide(&label)).filter(|s| !s.is_empty());
    let fs = ok.then(|| from_wide(&fsname)).filter(|s| !s.is_empty());
    Some((
        (ext.DiskNumber, ext.StartingOffset as u64),
        VolInfo { guid_path: guid_path.to_string(), mounts, label, fs, free },
    ))
}

fn fs_from_name(n: &str) -> FsType {
    match n.to_ascii_uppercase().as_str() {
        "NTFS" => FsType::Ntfs,
        "FAT" | "FAT16" => FsType::Fat16,
        "FAT12" => FsType::Fat12,
        "FAT32" => FsType::Fat32,
        "EXFAT" => FsType::ExFat,
        "REFS" => FsType::Refs,
        _ => FsType::Unknown,
    }
}

fn system_volume() -> Option<String> {
    let mut dir = [0u16; 261];
    // SAFETY: buffer valid.
    let n = unsafe { GetSystemWindowsDirectoryW(dir.as_mut_ptr(), dir.len() as u32) };
    if n == 0 {
        return None;
    }
    let mut root = [0u16; 261];
    let mut guid = [0u16; 100];
    // SAFETY: buffers valid, dir NUL-terminated by the API.
    unsafe {
        if GetVolumePathNameW(dir.as_ptr(), root.as_mut_ptr(), root.len() as u32) == 0 {
            return None;
        }
        if GetVolumeNameForVolumeMountPointW(root.as_ptr(), guid.as_mut_ptr(), guid.len() as u32) == 0 {
            return None;
        }
    }
    Some(from_wide(&guid))
}

pub(crate) fn list_disks() -> Result<Vec<Disk>, DiskError> {
    let vols = volumes();
    let sys = system_volume();
    let elevated = is_elevated();
    let mut disks = Vec::new();
    for n in 0..64u32 {
        let raw_path = format!(r"\\.\PhysicalDrive{n}");
        let Some(h) = open(&raw_path, 0) else { continue };
        let info = disk_info(&h);
        let disk_id = format!("disk{n}");
        let (style, mut parts) = layout(&h, &disk_id, &raw_path);
        drop(h);
        for p in &mut parts {
            if let Some(v) = vols.get(&(n, p.offset)) {
                p.volume = Some(v.guid_path.clone());
                p.mounts = v.mounts.clone();
                p.mount = v.mounts.first().cloned();
                p.free = v.free;
                if v.label.is_some() {
                    p.label = v.label.clone();
                }
                if let Some(f) = v.fs.as_deref() {
                    let f = fs_from_name(f);
                    if f != FsType::Unknown {
                        p.fs = f;
                    }
                }
                p.is_system = sys.as_deref().is_some_and(|s| s.eq_ignore_ascii_case(&v.guid_path));
            }
            // Superblock probing for what Windows can't tell us (ext4, swap, LVM,
            // BitLocker...) and hibernation of unmounted NTFS. Needs admin.
            let msr = p.part_type == "e3c9e316-0b5c-4db8-817d-f92df00215ae";
            let wants_probe = !msr
                && !p.is_system && !p.is_efi && !p.is_recovery
                && (matches!(p.fs, FsType::Unknown | FsType::Linux)
                    || (p.fs == FsType::Ntfs && p.mount.is_none()));
            if wants_probe {
                if elevated {
                    match crate::rawfs::probe_partition(p) {
                        Ok(probe) => apply_probe(p, &probe),
                        Err(DiskError::NeedsAdmin) => p.needs_admin = true,
                        Err(_) => {}
                    }
                } else {
                    p.needs_admin = true;
                }
            }
        }
        disks.push(Disk {
            id: disk_id,
            model: info.model,
            bus: info.bus,
            removable: info.removable,
            size: info.size,
            partition_style: style,
            raw_path,
            partitions: parts,
        });
    }
    Ok(disks)
}

pub(crate) fn mount(p: &Partition, _read_only: bool) -> Result<String, DiskError> {
    let Some(vol) = &p.volume else {
        return Err(DiskError::unsupported(
            "Windows has no volume for this partition (file system not supported by Windows); open it with RawFs",
        ));
    };
    if !(p.fs == FsType::Ntfs || p.fs == FsType::Refs || p.fs.is_fat()) {
        return Err(DiskError::unsupported(format!("Windows can't mount {:?}", p.fs)));
    }
    if p.hibernated || p.dirty || p.is_efi || p.is_recovery {
        return Err(DiskError::unsupported(
            "refusing to assign a drive letter to a hibernated/dirty, EFI or recovery volume; open it with RawFs",
        ));
    }
    // SAFETY: no preconditions.
    let used = unsafe { GetLogicalDrives() };
    let letter = (b'D'..=b'Z').find(|l| used & (1 << (l - b'A')) == 0).ok_or_else(|| DiskError::io("no free drive letter"))?;
    let mp = format!("{}:\\", letter as char);
    let (mw, vw) = (wide(&mp), wide(vol));
    // SAFETY: valid NUL-terminated strings.
    if unsafe { SetVolumeMountPointW(mw.as_ptr(), vw.as_ptr()) } == 0 {
        return Err(win_err("SetVolumeMountPointW"));
    }
    Ok(mp)
}

pub(crate) fn unmount(p: &Partition) -> Result<(), DiskError> {
    for m in &p.mounts {
        let mut m = m.clone();
        if !m.ends_with('\\') {
            m.push('\\');
        }
        let w = wide(&m);
        // SAFETY: valid string.
        if unsafe { DeleteVolumeMountPointW(w.as_ptr()) } == 0 {
            return Err(win_err("DeleteVolumeMountPointW"));
        }
    }
    Ok(())
}

/// Device instance of the disk with this number (GUID_DEVINTERFACE_DISK).
fn disk_devinst(number: u32) -> Option<u32> {
    // SAFETY: standard SetupDi enumeration; buffers sized as the API reports.
    unsafe {
        let set = SetupDiGetClassDevsW(&GUID_DEVINTERFACE_DISK, null(), null_mut(), DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
        if set == INVALID_HANDLE_VALUE as HDEVINFO {
            return None;
        }
        let mut found = None;
        for i in 0..256 {
            let mut ifd: SP_DEVICE_INTERFACE_DATA = std::mem::zeroed();
            ifd.cbSize = size_of::<SP_DEVICE_INTERFACE_DATA>() as u32;
            if SetupDiEnumDeviceInterfaces(set, null(), &GUID_DEVINTERFACE_DISK, i, &mut ifd) == 0 {
                break;
            }
            let mut need = 0u32;
            SetupDiGetDeviceInterfaceDetailW(set, &ifd, null_mut(), 0, &mut need, null_mut());
            if need == 0 {
                continue;
            }
            let mut buf = vec![0u64; (need as usize).div_ceil(8)];
            let det = buf.as_mut_ptr().cast::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>();
            (*det).cbSize = size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32;
            let mut dev: SP_DEVINFO_DATA = std::mem::zeroed();
            dev.cbSize = size_of::<SP_DEVINFO_DATA>() as u32;
            if SetupDiGetDeviceInterfaceDetailW(set, &ifd, det, need, null_mut(), &mut dev) == 0 {
                continue;
            }
            let path_ptr = std::ptr::addr_of!((*det).DevicePath).cast::<u16>();
            let max = (need as usize - 4) / 2;
            let path = from_wide(std::slice::from_raw_parts(path_ptr, max));
            let Some(h) = open(&path, 0) else { continue };
            if let Some(b) = ioctl(&h, IOCTL_STORAGE_GET_DEVICE_NUMBER, &[], size_of::<STORAGE_DEVICE_NUMBER>())
                && read_struct::<STORAGE_DEVICE_NUMBER>(&b, 0).is_some_and(|d| d.DeviceNumber == number)
            {
                found = Some(dev.DevInst);
                break;
            }
        }
        SetupDiDestroyDeviceInfoList(set);
        found
    }
}

/// Process names from recent Kernel-PnP event 225 ("application X with process
/// id N stopped the removal or ejection").
fn pnp_veto_processes() -> Vec<String> {
    let mut out = Vec::new();
    let query = wide(
        "*[System[Provider[@Name='Microsoft-Windows-Kernel-PnP'] and (EventID=225) and TimeCreated[timediff(@SystemTime) <= 30000]]]",
    );
    for channel in ["System", "Microsoft-Windows-Kernel-PnP/Configuration"] {
        let ch = wide(channel);
        // SAFETY: valid strings; handles closed below.
        unsafe {
            let q = EvtQuery(0, ch.as_ptr(), query.as_ptr(), EvtQueryChannelPath | EvtQueryReverseDirection);
            if q == 0 {
                continue;
            }
            let mut evs = [0isize; 8];
            let mut n = 0u32;
            if EvtNext(q, evs.len() as u32, evs.as_mut_ptr(), 1000, 0, &mut n) != 0 {
                for &ev in &evs[..n as usize] {
                    let mut used = 0u32;
                    let mut props = 0u32;
                    EvtRender(0, ev, EvtRenderEventXml, 0, null_mut(), &mut used, &mut props);
                    let mut buf = vec![0u16; used as usize / 2 + 1];
                    if EvtRender(0, ev, EvtRenderEventXml, (buf.len() * 2) as u32, buf.as_mut_ptr().cast::<c_void>(), &mut used, &mut props) != 0 {
                        out.extend(exe_names_in_event_xml(&from_wide(&buf)));
                    }
                    EvtClose(ev);
                }
            }
            EvtClose(q);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Pull `*.exe` values (file name only) out of `<Data ...>value</Data>` elements.
pub(crate) fn exe_names_in_event_xml(xml: &str) -> Vec<String> {
    let mut v = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find("<Data") {
        rest = &rest[i..];
        let Some(gt) = rest.find('>') else { break };
        let Some(end) = rest.find("</Data>") else { break };
        if gt < end {
            let val = rest[gt + 1..end].trim();
            if val.to_ascii_lowercase().ends_with(".exe") {
                let name = val.rsplit(['\\', '/']).next().unwrap_or(val);
                v.push(name.to_string());
            }
        }
        rest = &rest[end + 7..];
    }
    v
}

pub(crate) fn eject(disk: &Disk) -> Result<(), DiskError> {
    let number: u32 = disk.id.trim_start_matches("disk").parse().map_err(|_| DiskError::NotFound)?;
    // 1. Flush, lock and dismount every volume (best effort; PnP is authoritative).
    let mut locked = Vec::new();
    for p in &disk.partitions {
        let Some(v) = &p.volume else { continue };
        let Some(h) = open(v.trim_end_matches('\\'), GENERIC_READ | GENERIC_WRITE) else { continue };
        // SAFETY: valid volume handle.
        unsafe { FlushFileBuffers(h.0) };
        let mut ok = false;
        for _ in 0..3 {
            if ioctl_none(&h, FSCTL_LOCK_VOLUME, &[]) {
                ok = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        if ok {
            ioctl_none(&h, FSCTL_DISMOUNT_VOLUME, &[]);
            let allow = PREVENT_MEDIA_REMOVAL { PreventMediaRemoval: false };
            ioctl_none(&h, IOCTL_STORAGE_MEDIA_REMOVAL, as_bytes(&allow));
            locked.push(h);
        }
    }
    // 2. Ask PnP to eject the device (same as "Safely Remove Hardware").
    let devinst = disk_devinst(number);
    if let Some(inst) = devinst {
        let mut parent = 0u32;
        // SAFETY: out pointer valid.
        let target = if unsafe { CM_Get_Parent(&mut parent, inst, 0) } == CR_SUCCESS { parent } else { inst };
        // Locks must be released or PnP will see our own open handles.
        drop(std::mem::take(&mut locked));
        for attempt in 0..3 {
            let mut veto: PNP_VETO_TYPE = PNP_VetoTypeUnknown;
            let mut name = [0u16; 260];
            // SAFETY: buffers valid.
            let cr = unsafe { CM_Request_Device_EjectW(target, &mut veto, name.as_mut_ptr(), name.len() as u32, 0) };
            if cr == CR_SUCCESS && veto == PNP_VetoTypeUnknown {
                return Ok(());
            }
            if attempt == 2 {
                let mut processes = pnp_veto_processes();
                if processes.is_empty() {
                    let n = from_wide(&name);
                    if !n.is_empty() {
                        processes.push(n);
                    }
                }
                return Err(DiskError::Busy { processes });
            }
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
    }
    // 3. No PnP device found (e.g. card reader): eject the media.
    let Some(h) = open(&disk.raw_path, GENERIC_READ) else { return Err(win_err("open disk")) };
    if ioctl_none(&h, IOCTL_STORAGE_EJECT_MEDIA, &[]) {
        Ok(())
    } else {
        Err(win_err("IOCTL_STORAGE_EJECT_MEDIA"))
    }
}

// ---- elevated helper transport -------------------------------------------------

pub(crate) fn valid_pipe_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 100 && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Helper side: connect to the app's pipe.
pub(crate) fn open_pipe_client(name: &str) -> Result<std::fs::File, DiskError> {
    let path = format!(r"\\.\pipe\{name}");
    let w = wide(&path);
    for _ in 0..50 {
        // SAFETY: valid path.
        let h = unsafe {
            CreateFileW(w.as_ptr(), GENERIC_READ | GENERIC_WRITE, 0, null(), OPEN_EXISTING, 0, null_mut())
        };
        if h != INVALID_HANDLE_VALUE {
            // SAFETY: fresh owned handle.
            return Ok(unsafe { std::fs::File::from_raw_handle(h) });
        }
        if last_error() == ERROR_PIPE_BUSY {
            // SAFETY: valid path.
            unsafe { WaitNamedPipeW(w.as_ptr(), 2000) };
        } else {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
    Err(win_err("open helper pipe"))
}

/// App side: create the pipe, launch `exe --disk-helper <name> <token>` with
/// the "runas" verb, wait for the helper to connect and verify its PID.
pub(crate) fn spawn_helper(
    exe: &std::path::Path,
    name: &str,
    token: &str,
) -> Result<(std::fs::File, OwnedHandle), DiskError> {
    let pw = wide(&format!(r"\\.\pipe\{name}"));
    // SAFETY: valid name; default security (owner = current user, which the
    // elevated helper shares).
    let pipe = unsafe {
        CreateNamedPipeW(
            pw.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            1 << 20,
            1 << 20,
            0,
            null(),
        )
    };
    if pipe == INVALID_HANDLE_VALUE {
        return Err(win_err("CreateNamedPipeW"));
    }
    let pipe = OwnedHandle(pipe);

    let verb = wide("runas");
    let file = wide(&exe.to_string_lossy());
    let params = wide(&format!("--disk-helper {name} {token}"));
    // SAFETY: zeroed is a valid initial state for this plain struct.
    let mut sei: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    sei.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    sei.lpVerb = verb.as_ptr();
    sei.lpFile = file.as_ptr();
    sei.lpParameters = params.as_ptr();
    sei.nShow = SW_HIDE;
    // SAFETY: struct initialised; strings outlive the call.
    if unsafe { ShellExecuteExW(&mut sei) } == 0 {
        return Err(if last_error() == ERROR_CANCELLED { DiskError::NeedsAdmin } else { win_err("ShellExecuteExW") });
    }
    let process = OwnedHandle(sei.hProcess);
    // SAFETY: valid process handle.
    let helper_pid = unsafe { GetProcessId(process.0) };

    // If the helper dies before connecting, poke the pipe so ConnectNamedPipe returns.
    let mut dup: HANDLE = null_mut();
    // SAFETY: duplicating our own valid process handle for the watcher thread.
    unsafe { DuplicateHandle(GetCurrentProcess(), process.0, GetCurrentProcess(), &mut dup, 0, 0, DUPLICATE_SAME_ACCESS) };
    let watch = OwnedHandle(dup);
    let pipe_name = format!(r"\\.\pipe\{name}");
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let done2 = done.clone();
    std::thread::spawn(move || {
        let watch = watch;
        // SAFETY: the thread owns this duplicated handle.
        unsafe { WaitForSingleObject(watch.0, 120_000) };
        if !done2.load(std::sync::atomic::Ordering::SeqCst) {
            let w = wide(&pipe_name);
            // SAFETY: valid path; handle closed immediately.
            let h = unsafe { CreateFileW(w.as_ptr(), GENERIC_READ, 0, null(), OPEN_EXISTING, 0, null_mut()) };
            if h != INVALID_HANDLE_VALUE {
                // SAFETY: we own h.
                unsafe { CloseHandle(h) };
            }
        }
    });
    // SAFETY: valid pipe handle, synchronous.
    let connected = unsafe { ConnectNamedPipe(pipe.0, null_mut()) } != 0 || last_error() == ERROR_PIPE_CONNECTED;
    done.store(true, std::sync::atomic::Ordering::SeqCst);
    if !connected {
        return Err(win_err("ConnectNamedPipe"));
    }
    let mut client_pid = 0u32;
    // SAFETY: out pointer valid.
    unsafe { GetNamedPipeClientProcessId(pipe.0, &mut client_pid) };
    if client_pid == 0 || client_pid != helper_pid {
        return Err(DiskError::io("helper did not start (unexpected pipe client)"));
    }
    let raw = pipe.0;
    std::mem::forget(pipe);
    // SAFETY: ownership transferred from OwnedHandle.
    Ok((unsafe { std::fs::File::from_raw_handle(raw) }, process))
}
