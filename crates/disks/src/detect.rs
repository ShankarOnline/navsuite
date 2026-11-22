//! File system detection from raw bytes (superblocks / boot sectors) and from
//! partition-table type codes. Pure functions, no I/O.

use crate::FsType;

/// How many bytes from the start of a partition [`detect_fs`] wants to see.
/// (btrfs keeps its superblock at 64 KiB; 64 KiB-page swap at 64 KiB - 10.)
pub const PROBE_LEN: usize = 0x11000;

fn at(buf: &[u8], off: usize, len: usize) -> Option<&[u8]> {
    buf.get(off..off.checked_add(len)?)
}
fn u16le(buf: &[u8], off: usize) -> Option<u16> {
    at(buf, off, 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}
fn u32le(buf: &[u8], off: usize) -> Option<u32> {
    at(buf, off, 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn eq(buf: &[u8], off: usize, sig: &[u8]) -> bool {
    at(buf, off, sig.len()) == Some(sig)
}

fn label_from(bytes: &[u8]) -> Option<String> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let s = String::from_utf8_lossy(&bytes[..end]).trim().to_string();
    if s.is_empty() || s == "NO NAME" { None } else { Some(s) }
}

/// Detect the file system from the first bytes of a partition (ideally
/// [`PROBE_LEN`] bytes; shorter buffers just detect less). Returns the type and
/// the volume label when the superblock/boot sector carries one.
pub fn detect_fs(buf: &[u8]) -> (FsType, Option<String>) {
    // Boot-sector OEM IDs at offset 3.
    if eq(buf, 3, b"-FVE-FS-") {
        return (FsType::Bitlocker, None);
    }
    if eq(buf, 3, b"NTFS    ") {
        return (FsType::Ntfs, None);
    }
    if eq(buf, 3, b"EXFAT   ") {
        return (FsType::ExFat, None);
    }
    if eq(buf, 3, b"ReFS\0\0\0\0") {
        return (FsType::Refs, None);
    }
    if eq(buf, 0, b"LUKS\xba\xbe") {
        let label = at(buf, 24, 48).and_then(label_from);
        return (FsType::Luks, label);
    }
    // LVM2 physical volume label lives in one of the first four sectors.
    for s in 0..4 {
        let o = s * 512;
        if eq(buf, o, b"LABELONE") && eq(buf, o + 24, b"LVM2 001") {
            return (FsType::Lvm, None);
        }
    }
    if eq(buf, 0, b"XFSB") {
        return (FsType::Xfs, at(buf, 108, 12).and_then(label_from));
    }
    // ext2/3/4: superblock at 1024, magic at +0x38.
    if u16le(buf, 1024 + 0x38) == Some(0xEF53) {
        let compat = u32le(buf, 1024 + 0x5c).unwrap_or(0);
        let incompat = u32le(buf, 1024 + 0x60).unwrap_or(0);
        let ro_compat = u32le(buf, 1024 + 0x64).unwrap_or(0);
        // ext4-only features: extents, 64bit, flex_bg / huge_file, gdt_csum,
        // dir_nlink, extra_isize, metadata_csum.
        let fs = if incompat & (0x40 | 0x80 | 0x200) != 0
            || ro_compat & (0x8 | 0x10 | 0x20 | 0x40 | 0x400) != 0
        {
            FsType::Ext4
        } else if compat & 0x4 != 0 {
            FsType::Ext3
        } else {
            FsType::Ext2
        };
        return (fs, at(buf, 1024 + 0x78, 16).and_then(label_from));
    }
    // HFS+ / HFSX volume header at 1024.
    if eq(buf, 1024, b"H+") || eq(buf, 1024, b"HX") {
        return (FsType::HfsPlus, None);
    }
    // APFS container superblock (NXSB) or volume superblock (APSB) magic at 32.
    if eq(buf, 32, b"NXSB") || eq(buf, 32, b"APSB") {
        return (FsType::Apfs, None);
    }
    if eq(buf, 0x10040, b"_BHRfS_M") {
        return (FsType::Btrfs, at(buf, 0x1012b, 256).and_then(label_from));
    }
    for page in [4096usize, 8192, 16384, 65536] {
        if eq(buf, page - 10, b"SWAPSPACE2") || eq(buf, page - 10, b"SWAP-SPACE") {
            return (FsType::Swap, at(buf, 1024 + 28, 16).and_then(label_from));
        }
    }
    if let Some(r) = detect_fat(buf) {
        return r;
    }
    (FsType::Unknown, None)
}

fn detect_fat(buf: &[u8]) -> Option<(FsType, Option<String>)> {
    if u16le(buf, 510)? != 0xAA55 || !matches!(buf[0], 0xEB | 0xE9) {
        return None;
    }
    let bps = u32::from(u16le(buf, 11)?);
    let spc = u32::from(buf[13]);
    let reserved = u32::from(u16le(buf, 14)?);
    let nfats = u32::from(buf[16]);
    let root_entries = u32::from(u16le(buf, 17)?);
    let total16 = u32::from(u16le(buf, 19)?);
    let fat16_size = u32::from(u16le(buf, 22)?);
    let total32 = u32le(buf, 32)?;
    let fat32_size = u32le(buf, 36)?;
    if !matches!(bps, 512 | 1024 | 2048 | 4096)
        || spc == 0
        || !spc.is_power_of_two()
        || reserved == 0
        || !(1..=2).contains(&nfats)
    {
        return None;
    }
    let fat_size = if fat16_size != 0 { fat16_size } else { fat32_size };
    let total = if total16 != 0 { total16 } else { total32 };
    if fat_size == 0 || total == 0 {
        return None;
    }
    let root_dir_sectors = (root_entries * 32).div_ceil(bps);
    let meta = reserved + nfats * fat_size + root_dir_sectors;
    let clusters = total.checked_sub(meta)? / spc;
    let fs = if fat16_size == 0 {
        FsType::Fat32
    } else if clusters < 4085 {
        FsType::Fat12
    } else if clusters < 65525 {
        FsType::Fat16
    } else {
        FsType::Fat32
    };
    let label = if fs == FsType::Fat32 {
        (buf.get(66) == Some(&0x29)).then(|| at(buf, 71, 11).and_then(label_from)).flatten()
    } else {
        (buf.get(38) == Some(&0x29)).then(|| at(buf, 43, 11).and_then(label_from)).flatten()
    };
    Some((fs, label))
}

/// What a partition-table type code tells us.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TypeHint {
    pub fs: FsType,
    pub efi: bool,
    pub recovery: bool,
    /// Extended-partition container (MBR) or the GPT protective entry: not a real partition.
    pub container: bool,
}

const fn hint(fs: FsType) -> TypeHint {
    TypeHint { fs, efi: false, recovery: false, container: false }
}

/// Map a GPT partition type GUID (any case, with dashes) to a hint.
pub fn fs_from_gpt_type(guid: &str) -> TypeHint {
    match guid.to_ascii_lowercase().as_str() {
        "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" => TypeHint { efi: true, ..hint(FsType::Fat32) },
        "de94bba4-06d1-4d40-a16a-bfd50179d6ac" => TypeHint { recovery: true, ..hint(FsType::Ntfs) },
        "426f6f74-0000-11aa-aa11-00306543ecac" | "52637672-7900-11aa-aa11-00306543ecac" => {
            TypeHint { recovery: true, ..hint(FsType::Unknown) }
        }
        "0fc63daf-8483-4772-8e79-3d69d8477de4"
        | "4f68bce3-e8cd-4db1-96e7-fbcaf984b709"
        | "b921b045-1df0-41c3-af44-4c6f280d3fae"
        | "44479540-f297-41b2-9af7-d131d5f0458a"
        | "69dad710-2ce4-4e3c-b16c-21a1d49abed3"
        | "933ac7e1-2eb4-4f13-b844-0e14e2aef915"
        | "bc13c2ff-59e6-4262-a352-b275fd6f7172" => hint(FsType::Linux),
        "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f" => hint(FsType::Swap),
        "e6d6d379-f507-44c2-a23c-238f2a3df928" => hint(FsType::Lvm),
        "ca7d7ccb-63ed-4c53-861c-1742536059cc" => hint(FsType::Luks),
        "48465300-0000-11aa-aa11-00306543ecac" => hint(FsType::HfsPlus),
        "7c3457ef-0000-11aa-aa11-00306543ecac" => hint(FsType::Apfs),
        _ => hint(FsType::Unknown),
    }
}

/// Map an MBR partition type byte to a hint.
pub fn fs_from_mbr_type(t: u8) -> TypeHint {
    match t {
        0x01 => hint(FsType::Fat12),
        0x04 | 0x06 | 0x0e => hint(FsType::Fat16),
        0x0b | 0x0c => hint(FsType::Fat32),
        0x27 => TypeHint { recovery: true, ..hint(FsType::Ntfs) },
        0x82 => hint(FsType::Swap),
        0x83 => hint(FsType::Linux),
        0x8e => hint(FsType::Lvm),
        0xaf => hint(FsType::HfsPlus),
        0xef => TypeHint { efi: true, ..hint(FsType::Fat32) },
        0x05 | 0x0f | 0x85 | 0xee => TypeHint { container: true, ..hint(FsType::Unknown) },
        _ => hint(FsType::Unknown),
    }
}

/// `hiberfil.sys` header check (first 4 bytes). "hibr"/"HIBR" = hibernated or
/// Fast Startup image; "wake"/"WAKE" is also treated as hibernated
/// (conservative: it only ever makes a volume read-only).
pub fn ntfs_hiberfil_is_hibernated(head: &[u8]) -> bool {
    let Some(sig) = head.get(..4) else { return false };
    sig.eq_ignore_ascii_case(b"hibr") || sig.eq_ignore_ascii_case(b"wake")
}

/// Format a little-endian on-disk GUID (16 bytes, mixed-endian) as text.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn guid_to_string(b: &[u8; 16]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}
