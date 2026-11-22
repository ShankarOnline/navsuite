use crate::detect::*;
use crate::helper::{HelperClient, serve, windows_raw_path_allowed};
use crate::*;
use std::path::Path;

// ---------- synthetic boot sectors / superblocks ----------

fn buf() -> Vec<u8> {
    vec![0u8; PROBE_LEN]
}

fn put(b: &mut [u8], off: usize, data: &[u8]) {
    b[off..off + data.len()].copy_from_slice(data);
}

#[allow(clippy::too_many_arguments)]
fn fat_bpb(bps: u16, spc: u8, reserved: u16, nfats: u8, root: u16, total16: u16, fat16: u16, total32: u32, fat32: u32) -> Vec<u8> {
    let mut b = buf();
    b[0] = 0xEB;
    b[1] = 0x3C;
    b[2] = 0x90;
    put(&mut b, 3, b"MSDOS5.0");
    put(&mut b, 11, &bps.to_le_bytes());
    b[13] = spc;
    put(&mut b, 14, &reserved.to_le_bytes());
    b[16] = nfats;
    put(&mut b, 17, &root.to_le_bytes());
    put(&mut b, 19, &total16.to_le_bytes());
    put(&mut b, 22, &fat16.to_le_bytes());
    put(&mut b, 32, &total32.to_le_bytes());
    put(&mut b, 36, &fat32.to_le_bytes());
    put(&mut b, 510, &[0x55, 0xAA]);
    b
}

#[test]
fn detect_fat_variants() {
    let mut f12 = fat_bpb(512, 1, 1, 2, 224, 2880, 9, 0, 0);
    f12[38] = 0x29;
    put(&mut f12, 43, b"FLOPPY     ");
    assert_eq!(detect_fs(&f12), (FsType::Fat12, Some("FLOPPY".into())));

    let f16 = fat_bpb(512, 4, 1, 2, 512, 0, 200, 200_000, 0);
    assert_eq!(detect_fs(&f16).0, FsType::Fat16);

    let mut f32 = fat_bpb(512, 8, 32, 2, 0, 0, 0, 1_000_000, 1000);
    f32[66] = 0x29;
    put(&mut f32, 71, b"MYUSB      ");
    put(&mut f32, 82, b"FAT32   ");
    assert_eq!(detect_fs(&f32), (FsType::Fat32, Some("MYUSB".into())));

    // An MBR (55AA but no jump instruction) is not FAT.
    let mut mbr = buf();
    put(&mut mbr, 510, &[0x55, 0xAA]);
    assert_eq!(detect_fs(&mbr).0, FsType::Unknown);
}

#[test]
fn detect_oem_id_types() {
    for (sig, fs) in [
        (&b"NTFS    "[..], FsType::Ntfs),
        (b"EXFAT   ", FsType::ExFat),
        (b"-FVE-FS-", FsType::Bitlocker),
        (b"ReFS\0\0\0\0", FsType::Refs),
    ] {
        let mut b = buf();
        b[0] = 0xEB;
        put(&mut b, 3, sig);
        put(&mut b, 510, &[0x55, 0xAA]);
        assert_eq!(detect_fs(&b).0, fs, "{sig:?}");
    }
}

fn ext_sb(compat: u32, incompat: u32, ro: u32) -> Vec<u8> {
    let mut b = buf();
    put(&mut b, 1024 + 0x38, &0xEF53u16.to_le_bytes());
    put(&mut b, 1024 + 0x5c, &compat.to_le_bytes());
    put(&mut b, 1024 + 0x60, &incompat.to_le_bytes());
    put(&mut b, 1024 + 0x64, &ro.to_le_bytes());
    put(&mut b, 1024 + 0x78, b"rootfs");
    b
}

#[test]
fn detect_ext_variants() {
    assert_eq!(detect_fs(&ext_sb(0, 0x2, 0x1)), (FsType::Ext2, Some("rootfs".into())));
    assert_eq!(detect_fs(&ext_sb(0x4, 0x2, 0x1)).0, FsType::Ext3);
    assert_eq!(detect_fs(&ext_sb(0x4, 0x2 | 0x40 | 0x200, 0x1)).0, FsType::Ext4);
    assert_eq!(detect_fs(&ext_sb(0x4, 0x2, 0x400)).0, FsType::Ext4);
}

#[test]
fn detect_other_types() {
    let mut hfs = buf();
    put(&mut hfs, 1024, b"H+");
    assert_eq!(detect_fs(&hfs).0, FsType::HfsPlus);

    let mut apfs = buf();
    put(&mut apfs, 32, b"NXSB");
    assert_eq!(detect_fs(&apfs).0, FsType::Apfs);

    let mut swap = buf();
    put(&mut swap, 4096 - 10, b"SWAPSPACE2");
    assert_eq!(detect_fs(&swap).0, FsType::Swap);
    let mut swap64k = buf();
    put(&mut swap64k, 65536 - 10, b"SWAPSPACE2");
    assert_eq!(detect_fs(&swap64k).0, FsType::Swap);

    let mut lvm = buf();
    put(&mut lvm, 512, b"LABELONE");
    put(&mut lvm, 512 + 24, b"LVM2 001");
    assert_eq!(detect_fs(&lvm).0, FsType::Lvm);

    let mut luks = buf();
    put(&mut luks, 0, b"LUKS\xba\xbe");
    assert_eq!(detect_fs(&luks).0, FsType::Luks);

    let mut btrfs = buf();
    put(&mut btrfs, 0x10040, b"_BHRfS_M");
    assert_eq!(detect_fs(&btrfs).0, FsType::Btrfs);

    let mut xfs = buf();
    put(&mut xfs, 0, b"XFSB");
    assert_eq!(detect_fs(&xfs).0, FsType::Xfs);

    assert_eq!(detect_fs(&buf()).0, FsType::Unknown);
    assert_eq!(detect_fs(&[]).0, FsType::Unknown);
    // Truncated buffers don't panic.
    assert_eq!(detect_fs(&ext_sb(0, 2, 0)[..1070]).0, FsType::Unknown);
}

#[test]
fn partition_type_hints() {
    let efi = fs_from_gpt_type("C12A7328-F81F-11D2-BA4B-00A0C93EC93B");
    assert!(efi.efi && efi.fs == FsType::Fat32);
    assert!(fs_from_gpt_type("de94bba4-06d1-4d40-a16a-bfd50179d6ac").recovery);
    assert_eq!(fs_from_gpt_type("0fc63daf-8483-4772-8e79-3d69d8477de4").fs, FsType::Linux);
    assert_eq!(fs_from_gpt_type("0657fd6d-a4ab-43c4-84e5-0933c84b4f4f").fs, FsType::Swap);
    assert_eq!(fs_from_mbr_type(0x83).fs, FsType::Linux);
    assert!(fs_from_mbr_type(0x05).container);
    assert!(fs_from_mbr_type(0xef).efi);
    let g = [0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b];
    assert_eq!(guid_to_string(&g), "c12a7328-f81f-11d2-ba4b-00a0c93ec93b");
}

#[test]
fn hiberfil_signatures() {
    assert!(ntfs_hiberfil_is_hibernated(b"HIBR\0\0"));
    assert!(ntfs_hiberfil_is_hibernated(b"hibr"));
    assert!(ntfs_hiberfil_is_hibernated(b"WAKE"));
    assert!(!ntfs_hiberfil_is_hibernated(&[0, 0, 0, 0]));
    assert!(!ntfs_hiberfil_is_hibernated(b"HI"));
}

// ---------- policy ----------

fn part() -> Partition {
    Partition {
        id: "disk1p1".into(),
        disk_id: "disk1".into(),
        number: 1,
        label: None,
        fs: FsType::Ntfs,
        size: 1 << 30,
        free: None,
        mount: Some("E:\\".into()),
        mounts: vec![],
        is_system: false,
        is_efi: false,
        is_recovery: false,
        hibernated: false,
        dirty: false,
        os: None,
        access: Access::ReadWrite,
        raw_path: String::new(),
        offset: 0,
        volume: None,
        part_type: String::new(),
        needs_admin: false,
    }
}

#[test]
fn policy_rules() {
    let mut fat = part();
    fat.fs = FsType::Fat32;
    assert_eq!(policy(&fat), Access::ReadWrite);

    let mut sys = part();
    sys.is_system = true;
    sys.os = Some(OsInstall { kind: OsKind::Windows, name: "Windows 11".into(), version: None, users: vec![] });
    assert_eq!(policy(&sys), Access::ReadWrite, "the running OS stays writable");

    let mut other = sys.clone();
    other.is_system = false;
    assert!(matches!(policy(&other), Access::ReadOnly { reason } if reason.contains("Windows 11")));

    let mut efi = part();
    efi.is_efi = true;
    assert!(policy(&efi).is_read_only());
    let mut rec = part();
    rec.is_recovery = true;
    assert!(policy(&rec).is_read_only());

    let mut hib = part();
    hib.hibernated = true;
    assert_eq!(policy(&hib), Access::ReadOnly { reason: HIBERNATED_REASON.into() });
    let mut dirty = part();
    dirty.dirty = true;
    assert!(policy(&dirty).is_read_only());

    for fs in [FsType::Swap, FsType::Lvm, FsType::Bitlocker, FsType::Luks] {
        let mut p = part();
        p.fs = fs;
        assert!(policy(&p).is_read_only(), "{fs:?}");
    }

    // Unmounted ext4 on Windows/macOS is only reachable through RawFs.
    let mut ext = part();
    ext.fs = FsType::Ext4;
    ext.mount = None;
    assert_eq!(policy(&ext).is_read_only(), !cfg!(target_os = "linux"));

    let mut msr = part();
    msr.fs = FsType::Unknown;
    msr.mount = None;
    msr.part_type = "e3c9e316-0b5c-4db8-817d-f92df00215ae".into();
    assert!(policy(&msr).is_read_only());
}

#[test]
fn serde_shapes() {
    assert_eq!(serde_json::to_string(&Access::ReadWrite).unwrap(), r#"{"type":"readWrite"}"#);
    assert_eq!(
        serde_json::to_string(&DiskError::Busy { processes: vec!["a.exe".into()] }).unwrap(),
        r#"{"type":"busy","processes":["a.exe"]}"#
    );
    assert_eq!(serde_json::to_string(&FsType::ExFat).unwrap(), r#""exFat""#);
    let v = serde_json::to_value(part()).unwrap();
    assert!(v.get("isSystem").is_some() && v.get("rawPath").is_some() && v.get("needsAdmin").is_some());
}

// ---------- OS detection on directory fixtures ----------

/// Minimal PE with a .rsrc section holding VS_FIXEDFILEINFO.
fn fake_pe(ms: u32, ls: u32) -> Vec<u8> {
    let mut b = vec![0u8; 4096 + 256];
    put(&mut b, 0, b"MZ");
    put(&mut b, 0x3c, &0x80u32.to_le_bytes());
    put(&mut b, 0x80, b"PE\0\0");
    put(&mut b, 0x80 + 6, &1u16.to_le_bytes());
    put(&mut b, 0x80 + 20, &0u16.to_le_bytes());
    let s = 0x80 + 24;
    put(&mut b, s, b".rsrc\0\0\0");
    put(&mut b, s + 16, &256u32.to_le_bytes());
    put(&mut b, s + 20, &4096u32.to_le_bytes());
    let f = 4096 + 40;
    put(&mut b, f, &0xFEEF04BDu32.to_le_bytes());
    put(&mut b, f + 16, &ms.to_le_bytes());
    put(&mut b, f + 20, &ls.to_le_bytes());
    b
}

fn mkfile(root: &Path, rel: &str, data: &[u8]) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, data).unwrap();
}

#[test]
fn detect_windows_install() {
    let t = tempfile::tempdir().unwrap();
    mkfile(t.path(), "Windows/System32/ntoskrnl.exe", &fake_pe(10 << 16, (22631 << 16) | 4460));
    for u in ["alice", "Public", "Default", "defaultuser0"] {
        std::fs::create_dir_all(t.path().join("Users").join(u)).unwrap();
    }
    std::fs::create_dir_all(t.path().join("Users/alice/Documents")).unwrap();
    let os = detect_os_in_dir(t.path()).unwrap();
    assert_eq!(os.kind, OsKind::Windows);
    assert_eq!(os.name, "Windows 11");
    assert_eq!(os.version.as_deref(), Some("10.0.22631.4460"));
    assert_eq!(os.users, vec!["alice".to_string()]);

    let mut p = part();
    p.mount = Some(t.path().to_string_lossy().into_owned());
    p.os = Some(os.clone());
    let folders = user_folders(&p);
    assert_eq!(folders.len(), 1, "only existing folders: {folders:?}");
    assert!(folders[0].label.contains("Documents") && !folders[0].raw);

    p.mount = None;
    let raw = user_folders(&p);
    assert_eq!(raw.len(), 4);
    assert!(raw.iter().all(|f| f.raw && f.path.starts_with("/Users/alice/")));

    // Windows 10 naming
    let t2 = tempfile::tempdir().unwrap();
    mkfile(t2.path(), "windows/system32/NTOSKRNL.EXE", &fake_pe(10 << 16, 19045 << 16));
    assert_eq!(detect_os_in_dir(t2.path()).unwrap().name, "Windows 10");
}

#[test]
fn detect_linux_and_macos_installs() {
    let t = tempfile::tempdir().unwrap();
    mkfile(t.path(), "etc/os-release", b"NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n");
    std::fs::create_dir_all(t.path().join("home/bob")).unwrap();
    std::fs::create_dir_all(t.path().join("home/lost+found")).unwrap();
    let os = detect_os_in_dir(t.path()).unwrap();
    assert_eq!((os.kind, os.name.as_str(), os.version.as_deref()), (OsKind::Linux, "Ubuntu 24.04.1 LTS", Some("24.04")));
    assert_eq!(os.users, vec!["bob".to_string()]);

    let m = tempfile::tempdir().unwrap();
    mkfile(
        m.path(),
        "System/Library/CoreServices/SystemVersion.plist",
        br#"<?xml version="1.0"?><plist version="1.0"><dict>
<key>ProductName</key>
<string>macOS</string>
<key>ProductVersion</key>
<string>15.1</string>
</dict></plist>"#,
    );
    for u in ["carol", "Shared", ".localized"] {
        std::fs::create_dir_all(m.path().join("Users").join(u)).unwrap();
    }
    let os = detect_os_in_dir(m.path()).unwrap();
    assert_eq!((os.kind, os.name.as_str(), os.version.as_deref()), (OsKind::Macos, "macOS", Some("15.1")));
    assert_eq!(os.users, vec!["carol".to_string()]);

    let empty = tempfile::tempdir().unwrap();
    assert!(detect_os_in_dir(empty.path()).is_none());
}

#[test]
fn mounted_hibernation_check() {
    let t = tempfile::tempdir().unwrap();
    mkfile(t.path(), "hiberfil.sys", b"HIBR\0\0\0\0");
    assert!(crate::os::mounted_hiberfil_hibernated(t.path()));
    let mut p = part();
    p.mount = Some(t.path().to_string_lossy().into_owned());
    enrich_partition(&mut p);
    assert!(p.hibernated && p.access.is_read_only());
}

// ---------- hand-built ext4 image ----------

const BS: usize = 1024;

struct Img(Vec<u8>);

impl Img {
    fn inode(&mut self, ino: u32, mode: u16, size: u32, links: u16, iblock: &[u8], extents: bool) {
        let off = 5 * BS + (ino as usize - 1) * 128;
        put(&mut self.0, off, &mode.to_le_bytes());
        put(&mut self.0, off + 4, &size.to_le_bytes());
        put(&mut self.0, off + 0x10, &1_700_000_000u32.to_le_bytes());
        put(&mut self.0, off + 0x1a, &links.to_le_bytes());
        if extents {
            put(&mut self.0, off + 0x20, &0x80000u32.to_le_bytes());
        }
        put(&mut self.0, off + 0x28, iblock);
    }
    /// One-extent tree: `len` blocks starting at `start`.
    fn extent(start: u32, len: u16) -> Vec<u8> {
        let mut e = vec![0u8; 24];
        put(&mut e, 0, &0xF30Au16.to_le_bytes());
        put(&mut e, 2, &1u16.to_le_bytes());
        put(&mut e, 4, &4u16.to_le_bytes());
        put(&mut e, 12, &0u32.to_le_bytes());
        put(&mut e, 16, &len.to_le_bytes());
        put(&mut e, 20, &start.to_le_bytes());
        e
    }
    fn dir(&mut self, block: usize, entries: &[(u32, u8, &str)]) {
        let mut off = block * BS;
        let end = off + BS;
        for (i, (ino, ft, name)) in entries.iter().enumerate() {
            let need = (8 + name.len()).div_ceil(4) * 4;
            let rec = if i + 1 == entries.len() { end - off } else { need };
            put(&mut self.0, off, &ino.to_le_bytes());
            put(&mut self.0, off + 4, &(rec as u16).to_le_bytes());
            self.0[off + 6] = name.len() as u8;
            self.0[off + 7] = *ft;
            put(&mut self.0, off + 8, name.as_bytes());
            off += rec;
        }
    }
}

/// Builds a 64 KiB ext4 image (1 KiB blocks, extents, no checksums/journal):
/// /dir/hello.txt (1500 bytes, 2 blocks), /etc/os-release, /etc/link -> os-release, /home/alice/
fn ext4_image() -> (Vec<u8>, Vec<u8>) {
    let mut img = Img(vec![0u8; 64 * BS]);
    let sb = BS;
    put(&mut img.0, sb, &32u32.to_le_bytes()); // inodes
    put(&mut img.0, sb + 4, &64u32.to_le_bytes()); // blocks
    put(&mut img.0, sb + 0x14, &1u32.to_le_bytes()); // first data block
    put(&mut img.0, sb + 0x18, &0u32.to_le_bytes()); // 1 KiB blocks
    put(&mut img.0, sb + 0x20, &8192u32.to_le_bytes()); // blocks/group
    put(&mut img.0, sb + 0x28, &32u32.to_le_bytes()); // inodes/group
    put(&mut img.0, sb + 0x38, &0xEF53u16.to_le_bytes());
    put(&mut img.0, sb + 0x4c, &1u32.to_le_bytes()); // rev 1
    put(&mut img.0, sb + 0x54, &11u32.to_le_bytes()); // first ino
    put(&mut img.0, sb + 0x58, &128u16.to_le_bytes()); // inode size
    put(&mut img.0, sb + 0x60, &(0x2u32 | 0x40).to_le_bytes()); // filetype | extents
    put(&mut img.0, sb + 0x68, &[7u8; 16]); // uuid
    put(&mut img.0, sb + 0x78, b"navtest");
    // Group descriptor at block 2: bitmaps 3/4, inode table 5..8.
    put(&mut img.0, 2 * BS, &3u32.to_le_bytes());
    put(&mut img.0, 2 * BS + 4, &4u32.to_le_bytes());
    put(&mut img.0, 2 * BS + 8, &5u32.to_le_bytes());

    let hello: Vec<u8> = (0..1500u32).map(|i| b'a' + (i % 26) as u8).collect();
    let osr = b"PRETTY_NAME=\"Test Linux 1.0\"\nVERSION_ID=1.0\n";

    img.inode(2, 0x41ED, BS as u32, 5, &Img::extent(10, 1), true);
    img.dir(10, &[(2, 2, "."), (2, 2, ".."), (11, 2, "dir"), (13, 2, "etc"), (15, 2, "home")]);
    img.inode(11, 0x41ED, BS as u32, 2, &Img::extent(11, 1), true);
    img.dir(11, &[(11, 2, "."), (2, 2, ".."), (12, 1, "hello.txt")]);
    img.inode(12, 0x81A4, hello.len() as u32, 1, &Img::extent(12, 2), true);
    put(&mut img.0, 12 * BS, &hello);
    img.inode(13, 0x41ED, BS as u32, 2, &Img::extent(14, 1), true);
    img.dir(14, &[(13, 2, "."), (2, 2, ".."), (14, 1, "os-release"), (17, 7, "link")]);
    img.inode(14, 0x81A4, osr.len() as u32, 1, &Img::extent(15, 1), true);
    put(&mut img.0, 15 * BS, osr);
    img.inode(15, 0x41ED, BS as u32, 3, &Img::extent(16, 1), true);
    img.dir(16, &[(15, 2, "."), (2, 2, ".."), (16, 2, "alice")]);
    img.inode(16, 0x41ED, BS as u32, 2, &Img::extent(17, 1), true);
    img.dir(17, &[(16, 2, "."), (15, 2, "..")]);
    img.inode(17, 0xA1FF, 10, 1, b"os-release", false); // fast symlink
    (img.0, hello)
}

#[test]
fn ext4_image_detected_as_ext4() {
    let (img, _) = ext4_image();
    assert_eq!(detect_fs(&img), (FsType::Ext4, Some("navtest".into())));
}

#[test]
fn rawfs_reads_ext4_image() {
    let (img, hello) = ext4_image();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.img");
    std::fs::write(&path, &img).unwrap();
    let fs = RawFs::open_image(&path).unwrap();
    assert_eq!(fs.fs_type(), FsType::Ext4);
    assert_eq!(fs.label().as_deref(), Some("navtest"));

    let mut root: Vec<String> = fs.list("/").unwrap().into_iter().map(|e| e.name).collect();
    root.sort();
    assert_eq!(root, ["dir", "etc", "home"]);

    let e = fs.stat("/dir/hello.txt").unwrap();
    assert_eq!((e.name.as_str(), e.is_dir, e.size, e.modified), ("hello.txt", false, 1500, Some(1_700_000_000_000)));
    assert!(fs.stat("dir").unwrap().is_dir);
    assert_eq!(fs.stat("/nope"), Err(DiskError::NotFound));

    assert_eq!(fs.read_at("/dir/hello.txt", 0, 10_000).unwrap(), hello);
    // Crosses the block boundary at 1024.
    assert_eq!(fs.read_at("\\dir\\hello.txt", 1000, 100).unwrap(), &hello[1000..1100]);
    assert!(fs.read_at("/dir/hello.txt", 5000, 10).unwrap().is_empty());

    let etc = fs.list("/etc").unwrap();
    let link = etc.iter().find(|e| e.name == "link").unwrap();
    assert!(link.is_link && link.path == "/etc/link");

    let probe = fs.probe();
    let os = probe.os.unwrap();
    assert_eq!((os.kind, os.name.as_str()), (OsKind::Linux, "Test Linux 1.0"));
    assert_eq!(os.users, vec!["alice".to_string()]);
    assert!(!probe.hibernated && !probe.dirty);
}

#[test]
fn rawfs_reads_partition_at_offset() {
    // Image embedded at 1 MiB inside a "disk", like a partition.
    let (img, hello) = ext4_image();
    let mut disk = vec![0u8; (1 << 20) + img.len() + 4096];
    disk[1 << 20..(1 << 20) + img.len()].copy_from_slice(&img);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("disk.img");
    std::fs::write(&path, &disk).unwrap();
    let p = path.to_string_lossy().into_owned();
    let fs = RawFs::open_raw(&p, 1 << 20, img.len() as u64, None).unwrap();
    assert_eq!(fs.read_at("/dir/hello.txt", 0, 1500).unwrap(), hello);
    let probe = crate::rawfs::probe_raw(&p, 1 << 20, img.len() as u64).unwrap();
    assert_eq!(probe.fs, FsType::Ext4);
    assert_eq!(probe.label.as_deref(), Some("navtest"));
    // Non-filesystem region -> Unsupported, not a panic.
    assert!(matches!(RawFs::open_raw(&p, 0, 65536, None), Err(DiskError::Unsupported { .. })));
}

// ---------- helper protocol (in-memory pipes) ----------

fn start_helper(token: &'static str) -> (std::thread::JoinHandle<Result<(), DiskError>>, std::io::PipeReader, std::io::PipeWriter) {
    let (req_r, req_w) = std::io::pipe().unwrap();
    let (resp_r, resp_w) = std::io::pipe().unwrap();
    let h = std::thread::spawn(move || serve(req_r, resp_w, token, &|_| true));
    (h, resp_r, req_w)
}

#[test]
fn helper_protocol_roundtrip() {
    let (img, hello) = ext4_image();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.img");
    std::fs::write(&path, &img).unwrap();

    let (h, r, w) = start_helper("s3cret");
    let client = HelperClient::over_streams(Box::new(r), Box::new(w), "s3cret").unwrap();
    let fs = client.open_raw(&path.to_string_lossy(), 0, 0, None).unwrap();
    assert_eq!(fs.fs_type(), FsType::Ext4);
    assert_eq!(fs.list("/dir").unwrap()[0].name, "hello.txt");
    assert_eq!(fs.stat("/dir/hello.txt").unwrap().size, 1500);
    assert_eq!(fs.read_at("/dir/hello.txt", 26, 4).unwrap(), &hello[26..30]);
    assert_eq!(fs.stat("/missing"), Err(DiskError::NotFound));
    drop(fs);
    client.shutdown();
    h.join().unwrap().unwrap();
}

#[test]
fn helper_rejects_bad_token() {
    let (h, r, w) = start_helper("right");
    assert!(HelperClient::over_streams(Box::new(r), Box::new(w), "wrong").is_err());
    assert!(h.join().unwrap().is_err());
}

#[test]
fn helper_raw_path_allowlist() {
    assert!(windows_raw_path_allowed(r"\\.\PhysicalDrive0"));
    assert!(windows_raw_path_allowed(r"\\.\PhysicalDrive12"));
    assert!(!windows_raw_path_allowed(r"\\.\PhysicalDrive"));
    assert!(!windows_raw_path_allowed(r"C:\Windows\System32\config\SAM"));
    assert!(!windows_raw_path_allowed(r"\\.\PhysicalDrive0\..\C:"));
}

#[test]
fn eject_refuses_internal_and_system_disks() {
    let mut d = Disk {
        id: "disk0".into(),
        model: "x".into(),
        bus: Bus::Nvme,
        removable: false,
        size: 1,
        partition_style: "gpt".into(),
        raw_path: String::new(),
        partitions: vec![part()],
    };
    assert!(check_ejectable(&d).is_err());
    d.bus = Bus::Usb;
    assert!(check_ejectable(&d).is_ok());
    d.partitions[0].is_system = true;
    assert!(check_ejectable(&d).is_err());
}

#[cfg(windows)]
#[test]
fn pnp_event_xml_parsing() {
    let xml = "<Event><EventData><Data Name='ProcessId'>7116</Data>\
<Data Name='ProcessName'>\\Device\\HarddiskVolume3\\Windows\\explorer.exe</Data>\
<Data Name='DeviceInstance'>USBSTOR\\Disk&amp;Ven_X</Data></EventData></Event>";
    assert_eq!(crate::windows::exe_names_in_event_xml(xml), vec!["explorer.exe".to_string()]);
}
