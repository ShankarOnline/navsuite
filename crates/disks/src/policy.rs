//! DB3: read-only policy for partitions that belong to another OS or are fragile.

use crate::{Access, FsType, Partition};

pub const HIBERNATED_REASON: &str = "Windows is hibernated or Fast Startup is on for this volume. \
Writing to it could corrupt data; shut Windows down fully (or disable Fast Startup) to make it writable.";

fn ro(reason: impl Into<String>) -> Access {
    Access::ReadOnly { reason: reason.into() }
}

/// File systems the host OS can mount read-write natively.
fn host_writes_natively(fs: FsType) -> bool {
    if cfg!(windows) {
        matches!(fs, FsType::Ntfs | FsType::Refs) || fs.is_fat()
    } else if cfg!(target_os = "macos") {
        matches!(fs, FsType::HfsPlus | FsType::Apfs) || fs.is_fat()
    } else {
        // Linux: ext*, btrfs, xfs, FAT/exFAT, NTFS (ntfs3).
        fs.is_ext() || fs.is_fat() || matches!(fs, FsType::Btrfs | FsType::Xfs | FsType::Ntfs)
    }
}

/// Decide whether the app may write to a partition.
///
/// Read-only when: it is an EFI or recovery partition; NTFS is hibernated or
/// dirty; it holds an OS install that isn't the running one; it isn't a plain
/// file system (swap, LVM, BitLocker, LUKS); or it is not mounted and the host
/// can't write that file system natively (so it would be reached through the
/// raw readers, which are read-only).
pub fn policy(p: &Partition) -> Access {
    if p.is_system {
        return Access::ReadWrite;
    }
    if p.is_efi {
        return ro("EFI system partition (boot loader files)");
    }
    if p.is_recovery {
        return ro("Recovery partition");
    }
    if p.hibernated {
        return ro(HIBERNATED_REASON);
    }
    if p.dirty {
        return ro("The volume was not shut down cleanly (NTFS dirty flag); run a check from Windows first");
    }
    if let Some(os) = &p.os {
        return ro(format!(
            "Holds another operating system ({}); opened read-only to protect it",
            os.name
        ));
    }
    if p.part_type == "e3c9e316-0b5c-4db8-817d-f92df00215ae" {
        return ro("Microsoft reserved partition (no file system)");
    }
    match p.fs {
        FsType::Swap => return ro("Swap space, not a file system"),
        FsType::Lvm => return ro("LVM physical volume (opened read-only)"),
        FsType::Bitlocker => return ro("BitLocker-encrypted volume"),
        FsType::Luks => return ro("LUKS-encrypted volume"),
        _ => {}
    }
    if p.mount.is_none() && !host_writes_natively(p.fs) {
        return ro("Read through the built-in raw reader, which is read-only");
    }
    Access::ReadWrite
}
