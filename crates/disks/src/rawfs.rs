//! DB5/DB6: read-only access to ext2/3/4 (`ext4-view`) and NTFS (`ntfs`) file
//! systems straight from a raw partition, without the OS mounting it.
//!
//! `ext4_view::Ext4` is `!Send` (it uses `Rc`), so each [`RawFs`] owns a worker
//! thread that holds the file system; calls are forwarded over a channel. This
//! makes `RawFs` `Send + Sync` and keeps the block cache warm across calls.

use crate::detect::{PROBE_LEN, detect_fs, ntfs_hiberfil_is_hibernated};
use crate::os::{Probe, detect_os};
use crate::rawdev::{BlockReader, open_device};
use crate::{DiskError, FsType, OsInstall, Partition};
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom};
use std::sync::mpsc;

/// Largest single `read_at` request (bytes).
pub const MAX_READ: usize = 16 << 20;

/// A directory entry or stat result from a [`RawFs`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RawEntry {
    pub name: String,
    /// Absolute path inside the partition, `/`-separated.
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    /// Modification time, unix milliseconds.
    pub modified: Option<i64>,
    pub is_link: bool,
}

/// What reading a partition raw revealed.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RawProbe {
    pub fs: FsType,
    pub label: Option<String>,
    pub hibernated: bool,
    pub dirty: bool,
    pub os: Option<OsInstall>,
}

enum Backend {
    Ext4(ext4_view::Ext4),
    Ntfs { ntfs: ntfs::Ntfs, dev: BlockReader },
}

type Job = Box<dyn FnOnce(&mut Backend) + Send>;

/// Read-only view of one partition's file system (ext2/3/4 or NTFS).
pub struct RawFs {
    tx: mpsc::Sender<Job>,
    fs: FsType,
}

impl std::fmt::Debug for RawFs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawFs").field("fs", &self.fs).finish()
    }
}

fn ext_err(e: ext4_view::Ext4Error) -> DiskError {
    match e {
        ext4_view::Ext4Error::NotFound => DiskError::NotFound,
        ext4_view::Ext4Error::Io(io) => {
            match io.downcast_ref::<std::io::Error>().map(|e| e.kind()) {
                Some(std::io::ErrorKind::PermissionDenied) => DiskError::NeedsAdmin,
                _ => DiskError::io(io),
            }
        }
        e => DiskError::io(e),
    }
}

fn ntfs_err(e: ntfs::NtfsError) -> DiskError {
    DiskError::io(format!("NTFS: {e}"))
}

/// Normalize to "/a/b" (accepts "", "/", "a\\b", "/a/b/").
fn norm(path: &str) -> String {
    let parts: Vec<&str> = path.split(['/', '\\']).filter(|c| !c.is_empty() && *c != ".").collect();
    format!("/{}", parts.join("/"))
}

fn join(dir: &str, name: &str) -> String {
    if dir == "/" { format!("/{name}") } else { format!("{dir}/{name}") }
}

fn base_name(path: &str) -> String {
    path.rsplit('/').next().unwrap_or("").to_string()
}

fn nt_to_unix_ms(t: ntfs::NtfsTime) -> Option<i64> {
    let ticks = t.nt_timestamp();
    if ticks == 0 {
        return None;
    }
    Some((ticks / 10_000) as i64 - 11_644_473_600_000)
}

fn ext_entry(path: String, md: &ext4_view::Metadata) -> RawEntry {
    let m = md.modified();
    RawEntry {
        name: base_name(&path),
        path,
        is_dir: md.is_dir(),
        size: if md.is_dir() { 0 } else { md.len() },
        modified: Some(m.seconds() * 1000 + i64::from(m.nanoseconds() / 1_000_000)),
        is_link: md.is_symlink(),
    }
}

impl Backend {
    fn load(raw_path: &str, offset: u64, size: u64, hint: Option<FsType>) -> Result<(Backend, FsType), DiskError> {
        let dev = open_device(raw_path)?;
        let size = if size == 0 { dev.metadata().map(|m| m.len()).unwrap_or(0) } else { size };
        if size == 0 {
            return Err(DiskError::io("unknown partition size"));
        }
        let mut reader = BlockReader::new(Box::new(dev), offset, size);
        let mut fs = hint.unwrap_or(FsType::Unknown);
        if !(fs.is_ext() || fs == FsType::Ntfs) {
            let n = PROBE_LEN.min(reader.len() as usize);
            let mut head = vec![0u8; n];
            reader.read_exact_at(0, &mut head).map_err(DiskError::from)?;
            fs = detect_fs(&head).0;
        }
        if fs.is_ext() {
            let ext = ext4_view::Ext4::load(Box::new(reader)).map_err(ext_err)?;
            Ok((Backend::Ext4(ext), fs))
        } else if fs == FsType::Ntfs {
            let mut ntfs = ntfs::Ntfs::new(&mut reader).map_err(ntfs_err)?;
            ntfs.read_upcase_table(&mut reader).map_err(ntfs_err)?;
            Ok((Backend::Ntfs { ntfs, dev: reader }, fs))
        } else {
            Err(DiskError::unsupported(format!("raw reading of {fs:?} is not supported")))
        }
    }

    fn label(&mut self) -> Option<String> {
        match self {
            Backend::Ext4(e) => {
                let l = e.label().to_str().ok()?.trim_end_matches('\0').trim().to_string();
                (!l.is_empty()).then_some(l)
            }
            Backend::Ntfs { ntfs, dev } => {
                let n = ntfs.volume_name(dev)?.ok()?;
                let l = n.name().to_string_lossy();
                (!l.is_empty()).then_some(l)
            }
        }
    }

    fn dirty(&mut self) -> bool {
        match self {
            Backend::Ext4(_) => false,
            Backend::Ntfs { ntfs, dev } => ntfs
                .volume_info(dev)
                .map(|v| v.flags().contains(ntfs::structured_values::NtfsVolumeFlags::IS_DIRTY))
                .unwrap_or(false),
        }
    }

    fn list(&mut self, path: &str) -> Result<Vec<RawEntry>, DiskError> {
        let path = norm(path);
        match self {
            Backend::Ext4(fs) => {
                let mut out = Vec::new();
                for e in fs.read_dir(path.as_str()).map_err(ext_err)? {
                    let e = e.map_err(ext_err)?;
                    let name = e.file_name();
                    if name.as_ref() == b"." || name.as_ref() == b".." {
                        continue;
                    }
                    let name = match name.as_str() {
                        Ok(s) => s.to_string(),
                        Err(_) => name.display().to_string(),
                    };
                    let md = e.metadata().map_err(ext_err)?;
                    out.push(ext_entry(join(&path, &name), &md));
                }
                Ok(out)
            }
            Backend::Ntfs { ntfs, dev } => {
                use ntfs::structured_values::{NtfsFileAttributeFlags, NtfsFileNamespace};
                let file = ntfs_resolve(ntfs, dev, &path)?;
                let index = file.directory_index(dev).map_err(ntfs_err)?;
                let mut entries = index.entries();
                let mut out = Vec::new();
                while let Some(e) = entries.next(dev) {
                    let e = e.map_err(ntfs_err)?;
                    let Some(key) = e.key() else { continue };
                    let key = key.map_err(ntfs_err)?;
                    if key.namespace() == NtfsFileNamespace::Dos {
                        continue;
                    }
                    let name = key.name().to_string_lossy();
                    // Skip "." and NTFS metadata files ($MFT, $Bitmap, ...).
                    if name == "." || (e.file_reference().file_record_number() < 24 && name.starts_with('$')) {
                        continue;
                    }
                    let is_dir = key.is_directory();
                    out.push(RawEntry {
                        path: join(&path, &name),
                        name,
                        is_dir,
                        size: if is_dir { 0 } else { key.data_size() },
                        modified: nt_to_unix_ms(key.modification_time()),
                        is_link: key.file_attributes().contains(NtfsFileAttributeFlags::REPARSE_POINT),
                    });
                }
                Ok(out)
            }
        }
    }

    fn stat(&mut self, path: &str) -> Result<RawEntry, DiskError> {
        let path = norm(path);
        match self {
            Backend::Ext4(fs) => {
                let md = fs.symlink_metadata(path.as_str()).map_err(ext_err)?;
                Ok(ext_entry(path, &md))
            }
            Backend::Ntfs { ntfs, dev } => {
                use ntfs::structured_values::NtfsFileAttributeFlags;
                let file = ntfs_resolve(ntfs, dev, &path)?;
                let info = file.info().map_err(ntfs_err)?;
                let is_dir = file.is_directory();
                let size = if is_dir {
                    0
                } else {
                    match file.data(dev, "") {
                        Some(item) => item.map_err(ntfs_err)?.to_attribute().map_err(ntfs_err)?.value_length(),
                        None => 0,
                    }
                };
                Ok(RawEntry {
                    name: base_name(&path),
                    path,
                    is_dir,
                    size,
                    modified: nt_to_unix_ms(info.modification_time()),
                    is_link: info.file_attributes().contains(NtfsFileAttributeFlags::REPARSE_POINT),
                })
            }
        }
    }

    fn read_at(&mut self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>, DiskError> {
        let path = norm(path);
        let len = len.min(MAX_READ);
        let mut buf = vec![0u8; len];
        let mut got = 0;
        match self {
            Backend::Ext4(fs) => {
                let mut f = fs.open(path.as_str()).map_err(ext_err)?;
                if offset >= f.metadata().len() {
                    return Ok(Vec::new());
                }
                f.seek_to(offset).map_err(ext_err)?;
                while got < len {
                    let n = f.read_bytes(&mut buf[got..]).map_err(ext_err)?;
                    if n == 0 {
                        break;
                    }
                    got += n;
                }
            }
            Backend::Ntfs { ntfs, dev } => {
                let file = ntfs_resolve(ntfs, dev, &path)?;
                if file.is_directory() {
                    return Err(DiskError::unsupported("is a directory"));
                }
                let item = file.data(dev, "").ok_or(DiskError::NotFound)?.map_err(ntfs_err)?;
                let attr = item.to_attribute().map_err(ntfs_err)?;
                if offset >= attr.value_length() {
                    return Ok(Vec::new());
                }
                let value = attr.value(dev).map_err(ntfs_err)?;
                let mut v = value.attach(dev);
                v.seek(SeekFrom::Start(offset)).map_err(DiskError::from)?;
                while got < len {
                    let n = v.read(&mut buf[got..]).map_err(DiskError::from)?;
                    if n == 0 {
                        break;
                    }
                    got += n;
                }
            }
        }
        buf.truncate(got);
        Ok(buf)
    }
}

fn ntfs_resolve<'n>(ntfs: &'n ntfs::Ntfs, dev: &mut BlockReader, path: &str) -> Result<ntfs::NtfsFile<'n>, DiskError> {
    use ntfs::indexes::NtfsFileNameIndex;
    let mut file = ntfs.root_directory(dev).map_err(ntfs_err)?;
    for comp in path.split('/').filter(|c| !c.is_empty()) {
        let next = {
            let index = file.directory_index(dev).map_err(|_| DiskError::NotFound)?;
            let mut finder = index.finder();
            let entry = NtfsFileNameIndex::find(&mut finder, ntfs, dev, comp)
                .ok_or(DiskError::NotFound)?
                .map_err(ntfs_err)?;
            entry.to_file(ntfs, dev).map_err(ntfs_err)?
        };
        file = next;
    }
    Ok(file)
}

impl RawFs {
    /// Open a partition's file system read-only. Uses `partition.fs` as a hint
    /// and sniffs the superblock otherwise. `Err(NeedsAdmin)` when the raw device
    /// can't be opened (Windows: not elevated; Linux/macOS: not root/disk group).
    pub fn open(partition: &Partition) -> Result<Self, DiskError> {
        Self::open_raw(&partition.raw_path, partition.offset, partition.size, Some(partition.fs))
    }

    /// Open a raw device/image region: `raw_path` read from `offset` for `size`
    /// bytes (`size == 0` = whole file, for image files).
    pub fn open_raw(raw_path: &str, offset: u64, size: u64, fs_hint: Option<FsType>) -> Result<Self, DiskError> {
        let (tx, rx) = mpsc::channel::<Job>();
        let (itx, irx) = mpsc::channel::<Result<FsType, DiskError>>();
        let raw_path = raw_path.to_string();
        std::thread::Builder::new()
            .name("disks-rawfs".into())
            .spawn(move || {
                let mut backend = match Backend::load(&raw_path, offset, size, fs_hint) {
                    Ok((b, fs)) => {
                        let _ = itx.send(Ok(fs));
                        b
                    }
                    Err(e) => {
                        let _ = itx.send(Err(e));
                        return;
                    }
                };
                while let Ok(job) = rx.recv() {
                    job(&mut backend);
                }
            })
            .map_err(DiskError::from)?;
        let fs = irx.recv().map_err(|_| DiskError::io("raw reader thread failed"))??;
        Ok(RawFs { tx, fs })
    }

    /// Open a whole image file (e.g. an ext4 `.img`).
    pub fn open_image(path: &std::path::Path) -> Result<Self, DiskError> {
        Self::open_raw(&path.to_string_lossy(), 0, 0, None)
    }

    fn call<R: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Backend) -> Result<R, DiskError> + Send + 'static,
    ) -> Result<R, DiskError> {
        let (rtx, rrx) = mpsc::channel();
        self.tx
            .send(Box::new(move |b| {
                let _ = rtx.send(f(b));
            }))
            .map_err(|_| DiskError::io("raw reader closed"))?;
        rrx.recv().map_err(|_| DiskError::io("raw reader closed"))?
    }

    pub fn fs_type(&self) -> FsType {
        self.fs
    }

    pub fn label(&self) -> Option<String> {
        self.call(|b| Ok(b.label())).ok().flatten()
    }

    pub fn list(&self, path: &str) -> Result<Vec<RawEntry>, DiskError> {
        let path = path.to_string();
        self.call(move |b| b.list(&path))
    }

    pub fn stat(&self, path: &str) -> Result<RawEntry, DiskError> {
        let path = path.to_string();
        self.call(move |b| b.stat(&path))
    }

    /// Read up to `len` bytes (capped at [`MAX_READ`]) at `offset`; shorter at EOF.
    pub fn read_at(&self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>, DiskError> {
        let path = path.to_string();
        self.call(move |b| b.read_at(&path, offset, len))
    }

    /// Label, OS install, hibernation (hiberfil.sys header) and dirty flag.
    pub fn probe(&self) -> RawProbe {
        let fs = self.fs;
        let hibernated = fs == FsType::Ntfs
            && self.read_at("/hiberfil.sys", 0, 4).is_ok_and(|h| ntfs_hiberfil_is_hibernated(&h));
        RawProbe {
            fs,
            label: self.label(),
            hibernated,
            dirty: self.call(|b| Ok(b.dirty())).unwrap_or(false),
            os: detect_os(self),
        }
    }
}

impl Probe for RawFs {
    fn kind(&self, path: &str) -> Option<bool> {
        self.stat(path).ok().map(|e| e.is_dir)
    }
    fn read_at(&self, path: &str, offset: u64, len: usize) -> Option<Vec<u8>> {
        RawFs::read_at(self, path, offset, len).ok()
    }
    fn subdirs(&self, path: &str) -> Vec<String> {
        let mut v: Vec<String> = self
            .list(path)
            .unwrap_or_default()
            .into_iter()
            .filter(|e| e.is_dir && !e.is_link)
            .map(|e| e.name)
            .collect();
        v.sort_by_key(|s| s.to_lowercase());
        v
    }
}

/// Probe a partition by reading it raw: file system from the superblock, and
/// for ext*/NTFS also label, OS install, hibernation and dirty state.
pub(crate) fn probe_raw(raw_path: &str, offset: u64, size: u64) -> Result<RawProbe, DiskError> {
    let head = crate::rawdev::read_head(raw_path, offset, size, PROBE_LEN)?;
    let (fs, label) = detect_fs(&head);
    if (fs.is_ext() || fs == FsType::Ntfs)
        && let Ok(r) = RawFs::open_raw(raw_path, offset, size, Some(fs))
    {
        let mut p = r.probe();
        p.label = p.label.or(label);
        return Ok(p);
    }
    Ok(RawProbe { fs, label, hibernated: false, dirty: false, os: None })
}

/// Probe a [`Partition`] raw (see [`RawFs::probe`]); `Err(NeedsAdmin)` if denied.
pub fn probe_partition(p: &Partition) -> Result<RawProbe, DiskError> {
    probe_raw(&p.raw_path, p.offset, p.size)
}
