//! Read-only raw device access with aligned reads and an in-memory block cache.
//!
//! Raw disk devices (Windows `\\.\PhysicalDriveN`, macOS `/dev/rdiskN`) require
//! sector-aligned offsets, lengths and (sometimes) buffers, so every device read
//! here is a whole, 4096-aligned chunk into a 4096-aligned buffer. Devices are
//! opened with read access only; nothing in this module can write.

use crate::DiskError;
use std::collections::HashMap;
use std::io::{self, Read, Seek, SeekFrom};

/// Anything we can read at an absolute offset.
pub(crate) trait Device: Send {
    /// Read up to `buf.len()` bytes at `offset`; may return fewer at end of device.
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize>;
}

impl Device for std::fs::File {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        #[cfg(windows)]
        {
            use std::os::windows::fs::FileExt;
            self.seek_read(buf, offset)
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            FileExt::read_at(self, buf, offset)
        }
        #[cfg(not(any(windows, unix)))]
        {
            self.seek(SeekFrom::Start(offset))?;
            self.read(buf)
        }
    }
}

/// Open a device or image file strictly read-only.
pub(crate) fn open_device(path: &str) -> Result<std::fs::File, DiskError> {
    let mut o = std::fs::OpenOptions::new();
    o.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // GENERIC_READ + FILE_SHARE_READ | FILE_SHARE_WRITE; never locks the volume.
        o.share_mode(0x1 | 0x2);
    }
    o.open(path).map_err(|e| match e.kind() {
        io::ErrorKind::PermissionDenied => DiskError::NeedsAdmin,
        io::ErrorKind::NotFound => DiskError::NotFound,
        _ => DiskError::io(format!("{path}: {e}")),
    })
}

const ALIGN: usize = 4096;
const CHUNK: usize = 64 * 1024;
const MAX_CHUNKS: usize = 256; // 16 MiB cache

struct AlignedBuf {
    raw: Vec<u8>,
    off: usize,
}

impl AlignedBuf {
    fn new() -> Self {
        let raw = vec![0u8; CHUNK + ALIGN];
        let off = raw.as_ptr().align_offset(ALIGN);
        AlignedBuf { raw, off }
    }
    fn buf(&self) -> &[u8] {
        &self.raw[self.off..self.off + CHUNK]
    }
    fn buf_mut(&mut self) -> &mut [u8] {
        &mut self.raw[self.off..self.off + CHUNK]
    }
}

/// A window `[base, base+len)` of a device, readable at any offset/length.
pub(crate) struct BlockReader {
    dev: Box<dyn Device>,
    base: u64,
    len: u64,
    pos: u64,
    cache: HashMap<u64, (u64, AlignedBuf)>,
    tick: u64,
}

impl BlockReader {
    pub(crate) fn new(dev: Box<dyn Device>, base: u64, len: u64) -> Self {
        BlockReader { dev, base, len, pos: 0, cache: HashMap::new(), tick: 0 }
    }

    pub(crate) fn len(&self) -> u64 {
        self.len
    }

    fn chunk(&mut self, idx: u64) -> io::Result<&AlignedBuf> {
        self.tick += 1;
        let tick = self.tick;
        if !self.cache.contains_key(&idx) {
            if self.cache.len() >= MAX_CHUNKS
                && let Some(old) = self.cache.iter().min_by_key(|(_, (t, _))| *t).map(|(k, _)| *k)
            {
                self.cache.remove(&old);
            }
            let mut b = AlignedBuf::new();
            let start = idx * CHUNK as u64;
            let dev_end = (self.base + self.len).div_ceil(512) * 512;
            let want = (dev_end.saturating_sub(start)).min(CHUNK as u64) as usize;
            let want = want.div_ceil(512) * 512;
            let mut got = 0;
            while got < want {
                let n = self.dev.read_at(start + got as u64, &mut b.buf_mut()[got..want])?;
                if n == 0 {
                    break;
                }
                got += n;
            }
            // Anything past the end of the device stays zero.
            self.cache.insert(idx, (tick, b));
        }
        let e = self.cache.get_mut(&idx).expect("inserted above");
        e.0 = tick;
        Ok(&e.1)
    }

    /// Read exactly `dst.len()` bytes at partition-relative `offset`.
    pub(crate) fn read_exact_at(&mut self, offset: u64, dst: &mut [u8]) -> io::Result<()> {
        if offset.checked_add(dst.len() as u64).is_none_or(|e| e > self.len) {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "read past end of partition"));
        }
        let mut done = 0usize;
        while done < dst.len() {
            let abs = self.base + offset + done as u64;
            let idx = abs / CHUNK as u64;
            let within = (abs % CHUNK as u64) as usize;
            let n = (CHUNK - within).min(dst.len() - done);
            let c = self.chunk(idx)?;
            dst[done..done + n].copy_from_slice(&c.buf()[within..within + n]);
            done += n;
        }
        Ok(())
    }
}

impl ext4_view::Ext4Read for BlockReader {
    fn read(
        &mut self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        self.read_exact_at(start_byte, dst).map_err(|e| Box::new(e).into())
    }
}

impl Read for BlockReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = (self.len.saturating_sub(self.pos)).min(buf.len() as u64) as usize;
        self.read_exact_at(self.pos, &mut buf[..n])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for BlockReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(p) => Some(p),
            SeekFrom::End(d) => self.len.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid seek"))?;
        self.pos = new;
        Ok(new)
    }
}

/// Read the first `len` bytes of a partition for file system detection.
pub(crate) fn read_head(raw_path: &str, offset: u64, size: u64, len: usize) -> Result<Vec<u8>, DiskError> {
    let dev = open_device(raw_path)?;
    let size = if size == 0 { len as u64 } else { size };
    let mut r = BlockReader::new(Box::new(dev), offset, size);
    let n = (len as u64).min(size) as usize;
    let mut buf = vec![0u8; n];
    r.read_exact_at(0, &mut buf).map_err(DiskError::from)?;
    Ok(buf)
}
