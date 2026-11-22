//! The copy engine: runs one job, file by file.

use crate::*;
use sha2::{Digest, Sha256};
use vfs::{ErrorKind, FileHandle, VfsError, WriteMode};

const RETRIES: u32 = 3;

pub(crate) enum Stop {
    Pause,
    Cancel,
    Mismatch,
    Err(VfsError),
}

impl From<VfsError> for Stop {
    fn from(e: VfsError) -> Self {
        Stop::Err(e)
    }
}

pub(crate) fn hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

fn sha_hex(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

fn parse(s: &str) -> std::result::Result<Loc, Stop> {
    Loc::parse(s).map_err(Stop::Err)
}

impl Queue {
    fn ctl(&self, id: &str) -> Option<Arc<Ctl>> {
        self.inner
            .lock()
            .unwrap()
            .jobs
            .get(id)
            .map(|j| j.ctl.clone())
    }

    fn check(&self, ctl: &Ctl) -> std::result::Result<(), Stop> {
        if ctl.cancel.load(Ordering::SeqCst) {
            return Err(Stop::Cancel);
        }
        if ctl.pause.load(Ordering::SeqCst) {
            return Err(Stop::Pause);
        }
        Ok(())
    }

    fn item(&self, id: &str, idx: usize) -> Option<JobItem> {
        self.inner
            .lock()
            .unwrap()
            .jobs
            .get(id)
            .and_then(|j| j.file.items.get(idx).cloned())
    }

    fn update<R>(&self, id: &str, f: impl FnOnce(&mut JobEntry) -> R) -> Option<R> {
        self.inner.lock().unwrap().jobs.get_mut(id).map(f)
    }

    fn set_state(&self, id: &str, st: JobState) {
        let emit = self
            .update(id, |j| {
                j.file.state = st;
                j.last_emit
                    .is_none_or(|t| t.elapsed() >= Duration::from_millis(250))
            })
            .unwrap_or(false);
        if emit {
            self.emit_status(id);
        }
    }

    /// Progress tick: update counters, emit at most ~4/s, save at most 1/s.
    fn tick(&self, id: &str, idx: usize, cur_bytes: u64, progress: Option<&FileProgress>) {
        let (emit, save) = self
            .update(id, |j| {
                j.cur_bytes = cur_bytes;
                if let Some(p) = progress {
                    j.file.items[idx].progress = Some(p.clone());
                }
                j.sample();
                let emit = j
                    .last_emit
                    .is_none_or(|t| t.elapsed() >= Duration::from_millis(250));
                let save = progress.is_some()
                    && j.last_save
                        .is_none_or(|t| t.elapsed() >= Duration::from_secs(1));
                (emit, save)
            })
            .unwrap_or((false, false));
        if save {
            self.save(id);
        }
        if emit {
            self.emit_status(id);
        }
    }

    async fn delay(&self) {
        let ms = self.chunk_delay_ms.load(Ordering::Relaxed);
        if ms > 0 {
            tokio::time::sleep(Duration::from_millis(ms)).await;
        }
    }

    /// Copy one file (resuming if possible). Returns the source SHA-256.
    async fn copy_file(
        &self,
        id: &str,
        idx: usize,
        ctl: &Ctl,
    ) -> std::result::Result<String, Stop> {
        let item = self.item(id, idx).ok_or(Stop::Cancel)?;
        let (src, dst) = (parse(&item.src)?, parse(&item.dst)?);
        let cs = self.chunk_size.load(Ordering::Relaxed);
        let sh = self.vfs.open_read(&src).await?;
        let r = self.copy_inner(id, idx, ctl, &item, &sh, &dst, cs).await;
        let _ = sh.close().await;
        r
    }

    #[allow(clippy::too_many_arguments)]
    async fn copy_inner(
        &self,
        id: &str,
        idx: usize,
        ctl: &Ctl,
        item: &JobItem,
        sh: &FileHandle,
        dst: &Loc,
        cs: u64,
    ) -> std::result::Result<String, Stop> {
        let src_size = sh.len().await?;
        let mut prog = item.progress.clone().unwrap_or_default();
        let mut whole = Sha256::new();
        let mut off = 0u64;
        let resumable =
            prog.chunk_size == cs && prog.src_size == src_size && !prog.digests.is_empty();
        let dh = if resumable {
            // Re-hash what the target already has; keep the matching prefix.
            let mut ok = 0;
            if let Ok(r) = self.vfs.open_read(dst).await {
                let dlen = r.len().await.unwrap_or(0);
                for (i, d) in prog.digests.iter().enumerate() {
                    let start = i as u64 * cs;
                    let end = (start + cs).min(src_size);
                    if end > dlen {
                        break;
                    }
                    let buf = r.read_at(start, (end - start) as usize).await?;
                    if buf.len() as u64 != end - start || sha_hex(&buf) != *d {
                        break;
                    }
                    whole.update(&buf);
                    off = end;
                    ok = i + 1;
                    self.check(ctl)?;
                }
                let _ = r.close().await;
            }
            prog.digests.truncate(ok);
            self.vfs.open_write(dst, WriteMode::ResumeAt(off)).await?
        } else {
            prog = FileProgress {
                chunk_size: cs,
                src_size,
                digests: Vec::new(),
            };
            self.vfs.open_write(dst, WriteMode::Truncate).await?
        };
        #[cfg(test)]
        if resumable {
            self.last_resume_offset.store(off, Ordering::SeqCst);
        }
        self.tick(id, idx, off, Some(&prog));
        let res: std::result::Result<(), Stop> = async {
            while off < src_size {
                self.check(ctl)?;
                let n = cs.min(src_size - off) as usize;
                let buf = sh.read_at(off, n).await?;
                if buf.len() != n {
                    return Err(Stop::Err(VfsError::other(format!(
                        "{}: source changed while copying (expected {src_size} bytes)",
                        item.src
                    ))));
                }
                whole.update(&buf);
                dh.write_at(off, &buf).await?;
                prog.digests.push(sha_hex(&buf));
                off += n as u64;
                self.tick(id, idx, off, Some(&prog));
                self.delay().await;
            }
            Ok(())
        }
        .await;
        // Always persist how far we got, so a resume can pick it up.
        self.update(id, |j| j.file.items[idx].progress = Some(prog.clone()));
        let closed = dh.close().await;
        res?;
        closed?;
        Ok(hex(&whole.finalize()))
    }

    /// Re-read the target and compare its hash.
    async fn verify(
        &self,
        id: &str,
        idx: usize,
        ctl: &Ctl,
        expected: &str,
    ) -> std::result::Result<bool, Stop> {
        let item = self.item(id, idx).ok_or(Stop::Cancel)?;
        let dst = parse(&item.dst)?;
        let cs = self.chunk_size.load(Ordering::Relaxed);
        let h = self.vfs.open_read(&dst).await?;
        let r: std::result::Result<bool, Stop> = async {
            let len = h.len().await?;
            let mut hasher = Sha256::new();
            let mut off = 0;
            while off < len {
                if ctl.cancel.load(Ordering::SeqCst) {
                    return Err(Stop::Cancel);
                }
                let buf = h.read_at(off, cs.min(len - off) as usize).await?;
                if buf.is_empty() {
                    break;
                }
                off += buf.len() as u64;
                hasher.update(&buf);
            }
            Ok(hex(&hasher.finalize()) == expected)
        }
        .await;
        let _ = h.close().await;
        r
    }

    /// Copy + verify, re-copying once on a mismatch.
    async fn copy_verified(
        &self,
        id: &str,
        idx: usize,
        ctl: &Ctl,
        verify: bool,
    ) -> std::result::Result<String, Stop> {
        let mut recopied = false;
        loop {
            let sha = self.copy_file(id, idx, ctl).await?;
            if !verify {
                return Ok(sha);
            }
            #[cfg(test)]
            if self.corrupt_before_verify.load(Ordering::SeqCst) > 0
                && self.corrupt_before_verify.fetch_sub(1, Ordering::SeqCst) > 0
                && let Some(it) = self.item(id, idx)
            {
                let h = self
                    .vfs
                    .open_write(&parse(&it.dst)?, WriteMode::ResumeAt(it.size))
                    .await?;
                h.write_at(0, b"BAD").await?;
                h.close().await?;
            }
            self.set_state(id, JobState::Verifying);
            let ok = self.verify(id, idx, ctl, &sha).await;
            self.set_state(id, JobState::Running);
            if ok? {
                return Ok(sha);
            }
            if recopied {
                return Err(Stop::Mismatch);
            }
            recopied = true;
            self.update(id, |j| j.file.items[idx].progress = None);
        }
    }

    /// Network errors: retry with backoff (1, 2, 4 s), interruptible by pause/cancel.
    async fn with_retries(
        &self,
        id: &str,
        idx: usize,
        ctl: &Ctl,
        verify: bool,
    ) -> std::result::Result<String, Stop> {
        let mut attempt = 0;
        loop {
            match self.copy_verified(id, idx, ctl, verify).await {
                Err(Stop::Err(e)) if e.is_transient() && attempt < RETRIES => {
                    let wait = Duration::from_secs(1 << attempt);
                    attempt += 1;
                    self.update(id, |j| {
                        j.file.error = Some(format!("{} (retry {attempt}/{RETRIES})", e.message))
                    });
                    self.emit_status(id);
                    let t0 = Instant::now();
                    while t0.elapsed() < wait {
                        self.check(ctl)?;
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
                r => {
                    self.update(id, |j| j.file.error = None);
                    return r;
                }
            }
        }
    }

    async fn append_manifest(&self, dest_dir: &Loc, rel: &str, sha: &str) -> vfs::Result<()> {
        let _g = self.manifest_lock.lock().await;
        let m = dest_dir.join("SHA256SUMS");
        let len = match self.vfs.stat(&m).await {
            Ok(e) => e.size.unwrap_or(0),
            Err(e) if e.kind == ErrorKind::NotFound => 0,
            Err(e) => return Err(e),
        };
        let h = self.vfs.open_write(&m, WriteMode::ResumeAt(len)).await?;
        let line = format!("{sha}  {rel}\n");
        let r = h.write_at(len, line.as_bytes()).await;
        h.close().await?;
        r
    }

    /// KeepBoth: pick a free "name (n)" and rewrite this item's and its
    /// descendants' destinations.
    async fn pick_keep_both(&self, id: &str, idx: usize) -> std::result::Result<(), Stop> {
        let item = self.item(id, idx).ok_or(Stop::Cancel)?;
        let dst = parse(&item.dst)?;
        let parent = dst
            .parent()
            .ok_or_else(|| Stop::Err(VfsError::other("no parent folder")))?;
        let name = dst.name();
        let mut n = 2;
        let new = loop {
            let cand = parent.join(&keep_both_name(&name, n, item.is_dir));
            if !self.vfs.exists(&cand).await? {
                break cand;
            }
            n += 1;
            if n > 9999 {
                return Err(Stop::Err(VfsError::conflict("no free name found")));
            }
        };
        let new_name = new.name();
        let old_rel = item.rel.clone();
        let new_rel = match old_rel.rsplit_once('/') {
            Some((p, _)) => format!("{p}/{new_name}"),
            None => new_name.clone(),
        };
        self.update(id, |j| {
            for (k, it) in j.file.items.iter_mut().enumerate() {
                if k == idx {
                    it.dst = new.to_uri();
                    it.rel = new_rel.clone();
                    it.keep_both = false;
                } else if let Some(tail) = it.rel.strip_prefix(&format!("{old_rel}/")) {
                    it.dst = new.join(tail).to_uri();
                    it.rel = format!("{new_rel}/{tail}");
                }
            }
        });
        self.save(id);
        Ok(())
    }

    fn mark_done_tree(&self, id: &str, idx: usize, renamed: bool) {
        self.update(id, |j| {
            let rel = j.file.items[idx].rel.clone();
            let pre = format!("{rel}/");
            for (k, it) in j.file.items.iter_mut().enumerate() {
                if k == idx || it.rel.starts_with(&pre) {
                    it.state = ItemState::Done;
                    it.renamed = renamed;
                }
            }
        });
    }

    async fn process(
        &self,
        id: &str,
        idx: usize,
        ctl: &Ctl,
        op: Op,
        opts: JobOptions,
        dest_dir: &Loc,
    ) -> std::result::Result<(), Stop> {
        let Some(item) = self.item(id, idx) else {
            return Ok(());
        };
        if item.state != ItemState::Pending {
            return Ok(());
        }
        self.check(ctl)?;
        if item.keep_both {
            self.pick_keep_both(id, idx).await?;
        }
        let item = self.item(id, idx).ok_or(Stop::Cancel)?;
        let (src, dst) = (parse(&item.src)?, parse(&item.dst)?);
        self.update(id, |j| {
            j.current = Some(item.dst.clone());
            j.cur_bytes = 0;
        });

        // Move fast path: rename top-level items on the same volume.
        let top = !item.rel.contains('/');
        if op == Op::Move
            && top
            && !(item.replace && item.is_dir)
            && self.vfs.same_volume(&src, dest_dir).await
        {
            let r = if item.replace {
                self.vfs.rename_over(&src, &dst).await
            } else {
                self.vfs.rename(&src, &dst).await
            };
            if r.is_ok() {
                self.mark_done_tree(id, idx, true);
                self.save(id);
                self.emit_status(id);
                return Ok(());
            }
        }

        if item.replace {
            // Replacing something of the other type: remove it first.
            if let Ok(e) = self.vfs.stat(&dst).await
                && e.is_dir != item.is_dir
            {
                self.vfs.delete_permanently(&dst, true).await?;
            }
        }
        if item.is_dir {
            self.vfs.mkdir(&dst).await?;
            self.update(id, |j| j.file.items[idx].state = ItemState::Done);
            return Ok(());
        }
        match self.with_retries(id, idx, ctl, opts.verify).await {
            Ok(sha) => {
                self.update(id, |j| {
                    let it = &mut j.file.items[idx];
                    it.state = ItemState::Done;
                    it.sha256 = Some(sha.clone());
                    it.progress = None;
                    j.cur_bytes = 0;
                });
                if opts.write_manifest
                    && let Err(e) = self.append_manifest(dest_dir, &item.rel, &sha).await
                {
                    self.update(id, |j| {
                        j.file.error = Some(format!("could not write SHA256SUMS: {e}"))
                    });
                }
                (self.emit)(XferEvent::FileDone {
                    job: id.to_string(),
                    dst: item.dst.clone(),
                    sha256: sha,
                });
                if op == Op::Move {
                    self.vfs.delete_permanently(&src, false).await?;
                }
                self.save(id);
                self.emit_status(id);
                Ok(())
            }
            Err(Stop::Mismatch) => {
                self.update(id, |j| {
                    j.file.items[idx].state = ItemState::Mismatch;
                    j.file.items[idx].progress = None;
                    j.file.mismatches.push(item.dst.clone());
                    j.cur_bytes = 0;
                });
                self.save(id);
                self.emit_status(id);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn finish(&self, id: &str, state: JobState, error: Option<String>) {
        self.update(id, |j| {
            j.file.state = state;
            if error.is_some() {
                j.file.error = error;
            }
            if state.is_finished() {
                j.file.finished = Some(now_ms());
            }
            j.current = None;
            j.cur_bytes = 0;
            j.running = false;
        });
        if state == JobState::Done {
            let path = self.state_path(id);
            // newest-wins saver: bump the sequence so a pending save cannot recreate it
            self.update(id, |j| j.save_seq += 1_000_000);
            let seq = self
                .inner
                .lock()
                .unwrap()
                .jobs
                .get(id)
                .map(|j| j.save_seq)
                .unwrap_or(0);
            let saved = self.saved_seq.clone();
            let idc = id.to_string();
            self.rt.spawn_blocking(move || {
                let mut s = saved.lock().unwrap();
                s.insert(idc, seq);
                let _ = std::fs::remove_file(path);
            });
        } else {
            self.save(id);
        }
        self.emit_status(id);
    }
}

pub(crate) async fn run_job(q: Arc<Queue>, id: String) {
    let Some(ctl) = q.ctl(&id) else { return };
    let Some((op, opts, dest, n)) = q.update(&id, |j| {
        (
            j.file.op,
            j.file.opts,
            j.file.dest_dir.clone(),
            j.file.items.len(),
        )
    }) else {
        return;
    };
    let dest_dir = match Loc::parse(&dest) {
        Ok(d) => d,
        Err(e) => return q.finish(&id, JobState::Failed, Some(e.message)),
    };
    for idx in 0..n {
        match q.process(&id, idx, &ctl, op, opts, &dest_dir).await {
            Ok(()) => {}
            Err(Stop::Pause) => return q.finish(&id, JobState::Paused, None),
            Err(Stop::Cancel) => return q.finish(&id, JobState::Cancelled, None),
            Err(Stop::Mismatch) => unreachable!("handled in process"),
            Err(Stop::Err(e)) => {
                let pause = e.is_transient()
                    || matches!(
                        e.kind,
                        ErrorKind::AuthRequired { .. } | ErrorKind::HostKeyUnknown { .. }
                    );
                let st = if pause {
                    JobState::Paused
                } else {
                    JobState::Failed
                };
                return q.finish(&id, st, Some(e.message));
            }
        }
    }
    // Move: remove emptied source folders, deepest first.
    if op == Op::Move {
        let dirs: Vec<String> = q
            .update(&id, |j| {
                j.file
                    .items
                    .iter()
                    .filter(|i| i.is_dir && i.state == ItemState::Done && !i.renamed)
                    .map(|i| i.src.clone())
                    .collect()
            })
            .unwrap_or_default();
        for d in dirs.iter().rev() {
            if let Ok(l) = Loc::parse(d) {
                let _ = q.vfs.delete_permanently(&l, false).await;
            }
        }
    }
    let mism = q.update(&id, |j| j.file.mismatches.len()).unwrap_or(0);
    if mism > 0 {
        q.finish(
            &id,
            JobState::Failed,
            Some(format!("{mism} file(s) failed verification")),
        );
    } else {
        q.finish(&id, JobState::Done, None);
    }
}
