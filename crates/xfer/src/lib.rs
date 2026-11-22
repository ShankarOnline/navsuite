//! xfer: one transfer queue for copies and moves between any `vfs` locations.
//!
//! Files are copied in chunks (4 MiB) through `vfs::FileHandle`; every chunk
//! and every file is hashed with SHA-256 while reading. Per-file progress
//! (chunk digests) is persisted to `<state_dir>/<job>.json`, so a pause,
//! cancel + retry, app restart or network drop resumes: the target's existing
//! chunks are re-hashed against the recorded digests and copying continues
//! from the first mismatch. After each file the target is re-read and its
//! hash compared with the source (optional).

mod engine;
mod plan;
mod types;

pub use plan::keep_both_name;
pub use types::*;

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};
use vfs::{Loc, Result, Vfs};

pub(crate) const DEFAULT_CHUNK: u64 = 4 * 1024 * 1024;
pub(crate) const MAX_RUNNING: usize = 2;

pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum ItemState {
    Pending,
    Done,
    Mismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FileProgress {
    pub chunk_size: u64,
    pub src_size: u64,
    /// Hex SHA-256 of each chunk written so far.
    pub digests: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct JobItem {
    pub src: String,
    pub dst: String,
    pub rel: String,
    pub size: u64,
    pub is_dir: bool,
    /// Destination existed and the user chose Replace.
    pub replace: bool,
    /// Destination existed and the user chose KeepBoth (name not yet picked).
    pub keep_both: bool,
    pub state: ItemState,
    pub sha256: Option<String>,
    pub progress: Option<FileProgress>,
    /// Moved with a rename (no copy).
    #[serde(default)]
    pub renamed: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct JobFile {
    pub id: String,
    pub op: Op,
    pub dest_dir: String,
    pub opts: JobOptions,
    pub items: Vec<JobItem>,
    pub state: JobState,
    pub error: Option<String>,
    pub mismatches: Vec<String>,
    pub started: Option<i64>,
    pub finished: Option<i64>,
    pub created: i64,
}

#[derive(Default)]
pub(crate) struct Ctl {
    pub pause: AtomicBool,
    pub cancel: AtomicBool,
}

pub(crate) struct JobEntry {
    pub file: JobFile,
    pub ctl: Arc<Ctl>,
    pub running: bool,
    pub current: Option<String>,
    /// Bytes of the current file already done.
    pub cur_bytes: u64,
    pub samples: VecDeque<(Instant, u64)>,
    pub last_emit: Option<Instant>,
    pub last_save: Option<Instant>,
    pub save_seq: u64,
}

impl JobEntry {
    fn new(file: JobFile) -> JobEntry {
        JobEntry {
            file,
            ctl: Arc::default(),
            running: false,
            current: None,
            cur_bytes: 0,
            samples: VecDeque::new(),
            last_emit: None,
            last_save: None,
            save_seq: 0,
        }
    }

    pub fn bytes_done(&self) -> u64 {
        let done: u64 = self
            .file
            .items
            .iter()
            .filter(|i| !i.is_dir && i.state != ItemState::Pending)
            .map(|i| i.size)
            .sum();
        done + self.cur_bytes
    }

    pub fn status(&self) -> JobStatus {
        let f = &self.file;
        let files = f.items.iter().filter(|i| !i.is_dir);
        let files_total = files.clone().count() as u64;
        let files_done = files
            .clone()
            .filter(|i| i.state != ItemState::Pending)
            .count() as u64;
        let bytes_total: u64 = files.map(|i| i.size).sum();
        let bytes_done = self.bytes_done();
        let active = matches!(f.state, JobState::Running | JobState::Verifying);
        let speed = if active { self.speed() } else { 0 };
        JobStatus {
            id: f.id.clone(),
            op: f.op,
            state: f.state,
            dest_dir: f.dest_dir.clone(),
            files_total,
            files_done,
            bytes_total,
            bytes_done,
            current: if active { self.current.clone() } else { None },
            speed_bps: speed,
            eta_secs: bytes_total.saturating_sub(bytes_done).checked_div(speed),
            error: f.error.clone(),
            mismatches: f.mismatches.clone(),
            started: f.started,
            finished: f.finished,
        }
    }

    fn speed(&self) -> u64 {
        let (Some(a), Some(b)) = (self.samples.front(), self.samples.back()) else {
            return 0;
        };
        let dt = b.0.duration_since(a.0).as_secs_f64();
        if dt < 0.3 {
            return 0;
        }
        (b.1.saturating_sub(a.1) as f64 / dt) as u64
    }

    pub fn sample(&mut self) {
        let now = Instant::now();
        let b = self.bytes_done();
        self.samples.push_back((now, b));
        while self
            .samples
            .front()
            .is_some_and(|s| now.duration_since(s.0) > Duration::from_secs(5))
        {
            self.samples.pop_front();
        }
    }
}

pub(crate) struct Inner {
    pub order: Vec<String>,
    pub jobs: HashMap<String, JobEntry>,
}

pub type Emit = Arc<dyn Fn(XferEvent) + Send + Sync>;

/// The transfer queue. Create once and share the `Arc`.
pub struct Queue {
    pub(crate) vfs: Arc<Vfs>,
    pub(crate) state_dir: PathBuf,
    pub(crate) emit: Emit,
    pub(crate) inner: Mutex<Inner>,
    pub(crate) rt: tokio::runtime::Handle,
    pub(crate) me: Weak<Queue>,
    pub(crate) manifest_lock: tokio::sync::Mutex<()>,
    pub(crate) chunk_size: AtomicU64,
    pub(crate) chunk_delay_ms: AtomicU64,
    pub(crate) saved_seq: Arc<Mutex<HashMap<String, u64>>>,
    /// Test hooks: offset the last resumed copy started at; corrupt targets before verify (count).
    #[cfg(test)]
    pub(crate) last_resume_offset: AtomicU64,
    #[cfg(test)]
    pub(crate) corrupt_before_verify: AtomicU64,
}

fn runtime_handle() -> tokio::runtime::Handle {
    if let Ok(h) = tokio::runtime::Handle::try_current() {
        return h;
    }
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("xfer")
            .enable_all()
            .build()
            .expect("xfer runtime")
    })
    .handle()
    .clone()
}

fn load_jobs(dir: &Path) -> Vec<JobFile> {
    let mut v = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return v;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("json") {
            continue;
        }
        let Some(mut j) = std::fs::read(&p)
            .ok()
            .and_then(|b| serde_json::from_slice::<JobFile>(&b).ok())
        else {
            continue;
        };
        match j.state {
            JobState::Done => {
                let _ = std::fs::remove_file(&p);
                continue;
            }
            JobState::Failed | JobState::Cancelled => {}
            _ => j.state = JobState::Paused,
        }
        v.push(j);
    }
    v.sort_by_key(|j| j.created);
    v
}

impl Queue {
    /// Loads unfinished jobs from `state_dir` as Paused. Uses the current
    /// Tokio runtime if there is one, otherwise a private one.
    pub fn new(vfs: Arc<Vfs>, state_dir: PathBuf, emit: Emit) -> Arc<Queue> {
        let _ = std::fs::create_dir_all(&state_dir);
        let jobs = load_jobs(&state_dir);
        let mut inner = Inner {
            order: Vec::new(),
            jobs: HashMap::new(),
        };
        for j in jobs {
            inner.order.push(j.id.clone());
            inner.jobs.insert(j.id.clone(), JobEntry::new(j));
        }
        Arc::new_cyclic(|me| Queue {
            vfs,
            state_dir,
            emit,
            inner: Mutex::new(inner),
            rt: runtime_handle(),
            me: me.clone(),
            manifest_lock: tokio::sync::Mutex::new(()),
            chunk_size: AtomicU64::new(DEFAULT_CHUNK),
            chunk_delay_ms: AtomicU64::new(0),
            saved_seq: Arc::default(),
            #[cfg(test)]
            last_resume_offset: AtomicU64::new(0),
            #[cfg(test)]
            corrupt_before_verify: AtomicU64::new(0),
        })
    }

    /// Test/tuning knob: chunk size in bytes (default 4 MiB).
    #[doc(hidden)]
    pub fn set_chunk_size(&self, bytes: u64) {
        self.chunk_size.store(bytes.max(1), Ordering::Relaxed);
    }

    /// Test knob: sleep after every chunk.
    #[doc(hidden)]
    pub fn set_chunk_delay(&self, d: Duration) {
        self.chunk_delay_ms
            .store(d.as_millis() as u64, Ordering::Relaxed);
    }

    /// Copy preview: walks folders, lists conflicts and skipped items, checks space.
    pub async fn plan(&self, sources: Vec<Loc>, dest_dir: Loc, op: Op) -> Result<Plan> {
        plan::plan(&self.vfs, sources, dest_dir, op).await
    }

    /// Queue a plan. Conflicts without a resolution are skipped.
    pub fn enqueue(
        &self,
        plan: Plan,
        resolutions: HashMap<String, Resolution>,
        opts: JobOptions,
    ) -> String {
        let conflicts: HashMap<&str, &Conflict> =
            plan.conflicts.iter().map(|c| (c.dst.as_str(), c)).collect();
        let mut items: Vec<JobItem> = Vec::new();
        let mut skipped_prefixes: Vec<String> = Vec::new();
        for it in &plan.items {
            if skipped_prefixes
                .iter()
                .any(|p| it.rel.starts_with(p.as_str()))
            {
                continue;
            }
            let mut ji = JobItem {
                src: it.src.clone(),
                dst: it.dst.clone(),
                rel: it.rel.clone(),
                size: it.size,
                is_dir: it.is_dir,
                replace: false,
                keep_both: false,
                state: ItemState::Pending,
                sha256: None,
                progress: None,
                renamed: false,
            };
            if let Some(c) = conflicts.get(it.dst.as_str()) {
                match resolutions
                    .get(&it.dst)
                    .copied()
                    .unwrap_or(Resolution::Skip)
                {
                    Resolution::Skip => {
                        if it.is_dir {
                            skipped_prefixes.push(format!("{}/", it.rel));
                        }
                        continue;
                    }
                    Resolution::Replace if c.same_file => ji.keep_both = true,
                    Resolution::Replace => ji.replace = true,
                    Resolution::KeepBoth => ji.keep_both = true,
                }
            }
            items.push(ji);
        }
        let id = plan::new_id("j");
        let file = JobFile {
            id: id.clone(),
            op: plan.op,
            dest_dir: plan.dest_dir,
            opts,
            items,
            state: JobState::Queued,
            error: None,
            mismatches: Vec::new(),
            started: None,
            finished: None,
            created: now_ms(),
        };
        {
            let mut g = self.inner.lock().unwrap();
            g.order.push(id.clone());
            g.jobs.insert(id.clone(), JobEntry::new(file));
        }
        self.save(&id);
        self.emit_status(&id);
        self.schedule();
        id
    }

    pub fn pause(&self, id: &str) {
        let changed = {
            let mut g = self.inner.lock().unwrap();
            let Some(j) = g.jobs.get_mut(id) else { return };
            match j.file.state {
                JobState::Running | JobState::Verifying => {
                    j.ctl.pause.store(true, Ordering::SeqCst);
                    false
                }
                JobState::Queued => {
                    j.file.state = JobState::Paused;
                    true
                }
                _ => false,
            }
        };
        if changed {
            self.save(id);
            self.emit_status(id);
        }
    }

    pub fn resume(&self, id: &str) {
        let changed = {
            let mut g = self.inner.lock().unwrap();
            let Some(j) = g.jobs.get_mut(id) else { return };
            j.ctl.pause.store(false, Ordering::SeqCst);
            if j.file.state == JobState::Paused {
                j.file.state = JobState::Queued;
                j.file.error = None;
                true
            } else {
                false
            }
        };
        if changed {
            self.save(id);
            self.emit_status(id);
            self.schedule();
        }
    }

    /// Stop a job. Its progress is kept so `retry` resumes where it stopped.
    pub fn cancel(&self, id: &str) {
        let changed = {
            let mut g = self.inner.lock().unwrap();
            let Some(j) = g.jobs.get_mut(id) else { return };
            if j.running {
                j.ctl.cancel.store(true, Ordering::SeqCst);
                false
            } else if !j.file.state.is_finished() {
                j.file.state = JobState::Cancelled;
                j.file.finished = Some(now_ms());
                true
            } else {
                false
            }
        };
        if changed {
            self.save(id);
            self.emit_status(id);
        }
    }

    /// Re-run a Failed or Cancelled job (files that failed verification are copied again).
    pub fn retry(&self, id: &str) {
        let changed = {
            let mut g = self.inner.lock().unwrap();
            let Some(j) = g.jobs.get_mut(id) else { return };
            if !matches!(j.file.state, JobState::Failed | JobState::Cancelled) || j.running {
                false
            } else {
                for it in j
                    .file
                    .items
                    .iter_mut()
                    .filter(|i| i.state == ItemState::Mismatch)
                {
                    it.state = ItemState::Pending;
                    it.progress = None;
                }
                j.file.mismatches.clear();
                j.file.error = None;
                j.file.finished = None;
                j.file.state = JobState::Queued;
                true
            }
        };
        if changed {
            self.save(id);
            self.emit_status(id);
            self.schedule();
        }
    }

    pub fn pause_all(&self) {
        for id in self.ids() {
            self.pause(&id);
        }
    }

    pub fn resume_all(&self) {
        for id in self.ids() {
            self.resume(&id);
        }
    }

    fn ids(&self) -> Vec<String> {
        self.inner.lock().unwrap().order.clone()
    }

    pub fn jobs(&self) -> Vec<JobStatus> {
        let g = self.inner.lock().unwrap();
        g.order
            .iter()
            .filter_map(|id| g.jobs.get(id))
            .map(|j| j.status())
            .collect()
    }

    pub fn job(&self, id: &str) -> Option<JobStatus> {
        self.inner.lock().unwrap().jobs.get(id).map(|j| j.status())
    }

    /// Forget Done, Failed and Cancelled jobs (and their state files). The
    /// partially written file of a cancelled job is deleted.
    pub fn clear_finished(&self) {
        let removed: Vec<JobEntry> = {
            let mut g = self.inner.lock().unwrap();
            let ids: Vec<String> = g
                .order
                .iter()
                .filter(|id| {
                    g.jobs
                        .get(*id)
                        .is_some_and(|j| j.file.state.is_finished() && !j.running)
                })
                .cloned()
                .collect();
            g.order.retain(|id| !ids.contains(id));
            ids.iter().filter_map(|id| g.jobs.remove(id)).collect()
        };
        for j in removed {
            let path = self.state_path(&j.file.id);
            let partial: Vec<String> = if j.file.state == JobState::Cancelled {
                j.file
                    .items
                    .iter()
                    .filter(|i| i.state == ItemState::Pending && i.progress.is_some() && !i.is_dir)
                    .map(|i| i.dst.clone())
                    .collect()
            } else {
                Vec::new()
            };
            let vfs = self.vfs.clone();
            self.rt.spawn(async move {
                let _ = tokio::fs::remove_file(path).await;
                for d in partial {
                    if let Ok(l) = Loc::parse(&d) {
                        let _ = vfs.delete_permanently(&l, false).await;
                    }
                }
            });
        }
    }

    // ------------------------------------------------------------ internals

    pub(crate) fn state_path(&self, id: &str) -> PathBuf {
        self.state_dir.join(format!("{id}.json"))
    }

    /// Persist a job (asynchronously, newest write wins).
    pub(crate) fn save(&self, id: &str) {
        let (bytes, seq) = {
            let mut g = self.inner.lock().unwrap();
            let Some(j) = g.jobs.get_mut(id) else { return };
            j.save_seq += 1;
            j.last_save = Some(Instant::now());
            (serde_json::to_vec(&j.file).unwrap_or_default(), j.save_seq)
        };
        let path = self.state_path(id);
        let saved = self.saved_seq.clone();
        let id = id.to_string();
        self.rt.spawn_blocking(move || {
            let mut s = saved.lock().unwrap();
            if s.get(&id).is_some_and(|&last| last >= seq) {
                return;
            }
            let tmp = path.with_extension("json.tmp");
            if std::fs::write(&tmp, &bytes).is_ok() && std::fs::rename(&tmp, &path).is_ok() {
                s.insert(id, seq);
            }
        });
    }

    pub(crate) fn emit_status(&self, id: &str) {
        let st = {
            let mut g = self.inner.lock().unwrap();
            let Some(j) = g.jobs.get_mut(id) else { return };
            j.last_emit = Some(Instant::now());
            j.status()
        };
        (self.emit)(XferEvent::Job(st));
    }

    /// Start queued jobs while fewer than MAX_RUNNING are running.
    pub(crate) fn schedule(&self) {
        let Some(me) = self.me.upgrade() else { return };
        let mut start = Vec::new();
        {
            let mut g = self.inner.lock().unwrap();
            let mut running = g.jobs.values().filter(|j| j.running).count();
            let order = g.order.clone();
            for id in order {
                if running >= MAX_RUNNING {
                    break;
                }
                let Some(j) = g.jobs.get_mut(&id) else {
                    continue;
                };
                if j.file.state == JobState::Queued && !j.running {
                    j.running = true;
                    j.ctl.pause.store(false, Ordering::SeqCst);
                    j.ctl.cancel.store(false, Ordering::SeqCst);
                    j.file.state = JobState::Running;
                    j.file.started.get_or_insert(now_ms());
                    j.samples.clear();
                    running += 1;
                    start.push(id);
                }
            }
        }
        for id in start {
            let q = me.clone();
            self.emit_status(&id);
            self.rt.spawn(async move {
                engine::run_job(q.clone(), id.clone()).await;
                if let Some(j) = q.inner.lock().unwrap().jobs.get_mut(&id) {
                    j.running = false;
                }
                q.schedule();
            });
        }
    }
}

#[cfg(test)]
mod tests;
