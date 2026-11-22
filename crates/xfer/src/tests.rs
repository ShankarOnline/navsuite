use super::*;
use sha2::{Digest, Sha256};
use std::path::Path;

struct Env {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    vfs: Arc<Vfs>,
    events: Arc<Mutex<Vec<XferEvent>>>,
}

fn env() -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let vfs = Arc::new(Vfs::new(root.join("data")));
    Env {
        _tmp: tmp,
        root,
        vfs,
        events: Arc::default(),
    }
}

impl Env {
    fn queue(&self) -> Arc<Queue> {
        let ev = self.events.clone();
        let q = Queue::new(
            self.vfs.clone(),
            self.root.join("state"),
            Arc::new(move |e| ev.lock().unwrap().push(e)),
        );
        q.set_chunk_size(64 * 1024);
        q
    }
    fn dir(&self, rel: &str) -> PathBuf {
        let p = self.root.join(rel);
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}

fn loc(p: &Path) -> Loc {
    Loc::local(p.to_string_lossy()).unwrap()
}

fn data(n: usize, seed: u8) -> Vec<u8> {
    let mut x: u32 = 0x9e37_79b9 ^ seed as u32;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

fn sha(b: &[u8]) -> String {
    engine::hex(&Sha256::digest(b))
}

async fn wait(q: &Queue, id: &str, secs: u64, f: impl Fn(&JobStatus) -> bool) -> JobStatus {
    let t0 = Instant::now();
    loop {
        let s = q.job(id).expect("job exists");
        if f(&s) {
            return s;
        }
        assert!(
            t0.elapsed() < Duration::from_secs(secs),
            "timeout waiting; last status {s:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_done(q: &Queue, id: &str) -> JobStatus {
    let s = wait(q, id, 30, |s| s.state.is_finished()).await;
    // let the runner task fully return
    tokio::time::sleep(Duration::from_millis(20)).await;
    s
}

#[test]
fn keep_both_names() {
    assert_eq!(keep_both_name("x.ext", 2, false), "x (2).ext");
    assert_eq!(keep_both_name("a.tar.gz", 3, false), "a.tar (3).gz");
    assert_eq!(keep_both_name(".bashrc", 2, false), ".bashrc (2)");
    assert_eq!(keep_both_name("folder.v1", 2, true), "folder.v1 (2)");
    assert_eq!(keep_both_name("README", 2, false), "README (2)");
}

#[tokio::test(flavor = "multi_thread")]
async fn copy_multi_chunk_file() {
    let e = env();
    let src = e.dir("src");
    let dst = e.dir("dst");
    let bytes = data(1_000_003, 1); // ~15.3 chunks of 64 KiB
    std::fs::write(src.join("big.bin"), &bytes).unwrap();
    std::fs::write(src.join("empty.txt"), b"").unwrap();
    let q = e.queue();
    let plan = q
        .plan(
            vec![loc(&src.join("big.bin")), loc(&src.join("empty.txt"))],
            loc(&dst),
            Op::Copy,
        )
        .await
        .unwrap();
    assert_eq!(plan.files, 2);
    assert_eq!(plan.total_bytes, 1_000_003);
    assert!(plan.conflicts.is_empty());
    assert_eq!(plan.enough_space, Some(true));
    let id = q.enqueue(
        plan,
        HashMap::new(),
        JobOptions {
            verify: true,
            write_manifest: true,
        },
    );
    let s = wait_done(&q, &id).await;
    assert_eq!(s.state, JobState::Done, "{s:?}");
    assert_eq!(s.files_done, 2);
    assert_eq!(s.bytes_done, 1_000_003);
    assert_eq!(std::fs::read(dst.join("big.bin")).unwrap(), bytes);
    assert_eq!(std::fs::read(dst.join("empty.txt")).unwrap(), b"");
    let manifest = std::fs::read_to_string(dst.join("SHA256SUMS")).unwrap();
    assert!(
        manifest.contains(&format!("{}  big.bin\n", sha(&bytes))),
        "{manifest}"
    );
    assert!(manifest.contains(&format!("{}  empty.txt\n", sha(b""))));
    let ev = e.events.lock().unwrap().clone();
    assert!(
        ev.iter()
            .any(|x| matches!(x, XferEvent::FileDone { sha256, .. } if *sha256 == sha(&bytes)))
    );
    // state file removed when done
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!e.root.join("state").join(format!("{id}.json")).exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn pause_corrupt_resume() {
    let e = env();
    let src = e.dir("src");
    let dst = e.dir("dst");
    let bytes = data(64 * 1024 * 40, 2); // 40 chunks
    std::fs::write(src.join("f.bin"), &bytes).unwrap();
    let q = e.queue();
    q.set_chunk_delay(Duration::from_millis(15));
    let plan = q
        .plan(vec![loc(&src.join("f.bin"))], loc(&dst), Op::Copy)
        .await
        .unwrap();
    let id = q.enqueue(plan, HashMap::new(), JobOptions::default());
    wait(&q, &id, 20, |s| s.bytes_done >= 64 * 1024 * 10).await;
    q.pause(&id);
    let s = wait(&q, &id, 20, |s| s.state == JobState::Paused).await;
    assert!(s.bytes_done < bytes.len() as u64, "{s:?}");
    let partial = std::fs::read(dst.join("f.bin")).unwrap();
    assert!(partial.len() >= 64 * 1024 * 10 && partial.len() < bytes.len());
    // persisted digests
    tokio::time::sleep(Duration::from_millis(100)).await;
    let jf: JobFile = serde_json::from_slice(
        &std::fs::read(e.root.join("state").join(format!("{id}.json"))).unwrap(),
    )
    .unwrap();
    let digests = &jf.items[0].progress.as_ref().unwrap().digests;
    assert!(digests.len() >= 10);
    assert_eq!(digests[0], sha(&bytes[..64 * 1024]));

    // corrupt chunk 3 of the partial target
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(dst.join("f.bin"))
            .unwrap();
        f.seek(SeekFrom::Start(3 * 64 * 1024 + 100)).unwrap();
        f.write_all(b"CORRUPTED").unwrap();
    }
    q.set_chunk_delay(Duration::ZERO);
    q.resume(&id);
    let s = wait_done(&q, &id).await;
    assert_eq!(s.state, JobState::Done, "{s:?}");
    assert!(s.mismatches.is_empty());
    assert_eq!(std::fs::read(dst.join("f.bin")).unwrap(), bytes);
    // resumed after the 3 good chunks, i.e. continued at the corrupted one
    assert_eq!(q.last_resume_offset.load(Ordering::SeqCst), 3 * 64 * 1024);
}

#[tokio::test(flavor = "multi_thread")]
async fn verify_mismatch_recopies_then_fails() {
    let e = env();
    let src = e.dir("src");
    let dst = e.dir("dst");
    let bytes = data(200_000, 5);
    std::fs::write(src.join("v.bin"), &bytes).unwrap();
    let q = e.queue();

    // corrupted once: detected by verify, re-copied, job succeeds
    q.corrupt_before_verify.store(1, Ordering::SeqCst);
    let p = q
        .plan(vec![loc(&src.join("v.bin"))], loc(&dst), Op::Copy)
        .await
        .unwrap();
    let id = q.enqueue(p, HashMap::new(), JobOptions::default());
    let s = wait_done(&q, &id).await;
    assert_eq!(s.state, JobState::Done, "{s:?}");
    assert_eq!(std::fs::read(dst.join("v.bin")).unwrap(), bytes);

    // corrupted every time: file listed in mismatches, job Failed, source untouched
    q.corrupt_before_verify.store(2, Ordering::SeqCst);
    let dst2 = e.dir("dst2");
    let p = q
        .plan(vec![loc(&src.join("v.bin"))], loc(&dst2), Op::Copy)
        .await
        .unwrap();
    let id = q.enqueue(p, HashMap::new(), JobOptions::default());
    let s = wait_done(&q, &id).await;
    assert_eq!(s.state, JobState::Failed, "{s:?}");
    assert_eq!(s.mismatches.len(), 1);
    assert!(s.error.unwrap().contains("verification"));
    assert!(src.join("v.bin").exists());
    // retry clears the mismatch and copies again
    q.retry(&id);
    let s = wait_done(&q, &id).await;
    assert_eq!(s.state, JobState::Done, "{s:?}");
    assert_eq!(std::fs::read(dst2.join("v.bin")).unwrap(), bytes);
}

#[tokio::test(flavor = "multi_thread")]
async fn restart_resumes_from_state_dir() {
    let e = env();
    let src = e.dir("src");
    let dst = e.dir("dst");
    let bytes = data(64 * 1024 * 30 + 7, 3);
    std::fs::write(src.join("r.bin"), &bytes).unwrap();
    let id = {
        let q = e.queue();
        q.set_chunk_delay(Duration::from_millis(15));
        let plan = q
            .plan(vec![loc(&src.join("r.bin"))], loc(&dst), Op::Copy)
            .await
            .unwrap();
        let id = q.enqueue(plan, HashMap::new(), JobOptions::default());
        wait(&q, &id, 20, |s| s.bytes_done >= 64 * 1024 * 5).await;
        q.pause(&id);
        wait(&q, &id, 20, |s| s.state == JobState::Paused).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        id
    };
    // "app restart"
    let q2 = e.queue();
    let s = q2.job(&id).expect("job reloaded");
    assert_eq!(s.state, JobState::Paused);
    q2.resume(&id);
    let s = wait_done(&q2, &id).await;
    assert_eq!(s.state, JobState::Done, "{s:?}");
    assert_eq!(std::fs::read(dst.join("r.bin")).unwrap(), bytes);
}

#[tokio::test(flavor = "multi_thread")]
async fn cancel_then_retry() {
    let e = env();
    let src = e.dir("src");
    let dst = e.dir("dst");
    let bytes = data(64 * 1024 * 20, 4);
    std::fs::write(src.join("c.bin"), &bytes).unwrap();
    let q = e.queue();
    q.set_chunk_delay(Duration::from_millis(10));
    let plan = q
        .plan(vec![loc(&src.join("c.bin"))], loc(&dst), Op::Copy)
        .await
        .unwrap();
    let id = q.enqueue(plan, HashMap::new(), JobOptions::default());
    wait(&q, &id, 20, |s| s.bytes_done > 0).await;
    q.cancel(&id);
    assert_eq!(wait_done(&q, &id).await.state, JobState::Cancelled);
    q.set_chunk_delay(Duration::ZERO);
    q.retry(&id);
    let s = wait_done(&q, &id).await;
    assert_eq!(s.state, JobState::Done, "{s:?}");
    assert_eq!(std::fs::read(dst.join("c.bin")).unwrap(), bytes);
    q.clear_finished();
    assert!(q.jobs().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn plan_merge_conflicts_skip() {
    let e = env();
    let a = e.dir("src/A");
    e.dir("src/A/sub");
    std::fs::write(a.join("a.txt"), b"new a").unwrap();
    std::fs::write(a.join("same.txt"), b"s").unwrap();
    std::fs::write(a.join("sub/b.txt"), b"b").unwrap();
    let dst = e.dir("dst");
    e.dir("dst/A");
    std::fs::write(dst.join("A/a.txt"), b"old a").unwrap();
    std::fs::write(dst.join("A/same.txt"), b"old s").unwrap();
    let q = e.queue();

    // destination inside source is skipped
    let p = q
        .plan(
            vec![loc(&e.root.join("src"))],
            loc(&a.join("sub")),
            Op::Copy,
        )
        .await
        .unwrap();
    assert!(p.items.is_empty());
    assert_eq!(p.skipped.len(), 1);
    assert!(p.skipped[0].reason.contains("inside"));

    let p = q.plan(vec![loc(&a)], loc(&dst), Op::Copy).await.unwrap();
    assert_eq!(p.dirs, 2);
    assert_eq!(p.files, 3);
    let mut c: Vec<String> = p
        .conflicts
        .iter()
        .map(|c| Loc::parse(&c.dst).unwrap().name())
        .collect();
    c.sort();
    assert_eq!(c, vec!["a.txt", "same.txt"]); // the folder merges, no conflict for A itself
    let a_conf = p
        .conflicts
        .iter()
        .find(|c| c.dst.ends_with("a.txt"))
        .unwrap();
    assert_eq!(a_conf.dst_size, Some(5));
    // parents before children
    let pos = |n: &str| p.items.iter().position(|i| i.rel == n).unwrap();
    assert!(pos("A") < pos("A/sub") && pos("A/sub") < pos("A/sub/b.txt"));

    let same_dst = p
        .conflicts
        .iter()
        .find(|c| c.dst.ends_with("same.txt"))
        .unwrap()
        .dst
        .clone();
    let mut res = HashMap::new();
    res.insert(same_dst, Resolution::Replace); // a.txt: no resolution -> skipped
    let id = q.enqueue(p, res, JobOptions::default());
    let s = wait_done(&q, &id).await;
    assert_eq!(s.state, JobState::Done, "{s:?}");
    assert_eq!(std::fs::read(dst.join("A/a.txt")).unwrap(), b"old a");
    assert_eq!(std::fs::read(dst.join("A/same.txt")).unwrap(), b"s");
    assert_eq!(std::fs::read(dst.join("A/sub/b.txt")).unwrap(), b"b");
}

#[tokio::test(flavor = "multi_thread")]
async fn keep_both_in_same_folder() {
    let e = env();
    let d = e.dir("d");
    std::fs::write(d.join("x.ext"), b"x").unwrap();
    std::fs::create_dir_all(d.join("folder")).unwrap();
    std::fs::write(d.join("folder/inner.txt"), b"i").unwrap();
    let q = e.queue();
    for expect in ["x (2).ext", "x (3).ext"] {
        let p = q
            .plan(vec![loc(&d.join("x.ext"))], loc(&d), Op::Copy)
            .await
            .unwrap();
        assert_eq!(p.conflicts.len(), 1);
        assert!(p.conflicts[0].same_file);
        // Replace on the same file is turned into KeepBoth, never a self-overwrite
        let res = HashMap::from([(p.conflicts[0].dst.clone(), Resolution::Replace)]);
        let id = q.enqueue(p, res, JobOptions::default());
        assert_eq!(wait_done(&q, &id).await.state, JobState::Done);
        assert_eq!(std::fs::read(d.join(expect)).unwrap(), b"x");
    }
    // folder copied onto itself with KeepBoth: descendants follow the new name
    let p = q
        .plan(vec![loc(&d.join("folder"))], loc(&d), Op::Copy)
        .await
        .unwrap();
    // folder onto same-named folder = merge with file conflicts
    assert_eq!(p.conflicts.len(), 1);
    let res = HashMap::from([(p.conflicts[0].dst.clone(), Resolution::KeepBoth)]);
    let id = q.enqueue(
        p,
        res,
        JobOptions {
            verify: true,
            write_manifest: true,
        },
    );
    assert_eq!(wait_done(&q, &id).await.state, JobState::Done);
    assert_eq!(std::fs::read(d.join("folder/inner (2).txt")).unwrap(), b"i");
    let m = std::fs::read_to_string(d.join("SHA256SUMS")).unwrap();
    assert!(m.contains("  folder/inner (2).txt\n"), "{m}");
}

#[tokio::test(flavor = "multi_thread")]
async fn move_rename_and_copy_paths() {
    let e = env();
    let src = e.dir("src");
    e.dir("src/tree/deep");
    std::fs::write(src.join("tree/deep/f.txt"), b"deep").unwrap();
    std::fs::write(src.join("m.txt"), b"move me").unwrap();
    let dst = e.dir("dst");
    let q = e.queue();
    // same volume: fast rename
    let p = q
        .plan(
            vec![loc(&src.join("tree")), loc(&src.join("m.txt"))],
            loc(&dst),
            Op::Move,
        )
        .await
        .unwrap();
    assert_eq!(p.enough_space, Some(true));
    let id = q.enqueue(p, HashMap::new(), JobOptions::default());
    let s = wait_done(&q, &id).await;
    assert_eq!(s.state, JobState::Done, "{s:?}");
    assert!(!src.join("tree").exists());
    assert!(!src.join("m.txt").exists());
    assert_eq!(std::fs::read(dst.join("tree/deep/f.txt")).unwrap(), b"deep");
    assert_eq!(std::fs::read(dst.join("m.txt")).unwrap(), b"move me");

    // merge-move (destination folder exists): per-file copy + verify + delete
    e.dir("src2/tree/deep");
    std::fs::write(e.root.join("src2/tree/deep/g.txt"), b"g").unwrap();
    let p = q
        .plan(vec![loc(&e.root.join("src2/tree"))], loc(&dst), Op::Move)
        .await
        .unwrap();
    assert!(p.conflicts.is_empty());
    let id = q.enqueue(p, HashMap::new(), JobOptions::default());
    assert_eq!(wait_done(&q, &id).await.state, JobState::Done);
    assert_eq!(std::fs::read(dst.join("tree/deep/g.txt")).unwrap(), b"g");
    assert!(
        !e.root.join("src2/tree").exists(),
        "emptied source folders are removed"
    );

    // moving into the folder it is already in is skipped
    let p = q
        .plan(vec![loc(&dst.join("m.txt"))], loc(&dst), Op::Move)
        .await
        .unwrap();
    assert!(p.items.is_empty());
    assert_eq!(p.skipped.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn two_jobs_run_concurrently_third_waits() {
    let e = env();
    let src = e.dir("src");
    let dst = e.dir("dst");
    for i in 0..3 {
        std::fs::write(src.join(format!("{i}.bin")), data(64 * 1024 * 10, i)).unwrap();
    }
    let q = e.queue();
    q.set_chunk_delay(Duration::from_millis(20));
    let mut ids = Vec::new();
    for i in 0..3 {
        let p = q
            .plan(
                vec![loc(&src.join(format!("{i}.bin")))],
                loc(&dst),
                Op::Copy,
            )
            .await
            .unwrap();
        ids.push(q.enqueue(p, HashMap::new(), JobOptions::default()));
    }
    tokio::time::sleep(Duration::from_millis(60)).await;
    let st: Vec<JobState> = q.jobs().iter().map(|j| j.state).collect();
    assert_eq!(
        st.iter()
            .filter(|s| matches!(s, JobState::Running | JobState::Verifying))
            .count(),
        2,
        "{st:?}"
    );
    assert_eq!(st[2], JobState::Queued);
    q.set_chunk_delay(Duration::ZERO);
    for id in &ids {
        assert_eq!(wait_done(&q, id).await.state, JobState::Done);
    }
}

#[test]
fn status_serializes_camel_case() {
    let s = JobStatus {
        id: "j".into(),
        op: Op::Copy,
        state: JobState::Running,
        dest_dir: "/d".into(),
        files_total: 1,
        files_done: 0,
        bytes_total: 10,
        bytes_done: 5,
        current: None,
        speed_bps: 1,
        eta_secs: Some(5),
        error: None,
        mismatches: vec![],
        started: None,
        finished: None,
    };
    let j = serde_json::to_string(&XferEvent::Job(s)).unwrap();
    assert!(
        j.starts_with(
            r#"{"type":"job","id":"j","op":"copy","state":"running","destDir":"/d","filesTotal":1"#
        ),
        "{j}"
    );
}
