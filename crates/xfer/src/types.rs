//! Public, serializable types.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Op {
    Copy,
    Move,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanItem {
    /// Source location (URI).
    pub src: String,
    /// Destination location (URI).
    pub dst: String,
    /// Path relative to the destination folder, `/`-separated.
    pub rel: String,
    pub size: u64,
    pub is_dir: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Conflict {
    pub src: String,
    pub dst: String,
    pub src_size: Option<u64>,
    pub dst_size: Option<u64>,
    pub src_modified: Option<i64>,
    pub dst_modified: Option<i64>,
    /// Destination exists with the other type (file vs folder).
    pub type_mismatch: bool,
    /// Source and destination are the same file (copy into its own folder).
    pub same_file: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Skipped {
    pub src: String,
    pub reason: String,
}

/// Copy/move preview. Pass it back unchanged to `Queue::enqueue`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Plan {
    pub id: String,
    pub op: Op,
    pub dest_dir: String,
    /// Parents before children.
    pub items: Vec<PlanItem>,
    pub files: u64,
    pub dirs: u64,
    pub total_bytes: u64,
    pub conflicts: Vec<Conflict>,
    pub free_space: Option<u64>,
    pub enough_space: Option<bool>,
    pub skipped: Vec<Skipped>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Resolution {
    Replace,
    Skip,
    KeepBoth,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobOptions {
    /// Re-read each target after writing and compare SHA-256 with the source.
    #[serde(default = "yes")]
    pub verify: bool,
    /// Append `<sha256>  <relative path>` lines to `<dest>/SHA256SUMS`.
    #[serde(default)]
    pub write_manifest: bool,
}

impl Default for JobOptions {
    fn default() -> Self {
        JobOptions {
            verify: true,
            write_manifest: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum JobState {
    Queued,
    Running,
    Paused,
    Verifying,
    Done,
    Failed,
    Cancelled,
}

impl JobState {
    pub fn is_finished(self) -> bool {
        matches!(
            self,
            JobState::Done | JobState::Failed | JobState::Cancelled
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobStatus {
    pub id: String,
    pub op: Op,
    pub state: JobState,
    pub dest_dir: String,
    pub files_total: u64,
    pub files_done: u64,
    pub bytes_total: u64,
    pub bytes_done: u64,
    /// Destination URI of the file being worked on.
    pub current: Option<String>,
    pub speed_bps: u64,
    pub eta_secs: Option<u64>,
    pub error: Option<String>,
    /// Destination URIs whose verification failed (after one re-copy).
    pub mismatches: Vec<String>,
    /// Unix ms.
    pub started: Option<i64>,
    pub finished: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum XferEvent {
    Job(JobStatus),
    #[serde(rename_all = "camelCase")]
    FileDone {
        job: String,
        dst: String,
        sha256: String,
    },
}
