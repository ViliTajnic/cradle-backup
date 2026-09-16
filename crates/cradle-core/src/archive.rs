//! Archive layer: a `restic` subprocess wrapper.
//!
//! restic already solves diff engines, dedup, retention logic, archive
//! encryption/compression, and cloud transports — this module wraps it,
//! it does not reimplement any of that. Every restic-compatible
//! repository URI works here unchanged (a local path,
//! `sftp:user@host:/path`, `s3:s3.amazonaws.com/bucket`, `b2:bucket:path`,
//! ...): Cradle has no backend-specific code because restic's own backend
//! abstraction already is that code. That's also why validating "local
//! first, then NAS, then S3/B2" doesn't need separate code paths — it's a
//! validation order, not an implementation order.
//!
//! `working/<UDID>/` stays canonical (see `backup.rs`): this module only
//! ever *reads* from it, via `restic backup`, and never writes into it.

use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;

use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use crate::CradleError;
use crate::backup::ProgressSink;
use crate::catalog::DestinationRecord;
use crate::keychain;

/// A raw restic failure: its own exit code and message, before Cradle
/// adds a fix-naming hint.
#[derive(Debug)]
struct ResticError {
    code: Option<i64>,
    message: String,
}

impl From<ResticError> for CradleError {
    fn from(e: ResticError) -> Self {
        let hint = e.code.and_then(error_hint);
        match hint {
            Some(hint) => CradleError::Other(format!("restic error: {} — {hint}", e.message)),
            None => CradleError::Other(format!("restic error: {}", e.message)),
        }
    }
}

/// Names the fix for restic's own documented exit codes, same spirit as
/// `backup::device_error_hint`.
fn error_hint(code: i64) -> Option<&'static str> {
    match code {
        10 => Some("the repository doesn't exist at this URI yet — check the destination's uri"),
        11 => {
            Some("the repository is locked by another process — wait for it, or run `restic unlock` on this repo if a previous run crashed")
        }
        12 => Some(
            "wrong repository password — the Keychain entry for this destination may have been \
             changed or deleted outside Cradle",
        ),
        _ => None,
    }
}

/// Runs `restic <args>` against `destination`, feeding every stdout line to
/// `on_line` as it arrives (so callers can stream progress rather than
/// waiting for the process to exit). Returns `Ok(())` on a zero exit
/// status; on failure, parses restic's own `exit_error` JSON off stderr
/// (that message type is written to stderr, not stdout — confirmed against
/// a real `restic` 0.19.1 binary) for a real error message instead of just
/// a bare exit code.
///
/// The repository password is read once, in this process, via
/// [`keychain::read`] and handed to restic as `RESTIC_PASSWORD` on its own
/// environment.
///
/// This was originally `--password-command "security find-generic-password
/// ..."`, so restic would fetch the secret itself and it would never touch
/// Cradle's own env. That looked more careful on paper, but broke in
/// practice: a Keychain item created via `security-framework`'s
/// `SecItemAdd` gets an access-control list scoped to the *creating*
/// application, and `/usr/bin/security` — a different binary, spawned as
/// restic's child, not Cradle's — triggered a macOS Keychain authorization
/// prompt to read it. That's a GUI dialog with nothing to answer it in a
/// terminal, so the whole pipeline hung indefinitely; confirmed against a
/// real repository, not a hypothetical. Reading the password here, in the
/// same process that owns the Keychain item, stays inside that ACL and
/// never prompts.
/// How many trailing stderr lines [`run_streaming`] keeps for
/// [`parse_error`] — see that field's own doc for why this is bounded
/// rather than collecting everything.
const STDERR_TAIL_LINES: usize = 200;

async fn run_streaming(
    destination: &DestinationRecord,
    args: &[String],
    mut on_line: impl FnMut(&str),
) -> Result<(), ResticError> {
    let password = keychain::read(&destination.credential_ref).map_err(|e| ResticError {
        code: None,
        message: format!("could not read repository password from Keychain: {e}"),
    })?;

    // Same resolver `libimobiledevice.rs` uses, not a bare `Command::new`
    // trusting inherited `PATH` alone — a GUI app launched from Finder/Dock
    // doesn't always have Homebrew's PATH entry, and this crate already
    // hit that exact problem for the device tools. See `tools.rs`.
    let restic_path = crate::tools::resolve("restic").map_err(|e| ResticError {
        code: None,
        message: format!("{e} (try `brew install restic`)"),
    })?;
    let mut cmd = Command::new(restic_path);
    cmd.arg("--repo")
        .arg(&destination.uri)
        .env("RESTIC_PASSWORD", &password)
        .arg("--json")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| ResticError {
        code: None,
        message: format!("could not start restic: {e}"),
    })?;

    let stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");

    // Drain stderr concurrently on its own task: if we only read stdout,
    // a child that fills the stderr pipe buffer would deadlock waiting for
    // us to read it. Bounded to the last STDERR_TAIL_LINES rather than
    // collected wholesale — `parse_error` below only ever needs the most
    // recent lines (to reverse-search for a JSON error message, or as a
    // last-resort text fallback), and an unbounded buffer here means a
    // restic bug that floods stderr costs us memory proportional to
    // however long the run had been going, not to the error itself.
    let stderr_task = tokio::spawn(async move {
        let mut lines = std::collections::VecDeque::with_capacity(STDERR_TAIL_LINES);
        let mut reader = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            if lines.len() == STDERR_TAIL_LINES {
                lines.pop_front();
            }
            lines.push_back(line);
        }
        Vec::from(lines).join("\n")
    });

    let mut lines = BufReader::new(stdout).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if !line.trim().is_empty() {
            on_line(&line);
        }
    }

    let status = child.wait().await.map_err(|e| ResticError {
        code: None,
        message: format!("restic process error: {e}"),
    })?;
    let stderr_text = stderr_task.await.unwrap_or_default();

    if status.success() {
        Ok(())
    } else {
        Err(parse_error(&stderr_text, status.code()))
    }
}

#[derive(Deserialize)]
struct ResticExitError {
    code: i64,
    message: String,
}

fn parse_error(stderr_text: &str, exit_code: Option<i32>) -> ResticError {
    for line in stderr_text.lines().rev() {
        if let Ok(err) = serde_json::from_str::<ResticExitError>(line.trim()) {
            return ResticError {
                code: Some(err.code),
                message: err.message,
            };
        }
    }
    ResticError {
        code: exit_code.map(i64::from),
        message: if stderr_text.trim().is_empty() {
            format!("restic exited with status {exit_code:?} and no error output")
        } else {
            stderr_text.trim().to_string()
        },
    }
}

/// Runs `restic init` against `destination`, creating the repository if it
/// doesn't already exist. Returns `true` if this call created it, `false`
/// if one was already there — safe to call before every archive rather
/// than tracking initialization state separately.
pub async fn ensure_initialized(destination: &DestinationRecord) -> Result<bool, CradleError> {
    match run_streaming(destination, &["init".to_string()], |_| {}).await {
        Ok(()) => Ok(true),
        Err(e) if e.message.contains("already exists") => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// The result of a successful `restic backup`.
#[derive(Debug, Clone)]
pub struct BackupSummary {
    pub snapshot_id: String,
    pub total_bytes_processed: u64,
    pub total_files_processed: u64,
    /// New data actually written to the repository — typically far less
    /// than `total_bytes_processed` thanks to restic's own dedup, and the
    /// number that matters for "how much did this archive actually cost."
    pub data_added: u64,
}

#[derive(Deserialize)]
#[serde(tag = "message_type", rename_all = "snake_case")]
enum ResticBackupMessage {
    Status {
        #[serde(default)]
        percent_done: f64,
        #[serde(default)]
        total_bytes: u64,
        #[serde(default)]
        bytes_done: u64,
        #[serde(default)]
        files_done: Option<u64>,
    },
    Summary {
        snapshot_id: String,
        #[serde(default)]
        total_bytes_processed: u64,
        #[serde(default)]
        total_files_processed: u64,
        #[serde(default)]
        data_added: u64,
    },
    #[serde(other)]
    Other,
}

/// Archives `source_dir` (in practice, `working/<UDID>/` — see the module
/// doc) into `destination`'s repository, reporting progress the same way
/// [`crate::backup::run`] does: [`ProgressSink::on_progress`] from restic's
/// own streamed `status` messages, converting its `percent_done` (a 0.0-1.0
/// fraction) to the 0-100 scale the rest of Cradle uses.
pub async fn backup(
    destination: &DestinationRecord,
    source_dir: &Path,
    progress: Arc<dyn ProgressSink>,
) -> Result<BackupSummary, CradleError> {
    let source_arg = source_dir
        .to_str()
        .ok_or_else(|| CradleError::Other("working directory path is not valid UTF-8".into()))?
        .to_string();

    let mut summary: Option<BackupSummary> = None;
    run_streaming(
        destination,
        &["backup".to_string(), source_arg],
        |line| match serde_json::from_str::<ResticBackupMessage>(line) {
            Ok(ResticBackupMessage::Status {
                percent_done,
                total_bytes,
                bytes_done,
                files_done,
            }) => {
                progress.on_progress(bytes_done, total_bytes, percent_done * 100.0);
                if let Some(files_done) = files_done {
                    progress.on_file("", files_done as u32);
                }
            }
            Ok(ResticBackupMessage::Summary {
                snapshot_id,
                total_bytes_processed,
                total_files_processed,
                data_added,
            }) => {
                summary = Some(BackupSummary {
                    snapshot_id,
                    total_bytes_processed,
                    total_files_processed,
                    data_added,
                });
            }
            Ok(ResticBackupMessage::Other) | Err(_) => {}
        },
    )
    .await?;

    summary.ok_or_else(|| CradleError::Other("restic backup finished without a summary message".into()))
}

/// One entry from `restic snapshots --json`.
#[derive(Debug, Clone, Deserialize)]
pub struct ResticSnapshot {
    pub id: String,
    pub short_id: String,
    pub time: String,
    #[serde(default)]
    pub paths: Vec<String>,
}

/// Lists every snapshot in `destination`'s repository.
pub async fn list_snapshots(destination: &DestinationRecord) -> Result<Vec<ResticSnapshot>, CradleError> {
    let mut output = String::new();
    run_streaming(destination, &["snapshots".to_string()], |line| {
        output.push_str(line);
        output.push('\n');
    })
    .await?;

    serde_json::from_str(output.trim())
        .map_err(|e| CradleError::Other(format!("could not parse restic snapshots output: {e}")))
}

#[derive(Deserialize)]
#[serde(tag = "message_type", rename_all = "snake_case")]
enum ResticRestoreMessage {
    // Field names and `omitempty` semantics taken straight from restic's
    // own internal/ui/restore/json.go, not guessed — a fast local restore
    // never actually emits a `status` line to check this against (it
    // finishes before the first progress tick), only `summary`.
    Status {
        #[serde(default)]
        percent_done: f64,
        #[serde(default)]
        total_bytes: u64,
        #[serde(default)]
        bytes_restored: u64,
        #[serde(default)]
        files_restored: u64,
    },
    Summary {
        #[serde(default)]
        total_files: u64,
        #[serde(default)]
        files_restored: u64,
        #[serde(default)]
        total_bytes: u64,
    },
    #[serde(other)]
    Other,
}

/// Result of a successful `restic restore`.
#[derive(Debug, Clone, Default)]
pub struct RestoreSummary {
    pub path: std::path::PathBuf,
    pub total_files: u64,
    pub files_restored: u64,
    pub total_bytes: u64,
}

/// Restores `snapshot_id` (a full or short restic snapshot id) from
/// `destination` into `scratch_dir`, reporting progress the same way
/// [`backup`] does.
///
/// restic mirrors the snapshot's *original absolute path* under
/// `--target` rather than flattening it — confirmed against a real
/// restore, where backing up `/tmp/rrt/source/UDID` and restoring into
/// `/tmp/rrt/scratch` produced `/tmp/rrt/scratch/tmp/rrt/source/UDID`, not
/// `/tmp/rrt/scratch/UDID`. So this reads the snapshot's own recorded
/// `paths[0]` (from `restic snapshots`) to compute where the restored
/// files actually landed, rather than assuming a layout.
pub async fn restore(
    destination: &DestinationRecord,
    snapshot_id: &str,
    scratch_dir: &Path,
    progress: Arc<dyn ProgressSink>,
) -> Result<RestoreSummary, CradleError> {
    let snapshots = list_snapshots(destination).await?;
    let snapshot = snapshots
        .iter()
        .find(|s| s.id == snapshot_id || s.short_id == snapshot_id)
        .ok_or_else(|| CradleError::Other(format!("no snapshot '{snapshot_id}' in this repository")))?;
    let original_path = snapshot
        .paths
        .first()
        .ok_or_else(|| CradleError::Other("snapshot has no recorded path".into()))?
        .clone();

    let scratch_arg = scratch_dir
        .to_str()
        .ok_or_else(|| CradleError::Other("scratch directory path is not valid UTF-8".into()))?
        .to_string();

    let mut summary: Option<RestoreSummary> = None;
    run_streaming(
        destination,
        &[
            "restore".to_string(),
            snapshot.id.clone(),
            "--target".to_string(),
            scratch_arg,
        ],
        |line| match serde_json::from_str::<ResticRestoreMessage>(line) {
            Ok(ResticRestoreMessage::Status {
                percent_done,
                total_bytes,
                bytes_restored,
                files_restored,
            }) => {
                progress.on_progress(bytes_restored, total_bytes, percent_done * 100.0);
                progress.on_file("", files_restored as u32);
            }
            Ok(ResticRestoreMessage::Summary {
                total_files,
                files_restored,
                total_bytes,
            }) => {
                summary = Some(RestoreSummary {
                    path: std::path::PathBuf::new(),
                    total_files,
                    files_restored,
                    total_bytes,
                });
            }
            Ok(ResticRestoreMessage::Other) | Err(_) => {}
        },
    )
    .await?;

    let mut summary =
        summary.ok_or_else(|| CradleError::Other("restic restore finished without a summary message".into()))?;
    summary.path = scratch_dir.join(original_path.trim_start_matches('/'));
    Ok(summary)
}

/// A retention policy for `restic forget --prune`. At least one field must
/// be set — restic itself refuses to forget everything by accident, and so
/// do we (see [`forget_and_prune`]).
#[derive(Debug, Clone, Default)]
pub struct RetentionPolicy {
    pub keep_last: Option<u32>,
    pub keep_daily: Option<u32>,
    pub keep_weekly: Option<u32>,
    pub keep_monthly: Option<u32>,
}

impl RetentionPolicy {
    fn to_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        let mut push = |flag: &str, value: Option<u32>| {
            if let Some(n) = value {
                args.push(flag.to_string());
                args.push(n.to_string());
            }
        };
        push("--keep-last", self.keep_last);
        push("--keep-daily", self.keep_daily);
        push("--keep-weekly", self.keep_weekly);
        push("--keep-monthly", self.keep_monthly);
        args
    }

    /// Serializes the policy for `destinations.retention_json` — an audit
    /// trail of what was last used, not something re-read to apply
    /// retention automatically (see [`crate::catalog::Catalog::set_destination_retention`]).
    pub fn to_json(&self) -> String {
        serde_json::json!({
            "keep_last": self.keep_last,
            "keep_daily": self.keep_daily,
            "keep_weekly": self.keep_weekly,
            "keep_monthly": self.keep_monthly,
        })
        .to_string()
    }
}

/// Result of a `restic forget --prune` run.
#[derive(Debug, Clone, Default)]
pub struct ForgetSummary {
    pub kept: u64,
    pub removed: u64,
}

#[derive(Deserialize)]
struct ForgetGroup {
    // restic prints `null` (not `[]`) for either field when there's
    // nothing to report — confirmed against a real `restic forget` run
    // that kept everything, where `"remove":null` appeared. `#[serde(default)]`
    // alone only covers a *missing* key, not a present `null` one, so
    // these have to be `Option<Vec<_>>` rather than a defaulted `Vec<_>`.
    #[serde(default)]
    keep: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    remove: Option<Vec<serde_json::Value>>,
}

/// One snapshot restic reported as kept or removed by a retention policy —
/// just enough to show a person which backup that actually is, pulled out
/// of `restic forget`'s full per-snapshot JSON object.
#[derive(Debug, Clone)]
pub struct RetentionPreviewEntry {
    pub short_id: String,
    pub time: String,
}

fn parse_preview_entries(values: Option<Vec<serde_json::Value>>) -> Vec<RetentionPreviewEntry> {
    values
        .unwrap_or_default()
        .iter()
        .map(|v| RetentionPreviewEntry {
            short_id: v.get("short_id").and_then(|x| x.as_str()).unwrap_or("?").to_string(),
            time: v.get("time").and_then(|x| x.as_str()).unwrap_or("?").to_string(),
        })
        .collect()
}

/// What applying `policy` would do, without actually doing it.
#[derive(Debug, Clone, Default)]
pub struct RetentionPreview {
    pub kept: Vec<RetentionPreviewEntry>,
    pub removed: Vec<RetentionPreviewEntry>,
}

fn require_policy_args(policy: &RetentionPolicy) -> Result<Vec<String>, CradleError> {
    let args = policy.to_args();
    if args.is_empty() {
        return Err(CradleError::Other(
            "no retention policy given — pass at least one of keep_last/keep_daily/keep_weekly/keep_monthly"
                .into(),
        ));
    }
    Ok(args)
}

async fn run_forget(destination: &DestinationRecord, args: Vec<String>) -> Result<Vec<ForgetGroup>, CradleError> {
    let mut output = String::new();
    run_streaming(destination, &args, |line| {
        output.push_str(line);
        output.push('\n');
    })
    .await?;

    serde_json::from_str(output.trim())
        .map_err(|e| CradleError::Other(format!("could not parse restic forget output: {e}")))
}

/// Shows which snapshots applying `policy` would keep or remove, without
/// actually removing anything — `restic forget --dry-run`.
/// CODEBASE_ANALYSIS.md: "Retention preview: Show which snapshots will be
/// removed before applying retention."
pub async fn preview_retention(
    destination: &DestinationRecord,
    policy: &RetentionPolicy,
) -> Result<RetentionPreview, CradleError> {
    let mut args = vec!["forget".to_string(), "--dry-run".to_string()];
    args.extend(require_policy_args(policy)?);

    let groups = run_forget(destination, args).await?;
    Ok(RetentionPreview {
        kept: groups.iter().flat_map(|g| parse_preview_entries(g.keep.clone())).collect(),
        removed: groups.iter().flat_map(|g| parse_preview_entries(g.remove.clone())).collect(),
    })
}

/// Applies `policy` to `destination`'s repository via `restic forget
/// --prune`, actually reclaiming space rather than just dropping snapshot
/// references — retention logic belongs to restic, not a Cradle-side
/// scheduler deciding what to keep.
pub async fn forget_and_prune(
    destination: &DestinationRecord,
    policy: &RetentionPolicy,
) -> Result<ForgetSummary, CradleError> {
    let mut args = vec!["forget".to_string(), "--prune".to_string()];
    args.extend(require_policy_args(policy)?);

    let groups = run_forget(destination, args).await?;
    Ok(ForgetSummary {
        kept: groups.iter().flat_map(|g| g.keep.as_deref()).flatten().count() as u64,
        removed: groups.iter().flat_map(|g| g.remove.as_deref()).flatten().count() as u64,
    })
}

/// Result of a `restic check` run.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CheckSummary {
    #[serde(default)]
    pub num_errors: u64,
}

/// How thoroughly [`check`] reads a repository. Plain `restic check`
/// (`CheckMode::Quick`) only verifies structure — that the index and
/// snapshots are internally consistent and every pack file *exists* — not
/// that any pack file's actual bytes are intact; bit rot or partial
/// corruption on the storage backend passes it silently.
/// CODEBASE_ANALYSIS.md: "`archive::check` invokes plain `restic check`,
/// while CLI wording claims it reads the entire repository. Plain check
/// does not read and verify all pack contents."
///
/// [Restic's own docs on this distinction](https://restic.readthedocs.io/en/stable/045_working_with_repos.html#checking-integrity-and-consistency).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckMode {
    /// `restic check` — structure only, seconds even for a large
    /// repository. Good for "did the last archive leave things sane",
    /// not for "is my data still readable."
    Quick,
    /// `restic check --read-data` — downloads and checksums every pack
    /// file. Actually reads the whole repository, at the cost of
    /// transferring all of it again; can take as long as the original
    /// archive did, longer over a slow link.
    Full,
    /// `restic check --read-data-subset=<percent>%` — checksums a random
    /// sample instead of everything, catching the same class of silent
    /// storage-level corruption `Full` does at a fraction of the cost.
    /// `percent` is clamped to `1..=100`.
    Sample { percent: u8 },
}

impl CheckMode {
    fn extra_args(self) -> Vec<String> {
        match self {
            CheckMode::Quick => vec![],
            CheckMode::Full => vec!["--read-data".to_string()],
            CheckMode::Sample { percent } => {
                vec![format!("--read-data-subset={}%", percent.clamp(1, 100))]
            }
        }
    }

    /// One line naming what this mode actually does — CLI/app wording
    /// should say this instead of inventing its own claim about how much
    /// of the repository was read.
    pub fn description(self) -> &'static str {
        match self {
            CheckMode::Quick => "checking repository structure (not pack contents — use --full or --sample for that)",
            CheckMode::Full => "reading and verifying every byte in the repository — this can take as long as the original archive",
            CheckMode::Sample { .. } => "reading and verifying a random sample of the repository",
        }
    }
}

/// Runs a repository check at `mode`'s thoroughness. Even `CheckMode::Full`
/// is heavier than the per-archive verification
/// [`crate::catalog::Catalog::finish_archive`] already does (restic
/// checksums everything it writes as part of `backup` itself) — this is
/// for a periodic, explicit audit, not something to run after every single
/// archive.
pub async fn check(destination: &DestinationRecord, mode: CheckMode) -> Result<CheckSummary, CradleError> {
    let mut args = vec!["check".to_string()];
    args.extend(mode.extra_args());

    let mut summary: Option<CheckSummary> = None;
    run_streaming(destination, &args, |line| {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(line)
            && value.get("message_type").and_then(|v| v.as_str()) == Some("summary")
            && let Ok(parsed) = serde_json::from_value(value)
        {
            summary = Some(parsed);
        }
    })
    .await?;

    summary.ok_or_else(|| CradleError::Other("restic check finished without a summary message".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::NullProgress;

    #[test]
    fn quick_check_adds_no_extra_flags() {
        assert!(CheckMode::Quick.extra_args().is_empty());
    }

    #[test]
    fn full_check_reads_all_data() {
        assert_eq!(CheckMode::Full.extra_args(), vec!["--read-data".to_string()]);
    }

    #[test]
    fn sample_check_uses_the_requested_percentage() {
        assert_eq!(
            CheckMode::Sample { percent: 10 }.extra_args(),
            vec!["--read-data-subset=10%".to_string()]
        );
    }

    #[test]
    fn sample_check_clamps_an_out_of_range_percentage() {
        assert_eq!(
            CheckMode::Sample { percent: 0 }.extra_args(),
            vec!["--read-data-subset=1%".to_string()]
        );
        assert_eq!(
            CheckMode::Sample { percent: 255 }.extra_args(),
            vec!["--read-data-subset=100%".to_string()]
        );
    }

    fn test_destination(uri: &str, credential_ref: &str) -> DestinationRecord {
        DestinationRecord {
            id: 0,
            name: "test".to_string(),
            kind: "local".to_string(),
            uri: uri.to_string(),
            credential_ref: credential_ref.to_string(),
            retention_json: None,
        }
    }

    /// Exercises the whole wrapper against a *real* `restic` binary and a
    /// *real* local repository — no mocking, matching how everything else
    /// in this codebase has been verified. `#[ignore]`d because it needs
    /// `restic` on PATH and touches the real macOS Keychain (see
    /// `keychain.rs`'s own ignored test for why that's not routine-safe);
    /// run explicitly with `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn full_lifecycle_against_real_restic() {
        let tmp = std::env::temp_dir().join(format!("cradle-archive-test-{}", std::process::id()));
        let repo_dir = tmp.join("repo");
        let source_dir = tmp.join("source");
        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::write(source_dir.join("file1.txt"), b"hello from a cradle test").unwrap();

        let account = format!("cradle-archive-test-{}", std::process::id());
        crate::keychain::generate_and_store(&account).unwrap();
        let destination = test_destination(repo_dir.to_str().unwrap(), &account);

        let created = ensure_initialized(&destination).await.unwrap();
        assert!(created, "fresh repo should report as newly created");
        let created_again = ensure_initialized(&destination).await.unwrap();
        assert!(!created_again, "second init on the same repo should be a no-op");

        let summary = backup(&destination, &source_dir, Arc::new(NullProgress))
            .await
            .unwrap();
        assert!(!summary.snapshot_id.is_empty());
        assert_eq!(summary.total_files_processed, 1);

        let snapshots = list_snapshots(&destination).await.unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].id, summary.snapshot_id);

        let check_summary = check(&destination, CheckMode::Full).await.unwrap();
        assert_eq!(check_summary.num_errors, 0);

        let forgotten = forget_and_prune(
            &destination,
            &RetentionPolicy {
                keep_last: Some(1),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(forgotten.kept, 1);
        assert_eq!(forgotten.removed, 0);

        crate::keychain::delete(&account).unwrap();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Same idea as above, but confirms a wrong-password repository open
    /// fails with a helpful, code-12-derived message instead of a bare
    /// exit status.
    #[tokio::test]
    #[ignore]
    async fn wrong_password_produces_a_named_hint() {
        let tmp = std::env::temp_dir().join(format!("cradle-archive-wrongpw-{}", std::process::id()));
        let repo_dir = tmp.join("repo");

        let right_account = format!("cradle-archive-wrongpw-right-{}", std::process::id());
        let wrong_account = format!("cradle-archive-wrongpw-wrong-{}", std::process::id());
        crate::keychain::generate_and_store(&right_account).unwrap();
        crate::keychain::generate_and_store(&wrong_account).unwrap();

        let real_destination = test_destination(repo_dir.to_str().unwrap(), &right_account);
        ensure_initialized(&real_destination).await.unwrap();

        let wrong_destination = test_destination(repo_dir.to_str().unwrap(), &wrong_account);
        let err = list_snapshots(&wrong_destination).await.unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("wrong repository password"),
            "expected a named hint for exit code 12, got: {message}"
        );

        crate::keychain::delete(&right_account).unwrap();
        crate::keychain::delete(&wrong_account).unwrap();
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
