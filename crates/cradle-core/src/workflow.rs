//! One place that owns an entire operation — prechecks, locking,
//! credentials, verification, and catalog bookkeeping — instead of each
//! frontend (`cradle-cli`, `cradle-app`) re-deriving the same sequence.
//!
//! CODEBASE_ANALYSIS.md: "The most valuable simplification is to make the
//! core own an entire operation, including its invariants and failure
//! handling." Before this module, `cradle-cli`'s `run_backup` and
//! `cradle-app`'s `run_backup` (and their `archive`/`restore` equivalents)
//! independently called `precheck::run`, `backup::run_resilient`,
//! `verify::run`, and every `Catalog` method in the same order — any fix
//! to that sequence (the working-set lock, the pre-archive re-verify) had
//! to land in both places and could drift. These functions are the single
//! sequence; a frontend supplies a [`crate::backup::ProgressSink`] and a
//! retry/attention callback for its own narration, and gets back a
//! [`BackupOutcome`]/[`ArchiveOutcome`]/[`RestoreOutcome`] to render
//! however it likes — CLI text, Tauri events, whatever a future GUI needs.
//!
//! What stays out on purpose: message *wording*. `precheck::Report` and
//! `verify::Report`'s `problems` are already structured enough for each
//! frontend to phrase its own hint (`cradle password enable --udid ...`
//! vs. "Use the Set backup password panel") — this module returns those
//! reports rather than pre-rendering text, so that stays a frontend
//! concern, not a core one.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::backup::{self, ProgressSink, RetryReason};
use crate::catalog::{Catalog, DeviceRecord, RunKind, RunStatus};
use crate::{CradleError, archive, keychain, lock::WorkingSetLock, precheck, restore, verify};

/// Every workflow function's error: either a precheck that failed before
/// anything irreversible happened (nothing was recorded), or a failure
/// partway through — always with whatever the device/repository actually
/// reported transferring, and always *after* the corresponding `runs` row
/// has already been closed out as `Failed`. A caller never needs to record
/// the failure itself; it only needs to show it.
#[derive(Debug)]
pub enum WorkflowError {
    /// Failed before a `runs` row was ever opened — a precheck, or the
    /// working-set lock (another operation already has it).
    NotStarted(NotStartedReason),
    /// Failed after a `runs` row was opened; it has already been marked
    /// `Failed` with `source`'s message before this is returned.
    Failed {
        source: CradleError,
        bytes_transferred: u64,
        files_transferred: u64,
    },
}

#[derive(Debug)]
pub enum NotStartedReason {
    /// A precheck failed — see the report for which one.
    Precheck(Box<precheck::Report>),
    /// Something before the transfer itself failed: the working-set lock
    /// (another operation already has it), or a catalog write.
    SetupFailed(CradleError),
}

impl std::fmt::Display for WorkflowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkflowError::NotStarted(NotStartedReason::Precheck(_)) => write!(f, "prechecks failed"),
            WorkflowError::NotStarted(NotStartedReason::SetupFailed(e)) => write!(f, "{e}"),
            WorkflowError::Failed { source, .. } => write!(f, "{source}"),
        }
    }
}
impl std::error::Error for WorkflowError {}

/// What to back up and where — the one thing every frontend's "Back Up
/// Now" action needs to supply.
pub struct BackupRequest {
    pub udid: String,
    pub working_root: PathBuf,
    pub full: bool,
}

/// A backup run that actually completed the transfer — which may still be
/// [`verify::Outcome::Invalid`]; that is a real, named result, not a
/// [`WorkflowError`]. Only a failure to even finish attempting the backup
/// is a `WorkflowError`.
pub struct BackupOutcome {
    pub backup_dir: PathBuf,
    pub bytes_transferred: u64,
    pub gate: verify::Report,
}

/// Runs prechecks, a resilient backup transfer, and the verification
/// gate against `request`, recording every step in `catalog`. Mirrors
/// what both frontends' `run_backup` did by hand before this module
/// existed — see the module doc.
///
/// `on_retry` is [`backup::run_resilient`]'s own callback, forwarded
/// unchanged: each frontend narrates a retry differently (CLI prints to
/// stderr, the app emits a Tauri event), which is exactly the kind of
/// wording this module deliberately leaves to the caller. `on_precheck_passed`
/// fires once, right before the transfer starts, for the same reason — a
/// status line like "Prechecks passed, backing up into …" is wording, not
/// orchestration.
pub async fn run_backup(
    catalog: Catalog,
    request: BackupRequest,
    progress: Arc<dyn ProgressSink>,
    on_precheck_passed: impl FnOnce(&crate::libimobiledevice::DeviceInfo),
    on_transfer_complete: impl FnOnce(),
    on_retry: impl Fn(RetryReason, u32, u32) + Send + Sync + 'static,
) -> Result<BackupOutcome, WorkflowError> {
    let BackupRequest { udid, working_root, full } = request;

    let precheck_report = precheck::run(&udid, &working_root)
        .await
        .map_err(|e| WorkflowError::NotStarted(NotStartedReason::SetupFailed(e)))?;
    if !precheck_report.passed() {
        return Err(WorkflowError::NotStarted(NotStartedReason::Precheck(Box::new(precheck_report))));
    }
    let device_info = precheck_report
        .device
        .expect("precheck_report.passed() implies pairing_valid, which implies device is Some");
    on_precheck_passed(&device_info);

    let _working_set_lock = WorkingSetLock::acquire(&working_root, &udid)
        .map_err(|e| WorkflowError::NotStarted(NotStartedReason::SetupFailed(e)))?;
    // Holding the lock means nothing else is genuinely running against
    // this device right now, so any `running` row still on file is
    // abandoned, not concurrent — see `fail_abandoned_runs`'s own doc.
    let _ = catalog.fail_abandoned_runs(&udid);

    catalog
        .upsert_device(&DeviceRecord {
            udid: udid.clone(),
            name: device_info.name.clone(),
            product_type: device_info.product_type.clone(),
            ios_version: device_info.ios_version.clone(),
            encrypted: precheck_report.encryption_enabled,
        })
        .map_err(|e| WorkflowError::NotStarted(NotStartedReason::SetupFailed(e)))?;
    let run_id = catalog
        .start_run(&udid, RunKind::Backup)
        .map_err(|e| WorkflowError::NotStarted(NotStartedReason::SetupFailed(e)))?;

    let fail = |catalog: &Catalog, source: CradleError, bytes: u64, files: u64| -> WorkflowError {
        let _ = catalog.finish_run(run_id, RunStatus::Failed, bytes, files, Some(&source.to_string()));
        WorkflowError::Failed {
            source,
            bytes_transferred: bytes,
            files_transferred: files,
        }
    };

    let outcome = backup::run_resilient(&udid, &working_root, full, progress, on_retry)
        .await
        .map_err(|e| fail(&catalog, e.source, e.bytes_transferred, e.files_received))?;
    on_transfer_complete();

    let stored_password = keychain::try_read(&keychain::device_account(&udid))
        .map_err(|e| fail(&catalog, e, outcome.bytes_transferred, outcome.files_received))?;
    let gate = verify::run(&outcome.backup_dir, outcome.files_received, stored_password.as_deref())
        .await
        .map_err(|e| fail(&catalog, e, outcome.bytes_transferred, outcome.files_received))?;

    match gate.outcome {
        verify::Outcome::Invalid => {
            let _ = catalog.finish_run(
                run_id,
                RunStatus::Failed,
                outcome.bytes_transferred,
                gate.files_on_disk,
                Some(&gate.problems.join(" ")),
            );
        }
        verify::Outcome::Verified | verify::Outcome::NeedsPassword => {
            // The transfer itself succeeded either way — only
            // `NeedsPassword` can't confirm it. The `verified` flag here
            // is what actually keeps an unconfirmed backup out of
            // `latest_verified_snapshot` (what archiving reads), not the
            // run's own status. One transaction, not two separate
            // writes — see `finish_run_with_snapshot`'s own doc.
            let _ = catalog.finish_run_with_snapshot(
                run_id,
                outcome.bytes_transferred,
                gate.files_on_disk,
                &udid,
                gate.total_bytes,
                &device_info.ios_version,
                gate.outcome == verify::Outcome::Verified,
            );
        }
    }

    Ok(BackupOutcome {
        backup_dir: outcome.backup_dir,
        bytes_transferred: outcome.bytes_transferred,
        gate,
    })
}

/// What to archive and where — resolved catalog/destination records
/// rather than names, since both frontends already look those up for
/// their own error messages before an archive can start.
pub struct ArchiveRequest<'a> {
    pub udid: String,
    pub working_root: PathBuf,
    pub destination: &'a crate::catalog::DestinationRecord,
}

pub struct ArchiveOutcome {
    pub summary: archive::BackupSummary,
}

/// Everything that can keep [`run_archive`] from producing an
/// [`ArchiveOutcome`] — refusals (nothing was touched) and failures
/// (something was attempted and recorded as failed) alike, since neither
/// caller (CLI, app) treats them differently beyond the message shown.
#[derive(Debug)]
pub enum ArchiveError {
    NoVerifiedSnapshot,
    SourceMissing(PathBuf),
    Locked(CradleError),
    /// The working directory no longer verifies right now, even though
    /// the catalog has an earlier verified snapshot — see
    /// CODEBASE_ANALYSIS.md's "an old verification record can authorize
    /// archiving a newer partial backup". Carries the fresh gate so the
    /// caller can show exactly what changed.
    NoLongerVerified(verify::Report),
    /// A step failed outright (Keychain, the catalog, or restic itself) —
    /// already recorded via `finish_archive` if an archive row was open
    /// when it happened.
    Failed(CradleError),
}

impl std::fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArchiveError::NoVerifiedSnapshot => write!(f, "no verified snapshot yet"),
            ArchiveError::SourceMissing(p) => write!(f, "backup directory {} not found", p.display()),
            ArchiveError::Locked(e) => write!(f, "{e}"),
            ArchiveError::NoLongerVerified(gate) => {
                write!(f, "no longer verifies: {}", gate.problems.join(" "))
            }
            ArchiveError::Failed(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for ArchiveError {}

/// Re-verifies the working directory fresh — never trusting the catalog's
/// historical `verified_at` alone — and, only if that passes, archives it.
/// See the module doc and [`ArchiveError::NoLongerVerified`].
pub async fn run_archive(
    catalog: Catalog,
    request: ArchiveRequest<'_>,
    progress: Arc<dyn ProgressSink>,
) -> Result<ArchiveOutcome, ArchiveError> {
    let snapshot = catalog
        .latest_verified_snapshot(&request.udid)
        .map_err(ArchiveError::Failed)?
        .ok_or(ArchiveError::NoVerifiedSnapshot)?;

    let source_dir = request.working_root.join(&request.udid);
    if !source_dir.is_dir() {
        return Err(ArchiveError::SourceMissing(source_dir));
    }

    // Held from here through the restic read below: see the module doc
    // and CODEBASE_ANALYSIS.md's "operations can overlap" finding.
    let _working_set_lock =
        WorkingSetLock::acquire(&request.working_root, &request.udid).map_err(ArchiveError::Locked)?;
    let _ = catalog.fail_abandoned_archives(snapshot.id);

    let stored_password =
        keychain::try_read(&keychain::device_account(&request.udid)).map_err(ArchiveError::Failed)?;
    let fresh_gate = verify::run(&source_dir, 0, stored_password.as_deref())
        .await
        .map_err(ArchiveError::Failed)?;
    if fresh_gate.outcome != verify::Outcome::Verified {
        return Err(ArchiveError::NoLongerVerified(fresh_gate));
    }

    archive::ensure_initialized(request.destination)
        .await
        .map_err(ArchiveError::Failed)?;
    let archive_id = catalog
        .start_archive(snapshot.id, request.destination.id)
        .map_err(ArchiveError::Failed)?;

    match archive::backup(request.destination, &source_dir, progress).await {
        Ok(summary) => {
            let _ = catalog.finish_archive(
                archive_id,
                crate::catalog::ArchiveState::Succeeded,
                Some(&summary.snapshot_id),
                None,
            );
            Ok(ArchiveOutcome { summary })
        }
        Err(e) => {
            let _ =
                catalog.finish_archive(archive_id, crate::catalog::ArchiveState::Failed, None, Some(&e.to_string()));
            Err(ArchiveError::Failed(e))
        }
    }
}

/// Copies a backup out of the working set into `scratch_root`, holding
/// the working-set lock only for that copy — restore itself runs
/// entirely out of the scratch copy afterward (CLAUDE.md: restore "does
/// not touch the working set").
pub async fn stage_restore_from_working(
    working_root: &Path,
    source_udid: &str,
    scratch_root: &Path,
    progress: Arc<dyn ProgressSink>,
) -> Result<PathBuf, CradleError> {
    let _working_set_lock = WorkingSetLock::acquire(working_root, source_udid)?;
    restore::stage_from_working(working_root, source_udid, scratch_root, progress).await
}
