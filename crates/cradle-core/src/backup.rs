//! Runs a `mobilebackup2` backup into the canonical working directory.
//!
//! `working/<UDID>/` is canonical: it stays exactly in the state the
//! device left it, because MobileBackup2 computes incrementals *on the
//! device* by inspecting `Status.plist` / `Manifest.plist` / `Manifest.db`
//! already sitting there. This module never moves, archives, or otherwise
//! touches that directory beyond what the protocol itself writes into it.
//!
//! The actual transfer is driven by `idevicebackup2` (see
//! [`crate::libimobiledevice`]) as a subprocess, not the `idevice` Rust
//! crate this module used until this fixed a real, reproducible bug: a
//! backup of a real device reliably failed with `MBErrorDomain 104` at a
//! fixed point (~94%, ~19,000 files), regardless of working directory or
//! destination volume, while `idevicebackup2` completed the identical
//! backup cleanly.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::CradleError;
use crate::libimobiledevice;

/// Receives honest, measurable progress during a backup.
///
/// Every long-running operation should report files done/total, bytes,
/// rate, ETA, and current domain — never ship an indeterminate spinner for
/// an operation whose progress can be measured. Implementations should be
/// cheap — these are called for every file and every progress tick.
///
/// `idevicebackup2`'s default output reports files done/total, bytes, and
/// an overall percentage, but not each file's domain the way the old
/// `idevice`-backed implementation's typed callback did — that would need
/// parsing `-d` debug output (raw protocol frames, fragile and versioned to
/// internals). Accepted trade-off.
pub trait ProgressSink: Send + Sync {
    /// `bytes_total` is 0 when the device hasn't reported a batch size yet.
    /// `overall_progress` is the device's own 0.0-100.0 estimate, or
    /// negative when it hasn't reported one.
    fn on_progress(&self, bytes_done: u64, bytes_total: u64, overall_progress: f64);
    fn on_file(&self, path: &str, file_count: u32);

    /// Fires when the device needs the user to physically look at it —
    /// concretely, when iOS shows an on-device passcode/Face ID prompt to
    /// authorize access to protected data (`true`), and again once that
    /// prompt is resolved (`false`).
    ///
    /// This is not a hypothetical: if nobody dismisses that prompt, the
    /// backup fails with MBErrorDomain 208 ("device locked when iOS needed
    /// to access protected data") — a real failure mode hit on the very
    /// first real-device run of this code. Default no-op so existing sinks
    /// don't have to know about it, but a UI that ignores this will
    /// silently stall until the user happens to glance at their phone.
    fn on_attention_needed(&self, _needed: bool) {}
}

/// A [`ProgressSink`] that discards everything. Useful for callers (tests,
/// library embedders, and one-shot operations like [`set_encryption`] that
/// don't need progress output) that don't need it.
pub struct NullProgress;

impl ProgressSink for NullProgress {
    fn on_progress(&self, _bytes_done: u64, _bytes_total: u64, _overall_progress: f64) {}
    fn on_file(&self, _path: &str, _file_count: u32) {}
}

/// The outcome of a completed backup run.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub udid: String,
    pub backup_dir: PathBuf,
    /// Number of files the device reported sending this run — parsed from
    /// `idevicebackup2`'s own `"Received %d files from device."` summary
    /// line where available, falling back to a live-counted approximation
    /// otherwise. Fed into [`crate::verify`] as the count to check on-disk
    /// files against.
    pub files_received: u64,
    /// Bytes actually moved over the wire this run — summed from
    /// `idevicebackup2`'s per-file progress output, not the on-disk size of
    /// the resulting snapshot (an incremental run typically moves far less
    /// than the snapshot is large, since most files were already there).
    /// Feeds `catalog::Catalog::finish_run`'s `bytes` column.
    pub bytes_transferred: u64,
}

/// A backup failure paired with how far the run got before it happened.
///
/// Found via a real run: a device error late in a 53-minute transfer left
/// the catalog recording 0 bytes / 0 files for a run that had in fact been
/// moving data continuously — partial counts weren't surviving the `Err`
/// path out of the function. `bytes_transferred`/`files_received` are 0
/// only when the run never got far enough to start the subprocess at all
/// (a missing tool, a bad working directory) — genuinely nothing moved in
/// that case.
#[derive(Debug)]
pub struct BackupError {
    pub source: CradleError,
    pub bytes_transferred: u64,
    pub files_received: u64,
}

impl std::fmt::Display for BackupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.source, f)
    }
}

impl std::error::Error for BackupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Early failures (working directory creation, a missing `idevicebackup2`)
/// happen before the subprocess starts, so 0/0 here is accurate, not a loss
/// of information.
impl From<CradleError> for BackupError {
    fn from(source: CradleError) -> Self {
        Self {
            source,
            bytes_transferred: 0,
            files_received: 0,
        }
    }
}

/// Backs up the device identified by `udid` into `working_root/<UDID>/`.
///
/// `working_root` must be the canonical working directory — never a network
/// mount, never an archived snapshot. The device relies on finding its own
/// prior `Status.plist` / `Manifest.plist` / `Manifest.db` here on the next
/// run to compute an incremental; deleting or relocating this directory
/// between runs forces a full transfer.
pub async fn run(udid: &str, working_root: &Path, force_full: bool, progress: Arc<dyn ProgressSink>) -> Result<Outcome, BackupError> {
    tokio::fs::create_dir_all(working_root).await.map_err(CradleError::from)?;

    let dir = working_root.to_str().ok_or_else(|| {
        CradleError::Other(format!("working directory {} is not valid UTF-8", working_root.display()))
    })?;
    let mut args = vec!["-u", udid, "backup"];
    if force_full {
        args.push("--full");
    }
    args.push(dir);

    let result = libimobiledevice::run_idevicebackup2(&args, &[], progress).await;
    match result.outcome {
        Ok(()) => Ok(Outcome {
            udid: udid.to_string(),
            backup_dir: working_root.join(udid),
            files_received: result.files_received,
            bytes_transferred: result.bytes_transferred,
        }),
        Err(source) => Err(BackupError {
            source,
            bytes_transferred: result.bytes_transferred,
            files_received: result.files_received,
        }),
    }
}

/// How many times [`run_resilient`] retries a backup that failed because
/// the device locked mid-transfer, and how long it waits between tries.
///
/// This is a safety net behind [`ProgressSink::on_attention_needed`], not a
/// substitute for it: the live prompt should catch this before it happens.
/// It exists because libimobiledevice's own issue tracker has cases of this
/// surfacing with no clear trigger the host side can see coming, and
/// because retrying costs little — the working directory's partial state
/// lets the device compute an incremental rather than starting over.
///
/// Bumped from 5 to 12 after real runs: right after a 104, a fresh
/// connection can keep reporting 208 for several retries in a row even
/// with a fast, real unlock each time (confirmed — not an unlock-timing
/// problem, something about the device's own state right after aborting a
/// transfer takes a few cycles to clear). One run needed ~4 retries to get
/// through; another exhausted all 5 and gave up despite identical unlock
/// behavior. 12 retries at 10s apart is still only ~2 minutes of extra
/// wait in the worst case, which is cheap next to losing the whole
/// attempt.
pub const LOCK_RETRY_ATTEMPTS: u32 = 12;
pub const LOCK_RETRY_DELAY: Duration = Duration::from_secs(10);

/// How many times [`run_resilient`] retries a backup that failed with
/// [`CradleError::HostIoError`] (MBErrorDomain 104), and how long it waits
/// between tries. Fewer attempts and a longer delay than the lock retry:
/// unlike a locked screen, which resolves the moment the user looks at
/// their phone, a host-side I/O error needs the underlying condition (low
/// memory, a disk hiccup) to actually clear, and retrying into the same
/// pressure repeatedly wastes an hour-long transfer's worth of time for no
/// gain.
pub const HOST_IO_RETRY_ATTEMPTS: u32 = 3;
pub const HOST_IO_RETRY_DELAY: Duration = Duration::from_secs(30);

/// How many times [`run_resilient`] retries a backup that failed with
/// [`CradleError::Stalled`] (no progress for
/// [`libimobiledevice`]'s stall watchdog), and how long it waits between
/// tries. Same shape as the host-I/O retry — a stalled subprocess needs a
/// moment before it's worth poking again, not an instant retry into
/// whatever caused the silence.
pub const STALL_RETRY_ATTEMPTS: u32 = 3;
pub const STALL_RETRY_DELAY: Duration = Duration::from_secs(30);

/// Ceiling on how long [`wait_for_host_io_retry`] will extend a single
/// retry's wait past [`HOST_IO_RETRY_DELAY`] while memory stays critically
/// low. Bounded rather than open-ended because [`crate::memory::free_bytes`]
/// is a noisy signal (see that module's doc) — it can't be trusted to ever
/// report "recovered" cleanly, so this must still give up and let the
/// attempt run rather than wait forever on a reading that may never look
/// clean.
const HOST_IO_MAX_EXTRA_WAIT: Duration = Duration::from_secs(90);
const HOST_IO_POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Waits before a host-I/O retry, checking free memory partway through
/// instead of always sleeping the same fixed [`HOST_IO_RETRY_DELAY`].
///
/// Found via a real run: three fixed 30-second waits in a row retried
/// straight back into the same memory pressure every time and burned all
/// [`HOST_IO_RETRY_ATTEMPTS`] for nothing — the wait was never actually
/// giving the underlying condition a chance to clear, just delaying the
/// same doomed attempt. This still does the base wait, then keeps polling
/// (up to [`HOST_IO_MAX_EXTRA_WAIT`] more) only while memory reads below
/// [`crate::precheck::MIN_FREE_MEMORY_BYTES`], returning as soon as it
/// looks recovered rather than always spending the full extra budget.
async fn wait_for_host_io_retry() {
    tokio::time::sleep(HOST_IO_RETRY_DELAY).await;

    let mut waited = Duration::ZERO;
    while waited < HOST_IO_MAX_EXTRA_WAIT {
        match crate::memory::free_bytes() {
            Some(bytes) if bytes < crate::precheck::MIN_FREE_MEMORY_BYTES => {
                tokio::time::sleep(HOST_IO_POLL_INTERVAL).await;
                waited += HOST_IO_POLL_INTERVAL;
            }
            // Recovered, or unmeasurable — either way, no point waiting
            // longer on a signal we can't use.
            _ => break,
        }
    }
}

/// Which condition [`run_resilient`] is retrying, passed to its `on_retry`
/// callback so the caller can show a message that names the actual cause
/// instead of a generic "retrying...".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryReason {
    /// MBErrorDomain 208 — the device needs the user to unlock it.
    DeviceLocked,
    /// MBErrorDomain 104 — a host-side I/O error, usually low memory.
    HostIo,
    /// No output from `idevicebackup2` for longer than its stall watchdog
    /// tolerates — the subprocess stopped responding with no error at all.
    Stalled,
}

/// Runs [`run`], automatically retrying on [`CradleError::DeviceLocked`]
/// (up to [`LOCK_RETRY_ATTEMPTS`] times), [`CradleError::HostIoError`] (up
/// to [`HOST_IO_RETRY_ATTEMPTS`] times), and [`CradleError::Stalled`] (up to
/// [`STALL_RETRY_ATTEMPTS`] times). `on_retry(reason, attempt,
/// max_attempts)` fires before each wait so a caller can tell the user
/// what's happening — for a lock, it's already too late for
/// `on_attention_needed` to have caught this one; for a host I/O error or a
/// stall, there was no earlier signal at all.
///
/// All three retries are cheap by construction, not just in theory: none
/// touches `working_root`, so the device still finds its own prior
/// `Status.plist`/`Manifest.plist`/`Manifest.db` there on the next attempt
/// and computes an incremental rather than starting the whole backup over
/// (see this module's own doc comment on why that's true).
/// Errors out with a [`BackupError`] carrying the *last attempt's* partial
/// counts, not an accumulation across retries — retries don't touch
/// `working_root`, so whatever a prior attempt already wrote stays on disk
/// and doesn't need to be counted again; only what the final attempt itself
/// moved matters for the catalog.
pub async fn run_resilient(
    udid: &str,
    working_root: &Path,
    force_full: bool,
    progress: Arc<dyn ProgressSink>,
    on_retry: impl Fn(RetryReason, u32, u32),
) -> Result<Outcome, BackupError> {
    let mut lock_attempt = 1;
    let mut host_io_attempt = 1;
    let mut stall_attempt = 1;
    loop {
        match run(udid, working_root, force_full, progress.clone()).await {
            Ok(outcome) => return Ok(outcome),
            Err(err) if matches!(err.source, CradleError::DeviceLocked) && lock_attempt < LOCK_RETRY_ATTEMPTS => {
                on_retry(RetryReason::DeviceLocked, lock_attempt, LOCK_RETRY_ATTEMPTS);
                tokio::time::sleep(LOCK_RETRY_DELAY).await;
                lock_attempt += 1;
            }
            Err(err) if matches!(err.source, CradleError::HostIoError) && host_io_attempt < HOST_IO_RETRY_ATTEMPTS => {
                on_retry(RetryReason::HostIo, host_io_attempt, HOST_IO_RETRY_ATTEMPTS);
                wait_for_host_io_retry().await;
                host_io_attempt += 1;
            }
            Err(err) if matches!(err.source, CradleError::Stalled) && stall_attempt < STALL_RETRY_ATTEMPTS => {
                on_retry(RetryReason::Stalled, stall_attempt, STALL_RETRY_ATTEMPTS);
                tokio::time::sleep(STALL_RETRY_DELAY).await;
                stall_attempt += 1;
            }
            Err(err) => return Err(err),
        }
    }
}

/// Enables, changes, or disables backup encryption on the device via
/// `idevicebackup2`'s `encryption`/`changepw` subcommands.
///
/// This is the actual mechanism behind Finder's "Encrypt local backup"
/// checkbox — iOS has no on-device Settings toggle for it at all, and
/// Finder's own local-backup bookkeeping can wedge that checkbox behind a
/// "backup was corrupt" dialog with no way through. Since prechecks (see
/// [`crate::precheck`]) refuse to start a backup without this enabled,
/// Cradle needs its own way to set it rather than sending the user to
/// fight with Finder for a setting that lives entirely on the wire.
///
/// Pass `old_password: None, new_password: Some(pw)` to enable encryption
/// for the first time; `Some(old), Some(new)` to change an existing
/// password; `Some(old), None` to turn encryption back off. Passwords go
/// through `BACKUP_PASSWORD`/`BACKUP_PASSWORD_NEW` environment variables,
/// never CLI arguments, so they never show up in `ps` or shell history.
pub async fn set_encryption(
    udid: &str,
    working_root: &Path,
    old_password: Option<&str>,
    new_password: Option<&str>,
) -> Result<(), CradleError> {
    tokio::fs::create_dir_all(working_root).await?;
    let dir = working_root
        .to_str()
        .ok_or_else(|| CradleError::Other(format!("working directory {} is not valid UTF-8", working_root.display())))?;

    let mut env: Vec<(&str, &str)> = Vec::new();
    let args: Vec<&str> = match (old_password, new_password) {
        (None, Some(new)) => {
            env.push(("BACKUP_PASSWORD_NEW", new));
            vec!["-u", udid, "encryption", "on", dir]
        }
        (Some(old), None) => {
            env.push(("BACKUP_PASSWORD", old));
            vec!["-u", udid, "encryption", "off", dir]
        }
        (Some(old), Some(new)) => {
            env.push(("BACKUP_PASSWORD", old));
            env.push(("BACKUP_PASSWORD_NEW", new));
            vec!["-u", udid, "changepw", dir]
        }
        (None, None) => {
            return Err(CradleError::Other("no password change requested".to_string()));
        }
    };

    let result = libimobiledevice::run_idevicebackup2(&args, &env, Arc::new(NullProgress)).await;
    result.outcome?;

    // `idevicebackup2` reports success once the device acknowledges the
    // ChangePassword message — but doesn't check whether the change
    // actually stuck. iOS silently refuses to enable backup encryption on
    // a device with no passcode set (found via a real device), which
    // doesn't surface as a protocol error. Re-read the flag we actually
    // care about instead of trusting that return.
    let now_enabled = libimobiledevice::will_encrypt(udid).await;
    let wanted_enabled = new_password.is_some();

    if now_enabled != wanted_enabled {
        return Err(CradleError::Other(format!(
            "The device did not accept the change — backup encryption is still {}. iOS \
             silently refuses to enable backup encryption on a device with no passcode set; \
             set a passcode under Settings > Face ID & Passcode (or Touch ID & Passcode) and \
             try again.",
            if now_enabled { "on" } else { "off" }
        )));
    }
    Ok(())
}
