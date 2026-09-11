//! Runs a `mobilebackup2` backup into the canonical working directory.
//!
//! Per CLAUDE.md, `working/<UDID>/` is canonical: it stays exactly in the
//! state the device left it, because MobileBackup2 computes incrementals
//! *on the device* by inspecting `Status.plist` / `Manifest.plist` /
//! `Manifest.db` already sitting there. This module never moves, archives,
//! or otherwise touches that directory beyond what the protocol itself
//! writes into it.

use std::future::Future;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use idevice::{
    IdeviceError, IdeviceService,
    mobilebackup2::{BackupDelegate, DirEntryInfo, FsBackupDelegate, MobileBackup2Client},
    notification_proxy::NotificationProxyClient,
    provider::IdeviceProvider,
};

use crate::CradleError;

/// Size of the buffer wrapped around every file handle
/// [`CradleDelegate`]/[`FsProgressDelegate`] hand back from
/// `open_file_read`. Read-only: `create_file_write`'s handle is
/// deliberately left unbuffered — see that method's own doc comment for
/// why buffering the write side is unsafe here specifically. 256 KiB is
/// negligible memory (the protocol only ever has one or two files open at
/// a time; this is not a source of the memory pressure that caused the
/// 104 errors) for a real cut in read syscalls on larger files sent during
/// restore.
const IO_BUFFER_CAPACITY: usize = 256 * 1024;

fn buffered_read(inner: Box<dyn Read + Send>) -> Box<dyn Read + Send> {
    Box::new(std::io::BufReader::with_capacity(IO_BUFFER_CAPACITY, inner))
}

/// Fired by iOS when it needs the user to authenticate (passcode/Face ID)
/// before granting a connected accessory access to protected data.
const AUTH_PRESENTED: &str = "com.apple.LocalAuthentication.ui.presented";
/// Fired when that prompt is resolved, one way or another.
const AUTH_DISMISSED: &str = "com.apple.LocalAuthentication.ui.dismissed";

/// Receives honest, measurable progress during a backup.
///
/// Per CLAUDE.md: "Every long-running operation reports files done/total,
/// bytes, rate, ETA, and current domain. Never ship an indeterminate spinner
/// for an operation whose progress we can measure." Implementations should
/// be cheap — these are called for every file and every progress tick.
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
/// library embedders) that don't need progress output.
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
    /// Number of files the device reported sending this run. Fed into
    /// [`crate::verify`] as the count to check on-disk files against —
    /// counting `on_file_received` calls rather than trusting any single
    /// `file_count` value it carries, since that value resets per upload
    /// batch and a backup can involve several batches.
    pub files_received: u64,
    /// Bytes actually moved over the wire this run — summed across upload
    /// batches, not the on-disk size of the resulting snapshot (an
    /// incremental run typically moves far less than the snapshot is
    /// large, since most files were already there). Feeds
    /// `catalog::Catalog::finish_run`'s `bytes` column.
    pub bytes_transferred: u64,
}

/// A backup failure paired with how far the run got before it happened.
///
/// Found via a real run: a device error late in a 53-minute transfer left
/// the catalog recording 0 bytes / 0 files for a run that had in fact been
/// moving data continuously — [`run`]'s delegate was tracking real counts
/// the whole time, they just never survived the `Err` path out of the
/// function. `bytes_transferred`/`files_received` are 0 only when the run
/// never got far enough to create the delegate (a connection failure, a
/// missing UDID) — genuinely nothing moved in that case.
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

/// Early failures (connect, missing UDID, `create_dir_all`) happen before
/// [`CradleDelegate`] exists to have counted anything — 0/0 here is
/// accurate, not a loss of information.
impl From<CradleError> for BackupError {
    fn from(source: CradleError) -> Self {
        Self {
            source,
            bytes_transferred: 0,
            files_received: 0,
        }
    }
}

/// [`BackupDelegate`] that stores to the local filesystem — via the crate's
/// own [`FsBackupDelegate`] — while forwarding progress to a
/// [`ProgressSink`].
///
/// This is the seam CLAUDE.md calls out: "backup to anywhere" lives in
/// alternate `BackupDelegate` implementations, not a copy step bolted on
/// afterwards. A future destination-aware delegate replaces `fs` here
/// without touching anything in this file.
///
/// `open_file_read` wraps `FsBackupDelegate`'s handle in a buffer rather
/// than forwarding it raw — see [`IO_BUFFER_CAPACITY`].
/// `create_file_write` deliberately does not: the `idevice` protocol loop
/// never calls `.flush()`, only lets the handle drop once a file's data
/// blocks are done, and `BufWriter`'s drop-time flush silently discards
/// any I/O error — a disk hiccup on the last partial buffer would produce
/// a truncated file with nothing to catch it (the verification gate checks
/// file *count*, not per-file content). Not worth that risk for what's a
/// modest win anyway, since the protocol already writes in
/// device-message-sized blocks, not byte-by-byte.
struct CradleDelegate {
    fs: FsBackupDelegate,
    progress: Arc<dyn ProgressSink>,
    files_received: AtomicU64,
    bytes_transferred: AtomicU64,
    /// `bytes_done` from the most recent `on_progress` call, to turn its
    /// per-batch running total into a whole-run delta sum (see
    /// `on_progress` below).
    last_batch_bytes: AtomicU64,
}

impl BackupDelegate for CradleDelegate {
    fn get_free_disk_space(&self, path: &Path) -> u64 {
        self.fs.get_free_disk_space(path)
    }

    fn open_file_read<'a>(
        &'a self,
        path: &'a Path,
    ) -> Pin<Box<dyn Future<Output = Result<Box<dyn Read + Send>, IdeviceError>> + Send + 'a>> {
        Box::pin(async move { self.fs.open_file_read(path).await.map(buffered_read) })
    }

    fn create_file_write<'a>(
        &'a self,
        path: &'a Path,
    ) -> Pin<Box<dyn Future<Output = Result<Box<dyn Write + Send>, IdeviceError>> + Send + 'a>> {
        self.fs.create_file_write(path)
    }

    fn create_dir_all<'a>(
        &'a self,
        path: &'a Path,
    ) -> Pin<Box<dyn Future<Output = Result<(), IdeviceError>> + Send + 'a>> {
        self.fs.create_dir_all(path)
    }

    fn remove<'a>(
        &'a self,
        path: &'a Path,
    ) -> Pin<Box<dyn Future<Output = Result<(), IdeviceError>> + Send + 'a>> {
        self.fs.remove(path)
    }

    fn rename<'a>(
        &'a self,
        from: &'a Path,
        to: &'a Path,
    ) -> Pin<Box<dyn Future<Output = Result<(), IdeviceError>> + Send + 'a>> {
        self.fs.rename(from, to)
    }

    fn copy<'a>(
        &'a self,
        src: &'a Path,
        dst: &'a Path,
    ) -> Pin<Box<dyn Future<Output = Result<(), IdeviceError>> + Send + 'a>> {
        self.fs.copy(src, dst)
    }

    fn exists<'a>(&'a self, path: &'a Path) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        self.fs.exists(path)
    }

    fn is_dir<'a>(&'a self, path: &'a Path) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        self.fs.is_dir(path)
    }

    fn list_dir<'a>(
        &'a self,
        path: &'a Path,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<DirEntryInfo>, IdeviceError>> + Send + 'a>> {
        self.fs.list_dir(path)
    }

    fn on_file_received(&self, path: &str, file_count: u32) {
        // Count events, not the `file_count` value: it's a running total
        // within the *current* upload batch, and a backup can involve
        // several batches, each restarting that count from zero.
        self.files_received.fetch_add(1, Ordering::Relaxed);
        self.progress.on_file(path, file_count);
    }

    fn on_progress(&self, bytes_done: u64, bytes_total: u64, overall_progress: f64) {
        // `bytes_done` is a running total *within the current batch*, per
        // the trait's own doc comment — same batching gotcha as file_count
        // above. Turn it into a whole-run total by summing deltas, treating
        // a drop (a new batch starting) as a fresh delta from 0.
        let previous = self.last_batch_bytes.swap(bytes_done, Ordering::Relaxed);
        let delta = if bytes_done >= previous {
            bytes_done - previous
        } else {
            bytes_done
        };
        self.bytes_transferred.fetch_add(delta, Ordering::Relaxed);
        self.progress
            .on_progress(bytes_done, bytes_total, overall_progress);
    }
}

/// [`BackupDelegate`] that stores to the local filesystem while forwarding
/// progress to a [`ProgressSink`] — everything [`CradleDelegate`] does,
/// minus the file/byte counters that only the M1 verification gate needs.
///
/// `restore.rs` uses this: `FsBackupDelegate` alone is a silent no-op for
/// `on_progress`/`on_file_received` (its own impl doesn't override the
/// trait's empty defaults), and restore has no gate to feed counters into
/// — it either succeeds or fails per the device's own response. Shared
/// here rather than duplicated in `restore.rs` because the eight
/// filesystem methods below are pure forwarding boilerplate either way.
pub(crate) struct FsProgressDelegate {
    fs: FsBackupDelegate,
    progress: Arc<dyn ProgressSink>,
}

impl FsProgressDelegate {
    pub(crate) fn new(progress: Arc<dyn ProgressSink>) -> Self {
        Self {
            fs: FsBackupDelegate,
            progress,
        }
    }
}

impl BackupDelegate for FsProgressDelegate {
    fn get_free_disk_space(&self, path: &Path) -> u64 {
        self.fs.get_free_disk_space(path)
    }

    fn open_file_read<'a>(
        &'a self,
        path: &'a Path,
    ) -> Pin<Box<dyn Future<Output = Result<Box<dyn Read + Send>, IdeviceError>> + Send + 'a>> {
        Box::pin(async move { self.fs.open_file_read(path).await.map(buffered_read) })
    }

    fn create_file_write<'a>(
        &'a self,
        path: &'a Path,
    ) -> Pin<Box<dyn Future<Output = Result<Box<dyn Write + Send>, IdeviceError>> + Send + 'a>> {
        self.fs.create_file_write(path)
    }

    fn create_dir_all<'a>(
        &'a self,
        path: &'a Path,
    ) -> Pin<Box<dyn Future<Output = Result<(), IdeviceError>> + Send + 'a>> {
        self.fs.create_dir_all(path)
    }

    fn remove<'a>(
        &'a self,
        path: &'a Path,
    ) -> Pin<Box<dyn Future<Output = Result<(), IdeviceError>> + Send + 'a>> {
        self.fs.remove(path)
    }

    fn rename<'a>(
        &'a self,
        from: &'a Path,
        to: &'a Path,
    ) -> Pin<Box<dyn Future<Output = Result<(), IdeviceError>> + Send + 'a>> {
        self.fs.rename(from, to)
    }

    fn copy<'a>(
        &'a self,
        src: &'a Path,
        dst: &'a Path,
    ) -> Pin<Box<dyn Future<Output = Result<(), IdeviceError>> + Send + 'a>> {
        self.fs.copy(src, dst)
    }

    fn exists<'a>(&'a self, path: &'a Path) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        self.fs.exists(path)
    }

    fn is_dir<'a>(&'a self, path: &'a Path) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        self.fs.is_dir(path)
    }

    fn list_dir<'a>(
        &'a self,
        path: &'a Path,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<DirEntryInfo>, IdeviceError>> + Send + 'a>> {
        self.fs.list_dir(path)
    }

    fn on_file_received(&self, path: &str, file_count: u32) {
        self.progress.on_file(path, file_count);
    }

    fn on_progress(&self, bytes_done: u64, bytes_total: u64, overall_progress: f64) {
        self.progress
            .on_progress(bytes_done, bytes_total, overall_progress);
    }
}

/// Names the fix for the `MBErrorDomain` codes the device most commonly
/// reports in a `DLMessageProcessMessage` final response, per CLAUDE.md's
/// "error messages name the fix, not the symptom" rule. `None` for anything
/// not worth a specific hint yet — the raw code is still shown to the user.
///
/// 208 (device locked) is deliberately not here — it gets its own
/// [`CradleError::DeviceLocked`] variant in [`run`] instead of a string,
/// since [`run_resilient`] retries on it specifically.
fn device_error_hint(code: i64) -> Option<&'static str> {
    match code {
        100 => Some(
            "couldn't export a Keychain/encryption key needed for the backup — retry, and if \
             it keeps happening, disable and re-enable encrypted backups in Finder (Change \
             Password) to reset the keybag",
        ),
        105 => Some(
            "not enough free space on this Mac to store the backup (the device checks this \
             itself before sending data) — free up space, or point --working-dir at a volume \
             with more room",
        ),
        106 => Some(
            "not enough free space on the device itself to prepare its backup — free up space \
             on the iPhone/iPad and retry",
        ),
        207 => Some(
            "invalid or missing backup password — set/confirm the encrypted backup password \
             in Finder (General > Transfer or Reset > Change Password), then retry",
        ),
        209 => Some(
            "the device couldn't find the encryption key for one of its files — retry with \
             --full to force a fresh backup",
        ),
        211 => Some("Find My is enabled on the target device — disable it before restoring"),
        _ => None,
    }
}

/// Watches for the on-device passcode/Face ID prompt for as long as the
/// caller keeps polling this future, forwarding presented/dismissed
/// transitions to `progress`.
///
/// Never resolves under normal operation — including when the notification
/// proxy connection dies or `observe_notifications` fails, since a device
/// that can't be watched shouldn't take down the backup racing against it
/// in [`run`]'s `tokio::select!`. It's meant to be raced, not awaited alone.
async fn watch_auth_prompts(mut client: NotificationProxyClient, progress: Arc<dyn ProgressSink>) {
    if client
        .observe_notifications(&[AUTH_PRESENTED, AUTH_DISMISSED])
        .await
        .is_ok()
    {
        while let Ok(name) = client.receive_notification().await {
            match name.as_str() {
                AUTH_PRESENTED => progress.on_attention_needed(true),
                AUTH_DISMISSED => progress.on_attention_needed(false),
                _ => {}
            }
        }
    }
    std::future::pending::<()>().await;
}

/// Backs up the device behind `provider` into `working_root/<UDID>/`.
///
/// `working_root` must be the canonical working directory — never a network
/// mount, never an archived snapshot. The device relies on finding its own
/// prior `Status.plist` / `Manifest.plist` / `Manifest.db` here on the next
/// run to compute an incremental; deleting or relocating this directory
/// between runs forces a full transfer.
///
/// Watches for the device's own on-screen passcode/Face ID prompt for the
/// duration of the transfer and reports it via
/// [`ProgressSink::on_attention_needed`] — see that method's docs for why:
/// without this, a backup that needs protected data access can stall or
/// fail (MBErrorDomain 208) with no visible cause, because the thing that
/// needs the user's attention is on the *phone's* screen, not the host's.
pub async fn run(
    provider: &dyn IdeviceProvider,
    working_root: &Path,
    force_full: bool,
    progress: Arc<dyn ProgressSink>,
) -> Result<Outcome, BackupError> {
    let mut client = MobileBackup2Client::connect(provider)
        .await
        .map_err(CradleError::from)?;
    let udid = client
        .idevice
        .udid()
        .map(|s| s.to_string())
        .ok_or(CradleError::MissingUdid)?;

    tokio::fs::create_dir_all(working_root)
        .await
        .map_err(CradleError::from)?;

    let options = force_full.then(|| {
        let mut dict = plist::Dictionary::new();
        dict.insert("ForceFullBackup".to_string(), plist::Value::Boolean(true));
        dict
    });

    let delegate = CradleDelegate {
        fs: FsBackupDelegate,
        progress: progress.clone(),
        files_received: AtomicU64::new(0),
        bytes_transferred: AtomicU64::new(0),
        last_batch_bytes: AtomicU64::new(0),
    };

    // Best-effort: a device that refuses this second connection still gets
    // backed up, just without the live "look at your phone" signal.
    let notification_proxy = NotificationProxyClient::connect(provider).await.ok();

    // Reads `delegate`'s counters as they stand right now — used on every
    // error path below, since `delegate` is only borrowed by
    // `backup_from_path`, not consumed, so it's still ours to read no
    // matter how the transfer ended.
    let partial_counts = |delegate: &CradleDelegate| {
        (
            delegate.bytes_transferred.load(Ordering::Relaxed),
            delegate.files_received.load(Ordering::Relaxed),
        )
    };

    let backup = client.backup_from_path(working_root, None, options, &delegate);
    let response = match notification_proxy {
        Some(np_client) => {
            tokio::select! {
                result = backup => result,
                _ = watch_auth_prompts(np_client, progress) => {
                    unreachable!("watch_auth_prompts never resolves")
                }
            }
        }
        None => backup.await,
    };
    let response = match response {
        Ok(response) => response,
        Err(e) => {
            let (bytes_transferred, files_received) = partial_counts(&delegate);
            return Err(BackupError {
                source: CradleError::from(e),
                bytes_transferred,
                files_received,
            });
        }
    };

    if let Some(dict) = &response
        && let Some(code) = dict.get("ErrorCode")
    {
        let (bytes_transferred, files_received) = partial_counts(&delegate);
        let number = code.as_signed_integer();
        let source = if number == Some(208) {
            CradleError::DeviceLocked
        } else if number == Some(104) {
            CradleError::HostIoError
        } else {
            let hint = number.and_then(device_error_hint);
            CradleError::Other(match (number, hint) {
                (Some(n), Some(hint)) => format!("device backup error {n}: {hint}"),
                (Some(n), None) => format!("device reported backup error {n}"),
                (None, _) => format!("device reported a backup error: {code:?}"),
            })
        };
        return Err(BackupError {
            source,
            bytes_transferred,
            files_received,
        });
    }

    Ok(Outcome {
        backup_dir: working_root.join(&udid),
        udid,
        files_received: delegate.files_received.load(Ordering::Relaxed),
        bytes_transferred: delegate.bytes_transferred.load(Ordering::Relaxed),
    })
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
pub const LOCK_RETRY_ATTEMPTS: u32 = 5;
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

/// Which condition [`run_resilient`] is retrying, passed to its `on_retry`
/// callback so the caller can show a message that names the actual cause
/// instead of a generic "retrying...".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryReason {
    /// MBErrorDomain 208 — the device needs the user to unlock it.
    DeviceLocked,
    /// MBErrorDomain 104 — a host-side I/O error, usually low memory.
    HostIo,
}

/// Runs [`run`], automatically retrying on [`CradleError::DeviceLocked`]
/// (up to [`LOCK_RETRY_ATTEMPTS`] times) and [`CradleError::HostIoError`]
/// (up to [`HOST_IO_RETRY_ATTEMPTS`] times). `on_retry(reason, attempt,
/// max_attempts)` fires before each wait so a caller can tell the user
/// what's happening — for a lock, it's already too late for
/// `on_attention_needed` to have caught this one; for a host I/O error,
/// there was no earlier signal at all.
///
/// Both retries are cheap by construction, not just in theory: neither
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
    provider: &dyn IdeviceProvider,
    working_root: &Path,
    force_full: bool,
    progress: Arc<dyn ProgressSink>,
    on_retry: impl Fn(RetryReason, u32, u32),
) -> Result<Outcome, BackupError> {
    let mut lock_attempt = 1;
    let mut host_io_attempt = 1;
    loop {
        match run(provider, working_root, force_full, progress.clone()).await {
            Ok(outcome) => return Ok(outcome),
            Err(err) if matches!(err.source, CradleError::DeviceLocked) && lock_attempt < LOCK_RETRY_ATTEMPTS => {
                on_retry(RetryReason::DeviceLocked, lock_attempt, LOCK_RETRY_ATTEMPTS);
                tokio::time::sleep(LOCK_RETRY_DELAY).await;
                lock_attempt += 1;
            }
            Err(err) if matches!(err.source, CradleError::HostIoError) && host_io_attempt < HOST_IO_RETRY_ATTEMPTS => {
                on_retry(RetryReason::HostIo, host_io_attempt, HOST_IO_RETRY_ATTEMPTS);
                tokio::time::sleep(HOST_IO_RETRY_DELAY).await;
                host_io_attempt += 1;
            }
            Err(err) => return Err(err),
        }
    }
}
