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

use idevice::{
    IdeviceError, IdeviceService,
    mobilebackup2::{BackupDelegate, DirEntryInfo, FsBackupDelegate, MobileBackup2Client},
    provider::IdeviceProvider,
};

use crate::CradleError;

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
}

/// [`BackupDelegate`] that stores to the local filesystem — via the crate's
/// own [`FsBackupDelegate`] — while forwarding progress to a
/// [`ProgressSink`].
///
/// This is the seam CLAUDE.md calls out: "backup to anywhere" lives in
/// alternate `BackupDelegate` implementations, not a copy step bolted on
/// afterwards. A future destination-aware delegate replaces `fs` here
/// without touching anything in this file.
struct CradleDelegate {
    fs: FsBackupDelegate,
    progress: Arc<dyn ProgressSink>,
    files_received: AtomicU64,
}

impl BackupDelegate for CradleDelegate {
    fn get_free_disk_space(&self, path: &Path) -> u64 {
        self.fs.get_free_disk_space(path)
    }

    fn open_file_read<'a>(
        &'a self,
        path: &'a Path,
    ) -> Pin<Box<dyn Future<Output = Result<Box<dyn Read + Send>, IdeviceError>> + Send + 'a>> {
        self.fs.open_file_read(path)
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
        self.progress
            .on_progress(bytes_done, bytes_total, overall_progress);
    }
}

/// Names the fix for the `MBErrorDomain` codes the device most commonly
/// reports in a `DLMessageProcessMessage` final response, per CLAUDE.md's
/// "error messages name the fix, not the symptom" rule. `None` for anything
/// not worth a specific hint yet — the raw code is still shown to the user.
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
        208 => Some(
            "the device was locked when iOS needed to access protected data — unlock it with \
             its passcode and keep it unlocked and awake for the whole backup, then retry",
        ),
        209 => Some(
            "the device couldn't find the encryption key for one of its files — retry with \
             --full to force a fresh backup",
        ),
        211 => Some("Find My is enabled on the target device — disable it before restoring"),
        _ => None,
    }
}

/// Backs up the device behind `provider` into `working_root/<UDID>/`.
///
/// `working_root` must be the canonical working directory — never a network
/// mount, never an archived snapshot. The device relies on finding its own
/// prior `Status.plist` / `Manifest.plist` / `Manifest.db` here on the next
/// run to compute an incremental; deleting or relocating this directory
/// between runs forces a full transfer.
pub async fn run(
    provider: &dyn IdeviceProvider,
    working_root: &Path,
    force_full: bool,
    progress: Arc<dyn ProgressSink>,
) -> Result<Outcome, CradleError> {
    let mut client = MobileBackup2Client::connect(provider).await?;
    let udid = client
        .idevice
        .udid()
        .map(|s| s.to_string())
        .ok_or(CradleError::MissingUdid)?;

    tokio::fs::create_dir_all(working_root).await?;

    let options = force_full.then(|| {
        let mut dict = plist::Dictionary::new();
        dict.insert("ForceFullBackup".to_string(), plist::Value::Boolean(true));
        dict
    });

    let delegate = CradleDelegate {
        fs: FsBackupDelegate,
        progress,
        files_received: AtomicU64::new(0),
    };

    let response = client
        .backup_from_path(working_root, None, options, &delegate)
        .await?;

    if let Some(dict) = &response {
        if let Some(code) = dict.get("ErrorCode") {
            let number = code.as_signed_integer();
            let hint = number.and_then(device_error_hint);
            let message = match (number, hint) {
                (Some(n), Some(hint)) => format!("device backup error {n}: {hint}"),
                (Some(n), None) => format!("device reported backup error {n}"),
                (None, _) => format!("device reported a backup error: {code:?}"),
            };
            return Err(CradleError::Other(message));
        }
    }

    Ok(Outcome {
        backup_dir: working_root.join(&udid),
        udid,
        files_received: delegate.files_received.load(Ordering::Relaxed),
    })
}
