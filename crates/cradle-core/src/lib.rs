//! Device protocol, prechecks, backup orchestration, the catalog, the
//! archive layer, restore, and backup decryption for Cradle.
//!
//! M0-M5 scope (see `/ROADMAP.md`): connect to a device over
//! `mobilebackup2`, run prechecks, perform a backup into the canonical
//! working directory with honest progress reporting, verify it, record it
//! in a small local catalog, archive it out to a restic-backed
//! destination, restore it back onto a device — free and unconditional per
//! CLAUDE.md's non-negotiable #1 — and, given the backup password, decrypt
//! `Manifest.db` and individual files. Manifest *browsing* (listing files
//! by domain/path, which needs an NSKeyedArchiver decoder) isn't built
//! yet — see `crypto.rs`'s module doc.

pub mod archive;
pub mod backup;
pub mod catalog;
pub mod crypto;
pub mod device;
pub mod keychain;
pub mod libimobiledevice;
pub mod memory;
pub mod notify;
pub mod power;
pub mod precheck;
pub mod restore;
pub mod verify;

/// Errors that can occur anywhere in the Cradle core: `libimobiledevice`
/// CLI-tool failures, local filesystem failures, or a handful of
/// Cradle-specific conditions.
#[derive(Debug, thiserror::Error)]
pub enum CradleError {
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),

    #[error("catalog error: {0}")]
    Catalog(#[from] rusqlite::Error),

    /// A `libimobiledevice` CLI tool (`idevice_id`, `ideviceinfo`,
    /// `idevicepair`, `idevicebackup2`) isn't on `PATH` or in one of the
    /// usual Homebrew prefixes.
    #[error("`{0}` not found — install libimobiledevice with `brew install libimobiledevice`")]
    ToolNotFound(&'static str),

    /// A `libimobiledevice` CLI tool exited non-zero or printed an error of
    /// its own. These tools already name the fix in plain English (e.g.
    /// "No device found with udid ...", "tap Trust"), so this is usually
    /// shown to the user as-is rather than re-translated.
    #[error("{0}")]
    ToolFailed(String),

    /// MBErrorDomain 208. Split out from [`Self::Other`] because it's
    /// recoverable: see [`backup::run_resilient`], which retries on this
    /// variant (and on [`Self::HostIoError`]).
    #[error(
        "the device was locked when iOS needed to access protected data — unlock it and keep \
         it unlocked and awake for the whole backup"
    )]
    DeviceLocked,

    /// MBErrorDomain 104 ("computer-side errors during backup" — the Mac
    /// itself failed to read or write a backup file mid-transfer). Split
    /// out from [`Self::Other`], like [`Self::DeviceLocked`], because
    /// [`backup::run_resilient`] retries on it: a real ~75GB backup hit
    /// this after 53 minutes of continuous transfer, traced to the Mac
    /// running low on free memory, not anything wrong with the backup
    /// data itself.
    ///
    /// Retrying costs nothing extra to *write* — `working_root` is
    /// untouched either way — but don't assume it makes the retry itself
    /// fast: confirmed against a real device, MobileBackup2 only computes
    /// an incremental against the *last successfully finished* backup, so
    /// an attempt that gets interrupted before finishing (this error,
    /// [`Self::DeviceLocked`], anything) can make the device discard the
    /// in-progress manifest and redo the whole transfer as full on the
    /// next attempt, no matter how much data is already sitting on disk.
    #[error(
        "the Mac had a host-side I/O error while writing the backup (device error 104) — this \
         is usually caused by low system memory or a disk/USB hiccup on this computer, not a \
         problem with the device; Cradle will retry automatically, but free up memory if it \
         keeps happening"
    )]
    HostIoError,

    /// The device stopped responding mid-attempt with no final `ErrorCode`
    /// and no transport error — just silence. Split out from [`Self::Other`]
    /// for the same reason as [`Self::DeviceLocked`]/[`Self::HostIoError`]:
    /// [`backup::run_resilient`] retries on it. Found necessary after a real
    /// run where an attempt hung indefinitely with no error at all —
    /// `backup_from_path` has no timeout of its own, so without a watchdog
    /// this could (and did) sit forever with no visible failure.
    #[error(
        "the device stopped responding mid-backup with no error and no further progress — \
         Cradle will retry automatically, but check the cable/USB connection and that the \
         device is unlocked and awake if it keeps happening"
    )]
    Stalled,

    #[error("{0}")]
    Other(String),
}
