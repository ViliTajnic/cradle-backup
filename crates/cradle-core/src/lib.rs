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
pub mod keychain;
pub mod libimobiledevice;
pub mod lock;
pub mod memory;
pub mod notify;
pub mod paths;
pub mod power;
pub mod precheck;
pub mod restore;
pub mod signals;
pub mod tools;
pub mod verify;
pub mod workflow;

/// Errors that can occur anywhere in the Cradle core: `libimobiledevice`
/// CLI-tool failures, local filesystem failures, or a handful of
/// Cradle-specific conditions.
#[derive(Debug, thiserror::Error)]
pub enum CradleError {
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),

    #[error("catalog error: {0}")]
    Catalog(#[from] rusqlite::Error),

    /// An external tool `crate::tools::resolve` looked for (a
    /// `libimobiledevice` CLI tool, or `restic`) isn't on `PATH` or in one
    /// of the usual Homebrew prefixes. Deliberately names only the tool,
    /// not an install command: `restic` and the `libimobiledevice` tools
    /// come from different packages, and a wrong hint here (this used to
    /// always say "install libimobiledevice" even for a missing `restic`)
    /// is worse than no hint — callers that know which package a given
    /// tool comes from append their own.
    #[error("`{0}` not found on PATH or in the usual Homebrew prefixes")]
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

    /// MBErrorDomain 207 — the device rejected the backup password given
    /// for restore (it can't unlock the backup's keybag with it). Split
    /// out from [`Self::Other`] so this shows up as a wrong password
    /// rather than the device's own opaque "Restore Failed (Error Code
    /// 207)." — confirmed against a real restore attempt where that raw
    /// text was the *entire* error shown, with nothing naming what 207
    /// actually means (CLAUDE.md: "Error messages name the fix, not the
    /// symptom").
    #[error(
        "the backup password Cradle sent was rejected — the device could not unlock this \
         backup with it. Double-check the password (or use the override field if this backup \
         used a different one than what's stored) and try again."
    )]
    WrongBackupPassword,

    /// `idevicebackup2` couldn't even start the `com.apple.mobilebackup2`
    /// lockdownd service — confirmed on a real device mid-`Setup
    /// Assistant`: pairing/Trust can succeed early, but iOS keeps this
    /// service disabled until the device has cleared enough of initial
    /// activation, the same gate Finder's own "Restore from Mac" option is
    /// hidden behind until the "Apps & Data" screen. Not a Cradle bug and
    /// not retryable on a timer — the device needs to move further through
    /// setup first.
    #[error(
        "the device isn't ready for a backup or restore yet — this happens when it hasn't gotten \
         far enough through initial setup (or activation) for iOS to enable that service. Get it \
         to the Wi-Fi / Apple ID / \"Apps & Data\" step in Setup Assistant (or finish setup \
         entirely) and try again."
    )]
    DeviceNotReadyForBackupService,

    #[error("{0}")]
    Other(String),
}
