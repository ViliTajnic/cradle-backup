//! Prechecks: never start a transfer we already know will fail.
//!
//! Per CLAUDE.md, M0's share of this is pairing validity, backup encryption,
//! and free space on the working volume. Restore-only prechecks (Find My
//! off, target iOS >= backup iOS) land in M4 alongside restore itself.

use std::path::Path;

use crate::CradleError;
use crate::libimobiledevice::{self, DeviceInfo};

/// Conservative floor for "enough free space to safely start a backup".
///
/// MobileBackup2 doesn't expose the size of the pending backup before the
/// transfer begins — the device streams files without ever declaring a
/// total. So this is a sanity floor, not a precise sizing check; a backup
/// can still run out of space mid-transfer on a nearly-full disk. Getting a
/// tighter bound would mean estimating from the previous snapshot's size
/// once the catalog exists (M2/M3).
pub const MIN_FREE_BYTES: u64 = 5 * 1024 * 1024 * 1024;

/// Floor [`backup::wait_for_host_io_retry`] uses to decide whether it's
/// still worth extending a host-I/O retry wait. Not a precheck gate: an
/// earlier version of this file blocked backup start below this floor on
/// the theory that low free memory reliably causes MBErrorDomain 104,
/// based on a single incident. It doesn't — real runs since have hit the
/// same 104 with memory well above this floor, timed to the device's own
/// passcode/Face ID prompt instead (see `backup.rs`'s auth-prompt log
/// lines). Gating backup *start* on a noisy, unconfirmed signal (see
/// [`crate::memory`]'s module doc on why raw "Pages free" swings wildly)
/// blocked legitimate backups for no real benefit, so it no longer does.
///
/// [`backup::wait_for_host_io_retry`]: crate::backup::wait_for_host_io_retry
pub const MIN_FREE_MEMORY_BYTES: u64 = 1024 * 1024 * 1024;

/// Free space in bytes available on the volume backing `path`, walking up
/// to the nearest existing ancestor. Host-side only — no device
/// involved — so this stays a plain `statfs` call rather than going
/// through `libimobiledevice`. `None` when this can't be measured
/// honestly — including, deliberately, when the path lives under an
/// unmounted `/Volumes/<name>`.
///
/// That last case is the one that actually matters: without it, pointing
/// `--working-dir` at an external drive that's since been unplugged (or
/// never mounted this boot) doesn't fail loudly. `dir.exists()` walks
/// straight past the missing `/Volumes/<name>` mount-point directory up to
/// `/Volumes` itself, which macOS always keeps around — so the `statfs`
/// below would silently measure the *internal* disk's free space and
/// report it as if it were the external one's. Confirmed against this
/// Mac: `/Volumes/<unplugged-name>` doesn't exist, but `/Volumes` does.
/// CODEBASE_ANALYSIS.md: "A missing external volume must not silently
/// redirect storage to the internal disk."
#[allow(clippy::unnecessary_cast)] // block-count/size widths vary per platform
pub fn free_disk_space(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;

    let mut dir = path;
    while !dir.exists() {
        let parent = dir.parent()?;
        if parent == Path::new("/Volumes") {
            return None;
        }
        dir = parent;
    }

    let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
    let mut s = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `c` is NUL-terminated; `s` is a writable buffer for `statfs`.
    if unsafe { libc::statfs(c.as_ptr(), s.as_mut_ptr()) } != 0 {
        return None;
    }
    let s = unsafe { s.assume_init() };
    Some(s.f_bavail as u64 * s.f_bsize as u64)
}

/// Result of running all M0 prechecks against one device.
#[derive(Debug, Clone)]
pub struct Report {
    pub pairing_valid: bool,
    pub pairing_message: Option<String>,
    pub encryption_enabled: bool,
    /// `None` when free space couldn't be honestly measured — including
    /// when the working directory lives on a volume that isn't currently
    /// mounted. See [`free_disk_space`]'s doc. Always treated as
    /// insufficient by [`free_space_ok`](Report::passed), never as "assume
    /// plenty."
    pub free_space_bytes: Option<u64>,
    pub free_space_ok: bool,
    /// Informational only — not gated on. See [`MIN_FREE_MEMORY_BYTES`]'s
    /// doc for why a low reading here no longer blocks a backup from
    /// starting. `None` when free memory couldn't be measured (non-macOS,
    /// or `vm_stat` unavailable).
    pub free_memory_bytes: Option<u64>,
    pub device: Option<DeviceInfo>,
}

impl Report {
    /// `true` only if every check passed. A backup must not start otherwise.
    pub fn passed(&self) -> bool {
        self.pairing_valid && self.encryption_enabled && self.free_space_ok
    }
}

/// Runs every M0 precheck against `udid`, evaluating free space on the
/// volume backing `working_dir` and free memory on this Mac.
pub async fn run(udid: &str, working_dir: &Path) -> Result<Report, CradleError> {
    let free_space_bytes = free_disk_space(working_dir);
    let free_space_ok = free_space_bytes.is_some_and(|bytes| bytes >= MIN_FREE_BYTES);
    let free_memory_bytes = crate::memory::free_bytes();

    let pairing = libimobiledevice::check_pairing(udid).await?;
    if !pairing.valid {
        return Ok(Report {
            pairing_valid: false,
            pairing_message: pairing.message,
            encryption_enabled: false,
            free_space_bytes,
            free_space_ok,
            free_memory_bytes,
            device: None,
        });
    }

    let device = libimobiledevice::device_info(udid).await.ok();
    let encryption_enabled = libimobiledevice::will_encrypt(udid).await;

    Ok(Report {
        pairing_valid: true,
        pairing_message: None,
        encryption_enabled,
        free_space_bytes,
        free_space_ok,
        free_memory_bytes,
        device,
    })
}

/// Result of running the restore-only prechecks against the *target*
/// device. Per CLAUDE.md: "Restore only: Find My iPhone disabled on
/// target" / "Restore only: target iOS version >= backup's iOS version
/// (read `Product Version` from `Info.plist`)".
#[derive(Debug, Clone)]
pub struct RestoreReport {
    pub pairing_valid: bool,
    pub pairing_message: Option<String>,
    pub find_my_disabled: bool,
    pub target_ios_version: Option<String>,
    pub backup_ios_version: String,
    pub target_ios_ok: bool,
    /// The staged backup's own total size — what the target device
    /// actually needs room for. Always known by the time this runs: the
    /// staging copy has already finished before prechecks start.
    pub backup_size_bytes: u64,
    /// The target device's own free space, read live via `ideviceinfo`.
    /// `None` when it couldn't be read — treated as insufficient, same as
    /// every other "couldn't measure" case in this module, never as
    /// "assume plenty."
    pub target_free_bytes: Option<u64>,
    pub enough_target_space: bool,
    pub device: Option<DeviceInfo>,
}

impl RestoreReport {
    /// `true` only if every check passed. A restore must not start
    /// otherwise — CLAUDE.md's non-negotiable #1 makes restore free and
    /// unconditional, not unchecked.
    pub fn passed(&self) -> bool {
        self.pairing_valid && self.find_my_disabled && self.target_ios_ok && self.enough_target_space
    }
}

/// Runs the restore-only prechecks against `udid` (the *target* device
/// restore will write to), comparing its iOS version against
/// `backup_ios_version` (read by the caller from the backup's own
/// `Info.plist` — see `restore.rs`) and its free space against
/// `backup_size_bytes` (the already-staged backup's own total size — see
/// [`crate::restore::staged_backup_size`]).
///
/// Found necessary on a real cross-device restore: `idevicebackup2`
/// itself only discovers "not enough room on the target" after the full
/// staging copy (tens of minutes for a large backup) *and* the on-device
/// transfer are both already under way, reporting it as an opaque
/// `MBErrorDomain 106` at the very end — exactly the "failing mid-transfer
/// instead of a precheck" CLAUDE.md's working agreements call out.
/// `ideviceinfo` can read the target's free space up front for free.
pub async fn run_restore(udid: &str, backup_ios_version: &str, backup_size_bytes: u64) -> Result<RestoreReport, CradleError> {
    let pairing = libimobiledevice::check_pairing(udid).await?;
    if !pairing.valid {
        return Ok(RestoreReport {
            pairing_valid: false,
            pairing_message: pairing.message,
            find_my_disabled: false,
            target_ios_version: None,
            backup_ios_version: backup_ios_version.to_string(),
            target_ios_ok: false,
            backup_size_bytes,
            target_free_bytes: None,
            enough_target_space: false,
            device: None,
        });
    }

    let device = libimobiledevice::device_info(udid).await.ok();
    let find_my_associated = libimobiledevice::find_my_associated(udid).await;
    let target_ios_version = device.as_ref().map(|d| d.ios_version.clone());
    let target_ios_ok = target_ios_version
        .as_deref()
        .is_some_and(|target| ios_version_at_least(target, backup_ios_version));
    let target_free_bytes = libimobiledevice::available_disk_space(udid).await;
    let enough_target_space = target_free_bytes.is_some_and(|free| free >= backup_size_bytes);

    Ok(RestoreReport {
        pairing_valid: true,
        pairing_message: None,
        find_my_disabled: !find_my_associated,
        target_ios_version,
        backup_ios_version: backup_ios_version.to_string(),
        target_ios_ok,
        backup_size_bytes,
        target_free_bytes,
        enough_target_space,
        device,
    })
}

/// Dotted-version comparison (`"26.6.1" >= "26.6"`), not string comparison
/// (`"9.0" < "10.0"` lexically fails as strings but must hold as
/// versions). Unparseable components read as 0.
fn ios_version_at_least(target: &str, backup: &str) -> bool {
    parse_version(target) >= parse_version(backup)
}

fn parse_version(v: &str) -> Vec<u32> {
    v.split('.').map(|part| part.parse().unwrap_or(0)).collect()
}

#[cfg(test)]
mod version_tests {
    use super::*;

    #[test]
    fn longer_prefix_beats_shorter() {
        assert!(ios_version_at_least("26.6.1", "26.6"));
        assert!(!ios_version_at_least("26.6", "26.6.1"));
    }

    #[test]
    fn numeric_not_lexical() {
        assert!(ios_version_at_least("10.0", "9.0"));
        assert!(!ios_version_at_least("9.0", "10.0"));
    }

    #[test]
    fn equal_versions_pass() {
        assert!(ios_version_at_least("18.1.2", "18.1.2"));
    }
}

#[cfg(test)]
mod free_disk_space_tests {
    use super::*;

    #[test]
    fn measures_an_existing_directory() {
        let dir = std::env::temp_dir();
        assert!(free_disk_space(&dir).is_some());
    }

    #[test]
    fn walks_up_to_an_existing_ancestor_for_a_not_yet_created_subdirectory() {
        let dir = std::env::temp_dir().join(format!("cradle-precheck-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // `dir` itself doesn't exist yet, but its parent (the real temp
        // dir) does — same shape as a working directory before its first
        // backup.
        assert!(free_disk_space(&dir.join("not-created-yet")).is_some());
    }

    #[test]
    fn an_unmounted_volumes_path_reports_unknown_rather_than_the_internal_disk() {
        // A `/Volumes/<name>` that doesn't exist means nothing is mounted
        // there right now — this must not silently fall back to measuring
        // whatever `/Volumes` itself sits on (the internal disk).
        let path = Path::new("/Volumes/cradle-definitely-not-a-real-mounted-volume-xyz/working");
        assert!(!path.exists());
        assert_eq!(free_disk_space(path), None);
    }
}

#[cfg(test)]
mod restore_report_tests {
    use super::*;

    fn base_report() -> RestoreReport {
        RestoreReport {
            pairing_valid: true,
            pairing_message: None,
            find_my_disabled: true,
            target_ios_version: Some("26.6.2".to_string()),
            backup_ios_version: "26.6.2".to_string(),
            target_ios_ok: true,
            backup_size_bytes: 10,
            target_free_bytes: Some(20),
            enough_target_space: true,
            device: None,
        }
    }

    #[test]
    fn passes_when_every_check_including_space_is_fine() {
        assert!(base_report().passed());
    }

    /// The exact gap a real cross-device restore hit: every other check
    /// passed, but the target genuinely didn't have room, and nothing
    /// caught it until `idevicebackup2` failed with an opaque
    /// `MBErrorDomain 106` after the full staging copy and part of the
    /// on-device transfer had already run.
    #[test]
    fn fails_when_target_does_not_have_enough_space_even_if_everything_else_passes() {
        let report = RestoreReport {
            backup_size_bytes: 50_000_000_000,
            target_free_bytes: Some(40_000_000_000),
            enough_target_space: false,
            ..base_report()
        };
        assert!(!report.passed());
    }

    #[test]
    fn unknown_free_space_is_never_treated_as_enough() {
        let report = RestoreReport {
            target_free_bytes: None,
            enough_target_space: false,
            ..base_report()
        };
        assert!(!report.passed());
    }
}
