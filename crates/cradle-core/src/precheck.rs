//! Prechecks: never start a transfer we already know will fail.
//!
//! Per CLAUDE.md, M0's share of this is pairing validity, backup encryption,
//! and free space on the working volume. Restore-only prechecks (Find My
//! off, target iOS >= backup iOS) land in M4 alongside restore itself.

use std::path::Path;

use crate::CradleError;
use crate::device::{self, DeviceInfo};
use crate::libimobiledevice;

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
/// through `libimobiledevice`. Reports a large constant where the OS can't
/// be queried (e.g. no existing ancestor at all).
#[allow(clippy::unnecessary_cast)] // block-count/size widths vary per platform
fn free_disk_space(path: &Path) -> u64 {
    use std::os::unix::ffi::OsStrExt;

    const ASSUMED_FREE: u64 = 1 << 50;

    let mut dir = path;
    loop {
        if dir.exists() {
            break;
        }
        match dir.parent() {
            Some(parent) => dir = parent,
            None => return ASSUMED_FREE,
        }
    }

    let Ok(c) = std::ffi::CString::new(dir.as_os_str().as_bytes()) else {
        return ASSUMED_FREE;
    };
    let mut s = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `c` is NUL-terminated; `s` is a writable buffer for `statfs`.
    if unsafe { libc::statfs(c.as_ptr(), s.as_mut_ptr()) } != 0 {
        return ASSUMED_FREE;
    }
    let s = unsafe { s.assume_init() };
    s.f_bavail as u64 * s.f_bsize as u64
}

/// Result of running all M0 prechecks against one device.
#[derive(Debug, Clone)]
pub struct Report {
    pub pairing_valid: bool,
    pub pairing_message: Option<String>,
    pub encryption_enabled: bool,
    pub free_space_bytes: u64,
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
    let free_space_ok = free_space_bytes >= MIN_FREE_BYTES;
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

    let device = device::info(udid).await.ok();
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
    pub device: Option<DeviceInfo>,
}

impl RestoreReport {
    /// `true` only if every check passed. A restore must not start
    /// otherwise — CLAUDE.md's non-negotiable #1 makes restore free and
    /// unconditional, not unchecked.
    pub fn passed(&self) -> bool {
        self.pairing_valid && self.find_my_disabled && self.target_ios_ok
    }
}

/// Runs the restore-only prechecks against `udid` (the *target* device
/// restore will write to), comparing its iOS version against
/// `backup_ios_version` (read by the caller from the backup's own
/// `Info.plist` — see `restore.rs`).
pub async fn run_restore(udid: &str, backup_ios_version: &str) -> Result<RestoreReport, CradleError> {
    let pairing = libimobiledevice::check_pairing(udid).await?;
    if !pairing.valid {
        return Ok(RestoreReport {
            pairing_valid: false,
            pairing_message: pairing.message,
            find_my_disabled: false,
            target_ios_version: None,
            backup_ios_version: backup_ios_version.to_string(),
            target_ios_ok: false,
            device: None,
        });
    }

    let device = device::info(udid).await.ok();
    let find_my_associated = libimobiledevice::find_my_associated(udid).await;
    let target_ios_version = device.as_ref().map(|d| d.ios_version.clone());
    let target_ios_ok = target_ios_version
        .as_deref()
        .is_some_and(|target| ios_version_at_least(target, backup_ios_version));

    Ok(RestoreReport {
        pairing_valid: true,
        pairing_message: None,
        find_my_disabled: !find_my_associated,
        target_ios_version,
        backup_ios_version: backup_ios_version.to_string(),
        target_ios_ok,
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
